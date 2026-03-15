//! Admission webhook HTTP handler
//!
//! Single POST endpoint that deserializes an AdmissionReview, dispatches to the
//! appropriate validator, and returns the response.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use kube::core::DynamicObject;

use crate::validators::ValidatorRegistry;

/// Shared state for the webhook handler
pub struct HandlerState {
    pub registry: ValidatorRegistry,
}

/// POST /validate handler
///
/// Receives an AdmissionReview, looks up the validator by GVR,
/// calls validate(), and returns the AdmissionReview response.
pub async fn validate_handler(
    State(state): State<Arc<HandlerState>>,
    Json(review): Json<AdmissionReview<DynamicObject>>,
) -> impl IntoResponse {
    let request: AdmissionRequest<DynamicObject> = match review.try_into() {
        Ok(req) => req,
        Err(e) => {
            tracing::error!(error = %e, "Failed to extract AdmissionRequest from review");
            let response = AdmissionResponse::invalid(format!("invalid admission review: {e}"));
            let review: AdmissionReview<DynamicObject> = response.into_review();
            return (StatusCode::OK, Json(review));
        }
    };

    // Extract GVR from the request's resource field
    let resource = &request.resource;
    let group = resource.group.as_str();
    let version = resource.version.as_str();
    let resource_name = resource.resource.as_str();

    let response = match state.registry.find(group, version, resource_name) {
        Some(validator) => {
            tracing::debug!(
                group = group,
                version = version,
                resource = resource_name,
                name = ?request.name,
                namespace = ?request.namespace,
                operation = ?request.operation,
                "Validating admission request"
            );
            validator.validate(&request)
        }
        None => {
            tracing::error!(
                group = group,
                version = version,
                resource = resource_name,
                "No validator registered — denying request (fail-closed)"
            );
            AdmissionResponse::invalid(format!(
                "no validator registered for {}/{} {}",
                group, version, resource_name
            ))
        }
    };

    let review: AdmissionReview<DynamicObject> = response.into_review();
    (StatusCode::OK, Json(review))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::post;
    use axum::Router;
    use kube::core::admission::AdmissionReview;
    use kube::core::DynamicObject;
    use tower::ServiceExt;

    fn test_app() -> Router {
        let state = Arc::new(HandlerState {
            registry: ValidatorRegistry::new(),
        });
        Router::new()
            .route("/validate", post(validate_handler))
            .with_state(state)
    }

    fn admission_review_json(resource_json: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "test-uid-123",
                "kind": {
                    "group": "lattice.dev",
                    "version": "v1alpha1",
                    "kind": "LatticeCluster"
                },
                "resource": {
                    "group": "lattice.dev",
                    "version": "v1alpha1",
                    "resource": "latticeclusters"
                },
                "operation": "CREATE",
                "userInfo": {
                    "username": "test-user"
                },
                "object": resource_json
            }
        })
    }

    #[tokio::test]
    async fn handler_allows_valid_cluster() {
        let app = test_app();
        let cluster_json = serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeCluster",
            "metadata": { "name": "test-cluster" },
            "spec": {
                "providerRef": "aws-prod",
                "provider": {
                    "kubernetes": {
                        "version": "1.32.0",
                        "certSANs": ["127.0.0.1"]
                    },
                    "config": { "docker": {} }
                },
                "nodes": {
                    "controlPlane": { "replicas": 1 },
                    "workerPools": {
                        "default": { "replicas": 2 }
                    }
                },
                "latticeImage": "ghcr.io/evan-hines-js/lattice:latest"
            }
        });

        let body = serde_json::to_string(&admission_review_json(cluster_json)).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/validate")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let review: AdmissionReview<DynamicObject> = serde_json::from_slice(&body).unwrap();
        let resp = review.response.unwrap();
        assert!(resp.allowed, "valid cluster should be allowed");
    }

    #[tokio::test]
    async fn handler_denies_invalid_cluster() {
        let app = test_app();
        let cluster_json = serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeCluster",
            "metadata": { "name": "bad-cluster" },
            "spec": {
                "providerRef": "",
                "provider": {
                    "kubernetes": {
                        "version": "1.32.0",
                        "certSANs": ["127.0.0.1"]
                    },
                    "config": { "docker": {} }
                },
                "nodes": {
                    "controlPlane": { "replicas": 1 },
                    "workerPools": {
                        "default": { "replicas": 2 }
                    }
                },
                "latticeImage": "ghcr.io/evan-hines-js/lattice:latest"
            }
        });

        let body = serde_json::to_string(&admission_review_json(cluster_json)).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/validate")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let review: AdmissionReview<DynamicObject> = serde_json::from_slice(&body).unwrap();
        let resp = review.response.unwrap();
        assert!(!resp.allowed, "invalid cluster should be denied");
    }

    #[tokio::test]
    async fn handler_allows_unknown_resource() {
        let app = test_app();
        let body = serde_json::to_string(&serde_json::json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "test-uid-456",
                "kind": {
                    "group": "other.dev",
                    "version": "v1",
                    "kind": "SomeOtherResource"
                },
                "resource": {
                    "group": "other.dev",
                    "version": "v1",
                    "resource": "someotherresources"
                },
                "operation": "CREATE",
                "userInfo": {
                    "username": "test-user"
                },
                "object": {
                    "apiVersion": "other.dev/v1",
                    "kind": "SomeOtherResource",
                    "metadata": { "name": "test" }
                }
            }
        }))
        .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/validate")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let review: AdmissionReview<DynamicObject> = serde_json::from_slice(&body).unwrap();
        let resp = review.response.unwrap();
        assert!(
            resp.allowed,
            "unknown resource should be allowed (no validator)"
        );
    }
}
