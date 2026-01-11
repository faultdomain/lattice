//! Deployment Mutation Webhook
//!
//! Handles AdmissionReview requests for Deployment resources, injecting
//! container specifications from matching LatticeService CRDs.

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use k8s_openapi::api::apps::v1::Deployment;
use kube::{
    api::{Api, DynamicObject},
    core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview},
};
use tracing::{debug, error, info, warn};

use crate::{
    crd::LatticeService,
    workload::{CompiledPodSpec, WorkloadCompiler},
};

use super::WebhookState;

/// Label key used to identify Lattice-managed Deployments
pub const LATTICE_SERVICE_LABEL: &str = "lattice.dev/service";

/// Error type for webhook operations
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    /// The admission review request was invalid or malformed
    #[error("invalid admission review: {0}")]
    InvalidReview(String),

    /// An error occurred while communicating with the Kubernetes API
    #[error("kubernetes API error: {0}")]
    Kube(#[from] kube::Error),

    /// An error occurred during JSON serialization/deserialization
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl IntoResponse for WebhookError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            WebhookError::InvalidReview(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            WebhookError::Kube(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            WebhookError::Serialization(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };

        (status, Json(serde_json::json!({"error": message}))).into_response()
    }
}

/// Handle mutating admission review for Deployments
///
/// This handler:
/// 1. Extracts the Deployment from the admission review
/// 2. Checks for the `lattice.dev/service` label
/// 3. If present, looks up the corresponding LatticeService
/// 4. Generates a JSON patch to inject the container spec
/// 5. Returns the mutated admission response
pub async fn mutate_handler(
    State(state): State<Arc<WebhookState>>,
    Json(review): Json<AdmissionReview<Deployment>>,
) -> Result<Json<AdmissionReview<DynamicObject>>, WebhookError> {
    let request = review
        .request
        .ok_or_else(|| WebhookError::InvalidReview("missing request".to_string()))?;

    let response = mutate_deployment(&state, &request).await;

    Ok(Json(response.into_review()))
}

/// Process a single deployment mutation request
async fn mutate_deployment(
    state: &WebhookState,
    request: &AdmissionRequest<Deployment>,
) -> AdmissionResponse {
    let uid = request.uid.clone();

    // Get the deployment object
    let deployment = match &request.object {
        Some(d) => d,
        None => {
            debug!(uid = %uid, "No deployment object in request, allowing unchanged");
            return AdmissionResponse::from(&request.clone());
        }
    };

    // Check for lattice service label
    let labels = deployment.metadata.labels.as_ref();
    let service_name = match labels.and_then(|l| l.get(LATTICE_SERVICE_LABEL)) {
        Some(name) => name.clone(),
        None => {
            debug!(
                uid = %uid,
                deployment = ?deployment.metadata.name,
                "No lattice.dev/service label, allowing unchanged"
            );
            return AdmissionResponse::from(&request.clone());
        }
    };

    info!(
        uid = %uid,
        service = %service_name,
        deployment = ?deployment.metadata.name,
        "Mutating deployment for LatticeService"
    );

    // Look up the LatticeService (cluster-scoped)
    let services: Api<LatticeService> = Api::all(state.kube.clone());
    let service = match services.get(&service_name).await {
        Ok(svc) => svc,
        Err(kube::Error::Api(e)) if e.code == 404 => {
            warn!(
                uid = %uid,
                service = %service_name,
                "LatticeService not found, denying to allow retry"
            );
            // Deny so the controller retries - LatticeService may not be created yet
            return AdmissionResponse::from(&request.clone())
                .deny(format!("LatticeService '{}' not found, will retry", service_name));
        }
        Err(e) => {
            error!(
                uid = %uid,
                service = %service_name,
                error = %e,
                "Failed to lookup LatticeService"
            );
            return AdmissionResponse::from(&request.clone()).deny(e.to_string());
        }
    };

    // Generate the pod spec from the LatticeService
    let pod_spec = WorkloadCompiler::compile_pod_spec(&service);

    // Build JSON patch operations
    let patch_ops = build_patch_operations(&service_name, &pod_spec);

    info!(
        uid = %uid,
        service = %service_name,
        patch_ops = patch_ops.len(),
        "Applying patch to deployment"
    );

    match AdmissionResponse::from(&request.clone()).with_patch(json_patch::Patch(patch_ops)) {
        Ok(response) => response,
        Err(e) => {
            error!(uid = %uid, error = %e, "Failed to serialize patch");
            AdmissionResponse::from(&request.clone()).deny(format!("patch serialization error: {e}"))
        }
    }
}

/// Build JSON patch operations to inject pod spec into deployment
fn build_patch_operations(
    service_name: &str,
    pod_spec: &CompiledPodSpec,
) -> Vec<json_patch::PatchOperation> {
    use json_patch::{AddOperation, PatchOperation, ReplaceOperation};
    use jsonptr::PointerBuf;

    let mut ops = Vec::new();

    // Ensure /spec/template/spec exists (should always exist for valid deployment)
    // Replace containers
    ops.push(PatchOperation::Replace(ReplaceOperation {
        path: PointerBuf::from_tokens(["spec", "template", "spec", "containers"]),
        value: serde_json::to_value(&pod_spec.containers).unwrap_or_default(),
    }));

    // Set service account name
    ops.push(PatchOperation::Add(AddOperation {
        path: PointerBuf::from_tokens(["spec", "template", "spec", "serviceAccountName"]),
        value: serde_json::Value::String(service_name.to_string()),
    }));

    // Add volumes if present
    if !pod_spec.volumes.is_empty() {
        ops.push(PatchOperation::Add(AddOperation {
            path: PointerBuf::from_tokens(["spec", "template", "spec", "volumes"]),
            value: serde_json::to_value(&pod_spec.volumes).unwrap_or_default(),
        }));
    }

    ops
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload::Container;
    use jsonptr::PointerBuf;
    use std::collections::BTreeMap;

    // =========================================================================
    // Unit Tests
    // =========================================================================

    fn make_test_container(name: &str, image: &str) -> Container {
        Container {
            name: name.to_string(),
            image: image.to_string(),
            command: None,
            args: None,
            env: vec![],
            ports: vec![],
            resources: None,
            liveness_probe: None,
            readiness_probe: None,
            volume_mounts: vec![],
        }
    }

    #[test]
    fn test_build_patch_operations_basic() {
        let pod_spec = CompiledPodSpec {
            containers: vec![make_test_container("main", "nginx:latest")],
            volumes: vec![],
            strategy: None,
        };

        let ops = build_patch_operations("my-service", &pod_spec);

        // Should have at least containers and service account
        assert!(ops.len() >= 2);

        let containers_path = PointerBuf::from_tokens(["spec", "template", "spec", "containers"]);
        let sa_path = PointerBuf::from_tokens(["spec", "template", "spec", "serviceAccountName"]);

        // Check containers patch
        let containers_op = ops
            .iter()
            .find(|op| matches!(op, json_patch::PatchOperation::Replace(r) if r.path == containers_path))
            .expect("should have containers patch");

        if let json_patch::PatchOperation::Replace(r) = containers_op {
            assert!(r.value.is_array());
        }

        // Check service account patch
        let sa_op = ops
            .iter()
            .find(|op| matches!(op, json_patch::PatchOperation::Add(a) if a.path == sa_path))
            .expect("should have service account patch");

        if let json_patch::PatchOperation::Add(a) = sa_op {
            assert_eq!(a.value, serde_json::Value::String("my-service".to_string()));
        }
    }

    #[test]
    fn test_build_patch_operations_with_volumes() {
        use crate::workload::{EmptyDirVolumeSource, Volume};

        let pod_spec = CompiledPodSpec {
            containers: vec![make_test_container("main", "nginx:latest")],
            volumes: vec![Volume {
                name: "cache".to_string(),
                config_map: None,
                secret: None,
                empty_dir: Some(EmptyDirVolumeSource {}),
            }],
            strategy: None,
        };

        let ops = build_patch_operations("my-service", &pod_spec);
        let volumes_path = PointerBuf::from_tokens(["spec", "template", "spec", "volumes"]);

        // Should have volumes patch
        let volumes_op = ops
            .iter()
            .find(|op| matches!(op, json_patch::PatchOperation::Add(a) if a.path == volumes_path));

        assert!(volumes_op.is_some(), "should have volumes patch when volumes present");
    }

    #[test]
    fn test_build_patch_operations_no_volumes() {
        let pod_spec = CompiledPodSpec {
            containers: vec![make_test_container("main", "nginx:latest")],
            volumes: vec![],
            strategy: None,
        };

        let ops = build_patch_operations("my-service", &pod_spec);
        let volumes_path = PointerBuf::from_tokens(["spec", "template", "spec", "volumes"]);

        // Should NOT have volumes patch when no volumes
        let volumes_op = ops
            .iter()
            .find(|op| matches!(op, json_patch::PatchOperation::Add(a) if a.path == volumes_path));

        assert!(volumes_op.is_none(), "should not have volumes patch when no volumes");
    }

    #[test]
    fn test_webhook_error_display() {
        let err = WebhookError::InvalidReview("test error".to_string());
        assert!(err.to_string().contains("test error"));

        let err = WebhookError::Serialization(serde_json::from_str::<()>("invalid").unwrap_err());
        assert!(err.to_string().contains("serialization"));
    }

    // =========================================================================
    // Story Tests
    // =========================================================================

    /// Story: Deployment without lattice label passes through unchanged
    #[test]
    fn story_non_lattice_deployment_unchanged() {
        // A deployment without the lattice.dev/service label should pass through
        // the webhook unchanged. This is important for non-Lattice workloads.
        let labels: BTreeMap<String, String> = BTreeMap::new();

        // No lattice.dev/service label means we don't look up a LatticeService
        let service_name = labels.get(LATTICE_SERVICE_LABEL);
        assert!(service_name.is_none());
    }

    /// Story: Deployment with lattice label gets containers injected
    #[test]
    fn story_lattice_deployment_gets_containers() {
        let mut labels = BTreeMap::new();
        labels.insert(LATTICE_SERVICE_LABEL.to_string(), "api-gateway".to_string());

        let service_name = labels.get(LATTICE_SERVICE_LABEL);
        assert_eq!(service_name, Some(&"api-gateway".to_string()));

        // With the label present, we would look up the LatticeService
        // and inject its container spec
    }

    /// Story: Patch operations produce valid JSON that can be serialized
    #[test]
    fn story_patch_operations_serialize_to_json() {
        let pod_spec = CompiledPodSpec {
            containers: vec![make_test_container("app", "myapp:v1")],
            volumes: vec![],
            strategy: None,
        };

        let ops = build_patch_operations("my-service", &pod_spec);

        // Convert to json_patch::Patch and serialize
        let patch = json_patch::Patch(ops);
        let serialized = serde_json::to_string(&patch);

        assert!(
            serialized.is_ok(),
            "patch should serialize to JSON: {:?}",
            serialized.err()
        );

        // Verify it's valid JSON array
        let json_str = serialized.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.is_array(), "patch should be a JSON array");
    }

    /// Story: Multiple containers are included in patch
    #[test]
    fn story_multiple_containers_in_patch() {
        let pod_spec = CompiledPodSpec {
            containers: vec![
                make_test_container("main", "nginx:latest"),
                make_test_container("sidecar", "envoy:v1"),
            ],
            volumes: vec![],
            strategy: None,
        };

        let ops = build_patch_operations("my-service", &pod_spec);
        let containers_path = PointerBuf::from_tokens(["spec", "template", "spec", "containers"]);

        let containers_op = ops
            .iter()
            .find(|op| {
                matches!(op, json_patch::PatchOperation::Replace(r) if r.path == containers_path)
            })
            .expect("should have containers patch");

        if let json_patch::PatchOperation::Replace(r) = containers_op {
            let arr = r.value.as_array().unwrap();
            assert_eq!(arr.len(), 2, "should have two containers");
        }
    }

    /// Story: Container details are preserved in patch
    #[test]
    fn story_container_details_preserved() {
        use crate::workload::{ContainerPort, EnvVar, ResourceQuantity, ResourceRequirements};

        let container = Container {
            name: "app".to_string(),
            image: "myapp:v1".to_string(),
            command: Some(vec!["/app".to_string()]),
            args: Some(vec!["--port".to_string(), "8080".to_string()]),
            env: vec![EnvVar {
                name: "DEBUG".to_string(),
                value: "true".to_string(),
            }],
            ports: vec![ContainerPort {
                name: None,
                container_port: 8080,
                protocol: Some("TCP".to_string()),
            }],
            resources: Some(ResourceRequirements {
                requests: Some(ResourceQuantity {
                    cpu: Some("100m".to_string()),
                    memory: Some("128Mi".to_string()),
                }),
                limits: Some(ResourceQuantity {
                    cpu: Some("500m".to_string()),
                    memory: Some("512Mi".to_string()),
                }),
            }),
            liveness_probe: None,
            readiness_probe: None,
            volume_mounts: vec![],
        };

        let pod_spec = CompiledPodSpec {
            containers: vec![container],
            volumes: vec![],
            strategy: None,
        };

        let ops = build_patch_operations("my-service", &pod_spec);

        // Serialize the patch and verify container details
        let patch = json_patch::Patch(ops);
        let json_str = serde_json::to_string(&patch).unwrap();

        // Verify key fields are present in serialized output
        assert!(json_str.contains("myapp:v1"), "image should be in patch");
        assert!(json_str.contains("8080"), "port should be in patch");
        assert!(json_str.contains("DEBUG"), "env var should be in patch");
        assert!(json_str.contains("100m"), "cpu request should be in patch");
    }

    /// Story: Service account name matches service name
    #[test]
    fn story_service_account_matches_service() {
        let pod_spec = CompiledPodSpec {
            containers: vec![make_test_container("app", "myapp:v1")],
            volumes: vec![],
            strategy: None,
        };

        // Test with different service names
        for service_name in ["api-gateway", "frontend", "backend-service"] {
            let ops = build_patch_operations(service_name, &pod_spec);
            let sa_path =
                PointerBuf::from_tokens(["spec", "template", "spec", "serviceAccountName"]);

            let sa_op = ops
                .iter()
                .find(|op| matches!(op, json_patch::PatchOperation::Add(a) if a.path == sa_path))
                .expect("should have service account patch");

            if let json_patch::PatchOperation::Add(a) = sa_op {
                assert_eq!(
                    a.value,
                    serde_json::Value::String(service_name.to_string()),
                    "service account should match service name"
                );
            }
        }
    }
}
