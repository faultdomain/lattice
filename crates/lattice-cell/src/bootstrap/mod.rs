//! Bootstrap endpoint for kubeadm callback and CSR signing
//!
//! This module implements HTTP endpoints that run WITHOUT mTLS:
//! - Bootstrap endpoint: kubeadm postKubeadmCommands calls to get manifests
//! - CSR signing endpoint: agents submit CSRs to get signed certificates
//!
//! # Security Model
//!
//! - Endpoints are NON-mTLS (agent doesn't have cert yet)
//! - Bootstrap uses one-time token authentication
//! - CSR signing uses a separate one-time CSR token (issued during bootstrap)
//! - Both tokens use constant-time comparison to prevent timing attacks
//!
//! # Bootstrap Flow
//!
//! 1. Cluster created → bootstrap token generated
//! 2. kubeadm runs postKubeadmCommands
//! 3. Script calls `GET /api/clusters/{id}/manifests` with Bearer token
//! 4. Endpoint validates token, marks as used, generates one-time CSR token
//! 5. Returns: agent manifest, CNI manifest, CA certificate, CSR token (in parent config Secret)
//!
//! # CSR Flow
//!
//! 1. Agent generates keypair locally (private key never leaves agent)
//! 2. Agent reads CSR token from parent config Secret
//! 3. Agent creates CSR and sends to `POST /api/clusters/{id}/csr` with CSR token
//! 4. Cell validates and consumes CSR token, signs CSR, returns certificate
//! 5. Agent uses cert for mTLS connection to gRPC server

pub mod addons;
mod bundle;
mod errors;
mod generator;
mod state;
#[cfg(test)]
mod test_helpers;
mod token;
mod types;

pub use addons::generate_for_provider;
pub use bundle::generate_bootstrap_bundle;
pub use errors::BootstrapError;
pub use generator::DefaultManifestGenerator;
pub use state::{BootstrapConfig, BootstrapState, ClusterBootstrapInfo};
pub use token::BootstrapToken;
pub use types::{BootstrapBundleConfig, BootstrapResponse, ClusterRegistration, ManifestGenerator};

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use tracing::{debug, info, warn};

use lattice_common::crd::validate_dns_label;
use lattice_common::CsrRequest;

use crate::resources::fetch_distributable_resources;

/// Extract bearer token from headers
fn extract_bearer_token(headers: &HeaderMap) -> Result<String, BootstrapError> {
    if !headers.contains_key("authorization") {
        return Err(BootstrapError::MissingAuth);
    }
    lattice_auth::extract_bearer_token(headers)
        .map(|s| s.to_string())
        .ok_or(BootstrapError::InvalidToken)
}

/// CSR signing endpoint handler
///
/// Agents call this endpoint to get their CSR signed after bootstrap.
/// The cluster must have completed bootstrap (token consumed).
pub async fn csr_handler<G: ManifestGenerator>(
    State(state): State<Arc<BootstrapState<G>>>,
    Path(cluster_id): Path<String>,
    Json(request): Json<CsrRequest>,
) -> Result<Json<lattice_common::CsrResponse>, BootstrapError> {
    validate_dns_label(&cluster_id, "cluster_id").map_err(|_| BootstrapError::InvalidToken)?;

    debug!(cluster_id = %cluster_id, "CSR signing request received");

    // Sign the CSR (validates and consumes the one-time CSR token)
    let response = state
        .sign_csr(&cluster_id, &request.csr_pem, &request.csr_token)
        .await?;

    info!(cluster_id = %cluster_id, "CSR signed successfully");

    Ok(Json(response))
}

/// Bootstrap manifests endpoint handler - returns raw YAML for kubectl apply
///
/// This endpoint is called by kubeadm postKubeadmCommands. It validates the
/// one-time token and returns the manifests as concatenated YAML that can
/// be piped directly to `kubectl apply -f -`.
///
/// Includes InfraProvider, SecretProvider CRDs and their referenced secrets
/// from the parent cluster so they're available immediately when the operator starts.
pub async fn bootstrap_manifests_handler<G: ManifestGenerator>(
    State(state): State<Arc<BootstrapState<G>>>,
    Path(cluster_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, BootstrapError> {
    validate_dns_label(&cluster_id, "cluster_id").map_err(|_| BootstrapError::InvalidToken)?;

    debug!(cluster_id = %cluster_id, "Bootstrap manifests request received");

    // Extract token
    let token = extract_bearer_token(&headers)?;

    // Validate and consume the token (also sets bootstrap_complete in CRD)
    let info = state.validate_and_consume(&cluster_id, &token).await?;

    info!(cluster_id = %cluster_id, "Bootstrap token validated, returning manifests");

    // Generate full bootstrap response (includes CNI, operator, LatticeCluster CRD, parent config)
    let response = state.generate_response(&info).await?;

    // Collect all manifests
    let mut all_manifests = response.manifests;

    // Include InfraProvider, SecretProvider, CedarPolicy, OIDCProvider and their referenced secrets
    // This ensures credentials and policies are available when the operator starts, before the gRPC connection
    if let (Some(ref client), Some(ref parent_cluster_name)) =
        (&state.kube_client, &state.cluster_name)
    {
        match fetch_distributable_resources(client, parent_cluster_name).await {
            Ok(resources) => {
                let count = resources.total_count();
                all_manifests.extend(resources.into_json_strings());

                info!(
                    cluster_id = %cluster_id,
                    count,
                    "included distributed resources in bootstrap"
                );
            }
            Err(e) => {
                // Distributable resources are best-effort during bootstrap.
                // They will be synced via the gRPC stream once the agent connects.
                // Failing the entire bootstrap here would consume the one-time token
                // and permanently block the cluster from bootstrapping.
                warn!(
                    cluster_id = %cluster_id,
                    error = %e,
                    "failed to fetch distributable resources, they will sync via gRPC"
                );
            }
        }
    }

    // Join with YAML document separator
    let yaml_output = all_manifests.join("\n---\n");

    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/x-yaml")],
        yaml_output,
    )
        .into_response())
}

/// Create the bootstrap router
///
/// Routes:
/// - `GET /api/clusters/{cluster_id}/manifests` - Get raw YAML manifests for kubectl apply (one-time with token)
/// - `POST /api/clusters/{cluster_id}/csr` - Sign a CSR (after bootstrap)
pub fn bootstrap_router<G: ManifestGenerator + 'static>(
    state: Arc<BootstrapState<G>>,
) -> axum::Router {
    axum::Router::new()
        .route(
            "/api/clusters/{cluster_id}/manifests",
            get(bootstrap_manifests_handler::<G>),
        )
        .route("/api/clusters/{cluster_id}/csr", post(csr_handler::<G>))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024)) // 64 KiB — CSR payloads are small
        // Limit concurrent bootstrap requests to prevent CPU exhaustion via
        // rapid token-hashing attempts. 10 concurrent requests is generous for
        // legitimate bootstrap traffic (clusters bootstrap one at a time).
        .layer(tower::limit::ConcurrencyLimitLayer::new(10))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use lattice_common::CsrResponse;
    use lattice_infra::pki::AgentCertRequest;
    use tower::ServiceExt;

    use super::test_helpers::*;

    #[test]
    fn bearer_token_authentication() {
        // Valid Bearer token
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer my-secret-token"
                .parse()
                .expect("header value parsing should succeed"),
        );
        let token = extract_bearer_token(&headers).expect("bearer token extraction should succeed");
        assert_eq!(token, "my-secret-token");

        // Missing header
        let empty_headers = HeaderMap::new();
        let missing_result = extract_bearer_token(&empty_headers);
        assert!(matches!(missing_result, Err(BootstrapError::MissingAuth)));

        // Wrong auth scheme (Basic instead of Bearer)
        let mut basic_headers = HeaderMap::new();
        basic_headers.insert(
            "authorization",
            "Basic dXNlcjpwYXNz"
                .parse()
                .expect("header value parsing should succeed"),
        );
        let wrong_scheme = extract_bearer_token(&basic_headers);
        assert!(matches!(wrong_scheme, Err(BootstrapError::InvalidToken)));
    }

    // ==========================================================================
    // Integration Tests: HTTP Handlers
    // ==========================================================================

    /// Integration test: bootstrap_router creates valid routes
    #[tokio::test]
    async fn integration_bootstrap_router_creation() {
        let state = Arc::new(test_state());
        let _router = bootstrap_router(state);

        // Router should be created without panic
    }

    /// Integration test: manifests endpoint with valid token
    #[tokio::test]
    async fn integration_manifests_handler_success() {
        let state = Arc::new(test_state());
        let token = register_test_cluster(
            &state,
            "http-test".to_string(),
            "cell:8443:50051".to_string(),
            "ca-cert".to_string(),
        )
        .await;

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/clusters/http-test/manifests")
            .header("authorization", format!("Bearer {}", token.as_str()))
            .body(Body::empty())
            .expect("request building should succeed");

        let response = router
            .oneshot(request)
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::OK);

        // Response is raw YAML for kubectl apply
        let body = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .expect("body reading should succeed");
        let manifests_yaml =
            String::from_utf8(body.to_vec()).expect("response should be valid UTF-8");

        // Should contain test manifest from TestManifestGenerator
        assert!(manifests_yaml.contains("# Test manifest"));
    }

    /// Integration test: manifests endpoint with missing auth
    #[tokio::test]
    async fn integration_manifests_handler_missing_auth() {
        let state = Arc::new(test_state());
        register_test_cluster(
            &state,
            "auth-test".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        )
        .await;

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/clusters/auth-test/manifests")
            // No authorization header
            .body(Body::empty())
            .expect("request building should succeed");

        let response = router
            .oneshot(request)
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Integration test: manifests endpoint with invalid token
    #[tokio::test]
    async fn integration_manifests_handler_invalid_token() {
        let state = Arc::new(test_state());
        register_test_cluster(
            &state,
            "token-test".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        )
        .await;

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/clusters/token-test/manifests")
            .header("authorization", "Bearer wrong-token")
            .body(Body::empty())
            .expect("request building should succeed");

        let response = router
            .oneshot(request)
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Integration test: manifests endpoint for unknown cluster
    #[tokio::test]
    async fn integration_manifests_handler_unknown_cluster() {
        let state = Arc::new(test_state());
        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/clusters/nonexistent/manifests")
            .header("authorization", "Bearer any-token")
            .body(Body::empty())
            .expect("request building should succeed");

        let response = router
            .oneshot(request)
            .await
            .expect("request should succeed");
        // Returns 401 (not 404) to prevent cluster enumeration
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Helper: extract raw CSR token from bootstrap state for a cluster
    fn get_csr_token(
        state: &Arc<BootstrapState<test_helpers::TestManifestGenerator>>,
        cluster_id: &str,
    ) -> String {
        state
            .clusters
            .get(cluster_id)
            .expect("cluster should be registered")
            .csr_token_raw
            .as_ref()
            .expect("CSR token should be set after bootstrap")
            .as_str()
            .to_string()
    }

    /// Integration test: CSR endpoint with valid request
    #[tokio::test]
    async fn integration_csr_handler_success() {
        let state = Arc::new(test_state());

        // Register and bootstrap first
        let token = register_test_cluster(
            &state,
            "csr-http-test".to_string(),
            "cell:8443:50051".to_string(),
            state.ca_trust_bundle_pem().await,
        )
        .await;
        state
            .validate_and_consume("csr-http-test", token.as_str())
            .await
            .expect("token validation should succeed");

        let csr_tok = get_csr_token(&state, "csr-http-test");

        // Generate CSR
        let agent_req = AgentCertRequest::new("csr-http-test")
            .expect("agent cert request creation should succeed");
        let csr_request = CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
            csr_token: csr_tok,
        };

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/api/clusters/csr-http-test/csr")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&csr_request).expect("JSON serialization should succeed"),
            ))
            .expect("request building should succeed");

        let response = router
            .oneshot(request)
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::OK);

        // Parse response
        let body = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .expect("body reading should succeed");
        let csr_response: CsrResponse =
            serde_json::from_slice(&body).expect("JSON parsing should succeed");

        assert!(csr_response.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(csr_response
            .ca_certificate_pem
            .contains("BEGIN CERTIFICATE"));
    }

    /// Integration test: CSR endpoint before bootstrap
    #[tokio::test]
    async fn integration_csr_handler_before_bootstrap() {
        let state = Arc::new(test_state());

        // Register but DON'T bootstrap
        register_test_cluster(
            &state,
            "not-bootstrapped".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        )
        .await;

        let agent_req = AgentCertRequest::new("not-bootstrapped")
            .expect("agent cert request creation should succeed");
        let csr_request = CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
            csr_token: "dummy-token".to_string(),
        };

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/api/clusters/not-bootstrapped/csr")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&csr_request).expect("JSON serialization should succeed"),
            ))
            .expect("request building should succeed");

        let response = router
            .oneshot(request)
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    }

    /// Integration test: CSR endpoint for unknown cluster
    #[tokio::test]
    async fn integration_csr_handler_unknown_cluster() {
        let state = Arc::new(test_state());

        let agent_req =
            AgentCertRequest::new("unknown").expect("agent cert request creation should succeed");
        let csr_request = CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
            csr_token: "dummy-token".to_string(),
        };

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/api/clusters/unknown/csr")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&csr_request).expect("JSON serialization should succeed"),
            ))
            .expect("request building should succeed");

        let response = router
            .oneshot(request)
            .await
            .expect("request should succeed");
        // Returns 401 (not 404) to prevent cluster enumeration
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Integration test: Full HTTP bootstrap flow (manifests + CSR)
    #[tokio::test]
    async fn integration_full_http_bootstrap_flow() {
        let state = Arc::new(test_state());
        let ca_cert = state.ca_trust_bundle_pem().await;

        // Step 1: Register cluster
        let token = register_test_cluster(
            &state,
            "full-flow-test".to_string(),
            "cell.example.com:8443:50051".to_string(),
            ca_cert.clone(),
        )
        .await;

        let router = bootstrap_router(state.clone());

        // Step 2: Get manifests (returns raw YAML for kubectl apply)
        let manifests_request = Request::builder()
            .method("GET")
            .uri("/api/clusters/full-flow-test/manifests")
            .header("authorization", format!("Bearer {}", token.as_str()))
            .body(Body::empty())
            .expect("request building should succeed");

        let response = router
            .clone()
            .oneshot(manifests_request)
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .expect("body reading should succeed");
        let manifests_yaml =
            String::from_utf8(body.to_vec()).expect("response should be valid UTF-8");
        // Manifest contains image from TestManifestGenerator, not cluster ID
        assert!(manifests_yaml.contains("# Test manifest"));
        // Manifests should include the CSR token in the parent config secret
        assert!(manifests_yaml.contains("csr_token"));

        // Step 3: CSR signing (using the CSR token from bootstrap)
        let csr_tok = get_csr_token(&state, "full-flow-test");
        let agent_req = AgentCertRequest::new("full-flow-test")
            .expect("agent cert request creation should succeed");
        let csr_body = serde_json::to_string(&CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
            csr_token: csr_tok,
        })
        .expect("JSON serialization should succeed");

        let csr_request = Request::builder()
            .method("POST")
            .uri("/api/clusters/full-flow-test/csr")
            .header("content-type", "application/json")
            .body(Body::from(csr_body))
            .expect("request building should succeed");

        let response = router
            .oneshot(csr_request)
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .expect("body reading should succeed");
        let csr_response: CsrResponse =
            serde_json::from_slice(&body).expect("JSON parsing should succeed");
        assert!(csr_response.certificate_pem.contains("BEGIN CERTIFICATE"));
    }
}
