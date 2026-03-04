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
//! - CSR signing validates cluster is registered
//!
//! # Bootstrap Flow
//!
//! 1. Cluster created → bootstrap token generated
//! 2. kubeadm runs postKubeadmCommands
//! 3. Script calls `GET /api/clusters/{id}/manifests` with Bearer token
//! 4. Endpoint validates token, marks as used
//! 5. Returns: agent manifest, CNI manifest, CA certificate
//!
//! # CSR Flow
//!
//! 1. Agent generates keypair locally (private key never leaves agent)
//! 2. Agent creates CSR and sends to `POST /api/clusters/{id}/csr`
//! 3. Cell signs CSR with CA and returns certificate
//! 4. Agent uses cert for mTLS connection to gRPC server

mod addons;
mod bundle;
mod errors;
mod generator;
mod state;
mod token;
mod types;

// Re-export everything so external consumers don't break
pub use addons::{
    generate_autoscaler_manifests, generate_aws_addon_manifests, generate_docker_addon_manifests,
};
pub use bundle::generate_bootstrap_bundle;
pub use errors::BootstrapError;
pub use generator::DefaultManifestGenerator;
pub use state::{BootstrapState, ClusterBootstrapInfo};
pub use token::BootstrapToken;
pub use types::{BootstrapBundleConfig, BootstrapResponse, ClusterRegistration, ManifestGenerator};

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use tracing::{debug, info, warn};

use lattice_common::CsrRequest;

use crate::resources::fetch_distributable_resources;

/// Extract bearer token from headers
fn extract_bearer_token(headers: &HeaderMap) -> Result<String, BootstrapError> {
    let auth_header = headers
        .get("authorization")
        .ok_or(BootstrapError::MissingAuth)?;

    let auth_str = auth_header
        .to_str()
        .map_err(|_| BootstrapError::InvalidToken)?;

    auth_str
        .strip_prefix("Bearer ")
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
    debug!(cluster_id = %cluster_id, "CSR signing request received");

    // Sign the CSR
    let response = state.sign_csr(&cluster_id, &request.csr_pem).await?;

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
    if let Some(ref client) = state.kube_client {
        let parent_cluster_name =
            std::env::var("CLUSTER_NAME").unwrap_or_else(|_| "unknown".to_string());
        match fetch_distributable_resources(client, &parent_cluster_name).await {
            Ok(resources) => {
                let cp_count = resources.cloud_providers.len();
                let sp_count = resources.secrets_providers.len();
                let secret_count = resources.secrets.len();
                let cedar_count = resources.cedar_policies.len();
                let oidc_count = resources.oidc_providers.len();

                // Add secrets first (credentials needed by providers)
                for secret_bytes in resources.secrets {
                    if let Ok(json) = String::from_utf8(secret_bytes) {
                        all_manifests.push(json);
                    }
                }

                // Add InfraProviders
                for cp_bytes in resources.cloud_providers {
                    if let Ok(json) = String::from_utf8(cp_bytes) {
                        all_manifests.push(json);
                    }
                }

                // Add SecretProviders
                for sp_bytes in resources.secrets_providers {
                    if let Ok(json) = String::from_utf8(sp_bytes) {
                        all_manifests.push(json);
                    }
                }

                // Add CedarPolicies (inherited from parent)
                for cedar_bytes in resources.cedar_policies {
                    if let Ok(json) = String::from_utf8(cedar_bytes) {
                        all_manifests.push(json);
                    }
                }

                // Add OIDCProviders (inherited from parent)
                for oidc_bytes in resources.oidc_providers {
                    if let Ok(json) = String::from_utf8(oidc_bytes) {
                        all_manifests.push(json);
                    }
                }

                info!(
                    cluster_id = %cluster_id,
                    cloud_providers = cp_count,
                    secrets_providers = sp_count,
                    cedar_policies = cedar_count,
                    oidc_providers = oidc_count,
                    secrets = secret_count,
                    "included distributed resources in bootstrap"
                );
            }
            Err(e) => {
                // Log but don't fail - operator can still sync later via gRPC
                warn!(
                    cluster_id = %cluster_id,
                    error = %e,
                    "failed to fetch distributed resources, credentials may be delayed"
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
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use lattice_common::crd::ProviderType;
    use lattice_common::CsrResponse;
    use lattice_infra::pki::{AgentCertRequest, CertificateAuthority, CertificateAuthorityBundle};
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    struct TestManifestGenerator;

    #[async_trait::async_trait]
    impl ManifestGenerator for TestManifestGenerator {
        async fn generate(
            &self,
            image: &str,
            _registry_credentials: Option<&str>,
            _cluster_name: Option<&str>,
            _provider: Option<ProviderType>,
        ) -> Vec<String> {
            vec![format!("# Test manifest with image {}", image)]
        }
    }

    fn test_ca_bundle() -> Arc<RwLock<CertificateAuthorityBundle>> {
        let ca = CertificateAuthority::new("Test CA").expect("test CA creation should succeed");
        Arc::new(RwLock::new(CertificateAuthorityBundle::new(ca)))
    }

    fn test_state() -> BootstrapState<TestManifestGenerator> {
        BootstrapState::new(
            TestManifestGenerator,
            Duration::from_secs(3600),
            test_ca_bundle(),
            "test:latest".to_string(),
            None,
            None,
        )
    }

    /// Test helper to register cluster without networking config
    async fn register_test_cluster<G: ManifestGenerator>(
        state: &BootstrapState<G>,
        cluster_id: impl Into<String>,
        cell_endpoint: impl Into<String>,
        ca_certificate: impl Into<String>,
    ) -> BootstrapToken {
        let cluster_manifest = r#"{"apiVersion":"lattice.dev/v1alpha1","kind":"LatticeCluster","metadata":{"name":"test"}}"#.to_string();
        state
            .register_cluster(
                ClusterRegistration {
                    cluster_id: cluster_id.into(),
                    cell_endpoint: cell_endpoint.into(),
                    ca_certificate: ca_certificate.into(),
                    cluster_manifest,
                    lb_cidr: None,
                    provider: ProviderType::Docker,
                    bootstrap: lattice_common::crd::BootstrapProvider::default(),
                    k8s_version: "1.32.0".to_string(),
                    autoscaling_enabled: false,
                },
                None,
            )
            .await
    }

    #[test]
    fn bearer_token_extracted_correctly() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer test-token-123"
                .parse()
                .expect("header value parsing should succeed"),
        );

        let token = extract_bearer_token(&headers).expect("bearer token extraction should succeed");
        assert_eq!(token, "test-token-123");
    }

    #[test]
    fn missing_auth_header_rejected() {
        let headers = HeaderMap::new();
        let result = extract_bearer_token(&headers);
        assert!(matches!(result, Err(BootstrapError::MissingAuth)));
    }

    #[test]
    fn non_bearer_auth_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Basic abc123"
                .parse()
                .expect("header value parsing should succeed"),
        );

        let result = extract_bearer_token(&headers);
        assert!(matches!(result, Err(BootstrapError::InvalidToken)));
    }

    /// Story: HTTP API - Bearer token extraction
    ///
    /// The bootstrap endpoint uses standard Bearer token authentication.
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
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
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

        // Generate CSR
        let agent_req = AgentCertRequest::new("csr-http-test")
            .expect("agent cert request creation should succeed");
        let csr_request = CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
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
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
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

        let router = bootstrap_router(state);

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

        // Step 3: CSR signing
        let agent_req = AgentCertRequest::new("full-flow-test")
            .expect("agent cert request creation should succeed");
        let csr_body = serde_json::to_string(&CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
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
