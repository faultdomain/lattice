//! Auth proxy server

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{any, get};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use tracing::info;

use crate::auth::OidcConfig;
use crate::auth_chain::AuthChain;
use crate::cedar::PolicyEngine;
use crate::error::Error;
use crate::kubeconfig::kubeconfig_handler;
use crate::proxy::{exec_handler, proxy_handler};

// Re-export from lattice-cell for convenience
pub use lattice_cell::subtree_registry::{ClusterInfo, RouteInfo, SubtreeRegistry};
pub use lattice_cell::SharedAgentRegistry;

/// Server configuration
#[derive(Clone)]
pub struct ServerConfig {
    /// Address to bind the server
    pub addr: SocketAddr,
    /// TLS certificate PEM
    pub cert_pem: String,
    /// TLS private key PEM
    pub key_pem: String,
    /// CA certificate PEM - included in generated kubeconfigs for TLS verification
    pub ca_cert_pem: String,
    /// Kubernetes API server URL (for proxying to self)
    pub k8s_api_url: String,
    /// This cluster's name
    pub cluster_name: String,
    /// Base URL for kubeconfig generation (e.g., "https://lattice.example.com")
    pub base_url: String,
}

/// Shared state for handlers
#[derive(Clone)]
pub struct AppState {
    /// Authentication chain (OIDC + ServiceAccount fallback)
    pub auth: Arc<AuthChain>,
    /// Cedar policy engine
    pub cedar: Arc<PolicyEngine>,
    /// Kubernetes API server URL
    pub k8s_api_url: String,
    /// This cluster's name
    pub cluster_name: String,
    /// Subtree registry (clusters we can route to)
    pub subtree: Arc<SubtreeRegistry>,
    /// Agent registry for routing to child clusters (optional)
    pub agent_registry: Option<SharedAgentRegistry>,
    /// Base URL for kubeconfig generation
    pub base_url: String,
    /// OIDC configuration for kubeconfig exec plugin
    pub oidc_config: Option<OidcConfig>,
    /// CA certificate (base64 encoded) for kubeconfig generation
    pub ca_cert_base64: String,
}

/// Start the auth proxy server
pub async fn start_server(
    config: ServerConfig,
    auth: Arc<AuthChain>,
    cedar: Arc<PolicyEngine>,
    subtree: Arc<SubtreeRegistry>,
) -> Result<(), Error> {
    start_server_with_registry(config, auth, cedar, subtree, None).await
}

/// Start the auth proxy server with optional agent registry for child cluster routing
pub async fn start_server_with_registry(
    config: ServerConfig,
    auth: Arc<AuthChain>,
    cedar: Arc<PolicyEngine>,
    subtree: Arc<SubtreeRegistry>,
    agent_registry: Option<SharedAgentRegistry>,
) -> Result<(), Error> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    // Get OIDC config for kubeconfig generation
    let oidc_config = auth.oidc_config().cloned();

    // Base64 encode CA cert for kubeconfig
    let ca_cert_base64 = STANDARD.encode(&config.ca_cert_pem);

    let state = AppState {
        auth,
        cedar,
        k8s_api_url: config.k8s_api_url.clone(),
        cluster_name: config.cluster_name.clone(),
        subtree,
        agent_registry,
        base_url: config.base_url.clone(),
        oidc_config,
        ca_cert_base64,
    };

    let app = Router::new()
        // Kubeconfig generation
        .route("/kubeconfig", get(kubeconfig_handler))
        // Health check
        .route("/healthz", get(|| async { "ok" }))
        // Exec/attach/portforward - WebSocket upgrade routes (must be before generic proxy)
        // These match paths like /clusters/{cluster}/api/v1/namespaces/{ns}/pods/{pod}/exec
        .route(
            "/clusters/{cluster_name}/api/v1/namespaces/{ns}/pods/{pod}/exec",
            get(exec_handler),
        )
        .route(
            "/clusters/{cluster_name}/api/v1/namespaces/{ns}/pods/{pod}/attach",
            get(exec_handler),
        )
        .route(
            "/clusters/{cluster_name}/api/v1/namespaces/{ns}/pods/{pod}/portforward",
            get(exec_handler),
        )
        // K8s API proxy - route all cluster paths to the proxy handler
        .route("/clusters/{cluster_name}", any(proxy_handler))
        .route("/clusters/{cluster_name}/{*path}", any(proxy_handler))
        .with_state(state);

    let tls_config =
        RustlsConfig::from_pem(config.cert_pem.into_bytes(), config.key_pem.into_bytes())
            .await
            .map_err(|e| Error::Config(format!("TLS config error: {}", e)))?;

    info!(addr = %config.addr, "Starting auth proxy server");

    axum_server::bind_rustls(config.addr, tls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| Error::Internal(format!("Server error: {}", e)))?;

    Ok(())
}
