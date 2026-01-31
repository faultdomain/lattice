//! Auth proxy server

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{any, get};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use tracing::info;

use crate::auth::{OidcConfig, OidcValidator};
use crate::cedar::PolicyEngine;
use crate::error::Error;
use crate::kubeconfig::kubeconfig_handler;
use crate::proxy::proxy_handler;

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
    /// OIDC token validator
    pub oidc: Arc<OidcValidator>,
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
}

/// Start the auth proxy server
pub async fn start_server(
    config: ServerConfig,
    oidc: Arc<OidcValidator>,
    cedar: Arc<PolicyEngine>,
    subtree: Arc<SubtreeRegistry>,
) -> Result<(), Error> {
    start_server_with_registry(config, oidc, cedar, subtree, None).await
}

/// Start the auth proxy server with optional agent registry for child cluster routing
pub async fn start_server_with_registry(
    config: ServerConfig,
    oidc: Arc<OidcValidator>,
    cedar: Arc<PolicyEngine>,
    subtree: Arc<SubtreeRegistry>,
    agent_registry: Option<SharedAgentRegistry>,
) -> Result<(), Error> {
    // Get OIDC config for kubeconfig generation
    let oidc_config = if !oidc.config().issuer_url.is_empty() {
        Some(oidc.config().clone())
    } else {
        None
    };

    let state = AppState {
        oidc,
        cedar,
        k8s_api_url: config.k8s_api_url.clone(),
        cluster_name: config.cluster_name.clone(),
        subtree,
        agent_registry,
        base_url: config.base_url.clone(),
        oidc_config,
    };

    let app = Router::new()
        // Kubeconfig generation
        .route("/kubeconfig", get(kubeconfig_handler))
        // Health check
        .route("/healthz", get(|| async { "ok" }))
        // K8s API proxy - cluster access
        .route("/clusters/{cluster_name}/api", any(proxy_handler))
        .route("/clusters/{cluster_name}/api/{*path}", any(proxy_handler))
        .route("/clusters/{cluster_name}/apis", any(proxy_handler))
        .route("/clusters/{cluster_name}/apis/{*path}", any(proxy_handler))
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
