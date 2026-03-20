//! Auth proxy server

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{any, get};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use tower::limit::ConcurrencyLimitLayer;
use tracing::info;

use crate::auth_chain::AuthChain;
use crate::backend::ProxyBackend;
use crate::error::Error;
use crate::kubeconfig::kubeconfig_handler;
use crate::portforward::portforward_handler;
use crate::proxy::{exec_handler, proxy_handler};
use lattice_cedar::PolicyEngine;

/// Maximum number of concurrent proxy requests (K8s API forwarding).
/// Prevents resource exhaustion from brute-force or flood attacks.
const MAX_CONCURRENT_PROXY_REQUESTS: usize = 100;

/// Maximum number of concurrent exec/attach/portforward sessions.
/// These are long-lived WebSocket connections that each hold a gRPC stream,
/// so a lower limit than general proxy requests is appropriate.
const MAX_CONCURRENT_EXEC_SESSIONS: usize = 20;

/// Server configuration
#[derive(Clone)]
pub struct ServerConfig {
    /// Address to bind the server
    pub addr: SocketAddr,
    /// TLS certificate PEM
    pub cert_pem: String,
    /// TLS private key PEM (zeroized on drop)
    pub key_pem: zeroize::Zeroizing<String>,
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
    /// Proxy backend for cluster routing and tunneling
    pub backend: Arc<dyn ProxyBackend>,
    /// Base URL for kubeconfig generation
    pub base_url: String,
    /// CA certificate (base64 encoded) for kubeconfig generation
    pub ca_cert_base64: String,
}

/// Start the auth proxy server
pub async fn start_server(
    config: ServerConfig,
    auth: Arc<AuthChain>,
    cedar: Arc<PolicyEngine>,
    backend: Arc<dyn ProxyBackend>,
) -> Result<(), Error> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    // Base64 encode CA cert for kubeconfig
    let ca_cert_base64 = STANDARD.encode(&config.ca_cert_pem);

    let state = AppState {
        auth,
        cedar,
        k8s_api_url: config.k8s_api_url.clone(),
        cluster_name: config.cluster_name.clone(),
        backend,
        base_url: config.base_url.clone(),
        ca_cert_base64,
    };

    // Exec/attach/portforward routes with a separate, lower concurrency limit
    // (these are long-lived WebSocket sessions that hold gRPC streams)
    let exec_routes = Router::new()
        .route(
            "/clusters/{cluster_name}/api/v1/namespaces/{ns}/pods/{pod}/exec",
            any(exec_handler),
        )
        .route(
            "/clusters/{cluster_name}/api/v1/namespaces/{ns}/pods/{pod}/attach",
            any(exec_handler),
        )
        .route(
            "/clusters/{cluster_name}/api/v1/namespaces/{ns}/pods/{pod}/portforward",
            any(portforward_handler),
        )
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_EXEC_SESSIONS));

    // Health check lives outside the concurrency-limited router so that
    // Kubernetes liveness probes always succeed, even under full load.
    let healthz = Router::new().route("/healthz", get(|| async { "ok" }));

    let limited_routes = Router::new()
        // Kubeconfig generation
        .route("/kubeconfig", get(kubeconfig_handler))
        // Exec/attach/portforward with dedicated concurrency limit
        .merge(exec_routes)
        // K8s API proxy - route all cluster paths to the proxy handler
        .route("/clusters/{cluster_name}", any(proxy_handler))
        .route("/clusters/{cluster_name}/{*path}", any(proxy_handler))
        .with_state(state)
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_PROXY_REQUESTS));

    let app = healthz.merge(limited_routes);

    let tls_config = RustlsConfig::from_pem(
        config.cert_pem.into_bytes(),
        config.key_pem.as_bytes().to_vec(),
    )
    .await
    .map_err(|e| Error::Config(format!("TLS config error: {}", e)))?;

    info!(addr = %config.addr, "Starting auth proxy server");

    // Bind with TCP keepalive so clients detect dead connections faster
    // in the SIGKILL/OOM case where graceful shutdown can't run.
    let listener = std::net::TcpListener::bind(config.addr)
        .map_err(|e| Error::Internal(format!("Failed to bind: {}", e)))?;
    let socket = socket2::Socket::from(listener);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(30))
        .with_interval(std::time::Duration::from_secs(10));
    socket
        .set_tcp_keepalive(&keepalive)
        .map_err(|e| Error::Internal(format!("Failed to set TCP keepalive: {}", e)))?;
    let listener: std::net::TcpListener = socket.into();

    // Handle for graceful shutdown — on SIGTERM/SIGINT, immediately drop all
    // connections so clients (istiod, kubectl) get EOF and reconnect to the
    // new pod instead of hanging on a half-open connection forever.
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to listen for SIGTERM");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT, closing all proxy connections");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, closing all proxy connections");
            }
        }
        shutdown_handle.shutdown();
    });

    axum_server::from_tcp_rustls(listener, tls_config)
        .handle(handle)
        .serve(app.into_make_service())
        .await
        .map_err(|e| Error::Internal(format!("Server error: {}", e)))?;

    Ok(())
}
