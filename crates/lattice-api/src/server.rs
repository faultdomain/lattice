//! Auth proxy server
//!
//! Uses a raw TcpListener + tokio-rustls + hyper so we own every connection
//! and can send HTTP/2 GOAWAY frames on shutdown.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::routing::{any, get};
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tower::limit::ConcurrencyLimitLayer;
use tracing::{debug, info, warn};

use crate::auth_chain::AuthChain;
use crate::backend::ProxyBackend;
use crate::error::Error;
use crate::kubeconfig::kubeconfig_handler;
use crate::portforward::portforward_handler;
use crate::proxy::{exec_handler, proxy_handler};
use lattice_cedar::PolicyEngine;

/// Maximum number of concurrent proxy requests (K8s API forwarding).
const MAX_CONCURRENT_PROXY_REQUESTS: usize = 100;

/// Maximum number of concurrent exec/attach/portforward sessions.
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
    /// Base URL for kubeconfig generation
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

/// Handle for graceful shutdown — sends GOAWAY to every HTTP/2 connection.
pub struct ProxyHandle {
    shutdown: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl ProxyHandle {
    /// Wait for the server task to exit (crash or shutdown).
    /// Does NOT trigger shutdown — use this in the supervisor loop.
    pub async fn wait(self) {
        let _ = self.task.await;
    }

    /// Send GOAWAY to all connections and wait for drain (up to timeout).
    pub async fn graceful_shutdown(self, timeout: std::time::Duration) {
        self.shutdown.notify_one();
        let _ = tokio::time::timeout(timeout, self.task).await;
    }
}

/// Start the auth proxy server. Returns a handle for graceful shutdown.
pub async fn start_server(
    config: ServerConfig,
    auth: Arc<AuthChain>,
    cedar: Arc<PolicyEngine>,
    backend: Arc<dyn ProxyBackend>,
) -> Result<ProxyHandle, Error> {
    use base64::{engine::general_purpose::STANDARD, Engine};

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

    let healthz = Router::new().route("/healthz", get(|| async { "ok" }));

    let limited_routes = Router::new()
        .route("/kubeconfig", get(kubeconfig_handler))
        .merge(exec_routes)
        .route("/clusters/{cluster_name}", any(proxy_handler))
        .route("/clusters/{cluster_name}/{*path}", any(proxy_handler))
        .with_state(state)
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_PROXY_REQUESTS));

    let app = healthz.merge(limited_routes);

    let tls_config = build_tls_config(&config.cert_pem, &config.key_pem)?;
    let listener = bind_with_keepalive(config.addr)?;

    info!(addr = %config.addr, "Starting auth proxy server");

    let shutdown = Arc::new(Notify::new());
    let task = tokio::spawn(accept_loop(listener, tls_config, app, shutdown.clone()));

    Ok(ProxyHandle { shutdown, task })
}

async fn accept_loop(
    listener: TcpListener,
    tls_config: Arc<rustls::ServerConfig>,
    app: Router,
    shutdown: Arc<Notify>,
) {
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
    let builder = Arc::new(Builder::new(TokioExecutor::new()));

    // Per-connection shutdown notifiers so we can GOAWAY each one individually.
    let conn_shutdowns: Arc<dashmap::DashMap<u64, Arc<Notify>>> = Arc::new(dashmap::DashMap::new());
    let mut next_id: u64 = 0;

    loop {
        let tcp_stream = tokio::select! {
            biased;
            _ = shutdown.notified() => break,
            result = listener.accept() => {
                match result {
                    Ok((stream, _addr)) => stream,
                    Err(e) => {
                        warn!(error = %e, "Failed to accept TCP connection");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        continue;
                    }
                }
            }
        };

        let tls_acceptor = tls_acceptor.clone();
        let builder = builder.clone();
        let app = app.clone();
        let conn_shutdowns = conn_shutdowns.clone();
        let conn_id = next_id;
        next_id += 1;

        let conn_notify = Arc::new(Notify::new());
        conn_shutdowns.insert(conn_id, conn_notify.clone());

        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    debug!(error = %e, "TLS handshake failed");
                    conn_shutdowns.remove(&conn_id);
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let hyper_svc = TowerToHyperService::new(app);
            let conn = builder.serve_connection_with_upgrades(io, hyper_svc);
            tokio::pin!(conn);

            tokio::select! {
                biased;
                _ = conn_notify.notified() => {
                    conn.as_mut().graceful_shutdown();
                    let _ = conn.await;
                }
                result = &mut conn => {
                    if let Err(e) = result {
                        debug!(error = %e, "Connection error");
                    }
                }
            }

            conn_shutdowns.remove(&conn_id);
        });
    }

    // Signal every active connection to send GOAWAY
    info!(
        active_connections = conn_shutdowns.len(),
        "Sending GOAWAY to all connections"
    );
    for entry in conn_shutdowns.iter() {
        entry.value().notify_one();
    }

    // Wait for all connections to drain
    while !conn_shutdowns.is_empty() {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    info!("All proxy connections drained");
}

fn build_tls_config(cert_pem: &str, key_pem: &str) -> Result<Arc<rustls::ServerConfig>, Error> {
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Error::Config(format!("Failed to parse TLS cert: {}", e)))?;

    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| Error::Config(format!("Failed to parse TLS key: {}", e)))?
        .ok_or_else(|| Error::Config("No private key found in PEM".to_string()))?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::Config(format!("TLS config error: {}", e)))?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

fn bind_with_keepalive(addr: SocketAddr) -> Result<TcpListener, Error> {
    let listener = std::net::TcpListener::bind(addr)
        .map_err(|e| Error::Internal(format!("Failed to bind: {}", e)))?;
    let socket = socket2::Socket::from(listener);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(30))
        .with_interval(std::time::Duration::from_secs(10));
    socket
        .set_tcp_keepalive(&keepalive)
        .map_err(|e| Error::Internal(format!("Failed to set TCP keepalive: {}", e)))?;
    let listener: std::net::TcpListener = socket.into();
    listener
        .set_nonblocking(true)
        .map_err(|e| Error::Internal(format!("Failed to set nonblocking: {}", e)))?;
    TcpListener::from_std(listener)
        .map_err(|e| Error::Internal(format!("Failed to create tokio listener: {}", e)))
}
