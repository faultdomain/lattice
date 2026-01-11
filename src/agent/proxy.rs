//! Kubernetes API proxy over gRPC
//!
//! This module implements a local HTTP server that proxies K8s API requests
//! through the gRPC connection to an agent. This allows tools like `clusterctl`
//! to operate on remote clusters using a standard kubeconfig.
//!
//! # Architecture
//!
//! The proxy is started when an agent connects and stays running for the
//! lifetime of the agent connection. This allows multiple clusterctl/kubectl
//! commands to use the same proxy without re-establishing channels.
//!
//! ```text
//! ┌─────────────────────────┐
//! │   AgentConnection       │
//! │   - proxy_port: u16     │  ← Just stores the port
//! └─────────────────────────┘
//!          │
//!          ▼
//! ┌─────────────────────────┐
//! │  Proxy Server Task      │  ← Owns channels, runs until agent disconnects
//! │  - request_tx           │
//! │  - response_rx          │
//! │  - pending: DashMap     │
//! └─────────────────────────┘
//! ```
//!
//! # Usage
//!
//! 1. Agent connects via `proxy_kubernetes_api` gRPC stream
//! 2. Server calls `start_persistent_proxy` which returns the port
//! 3. Port is stored in `AgentConnection`
//! 4. kubectl/clusterctl commands use kubeconfig pointing to `127.0.0.1:{port}`
//! 5. Proxy runs until agent disconnects

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Method, Response, StatusCode, Uri};
use axum::routing::any;
use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use crate::proto::{HttpHeader, KubeProxyRequest};

/// Proxy errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyError {
    /// Failed to bind to address
    BindFailed(String),
    /// Server failed
    ServerFailed(String),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::BindFailed(e) => write!(f, "failed to bind: {}", e),
            ProxyError::ServerFailed(e) => write!(f, "server failed: {}", e),
        }
    }
}

impl std::error::Error for ProxyError {}

// =============================================================================
// Central Proxy Server
// =============================================================================

use super::connection::SharedAgentRegistry;

/// Default port for the central proxy service
pub const CENTRAL_PROXY_PORT: u16 = 8081;

/// Central proxy state shared across all handlers
struct CentralProxyState {
    registry: SharedAgentRegistry,
}

/// Path parameters for cluster routing
#[derive(serde::Deserialize)]
struct ClusterPath {
    cluster: String,
    path: Option<String>,
}

/// Start the central proxy server
///
/// Routes requests based on path prefix: `/cluster/{cluster_name}/...`
/// Example: `https://lattice-proxy.lattice-system.svc:8081/cluster/my-cluster/api/v1/nodes`
///
/// # Arguments
/// * `registry` - Agent registry for looking up proxy channels
/// * `port` - Port to listen on (use 0 for random)
/// * `cert_pem` - Server certificate PEM
/// * `key_pem` - Server private key PEM
///
/// # Returns
/// The port the server is listening on
pub async fn start_central_proxy(
    registry: SharedAgentRegistry,
    port: u16,
    cert_pem: String,
    key_pem: String,
) -> Result<u16, ProxyError> {
    let bind_addr: std::net::SocketAddr = format!("0.0.0.0:{}", port)
        .parse()
        .map_err(|e| ProxyError::BindFailed(format!("Invalid address: {}", e)))?;

    let state = Arc::new(CentralProxyState { registry });

    // Path-based routing: /cluster/{cluster_name}/{*path}
    // Need all three patterns: with path, trailing slash only, no trailing slash
    // Fallback catches unmatched requests to debug routing issues
    let app = Router::new()
        .route("/cluster/{cluster}/{*path}", any(central_proxy_handler))
        .route("/cluster/{cluster}/", any(central_proxy_handler))
        .route("/cluster/{cluster}", any(central_proxy_handler))
        .fallback(fallback_handler)
        .with_state(state);

    // Configure TLS
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        cert_pem.as_bytes().to_vec(),
        key_pem.as_bytes().to_vec(),
    )
    .await
    .map_err(|e| ProxyError::BindFailed(format!("TLS config failed: {}", e)))?;

    let actual_port = if port == 0 {
        // Bind to get an ephemeral port
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| ProxyError::BindFailed(e.to_string()))?;
        let port = listener
            .local_addr()
            .map_err(|e| ProxyError::BindFailed(e.to_string()))?
            .port();
        drop(listener);
        port
    } else {
        port
    };

    let actual_addr: std::net::SocketAddr = format!("0.0.0.0:{}", actual_port)
        .parse()
        .map_err(|e| ProxyError::BindFailed(format!("Invalid address: {}", e)))?;

    info!(port = actual_port, "Central K8s API proxy (HTTPS) starting");

    // Spawn server task
    tokio::spawn(async move {
        if let Err(e) = axum_server::bind_rustls(actual_addr, tls_config)
            .serve(app.into_make_service())
            .await
        {
            error!(error = %e, "Central proxy server failed");
        }
    });

    Ok(actual_port)
}

/// Handle requests routed to a specific cluster via path prefix
///
/// Supports streaming responses for K8s watch requests.
async fn central_proxy_handler(
    State(state): State<Arc<CentralProxyState>>,
    axum::extract::Path(path_params): axum::extract::Path<ClusterPath>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, StatusCode> {
    use tokio_stream::wrappers::ReceiverStream;

    let cluster_name = &path_params.cluster;

    // Get proxy channels for this cluster
    let channels = state
        .registry
        .get_proxy_channels(cluster_name)
        .ok_or_else(|| {
            warn!(cluster = %cluster_name, "No proxy channels for cluster");
            StatusCode::NOT_FOUND
        })?;

    let request_id = channels.next_request_id(cluster_name);

    // Reconstruct the API path from the remaining path + query string
    let remaining_path = path_params.path.as_deref().unwrap_or("");
    let api_path = if let Some(query) = uri.query() {
        format!("/{}?{}", remaining_path, query)
    } else if remaining_path.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", remaining_path)
    };

    let is_watch = api_path.contains("watch=true");

    debug!(
        request_id = %request_id,
        cluster = %cluster_name,
        method = %method,
        path = %api_path,
        is_watch = is_watch,
        "Central proxy request"
    );

    // Convert headers
    let proto_headers: Vec<HttpHeader> = headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str().ok().map(|v| HttpHeader {
                key: k.to_string(),
                value: v.to_string(),
            })
        })
        .collect();

    // Read body
    let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Create proxy request
    let proxy_request = KubeProxyRequest {
        request_id: request_id.clone(),
        method: method.to_string(),
        path: api_path,
        headers: proto_headers,
        body: body_bytes.to_vec(),
    };

    // Create response channel (mpsc for streaming)
    let (response_tx, mut response_rx) = tokio::sync::mpsc::channel(32);

    // Register pending request
    channels
        .register_pending(request_id.clone(), response_tx)
        .await;

    // Send request to agent
    if let Err(e) = channels.request_tx.send(proxy_request).await {
        error!(error = %e, "Failed to send central proxy request");
        channels.remove_pending(&request_id).await;
        return Err(StatusCode::BAD_GATEWAY);
    }

    // Wait for first response chunk (with timeout for initial response)
    let first_response =
        tokio::time::timeout(std::time::Duration::from_secs(30), response_rx.recv())
            .await
            .map_err(|_| {
                error!(request_id = %request_id, "Central proxy request timeout");
                StatusCode::GATEWAY_TIMEOUT
            })?
            .ok_or_else(|| {
                error!(request_id = %request_id, "Response channel closed");
                StatusCode::BAD_GATEWAY
            })?;

    // Check for proxy error
    if !first_response.error.is_empty() {
        error!(error = %first_response.error, "Central proxy error");
        return Err(StatusCode::BAD_GATEWAY);
    }

    debug!(
        request_id = %request_id,
        status = first_response.status_code,
        is_streaming = first_response.is_streaming,
        "Central proxy response"
    );

    // Build response headers
    let mut builder = Response::builder().status(first_response.status_code as u16);

    for header in &first_response.headers {
        let key_lower = header.key.to_lowercase();
        // Skip headers we'll set ourselves for streaming
        if key_lower == "content-length" || key_lower == "transfer-encoding" {
            continue;
        }
        builder = builder.header(&header.key, &header.value);
    }

    if first_response.is_streaming {
        // Streaming response - use chunked transfer encoding
        builder = builder.header("transfer-encoding", "chunked");

        // Create a stream that yields body chunks
        let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(32);

        // Send first chunk
        let first_body = first_response.body;
        let body_tx_clone = body_tx.clone();
        tokio::spawn(async move {
            if !first_body.is_empty() {
                let _ = body_tx_clone.send(Ok(Bytes::from(first_body))).await;
            }
        });

        // Spawn task to forward remaining chunks
        let request_id_clone = request_id.clone();
        tokio::spawn(async move {
            while let Some(chunk) = response_rx.recv().await {
                if !chunk.body.is_empty() {
                    if body_tx.send(Ok(Bytes::from(chunk.body))).await.is_err() {
                        debug!(request_id = %request_id_clone, "Body channel closed");
                        break;
                    }
                }
                if chunk.is_final {
                    debug!(request_id = %request_id_clone, "Stream complete");
                    break;
                }
            }
        });

        let body_stream = ReceiverStream::new(body_rx);
        builder
            .body(Body::from_stream(body_stream))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        // Non-streaming response
        let body_len = first_response.body.len();
        builder = builder.header("content-length", body_len.to_string());

        builder
            .body(Body::from(first_response.body))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }
}

/// Fallback handler for unmatched routes - logs what's being requested
async fn fallback_handler(method: Method, uri: Uri) -> StatusCode {
    warn!(
        method = %method,
        uri = %uri,
        "Unmatched request to central proxy - expected /cluster/{{name}}/..."
    );
    StatusCode::NOT_FOUND
}

/// Generate kubeconfig YAML for central proxy
///
/// Points to the central proxy service with path-based routing.
/// Example: `https://lattice-proxy.lattice-system.svc:8081/cluster/my-cluster`
/// Includes CA cert for TLS verification.
pub fn generate_central_proxy_kubeconfig(
    cluster_name: &str,
    service_url: &str,
    ca_cert_pem: &str,
) -> String {
    let ca_cert_b64 = STANDARD.encode(ca_cert_pem.as_bytes());
    format!(
        r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    server: {service_url}/cluster/{cluster}
    certificate-authority-data: {ca_cert}
  name: {cluster}
contexts:
- context:
    cluster: {cluster}
    user: {cluster}-user
  name: {cluster}
current-context: {cluster}
users:
- name: {cluster}-user
  user: {{}}
"#,
        service_url = service_url,
        cluster = cluster_name,
        ca_cert = ca_cert_b64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test ProxyError display implementations
    #[test]
    fn test_proxy_error_bind_failed_display() {
        let err = ProxyError::BindFailed("address in use".to_string());
        assert_eq!(err.to_string(), "failed to bind: address in use");
    }

    #[test]
    fn test_proxy_error_server_failed_display() {
        let err = ProxyError::ServerFailed("connection reset".to_string());
        assert_eq!(err.to_string(), "server failed: connection reset");
    }

    #[test]
    fn test_proxy_error_equality() {
        let err1 = ProxyError::BindFailed("test".to_string());
        let err2 = ProxyError::BindFailed("test".to_string());
        let err3 = ProxyError::ServerFailed("test".to_string());

        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_proxy_error_clone() {
        let err = ProxyError::BindFailed("original".to_string());
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn test_proxy_error_debug() {
        let err = ProxyError::BindFailed("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("BindFailed"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_proxy_error_is_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(ProxyError::BindFailed("error".to_string()));
        assert!(err.to_string().contains("failed to bind"));
    }

    // ==========================================================================
    // Central Proxy Tests
    // ==========================================================================

    #[test]
    fn test_generate_central_proxy_kubeconfig() {
        let ca_cert = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----";
        let kubeconfig =
            generate_central_proxy_kubeconfig("my-cluster", "https://proxy.svc:8081", ca_cert);

        assert!(kubeconfig.contains("server: https://proxy.svc:8081/cluster/my-cluster"));
        assert!(kubeconfig.contains("certificate-authority-data:"));
        assert!(kubeconfig.contains("name: my-cluster"));
        assert!(kubeconfig.contains("current-context: my-cluster"));
        assert!(kubeconfig.contains("apiVersion: v1"));
        assert!(kubeconfig.contains("kind: Config"));
    }
}
