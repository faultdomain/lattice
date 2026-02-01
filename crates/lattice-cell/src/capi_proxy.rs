//! Read-only K8s API proxy for air-gapped pivot support
//!
//! Proxies K8s API requests through the gRPC tunnel to agents.
//! Only active during pre-pivot phase. Read-only operations only.
//!
//! # Architecture
//!
//! ```text
//! CAPI Controller --> Proxy Server --> gRPC Tunnel --> Agent --> Child K8s API
//!      (GET/LIST/WATCH)    :8081        (outbound)              (local)
//! ```
//!
//! # Security
//!
//! - **Read-only only**: Only GET, LIST, WATCH operations allowed
//! - **Pre-pivot only**: Proxy only active when `pivot_complete = false`
//! - **mTLS**: Proxy endpoint uses same CA as bootstrap/gRPC servers

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use tracing::{debug, info, warn};

use crate::connection::SharedAgentRegistry;
use crate::k8s_tunnel::{tunnel_request, K8sRequestParams, TunnelError};

/// Proxy server configuration
#[derive(Clone)]
pub struct CapiProxyConfig {
    /// Address to bind the proxy server
    pub addr: SocketAddr,
    /// TLS certificate PEM
    pub cert_pem: String,
    /// TLS private key PEM
    pub key_pem: String,
}

/// Shared state for proxy handlers
#[derive(Clone)]
struct ProxyState {
    registry: SharedAgentRegistry,
}

/// Error type for proxy operations
#[derive(Debug, thiserror::Error)]
pub enum CapiProxyError {
    /// Agent not connected
    #[error("agent not connected for cluster: {0}")]
    AgentNotConnected(String),

    /// Cluster already pivoted
    #[error("cluster already pivoted: {0}")]
    AlreadyPivoted(String),

    /// Method not allowed (non-read operation)
    #[error("method not allowed: {0}")]
    MethodNotAllowed(String),

    /// Tunnel error
    #[error("{0}")]
    Tunnel(#[from] TunnelError),

    /// TLS configuration error
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    /// Server error
    #[error("server error: {0}")]
    Server(String),
}

impl IntoResponse for CapiProxyError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            CapiProxyError::AgentNotConnected(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, self.to_string())
            }
            CapiProxyError::AlreadyPivoted(_) => (StatusCode::GONE, self.to_string()),
            CapiProxyError::MethodNotAllowed(_) => {
                (StatusCode::METHOD_NOT_ALLOWED, self.to_string())
            }
            CapiProxyError::Tunnel(e) => (e.status_code(), self.to_string()),
            CapiProxyError::TlsConfig(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            CapiProxyError::Server(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        // Build the error response - the fallback uses default() which is infallible
        Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(Body::from(format!(
                r#"{{"kind":"Status","apiVersion":"v1","status":"Failure","message":"{}","code":{}}}"#,
                message,
                status.as_u16()
            )))
            .unwrap_or_else(|_| {
                let mut response = Response::default();
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                response
            })
    }
}

/// Start the read-only K8s API proxy server
pub async fn start_capi_proxy(
    registry: SharedAgentRegistry,
    config: CapiProxyConfig,
) -> Result<(), CapiProxyError> {
    let state = ProxyState { registry };

    let app = Router::new()
        .route("/clusters/{cluster_name}", any(proxy_handler))
        .route("/clusters/{cluster_name}/{*path}", any(proxy_handler))
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .with_state(state);

    let tls_config =
        RustlsConfig::from_pem(config.cert_pem.into_bytes(), config.key_pem.into_bytes())
            .await
            .map_err(|e| CapiProxyError::TlsConfig(e.to_string()))?;

    info!(addr = %config.addr, "Starting K8s API proxy server");

    axum_server::bind_rustls(config.addr, tls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| CapiProxyError::Server(e.to_string()))?;

    Ok(())
}

/// Check if a method is allowed (read-only)
fn is_read_only_method(method: &Method) -> bool {
    matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS)
}

/// Extract path parameters from axum
#[derive(serde::Deserialize)]
struct ProxyPathParams {
    cluster_name: String,
    #[serde(default)]
    path: String,
}

/// Handle proxy requests
async fn proxy_handler(
    State(state): State<ProxyState>,
    Path(params): Path<ProxyPathParams>,
    request: Request<Body>,
) -> Result<Response<Body>, CapiProxyError> {
    let cluster_name = &params.cluster_name;
    let method = request.method().clone();
    let uri = request.uri().clone();
    let query = uri.query().unwrap_or("");

    debug!(
        cluster = %cluster_name,
        method = %method,
        path = %params.path,
        query = ?query,
        "Proxy request received"
    );

    // Check if method is read-only
    if !is_read_only_method(&method) {
        warn!(
            cluster = %cluster_name,
            method = %method,
            "Rejected non-read proxy request"
        );
        return Err(CapiProxyError::MethodNotAllowed(method.to_string()));
    }

    // Look up agent in registry
    let agent = state.registry.get(cluster_name).ok_or_else(|| {
        debug!(cluster = %cluster_name, "Agent not connected");
        CapiProxyError::AgentNotConnected(cluster_name.clone())
    })?;

    // Check if pivot is already complete
    if agent.pivot_complete {
        warn!(
            cluster = %cluster_name,
            "Rejected proxy request for already-pivoted cluster"
        );
        return Err(CapiProxyError::AlreadyPivoted(cluster_name.clone()));
    }

    let command_tx = agent.command_tx.clone();
    drop(agent);

    // Build the API path
    let api_path = if params.path.is_empty() {
        "/".to_string()
    } else if params.path.starts_with('/') {
        params.path
    } else {
        format!("/{}", params.path)
    };

    // Use shared tunnel logic
    let result = tunnel_request(
        &state.registry,
        cluster_name,
        command_tx,
        K8sRequestParams {
            method: method.to_string(),
            path: api_path,
            query: query.to_string(),
            body: Vec::new(), // Read-only, no body
            content_type: String::new(),
        },
    )
    .await?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_read_only_method() {
        assert!(is_read_only_method(&Method::GET));
        assert!(is_read_only_method(&Method::HEAD));
        assert!(is_read_only_method(&Method::OPTIONS));
        assert!(!is_read_only_method(&Method::POST));
        assert!(!is_read_only_method(&Method::PUT));
        assert!(!is_read_only_method(&Method::PATCH));
        assert!(!is_read_only_method(&Method::DELETE));
    }

    #[test]
    fn test_proxy_error_response() {
        let error = CapiProxyError::AgentNotConnected("test".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let error = CapiProxyError::AlreadyPivoted("test".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::GONE);

        let error = CapiProxyError::MethodNotAllowed("POST".to_string());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn test_proxy_error_tunnel() {
        let error = CapiProxyError::Tunnel(TunnelError::Timeout);
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);

        let error = CapiProxyError::Tunnel(TunnelError::ChannelClosed);
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }
}
