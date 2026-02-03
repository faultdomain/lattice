//! Shared K8s API tunneling logic
//!
//! Common functionality for routing K8s API requests through gRPC tunnels.
//! Used by both the internal pre-pivot proxy and the external auth proxy.

use std::time::Duration;

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use tokio::sync::mpsc;
use tracing::{debug, error, instrument, warn};
use uuid::Uuid;

use lattice_proto::{
    cell_command, is_watch_query, CellCommand, KubernetesRequest, KubernetesResponse,
};

use crate::connection::SharedAgentRegistry;

/// Default timeout for non-watch requests
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Channel buffer size for K8s API responses
pub const RESPONSE_CHANNEL_SIZE: usize = 64;

/// Parameters for building a K8s API request
pub struct K8sRequestParams {
    /// HTTP method/verb
    pub method: String,
    /// API path (e.g., /api/v1/pods)
    pub path: String,
    /// Query string
    pub query: String,
    /// Request body
    pub body: Vec<u8>,
    /// Content-Type header
    pub content_type: String,
    /// Accept header - desired response format
    pub accept: String,
    /// Target cluster - the final destination cluster
    /// Agent compares this to its own cluster name:
    /// - If equal: execute request locally
    /// - If different: forward to target cluster via its subtree
    pub target_cluster: String,
    /// Source user identity (preserved through routing chain for Cedar)
    pub source_user: String,
    /// Source user groups (preserved through routing chain for Cedar)
    pub source_groups: Vec<String>,
}

/// Send a K8s API request through the gRPC tunnel and wait for response
///
/// This is the main entry point for tunneling K8s requests to child clusters.
#[instrument(
    skip(registry, command_tx, params),
    fields(
        target_cluster = %params.target_cluster,
        verb = %params.method,
        path = %params.path,
        otel.kind = "client"
    )
)]
pub async fn tunnel_request(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    command_tx: mpsc::Sender<CellCommand>,
    params: K8sRequestParams,
) -> Result<Response<Body>, TunnelError> {
    let request_id = Uuid::new_v4().to_string();
    let is_watch = is_watch_query(&params.query);

    // Build KubernetesRequest with trace context injection
    let mut k8s_request = KubernetesRequest {
        request_id: request_id.clone(),
        verb: params.method,
        path: params.path,
        query: params.query,
        body: params.body,
        content_type: params.content_type,
        accept: params.accept,
        timeout_ms: if is_watch {
            0
        } else {
            DEFAULT_TIMEOUT.as_millis() as u32
        },
        cancel: false,
        target_cluster: params.target_cluster,
        source_user: params.source_user,
        source_groups: params.source_groups,
        traceparent: String::new(),
        tracestate: String::new(),
    };

    // Inject trace context for distributed tracing
    lattice_proto::tracing::inject_context(&mut k8s_request);

    // Create response channel
    let (response_tx, mut response_rx) = mpsc::channel::<KubernetesResponse>(RESPONSE_CHANNEL_SIZE);

    // Register pending response
    registry.register_pending_k8s_response(&request_id, response_tx);

    // Send request to agent
    let command = CellCommand {
        command_id: request_id.clone(),
        command: Some(cell_command::Command::KubernetesRequest(k8s_request)),
    };

    if let Err(e) = command_tx.send(command).await {
        registry.take_pending_k8s_response(&request_id);
        error!(
            cluster = %cluster_name,
            request_id = %request_id,
            error = %e,
            "Failed to send K8s request to agent"
        );
        return Err(TunnelError::SendFailed(e.to_string()));
    }

    debug!(
        cluster = %cluster_name,
        request_id = %request_id,
        is_watch = is_watch,
        "Sent K8s request to agent"
    );

    // Handle response
    if is_watch {
        handle_watch_response(cluster_name, &request_id, response_rx, registry).await
    } else {
        handle_single_response(cluster_name, &request_id, &mut response_rx, registry).await
    }
}

/// Handle a single (non-watch) response from the agent
async fn handle_single_response(
    cluster_name: &str,
    request_id: &str,
    response_rx: &mut mpsc::Receiver<KubernetesResponse>,
    registry: &SharedAgentRegistry,
) -> Result<Response<Body>, TunnelError> {
    match tokio::time::timeout(DEFAULT_TIMEOUT, response_rx.recv()).await {
        Ok(Some(response)) => {
            debug!(
                cluster = %cluster_name,
                request_id = %request_id,
                status_code = response.status_code,
                body_len = response.body.len(),
                "Received K8s API response"
            );

            registry.take_pending_k8s_response(request_id);

            if !response.error.is_empty() {
                return Err(TunnelError::AgentError(response.error));
            }

            build_http_response(&response)
        }
        Ok(None) => {
            registry.take_pending_k8s_response(request_id);
            error!(
                cluster = %cluster_name,
                request_id = %request_id,
                "Response channel closed unexpectedly"
            );
            Err(TunnelError::ChannelClosed)
        }
        Err(_) => {
            registry.take_pending_k8s_response(request_id);
            warn!(
                cluster = %cluster_name,
                request_id = %request_id,
                "K8s API request timed out"
            );
            Err(TunnelError::Timeout)
        }
    }
}

/// Handle a watch (streaming) response from the agent
async fn handle_watch_response(
    cluster_name: &str,
    request_id: &str,
    mut response_rx: mpsc::Receiver<KubernetesResponse>,
    registry: &SharedAgentRegistry,
) -> Result<Response<Body>, TunnelError> {
    let (body_tx, body_rx) =
        mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(RESPONSE_CHANNEL_SIZE);

    let cluster_name = cluster_name.to_string();
    let request_id = request_id.to_string();
    let registry = registry.clone();

    tokio::spawn(async move {
        loop {
            match response_rx.recv().await {
                Some(response) => {
                    debug!(
                        cluster = %cluster_name,
                        request_id = %request_id,
                        streaming = response.streaming,
                        stream_end = response.stream_end,
                        body_len = response.body.len(),
                        "Forwarding watch event"
                    );

                    if !response.body.is_empty() {
                        let mut body = response.body;
                        body.push(b'\n');
                        if body_tx
                            .send(Ok(axum::body::Bytes::from(body)))
                            .await
                            .is_err()
                        {
                            debug!(
                                cluster = %cluster_name,
                                request_id = %request_id,
                                "Client disconnected during watch"
                            );
                            break;
                        }
                    }

                    if !response.error.is_empty() {
                        warn!(
                            cluster = %cluster_name,
                            request_id = %request_id,
                            error = %response.error,
                            "Watch error from agent"
                        );
                    }

                    if response.stream_end {
                        debug!(
                            cluster = %cluster_name,
                            request_id = %request_id,
                            "Watch stream ended"
                        );
                        break;
                    }
                }
                None => {
                    debug!(
                        cluster = %cluster_name,
                        request_id = %request_id,
                        "Watch channel closed"
                    );
                    break;
                }
            }
        }

        registry.take_pending_k8s_response(&request_id);
    });

    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(body_rx));

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("Transfer-Encoding", "chunked")
        .body(body)
        .map_err(|e| TunnelError::ResponseBuild(e.to_string()))
}

/// Build HTTP response from KubernetesResponse
fn build_http_response(response: &KubernetesResponse) -> Result<Response<Body>, TunnelError> {
    let status = StatusCode::from_u16(response.status_code as u16)
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let content_type = if response.content_type.is_empty() {
        "application/json"
    } else {
        &response.content_type
    };

    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .body(Body::from(response.body.clone()))
        .map_err(|e| TunnelError::ResponseBuild(e.to_string()))
}

/// Errors that can occur during K8s API tunneling
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    /// Failed to send request to agent
    #[error("failed to send request: {0}")]
    SendFailed(String),

    /// Response channel closed
    #[error("agent connection lost")]
    ChannelClosed,

    /// Request timed out
    #[error("request timed out")]
    Timeout,

    /// Error from agent
    #[error("agent error: {0}")]
    AgentError(String),

    /// Failed to build response
    #[error("failed to build response: {0}")]
    ResponseBuild(String),
}

impl TunnelError {
    /// Get the appropriate HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            TunnelError::SendFailed(_) => StatusCode::BAD_GATEWAY,
            TunnelError::ChannelClosed => StatusCode::BAD_GATEWAY,
            TunnelError::Timeout => StatusCode::GATEWAY_TIMEOUT,
            TunnelError::AgentError(_) => StatusCode::BAD_GATEWAY,
            TunnelError::ResponseBuild(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_error_status_codes() {
        assert_eq!(
            TunnelError::SendFailed("test".into()).status_code(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            TunnelError::ChannelClosed.status_code(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            TunnelError::Timeout.status_code(),
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            TunnelError::AgentError("test".into()).status_code(),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            TunnelError::ResponseBuild("test".into()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_build_http_response() {
        let response = KubernetesResponse {
            request_id: "test".to_string(),
            status_code: 200,
            body: b"hello".to_vec(),
            content_type: "application/json".to_string(),
            error: String::new(),
            streaming: false,
            stream_end: false,
        };

        let http_response = build_http_response(&response).expect("should build");
        assert_eq!(http_response.status(), StatusCode::OK);
    }

    #[test]
    fn test_build_http_response_empty_content_type() {
        let response = KubernetesResponse {
            request_id: "test".to_string(),
            status_code: 404,
            body: b"not found".to_vec(),
            content_type: String::new(),
            error: String::new(),
            streaming: false,
            stream_end: false,
        };

        let http_response = build_http_response(&response).expect("should build");
        assert_eq!(http_response.status(), StatusCode::NOT_FOUND);
    }
}
