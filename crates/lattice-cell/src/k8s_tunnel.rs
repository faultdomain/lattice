//! Shared K8s API tunneling logic
//!
//! Common functionality for routing K8s API requests through gRPC tunnels.
//! Used by both the internal pre-pivot proxy and the external auth proxy.

use std::time::Duration;

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use uuid::Uuid;

use lattice_proto::{
    cell_command, is_watch_query, CellCommand, KubernetesRequest, KubernetesResponse,
};

use crate::connection::{K8sResponseRegistry, SharedAgentRegistry};

/// Default timeout for non-watch requests
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Channel buffer size for K8s API responses
pub const RESPONSE_CHANNEL_SIZE: usize = 64;

/// Parameters for building a K8s API request
#[derive(Clone)]
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
    /// Routing path for hierarchical proxy (e.g. "child-b/grandchild-c")
    pub target_path: String,
    /// Source user identity (preserved through routing chain for Cedar)
    pub source_user: String,
    /// Source user groups (preserved through routing chain for Cedar)
    pub source_groups: Vec<String>,
}

/// Send K8s request and return raw response channel for streaming.
///
/// Returns `(request_id, receiver)` so callers can clean up the pending
/// response entry in the registry if the watch is interrupted.
///
/// Use this when you need to handle streaming responses (watch/follow) or
/// need direct access to the KubernetesResponse messages.
pub async fn tunnel_request_streaming(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    command_tx: mpsc::Sender<CellCommand>,
    params: K8sRequestParams,
) -> Result<(String, mpsc::Receiver<KubernetesResponse>), TunnelError> {
    let is_watch = is_watch_query(&params.query);
    send_request(registry, cluster_name, command_tx, params, is_watch).await
}

/// Send request to agent and return request_id + response channel
async fn send_request(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    command_tx: mpsc::Sender<CellCommand>,
    params: K8sRequestParams,
    is_watch: bool,
) -> Result<(String, mpsc::Receiver<KubernetesResponse>), TunnelError> {
    let request_id = Uuid::new_v4().to_string();

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
        target_path: params.target_path,
        source_user: params.source_user,
        source_groups: params.source_groups,
        traceparent: String::new(),
        tracestate: String::new(),
    };

    lattice_proto::tracing::inject_context(&mut k8s_request);

    let (response_tx, response_rx) = mpsc::channel::<KubernetesResponse>(RESPONSE_CHANNEL_SIZE);
    registry
        .register_pending_k8s_response(cluster_name, &request_id, response_tx)
        .await;

    let command = CellCommand {
        command_id: request_id.clone(),
        command: Some(cell_command::Command::KubernetesRequest(k8s_request)),
    };

    // Timeout the channel send — if the agent's command buffer is full (zombie
    // gRPC stream), send() blocks forever. A healthy agent drains commands in
    // milliseconds, so 5 seconds is generous.
    const SEND_TIMEOUT: Duration = Duration::from_secs(5);

    let send_result = tokio::time::timeout(SEND_TIMEOUT, command_tx.send(command)).await;

    let send_err = match send_result {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e.0),
        Err(_elapsed) => {
            // Channel full — agent is alive but not reading. Mark it stale
            // so subsequent requests fail fast instead of also blocking.
            warn!(
                cluster = %cluster_name,
                request_id = %request_id,
                "Command channel full (agent not reading), treating as disconnected"
            );
            registry
                .take_pending_k8s_response(cluster_name, &request_id)
                .await;
            return Err(TunnelError::AgentNotConnected(format!(
                "{cluster_name}: command channel full"
            )));
        }
    };

    if send_err.is_some() {
        // Channel closed — agent disconnected, fail immediately.
        // Don't wait for reconnect: the caller (resilient_tunnel) handles
        // retry policy. Waiting here blocks the proxy thread.
        warn!(
            cluster = %cluster_name,
            request_id = %request_id,
            "Send failed on closed channel"
        );
        registry
            .take_pending_k8s_response(cluster_name, &request_id)
            .await;
        return Err(TunnelError::SendFailed("agent channel closed".to_string()));
    }

    debug!(
        cluster = %cluster_name,
        request_id = %request_id,
        is_watch = is_watch,
        "Sent K8s request to agent"
    );

    Ok((request_id, response_rx))
}

/// Build HTTP response from KubernetesResponse
///
/// Returns error if the response contains an error field.
pub fn build_http_response(response: &KubernetesResponse) -> Result<Response<Body>, TunnelError> {
    if !response.error.is_empty() {
        return Err(TunnelError::AgentError(response.error.clone()));
    }

    let status = StatusCode::from_u16(response.status_code as u16).unwrap_or_else(|_| {
        tracing::warn!(
            status_code = response.status_code,
            "Invalid HTTP status code from agent, using 500"
        );
        StatusCode::INTERNAL_SERVER_ERROR
    });

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
    #[error("failed to send request: {0}")]
    SendFailed(String),

    #[error("agent disconnected")]
    ChannelClosed,

    #[error("unknown cluster: {0}")]
    UnknownCluster(String),

    #[error("request timed out")]
    Timeout,

    #[error("agent error: {0}")]
    AgentError(String),

    #[error("failed to build response: {0}")]
    ResponseBuild(String),

    #[error("agent not connected: {0}")]
    AgentNotConnected(String),
}

impl TunnelError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            TunnelError::SendFailed(_) => StatusCode::BAD_GATEWAY,
            TunnelError::ChannelClosed => StatusCode::BAD_GATEWAY,
            TunnelError::UnknownCluster(_) => StatusCode::NOT_FOUND,
            TunnelError::Timeout => StatusCode::GATEWAY_TIMEOUT,
            TunnelError::AgentError(_) => StatusCode::BAD_GATEWAY,
            TunnelError::ResponseBuild(_) => StatusCode::INTERNAL_SERVER_ERROR,
            TunnelError::AgentNotConnected(_) => StatusCode::SERVICE_UNAVAILABLE,
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
            TunnelError::Timeout.status_code(),
            StatusCode::GATEWAY_TIMEOUT
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
}
