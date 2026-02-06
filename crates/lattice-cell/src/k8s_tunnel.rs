//! Shared K8s API tunneling logic
//!
//! Common functionality for routing K8s API requests through gRPC tunnels.
//! Used by both the internal pre-pivot proxy and the external auth proxy.

use std::time::Duration;

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};
use uuid::Uuid;

use lattice_common::metrics::{ProxyStatus, ProxyTimer};
use lattice_proto::{
    cell_command, is_watch_query, CellCommand, KubernetesRequest, KubernetesResponse,
};

use crate::connection::{K8sResponseRegistry, SharedAgentRegistry};
use crate::resilient_tunnel::RECONNECT_TIMEOUT;

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
    /// Target cluster - the final destination cluster
    pub target_cluster: String,
    /// Source user identity (preserved through routing chain for Cedar)
    pub source_user: String,
    /// Source user groups (preserved through routing chain for Cedar)
    pub source_groups: Vec<String>,
}

/// Send K8s request and return raw response channel for streaming.
///
/// Use this when you need to handle streaming responses (watch/follow) or
/// need direct access to the KubernetesResponse messages.
pub async fn tunnel_request_streaming(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    command_tx: mpsc::Sender<CellCommand>,
    params: K8sRequestParams,
) -> Result<mpsc::Receiver<KubernetesResponse>, TunnelError> {
    let is_watch = is_watch_query(&params.query);
    send_request(registry, cluster_name, command_tx, params, is_watch).await
}

/// Send a K8s API request through the gRPC tunnel and wait for HTTP response.
///
/// For watch requests, returns a streaming HTTP response body.
/// For regular requests, returns a single HTTP response.
pub async fn tunnel_request(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    command_tx: mpsc::Sender<CellCommand>,
    params: K8sRequestParams,
) -> Result<Response<Body>, TunnelError> {
    let timer = ProxyTimer::start(cluster_name, &params.method);
    let is_watch = is_watch_query(&params.query);
    let response_rx = send_request(registry, cluster_name, command_tx, params, is_watch).await?;

    let result = if is_watch {
        build_streaming_http_response(response_rx)
    } else {
        receive_single_response(cluster_name, response_rx).await
    };

    match &result {
        Ok(response) => {
            timer.complete(ProxyStatus::from_status_code(response.status().as_u16()));
        }
        Err(e) => {
            let status = match e {
                TunnelError::Timeout => ProxyStatus::ServerError,
                _ => ProxyStatus::ServerError,
            };
            timer.complete(status);
        }
    }

    result
}

/// Send request to agent and return response channel
async fn send_request(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    command_tx: mpsc::Sender<CellCommand>,
    params: K8sRequestParams,
    is_watch: bool,
) -> Result<mpsc::Receiver<KubernetesResponse>, TunnelError> {
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
        target_cluster: params.target_cluster,
        source_user: params.source_user,
        source_groups: params.source_groups,
        traceparent: String::new(),
        tracestate: String::new(),
    };

    lattice_proto::tracing::inject_context(&mut k8s_request);

    let (response_tx, response_rx) = mpsc::channel::<KubernetesResponse>(RESPONSE_CHANNEL_SIZE);
    registry.register_pending_k8s_response(&request_id, response_tx);

    let command = CellCommand {
        command_id: request_id.clone(),
        command: Some(cell_command::Command::KubernetesRequest(k8s_request)),
    };

    if let Err(e) = command_tx.send(command).await {
        // Channel is stale — wait for the agent to reconnect and retry once
        warn!(
            cluster = %cluster_name,
            request_id = %request_id,
            "Send failed on stale channel, waiting for agent reconnection"
        );

        let command = e.0; // recover the unsent command
        let new_tx = registry
            .wait_for_connection(cluster_name, RECONNECT_TIMEOUT)
            .await
            .ok_or_else(|| {
                registry.take_pending_k8s_response(&request_id);
                TunnelError::SendFailed("agent did not reconnect".to_string())
            })?;

        if let Err(e) = new_tx.send(command).await {
            registry.take_pending_k8s_response(&request_id);
            error!(
                cluster = %cluster_name,
                request_id = %request_id,
                error = %e,
                "Failed to send K8s request after reconnection"
            );
            return Err(TunnelError::SendFailed(e.to_string()));
        }

        debug!(
            cluster = %cluster_name,
            request_id = %request_id,
            "Successfully sent K8s request after agent reconnection"
        );
    }

    debug!(
        cluster = %cluster_name,
        request_id = %request_id,
        is_watch = is_watch,
        "Sent K8s request to agent"
    );

    Ok(response_rx)
}

/// Receive a single response and convert to HTTP
async fn receive_single_response(
    cluster_name: &str,
    mut response_rx: mpsc::Receiver<KubernetesResponse>,
) -> Result<Response<Body>, TunnelError> {
    match tokio::time::timeout(DEFAULT_TIMEOUT, response_rx.recv()).await {
        Ok(Some(response)) => {
            debug!(
                cluster = %cluster_name,
                status_code = response.status_code,
                body_len = response.body.len(),
                "Received K8s API response"
            );
            build_http_response(&response)
        }
        Ok(None) => {
            error!(cluster = %cluster_name, "Response channel closed unexpectedly");
            Err(TunnelError::ChannelClosed)
        }
        Err(_) => {
            warn!(cluster = %cluster_name, "K8s API request timed out");
            Err(TunnelError::Timeout)
        }
    }
}

/// Build streaming HTTP response from response channel
fn build_streaming_http_response(
    mut response_rx: mpsc::Receiver<KubernetesResponse>,
) -> Result<Response<Body>, TunnelError> {
    let (body_tx, body_rx) =
        mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(RESPONSE_CHANNEL_SIZE);

    tokio::spawn(async move {
        while let Some(response) = response_rx.recv().await {
            // K8s watch responses are already NDJSON - don't add extra newlines
            if !response.body.is_empty()
                && body_tx
                    .send(Ok(axum::body::Bytes::from(response.body)))
                    .await
                    .is_err()
            {
                break;
            }

            if !response.error.is_empty() {
                warn!(error = %response.error, "Watch error from agent");
            }

            if response.stream_end {
                break;
            }
        }
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
///
/// Returns error if the response contains an error field.
pub fn build_http_response(response: &KubernetesResponse) -> Result<Response<Body>, TunnelError> {
    if !response.error.is_empty() {
        return Err(TunnelError::AgentError(response.error.clone()));
    }

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
