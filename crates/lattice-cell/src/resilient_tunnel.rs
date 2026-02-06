//! Resilient K8s API tunneling with automatic reconnection
//!
//! Wraps the basic k8s_tunnel functionality to provide:
//! - Automatic retry on agent connection/reconnection
//! - Client connection buffering during brief disconnections
//! - Watch resumption using resourceVersion
//!
//! Uses `AgentRegistry::wait_for_connection()` as the single mechanism for
//! waiting on agent availability — both for never-connected and disconnected agents.

use std::time::Duration;

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use lattice_proto::KubernetesResponse;

use crate::connection::SharedAgentRegistry;
use crate::k8s_tunnel::{
    build_http_response, tunnel_request_streaming, K8sRequestParams, TunnelError, DEFAULT_TIMEOUT,
    RESPONSE_CHANNEL_SIZE,
};

/// Default timeout for waiting for agent connection
pub const RECONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for resilient tunneling
#[derive(Clone, Debug)]
pub struct ResilientTunnelConfig {
    /// How long to wait for agent connection before giving up
    pub reconnect_timeout: Duration,
    /// Whether to enable resilient mode (wait for connection vs fail fast)
    pub enabled: bool,
}

impl Default for ResilientTunnelConfig {
    fn default() -> Self {
        Self {
            reconnect_timeout: RECONNECT_TIMEOUT,
            enabled: true,
        }
    }
}

/// Send a K8s request with automatic retry on agent connection.
///
/// For watch requests: Returns a streaming response that survives brief disconnections.
/// For regular requests: Retries once if agent connects within timeout.
///
/// This provides a better user experience by buffering the client connection
/// during temporary agent disconnections instead of immediately failing.
pub async fn tunnel_request_resilient(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    params: K8sRequestParams,
    config: &ResilientTunnelConfig,
) -> Result<Response<Body>, TunnelError> {
    if lattice_proto::is_watch_query(&params.query) {
        tunnel_watch_resilient(registry, cluster_name, params, config).await
    } else {
        tunnel_single_resilient(registry, cluster_name, params, config).await
    }
}

/// Handle a single (non-watch) request with connection retry
async fn tunnel_single_resilient(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    params: K8sRequestParams,
    config: &ResilientTunnelConfig,
) -> Result<Response<Body>, TunnelError> {
    let timeout = if config.enabled {
        config.reconnect_timeout
    } else {
        Duration::ZERO
    };

    // Get command channel (waits for agent if not yet connected)
    let command_tx = registry
        .wait_for_connection(cluster_name, timeout)
        .await
        .ok_or(TunnelError::Timeout)?;

    // First attempt
    let result = tunnel_and_receive(registry, cluster_name, command_tx, &params).await;

    match result {
        Ok(response) => Ok(response),
        Err(e) if config.enabled && is_retryable(&e) => {
            debug!(
                cluster = %cluster_name,
                error = %e,
                "Request failed, waiting for agent reconnection"
            );

            // Agent disconnected mid-request — wait for reconnection and retry once
            let command_tx = registry
                .wait_for_connection(cluster_name, config.reconnect_timeout)
                .await
                .ok_or(TunnelError::Timeout)?;

            info!(cluster = %cluster_name, "Agent reconnected, retrying request");
            tunnel_and_receive(registry, cluster_name, command_tx, &params).await
        }
        Err(e) => Err(e),
    }
}

/// Handle a watch request with reconnection resilience
///
/// Creates a streaming response that survives brief disconnections by:
/// 1. Extracting resourceVersion from each event
/// 2. On disconnect, waiting for reconnect via `wait_for_connection`
/// 3. Re-establishing watch from last known resourceVersion
async fn tunnel_watch_resilient(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    params: K8sRequestParams,
    config: &ResilientTunnelConfig,
) -> Result<Response<Body>, TunnelError> {
    let (body_tx, body_rx) =
        mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(RESPONSE_CHANNEL_SIZE);

    let registry = registry.clone();
    let cluster_name = cluster_name.to_string();
    let reconnect_timeout = config.reconnect_timeout;
    let resilient_enabled = config.enabled;

    tokio::spawn(async move {
        let mut current_params = params;

        loop {
            // Get command channel (waits for agent if not yet connected)
            let command_tx = match registry
                .wait_for_connection(&cluster_name, reconnect_timeout)
                .await
            {
                Some(tx) => tx,
                None => {
                    warn!(cluster = %cluster_name, "Agent connection timeout, ending watch");
                    break;
                }
            };

            // Start watch stream
            let response_rx = match tunnel_request_streaming(
                &registry,
                &cluster_name,
                command_tx,
                current_params.clone(),
            )
            .await
            {
                Ok(rx) => rx,
                Err(_) if !resilient_enabled => break,
                Err(e) => {
                    debug!(
                        cluster = %cluster_name,
                        error = %e,
                        "Watch request failed, waiting for agent reconnection"
                    );
                    continue; // Loop back to wait_for_connection
                }
            };

            // Stream responses to client, tracking resourceVersion
            let disconnected =
                stream_watch_responses(response_rx, &body_tx, &mut current_params).await;

            if !disconnected || !resilient_enabled {
                break;
            }

            info!(
                cluster = %cluster_name,
                "Watch stream interrupted, waiting for agent reconnection"
            );
            // Loop back to wait_for_connection
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

/// Execute tunnel request and receive single response
async fn tunnel_and_receive(
    registry: &SharedAgentRegistry,
    cluster_name: &str,
    command_tx: mpsc::Sender<lattice_proto::CellCommand>,
    params: &K8sRequestParams,
) -> Result<Response<Body>, TunnelError> {
    let mut response_rx =
        tunnel_request_streaming(registry, cluster_name, command_tx, params.clone()).await?;

    match tokio::time::timeout(DEFAULT_TIMEOUT, response_rx.recv()).await {
        Ok(Some(response)) => build_http_response(&response),
        Ok(None) => Err(TunnelError::ChannelClosed),
        Err(_) => Err(TunnelError::Timeout),
    }
}

/// Check if an error is retryable (agent disconnected mid-request)
fn is_retryable(e: &TunnelError) -> bool {
    matches!(e, TunnelError::ChannelClosed | TunnelError::SendFailed(_))
}

/// Stream watch responses to client, tracking resourceVersion
///
/// Returns true if disconnected (should retry), false if stream ended normally
async fn stream_watch_responses(
    mut response_rx: mpsc::Receiver<KubernetesResponse>,
    body_tx: &mpsc::Sender<Result<axum::body::Bytes, std::io::Error>>,
    params: &mut K8sRequestParams,
) -> bool {
    while let Some(response) = response_rx.recv().await {
        // Extract resourceVersion from watch events for resume
        if let Some(rv) = extract_resource_version(&response.body) {
            update_resource_version_in_query(&mut params.query, &rv);
        }

        // Forward to client
        if !response.body.is_empty()
            && body_tx
                .send(Ok(axum::body::Bytes::from(response.body)))
                .await
                .is_err()
        {
            // Client disconnected
            return false;
        }

        if !response.error.is_empty() {
            warn!(error = %response.error, "Watch error from agent");
        }

        if response.stream_end {
            return false; // Normal end
        }
    }

    // Channel closed = agent disconnected
    true
}

/// Extract resourceVersion from a watch event JSON
///
/// Watch events look like: {"type":"ADDED","object":{"metadata":{"resourceVersion":"12345",...},...}}
fn extract_resource_version(body: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(body).ok()?;
    let rv_key = "\"resourceVersion\":\"";
    let start = s.find(rv_key)? + rv_key.len();
    let end = s[start..].find('"')? + start;
    Some(s[start..end].to_string())
}

/// Update resourceVersion in query string for watch resume
fn update_resource_version_in_query(query: &mut String, resource_version: &str) {
    let mut params: Vec<(String, String)> = query
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|kv| {
            let mut parts = kv.splitn(2, '=');
            Some((parts.next()?.to_string(), parts.next()?.to_string()))
        })
        .collect();

    let mut found = false;
    for (k, v) in &mut params {
        if k == "resourceVersion" {
            *v = resource_version.to_string();
            found = true;
            break;
        }
    }
    if !found {
        params.push(("resourceVersion".to_string(), resource_version.to_string()));
    }

    *query = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_resource_version() {
        let event =
            br#"{"type":"ADDED","object":{"metadata":{"resourceVersion":"12345","name":"test"}}}"#;
        assert_eq!(extract_resource_version(event), Some("12345".to_string()));
    }

    #[test]
    fn test_extract_resource_version_no_rv() {
        let event = br#"{"type":"ERROR","object":{}}"#;
        assert_eq!(extract_resource_version(event), None);
    }

    #[test]
    fn test_update_resource_version_in_query_existing() {
        let mut query = "watch=true&resourceVersion=100".to_string();
        update_resource_version_in_query(&mut query, "200");
        assert!(query.contains("resourceVersion=200"));
        assert!(!query.contains("resourceVersion=100"));
    }

    #[test]
    fn test_update_resource_version_in_query_new() {
        let mut query = "watch=true".to_string();
        update_resource_version_in_query(&mut query, "300");
        assert!(query.contains("resourceVersion=300"));
        assert!(query.contains("watch=true"));
    }

    #[test]
    fn test_update_resource_version_in_query_empty() {
        let mut query = String::new();
        update_resource_version_in_query(&mut query, "400");
        assert_eq!(query, "resourceVersion=400");
    }

    #[test]
    fn test_is_retryable() {
        assert!(is_retryable(&TunnelError::ChannelClosed));
        assert!(is_retryable(&TunnelError::SendFailed("test".into())));
        assert!(!is_retryable(&TunnelError::UnknownCluster("test".into())));
        assert!(!is_retryable(&TunnelError::Timeout));
        assert!(!is_retryable(&TunnelError::AgentError("test".into())));
    }

    #[test]
    fn test_resilient_config_default() {
        let config = ResilientTunnelConfig::default();
        assert_eq!(config.reconnect_timeout, RECONNECT_TIMEOUT);
        assert!(config.enabled);
    }
}
