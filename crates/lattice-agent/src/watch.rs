//! Watch execution for K8s API proxy
//!
//! Handles streaming watch requests from the parent cell by streaming
//! raw bytes from the K8s API. This is a pure L4 proxy approach.
//!
//! Uses `client.send()` with chunked transfer encoding (NOT HTTP upgrade)
//! since K8s watch API returns streaming responses via chunked encoding.

use std::sync::Arc;

use dashmap::DashMap;
use http::Request;
use http_body_util::BodyExt;
use kube::client::Body;
use kube::Client;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace};

use crate::executor::build_url;
use lattice_proto::{agent_message::Payload, AgentMessage, KubernetesRequest, KubernetesResponse};

/// Build a streaming response chunk (pure function)
pub fn build_stream_chunk_response(request_id: &str, body: Vec<u8>) -> KubernetesResponse {
    KubernetesResponse {
        request_id: request_id.to_string(),
        status_code: 200,
        body,
        content_type: "application/json".to_string(),
        streaming: true,
        stream_end: false,
        error: String::new(),
    }
}

/// Build an error response for watch failures (pure function)
pub fn build_watch_error_response(
    request_id: &str,
    status_code: u32,
    error: &str,
) -> KubernetesResponse {
    KubernetesResponse {
        request_id: request_id.to_string(),
        status_code,
        error: error.to_string(),
        streaming: true,
        stream_end: true,
        ..Default::default()
    }
}

/// Build a stream end response (pure function)
pub fn build_stream_end_response(request_id: &str) -> KubernetesResponse {
    KubernetesResponse {
        request_id: request_id.to_string(),
        streaming: true,
        stream_end: true,
        ..Default::default()
    }
}

/// Registry for tracking active watches on the agent
#[derive(Default)]
pub struct WatchRegistry {
    active: DashMap<String, CancellationToken>,
}

impl WatchRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            active: DashMap::new(),
        }
    }

    /// Register a watch and return its cancellation token
    pub fn register(&self, request_id: String) -> CancellationToken {
        let token = CancellationToken::new();
        debug!(request_id = %request_id, "Registering watch");
        self.active.insert(request_id, token.clone());
        token
    }

    /// Cancel an active watch
    pub fn cancel(&self, request_id: &str) -> bool {
        if let Some((_, token)) = self.active.remove(request_id) {
            info!(request_id = %request_id, "Cancelling watch");
            token.cancel();
            true
        } else {
            false
        }
    }

    /// Unregister a watch after completion
    pub fn unregister(&self, request_id: &str) {
        self.active.remove(request_id);
    }

    /// Cancel all active watches
    pub fn cancel_all(&self) {
        let count = self.active.len();
        if count > 0 {
            info!(count = count, "Cancelling all active watches");
            for entry in self.active.iter() {
                entry.value().cancel();
            }
            self.active.clear();
        }
    }
}

/// Execute a watch request and stream events back using raw byte streaming.
///
/// This is a pure L4 proxy approach - we stream raw bytes from the K8s API
/// without parsing them. Each chunk of data is forwarded as-is.
///
/// Uses `client.send()` with chunked transfer encoding. The K8s watch API
/// returns streaming responses via HTTP/1.1 chunked encoding, NOT via
/// HTTP upgrade (SPDY/WebSocket). This is different from exec/attach/port-forward
/// which DO require upgrade.
pub async fn execute_watch(
    client: Client,
    req: KubernetesRequest,
    cluster_name: String,
    message_tx: mpsc::Sender<AgentMessage>,
    registry: Arc<WatchRegistry>,
) {
    let request_id = req.request_id.clone();
    let cancel_token = registry.register(request_id.clone());
    let url = build_url(&req.path, &req.query);

    debug!(
        request_id = %request_id,
        url = %url,
        "Starting watch stream"
    );

    // Build raw HTTP request with kube::client::Body
    let http_request = match Request::builder()
        .method(req.verb.as_str())
        .uri(&url)
        .header("Accept", &req.accept)
        .body(Body::empty())
    {
        Ok(r) => r,
        Err(e) => {
            send_error_response(
                &message_tx,
                &cluster_name,
                &request_id,
                400,
                &format!("Failed to build request: {}", e),
            )
            .await;
            registry.unregister(&request_id);
            return;
        }
    };

    // Execute request using client.send() - this handles chunked responses properly
    // Unlike request_stream(), send() doesn't require HTTP upgrade
    let response = match client.send(http_request).await {
        Ok(r) => r,
        Err(e) => {
            send_error_response(
                &message_tx,
                &cluster_name,
                &request_id,
                500,
                &format!("Failed to start watch: {}", e),
            )
            .await;
            registry.unregister(&request_id);
            return;
        }
    };

    // Check response status
    let status = response.status();
    if !status.is_success() {
        // Try to read error body
        let body = response.into_body();
        let error_body = match body.collect().await {
            Ok(collected) => String::from_utf8_lossy(&collected.to_bytes()).to_string(),
            Err(_) => "unknown error".to_string(),
        };
        send_error_response(
            &message_tx,
            &cluster_name,
            &request_id,
            status.as_u16() as u32,
            &error_body,
        )
        .await;
        registry.unregister(&request_id);
        return;
    }

    // Stream the response body
    let mut body = response.into_body();
    let mut chunk_count: u64 = 0;
    let mut total_bytes: u64 = 0;

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                debug!(
                    request_id = %request_id,
                    chunks = chunk_count,
                    total_bytes = total_bytes,
                    "Watch cancelled"
                );
                send_stream_end(&message_tx, &cluster_name, &request_id).await;
                break;
            }
            frame_result = body.frame() => {
                match frame_result {
                    Some(Ok(frame)) => {
                        if let Some(data) = frame.data_ref() {
                            let bytes = data.len();
                            chunk_count += 1;
                            total_bytes += bytes as u64;

                            // Use trace for individual chunks to reduce log noise
                            // Log summary every 100 chunks at debug level
                            if chunk_count.is_multiple_of(100) {
                                debug!(
                                    request_id = %request_id,
                                    chunks = chunk_count,
                                    total_bytes = total_bytes,
                                    "Watch progress"
                                );
                            } else {
                                trace!(
                                    request_id = %request_id,
                                    bytes = bytes,
                                    chunk = chunk_count,
                                    "Forwarding watch chunk"
                                );
                            }

                            // Send the chunk as a streaming response
                            let response = build_stream_chunk_response(&request_id, data.to_vec());
                            if send_response(&message_tx, &cluster_name, response).await.is_err() {
                                debug!(
                                    request_id = %request_id,
                                    "Watch stream send failed, client disconnected"
                                );
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        error!(request_id = %request_id, error = %e, "Watch read error");
                        send_error_response(
                            &message_tx,
                            &cluster_name,
                            &request_id,
                            500,
                            &e.to_string(),
                        ).await;
                        break;
                    }
                    None => {
                        // Stream ended normally
                        debug!(
                            request_id = %request_id,
                            chunks = chunk_count,
                            total_bytes = total_bytes,
                            "Watch stream ended"
                        );
                        send_stream_end(&message_tx, &cluster_name, &request_id).await;
                        break;
                    }
                }
            }
        }
    }

    registry.unregister(&request_id);
}

async fn send_response(
    tx: &mpsc::Sender<AgentMessage>,
    cluster_name: &str,
    response: KubernetesResponse,
) -> Result<(), ()> {
    let msg = AgentMessage {
        cluster_name: cluster_name.to_string(),
        payload: Some(Payload::KubernetesResponse(response)),
    };
    tx.send(msg).await.map_err(|_| ())
}

async fn send_error_response(
    tx: &mpsc::Sender<AgentMessage>,
    cluster_name: &str,
    request_id: &str,
    status_code: u32,
    error: &str,
) {
    let response = build_watch_error_response(request_id, status_code, error);
    let _ = send_response(tx, cluster_name, response).await;
}

async fn send_stream_end(tx: &mpsc::Sender<AgentMessage>, cluster_name: &str, request_id: &str) {
    let response = build_stream_end_response(request_id);
    let _ = send_response(tx, cluster_name, response).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watch_registry() {
        let registry = WatchRegistry::new();

        let token = registry.register("watch-1".to_string());
        assert!(!token.is_cancelled());

        registry.cancel("watch-1");
        assert!(token.is_cancelled());
    }

    #[test]
    fn test_watch_registry_cancel_all() {
        let registry = WatchRegistry::new();

        let t1 = registry.register("w1".to_string());
        let t2 = registry.register("w2".to_string());

        registry.cancel_all();

        assert!(t1.is_cancelled());
        assert!(t2.is_cancelled());
    }

    #[test]
    fn test_watch_registry_cancel_nonexistent() {
        let registry = WatchRegistry::new();
        assert!(!registry.cancel("nonexistent"));
    }

    #[test]
    fn test_watch_registry_unregister() {
        let registry = WatchRegistry::new();
        let token = registry.register("watch-1".to_string());

        registry.unregister("watch-1");

        assert!(!token.is_cancelled());
        assert!(!registry.cancel("watch-1"));
    }

    #[test]
    fn test_watch_registry_cancel_all_empty() {
        let registry = WatchRegistry::new();
        registry.cancel_all();
    }

    #[test]
    fn test_build_stream_chunk_response() {
        let resp = build_stream_chunk_response("req-123", b"test data".to_vec());

        assert_eq!(resp.request_id, "req-123");
        assert_eq!(resp.status_code, 200);
        assert!(resp.streaming);
        assert!(!resp.stream_end);
        assert_eq!(resp.body, b"test data");
    }

    #[test]
    fn test_build_watch_error_response() {
        let resp = build_watch_error_response("req-err", 500, "Internal error");

        assert_eq!(resp.request_id, "req-err");
        assert_eq!(resp.status_code, 500);
        assert_eq!(resp.error, "Internal error");
        assert!(resp.streaming);
        assert!(resp.stream_end);
    }

    #[test]
    fn test_build_stream_end_response() {
        let resp = build_stream_end_response("req-end");

        assert_eq!(resp.request_id, "req-end");
        assert!(resp.streaming);
        assert!(resp.stream_end);
        assert_eq!(resp.status_code, 0);
        assert!(resp.error.is_empty());
    }

}
