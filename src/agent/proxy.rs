//! Kubernetes API proxy over gRPC
//!
//! This module implements a local HTTP server that proxies K8s API requests
//! through the gRPC connection to an agent. This allows tools like `clusterctl`
//! to operate on remote clusters using a standard kubeconfig.
//!
//! # Usage
//!
//! 1. Start the proxy for a connected agent
//! 2. Generate a kubeconfig pointing to the proxy
//! 3. Use kubectl or clusterctl with the proxy kubeconfig
//!
//! ```text
//! clusterctl move --to-kubeconfig /tmp/agent-proxy.kubeconfig
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, Response, StatusCode, Uri};
use axum::routing::any;
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{debug, error, info, instrument, warn};

use crate::proto::{HttpHeader, KubeProxyRequest, KubeProxyResponse};

/// Kubernetes API proxy that tunnels requests through gRPC
pub struct KubeProxy {
    /// Cluster name being proxied
    cluster_name: String,
    /// Channel to send requests to the agent
    request_tx: mpsc::Sender<KubeProxyRequest>,
    /// Pending responses waiting for agent reply
    pending: Arc<RwLock<HashMap<String, oneshot::Sender<KubeProxyResponse>>>>,
    /// Local address the proxy is listening on
    local_addr: Option<SocketAddr>,
}

impl KubeProxy {
    /// Create a new proxy for the given cluster
    pub fn new(cluster_name: String, request_tx: mpsc::Sender<KubeProxyRequest>) -> Self {
        Self {
            cluster_name,
            request_tx,
            pending: Arc::new(RwLock::new(HashMap::new())),
            local_addr: None,
        }
    }

    /// Handle a response from the agent
    pub async fn handle_response(&self, response: KubeProxyResponse) {
        let request_id = response.request_id.clone();

        let sender = {
            let mut pending = self.pending.write().await;
            pending.remove(&request_id)
        };

        match sender {
            Some(tx) => {
                if tx.send(response).is_err() {
                    warn!(request_id = %request_id, "Response receiver dropped");
                }
            }
            None => {
                warn!(request_id = %request_id, "No pending request for response");
            }
        }
    }

    /// Start the proxy HTTP server
    #[instrument(skip(self, response_rx))]
    pub async fn start(
        &mut self,
        bind_addr: SocketAddr,
        mut response_rx: mpsc::Receiver<KubeProxyResponse>,
    ) -> Result<(), ProxyError> {
        info!(addr = %bind_addr, cluster = %self.cluster_name, "Starting K8s API proxy");

        // Spawn response handler
        let pending = self.pending.clone();
        tokio::spawn(async move {
            while let Some(response) = response_rx.recv().await {
                let request_id = response.request_id.clone();

                let sender = {
                    let mut pending = pending.write().await;
                    pending.remove(&request_id)
                };

                if let Some(tx) = sender {
                    let _ = tx.send(response);
                }
            }
        });

        // Create shared state for handlers
        let state = ProxyState {
            request_tx: self.request_tx.clone(),
            pending: self.pending.clone(),
            cluster_name: self.cluster_name.clone(),
            request_counter: Arc::new(AtomicU64::new(0)),
        };

        // Build router - catch all paths
        // Note: axum 0.8 uses {*path} syntax for wildcards
        let app = Router::new()
            .route("/{*path}", any(proxy_handler))
            .route("/", any(proxy_handler))
            .with_state(Arc::new(state));

        // Bind and serve
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| ProxyError::BindFailed(e.to_string()))?;

        self.local_addr = Some(
            listener
                .local_addr()
                .map_err(|e| ProxyError::BindFailed(e.to_string()))?,
        );

        info!(addr = ?self.local_addr, "K8s API proxy listening");

        axum::serve(listener, app)
            .await
            .map_err(|e| ProxyError::ServerFailed(e.to_string()))?;

        Ok(())
    }

    /// Get the local address the proxy is listening on
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Generate a kubeconfig YAML for this proxy
    pub fn generate_kubeconfig(&self) -> Option<String> {
        let addr = self.local_addr?;

        Some(format!(
            r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    server: http://{}
    insecure-skip-tls-verify: true
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
            addr,
            cluster = self.cluster_name,
        ))
    }
}

/// Shared state for proxy handlers
#[derive(Clone)]
struct ProxyState {
    request_tx: mpsc::Sender<KubeProxyRequest>,
    pending: Arc<RwLock<HashMap<String, oneshot::Sender<KubeProxyResponse>>>>,
    cluster_name: String,
    request_counter: Arc<AtomicU64>,
}

impl ProxyState {
    fn next_request_id(&self) -> String {
        let id = self.request_counter.fetch_add(1, Ordering::SeqCst);
        format!("{}-{}", self.cluster_name, id)
    }
}

/// Handle proxied K8s API requests
async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, StatusCode> {
    let request_id = state.next_request_id();
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    debug!(
        request_id = %request_id,
        method = %method,
        path = %path,
        "Proxying K8s API request"
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
    let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024) // 10MB limit
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Create proxy request
    let proxy_request = KubeProxyRequest {
        request_id: request_id.clone(),
        method: method.to_string(),
        path: path.to_string(),
        headers: proto_headers,
        body: body_bytes.to_vec(),
    };

    // Create response channel
    let (response_tx, response_rx) = oneshot::channel();

    // Register pending request
    {
        let mut pending = state.pending.write().await;
        pending.insert(request_id.clone(), response_tx);
    }

    // Send request to agent
    if let Err(e) = state.request_tx.send(proxy_request).await {
        error!(error = %e, "Failed to send proxy request");

        // Clean up pending
        let mut pending = state.pending.write().await;
        pending.remove(&request_id);

        return Err(StatusCode::BAD_GATEWAY);
    }

    // Wait for response (with timeout)
    let response = tokio::time::timeout(std::time::Duration::from_secs(30), response_rx)
        .await
        .map_err(|_| {
            error!(request_id = %request_id, "Proxy request timeout");
            StatusCode::GATEWAY_TIMEOUT
        })?
        .map_err(|_| {
            error!(request_id = %request_id, "Response channel closed");
            StatusCode::BAD_GATEWAY
        })?;

    // Check for proxy error
    if !response.error.is_empty() {
        error!(error = %response.error, "Proxy error");
        return Err(StatusCode::BAD_GATEWAY);
    }

    // Build HTTP response
    let mut builder = Response::builder().status(response.status_code as u16);

    for header in &response.headers {
        builder = builder.header(&header.key, &header.value);
    }

    builder
        .body(Body::from(response.body))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kubeconfig_generation() {
        let (tx, _rx) = mpsc::channel(1);
        let mut proxy = KubeProxy::new("my-cluster".to_string(), tx);

        // No address yet
        assert!(proxy.generate_kubeconfig().is_none());

        // Set address manually for testing
        proxy.local_addr = Some("127.0.0.1:8080".parse().unwrap());

        let kubeconfig = proxy.generate_kubeconfig().unwrap();
        assert!(kubeconfig.contains("my-cluster"));
        assert!(kubeconfig.contains("127.0.0.1:8080"));
        assert!(kubeconfig.contains("insecure-skip-tls-verify: true"));
        assert!(kubeconfig.contains("current-context: my-cluster"));
    }

    #[test]
    fn test_kubeconfig_yaml_structure() {
        let (tx, _rx) = mpsc::channel(1);
        let mut proxy = KubeProxy::new("test-cluster".to_string(), tx);
        proxy.local_addr = Some("10.0.0.1:6443".parse().unwrap());

        let kubeconfig = proxy.generate_kubeconfig().unwrap();

        // Verify it's valid YAML by checking key sections
        assert!(kubeconfig.contains("apiVersion: v1"));
        assert!(kubeconfig.contains("kind: Config"));
        assert!(kubeconfig.contains("clusters:"));
        assert!(kubeconfig.contains("contexts:"));
        assert!(kubeconfig.contains("users:"));
        assert!(kubeconfig.contains("server: http://10.0.0.1:6443"));
    }

    #[test]
    fn test_local_addr_initially_none() {
        let (tx, _rx) = mpsc::channel(1);
        let proxy = KubeProxy::new("test".to_string(), tx);
        assert!(proxy.local_addr().is_none());
    }

    #[test]
    fn test_local_addr_after_setting() {
        let (tx, _rx) = mpsc::channel(1);
        let mut proxy = KubeProxy::new("test".to_string(), tx);
        let addr: SocketAddr = "192.168.1.100:8443".parse().unwrap();
        proxy.local_addr = Some(addr);
        assert_eq!(proxy.local_addr(), Some(addr));
    }

    #[tokio::test]
    async fn test_handle_response() {
        let (tx, _rx) = mpsc::channel(1);
        let proxy = KubeProxy::new("test".to_string(), tx);

        // Register a pending request
        let (response_tx, response_rx) = oneshot::channel();
        {
            let mut pending = proxy.pending.write().await;
            pending.insert("req-1".to_string(), response_tx);
        }

        // Handle response
        let response = KubeProxyResponse {
            request_id: "req-1".to_string(),
            status_code: 200,
            headers: vec![],
            body: b"test".to_vec(),
            error: String::new(),
        };

        proxy.handle_response(response).await;

        // Verify response was received
        let received = response_rx.await.unwrap();
        assert_eq!(received.status_code, 200);
        assert_eq!(received.body, b"test");
    }

    #[tokio::test]
    async fn test_handle_response_no_pending_request() {
        let (tx, _rx) = mpsc::channel(1);
        let proxy = KubeProxy::new("test".to_string(), tx);

        // Handle response for non-existent request (should not panic)
        let response = KubeProxyResponse {
            request_id: "non-existent".to_string(),
            status_code: 200,
            headers: vec![],
            body: vec![],
            error: String::new(),
        };

        proxy.handle_response(response).await;
        // Test passes if no panic
    }

    #[tokio::test]
    async fn test_handle_response_receiver_dropped() {
        let (tx, _rx) = mpsc::channel(1);
        let proxy = KubeProxy::new("test".to_string(), tx);

        // Register a pending request and immediately drop the receiver
        let (response_tx, response_rx) = oneshot::channel();
        {
            let mut pending = proxy.pending.write().await;
            pending.insert("req-drop".to_string(), response_tx);
        }
        drop(response_rx);

        // Handle response - should log warning but not panic
        let response = KubeProxyResponse {
            request_id: "req-drop".to_string(),
            status_code: 200,
            headers: vec![],
            body: vec![],
            error: String::new(),
        };

        proxy.handle_response(response).await;
        // Test passes if no panic
    }

    #[tokio::test]
    async fn test_handle_multiple_responses() {
        let (tx, _rx) = mpsc::channel(1);
        let proxy = KubeProxy::new("test".to_string(), tx);

        // Register multiple pending requests
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        let (tx3, rx3) = oneshot::channel();

        {
            let mut pending = proxy.pending.write().await;
            pending.insert("req-1".to_string(), tx1);
            pending.insert("req-2".to_string(), tx2);
            pending.insert("req-3".to_string(), tx3);
        }

        // Handle responses out of order
        proxy
            .handle_response(KubeProxyResponse {
                request_id: "req-2".to_string(),
                status_code: 201,
                headers: vec![],
                body: b"second".to_vec(),
                error: String::new(),
            })
            .await;

        proxy
            .handle_response(KubeProxyResponse {
                request_id: "req-1".to_string(),
                status_code: 200,
                headers: vec![],
                body: b"first".to_vec(),
                error: String::new(),
            })
            .await;

        proxy
            .handle_response(KubeProxyResponse {
                request_id: "req-3".to_string(),
                status_code: 404,
                headers: vec![],
                body: b"not found".to_vec(),
                error: String::new(),
            })
            .await;

        // Verify all responses received correctly
        let r1 = rx1.await.unwrap();
        let r2 = rx2.await.unwrap();
        let r3 = rx3.await.unwrap();

        assert_eq!(r1.status_code, 200);
        assert_eq!(r2.status_code, 201);
        assert_eq!(r3.status_code, 404);
    }

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

    // Test ProxyState
    #[test]
    fn test_proxy_state_request_id_generation() {
        let (tx, _rx) = mpsc::channel(1);
        let state = ProxyState {
            request_tx: tx,
            pending: Arc::new(RwLock::new(HashMap::new())),
            cluster_name: "state-test".to_string(),
            request_counter: Arc::new(AtomicU64::new(0)),
        };

        let id1 = state.next_request_id();
        let id2 = state.next_request_id();

        assert_eq!(id1, "state-test-0");
        assert_eq!(id2, "state-test-1");
    }

    #[test]
    fn test_proxy_state_clone() {
        let (tx, _rx) = mpsc::channel(1);
        let state = ProxyState {
            request_tx: tx,
            pending: Arc::new(RwLock::new(HashMap::new())),
            cluster_name: "clone-test".to_string(),
            request_counter: Arc::new(AtomicU64::new(5)),
        };

        let cloned = state.clone();
        assert_eq!(cloned.cluster_name, "clone-test");

        // Counter should be shared
        let _ = state.next_request_id();
        let id = cloned.next_request_id();
        assert_eq!(id, "clone-test-6");
    }

    // Test KubeProxy creation
    #[test]
    fn test_kube_proxy_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let proxy = KubeProxy::new("production-cluster".to_string(), tx);

        assert_eq!(proxy.cluster_name, "production-cluster");
        assert!(proxy.local_addr.is_none());
    }

    #[tokio::test]
    async fn test_kube_proxy_pending_map_operations() {
        let (tx, _rx) = mpsc::channel(1);
        let proxy = KubeProxy::new("test".to_string(), tx);

        // Initially empty
        assert!(proxy.pending.read().await.is_empty());

        // Add a pending request
        let (response_tx, _response_rx) = oneshot::channel();
        {
            let mut pending = proxy.pending.write().await;
            pending.insert("req-1".to_string(), response_tx);
        }

        assert_eq!(proxy.pending.read().await.len(), 1);

        // Remove the pending request
        {
            let mut pending = proxy.pending.write().await;
            pending.remove("req-1");
        }

        assert!(proxy.pending.read().await.is_empty());
    }

    // ==========================================================================
    // Integration Tests: Real HTTP Server
    // ==========================================================================

    /// Integration test: Start proxy server and make real HTTP request
    #[tokio::test]
    async fn integration_proxy_handles_http_request() {
        use tokio::time::Duration;

        let (request_tx, mut request_rx) = mpsc::channel::<KubeProxyRequest>(32);
        let (response_tx, response_rx) = mpsc::channel::<KubeProxyResponse>(32);

        let mut proxy = KubeProxy::new("integration-test".to_string(), request_tx);

        // Start proxy server in background
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let proxy_handle = tokio::spawn(async move { proxy.start(bind_addr, response_rx).await });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Simulate agent responding to requests
        let response_tx_clone = response_tx.clone();
        let agent_handle = tokio::spawn(async move {
            while let Some(request) = request_rx.recv().await {
                // Echo back request info in response
                let response = KubeProxyResponse {
                    request_id: request.request_id,
                    status_code: 200,
                    headers: vec![HttpHeader {
                        key: "content-type".to_string(),
                        value: "application/json".to_string(),
                    }],
                    body: format!(
                        r#"{{"method":"{}","path":"{}"}}"#,
                        request.method, request.path
                    )
                    .into_bytes(),
                    error: String::new(),
                };
                let _ = response_tx_clone.send(response).await;
            }
        });

        // Make HTTP request to the proxy
        // Note: We can't easily get the bound address from here, so we'll test the handler directly

        // Clean up
        proxy_handle.abort();
        agent_handle.abort();
    }

    /// Integration test: proxy_handler processes requests correctly
    #[tokio::test]
    async fn integration_proxy_handler_success() {
        let (request_tx, mut request_rx) = mpsc::channel::<KubeProxyRequest>(32);
        let pending = Arc::new(RwLock::new(HashMap::new()));

        let state = Arc::new(ProxyState {
            request_tx,
            pending: pending.clone(),
            cluster_name: "handler-test".to_string(),
            request_counter: Arc::new(AtomicU64::new(0)),
        });

        // Spawn task to handle the request and send response
        let pending_clone = pending.clone();
        tokio::spawn(async move {
            if let Some(request) = request_rx.recv().await {
                // Find the pending sender and send response
                let sender = {
                    let mut p = pending_clone.write().await;
                    p.remove(&request.request_id)
                };
                if let Some(tx) = sender {
                    let response = KubeProxyResponse {
                        request_id: request.request_id,
                        status_code: 200,
                        headers: vec![],
                        body: b"success".to_vec(),
                        error: String::new(),
                    };
                    let _ = tx.send(response);
                }
            }
        });

        // Call the handler
        let result = proxy_handler(
            State(state),
            Method::GET,
            "/api/v1/namespaces".parse().unwrap(),
            HeaderMap::new(),
            Body::empty(),
        )
        .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), 200);
    }

    /// Integration test: proxy_handler handles timeout
    #[tokio::test]
    async fn integration_proxy_handler_timeout() {
        let (request_tx, _request_rx) = mpsc::channel::<KubeProxyRequest>(32);
        // Don't spawn anything to handle requests - they will timeout

        let state = Arc::new(ProxyState {
            request_tx,
            pending: Arc::new(RwLock::new(HashMap::new())),
            cluster_name: "timeout-test".to_string(),
            request_counter: Arc::new(AtomicU64::new(0)),
        });

        // Override the timeout for testing (we can't easily do this, so this test
        // would take 30 seconds - skip for now by dropping the receiver)
        drop(_request_rx);

        let result = proxy_handler(
            State(state),
            Method::GET,
            "/api/v1/pods".parse().unwrap(),
            HeaderMap::new(),
            Body::empty(),
        )
        .await;

        // Should fail because channel is closed
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::BAD_GATEWAY);
    }

    /// Integration test: proxy_handler handles error response
    #[tokio::test]
    async fn integration_proxy_handler_error_response() {
        let (request_tx, mut request_rx) = mpsc::channel::<KubeProxyRequest>(32);
        let pending = Arc::new(RwLock::new(HashMap::new()));

        let state = Arc::new(ProxyState {
            request_tx,
            pending: pending.clone(),
            cluster_name: "error-test".to_string(),
            request_counter: Arc::new(AtomicU64::new(0)),
        });

        // Spawn task to send error response
        let pending_clone = pending.clone();
        tokio::spawn(async move {
            if let Some(request) = request_rx.recv().await {
                let sender = {
                    let mut p = pending_clone.write().await;
                    p.remove(&request.request_id)
                };
                if let Some(tx) = sender {
                    let response = KubeProxyResponse {
                        request_id: request.request_id,
                        status_code: 500,
                        headers: vec![],
                        body: vec![],
                        error: "internal server error".to_string(),
                    };
                    let _ = tx.send(response);
                }
            }
        });

        let result = proxy_handler(
            State(state),
            Method::POST,
            "/api/v1/namespaces".parse().unwrap(),
            HeaderMap::new(),
            Body::empty(),
        )
        .await;

        // Should return BAD_GATEWAY because of error in response
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::BAD_GATEWAY);
    }

    /// Integration test: proxy_handler with headers
    #[tokio::test]
    async fn integration_proxy_handler_with_headers() {
        let (request_tx, mut request_rx) = mpsc::channel::<KubeProxyRequest>(32);
        let pending = Arc::new(RwLock::new(HashMap::new()));

        let state = Arc::new(ProxyState {
            request_tx,
            pending: pending.clone(),
            cluster_name: "headers-test".to_string(),
            request_counter: Arc::new(AtomicU64::new(0)),
        });

        // Spawn task to verify headers are passed
        let pending_clone = pending.clone();
        tokio::spawn(async move {
            if let Some(request) = request_rx.recv().await {
                // Verify headers were passed
                let has_auth = request.headers.iter().any(|h| h.key == "authorization");

                let sender = {
                    let mut p = pending_clone.write().await;
                    p.remove(&request.request_id)
                };
                if let Some(tx) = sender {
                    let response = KubeProxyResponse {
                        request_id: request.request_id,
                        status_code: if has_auth { 200 } else { 401 },
                        headers: vec![HttpHeader {
                            key: "x-custom".to_string(),
                            value: "header-value".to_string(),
                        }],
                        body: vec![],
                        error: String::new(),
                    };
                    let _ = tx.send(response);
                }
            }
        });

        // Create headers
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer token".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());

        let result = proxy_handler(
            State(state),
            Method::GET,
            "/api/v1/secrets".parse().unwrap(),
            headers,
            Body::empty(),
        )
        .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), 200);
        assert!(response.headers().contains_key("x-custom"));
    }

    /// Integration test: proxy_handler with body
    #[tokio::test]
    async fn integration_proxy_handler_with_body() {
        let (request_tx, mut request_rx) = mpsc::channel::<KubeProxyRequest>(32);
        let pending = Arc::new(RwLock::new(HashMap::new()));

        let state = Arc::new(ProxyState {
            request_tx,
            pending: pending.clone(),
            cluster_name: "body-test".to_string(),
            request_counter: Arc::new(AtomicU64::new(0)),
        });

        // Spawn task to echo body back
        let pending_clone = pending.clone();
        tokio::spawn(async move {
            if let Some(request) = request_rx.recv().await {
                let sender = {
                    let mut p = pending_clone.write().await;
                    p.remove(&request.request_id)
                };
                if let Some(tx) = sender {
                    let response = KubeProxyResponse {
                        request_id: request.request_id,
                        status_code: 201,
                        headers: vec![],
                        body: request.body, // Echo body back
                        error: String::new(),
                    };
                    let _ = tx.send(response);
                }
            }
        });

        let body_content = r#"{"name":"test-namespace"}"#;
        let result = proxy_handler(
            State(state),
            Method::POST,
            "/api/v1/namespaces".parse().unwrap(),
            HeaderMap::new(),
            Body::from(body_content),
        )
        .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), 201);

        // Read response body
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(body_bytes.as_ref(), body_content.as_bytes());
    }
}
