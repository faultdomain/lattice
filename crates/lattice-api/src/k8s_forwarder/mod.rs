//! K8s API request forwarding
//!
//! Forwards K8s API requests to the appropriate destination:
//! - Local cluster: proxies to the local K8s API server using ServiceAccount auth
//!   with user impersonation for K8s RBAC enforcement
//! - Remote cluster: tunnels through gRPC to the child cluster's agent
//!
//! # Security
//!
//! **Impersonation headers from users are always stripped** to prevent privilege
//! escalation. The proxy adds its own impersonation headers based on the
//! authenticated identity. This allows K8s RBAC to enforce permissions and
//! ensures audit logs show the real user.
//!
//! # Dependency Injection
//!
//! The module uses trait-based dependency injection for testability:
//! - `K8sHttpClient`: HTTP client for proxying to K8s API
//! - `TokenReader`: ServiceAccount token file reader
//!
//! Tests can inject mock implementations to test without real infrastructure.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use futures::TryStreamExt;
use std::sync::{Arc, OnceLock};
use tracing::debug;

use crate::auth::UserIdentity;
use crate::backend::{K8sTunnelRequest, ProxyError};
use crate::error::Error;
use crate::routing::strip_cluster_prefix;
use crate::server::AppState;
use lattice_proto::is_watch_query;

/// Default timeout for local K8s API requests (30 seconds)
const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

// ============================================================================
// Constants
// ============================================================================

/// Maximum request body size (10 MB - reasonable for K8s API)
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Default content type for K8s API requests/responses
const DEFAULT_CONTENT_TYPE: &str = "application/json";

/// Path to the in-cluster CA certificate
pub(crate) const CA_CERT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

/// Path to the ServiceAccount token
pub(crate) const TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

/// Impersonation header names that must be stripped from incoming requests
const IMPERSONATION_HEADERS: &[&str] = &[
    "Impersonate-User",
    "Impersonate-Group",
    "Impersonate-Uid",
    // Impersonate-Extra-* headers are handled with a prefix check
];

/// Shared HTTP client for local K8s API requests
static K8S_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

// ============================================================================
// Traits for Dependency Injection
// ============================================================================

/// Trait for reading ServiceAccount token from filesystem
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait TokenReader: Send + Sync {
    /// Read the ServiceAccount token
    async fn read_token(&self) -> Result<String, Error>;
}

/// Default TokenReader that reads from the standard K8s mount path
#[derive(Clone, Default)]
pub struct FileTokenReader;

#[async_trait]
impl TokenReader for FileTokenReader {
    async fn read_token(&self) -> Result<String, Error> {
        tokio::fs::read_to_string(TOKEN_PATH)
            .await
            .map_err(|e| Error::Internal(format!("Failed to read ServiceAccount token: {}", e)))
    }
}

/// HTTP response from K8s API (non-streaming)
#[derive(Debug)]
pub struct HttpResponse {
    /// HTTP status code
    pub status: u16,
    /// Content-Type header value
    pub content_type: String,
    /// Response body bytes
    pub body: Vec<u8>,
}

/// Streaming HTTP response for watch/follow queries
pub struct StreamingHttpResponse {
    /// HTTP status code
    pub status: u16,
    /// Content-Type header value
    pub content_type: String,
    /// Stream of response chunks
    pub stream: std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Send>,
    >,
}

/// Parameters for K8s HTTP requests
#[derive(Clone)]
pub struct K8sHttpRequest {
    /// HTTP method
    pub method: String,
    /// Full URL
    pub url: String,
    /// Bearer token (zeroized on drop)
    pub token: zeroize::Zeroizing<String>,
    /// User identity for impersonation
    pub identity: UserIdentity,
    /// Content-Type header
    pub content_type: Option<String>,
    /// Request body
    pub body: Vec<u8>,
}

/// Trait for making HTTP requests to the K8s API
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait K8sHttpClient: Send + Sync {
    /// Make a non-streaming HTTP request
    async fn request(&self, req: K8sHttpRequest) -> Result<HttpResponse, Error>;

    /// Make a streaming HTTP request (for watch/follow queries)
    async fn request_streaming(&self, req: K8sHttpRequest) -> Result<StreamingHttpResponse, Error>;
}

/// Default K8sHttpClient using reqwest with in-cluster TLS
pub struct ReqwestK8sClient {
    client: reqwest::Client,
}

impl ReqwestK8sClient {
    /// Create a new client using the shared static client
    pub async fn new() -> Result<Self, Error> {
        let client = get_or_init_client().await?.clone();
        Ok(Self { client })
    }

    /// Build a reqwest request from K8sHttpRequest
    fn build_request(&self, req: &K8sHttpRequest) -> Result<reqwest::Request, Error> {
        let method = reqwest::Method::from_bytes(req.method.as_bytes())
            .map_err(|_| Error::Internal(format!("Invalid HTTP method: {}", req.method)))?;

        let mut builder = self
            .client
            .request(method, &req.url)
            .header("Authorization", format!("Bearer {}", *req.token))
            .header("Impersonate-User", &req.identity.username);

        for group in &req.identity.groups {
            builder = builder.header("Impersonate-Group", group);
        }

        if let Some(ct) = &req.content_type {
            builder = builder.header("Content-Type", ct);
        }

        if !req.body.is_empty() {
            builder = builder.body(req.body.clone());
        }

        builder
            .build()
            .map_err(|e| Error::Internal(format!("Failed to build request: {}", e)))
    }
}

#[async_trait]
impl K8sHttpClient for ReqwestK8sClient {
    async fn request(&self, req: K8sHttpRequest) -> Result<HttpResponse, Error> {
        let http_request = self.build_request(&req)?;

        let response = self
            .client
            .execute(http_request)
            .await
            .map_err(|e| Error::Proxy(format!("Failed to proxy to K8s API: {}", e)))?;

        let status = response.status().as_u16();
        let content_type = extract_content_type(&response);

        let body_bytes = response
            .bytes()
            .await
            .map_err(|e| Error::Proxy(format!("Failed to read K8s API response: {}", e)))?;

        Ok(HttpResponse {
            status,
            content_type,
            body: body_bytes.to_vec(),
        })
    }

    async fn request_streaming(&self, req: K8sHttpRequest) -> Result<StreamingHttpResponse, Error> {
        let http_request = self.build_request(&req)?;

        let response = self
            .client
            .execute(http_request)
            .await
            .map_err(|e| Error::Proxy(format!("Failed to proxy to K8s API: {}", e)))?;

        let status = response.status().as_u16();
        let content_type = extract_content_type(&response);
        let stream = response.bytes_stream().map_err(std::io::Error::other);

        Ok(StreamingHttpResponse {
            status,
            content_type,
            stream: Box::pin(stream),
        })
    }
}

/// Extract Content-Type header from response
fn extract_content_type(response: &reqwest::Response) -> String {
    response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(DEFAULT_CONTENT_TYPE)
        .to_string()
}

/// Get or initialize the shared K8s HTTP client
async fn get_or_init_client() -> Result<&'static reqwest::Client, Error> {
    if let Some(client) = K8S_CLIENT.get() {
        return Ok(client);
    }

    let ca_cert = tokio::fs::read(CA_CERT_PATH)
        .await
        .map_err(|e| Error::Internal(format!("Failed to read in-cluster CA certificate: {}", e)))?;

    let cert = reqwest::Certificate::from_pem(&ca_cert)
        .map_err(|e| Error::Internal(format!("Invalid CA certificate: {}", e)))?;

    let client = reqwest::Client::builder()
        .add_root_certificate(cert)
        .timeout(DEFAULT_TIMEOUT)
        .build()
        .map_err(|e| Error::Internal(format!("Failed to create HTTP client: {}", e)))?;

    let _ = K8S_CLIENT.set(client);
    K8S_CLIENT
        .get()
        .ok_or_else(|| Error::Internal("Failed to initialize K8s HTTP client".into()))
}

// ============================================================================
// Injectable Dependencies
// ============================================================================

/// Injectable dependencies for K8s API forwarding
pub struct ForwarderDeps {
    /// HTTP client for K8s API requests
    pub http_client: Arc<dyn K8sHttpClient>,
    /// Token reader for ServiceAccount auth
    pub token_reader: Arc<dyn TokenReader>,
}

impl ForwarderDeps {
    /// Create dependencies with default implementations
    pub async fn new() -> Result<Self, Error> {
        let http_client = ReqwestK8sClient::new().await?;
        Ok(Self {
            http_client: Arc::new(http_client),
            token_reader: Arc::new(FileTokenReader),
        })
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Route a request to the target cluster
///
/// Authorization is handled by Cedar before this function is called.
/// The proxy's service account is used for K8s API calls with user impersonation
/// to preserve identity for K8s RBAC and audit logs.
pub async fn route_to_cluster(
    state: &AppState,
    cluster_name: &str,
    identity: &UserIdentity,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    let deps = ForwarderDeps::new().await?;
    route_to_cluster_with_deps(state, cluster_name, identity, request, &deps).await
}

/// Route a request to the target cluster with injected dependencies (for testing)
pub async fn route_to_cluster_with_deps(
    state: &AppState,
    cluster_name: &str,
    identity: &UserIdentity,
    request: Request<Body>,
    deps: &ForwarderDeps,
) -> Result<Response<Body>, Error> {
    // SECURITY: Strip any user-supplied impersonation headers
    let request = strip_impersonation_headers(request);

    // Check if this is the local cluster
    if cluster_name == state.cluster_name {
        debug!(cluster = %cluster_name, "Routing to local K8s API");
        return forward_to_k8s_api(&state.k8s_api_url, cluster_name, identity, request, deps).await;
    }

    // Check if the cluster is in our backend
    let route_info = state
        .backend
        .get_route(cluster_name)
        .await
        .ok_or_else(|| Error::ClusterNotFound(cluster_name.to_string()))?;

    if route_info.is_self {
        return forward_to_k8s_api(&state.k8s_api_url, cluster_name, identity, request, deps).await;
    }

    // Get the agent to route through
    let agent_id = route_info
        .agent_id
        .ok_or_else(|| Error::Internal("Route info missing agent_id".into()))?;

    debug!(
        cluster = %cluster_name,
        agent_id = %agent_id,
        "Routing to child cluster via gRPC tunnel"
    );

    route_to_child_cluster(state, cluster_name, &agent_id, identity, request).await
}

// ============================================================================
// Local API Forwarding
// ============================================================================

/// Route request to local K8s API server with user impersonation
///
/// This is the core forwarding logic, extracted for testability.
/// Takes only the dependencies it needs rather than full AppState.
async fn forward_to_k8s_api(
    k8s_api_url: &str,
    cluster_name: &str,
    identity: &UserIdentity,
    request: Request<Body>,
    deps: &ForwarderDeps,
) -> Result<Response<Body>, Error> {
    let method = request.method().to_string();
    let uri = request.uri().clone();
    let path = strip_cluster_prefix(uri.path(), cluster_name);
    let query = uri.query();
    let query_str = query.unwrap_or("");

    debug!(
        method = %method,
        path = %path,
        query = ?query,
        user = %identity.username,
        "Proxying to local K8s API with impersonation"
    );

    let target_url = match query {
        Some(q) => format!("{}{}?{}", k8s_api_url, path, q),
        None => format!("{}{}", k8s_api_url, path),
    };

    let sa_token = deps.token_reader.read_token().await?;

    let content_type = request
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body = axum::body::to_bytes(request.into_body(), MAX_BODY_SIZE)
        .await
        .map_err(|e| Error::Internal(format!("Failed to read request body: {}", e)))?;

    let http_req = K8sHttpRequest {
        method,
        url: target_url,
        token: zeroize::Zeroizing::new(sa_token),
        identity: identity.clone(),
        content_type,
        body: body.to_vec(),
    };

    if is_watch_query(query_str) {
        let streaming = deps.http_client.request_streaming(http_req).await?;
        return build_streaming_response(streaming);
    }

    let http_response = deps.http_client.request(http_req).await?;
    build_buffered_response(http_response)
}

// ============================================================================
// Remote Cluster Forwarding
// ============================================================================

/// Route request to child cluster via backend tunnel
async fn route_to_child_cluster(
    state: &AppState,
    cluster_name: &str,
    agent_id: &str,
    identity: &UserIdentity,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    let method = request.method().to_string();
    let uri = request.uri().clone();
    let path = strip_cluster_prefix(uri.path(), cluster_name).to_string();
    let query = uri.query().unwrap_or("").to_string();
    let content_type = request
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(DEFAULT_CONTENT_TYPE)
        .to_string();
    let accept = request
        .headers()
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(DEFAULT_CONTENT_TYPE)
        .to_string();

    let body = axum::body::to_bytes(request.into_body(), MAX_BODY_SIZE)
        .await
        .map_err(|e| Error::Internal(format!("Failed to read request body: {}", e)))?;

    state
        .backend
        .tunnel_request(
            agent_id,
            K8sTunnelRequest {
                method,
                path,
                query,
                body: body.to_vec(),
                content_type,
                accept,
                target_cluster: cluster_name.to_string(),
                source_user: identity.username.clone(),
                source_groups: identity.groups.clone(),
            },
        )
        .await
        .map_err(proxy_error_to_api_error)
}

// ============================================================================
// Response Building
// ============================================================================

/// Build a response builder with common status and Content-Type headers
fn build_response_base(status: u16, content_type: String) -> axum::http::response::Builder {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header("Content-Type", content_type)
}

/// Build a streaming response for watch/follow queries
fn build_streaming_response(response: StreamingHttpResponse) -> Result<Response<Body>, Error> {
    debug!(status = response.status, "Starting streaming response");

    build_response_base(response.status, response.content_type)
        .header("Transfer-Encoding", "chunked")
        .body(Body::from_stream(response.stream))
        .map_err(|e| Error::Internal(format!("Failed to build streaming response: {}", e)))
}

/// Build a buffered response for regular (non-streaming) requests
fn build_buffered_response(response: HttpResponse) -> Result<Response<Body>, Error> {
    debug!(
        status = response.status,
        body_len = response.body.len(),
        "Received response from K8s API"
    );

    build_response_base(response.status, response.content_type)
        .body(Body::from(response.body))
        .map_err(|e| Error::Internal(format!("Failed to build response: {}", e)))
}

// ============================================================================
// Security
// ============================================================================

/// Strip any user-supplied impersonation headers to prevent privilege escalation
pub(crate) fn strip_impersonation_headers(request: Request<Body>) -> Request<Body> {
    let (mut parts, body) = request.into_parts();

    for header in IMPERSONATION_HEADERS {
        parts.headers.remove(*header);
    }

    // Remove Impersonate-Extra-* headers (prefix-based)
    let extra_headers: Vec<_> = parts
        .headers
        .keys()
        .filter(|k| k.as_str().to_lowercase().starts_with("impersonate-extra-"))
        .cloned()
        .collect();

    for key in extra_headers {
        parts.headers.remove(&key);
    }

    Request::from_parts(parts, body)
}

// ============================================================================
// Error Conversion
// ============================================================================

/// Convert ProxyError to API Error
fn proxy_error_to_api_error(e: ProxyError) -> Error {
    match e {
        ProxyError::ClusterNotFound(name) => Error::ClusterNotFound(name),
        ProxyError::AgentDisconnected => Error::Proxy("Agent disconnected".into()),
        ProxyError::Timeout => Error::Proxy("Request timed out".into()),
        ProxyError::SendFailed(msg) => Error::Proxy(msg),
        ProxyError::AgentError(msg) => Error::Proxy(msg),
        ProxyError::ResponseBuild(msg) => Error::Internal(msg),
        ProxyError::NotConfigured => Error::Internal("Backend not configured".into()),
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
