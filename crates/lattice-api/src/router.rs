//! Subtree routing logic
//!
//! Determines how to reach a target cluster:
//! - If it's the local cluster, proxy to local K8s API
//! - If it's a child cluster, route via gRPC tunnel to agent

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use std::sync::OnceLock;
use tracing::debug;

use crate::error::Error;
use crate::server::AppState;
use lattice_cell::{tunnel_request, K8sRequestParams, TunnelError, DEFAULT_TIMEOUT};

/// Maximum request body size (10 MB - reasonable for K8s API)
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Path to the in-cluster CA certificate
const CA_CERT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

/// Shared HTTP client for local K8s API requests
static K8S_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

/// Route a request to the target cluster
///
/// Authorization is handled by Cedar before this function is called.
/// The proxy's service account is used for K8s API calls.
pub async fn route_to_cluster(
    state: &AppState,
    cluster_name: &str,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    // Check if this is the local cluster
    if cluster_name == state.cluster_name {
        debug!(cluster = %cluster_name, "Routing to local K8s API");
        return route_to_local_api(state, request).await;
    }

    // Check if the cluster is in our subtree
    let route_info = state
        .subtree
        .get_route(cluster_name)
        .await
        .ok_or_else(|| Error::ClusterNotFound(cluster_name.to_string()))?;

    if route_info.is_self {
        return route_to_local_api(state, request).await;
    }

    // Route to child cluster via gRPC tunnel
    debug!(
        cluster = %cluster_name,
        agent_id = ?route_info.agent_id,
        "Routing to child cluster via gRPC tunnel"
    );

    route_to_child_cluster(state, cluster_name, request).await
}

/// Route request to local K8s API server
async fn route_to_local_api(
    state: &AppState,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path();
    let query = uri.query();

    debug!(
        method = %method,
        path = %path,
        query = ?query,
        "Proxying to local K8s API"
    );

    // Build target URL
    let target_url = if let Some(q) = query {
        format!("{}{}?{}", state.k8s_api_url, path, q)
    } else {
        format!("{}{}", state.k8s_api_url, path)
    };

    // Read ServiceAccount token
    let sa_token = read_service_account_token().await?;

    // Get or create the shared HTTP client with proper TLS
    let client = get_k8s_client().await?;

    // Build request with service account auth
    let mut req_builder = client.request(method.clone(), &target_url);
    req_builder = req_builder.header("Authorization", format!("Bearer {}", sa_token));

    // Copy content-type if present
    if let Some(content_type) = request.headers().get("content-type") {
        if let Ok(ct) = content_type.to_str() {
            req_builder = req_builder.header("Content-Type", ct);
        }
    }

    // Copy body with size limit to prevent memory exhaustion
    let body = axum::body::to_bytes(request.into_body(), MAX_BODY_SIZE)
        .await
        .map_err(|e| Error::Internal(format!("Failed to read request body: {}", e)))?;

    if !body.is_empty() {
        req_builder = req_builder.body(body.to_vec());
    }

    // Execute request
    let response = req_builder
        .send()
        .await
        .map_err(|e| Error::Proxy(format!("Failed to proxy to K8s API: {}", e)))?;

    // Build response
    let status = response.status();
    let headers = response.headers().clone();
    let body_bytes = response
        .bytes()
        .await
        .map_err(|e| Error::Proxy(format!("Failed to read K8s API response: {}", e)))?;

    debug!(
        status = %status,
        body_len = body_bytes.len(),
        "Received response from local K8s API"
    );

    let mut builder =
        Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK));

    if let Some(ct) = headers.get("content-type") {
        builder = builder.header("Content-Type", ct.to_str().unwrap_or("application/json"));
    }

    builder
        .body(Body::from(body_bytes.to_vec()))
        .map_err(|e| Error::Internal(format!("Failed to build response: {}", e)))
}

/// Route request to child cluster via gRPC tunnel
async fn route_to_child_cluster(
    state: &AppState,
    cluster_name: &str,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    let agent_registry = state
        .agent_registry
        .as_ref()
        .ok_or_else(|| Error::Internal("Agent registry not configured".into()))?;

    let agent = agent_registry
        .get(cluster_name)
        .ok_or_else(|| Error::ClusterNotFound(format!("Agent not connected: {}", cluster_name)))?;

    let command_tx = agent.command_tx.clone();
    drop(agent);

    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or("").to_string();
    let content_type = request
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();

    let body = axum::body::to_bytes(request.into_body(), MAX_BODY_SIZE)
        .await
        .map_err(|e| Error::Internal(format!("Failed to read request body: {}", e)))?;

    // Use shared tunnel logic
    tunnel_request(
        agent_registry,
        cluster_name,
        command_tx,
        K8sRequestParams {
            method: method.to_string(),
            path,
            query,
            body: body.to_vec(),
            content_type,
        },
    )
    .await
    .map_err(tunnel_error_to_api_error)
}

/// Convert TunnelError to API Error
fn tunnel_error_to_api_error(e: TunnelError) -> Error {
    match e {
        TunnelError::SendFailed(msg) => Error::Proxy(msg),
        TunnelError::ChannelClosed => Error::Proxy("Agent connection lost".into()),
        TunnelError::Timeout => Error::Proxy("Request timed out".into()),
        TunnelError::AgentError(msg) => Error::Proxy(msg),
        TunnelError::ResponseBuild(msg) => Error::Internal(msg),
    }
}

/// Get or create the shared K8s HTTP client with proper TLS verification
async fn get_k8s_client() -> Result<&'static reqwest::Client, Error> {
    if let Some(client) = K8S_CLIENT.get() {
        return Ok(client);
    }

    // Read the in-cluster CA certificate
    let ca_cert = tokio::fs::read(CA_CERT_PATH).await.map_err(|e| {
        Error::Internal(format!("Failed to read in-cluster CA certificate: {}", e))
    })?;

    let cert = reqwest::Certificate::from_pem(&ca_cert)
        .map_err(|e| Error::Internal(format!("Invalid CA certificate: {}", e)))?;

    let client = reqwest::Client::builder()
        .add_root_certificate(cert)
        .timeout(DEFAULT_TIMEOUT)
        .build()
        .map_err(|e| Error::Internal(format!("Failed to create HTTP client: {}", e)))?;

    // Try to set the client, but another thread may have beaten us
    let _ = K8S_CLIENT.set(client);
    Ok(K8S_CLIENT.get().expect("client was just set"))
}

/// Read the ServiceAccount token from the mounted volume
async fn read_service_account_token() -> Result<String, Error> {
    const TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    tokio::fs::read_to_string(TOKEN_PATH)
        .await
        .map_err(|e| Error::Internal(format!("Failed to read ServiceAccount token: {}", e)))
}

#[cfg(test)]
mod tests {
    use lattice_cell::k8s_tunnel::is_watch_query;

    #[test]
    fn test_is_watch_query() {
        assert!(is_watch_query("watch=true"));
        assert!(is_watch_query("watch=1"));
        assert!(is_watch_query("labelSelector=app&watch=true"));
        assert!(!is_watch_query("watch=false"));
        assert!(!is_watch_query(""));
    }
}
