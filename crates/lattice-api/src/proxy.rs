//! K8s API proxy with path-based routing
//!
//! Handles OIDC authentication and Cedar authorization for K8s API requests.
//! Routes requests to local or child cluster K8s APIs.

use axum::body::Body;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path, State};
use axum::http::Request;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tracing::{debug, instrument};

use crate::auth::authenticate_and_authorize;
use crate::error::Error;
use crate::exec_proxy::{handle_exec_websocket, has_websocket_upgrade_headers};
use crate::k8s_forwarder::route_to_cluster;
use crate::routing::{method_to_k8s_verb, strip_cluster_prefix};
use crate::server::AppState;
use lattice_proto::is_exec_path;

/// Path parameters for proxy routes
#[derive(Debug, Deserialize)]
pub struct ProxyPath {
    /// Target cluster name
    pub cluster_name: String,
    /// Remainder of the path (e.g., "v1/pods")
    #[serde(default)]
    pub path: String,
}

/// Path parameters for exec/attach/portforward routes
#[derive(Debug, Deserialize)]
pub struct ExecPath {
    /// Target cluster name
    pub cluster_name: String,
    /// Namespace
    pub ns: String,
    /// Pod name
    pub pod: String,
}

/// Handle proxy requests to /clusters/{cluster_name}/api/* and /clusters/{cluster_name}/apis/*
///
/// Flow:
/// 1. Validate token (OIDC or ServiceAccount)
/// 2. Authorize with Cedar
/// 3. Route to cluster (uses proxy's service account)
#[instrument(
    skip(state, request),
    fields(
        otel.kind = "server"
    )
)]
pub async fn proxy_handler(
    State(state): State<AppState>,
    Path(params): Path<ProxyPath>,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    let cluster_name = &params.cluster_name;
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path();

    debug!(
        cluster = %cluster_name,
        method = %method,
        path = %params.path,
        "Proxy request received"
    );

    // Check if this is an exec/attach/portforward request that needs WebSocket upgrade
    if is_exec_path(path) && has_websocket_upgrade_headers(request.headers()) {
        return Err(Error::Internal(
            "WebSocket exec requests should use the exec handler route".into(),
        ));
    }

    // Authenticate and authorize
    let action = method_to_k8s_verb(&method);
    let identity = authenticate_and_authorize(
        &state.auth,
        &state.cedar,
        request.headers(),
        cluster_name,
        action,
    )
    .await?;

    // Route to the target cluster
    route_to_cluster(&state, cluster_name, &identity, request).await
}

/// Handle exec/attach/portforward requests with WebSocket upgrade
///
/// This is a separate handler because WebSocket upgrade requires a different extractor.
#[instrument(
    skip(state, ws, request),
    fields(
        otel.kind = "server"
    )
)]
pub async fn exec_handler(
    State(state): State<AppState>,
    Path(params): Path<ExecPath>,
    ws: WebSocketUpgrade,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    let cluster_name = &params.cluster_name;
    let uri = request.uri().clone();
    let path = uri.path();
    let query = uri.query().unwrap_or("").to_string();

    debug!(
        cluster = %cluster_name,
        namespace = %params.ns,
        pod = %params.pod,
        path = %path,
        "Exec WebSocket request received"
    );

    // Authenticate and authorize (exec uses "create" verb like kubectl)
    let identity = authenticate_and_authorize(
        &state.auth,
        &state.cedar,
        request.headers(),
        cluster_name,
        "create",
    )
    .await?;

    // Strip the /clusters/{cluster_name} prefix from the path
    let api_path = strip_cluster_prefix(path, cluster_name);

    // Handle WebSocket upgrade and bridge to gRPC
    Ok(handle_exec_websocket(
        ws,
        state,
        cluster_name.clone(),
        identity,
        api_path.to_string(),
        query,
    )
    .await
    .into_response())
}
