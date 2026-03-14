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
use crate::exec_proxy::handlers::{handle_exec_websocket, has_websocket_upgrade_headers};
use crate::k8s_forwarder::route_to_cluster;
use crate::routing::{parse_cluster_path, strip_cluster_prefix};
use crate::server::AppState;
use lattice_cedar::ClusterAttributes;
use lattice_common::crd::validate_dns_label;
use lattice_proto::is_exec_path;

/// Validate a path parameter as a K8s DNS label (max 63 chars, RFC 1123).
pub(crate) fn validate_k8s_name(name: &str, field: &str) -> std::result::Result<(), Error> {
    validate_dns_label(name, field).map_err(Error::ClusterNotFound)
}

/// Path parameters for proxy routes
#[derive(Debug, Deserialize)]
pub(crate) struct ProxyPath {
    /// Target cluster name
    pub cluster_name: String,
    /// Remainder of the path (e.g., "v1/pods")
    #[serde(default)]
    pub path: String,
}

/// Path parameters for exec/attach/portforward routes
#[derive(Debug, Deserialize)]
pub(crate) struct ExecPath {
    /// Target cluster name
    pub cluster_name: String,
    /// Namespace
    pub ns: String,
    /// Pod name
    pub pod: String,
}

/// Look up cluster attributes from the backend for Cedar authorization.
///
/// Returns an error if the cluster is unknown — we never authorize against
/// default attributes because that could bypass Cedar policies that assume
/// attributes are always populated from real cluster state.
fn cluster_attrs(route: &crate::backend::ProxyRouteInfo) -> ClusterAttributes {
    ClusterAttributes::from_labels(&route.labels)
}

/// Authenticate a request and authorize it against Cedar policies for a cluster.
///
/// Rejects unknown clusters with ClusterNotFound instead of evaluating against
/// default attributes, which would silently pass permissive policies.
pub(crate) async fn authorize_request(
    state: &AppState,
    cluster_name: &str,
    headers: &axum::http::HeaderMap,
) -> Result<crate::auth::UserIdentity, Error> {
    let route = state
        .backend
        .get_route(cluster_name)
        .await
        .ok_or_else(|| Error::ClusterNotFound(cluster_name.to_string()))?;
    let attrs = cluster_attrs(&route);
    authenticate_and_authorize(&state.auth, &state.cedar, headers, cluster_name, &attrs).await
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
pub(crate) async fn proxy_handler(
    State(state): State<AppState>,
    Path(params): Path<ProxyPath>,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    let cluster_name = &params.cluster_name;
    validate_k8s_name(cluster_name, "cluster name")?;

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

    // Parse nested /clusters/{name}/clusters/{name}/... path to extract the
    // full routing target path and the remaining K8s API path.
    let (target_path, _k8s_path) = parse_cluster_path(path)
        .ok_or_else(|| Error::ClusterNotFound("missing cluster path".to_string()))?;

    // Authorize against EVERY cluster in the multi-hop chain, not just the first.
    // This prevents IDOR where a user authorized for cluster A accesses A's
    // children without separate authorization for each hop.
    let identity = authorize_request(&state, cluster_name, request.headers()).await?;
    for hop in target_path.split('/').skip(1) {
        authorize_request(&state, hop, request.headers()).await?;
    }

    route_to_cluster(&state, &target_path, &identity, request).await
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
pub(crate) async fn exec_handler(
    State(state): State<AppState>,
    Path(params): Path<ExecPath>,
    ws: WebSocketUpgrade,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    let cluster_name = &params.cluster_name;
    validate_k8s_name(cluster_name, "cluster name")?;
    validate_k8s_name(&params.ns, "namespace")?;
    validate_k8s_name(&params.pod, "pod name")?;

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

    // Authorize the target cluster
    let identity = authorize_request(&state, cluster_name, request.headers()).await?;

    // Authorize any additional hops in the path (consistent with proxy_handler)
    let (target_path, _) = parse_cluster_path(path)
        .ok_or_else(|| Error::ClusterNotFound("missing cluster path".to_string()))?;
    for hop in target_path.split('/').skip(1) {
        authorize_request(&state, hop, request.headers()).await?;
    }

    // Strip the /clusters/{cluster_name} prefix from the path
    let api_path = strip_cluster_prefix(path, cluster_name).ok_or_else(|| {
        Error::Internal(format!(
            "path missing expected /clusters/{} prefix",
            cluster_name
        ))
    })?;

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
