//! K8s API proxy with path-based routing
//!
//! Handles OIDC authentication and Cedar authorization for K8s API requests.
//! Routes requests to local or child cluster K8s APIs.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{Method, Request};
use axum::response::Response;
use serde::Deserialize;
use tracing::{debug, instrument};

use crate::auth::extract_bearer_token;
use crate::error::Error;
use crate::router::route_to_cluster;
use crate::server::AppState;

/// Path parameters for proxy routes
#[derive(Debug, Deserialize)]
pub struct ProxyPath {
    /// Target cluster name
    pub cluster_name: String,
    /// Remainder of the path (e.g., "v1/pods")
    #[serde(default)]
    pub path: String,
}

/// Handle proxy requests to /clusters/{cluster_name}/api/* and /clusters/{cluster_name}/apis/*
///
/// Flow:
/// 1. Validate OIDC token
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

    debug!(
        cluster = %cluster_name,
        method = %method,
        path = %params.path,
        "Proxy request received"
    );

    // 1. Extract and validate token (OIDC or ServiceAccount)
    let token = extract_bearer_token(request.headers())
        .ok_or_else(|| Error::Unauthorized("Missing Authorization header".into()))?;

    let identity = state.auth.validate(token).await?;

    // 2. Map HTTP method to K8s verb for authorization
    let action = method_to_k8s_verb(&method);

    // 3. Check Cedar authorization
    state
        .cedar
        .authorize(&identity, cluster_name, action)
        .await?;

    // 4. Route to the target cluster (passing identity for downstream Cedar checks)
    route_to_cluster(&state, cluster_name, &identity, request).await
}

/// Map HTTP method to Kubernetes verb
fn method_to_k8s_verb(method: &Method) -> &'static str {
    match *method {
        Method::GET => "get", // Could also be "list" or "watch" depending on path
        Method::POST => "create",
        Method::PUT => "update",
        Method::PATCH => "patch",
        Method::DELETE => "delete",
        Method::HEAD => "get",
        Method::OPTIONS => "get",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_to_k8s_verb() {
        assert_eq!(method_to_k8s_verb(&Method::GET), "get");
        assert_eq!(method_to_k8s_verb(&Method::POST), "create");
        assert_eq!(method_to_k8s_verb(&Method::PUT), "update");
        assert_eq!(method_to_k8s_verb(&Method::PATCH), "patch");
        assert_eq!(method_to_k8s_verb(&Method::DELETE), "delete");
    }
}
