//! Transparent HTTP upgrade proxy for portforward requests
//!
//! Instead of terminating the WebSocket/SPDY connection, this handler forwards
//! the entire HTTP upgrade handshake to the K8s API server and bridges raw byte
//! streams. This is protocol-agnostic — works with SPDY, WebSocket, or any
//! future upgrade protocol without parsing frames.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::Request;
use axum::response::Response;
use tracing::{debug, error, info, instrument};

use crate::auth::authenticate_and_authorize;
use crate::error::Error;
use crate::k8s_forwarder::{FileTokenReader, TokenReader, CA_CERT_PATH};
use crate::proxy::{cluster_attrs, ExecPath};
use crate::routing::strip_cluster_prefix;
use crate::server::AppState;

/// Handle portforward requests by transparently proxying the HTTP upgrade
///
/// Flow:
/// 1. Authenticate and authorize the user
/// 2. Check if the cluster is local or remote
/// 3. Local: proxy the full HTTP upgrade to the K8s API server
/// 4. Remote: return error (not yet supported)
#[instrument(
    skip(state, request),
    fields(otel.kind = "server")
)]
pub(crate) async fn portforward_handler(
    State(state): State<AppState>,
    Path(params): Path<ExecPath>,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    let cluster_name = &params.cluster_name;

    debug!(
        cluster = %cluster_name,
        namespace = %params.ns,
        pod = %params.pod,
        "Portforward request received"
    );

    let attrs = cluster_attrs(&state, cluster_name).await;
    let identity = authenticate_and_authorize(
        &state.auth,
        &state.cedar,
        request.headers(),
        cluster_name,
        &attrs,
    )
    .await?;

    let uri = request.uri().clone();
    let path = uri.path();
    let api_path = strip_cluster_prefix(path, cluster_name);
    let query = uri.query().unwrap_or("");

    // Check if this is a local or remote cluster
    let route_info = state
        .backend
        .get_route(cluster_name)
        .await
        .ok_or_else(|| Error::ClusterNotFound(cluster_name.to_string()))?;

    if route_info.is_self || cluster_name == &state.cluster_name {
        proxy_upgrade_to_k8s(&state.k8s_api_url, &identity, api_path, query, request).await
    } else {
        Err(Error::Proxy("Remote portforward not yet supported".into()))
    }
}

/// Proxy an HTTP upgrade request transparently to the K8s API server
///
/// Forwards upgrade headers (Upgrade, Connection, Sec-WebSocket-*) to the
/// upstream K8s API, bridges the upgraded connections bidirectionally, and
/// returns the upstream's 101 response to the client.
async fn proxy_upgrade_to_k8s(
    k8s_api_url: &str,
    identity: &crate::auth::UserIdentity,
    api_path: &str,
    query: &str,
    request: Request<Body>,
) -> Result<Response<Body>, Error> {
    // Clone headers before we consume the request for upgrade
    let incoming_headers = request.headers().clone();

    // Get the incoming upgrade handle — this takes ownership of the connection
    let incoming_upgrade = hyper::upgrade::on(request);

    // Read SA token for upstream auth
    let token_reader = FileTokenReader;
    let sa_token = token_reader.read_token().await?;

    // Build upstream URL
    let upstream_url = if query.is_empty() {
        format!("{}{}", k8s_api_url, api_path)
    } else {
        format!("{}{}?{}", k8s_api_url, api_path, query)
    };

    debug!(url = %upstream_url, "Proxying upgrade to K8s API");

    // Build upstream request with HTTP/1.1 (required for upgrade)
    let ca_cert = tokio::fs::read(CA_CERT_PATH)
        .await
        .map_err(|e| Error::Internal(format!("Failed to read CA certificate: {}", e)))?;

    let cert = reqwest::Certificate::from_pem(&ca_cert)
        .map_err(|e| Error::Internal(format!("Invalid CA certificate: {}", e)))?;

    let upgrade_client = reqwest::Client::builder()
        .add_root_certificate(cert)
        .http1_only()
        .no_proxy()
        .build()
        .map_err(|e| Error::Internal(format!("Failed to create upgrade client: {}", e)))?;

    // Start with SA token + impersonation
    let mut upstream_builder = upgrade_client
        .get(&upstream_url)
        .header("Authorization", format!("Bearer {}", sa_token))
        .header("Impersonate-User", &identity.username);

    for group in &identity.groups {
        upstream_builder = upstream_builder.header("Impersonate-Group", group);
    }

    // Forward upgrade-related headers from the incoming request
    for name in &[
        "Upgrade",
        "Connection",
        "Sec-WebSocket-Key",
        "Sec-WebSocket-Version",
        "Sec-WebSocket-Protocol",
        "Sec-WebSocket-Extensions",
    ] {
        if let Some(value) = incoming_headers.get(*name) {
            upstream_builder = upstream_builder.header(*name, value);
        }
    }

    // Send the upgrade request to K8s API
    let upstream_response = upstream_builder.send().await.map_err(|e| {
        Error::Proxy(format!(
            "Failed to connect to K8s API for portforward: {}",
            e
        ))
    })?;

    let upstream_status = upstream_response.status();
    if upstream_status != reqwest::StatusCode::SWITCHING_PROTOCOLS {
        let body = upstream_response
            .text()
            .await
            .unwrap_or_else(|_| "unknown error".to_string());
        return Err(Error::Proxy(format!(
            "K8s API returned {} instead of 101: {}",
            upstream_status, body
        )));
    }

    // Collect response headers to return to client
    let mut response_builder = Response::builder().status(101);
    for (name, value) in upstream_response.headers() {
        response_builder = response_builder.header(name, value);
    }

    // Get the upgraded upstream connection
    let upstream_upgraded = upstream_response
        .upgrade()
        .await
        .map_err(|e| Error::Internal(format!("Failed to upgrade upstream connection: {}", e)))?;

    // Spawn a task to bridge the two upgraded connections
    tokio::spawn(async move {
        match incoming_upgrade.await {
            Ok(incoming_upgraded) => {
                // hyper::Upgraded needs TokioIo adapter for tokio AsyncRead/Write
                let mut incoming = hyper_util::rt::TokioIo::new(incoming_upgraded);
                // reqwest::Upgraded already implements tokio AsyncRead/Write
                let mut upstream = upstream_upgraded;

                match tokio::io::copy_bidirectional(&mut incoming, &mut upstream).await {
                    Ok((from_client, from_server)) => {
                        info!(from_client, from_server, "Portforward session ended");
                    }
                    Err(e) => {
                        debug!(error = %e, "Portforward bridge error");
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to upgrade incoming connection");
            }
        }
    });

    // Return the 101 response to the client
    response_builder
        .body(Body::empty())
        .map_err(|e| Error::Internal(format!("Failed to build upgrade response: {}", e)))
}
