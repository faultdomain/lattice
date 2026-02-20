//! WebSocket handlers for exec/attach
//!
//! Handles WebSocket upgrade for kubectl exec/attach requests
//! and bridges them to the gRPC tunnel or local K8s API.
//!
//! Portforward is handled separately by the `portforward` module using
//! transparent HTTP upgrade proxying.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures::{SinkExt, StreamExt};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, AttachParams};
use kube::Client;
use tracing::{debug, error, info, warn, Instrument};
use uuid::Uuid;

use lattice_proto::{parse_exec_command, parse_exec_params, parse_exec_path};

use crate::backend::ExecTunnelRequest;

use super::io::ExecIo;
use super::local_io::LocalExecIo;
use super::remote_io::RemoteExecIo;
use super::websocket::{
    build_k8s_message, parse_k8s_message, send_close_normal, send_k8s_error_and_close, K8sMessage,
};
use crate::auth::UserIdentity;
use crate::server::AppState;

/// Check if headers indicate a WebSocket upgrade request
pub fn has_websocket_upgrade_headers(headers: &axum::http::HeaderMap) -> bool {
    let has_upgrade = headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    let has_connection = headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_lowercase().contains("upgrade"))
        .unwrap_or(false);

    has_upgrade && has_connection
}

/// Handle exec/attach/portforward requests with WebSocket upgrade
pub async fn handle_exec_websocket(
    ws: WebSocketUpgrade,
    state: AppState,
    cluster_name: String,
    identity: UserIdentity,
    path: String,
    query: String,
) -> impl IntoResponse {
    // K8s WebSocket subprotocols in order of preference
    // Without this negotiation, kubectl disconnects immediately after upgrade
    // See: https://kubernetes.io/docs/reference/using-api/websockets/
    // v5 added in K8s 1.31 for close signal support
    let protocols = [
        "v5.channel.k8s.io",
        "v4.channel.k8s.io",
        "v3.channel.k8s.io",
        "v2.channel.k8s.io",
        "channel.k8s.io",
    ];

    ws.protocols(protocols).on_upgrade(move |socket| {
        handle_websocket_connection(socket, state, cluster_name, identity, path, query)
    })
}

/// Handle the WebSocket connection after upgrade
async fn handle_websocket_connection(
    socket: WebSocket,
    state: AppState,
    cluster_name: String,
    identity: UserIdentity,
    path: String,
    query: String,
) {
    info!(
        cluster = %cluster_name,
        user = %identity.username,
        path = %path,
        "Exec WebSocket connection established"
    );

    // Check if this is a local cluster request
    let route_info = match state.backend.get_route(&cluster_name).await {
        Some(ri) => ri,
        None => {
            let (mut ws_sender, _) = socket.split();
            error!(cluster = %cluster_name, "Cluster not found in backend");
            send_k8s_error_and_close(&mut ws_sender, "Cluster not found").await;
            return;
        }
    };

    // Route to local K8s API or through backend tunnel
    if route_info.is_self {
        handle_local_exec(socket, path, query).await;
    } else {
        handle_remote_exec(
            socket,
            state,
            cluster_name,
            identity,
            path,
            query,
            route_info,
        )
        .await;
    }
}

/// Convert ExecParams to kube AttachParams
fn to_attach_params(params: lattice_proto::ExecParams) -> AttachParams {
    AttachParams {
        stdin: params.stdin,
        stdout: params.stdout,
        stderr: params.stderr,
        tty: params.tty,
        container: params.container,
        max_stdin_buf_size: None,
        max_stdout_buf_size: None,
        max_stderr_buf_size: None,
    }
}

/// Send an error on the WebSocket and close it, consuming the socket
async fn send_error_and_close(socket: WebSocket, msg: impl Into<String>) {
    let (mut ws_sender, _) = socket.split();
    send_k8s_error_and_close(&mut ws_sender, msg).await;
}

/// Handle exec for the local cluster using kube-rs
async fn handle_local_exec(socket: WebSocket, path: String, query: String) {
    let request_id = Uuid::new_v4().to_string();

    // Parse the path to extract namespace and pod name
    let Some((namespace, pod_name, subresource)) = parse_exec_path(&path) else {
        error!(request_id = %request_id, path = %path, "Invalid exec path");
        send_error_and_close(socket, "Invalid exec path").await;
        return;
    };

    debug!(
        request_id = %request_id,
        namespace = %namespace,
        pod = %pod_name,
        subresource = %subresource,
        "Starting local exec session"
    );

    // Create kube client
    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            error!(request_id = %request_id, error = %e, "Failed to create K8s client");
            send_error_and_close(socket, "Failed to create K8s client").await;
            return;
        }
    };

    let pods: Api<Pod> = Api::namespaced(client, namespace);

    let attach_params = to_attach_params(parse_exec_params(&query));
    let commands = parse_exec_command(&query);

    // Start exec/attach
    let result = match subresource {
        "exec" => pods
            .exec(pod_name, commands, &attach_params)
            .await
            .map_err(|e| format!("exec failed: {}", e)),
        "attach" => pods
            .attach(pod_name, &attach_params)
            .await
            .map_err(|e| format!("attach failed: {}", e)),
        _ => {
            send_error_and_close(socket, format!("Unsupported subresource: {}", subresource)).await;
            return;
        }
    };

    let attached = match result {
        Ok(a) => a,
        Err(e) => {
            error!(request_id = %request_id, error = %e, "Failed to start exec");
            send_error_and_close(socket, e).await;
            return;
        }
    };

    info!(request_id = %request_id, namespace = %namespace, pod = %pod_name, "Local exec session established");

    let io = LocalExecIo::new(attached, request_id.clone());
    run_exec_bridge(socket, Box::new(io)).await;

    info!(request_id = %request_id, namespace = %namespace, pod = %pod_name, "Local exec session closed");
}

/// Handle exec for remote clusters through backend tunnel
async fn handle_remote_exec(
    socket: WebSocket,
    state: AppState,
    cluster_name: String,
    identity: UserIdentity,
    path: String,
    query: String,
    route_info: crate::backend::ProxyRouteInfo,
) {
    let agent_id = match route_info.agent_id {
        Some(id) => id,
        None => {
            error!(cluster = %cluster_name, "No agent route available");
            send_error_and_close(socket, "No agent route available").await;
            return;
        }
    };

    let exec_request = ExecTunnelRequest {
        path,
        query,
        target_cluster: cluster_name.clone(),
        source_user: identity.username.clone(),
        source_groups: identity.groups.clone(),
    };

    let (exec_session, data_rx) = match state
        .backend
        .start_exec_session(&agent_id, exec_request)
        .await
    {
        Ok(session) => session,
        Err(e) => {
            error!(error = %e, "Failed to start exec session");
            send_error_and_close(socket, format!("Failed to start exec session: {}", e)).await;
            return;
        }
    };

    let request_id = exec_session.request_id().to_string();
    info!(
        request_id = %request_id,
        cluster = %cluster_name,
        user = %identity.username,
        "Remote exec session started"
    );

    let io = RemoteExecIo::new(exec_session, data_rx);
    run_exec_bridge(socket, Box::new(io)).await;

    info!(
        request_id = %request_id,
        cluster = %cluster_name,
        user = %identity.username,
        "Remote exec session closed"
    );
}

/// Unified WebSocket ↔ ExecIo bridge
///
/// Handles the common message loop for both local and remote exec sessions:
/// - WebSocket input → parse K8s messages → send stdin/resize to ExecIo
/// - ExecIo output → build K8s messages → send to WebSocket
async fn run_exec_bridge(socket: WebSocket, io: Box<dyn ExecIo>) {
    let request_id = io.request_id().to_string();
    let span = tracing::info_span!("exec_bridge", request_id = %request_id);
    run_exec_bridge_inner(socket, io, &request_id)
        .instrument(span)
        .await;
}

async fn run_exec_bridge_inner(socket: WebSocket, mut io: Box<dyn ExecIo>, request_id: &str) {
    debug!(request_id = %request_id, "Exec bridge started");

    let (mut ws_sender, mut ws_receiver) = socket.split();

    loop {
        tokio::select! {
            ws_msg = ws_receiver.next() => {
                match ws_msg {
                    Some(Ok(Message::Binary(data))) => {
                        if let Some(k8s_msg) = parse_k8s_message(&data) {
                            match k8s_msg {
                                K8sMessage::Resize { width, height } => {
                                    io.send_resize(width, height).await;
                                }
                                K8sMessage::Stdin(payload) | K8sMessage::Raw(payload) => {
                                    if io.send_stdin(payload).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if io.send_stdin(text.as_bytes().to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        debug!(request_id = %request_id, "WebSocket close received");
                        break;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = ws_sender.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Err(e)) => {
                        warn!(request_id = %request_id, error = %e, "WebSocket error");
                        break;
                    }
                    None => {
                        debug!(request_id = %request_id, "WebSocket stream ended");
                        break;
                    }
                }
            }

            output = io.output_rx().recv() => {
                match output {
                    Some(exec_output) => {
                        let msg = build_k8s_message(exec_output.stream_id, &exec_output.data);
                        if ws_sender.send(Message::Binary(msg.into())).await.is_err() {
                            break;
                        }
                        if exec_output.is_terminal {
                            break;
                        }
                    }
                    None => {
                        debug!(request_id = %request_id, "Output channel closed");
                        break;
                    }
                }
            }
        }
    }

    // Let the backend clean up and send any final messages (e.g., exit status)
    if let Some(final_msg) = io.finalize().await {
        let msg = build_k8s_message(final_msg.stream_id, &final_msg.data);
        let _ = ws_sender.send(Message::Binary(msg.into())).await;
    }

    send_close_normal(&mut ws_sender, "Exec session ended").await;

    debug!(request_id = %request_id, "Exec bridge ended");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_websocket_upgrade_headers() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("upgrade", "websocket".parse().unwrap());
        headers.insert("connection", "upgrade".parse().unwrap());

        assert!(has_websocket_upgrade_headers(&headers));
    }

    #[test]
    fn test_has_websocket_upgrade_headers_case_insensitive() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("upgrade", "WebSocket".parse().unwrap());
        headers.insert("connection", "Upgrade".parse().unwrap());

        assert!(has_websocket_upgrade_headers(&headers));
    }

    #[test]
    fn test_has_websocket_upgrade_headers_empty() {
        let headers = axum::http::HeaderMap::new();
        assert!(!has_websocket_upgrade_headers(&headers));
    }

    #[test]
    fn test_has_websocket_upgrade_headers_missing_connection() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("upgrade", "websocket".parse().unwrap());

        assert!(!has_websocket_upgrade_headers(&headers));
    }

    #[test]
    fn test_has_websocket_upgrade_headers_wrong_upgrade_type() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("upgrade", "spdy".parse().unwrap());
        headers.insert("connection", "upgrade".parse().unwrap());

        assert!(!has_websocket_upgrade_headers(&headers));
    }
}
