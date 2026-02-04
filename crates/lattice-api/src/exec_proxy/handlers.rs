//! WebSocket handlers for exec/attach/portforward
//!
//! Handles WebSocket upgrade for kubectl exec/attach/portforward requests
//! and bridges them to the gRPC tunnel or local K8s API.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures::{SinkExt, StreamExt};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, AttachParams, TerminalSize};
use kube::Client;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

use lattice_cell::{start_exec_session, ExecRequestParams};
use lattice_proto::{
    parse_exec_command, parse_exec_params, parse_exec_path, parse_portforward_ports, stream_id,
};

use super::websocket::{
    build_k8s_message, channel, parse_k8s_message, send_close_error, send_close_internal,
    send_close_normal, K8sMessage,
};
use crate::auth::UserIdentity;
use crate::server::AppState;

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
    ws.on_upgrade(move |socket| {
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
    let route_info = match state.subtree.get_route(&cluster_name).await {
        Some(ri) => ri,
        None => {
            let (mut ws_sender, _) = socket.split();
            error!(cluster = %cluster_name, "Cluster not found in subtree");
            send_close_error(&mut ws_sender, "Cluster not found").await;
            return;
        }
    };

    // Route to local K8s API or through gRPC tunnel
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

/// Handle exec for the local cluster using kube-rs
async fn handle_local_exec(socket: WebSocket, path: String, query: String) {
    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Parse the path to extract namespace and pod name
    let Some((namespace, pod_name, subresource)) = parse_exec_path(&path) else {
        error!(path = %path, "Invalid exec path");
        send_close_error(&mut ws_sender, "Invalid exec path").await;
        return;
    };

    info!(
        namespace = %namespace,
        pod = %pod_name,
        subresource = %subresource,
        "Starting local exec session"
    );

    // Create kube client
    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Failed to create K8s client");
            send_close_internal(&mut ws_sender, "Failed to create K8s client").await;
            return;
        }
    };

    let pods: Api<Pod> = Api::namespaced(client, namespace);

    // Handle portforward separately - it uses a different API
    if subresource == "portforward" {
        handle_local_portforward(ws_sender, ws_receiver, pods, pod_name, &query).await;
        return;
    }

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
            send_close_error(
                &mut ws_sender,
                format!("Unsupported subresource: {}", subresource),
            )
            .await;
            return;
        }
    };

    let mut attached = match result {
        Ok(a) => a,
        Err(e) => {
            error!(error = %e, "Failed to start exec");
            send_close_internal(&mut ws_sender, e).await;
            return;
        }
    };

    info!(namespace = %namespace, pod = %pod_name, "Local exec session established");

    // Create channel for forwarding stdout/stderr to main loop
    let (output_tx, mut output_rx) = tokio::sync::mpsc::channel::<(u8, Vec<u8>)>(64);

    // Spawn tasks to read stdout/stderr
    let mut handles = vec![];

    if let Some(stdout) = attached.stdout() {
        let tx = output_tx.clone();
        handles.push(tokio::spawn(async move {
            forward_stream_to_channel(stdout, tx, channel::STDOUT).await;
        }));
    }

    if let Some(stderr) = attached.stderr() {
        let tx = output_tx.clone();
        handles.push(tokio::spawn(async move {
            forward_stream_to_channel(stderr, tx, channel::STDERR).await;
        }));
    }

    // Drop our copy of the sender so the channel closes when tasks complete
    drop(output_tx);

    // Handle stdin from WebSocket and output from kube-rs
    let mut stdin_writer = attached.stdin();
    let mut terminal_size_tx = attached.terminal_size();

    loop {
        tokio::select! {
            ws_msg = ws_receiver.next() => {
                match ws_msg {
                    Some(Ok(Message::Binary(data))) => {
                        if let Some(k8s_msg) = parse_k8s_message(&data) {
                            match k8s_msg {
                                K8sMessage::Resize { width, height } => {
                                    if let Some(ref mut tx) = terminal_size_tx {
                                        let _ = tx.send(TerminalSize { width, height }).await;
                                    }
                                }
                                K8sMessage::Stdin(payload) | K8sMessage::Raw(payload) => {
                                    if let Some(ref mut writer) = stdin_writer {
                                        if writer.write_all(&payload).await.is_err() {
                                            break;
                                        }
                                        let _ = writer.flush().await;
                                    }
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if let Some(ref mut writer) = stdin_writer {
                            if writer.write_all(text.as_bytes()).await.is_err() {
                                break;
                            }
                            let _ = writer.flush().await;
                        }
                    }
                    Some(Ok(Message::Close(_))) => break,
                    Some(Ok(Message::Ping(data))) => {
                        let _ = ws_sender.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Err(_)) | None => break,
                }
            }

            output = output_rx.recv() => {
                match output {
                    Some((stream_id, data)) => {
                        let msg = build_k8s_message(stream_id, &data);
                        if ws_sender.send(Message::Binary(msg.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break, // All output streams closed
                }
            }
        }
    }

    // Wait for reader tasks
    for h in handles {
        let _ = h.await;
    }

    send_close_normal(&mut ws_sender, "Exec session ended").await;
    info!(namespace = %namespace, pod = %pod_name, "Local exec session closed");
}

/// Forward a stream (stdout/stderr) to a channel
async fn forward_stream_to_channel<R: AsyncRead + Unpin>(
    mut reader: R,
    tx: tokio::sync::mpsc::Sender<(u8, Vec<u8>)>,
    stream_id: u8,
) {
    let mut buf = vec![0u8; 4096];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if tx.send((stream_id, buf[..n].to_vec())).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

/// Handle portforward for the local cluster
async fn handle_local_portforward(
    mut ws_sender: futures::stream::SplitSink<WebSocket, Message>,
    mut ws_receiver: futures::stream::SplitStream<WebSocket>,
    pods: Api<Pod>,
    pod_name: &str,
    query: &str,
) {
    let ports = parse_portforward_ports(query);

    if ports.is_empty() {
        send_close_error(&mut ws_sender, "No ports specified").await;
        return;
    }

    // Support single port for now
    let port = ports[0];

    info!(pod = %pod_name, port, "Starting local portforward session");

    // Start portforwarder
    let mut pf = match pods.portforward(pod_name, &[port]).await {
        Ok(pf) => pf,
        Err(e) => {
            error!(error = %e, "Failed to start portforward");
            send_close_internal(&mut ws_sender, format!("portforward failed: {}", e)).await;
            return;
        }
    };

    // Get the stream for the port
    let stream = match pf.take_stream(port) {
        Some(s) => s,
        None => {
            error!(port, "Failed to get stream for port");
            send_close_internal(
                &mut ws_sender,
                format!("Failed to get stream for port {}", port),
            )
            .await;
            return;
        }
    };

    info!(pod = %pod_name, port, "Local portforward session established");

    let (reader, mut writer) = tokio::io::split(stream);

    // Create channel for forwarding data from pod to WebSocket
    let (output_tx, mut output_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    // Spawn reader task
    let reader_handle = tokio::spawn(async move {
        let tx = output_tx;
        let mut reader = reader;
        let mut buf = vec![0u8; 4096];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Handle bidirectional communication
    loop {
        tokio::select! {
            ws_msg = ws_receiver.next() => {
                match ws_msg {
                    Some(Ok(Message::Binary(data))) => {
                        // For portforward, data is sent raw (no channel prefix)
                        if writer.write_all(&data).await.is_err() {
                            break;
                        }
                        let _ = writer.flush().await;
                    }
                    Some(Ok(Message::Text(text))) => {
                        if writer.write_all(text.as_bytes()).await.is_err() {
                            break;
                        }
                        let _ = writer.flush().await;
                    }
                    Some(Ok(Message::Close(_))) => break,
                    Some(Ok(Message::Ping(data))) => {
                        let _ = ws_sender.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Err(_)) | None => break,
                }
            }

            output = output_rx.recv() => {
                match output {
                    Some(data) => {
                        if ws_sender.send(Message::Binary(data.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    let _ = reader_handle.await;

    send_close_normal(&mut ws_sender, "Portforward session ended").await;
    info!(pod = %pod_name, port, "Local portforward session closed");
}

/// Handle exec for remote clusters through gRPC tunnel
async fn handle_remote_exec(
    socket: WebSocket,
    state: AppState,
    cluster_name: String,
    identity: UserIdentity,
    path: String,
    query: String,
    route_info: lattice_cell::RouteInfo,
) {
    let (mut ws_sender, mut ws_receiver) = socket.split();

    let Some(agent_registry) = state.agent_registry.as_ref() else {
        error!("Agent registry not configured");
        send_close_internal(&mut ws_sender, "Agent registry not configured").await;
        return;
    };

    let agent_id = match route_info.agent_id {
        Some(id) => id,
        None => {
            error!(cluster = %cluster_name, "No agent route available");
            send_close_error(&mut ws_sender, "No agent route available").await;
            return;
        }
    };

    let command_tx = match agent_registry.get(&agent_id) {
        Some(agent) => agent.command_tx.clone(),
        None => {
            error!(agent = %agent_id, "Agent not connected");
            send_close_error(&mut ws_sender, "Agent not connected").await;
            return;
        }
    };

    let exec_params = ExecRequestParams {
        path,
        query,
        target_cluster: cluster_name.clone(),
        source_user: identity.username.clone(),
        source_groups: identity.groups.clone(),
    };

    let (exec_session, mut data_rx) =
        match start_exec_session(agent_registry, &agent_id, command_tx, exec_params).await {
            Ok(session) => session,
            Err(e) => {
                error!(error = %e, "Failed to start exec session");
                send_close_internal(
                    &mut ws_sender,
                    format!("Failed to start exec session: {}", e),
                )
                .await;
                return;
            }
        };

    let request_id = exec_session.request_id.clone();
    info!(request_id = %request_id, "Remote exec session started");

    loop {
        tokio::select! {
            ws_msg = ws_receiver.next() => {
                match ws_msg {
                    Some(Ok(Message::Binary(data))) => {
                        if let Some(k8s_msg) = parse_k8s_message(&data) {
                            match k8s_msg {
                                K8sMessage::Resize { width, height } => {
                                    if let Err(e) = exec_session.send_resize(width as u32, height as u32).await {
                                        warn!(request_id = %request_id, error = %e, "Failed to send resize");
                                    }
                                }
                                K8sMessage::Stdin(payload) => {
                                    if let Err(e) = exec_session.send_stdin(payload).await {
                                        warn!(request_id = %request_id, error = %e, "Failed to send stdin");
                                        break;
                                    }
                                }
                                K8sMessage::Raw(payload) => {
                                    if let Err(e) = exec_session.send_stdin(payload).await {
                                        warn!(request_id = %request_id, error = %e, "Failed to send stdin");
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if let Err(e) = exec_session.send_stdin(text.as_bytes().to_vec()).await {
                            warn!(request_id = %request_id, error = %e, "Failed to send stdin text");
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        debug!(request_id = %request_id, "WebSocket closed by client");
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

            exec_data = data_rx.recv() => {
                match exec_data {
                    Some(data) => {
                        if data.stream_id == stream_id::ERROR {
                            let error_msg = String::from_utf8_lossy(&data.data);
                            error!(request_id = %request_id, error = %error_msg, "Exec error from agent");
                            send_close_internal(&mut ws_sender, error_msg.to_string()).await;
                            break;
                        }

                        let msg = build_k8s_message(data.stream_id as u8, &data.data);

                        if let Err(e) = ws_sender.send(Message::Binary(msg.into())).await {
                            warn!(request_id = %request_id, error = %e, "Failed to send to WebSocket");
                            break;
                        }

                        if data.stream_end && data.stream_id != stream_id::STDIN {
                            debug!(request_id = %request_id, stream_id = data.stream_id, "Stream ended");
                        }
                    }
                    None => {
                        debug!(request_id = %request_id, "Exec data channel closed");
                        break;
                    }
                }
            }
        }
    }

    send_close_normal(&mut ws_sender, "Exec session ended").await;
    info!(request_id = %request_id, "Remote exec session closed");
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
