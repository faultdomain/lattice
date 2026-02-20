//! Exec/attach/portforward execution for K8s API proxy
//!
//! Handles exec, attach, and portforward requests from the parent cell by
//! establishing bidirectional streams to the local K8s API server.
//!
//! Unlike watch requests that use HTTP chunked transfer encoding, exec/attach/portforward
//! require HTTP upgrade (SPDY/WebSocket) for bidirectional multiplexed streams.

use std::sync::Arc;

use dashmap::DashMap;
use futures::SinkExt;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, AttachParams, TerminalSize};
use kube::Client;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use lattice_proto::{
    agent_message::Payload, parse_exec_command, parse_exec_params, parse_exec_path,
    parse_portforward_ports, AgentMessage, ExecData, ExecRequest,
};

use lattice_proto::stream_id;

/// Build a K8s success Status JSON for exec sessions that exit cleanly.
///
/// kubectl expects a Status object on channel 3 (error/status channel) at
/// session end. For successful exits, this is `{"status": "Success"}`.
fn k8s_success_status() -> serde_json::Value {
    serde_json::json!({
        "status": "Success",
        "metadata": {}
    })
}

/// Registry for tracking active exec sessions on the agent
#[derive(Default)]
pub struct ExecRegistry {
    active: DashMap<String, ExecSession>,
}

struct ExecSession {
    cancel_token: CancellationToken,
    stdin_tx: mpsc::Sender<Vec<u8>>,
    resize_tx: mpsc::Sender<TerminalSize>,
}

impl ExecRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn register(
        &self,
        request_id: String,
    ) -> (
        CancellationToken,
        mpsc::Receiver<Vec<u8>>,
        mpsc::Receiver<TerminalSize>,
    ) {
        let cancel_token = CancellationToken::new();
        let (stdin_tx, stdin_rx) = mpsc::channel(64);
        let (resize_tx, resize_rx) = mpsc::channel(8);

        debug!(request_id = %request_id, "Registering exec session");
        self.active.insert(
            request_id,
            ExecSession {
                cancel_token: cancel_token.clone(),
                stdin_tx,
                resize_tx,
            },
        );

        (cancel_token, stdin_rx, resize_rx)
    }

    pub async fn send_stdin(&self, request_id: &str, data: Vec<u8>) -> bool {
        if let Some(session) = self.active.get(request_id) {
            session.stdin_tx.send(data).await.is_ok()
        } else {
            warn!(request_id = %request_id, "Stdin for unknown exec session");
            false
        }
    }

    pub async fn send_resize(&self, request_id: &str, width: u16, height: u16) -> bool {
        if let Some(session) = self.active.get(request_id) {
            session
                .resize_tx
                .send(TerminalSize { width, height })
                .await
                .is_ok()
        } else {
            warn!(request_id = %request_id, "Resize for unknown exec session");
            false
        }
    }

    pub fn cancel(&self, request_id: &str) -> bool {
        if let Some((_, session)) = self.active.remove(request_id) {
            info!(request_id = %request_id, "Cancelling exec session");
            session.cancel_token.cancel();
            true
        } else {
            false
        }
    }

    fn unregister(&self, request_id: &str) {
        self.active.remove(request_id);
    }

    pub fn cancel_all(&self) {
        let count = self.active.len();
        if count > 0 {
            info!(count, "Cancelling all active exec sessions");
            self.active.retain(|_, session| {
                session.cancel_token.cancel();
                false
            });
        }
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

/// Spawn a task to read from an async reader and send to message channel
async fn spawn_reader_task<R: AsyncRead + Unpin + Send + 'static>(
    mut reader: R,
    stream_id: u32,
    request_id: String,
    cluster_name: String,
    message_tx: mpsc::Sender<AgentMessage>,
    cancel_token: CancellationToken,
) {
    let mut buf = vec![0u8; 4096];

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => break,
            result = reader.read(&mut buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        let msg = AgentMessage {
                            cluster_name: cluster_name.clone(),
                            payload: Some(Payload::ExecData(ExecData {
                                request_id: request_id.clone(),
                                stream_id,
                                data: buf[..n].to_vec(),
                                stream_end: false,
                            })),
                        };
                        if message_tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!(request_id = %request_id, stream_id, error = %e, "Reader error");
                        break;
                    }
                }
            }
        }
    }

    // Send stream end marker
    let _ = message_tx
        .send(AgentMessage {
            cluster_name,
            payload: Some(Payload::ExecData(ExecData {
                request_id,
                stream_id,
                data: vec![],
                stream_end: true,
            })),
        })
        .await;
}

/// Execute an exec request and stream data bidirectionally.
pub async fn execute_exec(
    client: Client,
    req: ExecRequest,
    cluster_name: String,
    message_tx: mpsc::Sender<AgentMessage>,
    registry: Arc<ExecRegistry>,
) {
    let request_id = req.request_id.clone();

    let path = req.path.clone();
    let Some((namespace, pod_name, subresource)) = parse_exec_path(&path) else {
        send_error(&message_tx, &cluster_name, &request_id, "Invalid exec path").await;
        return;
    };

    debug!(
        request_id = %request_id,
        namespace, pod = pod_name, subresource,
        "Starting exec session"
    );

    // Handle portforward separately - it uses a different API
    if subresource == "portforward" {
        execute_portforward(
            client,
            req,
            cluster_name,
            message_tx,
            registry,
            namespace,
            pod_name,
        )
        .await;
        return;
    }

    let (cancel_token, mut stdin_rx, mut resize_rx) = registry.register(request_id.clone());
    let attach_params = to_attach_params(parse_exec_params(&req.query));
    let commands = parse_exec_command(&req.query);

    let pods: Api<Pod> = Api::namespaced(client, namespace);

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
            send_error(
                &message_tx,
                &cluster_name,
                &request_id,
                &format!("unknown subresource: {}", subresource),
            )
            .await;
            registry.unregister(&request_id);
            return;
        }
    };

    let mut attached = match result {
        Ok(a) => a,
        Err(e) => {
            send_error(&message_tx, &cluster_name, &request_id, &e).await;
            registry.unregister(&request_id);
            return;
        }
    };

    info!(
        request_id = %request_id,
        namespace, pod = pod_name,
        "Exec session established"
    );

    // Spawn reader tasks for stdout and stderr
    let mut handles = vec![];

    if let Some(stdout) = attached.stdout() {
        handles.push(tokio::spawn(spawn_reader_task(
            stdout,
            stream_id::STDOUT,
            request_id.clone(),
            cluster_name.clone(),
            message_tx.clone(),
            cancel_token.clone(),
        )));
    }

    if let Some(stderr) = attached.stderr() {
        handles.push(tokio::spawn(spawn_reader_task(
            stderr,
            stream_id::STDERR,
            request_id.clone(),
            cluster_name.clone(),
            message_tx.clone(),
            cancel_token.clone(),
        )));
    }

    // Handle stdin and resize in main task
    let mut stdin_writer = attached.stdin();
    let mut terminal_size_tx = attached.terminal_size();

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                debug!(request_id = %request_id, "Exec session cancelled");
                break;
            }

            Some(data) = stdin_rx.recv() => {
                if let Some(ref mut writer) = stdin_writer {
                    if writer.write_all(&data).await.is_err() || writer.flush().await.is_err() {
                        break;
                    }
                }
            }

            Some(size) = resize_rx.recv() => {
                if let Some(ref mut tx) = terminal_size_tx {
                    let _ = tx.send(size).await;
                }
            }

            // All reader tasks completed
            _ = async {
                for h in &mut handles {
                    let _ = h.await;
                }
            } => {
                debug!(request_id = %request_id, "All streams ended");
                break;
            }
        }
    }

    // Signal cancellation so any still-running reader tasks exit their loops.
    cancel_token.cancel();

    // Do NOT re-await handles here. If the select loop broke via the "all
    // streams ended" branch, the JoinHandle results were already consumed
    // through &mut references. Awaiting a consumed JoinHandle hangs forever
    // because the result has been taken and no waker will fire. Dropping the
    // handles is sufficient — the spawned tasks will complete independently.
    drop(handles);

    // Drop stdin/resize so kube-rs can close the WebSocket connection.
    drop(stdin_writer);
    drop(terminal_size_tx);

    // Get exit status and send it on the error channel (K8s protocol requirement).
    // kubectl expects a JSON Status object on channel 3 before it considers
    // the session complete. Without this, kubectl hangs waiting for status.
    // take_status() is a oneshot receiver that resolves as soon as kube-rs
    // receives channel 3 data — it does NOT wait for the background task to exit.
    let status_json = match attached.take_status() {
        Some(status_future) => match status_future.await {
            Some(status) => {
                debug!(request_id = %request_id, ?status, "Exec completed with status");
                serde_json::to_vec(&status).unwrap_or_default()
            }
            None => {
                debug!(request_id = %request_id, "Exec completed with no status");
                serde_json::to_vec(&k8s_success_status()).unwrap_or_default()
            }
        },
        None => {
            debug!(request_id = %request_id, "Exec completed (no status channel)");
            serde_json::to_vec(&k8s_success_status()).unwrap_or_default()
        }
    };

    let _ = message_tx
        .send(AgentMessage {
            cluster_name,
            payload: Some(Payload::ExecData(ExecData {
                request_id: request_id.clone(),
                stream_id: stream_id::ERROR,
                data: status_json,
                stream_end: true,
            })),
        })
        .await;

    registry.unregister(&request_id);
    info!(request_id = %request_id, "Exec session ended");
}

async fn send_error(
    tx: &mpsc::Sender<AgentMessage>,
    cluster_name: &str,
    request_id: &str,
    error: &str,
) {
    error!(request_id = %request_id, error, "Exec error");
    let _ = tx
        .send(AgentMessage {
            cluster_name: cluster_name.to_string(),
            payload: Some(Payload::ExecData(ExecData {
                request_id: request_id.to_string(),
                stream_id: stream_id::ERROR,
                data: error.as_bytes().to_vec(),
                stream_end: true,
            })),
        })
        .await;
}

/// Execute a portforward request.
///
/// Portforward establishes a bidirectional stream for forwarding traffic to a port
/// on a pod. Data is sent/received through the exec session's stdin/stdout channels.
///
/// Note: Currently supports forwarding a single port per session. For multiple ports,
/// create multiple portforward requests.
async fn execute_portforward(
    client: Client,
    req: ExecRequest,
    cluster_name: String,
    message_tx: mpsc::Sender<AgentMessage>,
    registry: Arc<ExecRegistry>,
    namespace: &str,
    pod_name: &str,
) {
    let request_id = req.request_id.clone();
    let ports = parse_portforward_ports(&req.query);

    if ports.is_empty() {
        send_error(
            &message_tx,
            &cluster_name,
            &request_id,
            "no ports specified for portforward",
        )
        .await;
        return;
    }

    // For simplicity, we handle one port per session. Multiple ports would need
    // separate sessions or a more complex multiplexing scheme.
    let port = ports[0];

    debug!(
        request_id = %request_id,
        namespace, pod = pod_name,
        port,
        "Starting portforward session"
    );

    let (cancel_token, mut stdin_rx, _resize_rx) = registry.register(request_id.clone());
    let pods: Api<Pod> = Api::namespaced(client, namespace);

    // Start portforwarder
    let mut pf = match pods.portforward(pod_name, &[port]).await {
        Ok(pf) => pf,
        Err(e) => {
            send_error(
                &message_tx,
                &cluster_name,
                &request_id,
                &format!("portforward failed: {}", e),
            )
            .await;
            registry.unregister(&request_id);
            return;
        }
    };

    // Get the stream for the port
    let stream = match pf.take_stream(port) {
        Some(s) => s,
        None => {
            send_error(
                &message_tx,
                &cluster_name,
                &request_id,
                &format!("failed to get stream for port {}", port),
            )
            .await;
            registry.unregister(&request_id);
            return;
        }
    };

    info!(
        request_id = %request_id,
        namespace, pod = pod_name,
        port,
        "Portforward session established"
    );

    let (reader, mut writer) = tokio::io::split(stream);

    // Spawn reader task - forwards data from pod to client (via stdout channel)
    let reader_tx = message_tx.clone();
    let reader_rid = request_id.clone();
    let reader_cn = cluster_name.clone();
    let reader_ct = cancel_token.clone();

    let reader_handle = tokio::spawn(async move {
        spawn_reader_task(
            reader,
            stream_id::STDOUT,
            reader_rid,
            reader_cn,
            reader_tx,
            reader_ct,
        )
        .await;
    });

    // Handle stdin (data from client) and write to pod
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                debug!(request_id = %request_id, "Portforward session cancelled");
                break;
            }

            data = stdin_rx.recv() => {
                match data {
                    Some(data) if !data.is_empty() => {
                        if writer.write_all(&data).await.is_err() {
                            break;
                        }
                        let _ = writer.flush().await;
                    }
                    None => {
                        debug!(request_id = %request_id, "Stdin channel closed");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    // Cleanup
    cancel_token.cancel();
    let _ = reader_handle.await;

    registry.unregister(&request_id);
    info!(request_id = %request_id, "Portforward session ended");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_attach_params() {
        let exec_params = parse_exec_params("stdin=true&stdout=true&stderr=true&tty=true");
        let attach_params = to_attach_params(exec_params);
        assert!(attach_params.stdin);
        assert!(attach_params.stdout);
        assert!(attach_params.stderr);
        assert!(attach_params.tty);

        let exec_params = parse_exec_params("stdin=1&stdout=1&container=main");
        let attach_params = to_attach_params(exec_params);
        assert!(attach_params.stdin);
        assert!(attach_params.stdout);
        assert_eq!(attach_params.container, Some("main".to_string()));
    }

    #[test]
    fn test_exec_registry() {
        let registry = ExecRegistry::new();

        let (token, _, _) = registry.register("exec-1".to_string());
        assert!(!token.is_cancelled());

        registry.cancel("exec-1");
        assert!(token.is_cancelled());
    }

    #[test]
    fn test_exec_registry_cancel_all() {
        let registry = ExecRegistry::new();

        let (t1, _, _) = registry.register("e1".to_string());
        let (t2, _, _) = registry.register("e2".to_string());

        registry.cancel_all();

        assert!(t1.is_cancelled());
        assert!(t2.is_cancelled());
    }

    #[test]
    fn test_exec_registry_cancel_nonexistent() {
        let registry = ExecRegistry::new();
        assert!(!registry.cancel("nonexistent"));
    }
}
