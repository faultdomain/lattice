//! Exec command handlers (ExecRequest, ExecStdin, ExecResize, ExecCancel).

use lattice_proto::{
    agent_message::Payload, AgentMessage, ExecCancel, ExecData, ExecRequest, ExecResize,
};
use tracing::{debug, error};

use crate::exec::stream_id;

use super::{CommandContext, StoredExecSession};

/// Handle an exec request from the cell.
pub async fn handle_exec_request(req: &ExecRequest, ctx: &CommandContext) {
    let target = &req.target_cluster;
    let is_local = target == &ctx.cluster_name;

    debug!(
        request_id = %req.request_id,
        path = %req.path,
        target_cluster = %target,
        is_local,
        "Received exec request"
    );

    if is_local {
        handle_local_exec(req, ctx).await;
    } else {
        handle_forwarded_exec(req, ctx).await;
    }
}

/// Handle a local exec request.
async fn handle_local_exec(req: &ExecRequest, ctx: &CommandContext) {
    let client = match ctx.kube_provider.create().await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Failed to create K8s client for exec");
            send_exec_error(
                &ctx.message_tx,
                &ctx.cluster_name,
                &req.request_id,
                &format!("Failed to create K8s client: {}", e),
            )
            .await;
            return;
        }
    };

    let cluster_name = ctx.cluster_name.clone();
    let message_tx = ctx.message_tx.clone();
    let req = req.clone();
    let registry = ctx.exec_registry.clone();

    tokio::spawn(async move {
        crate::exec::execute_exec(client, req, cluster_name, message_tx, registry).await;
    });
}

/// Handle a forwarded exec request to a child cluster.
async fn handle_forwarded_exec(req: &ExecRequest, ctx: &CommandContext) {
    let target = req.target_cluster.clone();
    let request_id = req.request_id.clone();

    match &ctx.exec_forwarder {
        Some(f) => {
            debug!(
                request_id = %request_id,
                target = %target,
                "Forwarding exec request to child cluster"
            );

            let f = f.clone();
            let req = req.clone();
            let cluster_name = ctx.cluster_name.clone();
            let message_tx = ctx.message_tx.clone();
            let sessions = ctx.forwarded_exec_sessions.clone();

            tokio::spawn(async move {
                match f.forward_exec(&target, req).await {
                    Ok(session) => {
                        let mut data_rx = session.data_rx;
                        let request_id = session.request_id.clone();
                        let cancel_token = session.cancel_token.clone();

                        // Store the session for stdin/resize forwarding
                        sessions.insert(
                            request_id.clone(),
                            StoredExecSession {
                                stdin_tx: session.stdin_tx,
                                resize_tx: session.resize_tx,
                                cancel_token,
                            },
                        );

                        // Relay data from child back to parent
                        while let Some(mut data) = data_rx.recv().await {
                            // Rewrite request_id to match the original command_id.
                            // When forwarding through child clusters, the inner tunnel
                            // generates a new request_id. The parent cell is waiting
                            // for the original one.
                            data.request_id = request_id.clone();
                            let msg = AgentMessage {
                                cluster_name: cluster_name.clone(),
                                payload: Some(Payload::ExecData(data)),
                            };
                            if message_tx.send(msg).await.is_err() {
                                break;
                            }
                        }

                        // Clean up session
                        sessions.remove(&request_id);
                    }
                    Err(e) => {
                        error!(
                            request_id = %request_id,
                            target = %target,
                            error = %e,
                            "Failed to forward exec request"
                        );
                        send_exec_error(
                            &message_tx,
                            &cluster_name,
                            &request_id,
                            &format!("exec forwarding failed: {}", e),
                        )
                        .await;
                    }
                }
            });
        }
        None => {
            debug!(
                request_id = %request_id,
                target = %target,
                "No exec forwarder configured, returning error"
            );
            send_exec_error(
                &ctx.message_tx,
                &ctx.cluster_name,
                &request_id,
                &format!("cluster '{}' not found in subtree", target),
            )
            .await;
        }
    }
}

/// Handle stdin data for an exec session.
pub async fn handle_exec_stdin(data: &ExecData, ctx: &CommandContext) {
    let request_id = data.request_id.clone();
    let data_bytes = data.data.clone();

    let exec_registry = ctx.exec_registry.clone();
    let forwarded = ctx.forwarded_exec_sessions.clone();

    tokio::spawn(async move {
        // Check if it's a local exec session
        if exec_registry
            .send_stdin(&request_id, data_bytes.clone())
            .await
        {
            return;
        }
        // Otherwise, try forwarded sessions
        if let Some(session) = forwarded.get(&request_id) {
            let _ = session.stdin_tx.send(data_bytes).await;
        }
    });
}

/// Handle resize event for an exec session.
pub async fn handle_exec_resize(resize: &ExecResize, ctx: &CommandContext) {
    let request_id = resize.request_id.clone();
    let width = resize.width as u16;
    let height = resize.height as u16;

    let exec_registry = ctx.exec_registry.clone();
    let forwarded = ctx.forwarded_exec_sessions.clone();

    tokio::spawn(async move {
        // Check if it's a local exec session
        if exec_registry.send_resize(&request_id, width, height).await {
            return;
        }
        // Otherwise, try forwarded sessions
        if let Some(session) = forwarded.get(&request_id) {
            let _ = session.resize_tx.send((width, height)).await;
        }
    });
}

/// Handle cancellation of an exec session.
pub fn handle_exec_cancel(cancel: &ExecCancel, ctx: &CommandContext) {
    let request_id = &cancel.request_id;
    debug!(request_id = %request_id, "Received exec cancel");

    // Try local exec registry first
    if ctx.exec_registry.cancel(request_id) {
        return;
    }

    // Otherwise, try forwarded sessions
    if let Some((_, session)) = ctx.forwarded_exec_sessions.remove(request_id) {
        session.cancel_token.cancel();
    }
}

/// Send an exec error response.
async fn send_exec_error(
    tx: &tokio::sync::mpsc::Sender<AgentMessage>,
    cluster_name: &str,
    request_id: &str,
    error: &str,
) {
    let response = lattice_proto::ExecData {
        request_id: request_id.to_string(),
        stream_id: stream_id::ERROR,
        data: error.as_bytes().to_vec(),
        stream_end: true,
    };
    let msg = AgentMessage {
        cluster_name: cluster_name.to_string(),
        payload: Some(Payload::ExecData(response)),
    };
    let _ = tx.send(msg).await;
}
