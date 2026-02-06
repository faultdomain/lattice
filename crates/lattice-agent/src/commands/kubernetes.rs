//! Kubernetes API request command handler.

use lattice_proto::{agent_message::Payload, AgentMessage, KubernetesRequest, KubernetesResponse};
use tracing::{debug, error};

use crate::watch::execute_watch;
use crate::{
    build_cluster_not_found_response, build_k8s_status_response, execute_k8s_request,
    is_watch_request,
};

use super::CommandContext;

/// Handle a Kubernetes API request from the cell.
pub async fn handle(req: &KubernetesRequest, ctx: &CommandContext) {
    let target = &req.target_cluster;
    let is_local = target == &ctx.cluster_name;

    debug!(
        request_id = %req.request_id,
        verb = %req.verb,
        path = %req.path,
        target_cluster = %target,
        is_local = is_local,
        "Received K8s API proxy request"
    );

    // Handle cancellation requests
    if req.cancel {
        handle_cancel(req, ctx).await;
        return;
    }

    let request_id = req.request_id.clone();
    let cluster_name = ctx.cluster_name.clone();
    let message_tx = ctx.message_tx.clone();
    let req = req.clone();
    let registry = ctx.watch_registry.clone();
    let forwarder = ctx.forwarder.clone();
    let provider = ctx.kube_provider.clone();

    tokio::spawn(async move {
        let response = if is_local {
            execute_local_request(&req, &cluster_name, &message_tx, registry, provider).await
        } else {
            execute_forwarded_request(&req, &cluster_name, &message_tx, forwarder).await
        };

        // Non-watch requests return a response to send
        if let Some(mut response) = response {
            // Rewrite the request_id to match the original command_id.
            // When forwarding through child clusters, the inner tunnel generates
            // a new request_id. The parent cell is waiting for the original one.
            response.request_id = request_id.clone();
            let msg = AgentMessage {
                cluster_name,
                payload: Some(Payload::KubernetesResponse(response)),
            };
            if let Err(e) = message_tx.send(msg).await {
                error!(request_id = %request_id, error = %e, "Failed to send K8s response");
            }
        }
    });
}

/// Handle a watch cancellation request.
async fn handle_cancel(req: &KubernetesRequest, ctx: &CommandContext) {
    ctx.watch_registry.cancel(&req.request_id);

    let response = KubernetesResponse {
        request_id: req.request_id.clone(),
        status_code: 200,
        streaming: true,
        stream_end: true,
        ..Default::default()
    };

    let msg = AgentMessage {
        cluster_name: ctx.cluster_name.clone(),
        payload: Some(Payload::KubernetesResponse(response)),
    };

    if let Err(e) = ctx.message_tx.send(msg).await {
        error!(error = %e, "Failed to send watch cancel response");
    }
}

/// Execute a request locally on this cluster.
///
/// Returns None for watch requests (they handle their own responses),
/// or Some(response) for regular requests.
async fn execute_local_request(
    req: &KubernetesRequest,
    cluster_name: &str,
    message_tx: &tokio::sync::mpsc::Sender<AgentMessage>,
    registry: std::sync::Arc<crate::watch::WatchRegistry>,
    provider: std::sync::Arc<dyn crate::kube_client::KubeClientProvider>,
) -> Option<KubernetesResponse> {
    let client = match provider.create().await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Failed to create K8s client for proxy request");
            return Some(crate::build_grpc_error_response(
                &req.request_id,
                500,
                &format!("Failed to create K8s client: {}", e),
            ));
        }
    };

    // Route watch requests to execute_watch, others to execute_k8s_request
    if is_watch_request(req) {
        execute_watch(
            client,
            req.clone(),
            cluster_name.to_string(),
            message_tx.clone(),
            registry,
        )
        .await;
        None // Watch handles its own response sending
    } else {
        Some(execute_k8s_request(&client, req).await)
    }
}

/// Execute a forwarded request to a child cluster.
///
/// Returns None for watch requests (they handle their own responses),
/// or Some(response) for regular requests.
async fn execute_forwarded_request(
    req: &KubernetesRequest,
    cluster_name: &str,
    message_tx: &tokio::sync::mpsc::Sender<AgentMessage>,
    forwarder: Option<crate::SharedK8sForwarder>,
) -> Option<KubernetesResponse> {
    let target = &req.target_cluster;
    let request_id = &req.request_id;

    let Some(f) = forwarder else {
        debug!(
            request_id = %request_id,
            target = %target,
            "No forwarder configured, returning 404"
        );
        return Some(build_cluster_not_found_response(target, request_id));
    };

    // Use streaming forwarder for watch requests
    if is_watch_request(req) {
        debug!(
            request_id = %request_id,
            target = %target,
            "Forwarding watch request to child cluster"
        );

        match f.forward_watch(target, req.clone()).await {
            Ok(mut rx) => {
                while let Some(mut response) = rx.recv().await {
                    // Rewrite request_id to match the original command_id
                    response.request_id = request_id.to_string();
                    let is_end = response.stream_end;
                    let msg = AgentMessage {
                        cluster_name: cluster_name.to_string(),
                        payload: Some(Payload::KubernetesResponse(response)),
                    };
                    if message_tx.send(msg).await.is_err() {
                        break;
                    }
                    if is_end {
                        break;
                    }
                }
            }
            Err(e) => {
                error!(request_id = %request_id, error = %e, "Failed to forward watch");
                let response = build_k8s_status_response(request_id, 502, &e);
                let msg = AgentMessage {
                    cluster_name: cluster_name.to_string(),
                    payload: Some(Payload::KubernetesResponse(response)),
                };
                let _ = message_tx.send(msg).await;
            }
        }
        return None;
    }

    debug!(
        request_id = %request_id,
        target = %target,
        "Forwarding request to child cluster"
    );

    Some(f.forward(target, req.clone()).await)
}
