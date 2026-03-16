//! Command handlers for the agent client.
//!
//! This module provides extracted command handlers from the main client,
//! enabling unit testing of individual command types.

pub mod apply_manifests;
mod exec;
mod kubernetes;
mod move_batch;
pub(crate) mod move_complete;
pub mod peer_routes;
mod state_sync;
mod status_request;
mod sync_resources;

use std::sync::Arc;

use dashmap::DashMap;
use moka::future::Cache;
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::exec::ExecRegistry;
use crate::kube_client::KubeClientProvider;
use crate::watch::WatchRegistry;
use crate::{SharedExecForwarder, SharedK8sForwarder};
use lattice_proto::{cell_command::Command, AgentMessage, AgentState, CellCommand};

/// Stored exec session for stdin/resize/cancel forwarding.
///
/// Unlike ForwardedExecSession, this doesn't include data_rx since the
/// receiver is consumed immediately when the session starts.
#[derive(Clone)]
pub struct StoredExecSession {
    pub stdin_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    pub resize_tx: tokio::sync::mpsc::Sender<(u16, u16)>,
    pub cancel_token: CancellationToken,
}

/// Context for command execution.
///
/// Bundles all dependencies needed by command handlers, reducing the
/// 10-argument function signature to a single context parameter.
pub struct CommandContext {
    /// Name of this cluster (used in response messages)
    pub cluster_name: String,
    /// Sender for outgoing agent messages
    pub message_tx: mpsc::Sender<AgentMessage>,
    /// Current agent state
    pub agent_state: Arc<RwLock<AgentState>>,
    /// Registry for tracking active K8s API watches
    pub watch_registry: Arc<WatchRegistry>,
    /// Registry for tracking active exec sessions
    pub exec_registry: Arc<ExecRegistry>,
    /// Optional forwarder for routing K8s requests to child clusters
    pub forwarder: Option<SharedK8sForwarder>,
    /// Optional forwarder for routing exec requests to child clusters
    pub exec_forwarder: Option<SharedExecForwarder>,
    /// Registry for tracking forwarded exec sessions (to child clusters).
    /// TTL evicts leaked entries when a child disconnects without cleanup.
    pub forwarded_exec_sessions: Arc<Cache<String, StoredExecSession>>,
    /// Provider for creating Kubernetes clients
    pub kube_provider: Arc<dyn KubeClientProvider>,
    /// Pending service lookup responses keyed by request_id
    pub pending_lookups:
        DashMap<String, tokio::sync::oneshot::Sender<lattice_proto::ServiceLookupResponse>>,
}

impl CommandContext {
    /// Create a new command context with all dependencies.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cluster_name: String,
        message_tx: mpsc::Sender<AgentMessage>,
        agent_state: Arc<RwLock<AgentState>>,
        watch_registry: Arc<WatchRegistry>,
        exec_registry: Arc<ExecRegistry>,
        forwarder: Option<SharedK8sForwarder>,
        exec_forwarder: Option<SharedExecForwarder>,
        forwarded_exec_sessions: Arc<Cache<String, StoredExecSession>>,
        kube_provider: Arc<dyn KubeClientProvider>,
    ) -> Self {
        Self {
            cluster_name,
            message_tx,
            agent_state,
            watch_registry,
            exec_registry,
            forwarder,
            exec_forwarder,
            forwarded_exec_sessions,
            kube_provider,
            pending_lookups: DashMap::new(),
        }
    }
}

impl CommandContext {
    /// Send a service lookup request to the parent and wait for the response.
    ///
    /// Returns `None` if the parent doesn't know about the service or the
    /// request times out.
    pub async fn lookup_service(
        &self,
        namespace: &str,
        name: &str,
    ) -> Option<lattice_proto::ServiceLookupResponse> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();

        self.pending_lookups.insert(request_id.clone(), tx);

        let msg = AgentMessage {
            cluster_name: self.cluster_name.clone(),
            payload: Some(lattice_proto::agent_message::Payload::ServiceLookupRequest(
                lattice_proto::ServiceLookupRequest {
                    request_id: request_id.clone(),
                    service_name: name.to_string(),
                    service_namespace: namespace.to_string(),
                },
            )),
        };

        if self.message_tx.send(msg).await.is_err() {
            self.pending_lookups.remove(&request_id);
            return None;
        }

        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(resp)) if resp.found => Some(resp),
            _ => {
                self.pending_lookups.remove(&request_id);
                None
            }
        }
    }
}

/// Handle an incoming command from the cell.
///
/// Dispatches the command to the appropriate handler based on its type.
pub async fn handle_command(command: &CellCommand, ctx: &CommandContext) {
    debug!(command_id = %command.command_id, "Received command");

    match &command.command {
        Some(Command::ApplyManifests(cmd)) => {
            apply_manifests::handle(cmd, ctx).await;
        }
        Some(Command::StatusRequest(_)) => {
            status_request::handle(&command.command_id, ctx).await;
        }
        Some(Command::SyncResources(cmd)) => {
            sync_resources::handle(cmd, ctx).await;
        }
        Some(Command::KubernetesRequest(req)) => {
            kubernetes::handle(req, ctx).await;
        }
        Some(Command::MoveBatch(batch)) => {
            move_batch::handle(&command.command_id, batch, ctx).await;
        }
        Some(Command::MoveComplete(complete)) => {
            move_complete::handle(&command.command_id, complete, ctx).await;
        }
        Some(Command::ExecRequest(req)) => {
            exec::handle_exec_request(req, ctx).await;
        }
        Some(Command::ExecStdin(data)) => {
            exec::handle_exec_stdin(data, ctx).await;
        }
        Some(Command::ExecResize(resize)) => {
            exec::handle_exec_resize(resize, ctx).await;
        }
        Some(Command::ExecCancel(cancel)) => {
            exec::handle_exec_cancel(cancel, ctx).await;
        }
        Some(Command::StateSyncRequest(_)) => {
            state_sync::handle(&command.command_id, ctx).await;
        }
        Some(Command::PeerRouteSync(sync)) => {
            peer_routes::handle(sync, ctx).await;
        }
        Some(Command::ServiceLookupResponse(resp)) => {
            tracing::debug!(
                request_id = %resp.request_id,
                found = resp.found,
                "Received service lookup response"
            );
            if let Some((_, sender)) = ctx.pending_lookups.remove(&resp.request_id) {
                let _ = sender.send(resp.clone());
            }
        }
        None => {
            warn!(command_id = %command.command_id, "Received command with no payload");
        }
    }
}
