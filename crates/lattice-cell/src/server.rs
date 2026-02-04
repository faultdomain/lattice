//! gRPC server for cell (management cluster)
//!
//! Accepts incoming connections from agents running on workload clusters.
//!
//! # mTLS Security
//!
//! The server requires client certificates signed by the cell CA.
//! Each agent presents its certificate, and the cluster ID is extracted
//! from the certificate's CN field.

use std::net::SocketAddr;
use std::pin::Pin;

use futures::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, error, info, instrument, warn};

use kube::api::{DeleteParams, Patch, PatchParams};
use kube::{Api, Client};
use lattice_common::crd::LatticeCluster;

use lattice_proto::lattice_agent_server::{LatticeAgent, LatticeAgentServer};
use lattice_proto::{agent_message::Payload, AgentMessage, AgentState, CellCommand};

use crate::kubeconfig::patch_kubeconfig_for_proxy;
use crate::subtree_registry::{ClusterInfo, SubtreeRegistry};
use crate::{AgentConnection, SharedAgentRegistry};
use lattice_infra::ServerMtlsConfig;
use lattice_proto::SubtreeState;

/// Shared reference to SubtreeRegistry
pub type SharedSubtreeRegistry = std::sync::Arc<SubtreeRegistry>;

/// Convert SubtreeState clusters to ClusterInfo, filtering out removed clusters
fn convert_subtree_to_cluster_infos(state: &SubtreeState) -> Vec<ClusterInfo> {
    state
        .clusters
        .iter()
        .filter(|c| !c.removed)
        .map(|c| ClusterInfo {
            name: c.name.clone(),
            parent: c.parent.clone(),
            phase: c.phase.clone(),
            labels: c.labels.clone(),
        })
        .collect()
}

/// Extract delta changes from SubtreeState (added and removed cluster names)
fn extract_delta_changes(state: &SubtreeState) -> (Vec<ClusterInfo>, Vec<String>) {
    let added = convert_subtree_to_cluster_infos(state);
    let removed = state
        .clusters
        .iter()
        .filter(|c| c.removed)
        .map(|c| c.name.clone())
        .collect();
    (added, removed)
}

/// gRPC server for agent communication
pub struct AgentServer {
    registry: SharedAgentRegistry,
    /// Subtree registry for tracking cluster hierarchy
    subtree_registry: SharedSubtreeRegistry,
    /// Kubernetes client for persisting deletion requests
    kube_client: Client,
}

/// Process an agent message (standalone function to avoid temporary object creation)
async fn process_agent_message(
    registry: SharedAgentRegistry,
    subtree_registry: SharedSubtreeRegistry,
    msg: &AgentMessage,
    command_tx: &mpsc::Sender<CellCommand>,
    kube_client: &Client,
) {
    let cluster_name = &msg.cluster_name;

    match &msg.payload {
        Some(Payload::Ready(ready)) => {
            info!(
                cluster = %cluster_name,
                agent_version = %ready.agent_version,
                k8s_version = %ready.kubernetes_version,
                state = ?ready.state(),
                "Agent connected"
            );

            let conn = AgentConnection::new(
                cluster_name.clone(),
                ready.agent_version.clone(),
                ready.kubernetes_version.clone(),
                command_tx.clone(),
            );
            registry.register(conn);
            registry.update_state(cluster_name, ready.state());

            // If agent reports Ready state, pivot must have completed
            if ready.state() == AgentState::Ready {
                registry.set_pivot_complete(cluster_name, true);
            }

            // NOTE: No ACK recovery needed for unpivot. Once the parent has imported
            // and unpaused CAPI resources, it owns the child's infrastructure and will
            // delete it via CAPI. The child cluster goes away at the infrastructure level,
            // so the child's finalizer becomes irrelevant.
        }
        Some(Payload::BootstrapComplete(bc)) => {
            info!(
                cluster = %cluster_name,
                capi_ready = bc.capi_ready,
                installed_providers = ?bc.installed_providers,
                "Bootstrap complete"
            );
            // Store CAPI ready status - pivot requires this to be true
            registry.set_capi_ready(cluster_name, bc.capi_ready);
        }
        Some(Payload::Heartbeat(hb)) => {
            debug!(
                cluster = %cluster_name,
                state = ?hb.state(),
                uptime = hb.uptime_seconds,
                "Heartbeat received"
            );
            registry.update_state(cluster_name, hb.state());
        }
        Some(Payload::ClusterHealth(health)) => {
            debug!(
                cluster = %cluster_name,
                ready_nodes = health.ready_nodes,
                total_nodes = health.total_nodes,
                "Health update"
            );
        }
        Some(Payload::StatusResponse(sr)) => {
            debug!(
                cluster = %cluster_name,
                request_id = %sr.request_id,
                "Status response received"
            );
        }
        Some(Payload::ClusterDeleting(cd)) => {
            // Guard against concurrent teardown spawns (in-memory, resets on restart)
            if !registry.start_teardown(cluster_name) {
                debug!(
                    cluster = %cluster_name,
                    "Teardown already in progress, ignoring duplicate ClusterDeleting"
                );
                return;
            }

            info!(
                cluster = %cluster_name,
                namespace = %cd.namespace,
                object_count = cd.objects.len(),
                "Cluster deletion requested"
            );

            // Convert proto objects to MoveObjectInput
            let objects: Vec<lattice_move::MoveObjectInput> = cd
                .objects
                .iter()
                .map(|obj| lattice_move::MoveObjectInput {
                    source_uid: obj.source_uid.clone(),
                    manifest: obj.manifest.clone(),
                    owners: obj
                        .owners
                        .iter()
                        .map(|o| lattice_move::SourceOwnerRefInput {
                            source_uid: o.source_uid.clone(),
                            api_version: o.api_version.clone(),
                            kind: o.kind.clone(),
                            name: o.name.clone(),
                            controller: o.controller,
                            block_owner_deletion: o.block_owner_deletion,
                        })
                        .collect(),
                })
                .collect();

            let namespace = cd.namespace.clone();
            let cluster = cluster_name.to_string();
            let client = kube_client.clone();
            let registry_for_task = registry.clone();

            // Spawn to avoid blocking the gRPC stream
            tokio::spawn(async move {
                let api: Api<LatticeCluster> = Api::all(client.clone());

                // Step 0: Check if import already complete (crash recovery)
                // This is the persistent marker that survives restarts
                let import_already_complete = match api.get(&cluster).await {
                    Ok(lc) => lc
                        .status
                        .as_ref()
                        .map(|s| s.unpivot_import_complete)
                        .unwrap_or(false),
                    Err(kube::Error::Api(ae)) if ae.code == 404 => {
                        // Cluster already deleted, nothing to do
                        info!(cluster = %cluster, "LatticeCluster already deleted");
                        registry_for_task.finish_teardown(&cluster);
                        return;
                    }
                    Err(e) => {
                        error!(cluster = %cluster, error = %e, "Failed to get LatticeCluster");
                        registry_for_task.finish_teardown(&cluster);
                        return;
                    }
                };

                if import_already_complete {
                    info!(
                        cluster = %cluster,
                        "CAPI import already complete, skipping re-import (crash recovery)"
                    );
                } else if objects.is_empty() {
                    // No objects received - discovery likely failed on child, don't proceed
                    error!(
                        cluster = %cluster,
                        "No CAPI objects received from child - discovery may have failed"
                    );
                    registry_for_task.finish_teardown(&cluster);
                    return;
                } else {
                    // Log each object received for debugging
                    for obj in &objects {
                        if let Ok(parsed) =
                            serde_json::from_slice::<serde_json::Value>(&obj.manifest)
                        {
                            let kind = parsed.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
                            let name = parsed
                                .get("metadata")
                                .and_then(|m| m.get("name"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("?");
                            info!(
                                cluster = %cluster,
                                kind = %kind,
                                name = %name,
                                source_uid = %obj.source_uid,
                                owners = obj.owners.len(),
                                "Unpivot: received object"
                            );
                        }
                    }

                    info!(
                        cluster = %cluster,
                        object_count = objects.len(),
                        "Importing CAPI objects from child"
                    );

                    let mut mover = lattice_move::AgentMover::new(client.clone(), &namespace);

                    // Ensure namespace exists
                    if let Err(e) = mover.ensure_namespace().await {
                        error!(cluster = %cluster, error = %e, "Failed to ensure namespace");
                        registry_for_task.finish_teardown(&cluster);
                        return;
                    }

                    // Apply all objects (AgentMover handles UID remapping)
                    let (mappings, errors) = mover.apply_batch(&objects).await;

                    if !errors.is_empty() {
                        for e in &errors {
                            error!(
                                cluster = %cluster,
                                source_uid = %e.source_uid,
                                error = %e.message,
                                "Failed to import object"
                            );
                        }
                        // Don't proceed with deletion if import failed - agent will retry
                        error!(
                            cluster = %cluster,
                            failed = errors.len(),
                            "Import failed, aborting teardown - agent will retry"
                        );
                        registry_for_task.finish_teardown(&cluster);
                        return;
                    }

                    info!(
                        cluster = %cluster,
                        created = mappings.len(),
                        "CAPI objects imported successfully"
                    );

                    // Patch kubeconfig to route through proxy
                    // This must happen BEFORE unpausing, otherwise CAPI can't reach the cluster
                    let Some(proxy_config) = registry_for_task.get_proxy_config() else {
                        error!(cluster = %cluster, "No proxy config available, cannot patch kubeconfig");
                        registry_for_task.finish_teardown(&cluster);
                        return;
                    };

                    match patch_kubeconfig_for_proxy(
                        &client,
                        &cluster,
                        &namespace,
                        &proxy_config.url,
                        &proxy_config.ca_cert_pem,
                    )
                    .await
                    {
                        Ok(true) => {
                            info!(cluster = %cluster, "Kubeconfig patched for proxy access");
                        }
                        Ok(false) => {
                            error!(cluster = %cluster, "Kubeconfig Secret not found after import");
                            registry_for_task.finish_teardown(&cluster);
                            return;
                        }
                        Err(e) => {
                            error!(cluster = %cluster, error = %e, "Failed to patch kubeconfig for proxy");
                            registry_for_task.finish_teardown(&cluster);
                            return;
                        }
                    }

                    // Unpause cluster - CAPI won't delete paused clusters
                    // This MUST succeed, otherwise infrastructure will be orphaned
                    if let Err(e) = mover.unpause_resources().await {
                        error!(cluster = %cluster, error = %e, "Failed to unpause cluster - infrastructure may be orphaned");
                        registry_for_task.finish_teardown(&cluster);
                        return;
                    }
                    info!(cluster = %cluster, "Cluster unpaused successfully");

                    // Step 1: Mark import complete BEFORE deletion (crash-safe)
                    // This prevents re-import on crash recovery which could cause UID conflicts
                    let status_patch = serde_json::json!({
                        "status": {
                            "unpivotImportComplete": true
                        }
                    });
                    if let Err(e) = api
                        .patch_status(
                            &cluster,
                            &PatchParams::apply("lattice-cell"),
                            &Patch::Merge(&status_patch),
                        )
                        .await
                    {
                        error!(cluster = %cluster, error = %e, "Failed to mark import complete");
                        registry_for_task.finish_teardown(&cluster);
                        return;
                    }
                    info!(cluster = %cluster, "Marked unpivot import complete");
                }

                // Step 2: Delete LatticeCluster (adds deletionTimestamp)
                // Controller will delete CAPI Cluster which triggers infrastructure cleanup.
                // The finalizer keeps it around while controller handles CAPI cleanup.
                info!(cluster = %cluster, "Initiating LatticeCluster deletion");
                if let Err(e) = api.delete(&cluster, &DeleteParams::default()).await {
                    if !matches!(&e, kube::Error::Api(ae) if ae.code == 404) {
                        error!(cluster = %cluster, error = %e, "Failed to delete LatticeCluster");
                    }
                }

                // NOTE: We intentionally do NOT call finish_teardown() here.
                // The teardown guard stays in place to prevent duplicate ClusterDeleting
                // messages from re-importing CAPI objects. The guard is cleared when
                // the agent disconnects (unregister).
                info!(cluster = %cluster, "Teardown initiated - controller will handle cleanup");
            });
        }
        Some(Payload::KubernetesResponse(resp)) => {
            debug!(
                cluster = %cluster_name,
                request_id = %resp.request_id,
                status_code = resp.status_code,
                streaming = resp.streaming,
                stream_end = resp.stream_end,
                body_len = resp.body.len(),
                "K8s API response received"
            );

            // Deliver response to waiting proxy handler
            if resp.stream_end {
                // Final message in stream - take the sender to remove it
                if let Some(sender) = registry.take_pending_k8s_response(&resp.request_id) {
                    if let Err(e) = sender.try_send(resp.clone()) {
                        warn!(
                            cluster = %cluster_name,
                            request_id = %resp.request_id,
                            error = %e,
                            "Failed to deliver final K8s API response"
                        );
                    }
                } else {
                    debug!(
                        cluster = %cluster_name,
                        request_id = %resp.request_id,
                        "Received K8s API response for unknown request (may have timed out)"
                    );
                }
            } else {
                // Streaming response - get sender but keep it registered
                if let Some(sender) = registry.get_pending_k8s_response(&resp.request_id) {
                    if let Err(e) = sender.try_send(resp.clone()) {
                        warn!(
                            cluster = %cluster_name,
                            request_id = %resp.request_id,
                            error = %e,
                            "Failed to deliver streaming K8s API response"
                        );
                        // Channel is full or closed, clean up
                        registry.take_pending_k8s_response(&resp.request_id);
                    }
                } else {
                    debug!(
                        cluster = %cluster_name,
                        request_id = %resp.request_id,
                        "Received K8s API response for unknown request"
                    );
                }
            }
        }
        Some(Payload::MoveAck(ack)) => {
            if let Some(sender) = registry.take_pending_batch_ack(&ack.request_id) {
                let batch_ack = lattice_move::BatchAck {
                    mappings: ack
                        .mappings
                        .iter()
                        .map(|m| (m.source_uid.clone(), m.target_uid.clone()))
                        .collect(),
                    errors: ack
                        .errors
                        .iter()
                        .map(|e| (e.source_uid.clone(), e.message.clone(), e.retryable))
                        .collect(),
                };
                let _ = sender.send(batch_ack);
                debug!(
                    cluster = %cluster_name,
                    request_id = %ack.request_id,
                    mappings = ack.mappings.len(),
                    "Delivered batch ack"
                );
            } else {
                warn!(
                    cluster = %cluster_name,
                    request_id = %ack.request_id,
                    "Received ack for unknown request"
                );
            }
        }
        Some(Payload::MoveCompleteAck(ack)) => {
            if let Some(sender) = registry.take_pending_complete_ack(&ack.request_id) {
                let complete_ack = lattice_move::CompleteAck {
                    success: ack.success,
                    error: ack.error.clone(),
                    resources_created: ack.resources_created,
                };
                let _ = sender.send(complete_ack);
                if ack.success {
                    info!(
                        cluster = %cluster_name,
                        request_id = %ack.request_id,
                        resources_created = ack.resources_created,
                        "Move completed"
                    );
                } else {
                    error!(
                        cluster = %cluster_name,
                        request_id = %ack.request_id,
                        error = %ack.error,
                        "Move failed"
                    );
                }
            } else {
                warn!(
                    cluster = %cluster_name,
                    request_id = %ack.request_id,
                    "Received ack for unknown request"
                );
            }
        }
        Some(Payload::SubtreeState(state)) => {
            debug!(
                cluster = %cluster_name,
                is_full_sync = state.is_full_sync,
                cluster_count = state.clusters.len(),
                service_count = state.services.len(),
                "Subtree state received"
            );

            if state.is_full_sync {
                // Full sync: replace all clusters from this agent
                let clusters = convert_subtree_to_cluster_infos(state);

                info!(
                    cluster = %cluster_name,
                    subtree_clusters = clusters.len(),
                    "Full sync: updating subtree registry"
                );
                subtree_registry
                    .handle_full_sync(cluster_name, clusters)
                    .await;
            } else {
                // Delta: add/remove specific clusters
                let (added, removed) = extract_delta_changes(state);

                if !added.is_empty() || !removed.is_empty() {
                    debug!(
                        cluster = %cluster_name,
                        added = added.len(),
                        removed = removed.len(),
                        "Delta: updating subtree registry"
                    );
                }
                subtree_registry
                    .handle_delta(cluster_name, added, removed)
                    .await;
            }
        }
        Some(Payload::ExecData(data)) => {
            debug!(
                cluster = %cluster_name,
                request_id = %data.request_id,
                stream_id = data.stream_id,
                data_len = data.data.len(),
                stream_end = data.stream_end,
                "Exec data received"
            );

            // Route exec data to pending exec session handler
            if let Some(sender) = registry.get_pending_exec_data(&data.request_id) {
                if let Err(e) = sender.try_send(data.clone()) {
                    warn!(
                        cluster = %cluster_name,
                        request_id = %data.request_id,
                        error = %e,
                        "Failed to deliver exec data"
                    );
                    if data.stream_end {
                        registry.take_pending_exec_data(&data.request_id);
                    }
                }
            } else {
                debug!(
                    cluster = %cluster_name,
                    request_id = %data.request_id,
                    "Received exec data for unknown session"
                );
            }

            // Clean up on stream end
            if data.stream_end {
                registry.take_pending_exec_data(&data.request_id);
            }
        }
        None => {
            warn!(cluster = %cluster_name, "Received message with no payload");
        }
    }
}

impl AgentServer {
    /// Create a new agent server with the given registries and kube client
    pub fn new(
        registry: SharedAgentRegistry,
        subtree_registry: SharedSubtreeRegistry,
        kube_client: Client,
    ) -> Self {
        Self {
            registry,
            subtree_registry,
            kube_client,
        }
    }

    /// Convert to a tonic service
    pub fn into_service(self) -> LatticeAgentServer<Self> {
        LatticeAgentServer::new(self)
    }

    /// Start the gRPC server with mTLS on the given address
    ///
    /// This is the primary entry point for running the cell gRPC server.
    /// It requires mTLS configuration with:
    /// - Server certificate (presented to agents)
    /// - Server private key
    /// - CA certificate (for verifying agent certificates)
    pub async fn serve_with_mtls(
        registry: SharedAgentRegistry,
        subtree_registry: SharedSubtreeRegistry,
        addr: SocketAddr,
        mtls_config: ServerMtlsConfig,
        kube_client: Client,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = Self::new(registry, subtree_registry, kube_client);
        let tls_config = mtls_config.to_tonic_config()?;

        info!(%addr, "Starting gRPC server with mTLS");

        Server::builder()
            .tls_config(tls_config)?
            .add_service(server.into_service())
            .serve(addr)
            .await?;

        Ok(())
    }
}

#[tonic::async_trait]
impl LatticeAgent for AgentServer {
    type StreamMessagesStream =
        Pin<Box<dyn Stream<Item = Result<CellCommand, Status>> + Send + 'static>>;

    #[instrument(skip(self, request))]
    async fn stream_messages(
        &self,
        request: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::StreamMessagesStream>, Status> {
        let remote_addr = request.remote_addr();
        info!(?remote_addr, "New agent connection");

        let mut inbound = request.into_inner();

        // Channel for sending commands to this agent
        let (command_tx, command_rx) = mpsc::channel::<CellCommand>(32);

        // Clone for the spawned task
        let registry = self.registry.clone();
        let subtree_registry = self.subtree_registry.clone();
        let kube_client = self.kube_client.clone();
        let command_tx_clone = command_tx.clone();

        // Spawn task to handle incoming messages
        tokio::spawn(async move {
            let mut cluster_name: Option<String> = None;

            while let Some(result) = inbound.next().await {
                match result {
                    Ok(msg) => {
                        // Track the cluster name for cleanup
                        if cluster_name.is_none() {
                            cluster_name = Some(msg.cluster_name.clone());
                        }

                        // Handle message directly using standalone function (no temp object)
                        process_agent_message(
                            registry.clone(),
                            subtree_registry.clone(),
                            &msg,
                            &command_tx_clone,
                            &kube_client,
                        )
                        .await;
                    }
                    Err(e) => {
                        error!(error = %e, "Error receiving agent message");
                        break;
                    }
                }
            }

            // Cleanup on disconnect
            if let Some(name) = cluster_name {
                info!(cluster = %name, "Agent disconnected");
                registry.unregister(&name);
                subtree_registry.handle_agent_disconnect(&name).await;
            }
        });

        // Return stream of commands to send to agent
        let outbound = ReceiverStream::new(command_rx);
        Ok(Response::new(Box::pin(outbound.map(Ok))))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::AgentRegistry;
    use lattice_proto::{
        agent_message::Payload, AgentReady, BootstrapComplete, ClusterHealth, Heartbeat,
        StatusResponse, SubtreeCluster, SubtreeState,
    };

    /// Test helper: handle message directly without needing a server
    /// This bypasses the kube client requirement for unit tests
    async fn test_handle_message(
        registry: &AgentRegistry,
        subtree_registry: &SubtreeRegistry,
        msg: &AgentMessage,
        command_tx: &mpsc::Sender<CellCommand>,
    ) {
        let cluster_name = &msg.cluster_name;

        // Simplified handler for tests - same logic but skips ClusterDeleting persistence
        match &msg.payload {
            Some(Payload::Ready(ready)) => {
                let conn = AgentConnection::new(
                    cluster_name.clone(),
                    ready.agent_version.clone(),
                    ready.kubernetes_version.clone(),
                    command_tx.clone(),
                );
                registry.register(conn);
                registry.update_state(cluster_name, ready.state());
                if ready.state() == AgentState::Ready {
                    registry.set_pivot_complete(cluster_name, true);
                }
            }
            Some(Payload::BootstrapComplete(bc)) => {
                registry.set_capi_ready(cluster_name, bc.capi_ready);
            }
            Some(Payload::Heartbeat(hb)) => {
                registry.update_state(cluster_name, hb.state());
            }
            Some(Payload::ClusterHealth(_)) => {}
            Some(Payload::StatusResponse(_)) => {}
            Some(Payload::ClusterDeleting(_)) => {}
            Some(Payload::KubernetesResponse(_)) => {}
            Some(Payload::MoveAck(_)) => {}
            Some(Payload::MoveCompleteAck(_)) => {}
            Some(Payload::SubtreeState(state)) => {
                if state.is_full_sync {
                    let clusters = convert_subtree_to_cluster_infos(state);
                    subtree_registry
                        .handle_full_sync(cluster_name, clusters)
                        .await;
                } else {
                    let (added, removed) = extract_delta_changes(state);
                    subtree_registry
                        .handle_delta(cluster_name, added, removed)
                        .await;
                }
            }
            Some(Payload::ExecData(_)) => {}
            None => {}
        }
    }

    /// Create a new registry for tests
    fn create_test_registry() -> SharedAgentRegistry {
        Arc::new(AgentRegistry::new())
    }

    /// Create a new subtree registry for tests
    fn create_test_subtree_registry() -> SubtreeRegistry {
        SubtreeRegistry::new("test-cell".to_string())
    }

    /// Test context containing all components needed for message handling tests
    struct TestContext {
        registry: SharedAgentRegistry,
        subtree_registry: SubtreeRegistry,
        tx: mpsc::Sender<CellCommand>,
        #[allow(dead_code)]
        rx: mpsc::Receiver<CellCommand>,
    }

    /// Setup common test context for message handling tests
    fn setup_test_context() -> TestContext {
        let registry = create_test_registry();
        let subtree_registry = create_test_subtree_registry();
        let (tx, rx) = mpsc::channel::<CellCommand>(32);
        TestContext {
            registry,
            subtree_registry,
            tx,
            rx,
        }
    }

    /// Factory function to create a Ready message for tests
    fn make_ready_msg(cluster: &str, state: AgentState) -> AgentMessage {
        AgentMessage {
            cluster_name: cluster.to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: state.into(),
                api_server_endpoint: format!("https://api.{}:6443", cluster),
            })),
        }
    }

    /// Factory function to create a Ready message with custom versions for tests
    fn make_ready_msg_with_versions(
        cluster: &str,
        state: AgentState,
        agent_version: &str,
        k8s_version: &str,
    ) -> AgentMessage {
        AgentMessage {
            cluster_name: cluster.to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: agent_version.to_string(),
                kubernetes_version: k8s_version.to_string(),
                state: state.into(),
                api_server_endpoint: format!("https://api.{}:6443", cluster),
            })),
        }
    }

    /// Factory function to create a Heartbeat message for tests
    fn make_heartbeat_msg(cluster: &str, state: AgentState) -> AgentMessage {
        AgentMessage {
            cluster_name: cluster.to_string(),
            payload: Some(Payload::Heartbeat(Heartbeat {
                state: state.into(),
                timestamp: None,
                uptime_seconds: 3600,
            })),
        }
    }

    /// Factory function to create a BootstrapComplete message for tests
    fn make_bootstrap_complete_msg(cluster: &str, capi_ready: bool) -> AgentMessage {
        AgentMessage {
            cluster_name: cluster.to_string(),
            payload: Some(Payload::BootstrapComplete(BootstrapComplete {
                capi_ready,
                installed_providers: vec!["docker".to_string()],
            })),
        }
    }

    /// Factory function to create a ClusterHealth message for tests
    fn make_cluster_health_msg(cluster: &str, ready_nodes: i32, total_nodes: i32) -> AgentMessage {
        AgentMessage {
            cluster_name: cluster.to_string(),
            payload: Some(Payload::ClusterHealth(ClusterHealth {
                ready_nodes,
                total_nodes,
                ready_control_plane: 1,
                total_control_plane: 1,
                conditions: vec![],
            })),
        }
    }

    /// Factory function to create a StatusResponse message for tests
    fn make_status_response_msg(
        cluster: &str,
        request_id: &str,
        state: AgentState,
    ) -> AgentMessage {
        AgentMessage {
            cluster_name: cluster.to_string(),
            payload: Some(Payload::StatusResponse(StatusResponse {
                request_id: request_id.to_string(),
                state: state.into(),
                health: None,
                capi_status: None,
            })),
        }
    }

    /// Factory function to create an empty (no payload) message for tests
    fn make_empty_msg(cluster: &str) -> AgentMessage {
        AgentMessage {
            cluster_name: cluster.to_string(),
            payload: None,
        }
    }

    #[tokio::test]
    async fn test_handle_ready_message() {
        let ctx = setup_test_context();

        let msg = make_ready_msg("test-cluster", AgentState::Provisioning);

        test_handle_message(&ctx.registry, &ctx.subtree_registry, &msg, &ctx.tx).await;

        assert!(!ctx.registry.is_empty());
        let conn = ctx
            .registry
            .get("test-cluster")
            .expect("agent should be registered");
        assert_eq!(conn.cluster_name, "test-cluster");
        assert_eq!(conn.agent_version, "0.1.0");
        assert_eq!(conn.kubernetes_version, "1.28.0");
        assert_eq!(conn.state, AgentState::Provisioning);
    }

    #[tokio::test]
    async fn test_handle_ready_message_updates_existing() {
        let ctx = setup_test_context();

        let msg1 = make_ready_msg("test-cluster", AgentState::Provisioning);
        test_handle_message(&ctx.registry, &ctx.subtree_registry, &msg1, &ctx.tx).await;

        let msg2 = make_ready_msg("test-cluster", AgentState::Ready);
        test_handle_message(&ctx.registry, &ctx.subtree_registry, &msg2, &ctx.tx).await;

        let conn = ctx
            .registry
            .get("test-cluster")
            .expect("agent should be registered");
        assert_eq!(conn.state, AgentState::Ready);
    }

    #[tokio::test]
    async fn test_handle_bootstrap_complete_message() {
        let ctx = setup_test_context();

        let msg = make_bootstrap_complete_msg("test-cluster", true);

        test_handle_message(&ctx.registry, &ctx.subtree_registry, &msg, &ctx.tx).await;
    }

    #[tokio::test]
    async fn test_handle_heartbeat_message() {
        let ctx = setup_test_context();

        let ready_msg = make_ready_msg("test-cluster", AgentState::Ready);
        test_handle_message(&ctx.registry, &ctx.subtree_registry, &ready_msg, &ctx.tx).await;

        let msg = make_heartbeat_msg("test-cluster", AgentState::Ready);
        test_handle_message(&ctx.registry, &ctx.subtree_registry, &msg, &ctx.tx).await;

        let conn = ctx
            .registry
            .get("test-cluster")
            .expect("agent should be registered");
        assert_eq!(conn.state, AgentState::Ready);
    }

    #[tokio::test]
    async fn test_handle_cluster_health_message() {
        let ctx = setup_test_context();

        let msg = make_cluster_health_msg("test-cluster", 3, 3);

        test_handle_message(&ctx.registry, &ctx.subtree_registry, &msg, &ctx.tx).await;
    }

    #[tokio::test]
    async fn test_handle_status_response_message() {
        let ctx = setup_test_context();

        let msg = make_status_response_msg("test-cluster", "req-123", AgentState::Ready);

        test_handle_message(&ctx.registry, &ctx.subtree_registry, &msg, &ctx.tx).await;
    }

    #[tokio::test]
    async fn test_handle_empty_payload_message() {
        let ctx = setup_test_context();

        let msg = make_empty_msg("test-cluster");

        test_handle_message(&ctx.registry, &ctx.subtree_registry, &msg, &ctx.tx).await;
    }

    #[tokio::test]
    async fn test_multiple_agents_registration() {
        let ctx = setup_test_context();

        let msg1 = make_ready_msg("cluster-1", AgentState::Ready);
        test_handle_message(&ctx.registry, &ctx.subtree_registry, &msg1, &ctx.tx).await;

        let msg2 =
            make_ready_msg_with_versions("cluster-2", AgentState::Provisioning, "0.2.0", "1.29.0");
        test_handle_message(&ctx.registry, &ctx.subtree_registry, &msg2, &ctx.tx).await;

        assert_eq!(ctx.registry.len(), 2);

        let conn1 = ctx
            .registry
            .get("cluster-1")
            .expect("cluster-1 should be registered");
        assert_eq!(conn1.agent_version, "0.1.0");

        let conn2 = ctx
            .registry
            .get("cluster-2")
            .expect("cluster-2 should be registered");
        assert_eq!(conn2.agent_version, "0.2.0");
    }

    #[tokio::test]
    async fn test_full_state_transition_lifecycle() {
        let ctx = setup_test_context();

        let msg = make_ready_msg("test-cluster", AgentState::Provisioning);
        test_handle_message(&ctx.registry, &ctx.subtree_registry, &msg, &ctx.tx).await;
        assert_eq!(
            ctx.registry
                .get("test-cluster")
                .expect("agent should be registered")
                .state,
            AgentState::Provisioning
        );

        let msg = make_heartbeat_msg("test-cluster", AgentState::Ready);
        test_handle_message(&ctx.registry, &ctx.subtree_registry, &msg, &ctx.tx).await;
        assert_eq!(
            ctx.registry
                .get("test-cluster")
                .expect("agent should be registered")
                .state,
            AgentState::Ready
        );
    }

    #[tokio::test]
    async fn test_subtree_state_full_sync() {
        let ctx = setup_test_context();

        let msg = AgentMessage {
            cluster_name: "child-cluster".to_string(),
            payload: Some(Payload::SubtreeState(SubtreeState {
                is_full_sync: true,
                clusters: vec![
                    SubtreeCluster {
                        name: "child-cluster".to_string(),
                        parent: "test-cell".to_string(),
                        phase: "Ready".to_string(),
                        removed: false,
                        labels: std::collections::HashMap::new(),
                    },
                    SubtreeCluster {
                        name: "grandchild".to_string(),
                        parent: "child-cluster".to_string(),
                        phase: "Ready".to_string(),
                        removed: false,
                        labels: std::collections::HashMap::new(),
                    },
                ],
                services: vec![],
            })),
        };

        test_handle_message(&ctx.registry, &ctx.subtree_registry, &msg, &ctx.tx).await;

        // Verify subtree registry was updated
        assert!(ctx.subtree_registry.contains("child-cluster").await);
        assert!(ctx.subtree_registry.contains("grandchild").await);
        // Self is always present
        assert!(ctx.subtree_registry.contains("test-cell").await);
    }

    #[tokio::test]
    async fn test_subtree_state_delta() {
        let ctx = setup_test_context();

        // First, full sync
        let msg1 = AgentMessage {
            cluster_name: "child-cluster".to_string(),
            payload: Some(Payload::SubtreeState(SubtreeState {
                is_full_sync: true,
                clusters: vec![SubtreeCluster {
                    name: "child-cluster".to_string(),
                    parent: "test-cell".to_string(),
                    phase: "Ready".to_string(),
                    removed: false,
                    labels: std::collections::HashMap::new(),
                }],
                services: vec![],
            })),
        };
        test_handle_message(&ctx.registry, &ctx.subtree_registry, &msg1, &ctx.tx).await;

        // Then, delta with removal
        let msg2 = AgentMessage {
            cluster_name: "child-cluster".to_string(),
            payload: Some(Payload::SubtreeState(SubtreeState {
                is_full_sync: false,
                clusters: vec![SubtreeCluster {
                    name: "child-cluster".to_string(),
                    parent: "test-cell".to_string(),
                    phase: "Ready".to_string(),
                    removed: true,
                    labels: std::collections::HashMap::new(),
                }],
                services: vec![],
            })),
        };
        test_handle_message(&ctx.registry, &ctx.subtree_registry, &msg2, &ctx.tx).await;

        assert!(!ctx.subtree_registry.contains("child-cluster").await);
    }
}
