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

use kube::api::DeleteParams;
use kube::{Api, Client};
use lattice_common::crd::LatticeCluster;

use lattice_proto::lattice_agent_server::{LatticeAgent, LatticeAgentServer};
use lattice_proto::{agent_message::Payload, AgentMessage, AgentState, CellCommand};

use crate::kubeconfig::patch_kubeconfig_for_proxy;
use crate::subtree_registry::{ClusterInfo, SubtreeRegistry};
use crate::{AgentConnection, SharedAgentRegistry};
use lattice_infra::ServerMtlsConfig;

/// Shared reference to SubtreeRegistry
pub type SharedSubtreeRegistry = std::sync::Arc<SubtreeRegistry>;

/// gRPC server for agent communication
pub struct AgentServer {
    registry: SharedAgentRegistry,
    /// Subtree registry for tracking cluster hierarchy
    subtree_registry: SharedSubtreeRegistry,
    /// Kubernetes client for persisting deletion requests
    kube_client: Client,
}

/// Handle an agent message (standalone function to avoid temporary object creation)
async fn handle_agent_message_impl(
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
            // Guard against concurrent teardown spawns
            if !registry.start_teardown(cluster_name) {
                debug!(
                    cluster = %cluster_name,
                    "Teardown already in progress, ignoring duplicate ClusterDeleting"
                );
                return;
            }

            // Log each object received for debugging
            for obj in &cd.objects {
                if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&obj.manifest) {
                    let kind = parsed.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
                    let name = parsed
                        .get("metadata")
                        .and_then(|m| m.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    info!(
                        cluster = %cluster_name,
                        kind = %kind,
                        name = %name,
                        source_uid = %obj.source_uid,
                        owners = obj.owners.len(),
                        "Unpivot: received object"
                    );
                }
            }
            info!(
                cluster = %cluster_name,
                namespace = %cd.namespace,
                object_count = cd.objects.len(),
                "Cluster deletion requested - importing CAPI and initiating deletion"
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
            // This only does import/unpause/delete - controller handles the rest
            tokio::spawn(async move {
                // Step 1: Import CAPI objects from child using AgentMover (same as pivot receiver)
                if !objects.is_empty() {
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
                            warn!(
                                cluster = %cluster,
                                source_uid = %e.source_uid,
                                error = %e.message,
                                "Failed to import object"
                            );
                        }
                    }

                    info!(
                        cluster = %cluster,
                        created = mappings.len(),
                        errors = errors.len(),
                        "CAPI objects imported"
                    );

                    // Step 1.5: Patch kubeconfig to route through proxy
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

                    // Step 1.6: Unpause cluster - CAPI won't delete paused clusters
                    // This MUST succeed, otherwise infrastructure will be orphaned
                    if let Err(e) = mover.unpause_resources().await {
                        error!(cluster = %cluster, error = %e, "Failed to unpause cluster - infrastructure may be orphaned");
                        registry_for_task.finish_teardown(&cluster);
                        return;
                    }
                    info!(cluster = %cluster, "Cluster unpaused successfully");
                }

                // Step 2: Delete LatticeCluster (adds deletionTimestamp)
                // Controller will delete CAPI Cluster which triggers infrastructure cleanup.
                // The finalizer keeps it around while controller handles CAPI cleanup.
                info!(cluster = %cluster, "Initiating LatticeCluster deletion");
                let api: Api<LatticeCluster> = Api::all(client.clone());
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
                let clusters: Vec<ClusterInfo> = state
                    .clusters
                    .iter()
                    .filter(|c| !c.removed)
                    .map(|c| ClusterInfo {
                        name: c.name.clone(),
                        parent: c.parent.clone(),
                        phase: c.phase.clone(),
                        labels: c.labels.clone(),
                    })
                    .collect();

                info!(
                    cluster = %cluster_name,
                    subtree_clusters = clusters.len(),
                    "Full sync: updating subtree registry"
                );
                subtree_registry.handle_full_sync(cluster_name, clusters).await;
            } else {
                // Delta: add/remove specific clusters
                let added: Vec<ClusterInfo> = state
                    .clusters
                    .iter()
                    .filter(|c| !c.removed)
                    .map(|c| ClusterInfo {
                        name: c.name.clone(),
                        parent: c.parent.clone(),
                        phase: c.phase.clone(),
                        labels: c.labels.clone(),
                    })
                    .collect();

                let removed: Vec<String> = state
                    .clusters
                    .iter()
                    .filter(|c| c.removed)
                    .map(|c| c.name.clone())
                    .collect();

                if !added.is_empty() || !removed.is_empty() {
                    debug!(
                        cluster = %cluster_name,
                        added = added.len(),
                        removed = removed.len(),
                        "Delta: updating subtree registry"
                    );
                }
                subtree_registry.handle_delta(cluster_name, added, removed).await;
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
                        handle_agent_message_impl(
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
                    let clusters: Vec<ClusterInfo> = state
                        .clusters
                        .iter()
                        .filter(|c| !c.removed)
                        .map(|c| ClusterInfo {
                            name: c.name.clone(),
                            parent: c.parent.clone(),
                            phase: c.phase.clone(),
                            labels: c.labels.clone(),
                        })
                        .collect();
                    subtree_registry.handle_full_sync(cluster_name, clusters).await;
                } else {
                    let added: Vec<ClusterInfo> = state
                        .clusters
                        .iter()
                        .filter(|c| !c.removed)
                        .map(|c| ClusterInfo {
                            name: c.name.clone(),
                            parent: c.parent.clone(),
                            phase: c.phase.clone(),
                            labels: c.labels.clone(),
                        })
                        .collect();
                    let removed: Vec<String> = state
                        .clusters
                        .iter()
                        .filter(|c| c.removed)
                        .map(|c| c.name.clone())
                        .collect();
                    subtree_registry.handle_delta(cluster_name, added, removed).await;
                }
            }
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

    #[tokio::test]
    async fn test_handle_ready_message() {
        let registry = create_test_registry();
        let subtree_registry = create_test_subtree_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };

        test_handle_message(&registry, &subtree_registry, &msg, &tx).await;

        assert!(!registry.is_empty());
        let conn = registry
            .get("test-cluster")
            .expect("agent should be registered");
        assert_eq!(conn.cluster_name, "test-cluster");
        assert_eq!(conn.agent_version, "0.1.0");
        assert_eq!(conn.kubernetes_version, "1.28.0");
        assert_eq!(conn.state, AgentState::Provisioning);
    }

    #[tokio::test]
    async fn test_handle_ready_message_updates_existing() {
        let registry = create_test_registry();
        let subtree_registry = create_test_subtree_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg1 = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &subtree_registry, &msg1, &tx).await;

        let msg2 = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &subtree_registry, &msg2, &tx).await;

        let conn = registry
            .get("test-cluster")
            .expect("agent should be registered");
        assert_eq!(conn.state, AgentState::Ready);
    }

    #[tokio::test]
    async fn test_handle_bootstrap_complete_message() {
        let registry = create_test_registry();
        let subtree_registry = create_test_subtree_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::BootstrapComplete(BootstrapComplete {
                capi_ready: true,
                installed_providers: vec!["docker".to_string()],
            })),
        };

        test_handle_message(&registry, &subtree_registry, &msg, &tx).await;
    }

    #[tokio::test]
    async fn test_handle_heartbeat_message() {
        let registry = create_test_registry();
        let subtree_registry = create_test_subtree_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let ready_msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &subtree_registry, &ready_msg, &tx).await;

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Heartbeat(Heartbeat {
                state: AgentState::Ready.into(),
                timestamp: None,
                uptime_seconds: 3600,
            })),
        };
        test_handle_message(&registry, &subtree_registry, &msg, &tx).await;

        let conn = registry
            .get("test-cluster")
            .expect("agent should be registered");
        assert_eq!(conn.state, AgentState::Ready);
    }

    #[tokio::test]
    async fn test_handle_cluster_health_message() {
        let registry = create_test_registry();
        let subtree_registry = create_test_subtree_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::ClusterHealth(ClusterHealth {
                ready_nodes: 3,
                total_nodes: 3,
                ready_control_plane: 1,
                total_control_plane: 1,
                conditions: vec![],
            })),
        };

        test_handle_message(&registry, &subtree_registry, &msg, &tx).await;
    }

    #[tokio::test]
    async fn test_handle_status_response_message() {
        let registry = create_test_registry();
        let subtree_registry = create_test_subtree_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::StatusResponse(StatusResponse {
                request_id: "req-123".to_string(),
                state: AgentState::Ready.into(),
                health: None,
                capi_status: None,
            })),
        };

        test_handle_message(&registry, &subtree_registry, &msg, &tx).await;
    }

    #[tokio::test]
    async fn test_handle_empty_payload_message() {
        let registry = create_test_registry();
        let subtree_registry = create_test_subtree_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: None,
        };

        test_handle_message(&registry, &subtree_registry, &msg, &tx).await;
    }

    #[tokio::test]
    async fn test_multiple_agents_registration() {
        let registry = create_test_registry();
        let subtree_registry = create_test_subtree_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg1 = AgentMessage {
            cluster_name: "cluster-1".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://api.cluster1:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &subtree_registry, &msg1, &tx).await;

        let msg2 = AgentMessage {
            cluster_name: "cluster-2".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.2.0".to_string(),
                kubernetes_version: "1.29.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://api.cluster2:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &subtree_registry, &msg2, &tx).await;

        assert_eq!(registry.len(), 2);

        let conn1 = registry
            .get("cluster-1")
            .expect("cluster-1 should be registered");
        assert_eq!(conn1.agent_version, "0.1.0");

        let conn2 = registry
            .get("cluster-2")
            .expect("cluster-2 should be registered");
        assert_eq!(conn2.agent_version, "0.2.0");
    }

    #[tokio::test]
    async fn test_full_state_transition_lifecycle() {
        let registry = create_test_registry();
        let subtree_registry = create_test_subtree_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &subtree_registry, &msg, &tx).await;
        assert_eq!(
            registry
                .get("test-cluster")
                .expect("agent should be registered")
                .state,
            AgentState::Provisioning
        );

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Heartbeat(Heartbeat {
                state: AgentState::Ready.into(),
                timestamp: None,
                uptime_seconds: 60,
            })),
        };
        test_handle_message(&registry, &subtree_registry, &msg, &tx).await;
        assert_eq!(
            registry
                .get("test-cluster")
                .expect("agent should be registered")
                .state,
            AgentState::Ready
        );
    }

    #[tokio::test]
    async fn test_subtree_state_full_sync() {
        let registry = create_test_registry();
        let subtree_registry = create_test_subtree_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

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

        test_handle_message(&registry, &subtree_registry, &msg, &tx).await;

        // Verify subtree registry was updated
        assert!(subtree_registry.contains("child-cluster").await);
        assert!(subtree_registry.contains("grandchild").await);
        // Self is always present
        assert!(subtree_registry.contains("test-cell").await);
    }

    #[tokio::test]
    async fn test_subtree_state_delta() {
        let registry = create_test_registry();
        let subtree_registry = create_test_subtree_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

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
        test_handle_message(&registry, &subtree_registry, &msg1, &tx).await;

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
        test_handle_message(&registry, &subtree_registry, &msg2, &tx).await;

        assert!(!subtree_registry.contains("child-cluster").await);
    }
}
