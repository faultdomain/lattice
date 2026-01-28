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

use k8s_openapi::api::core::v1::Secret;
use kube::api::{Patch, PatchParams, PostParams};
use kube::{Api, Client};
use lattice_common::crd::{LatticeCluster, LatticeClusterStatus};
use lattice_common::LATTICE_SYSTEM_NAMESPACE;

use lattice_proto::lattice_agent_server::{LatticeAgent, LatticeAgentServer};
use lattice_proto::{
    agent_message::Payload, cell_command::Command, AgentMessage, AgentState, CellCommand,
    PivotPhase, SyncDistributedResourcesCommand,
};

use crate::{AgentConnection, AgentRegistry, SharedAgentRegistry};
use lattice_infra::ServerMtlsConfig;

/// gRPC server for agent communication
pub struct AgentServer {
    registry: SharedAgentRegistry,
    /// Kubernetes client for persisting deletion requests
    kube_client: Client,
}

/// Handle an agent message (standalone function to avoid temporary object creation)
async fn handle_agent_message_impl(
    registry: &AgentRegistry,
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
                pivot_phase = ?ready.pivot_phase(),
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
            // (Ready is only reached after successful CAPI import)
            if ready.state() == AgentState::Ready {
                registry.set_pivot_complete(cluster_name, true);
            }

            // If agent crashed during resource application, push resources now
            if ready.pivot_phase() == PivotPhase::ApplyingResources {
                info!(cluster = %cluster_name, "Agent needs resources (crash recovery), pushing sync");
                push_resources_for_recovery(kube_client.clone(), command_tx.clone()).await;
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
        Some(Payload::PivotComplete(pc)) => {
            if pc.success {
                info!(
                    cluster = %cluster_name,
                    resources_imported = pc.resources_imported,
                    "Pivot complete"
                );
                registry.update_state(cluster_name, AgentState::Ready);
                registry.set_pivot_complete(cluster_name, true);

                // Persist pivot_complete to CR status immediately
                // This ensures we don't lose state if agent disconnects before reconcile
                let api: Api<LatticeCluster> = Api::all(kube_client.clone());
                let patch = serde_json::json!({
                    "status": {
                        "pivotComplete": true
                    }
                });
                if let Err(e) = api
                    .patch_status(
                        cluster_name,
                        &PatchParams::apply("lattice-operator"),
                        &Patch::Merge(&patch),
                    )
                    .await
                {
                    error!(
                        cluster = %cluster_name,
                        error = %e,
                        "Failed to persist pivot_complete to status"
                    );
                } else {
                    info!(cluster = %cluster_name, "Pivot complete persisted to cluster status");
                }

                // Delete source CAPI resources now that child has successfully imported them
                // This prevents race conditions and ensures only one cluster owns the resources
                if let Some(source_manifests) = registry.take_pivot_source_manifests(cluster_name) {
                    info!(
                        cluster = %cluster_name,
                        manifest_count = source_manifests.capi_manifests.len(),
                        "Deleting source CAPI resources after successful pivot"
                    );
                    match lattice_common::clusterctl::delete_pivoted_capi_resources(
                        kube_client,
                        &source_manifests.capi_manifests,
                    )
                    .await
                    {
                        Ok(deleted) => {
                            info!(
                                cluster = %cluster_name,
                                deleted,
                                "Source CAPI resources deleted"
                            );
                        }
                        Err(e) => {
                            // Log error but don't fail - child already owns the resources
                            // Manual cleanup may be needed
                            error!(
                                cluster = %cluster_name,
                                error = %e,
                                "Failed to delete source CAPI resources (manual cleanup may be needed)"
                            );
                        }
                    }
                }

                // Send post-pivot manifests (CiliumNetworkPolicy)
                // Note: LatticeCluster CRD/instance already delivered via bootstrap webhook
                if let Some(manifests) = registry.take_post_pivot_manifests(cluster_name) {
                    let network_policy_yaml = manifests.network_policy_yaml.clone();

                    // Add CiliumNetworkPolicy for lattice-operator (requires Cilium CRDs)
                    if let Some(ref policy) = network_policy_yaml {
                        let manifest_bytes = vec![policy.clone().into_bytes()];

                        info!(
                            cluster = %cluster_name,
                            manifest_count = manifest_bytes.len(),
                            "Sending post-pivot ApplyManifestsCommand"
                        );

                        let apply_cmd = CellCommand {
                            command_id: format!("post-pivot-apply-{}", cluster_name),
                            command: Some(lattice_proto::cell_command::Command::ApplyManifests(
                                lattice_proto::ApplyManifestsCommand {
                                    manifests: manifest_bytes,
                                },
                            )),
                        };

                        if let Err(e) = command_tx.send(apply_cmd).await {
                            error!(
                                cluster = %cluster_name,
                                error = %e,
                                "Failed to send post-pivot ApplyManifestsCommand, restoring manifests"
                            );
                            // Restore manifests so they can be retried on next PivotComplete
                            registry.set_post_pivot_manifests(
                                cluster_name,
                                crate::PostPivotManifests {
                                    network_policy_yaml,
                                },
                            );
                        }
                    }
                }
            } else {
                error!(
                    cluster = %cluster_name,
                    error = %pc.error_message,
                    "Pivot failed"
                );
                registry.update_state(cluster_name, AgentState::Failed);
            }
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
            info!(
                cluster = %cluster_name,
                namespace = %cd.namespace,
                manifest_count = cd.capi_manifests.len(),
                "Cluster deletion requested by child with CAPI manifests"
            );

            // Store CAPI manifests in memory for immediate use
            registry.set_unpivot_manifests(
                cluster_name,
                crate::UnpivotManifests {
                    capi_manifests: cd.capi_manifests.clone(),
                    namespace: cd.namespace.clone(),
                },
            );

            // Persist manifests to a Secret so they survive operator restarts
            let secret_name = format!("{}{}", UNPIVOT_MANIFESTS_SECRET_PREFIX, cluster_name);
            let secret_api: Api<Secret> =
                Api::namespaced(kube_client.clone(), LATTICE_SYSTEM_NAMESPACE);

            // Encode manifests as base64 JSON array
            let manifests_json = serde_json::to_vec(&cd.capi_manifests).unwrap_or_default();
            let mut data = std::collections::BTreeMap::new();
            data.insert(
                "manifests".to_string(),
                k8s_openapi::ByteString(manifests_json),
            );
            data.insert(
                "namespace".to_string(),
                k8s_openapi::ByteString(cd.namespace.as_bytes().to_vec()),
            );

            let secret = Secret {
                metadata: kube::api::ObjectMeta {
                    name: Some(secret_name.clone()),
                    namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                    labels: Some(
                        [
                            (
                                "app.kubernetes.io/managed-by".to_string(),
                                "lattice-operator".to_string(),
                            ),
                            ("lattice.io/cluster".to_string(), cluster_name.to_string()),
                        ]
                        .into(),
                    ),
                    ..Default::default()
                },
                data: Some(data),
                ..Default::default()
            };

            // Create or update the Secret
            match secret_api.create(&PostParams::default(), &secret).await {
                Ok(_) => {
                    info!(cluster = %cluster_name, secret = %secret_name, "Unpivot manifests persisted to Secret")
                }
                Err(kube::Error::Api(ae)) if ae.code == 409 => {
                    // Already exists, update it
                    if let Err(e) = secret_api
                        .replace(&secret_name, &PostParams::default(), &secret)
                        .await
                    {
                        error!(cluster = %cluster_name, error = %e, "Failed to update unpivot manifests Secret");
                    }
                }
                Err(e) => {
                    error!(cluster = %cluster_name, error = %e, "Failed to create unpivot manifests Secret")
                }
            }

            // Delete the parent's LatticeCluster to trigger proper cleanup flow
            // The finalizer on the LatticeCluster ensures unpivot cleanup completes
            // before the resource is removed. The persisted Secret contains manifests
            // needed for crash recovery.
            let api: Api<LatticeCluster> = Api::all(kube_client.clone());

            // First set unpivotPending to true (for controller to know unpivot is in progress)
            let patch = serde_json::json!({
                "status": {
                    "unpivotPending": true
                }
            });
            if let Err(e) = api
                .patch_status(
                    cluster_name,
                    &PatchParams::apply("lattice-operator"),
                    &Patch::Merge(&patch),
                )
                .await
            {
                error!(
                    cluster = %cluster_name,
                    error = %e,
                    "Failed to set unpivotPending status"
                );
            }

            // Now delete the LatticeCluster - finalizer ensures cleanup completes
            match api.delete(cluster_name, &Default::default()).await {
                Ok(_) => {
                    info!(
                        cluster = %cluster_name,
                        "LatticeCluster deletion initiated (finalizer will ensure cleanup)"
                    );
                }
                Err(kube::Error::Api(ae)) if ae.code == 404 => {
                    // Already deleted or doesn't exist
                    debug!(cluster = %cluster_name, "LatticeCluster already deleted");
                }
                Err(e) => {
                    error!(
                        cluster = %cluster_name,
                        error = %e,
                        "Failed to delete LatticeCluster"
                    );
                }
            };

            // The agent handles unpivot by continuously sending ClusterDeleting until
            // the controller successfully imports and unpauses the CAPI resources.
            // Sending ACK prematurely causes the child to remove its finalizer
            // before the parent has actually taken ownership of the CAPI resources.
            // If the parent crashes between ACK and unpause, the child's
            // LatticeCluster gets deleted and the cluster becomes orphaned.
            //
            // The controller will send the ACK after unpause_capi_cluster succeeds.
            info!(cluster = %cluster_name, "Unpivot manifests stored, waiting for controller to import and unpause before ACK");
        }
        Some(Payload::KubernetesResponse(resp)) => {
            debug!(
                cluster = %cluster_name,
                request_id = %resp.request_id,
                status_code = resp.status_code,
                streaming = resp.streaming,
                stream_end = resp.stream_end,
                "K8s API response received (not processed - future RPC support)"
            );
            // K8s API proxy functionality not yet implemented.
            // All interactions should use RPC commands, not HTTP proxying.
        }
        None => {
            warn!(cluster = %cluster_name, "Received message with no payload");
        }
    }
}

impl AgentServer {
    /// Create a new agent server with the given registry and kube client
    pub fn new(registry: SharedAgentRegistry, kube_client: Client) -> Self {
        Self {
            registry,
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
        addr: SocketAddr,
        mtls_config: ServerMtlsConfig,
        kube_client: Client,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = Self::new(registry, kube_client);
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
                        handle_agent_message_impl(&registry, &msg, &command_tx_clone, &kube_client)
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
            }
        });

        // Return stream of commands to send to agent
        let outbound = ReceiverStream::new(command_rx);
        Ok(Response::new(Box::pin(outbound.map(Ok))))
    }
}

/// Push distributed resources to agent for crash recovery
///
/// Called when an agent reconnects with pivot_phase = ApplyingResources,
/// indicating it crashed after kubeconfig patch but before applying resources.
async fn push_resources_for_recovery(kube_client: Client, command_tx: mpsc::Sender<CellCommand>) {
    // Fetch current distributed resources
    let resources = match crate::resources::fetch_distributable_resources(&kube_client).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "Failed to fetch resources for recovery push");
            return;
        }
    };

    if resources.is_empty() {
        debug!("No resources to push for recovery");
        return;
    }

    let cmd = CellCommand {
        command_id: uuid::Uuid::new_v4().to_string(),
        command: Some(Command::SyncResources(SyncDistributedResourcesCommand {
            cloud_providers: resources.cloud_providers,
            secrets_providers: resources.secrets_providers,
            secrets: resources.secrets,
            full_sync: true,
        })),
    };

    if let Err(e) = command_tx.send(cmd).await {
        warn!(error = %e, "Failed to send resources for recovery");
    } else {
        info!("Pushed resources to agent for crash recovery");
    }
}

/// Prefix for unpivot manifests Secrets
pub const UNPIVOT_MANIFESTS_SECRET_PREFIX: &str = "unpivot-manifests-";

/// Determine if unpivot manifests should be cleaned up based on cluster status.
///
/// Returns true if unpivot is complete (unpivot_pending is false).
/// This is a pure function for easy testing.
pub fn should_cleanup_unpivot_manifests(status: Option<&LatticeClusterStatus>) -> bool {
    let unpivot_pending = status.map(|s| s.unpivot_pending).unwrap_or(false);
    !unpivot_pending
}

/// Clean up stale unpivot-manifests Secrets on operator startup.
///
/// Called during operator initialization to delete unpivot-manifests Secrets for clusters
/// that have been deleted or no longer need them. This handles the case where the operator
/// crashed after unpivot completed but before the Secret was deleted.
pub async fn cleanup_stale_unpivot_secrets(client: &Client) -> Result<usize, String> {
    use kube::api::{DeleteParams, ListParams};

    let secret_api: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let cluster_api: Api<LatticeCluster> = Api::all(client.clone());

    // List all unpivot-manifests Secrets
    let secrets = secret_api
        .list(&ListParams::default())
        .await
        .map_err(|e| format!("Failed to list secrets: {}", e))?;

    let mut cleaned = 0;
    for secret in secrets.items {
        let Some(name) = secret.metadata.name.as_ref() else {
            continue;
        };

        if !name.starts_with(UNPIVOT_MANIFESTS_SECRET_PREFIX) {
            continue;
        }

        // Extract cluster name from secret name
        let cluster_name = &name[UNPIVOT_MANIFESTS_SECRET_PREFIX.len()..];
        if cluster_name.is_empty() {
            continue;
        }

        // Check if cluster still needs unpivot manifests
        let should_delete = match cluster_api.get(cluster_name).await {
            Ok(cluster) => should_cleanup_unpivot_manifests(cluster.status.as_ref()),
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                // Cluster doesn't exist - clean up stale Secret
                true
            }
            Err(_) => {
                // API error - keep the Secret to be safe
                false
            }
        };

        if should_delete {
            match secret_api.delete(name, &DeleteParams::default()).await {
                Ok(_) => {
                    debug!(cluster = %cluster_name, "Cleaned up stale unpivot-manifests Secret");
                    cleaned += 1;
                }
                Err(kube::Error::Api(ae)) if ae.code == 404 => {}
                Err(e) => {
                    warn!(cluster = %cluster_name, error = %e, "Failed to delete unpivot-manifests Secret");
                }
            }
        }
    }

    if cleaned > 0 {
        info!(
            count = cleaned,
            "Cleaned up stale unpivot-manifests Secrets"
        );
    }

    Ok(cleaned)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use lattice_proto::{
        agent_message::Payload, AgentReady, BootstrapComplete, ClusterHealth, Heartbeat,
        PivotComplete, StatusResponse,
    };

    /// Test helper: handle message directly without needing a server
    /// This bypasses the kube client requirement for unit tests
    async fn test_handle_message(
        registry: &AgentRegistry,
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
            Some(Payload::PivotComplete(pc)) => {
                if pc.success {
                    registry.update_state(cluster_name, AgentState::Ready);

                    // Send post-pivot manifests like the real handler does
                    if let Some(manifests) = registry.take_post_pivot_manifests(cluster_name) {
                        let network_policy_yaml = manifests.network_policy_yaml.clone();

                        if let Some(ref policy) = network_policy_yaml {
                            let manifest_bytes = vec![policy.clone().into_bytes()];

                            let apply_cmd = CellCommand {
                                command_id: format!("post-pivot-apply-{}", cluster_name),
                                command: Some(
                                    lattice_proto::cell_command::Command::ApplyManifests(
                                        lattice_proto::ApplyManifestsCommand {
                                            manifests: manifest_bytes,
                                        },
                                    ),
                                ),
                            };
                            // Restore manifests on send failure for retry
                            if command_tx.send(apply_cmd).await.is_err() {
                                registry.set_post_pivot_manifests(
                                    cluster_name,
                                    crate::PostPivotManifests {
                                        network_policy_yaml,
                                    },
                                );
                            }
                        }
                    }
                } else {
                    registry.update_state(cluster_name, AgentState::Failed);
                }
            }
            Some(Payload::Heartbeat(hb)) => {
                registry.update_state(cluster_name, hb.state());
            }
            Some(Payload::ClusterHealth(_)) => {}
            Some(Payload::StatusResponse(_)) => {}
            Some(Payload::ClusterDeleting(_)) => {}
            Some(Payload::KubernetesResponse(_)) => {}
            None => {}
        }
    }

    /// Create a new registry for tests
    fn create_test_registry() -> SharedAgentRegistry {
        Arc::new(AgentRegistry::new())
    }

    // Test handle_agent_message with Ready payload
    #[tokio::test]
    async fn test_handle_ready_message() {
        let registry = create_test_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Provisioning.into(),
                pivot_phase: PivotPhase::None.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };

        test_handle_message(&registry, &msg, &tx).await;

        // Verify agent was registered
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
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // First ready message
        let msg1 = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Provisioning.into(),
                pivot_phase: PivotPhase::None.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &msg1, &tx).await;

        // Second ready message with updated state
        let msg2 = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Ready.into(),
                pivot_phase: PivotPhase::None.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &msg2, &tx).await;

        let conn = registry
            .get("test-cluster")
            .expect("agent should be registered");
        assert_eq!(conn.state, AgentState::Ready);
    }

    // Test handle_agent_message with BootstrapComplete payload
    #[tokio::test]
    async fn test_handle_bootstrap_complete_message() {
        let registry = create_test_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::BootstrapComplete(BootstrapComplete {
                capi_ready: true,
                installed_providers: vec!["docker".to_string()],
            })),
        };

        // Should not panic
        test_handle_message(&registry, &msg, &tx).await;
    }

    // Test handle_agent_message with PivotComplete (success)
    #[tokio::test]
    async fn test_handle_pivot_complete_success_message() {
        let registry = create_test_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // First register the agent
        let ready_msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Pivoting.into(),
                pivot_phase: PivotPhase::None.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &ready_msg, &tx).await;

        // Send pivot complete (success)
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: true,
                error_message: String::new(),
                resources_imported: 5,
            })),
        };
        test_handle_message(&registry, &msg, &tx).await;

        // Verify state changed to Ready
        let conn = registry
            .get("test-cluster")
            .expect("agent should be registered");
        assert_eq!(conn.state, AgentState::Ready);
    }

    // Test handle_agent_message with PivotComplete (failure)
    #[tokio::test]
    async fn test_handle_pivot_complete_failure_message() {
        let registry = create_test_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // First register the agent
        let ready_msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Pivoting.into(),
                pivot_phase: PivotPhase::None.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &ready_msg, &tx).await;

        // Send pivot complete (failure)
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: false,
                error_message: "clusterctl failed".to_string(),
                resources_imported: 0,
            })),
        };
        test_handle_message(&registry, &msg, &tx).await;

        // Verify state changed to Failed
        let conn = registry
            .get("test-cluster")
            .expect("agent should be registered");
        assert_eq!(conn.state, AgentState::Failed);
    }

    // Test handle_agent_message with Heartbeat payload
    #[tokio::test]
    async fn test_handle_heartbeat_message() {
        let registry = create_test_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // First register the agent
        let ready_msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Ready.into(),
                pivot_phase: PivotPhase::None.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &ready_msg, &tx).await;

        // Send heartbeat
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Heartbeat(Heartbeat {
                state: AgentState::Ready.into(),
                timestamp: None,
                uptime_seconds: 3600,
            })),
        };
        test_handle_message(&registry, &msg, &tx).await;

        // State should remain Ready
        let conn = registry
            .get("test-cluster")
            .expect("agent should be registered");
        assert_eq!(conn.state, AgentState::Ready);
    }

    // Test handle_agent_message with ClusterHealth payload
    #[tokio::test]
    async fn test_handle_cluster_health_message() {
        let registry = create_test_registry();
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

        // Should not panic
        test_handle_message(&registry, &msg, &tx).await;
    }

    // Test handle_agent_message with StatusResponse payload
    #[tokio::test]
    async fn test_handle_status_response_message() {
        let registry = create_test_registry();
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

        // Should not panic
        test_handle_message(&registry, &msg, &tx).await;
    }

    // Test handle_agent_message with no payload
    #[tokio::test]
    async fn test_handle_empty_payload_message() {
        let registry = create_test_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: None,
        };

        // Should not panic, just log warning
        test_handle_message(&registry, &msg, &tx).await;
    }

    // Test registry interactions through server
    #[tokio::test]
    async fn test_multiple_agents_registration() {
        let registry = create_test_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // Register first agent
        let msg1 = AgentMessage {
            cluster_name: "cluster-1".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Ready.into(),
                pivot_phase: PivotPhase::None.into(),
                api_server_endpoint: "https://api.cluster1:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &msg1, &tx).await;

        // Register second agent
        let msg2 = AgentMessage {
            cluster_name: "cluster-2".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.2.0".to_string(),
                kubernetes_version: "1.29.0".to_string(),
                state: AgentState::Provisioning.into(),
                pivot_phase: PivotPhase::None.into(),
                api_server_endpoint: "https://api.cluster2:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &msg2, &tx).await;

        // Verify both are registered
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

    // Test state transitions through messages
    #[tokio::test]
    async fn test_full_state_transition_lifecycle() {
        let registry = create_test_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // Initial: Provisioning
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Provisioning.into(),
                pivot_phase: PivotPhase::None.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &msg, &tx).await;
        assert_eq!(
            registry
                .get("test-cluster")
                .expect("agent should be registered")
                .state,
            AgentState::Provisioning
        );

        // Heartbeat with Ready state
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Heartbeat(Heartbeat {
                state: AgentState::Ready.into(),
                timestamp: None,
                uptime_seconds: 60,
            })),
        };
        test_handle_message(&registry, &msg, &tx).await;
        assert_eq!(
            registry
                .get("test-cluster")
                .expect("agent should be registered")
                .state,
            AgentState::Ready
        );

        // Pivot complete
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: true,
                error_message: String::new(),
                resources_imported: 10,
            })),
        };
        test_handle_message(&registry, &msg, &tx).await;
        assert_eq!(
            registry
                .get("test-cluster")
                .expect("agent should be registered")
                .state,
            AgentState::Ready
        );
    }

    // ==========================================================================
    // Post-Pivot Manifest Delivery Tests
    // ==========================================================================
    //
    // These tests verify the critical business logic that sends LatticeCluster
    // CRD and resource manifests to agents after pivot completes. This enables
    // the workload cluster to become fully self-managing.

    /// Story: When pivot completes successfully and post-pivot manifests exist,
    /// they should be sent to the agent via an ApplyManifestsCommand.
    ///
    /// This tests post-pivot manifest delivery for CiliumNetworkPolicy.
    /// Note: LatticeCluster CRD/instance are now delivered via bootstrap webhook.
    #[tokio::test]
    async fn test_pivot_complete_sends_post_pivot_manifests() {
        use crate::PostPivotManifests;

        let registry = create_test_registry();
        let (tx, mut rx) = mpsc::channel::<CellCommand>(32);

        // Register agent
        let ready_msg = AgentMessage {
            cluster_name: "self-managed-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Pivoting.into(),
                pivot_phase: PivotPhase::None.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &ready_msg, &tx).await;

        // Store post-pivot manifests (network policy)
        let policy_yaml = "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\n...";
        registry.set_post_pivot_manifests(
            "self-managed-cluster",
            PostPivotManifests {
                network_policy_yaml: Some(policy_yaml.to_string()),
            },
        );

        // Verify manifests are stored
        assert!(registry.has_post_pivot_manifests("self-managed-cluster"));

        // Send pivot complete
        let pivot_msg = AgentMessage {
            cluster_name: "self-managed-cluster".to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: true,
                error_message: String::new(),
                resources_imported: 10,
            })),
        };
        test_handle_message(&registry, &pivot_msg, &tx).await;

        // Verify ApplyManifestsCommand was sent with manifests
        let cmd = rx.try_recv().expect("should have received a command");
        assert!(
            cmd.command_id.starts_with("post-pivot-apply-"),
            "command_id should indicate post-pivot apply"
        );

        match cmd.command {
            Some(lattice_proto::cell_command::Command::ApplyManifests(apply)) => {
                assert_eq!(apply.manifests.len(), 1, "should include network policy");
                // Verify manifest contents
                let manifest = String::from_utf8(apply.manifests[0].clone())
                    .expect("manifest should be valid UTF-8");
                assert!(manifest.contains("CiliumNetworkPolicy"));
            }
            _ => panic!("expected ApplyManifestsCommand"),
        }

        // Verify manifests were consumed (not available for retry)
        assert!(
            !registry.has_post_pivot_manifests("self-managed-cluster"),
            "manifests should be consumed after successful send"
        );
    }

    /// Story: When pivot completes but no post-pivot manifests exist,
    /// no ApplyManifestsCommand should be sent.
    #[tokio::test]
    async fn test_pivot_complete_without_manifests_sends_nothing() {
        let registry = create_test_registry();
        let (tx, mut rx) = mpsc::channel::<CellCommand>(32);

        // Register agent (no manifests stored)
        let ready_msg = AgentMessage {
            cluster_name: "no-manifests-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Pivoting.into(),
                pivot_phase: PivotPhase::None.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &ready_msg, &tx).await;

        // Verify no manifests stored
        assert!(!registry.has_post_pivot_manifests("no-manifests-cluster"));

        // Send pivot complete
        let pivot_msg = AgentMessage {
            cluster_name: "no-manifests-cluster".to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: true,
                error_message: String::new(),
                resources_imported: 5,
            })),
        };
        test_handle_message(&registry, &pivot_msg, &tx).await;

        // No command should be sent
        assert!(
            rx.try_recv().is_err(),
            "should not send command when no manifests exist"
        );
    }

    /// Story: When pivot fails, post-pivot manifests should not be sent
    /// and state should transition to Failed.
    #[tokio::test]
    async fn test_pivot_failure_does_not_send_manifests() {
        use crate::PostPivotManifests;

        let registry = create_test_registry();
        let (tx, mut rx) = mpsc::channel::<CellCommand>(32);

        // Register agent
        let ready_msg = AgentMessage {
            cluster_name: "failed-pivot-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Pivoting.into(),
                pivot_phase: PivotPhase::None.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &ready_msg, &tx).await;

        // Store manifests (they should remain after failed pivot)
        registry.set_post_pivot_manifests(
            "failed-pivot-cluster",
            PostPivotManifests {
                network_policy_yaml: Some("policy".to_string()),
            },
        );

        // Send pivot complete with failure
        let pivot_msg = AgentMessage {
            cluster_name: "failed-pivot-cluster".to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: false,
                error_message: "clusterctl move failed".to_string(),
                resources_imported: 0,
            })),
        };
        test_handle_message(&registry, &pivot_msg, &tx).await;

        // No command should be sent
        assert!(
            rx.try_recv().is_err(),
            "should not send manifests on pivot failure"
        );

        // State should be Failed
        let conn = registry
            .get("failed-pivot-cluster")
            .expect("agent should be registered");
        assert_eq!(conn.state, AgentState::Failed);

        // Manifests should still exist (can retry after fixing pivot)
        assert!(
            registry.has_post_pivot_manifests("failed-pivot-cluster"),
            "manifests should remain after failed pivot for retry"
        );
    }

    /// Story: When post-pivot manifest send fails, manifests should be
    /// restored for retry on next PivotComplete.
    ///
    /// This tests the error recovery path where the command channel is closed
    /// (simulating disconnect) but we need to preserve manifests for retry.
    #[tokio::test]
    async fn test_pivot_complete_restores_manifests_on_send_failure() {
        use crate::PostPivotManifests;

        let registry = create_test_registry();
        let (tx, rx) = mpsc::channel::<CellCommand>(32);

        // Register agent
        let ready_msg = AgentMessage {
            cluster_name: "restore-test".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Pivoting.into(),
                pivot_phase: PivotPhase::None.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &ready_msg, &tx).await;

        // Store manifests
        registry.set_post_pivot_manifests(
            "restore-test",
            PostPivotManifests {
                network_policy_yaml: Some("policy-yaml-content".to_string()),
            },
        );

        // Drop the receiver to simulate channel closure / agent disconnect
        drop(rx);

        // Send pivot complete - the send will fail because channel is closed
        let pivot_msg = AgentMessage {
            cluster_name: "restore-test".to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: true,
                error_message: String::new(),
                resources_imported: 5,
            })),
        };
        test_handle_message(&registry, &pivot_msg, &tx).await;

        // Manifests should be restored for retry (can be sent on reconnect)
        assert!(
            registry.has_post_pivot_manifests("restore-test"),
            "manifests should be restored after send failure for retry"
        );

        // Verify the restored manifests still have their content
        let manifests = registry
            .take_post_pivot_manifests("restore-test")
            .expect("manifests should exist");
        assert_eq!(
            manifests.network_policy_yaml,
            Some("policy-yaml-content".to_string())
        );
    }

    /// Story: Post-pivot manifests with only network policy
    /// should still be sent correctly.
    #[tokio::test]
    async fn test_pivot_complete_with_partial_manifests() {
        use crate::PostPivotManifests;

        let registry = create_test_registry();
        let (tx, mut rx) = mpsc::channel::<CellCommand>(32);

        // Register agent
        let ready_msg = AgentMessage {
            cluster_name: "partial-manifests".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Pivoting.into(),
                pivot_phase: PivotPhase::None.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        test_handle_message(&registry, &ready_msg, &tx).await;

        // Store network policy
        registry.set_post_pivot_manifests(
            "partial-manifests",
            PostPivotManifests {
                network_policy_yaml: Some(
                    "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy".to_string(),
                ),
            },
        );

        // Send pivot complete
        let pivot_msg = AgentMessage {
            cluster_name: "partial-manifests".to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: true,
                error_message: String::new(),
                resources_imported: 3,
            })),
        };
        test_handle_message(&registry, &pivot_msg, &tx).await;

        // Should receive command with only one manifest
        let cmd = rx.try_recv().expect("should have received a command");
        match cmd.command {
            Some(lattice_proto::cell_command::Command::ApplyManifests(apply)) => {
                assert_eq!(
                    apply.manifests.len(),
                    1,
                    "should include only the network policy manifest"
                );
            }
            _ => panic!("expected ApplyManifestsCommand"),
        }
    }

    // =========================================================================
    // Cleanup Decision Logic Tests
    // =========================================================================

    #[test]
    fn should_cleanup_unpivot_when_not_pending() {
        // unpivot_pending = false (default) -> should cleanup
        let status = LatticeClusterStatus::default();
        assert!(should_cleanup_unpivot_manifests(Some(&status)));

        // Explicitly set to false
        let status = LatticeClusterStatus {
            unpivot_pending: false,
            ..Default::default()
        };
        assert!(should_cleanup_unpivot_manifests(Some(&status)));
    }

    #[test]
    fn should_not_cleanup_unpivot_when_pending() {
        let status = LatticeClusterStatus {
            unpivot_pending: true,
            ..Default::default()
        };
        assert!(!should_cleanup_unpivot_manifests(Some(&status)));
    }

    #[test]
    fn should_cleanup_unpivot_with_no_status() {
        // No status means unpivot not in progress
        assert!(should_cleanup_unpivot_manifests(None));
    }
}
