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
use std::sync::LazyLock;
use std::time::Duration;

use futures::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, error, info, instrument, warn};

use kube::api::{DeleteParams, Patch, PatchParams};
use kube::{Api, Client};
use lattice_common::crd::{ClusterRoute, LatticeCluster, LatticeClusterRoutes};

use lattice_proto::lattice_agent_server::{LatticeAgent, LatticeAgentServer};
use lattice_proto::{
    agent_message::Payload, grpc_max_message_size, AgentMessage, AgentState, CellCommand,
    SubtreeState,
};

use crate::connection::K8sResponseRegistry;
use crate::kubeconfig::patch_kubeconfig_for_proxy;
use crate::state_sync;
use crate::subtree_registry::{ClusterInfo, SubtreeRegistry};
use crate::{AgentConnection, SharedAgentRegistry};
use lattice_infra::{extract_cluster_id_from_cert, MtlsError, ServerMtlsConfig};
use tonic::transport::server::TlsConnectInfo;

/// Shared reference to SubtreeRegistry
pub type SharedSubtreeRegistry = std::sync::Arc<SubtreeRegistry>;

/// Timeout for CAPI object import during unpivot. If the distributed move hangs,
/// the agent will retry on the next attempt rather than blocking indefinitely.
const CAPI_IMPORT_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum total concurrent gRPC streams across all connections.
/// Prevents file descriptor and memory exhaustion from connection flooding.
/// 64 streams/connection × 256 global cap is generous for legitimate traffic.
const MAX_GLOBAL_CONCURRENT_STREAMS: usize = 256;

/// Errors that can occur during CAPI object import
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// Failed to create or ensure the target namespace exists
    #[error("failed to ensure namespace: {0}")]
    NamespaceCreation(#[source] lattice_move::MoveError),
    /// CAPI import timed out waiting for objects to be applied
    #[error("CAPI import timed out after {0:?} for cluster {1}")]
    Timeout(Duration, String),
    /// One or more objects failed to import
    #[error("{0} object(s) failed to import")]
    ObjectImport(usize),
    /// No proxy config available for kubeconfig patching
    #[error("no proxy config available")]
    NoProxyConfig,
    /// Kubeconfig Secret was not found after import
    #[error("kubeconfig Secret not found after import")]
    KubeconfigNotFound,
    /// Failed to patch kubeconfig for proxy access
    #[error("failed to patch kubeconfig: {0}")]
    KubeconfigPatch(String),
    /// Failed to unpause cluster resources after import
    #[error("failed to unpause cluster: {0}")]
    UnpauseResources(#[source] lattice_move::MoveError),
}

/// Convert SubtreeState clusters to ClusterInfo, filtering out removed clusters.
///
/// Returns an error if the payload exceeds size limits — callers must handle
/// this explicitly rather than proceeding with empty state.
fn convert_subtree_to_cluster_infos(
    state: &SubtreeState,
) -> Result<Vec<ClusterInfo>, &'static str> {
    if state.clusters.len() > *MAX_CLUSTERS_PER_SUBTREE {
        warn!(
            count = state.clusters.len(),
            max = *MAX_CLUSTERS_PER_SUBTREE,
            "rejecting SubtreeState: too many cluster entries"
        );
        return Err("SubtreeState exceeds MAX_CLUSTERS_PER_SUBTREE");
    }

    Ok(state
        .clusters
        .iter()
        .filter(|c| !c.removed)
        .map(|c| ClusterInfo {
            name: c.name.clone(),
            parent: c.parent.clone(),
            phase: c.phase.clone(),
            labels: c.labels.clone(),
        })
        .collect())
}

/// Extract delta changes from SubtreeState (added and removed cluster names)
fn extract_delta_changes(
    state: &SubtreeState,
) -> Result<(Vec<ClusterInfo>, Vec<String>), &'static str> {
    let added = convert_subtree_to_cluster_infos(state)?;
    let removed = state
        .clusters
        .iter()
        .filter(|c| c.removed)
        .map(|c| c.name.clone())
        .collect();
    Ok((added, removed))
}

/// Handle a cross-cluster service lookup by checking local LatticeClusterRoutes CRDs.
///
/// Only returns routes where the requesting cluster is listed in `allowed_services`
/// (or the route is open to all via `"*"`). This prevents a compromised agent from
/// enumerating the full cross-cluster topology.
async fn handle_service_lookup(
    client: &Client,
    req: &lattice_proto::ServiceLookupRequest,
    requesting_cluster: &str,
) -> lattice_proto::ServiceLookupResponse {
    let api: Api<LatticeClusterRoutes> = Api::all(client.clone());

    match api.list(&kube::api::ListParams::default()).await {
        Ok(list) => {
            for table in &list.items {
                for route in &table.spec.routes {
                    if route.service_name == req.service_name
                        && route.service_namespace == req.service_namespace
                    {
                        // Check that the requesting cluster is authorized to
                        // discover this route (bilateral agreement check).
                        let allowed = route.allowed_services.iter().any(|s| {
                            s == "*"
                                || s.split('/')
                                    .next()
                                    .map(|cluster| cluster == requesting_cluster)
                                    .unwrap_or(false)
                        });
                        if !allowed {
                            debug!(
                                service = %req.service_name,
                                namespace = %req.service_namespace,
                                requesting_cluster = %requesting_cluster,
                                "service lookup denied: requesting cluster not in allowed_services"
                            );
                            continue;
                        }

                        return lattice_proto::ServiceLookupResponse {
                            request_id: req.request_id.clone(),
                            found: true,
                            address: route.address.clone(),
                            port: route.port as u32,
                            hostname: route.hostname.clone(),
                            cluster: table.metadata.name.clone().unwrap_or_default(),
                            error: String::new(),
                        };
                    }
                }
            }
            // Service not found in any route table (or not authorized)
            lattice_proto::ServiceLookupResponse {
                request_id: req.request_id.clone(),
                found: false,
                address: String::new(),
                port: 0,
                hostname: String::new(),
                cluster: String::new(),
                error: String::new(),
            }
        }
        Err(e) => {
            warn!(error = %e, "Failed to list LatticeClusterRoutes for service lookup");
            lattice_proto::ServiceLookupResponse {
                request_id: req.request_id.clone(),
                found: false,
                address: String::new(),
                port: 0,
                hostname: String::new(),
                cluster: String::new(),
                error: "lookup temporarily unavailable".to_string(),
            }
        }
    }
}

/// Maximum routes accepted from a single child. Prevents unbounded CRD/memory growth.
/// Override with `LATTICE_MAX_ROUTES_PER_CLUSTER` env var. Clamped to [1, 10000].
static MAX_ROUTES_PER_CLUSTER: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("LATTICE_MAX_ROUTES_PER_CLUSTER")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
        .clamp(1, 10_000)
});

/// Maximum clusters accepted in a single SubtreeState. Prevents DashMap exhaustion.
/// Override with `LATTICE_MAX_CLUSTERS_PER_SUBTREE` env var. Clamped to [1, 5000].
static MAX_CLUSTERS_PER_SUBTREE: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("LATTICE_MAX_CLUSTERS_PER_SUBTREE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(500)
        .clamp(1, 5_000)
});

/// Group SubtreeService entries by originating cluster and convert to ClusterRoutes.
///
/// Preserves the `cluster` field from each SubtreeService so that routes from
/// different origin clusters get written to separate LatticeClusterRoutes CRDs.
/// Falls back to `sender_cluster` when a service has no cluster field set.
fn group_subtree_routes_by_cluster(
    state: &SubtreeState,
    sender_cluster: &str,
) -> Result<std::collections::HashMap<String, Vec<ClusterRoute>>, &'static str> {
    if state.services.len() > *MAX_ROUTES_PER_CLUSTER {
        warn!(
            count = state.services.len(),
            max = *MAX_ROUTES_PER_CLUSTER,
            "rejecting SubtreeState: too many service routes"
        );
        return Err("SubtreeState exceeds MAX_ROUTES_PER_CLUSTER");
    }

    let mut grouped: std::collections::HashMap<String, Vec<ClusterRoute>> =
        std::collections::HashMap::new();

    for s in &state.services {
        if s.removed {
            continue;
        }
        if s.port > u16::MAX as u32 {
            warn!(service = %s.name, port = s.port, "rejecting: port > 65535");
            continue;
        }
        let route = ClusterRoute {
            service_name: s.name.clone(),
            service_namespace: s.namespace.clone(),
            hostname: s.hostname.clone(),
            address: s.address.clone(),
            port: s.port as u16,
            protocol: s.protocol.clone(),
            allowed_services: s.allowed_services.clone(),
        };
        if let Err(reason) = route.validate() {
            warn!(service = %s.name, reason = %reason, "rejecting route");
            continue;
        }
        let origin = if s.cluster.is_empty() {
            sender_cluster.to_string()
        } else {
            s.cluster.clone()
        };
        grouped.entry(origin).or_default().push(route);
    }

    Ok(grouped)
}

/// Handle cluster deletion (unpivot flow)
///
/// This is the core logic for handling a ClusterDeleting message from an agent.
/// It imports CAPI objects from the child cluster, patches the kubeconfig,
/// unpauses resources, and initiates deletion.
///
/// # Arguments
/// * `cluster` - Name of the cluster being deleted
/// * `namespace` - Namespace where CAPI objects should be imported
/// * `objects` - CAPI objects to import
/// * `client` - Kubernetes client
/// * `registry` - Agent registry for state management
async fn handle_cluster_deletion(
    cluster: String,
    namespace: String,
    objects: Vec<lattice_move::MoveObjectOutput>,
    client: Client,
    registry: SharedAgentRegistry,
) {
    let api: Api<LatticeCluster> = Api::all(client.clone());

    // Step 0: Check if import already complete (crash recovery)
    let import_already_complete = match api.get(&cluster).await {
        Ok(lc) => lc
            .status
            .as_ref()
            .map(|s| s.unpivot_import_complete)
            .unwrap_or(false),
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            info!(cluster = %cluster, "LatticeCluster already deleted");
            registry.finish_teardown(&cluster);
            return;
        }
        Err(e) => {
            error!(cluster = %cluster, error = %e, "Failed to get LatticeCluster");
            registry.finish_teardown(&cluster);
            return;
        }
    };

    if import_already_complete {
        info!(
            cluster = %cluster,
            "CAPI import already complete, skipping re-import (crash recovery)"
        );
    } else if objects.is_empty() {
        error!(
            cluster = %cluster,
            "No CAPI objects received from child - discovery may have failed"
        );
        registry.finish_teardown(&cluster);
        return;
    } else {
        // Import CAPI objects
        if let Err(e) =
            import_capi_objects(&cluster, &namespace, &objects, &client, &registry).await
        {
            error!(cluster = %cluster, error = %e, "Failed to import CAPI objects");
            registry.finish_teardown(&cluster);
            return;
        }

        // Mark import complete (crash-safe)
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
            registry.finish_teardown(&cluster);
            return;
        }
        info!(cluster = %cluster, "Marked unpivot import complete");
    }

    // Step 2: Delete LatticeCluster
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
}

/// Import CAPI objects from child cluster
///
/// Handles object logging, namespace creation, batch apply, kubeconfig patching,
/// and resource unpausing.
async fn import_capi_objects(
    cluster: &str,
    namespace: &str,
    objects: &[lattice_move::MoveObjectOutput],
    client: &Client,
    registry: &SharedAgentRegistry,
) -> Result<(), ImportError> {
    // Log each object received for debugging
    for obj in objects {
        if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&obj.manifest) {
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

    let mut mover = lattice_move::AgentMover::new(client.clone(), namespace);

    // Ensure namespace exists
    mover
        .ensure_namespace()
        .await
        .map_err(ImportError::NamespaceCreation)?;

    // Apply all objects (with timeout to prevent indefinite hangs during unpivot)
    let (mappings, errors) = tokio::time::timeout(CAPI_IMPORT_TIMEOUT, mover.apply_batch(objects))
        .await
        .map_err(|_| ImportError::Timeout(CAPI_IMPORT_TIMEOUT, cluster.to_string()))?;

    if !errors.is_empty() {
        for e in &errors {
            error!(
                cluster = %cluster,
                source_uid = %e.source_uid,
                error = %e.message,
                "Failed to import object"
            );
        }
        return Err(ImportError::ObjectImport(errors.len()));
    }

    info!(
        cluster = %cluster,
        created = mappings.len(),
        "CAPI objects imported successfully"
    );

    // Patch kubeconfig for proxy access
    let proxy_config = registry
        .get_proxy_config()
        .ok_or(ImportError::NoProxyConfig)?;

    match patch_kubeconfig_for_proxy(
        client,
        cluster,
        namespace,
        &proxy_config.url,
        &proxy_config.ca_cert_pem,
    )
    .await
    {
        Ok(true) => info!(cluster = %cluster, "Kubeconfig patched for proxy access"),
        Ok(false) => return Err(ImportError::KubeconfigNotFound),
        Err(e) => return Err(ImportError::KubeconfigPatch(e.to_string())),
    }

    // Unpause cluster
    mover
        .unpause_resources()
        .await
        .map_err(ImportError::UnpauseResources)?;
    info!(cluster = %cluster, "Cluster unpaused successfully");

    Ok(())
}

/// Typed errors from the gRPC server startup path.
///
/// Replaces `Box<dyn Error>` so callers never accidentally leak internal
/// details (file paths, library versions, cert parsing messages) to
/// external observers.
#[derive(Debug, thiserror::Error)]
pub enum GrpcServerError {
    #[error("mTLS configuration error: {0}")]
    Mtls(#[from] MtlsError),
    #[error("gRPC transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
}

/// Configuration for starting the gRPC agent server
pub struct GrpcServerConfig {
    /// Agent registry for tracking connections
    pub registry: SharedAgentRegistry,
    /// Subtree registry for tracking cluster hierarchy
    pub subtree_registry: SharedSubtreeRegistry,
    /// Address to bind the server to
    pub addr: SocketAddr,
    /// mTLS configuration (server cert, key, CA)
    pub mtls_config: ServerMtlsConfig,
    /// Kubernetes client for persisting deletion requests
    pub kube_client: Client,
    /// Certificate blocklist for immediate revocation
    pub blocklist: crate::blocklist::CertificateBlocklist,
    /// Channel for sending route updates to the reconciler
    pub route_update_tx: crate::route_reconciler::RouteUpdateSender,
    /// Shared peer route config, populated after auth proxy starts
    pub peer_config: SharedPeerRouteConfig,
}

/// gRPC server for agent communication
pub struct AgentServer {
    registry: SharedAgentRegistry,
    /// Subtree registry for tracking cluster hierarchy
    subtree_registry: SharedSubtreeRegistry,
    /// Kubernetes client for persisting deletion requests
    kube_client: Client,
    /// Certificate blocklist for immediate revocation
    blocklist: crate::blocklist::CertificateBlocklist,
    /// Channel for sending route updates to the reconciler
    route_update_tx: crate::route_reconciler::RouteUpdateSender,
    /// Shared peer route config, set after auth proxy starts
    peer_config: SharedPeerRouteConfig,
}

/// Peer route sync configuration (set after auth proxy starts)
#[derive(Clone)]
pub struct PeerRouteConfig {
    pub proxy_url: String,
    pub ca_cert_pem: String,
    pub parent_cluster_name: String,
    pub all_routes: crate::route_reconciler::AllRoutesReceiver,
}

/// Shared reference to peer route config, populated after auth proxy starts
pub type SharedPeerRouteConfig = std::sync::Arc<tokio::sync::RwLock<Option<PeerRouteConfig>>>;

/// Shared context for processing agent messages within a connection.
struct MessageContext {
    registry: SharedAgentRegistry,
    subtree_registry: SharedSubtreeRegistry,
    command_tx: mpsc::Sender<CellCommand>,
    kube_client: Client,
    route_update_tx: crate::route_reconciler::RouteUpdateSender,
    connection_generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

/// Process an agent message
async fn process_agent_message(
    ctx: &MessageContext,
    msg: &AgentMessage,
    peer_config: Option<&PeerRouteConfig>,
) {
    let registry = &ctx.registry;
    let subtree_registry = &ctx.subtree_registry;
    let command_tx = &ctx.command_tx;
    let kube_client = &ctx.kube_client;
    let route_update_tx = &ctx.route_update_tx;
    let connection_generation = &ctx.connection_generation;
    let cluster_name = &msg.cluster_name;

    match &msg.payload {
        Some(Payload::Ready(ready)) => {
            info!(
                cluster = %cluster_name,
                agent_version = %ready.agent_version,
                k8s_version = %ready.kubernetes_version,
                protocol_version = ready.protocol_version,
                state = ?ready.state(),
                "Agent connected"
            );

            let conn = AgentConnection::new(
                cluster_name.clone(),
                ready.agent_version.clone(),
                ready.kubernetes_version.clone(),
                command_tx.clone(),
            );
            let gen = registry.register(conn);
            connection_generation.store(gen, std::sync::atomic::Ordering::Relaxed);
            registry.update_state(cluster_name, ready.state());

            // Mark cluster as connected in subtree registry (restores connectivity after disconnect)
            subtree_registry.handle_agent_reconnect(cluster_name).await;

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
            registry.update_lattice_image(cluster_name, hb.lattice_image.clone());
            registry.update_kubernetes_version(cluster_name, hb.kubernetes_version.clone());
            if let Some(ref health) = hb.health {
                debug!(
                    cluster = %cluster_name,
                    ready_nodes = health.ready_nodes,
                    total_nodes = health.total_nodes,
                    "Health update from heartbeat"
                );
                registry.update_health(cluster_name, health.clone());
            }
            if let Some(age) = registry.heartbeat_age_seconds(cluster_name) {
                lattice_common::metrics::set_agent_heartbeat_age(cluster_name, age);
            }

            // Check spec/status hashes for state sync
            if registry.update_hashes(cluster_name, &hb.spec_hash, &hb.status_hash) {
                debug!(cluster = %cluster_name, "Hash mismatch detected, requesting state sync");
                let sync_cmd = CellCommand {
                    command_id: format!("state-sync-{}", cluster_name),
                    command: Some(lattice_proto::cell_command::Command::StateSyncRequest(
                        lattice_proto::RequestStateSync {},
                    )),
                };
                if let Err(e) = command_tx.send(sync_cmd).await {
                    warn!(
                        cluster = %cluster_name,
                        error = %e,
                        "Failed to send state sync request"
                    );
                }
            }

            // Check peer routes hash — if the child's hash doesn't match what
            // we'd send it, push a full PeerRouteSync
            if let Some(pc) = peer_config {
                crate::peer_routes::check_and_sync_peer_routes(
                    registry,
                    cluster_name,
                    &hb.peer_routes_hash,
                    pc,
                    kube_client,
                )
                .await;
            }
        }
        Some(Payload::ClusterHealth(health)) => {
            // Legacy standalone health message — persist to registry
            debug!(
                cluster = %cluster_name,
                ready_nodes = health.ready_nodes,
                total_nodes = health.total_nodes,
                "Health update (standalone)"
            );
            registry.update_health(cluster_name, health.clone());
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

            info!(
                cluster = %cluster_name,
                namespace = %cd.namespace,
                object_count = cd.objects.len(),
                "Cluster deletion requested"
            );

            let objects: Vec<lattice_move::MoveObjectOutput> =
                cd.objects.iter().cloned().map(Into::into).collect();
            let namespace = cd.namespace.clone();
            let cluster = cluster_name.to_string();
            let client = kube_client.clone();
            let registry_clone = registry.clone();

            tokio::spawn(handle_cluster_deletion(
                cluster,
                namespace,
                objects,
                client,
                registry_clone,
            ));
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
                if let Some(sender) = registry.take_pending_k8s_response(&resp.request_id).await {
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
                if let Some(sender) = registry.get_pending_k8s_response(&resp.request_id).await {
                    if let Err(e) = sender.try_send(resp.clone()) {
                        warn!(
                            cluster = %cluster_name,
                            request_id = %resp.request_id,
                            error = %e,
                            "Failed to deliver streaming K8s API response"
                        );
                        // Channel is full or closed, clean up
                        registry.take_pending_k8s_response(&resp.request_id).await;
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

            // Update cluster routing in the subtree registry
            if state.is_full_sync {
                match convert_subtree_to_cluster_infos(state) {
                    Ok(clusters) => {
                        info!(
                            cluster = %cluster_name,
                            subtree_clusters = clusters.len(),
                            "Full sync: updating subtree registry"
                        );
                        subtree_registry
                            .handle_full_sync(cluster_name, clusters)
                            .await;
                    }
                    Err(e) => {
                        error!(cluster = %cluster_name, error = %e, "rejecting oversized subtree state");
                        return;
                    }
                }
            } else {
                match extract_delta_changes(state) {
                    Ok((added, removed)) => {
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
                    Err(e) => {
                        error!(cluster = %cluster_name, error = %e, "rejecting oversized subtree state");
                        return;
                    }
                }
            }

            // Send service routes to the reconciler, grouped by originating cluster.
            // Each SubtreeService carries the cluster name of its origin so routes
            // propagate up the hierarchy without losing provenance.
            if !state.services.is_empty() || state.is_full_sync {
                let grouped = match group_subtree_routes_by_cluster(state, cluster_name) {
                    Ok(g) => g,
                    Err(e) => {
                        error!(cluster = %cluster_name, error = %e, "rejecting oversized route state");
                        return;
                    }
                };
                for (origin, origin_routes) in grouped {
                    let update = crate::route_reconciler::RouteUpdate {
                        cluster_name: origin,
                        routes: origin_routes,
                    };
                    if let Err(e) = route_update_tx.send(update).await {
                        warn!(
                            cluster = %cluster_name,
                            error = %e,
                            "failed to send route update to reconciler"
                        );
                    }
                }
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

            // Route exec data to the pending exec session handler.
            // Spawn the send so we don't block the gRPC receive loop if
            // the channel is full — this guarantees stream3 (exit status)
            // is never silently dropped.
            if let Some(sender) = registry.get_pending_exec_data(&data.request_id) {
                let cluster = cluster_name.to_string();
                let request_id = data.request_id.clone();
                let data = data.clone();
                tokio::spawn(async move {
                    if let Err(e) = sender.send(data).await {
                        warn!(
                            cluster = %cluster,
                            request_id = %request_id,
                            error = %e,
                            "Failed to deliver exec data"
                        );
                    }
                });
            } else {
                debug!(
                    cluster = %cluster_name,
                    request_id = %data.request_id,
                    "Received exec data for unknown session"
                );
            }
        }
        Some(Payload::Event(event)) => {
            info!(
                cluster = %cluster_name,
                reason = %event.reason,
                source = %event.source_cluster,
                severity = %event.severity,
                "Forwarded lifecycle event from child: {}",
                event.message
            );
            // The event is logged and available through the registry.
            // The cluster controller will see these events when it reconciles
            // and can emit them as K8s Events on the parent's LatticeCluster CRD
            // if needed in the future.
        }
        Some(Payload::StateSyncResponse(sync)) => {
            debug!(
                cluster = %cluster_name,
                spec_len = sync.spec_json.len(),
                status_len = sync.status_json.len(),
                "Received state sync response"
            );
            state_sync::handle_state_sync_response(cluster_name, sync, kube_client).await;
        }
        Some(Payload::ServiceLookupRequest(req)) => {
            debug!(
                cluster = %cluster_name,
                service = %req.service_name,
                namespace = %req.service_namespace,
                "Service lookup request"
            );
            let response = handle_service_lookup(kube_client, req, cluster_name).await;
            let cmd = lattice_proto::CellCommand {
                command_id: req.request_id.clone(),
                command: Some(lattice_proto::cell_command::Command::ServiceLookupResponse(
                    response,
                )),
            };
            if let Err(e) = command_tx.send(cmd).await {
                warn!(
                    cluster = %cluster_name,
                    error = %e,
                    "Failed to send service lookup response"
                );
            }
        }
        Some(Payload::ServiceLookupResponse(_)) => {
            // Forwarded from a child's parent — not used on the cell side
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
        blocklist: crate::blocklist::CertificateBlocklist,
        route_update_tx: crate::route_reconciler::RouteUpdateSender,
        peer_config: SharedPeerRouteConfig,
    ) -> Self {
        Self {
            registry,
            subtree_registry,
            kube_client,
            blocklist,
            route_update_tx,
            peer_config,
        }
    }

    /// Convert to a tonic service
    pub fn into_service(self) -> LatticeAgentServer<Self> {
        let max_msg_size = grpc_max_message_size();
        LatticeAgentServer::new(self)
            .max_decoding_message_size(max_msg_size)
            .max_encoding_message_size(max_msg_size)
    }

    /// Start the gRPC server with mTLS on the given address
    ///
    /// This is the primary entry point for running the cell gRPC server.
    /// It requires mTLS configuration with:
    /// - Server certificate (presented to agents)
    /// - Server private key
    /// - CA certificate (for verifying agent certificates)
    pub async fn serve_with_mtls(config: GrpcServerConfig) -> Result<(), GrpcServerError> {
        let server = Self::new(
            config.registry,
            config.subtree_registry,
            config.kube_client,
            config.blocklist,
            config.route_update_tx,
            config.peer_config,
        );
        let tls_config = config.mtls_config.to_tonic_config()?;
        let addr = config.addr;

        info!(%addr, "Starting gRPC server with mTLS");

        Server::builder()
            .tls_config(tls_config)?
            .concurrency_limit_per_connection(64)
            .layer(tower::limit::ConcurrencyLimitLayer::new(
                MAX_GLOBAL_CONCURRENT_STREAMS,
            ))
            .add_service(server.into_service())
            .serve(addr)
            .await?;

        Ok(())
    }
}

/// Extract the cluster ID from the mTLS client certificate presented during TLS handshake.
///
/// The certificate CN is in the format "lattice-agent-{cluster_id}".
/// This is the cryptographic source of truth for agent identity — it cannot be spoofed
/// because the certificate was signed by our CA during bootstrap.
/// Errors from mTLS client certificate extraction.
///
/// Kept small (single pointer) so `Result<String, MtlsAuthError>` doesn't
/// trigger `clippy::result_large_err` the way `Result<String, Status>` would.
#[derive(Debug, thiserror::Error)]
enum MtlsAuthError {
    #[error("No TLS connection info — mTLS is required")]
    NoTls,
    #[error("No client certificate presented — mTLS is required")]
    NoCert,
    #[error("Empty client certificate chain")]
    EmptyChain,
    #[error("Failed to extract cluster ID from certificate: {0}")]
    InvalidCert(String),
    #[error("Certificate is blocklisted")]
    CertificateBlocked(String),
}

impl From<MtlsAuthError> for Status {
    fn from(e: MtlsAuthError) -> Self {
        Status::unauthenticated(e.to_string())
    }
}

/// Extract the client certificate DER bytes from a gRPC request.
fn extract_cert_der_from_request<T>(request: &Request<T>) -> Result<Vec<u8>, MtlsAuthError> {
    let tls_info = request
        .extensions()
        .get::<TlsConnectInfo<tonic::transport::server::TcpConnectInfo>>()
        .ok_or(MtlsAuthError::NoTls)?;

    let certs = tls_info.peer_certs().ok_or(MtlsAuthError::NoCert)?;
    let cert = certs.first().ok_or(MtlsAuthError::EmptyChain)?;

    Ok(cert.to_vec())
}

/// Extract the cluster ID and check the blocklist in a single pass.
fn authenticate_request<T>(
    request: &Request<T>,
    blocklist: &crate::blocklist::CertificateBlocklist,
) -> Result<String, MtlsAuthError> {
    let cert_der = extract_cert_der_from_request(request)?;

    // Check blocklist before extracting identity
    let fingerprint = crate::blocklist::CertificateBlocklist::fingerprint(&cert_der);
    if blocklist.is_blocked(&fingerprint) {
        warn!(fingerprint = %fingerprint, "Rejecting blocklisted certificate");
        return Err(MtlsAuthError::CertificateBlocked(fingerprint));
    }

    extract_cluster_id_from_cert(&cert_der).map_err(|e| MtlsAuthError::InvalidCert(e.to_string()))
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

        // Extract cluster ID from mTLS client certificate CN and check blocklist.
        // This is the cryptographic identity — message-level cluster_name
        // is validated against this to prevent impersonation.
        let cert_cluster_id = authenticate_request(&request, &self.blocklist)?;

        info!(
            ?remote_addr,
            cert_cluster_id = %cert_cluster_id,
            "New agent connection (mTLS verified)"
        );

        let mut inbound = request.into_inner();

        // Channel for sending commands to this agent
        let (command_tx, command_rx) = mpsc::channel::<CellCommand>(32);

        // Clone for the spawned task
        let registry = self.registry.clone();
        let subtree_registry = self.subtree_registry.clone();
        let kube_client = self.kube_client.clone();
        let route_update_tx = self.route_update_tx.clone();
        let command_tx_clone = command_tx.clone();
        let peer_config_lock = self.peer_config.clone();

        // Track the connection generation so cleanup doesn't stomp newer connections
        let connection_generation = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cleanup_generation = connection_generation.clone();

        let msg_ctx = MessageContext {
            registry,
            subtree_registry,
            command_tx: command_tx_clone,
            kube_client,
            route_update_tx,
            connection_generation,
        };

        // Spawn task to handle incoming messages
        tokio::spawn(async move {
            while let Some(result) = inbound.next().await {
                match result {
                    Ok(msg) => {
                        if msg.cluster_name != cert_cluster_id {
                            error!(
                                cert_cluster_id = %cert_cluster_id,
                                msg_cluster_name = %msg.cluster_name,
                                "Cluster name mismatch: message claims different identity than mTLS certificate"
                            );
                            break;
                        }

                        let peer_config = peer_config_lock.read().await.clone();
                        process_agent_message(&msg_ctx, &msg, peer_config.as_ref()).await;
                    }
                    Err(e) => {
                        error!(error = %e, "Error receiving agent message");
                        break;
                    }
                }
            }

            // Cleanup on disconnect — only if this is still the current connection.
            // A stale task from a previous connection must not stomp the new one.
            let gen = cleanup_generation.load(std::sync::atomic::Ordering::Relaxed);
            msg_ctx.registry.unregister(&cert_cluster_id, gen);
            msg_ctx
                .subtree_registry
                .handle_agent_disconnect(&cert_cluster_id)
                .await;

            // Send empty route update to purge this child's routes from the
            // reconciler. Without this, a disconnected child's routes would
            // persist in the LatticeClusterRoutes CRD indefinitely.
            let cleanup = crate::route_reconciler::RouteUpdate {
                cluster_name: cert_cluster_id.to_string(),
                routes: vec![],
            };
            if let Err(e) = msg_ctx.route_update_tx.send(cleanup).await {
                warn!(
                    cluster = %cert_cluster_id,
                    error = %e,
                    "failed to send route cleanup on disconnect"
                );
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
                // Mark cluster as connected in subtree registry
                subtree_registry.handle_agent_reconnect(cluster_name).await;
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
                    if let Ok(clusters) = convert_subtree_to_cluster_infos(state) {
                        subtree_registry
                            .handle_full_sync(cluster_name, clusters)
                            .await;
                    }
                } else if let Ok((added, removed)) = extract_delta_changes(state) {
                    subtree_registry
                        .handle_delta(cluster_name, added, removed)
                        .await;
                }
                // Note: service routes (LatticeClusterRoutes CRD) not tested here
                // since test_handle_message doesn't have a kube client
            }
            Some(Payload::ExecData(_)) => {}
            Some(Payload::Event(_)) => {}
            Some(Payload::StateSyncResponse(_)) => {}
            Some(Payload::ServiceLookupRequest(_)) => {}
            Some(Payload::ServiceLookupResponse(_)) => {}
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
    }

    /// Setup common test context for message handling tests
    fn setup_test_context() -> TestContext {
        let registry = create_test_registry();
        let subtree_registry = create_test_subtree_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);
        TestContext {
            registry,
            subtree_registry,
            tx,
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
                protocol_version: lattice_proto::PROTOCOL_VERSION,
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
                protocol_version: lattice_proto::PROTOCOL_VERSION,
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
                health: None,
                spec_hash: vec![],
                status_hash: vec![],
                lattice_image: String::new(),
                kubernetes_version: String::new(),
                peer_routes_hash: vec![],
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
                pool_resources: vec![],
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

    // =========================================================================
    // gRPC Max Message Size
    // =========================================================================

    #[test]
    fn test_grpc_max_message_size_default() {
        // When env var is not set, should return 16 MiB
        std::env::remove_var("LATTICE_GRPC_MAX_MESSAGE_SIZE");
        assert_eq!(grpc_max_message_size(), 16 * 1024 * 1024);
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

    // =========================================================================
    // Route conversion tests
    // =========================================================================

    #[test]
    fn test_group_routes_filters_removed() {
        let state = SubtreeState {
            clusters: vec![],
            services: vec![
                lattice_proto::SubtreeService {
                    name: "jellyfin".to_string(),
                    namespace: "media".to_string(),
                    cluster: "backend".to_string(),
                    removed: false,
                    hostname: "jellyfin.home.arpa".to_string(),
                    address: "10.0.0.217".to_string(),
                    port: 80,
                    protocol: "HTTP".to_string(),
                    labels: std::collections::HashMap::new(),
                    allowed_services: vec![],
                },
                lattice_proto::SubtreeService {
                    name: "old-service".to_string(),
                    namespace: "default".to_string(),
                    cluster: "backend".to_string(),
                    removed: true,
                    hostname: "old.home.arpa".to_string(),
                    address: "10.0.0.218".to_string(),
                    port: 80,
                    protocol: "HTTP".to_string(),
                    labels: std::collections::HashMap::new(),
                    allowed_services: vec![],
                },
            ],
            is_full_sync: true,
        };

        let grouped = group_subtree_routes_by_cluster(&state, "child").unwrap();
        let routes = &grouped["backend"];
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].service_name, "jellyfin");
    }

    #[test]
    fn test_group_routes_empty() {
        let state = SubtreeState {
            clusters: vec![],
            services: vec![],
            is_full_sync: true,
        };

        let grouped = group_subtree_routes_by_cluster(&state, "child").unwrap();
        assert!(grouped.is_empty());
    }

    #[test]
    fn test_group_routes_preserves_fields() {
        let state = SubtreeState {
            clusters: vec![],
            services: vec![lattice_proto::SubtreeService {
                name: "api".to_string(),
                namespace: "webapp".to_string(),
                cluster: "backend".to_string(),
                removed: false,
                hostname: "api.example.com".to_string(),
                address: "192.168.1.100".to_string(),
                port: 8443,
                protocol: "HTTPS".to_string(),
                labels: std::collections::HashMap::new(),
                allowed_services: vec![],
            }],
            is_full_sync: false,
        };

        let grouped = group_subtree_routes_by_cluster(&state, "child").unwrap();
        let routes = &grouped["backend"];
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].service_name, "api");
        assert_eq!(routes[0].service_namespace, "webapp");
        assert_eq!(routes[0].hostname, "api.example.com");
        assert_eq!(routes[0].address, "192.168.1.100");
        assert_eq!(routes[0].port, 8443);
        assert_eq!(routes[0].protocol, "HTTPS");
    }

    #[test]
    fn test_group_routes_by_cluster_separates_origins() {
        let state = SubtreeState {
            clusters: vec![],
            services: vec![
                lattice_proto::SubtreeService {
                    name: "api".to_string(),
                    namespace: "webapp".to_string(),
                    cluster: "cluster-a".to_string(),
                    removed: false,
                    hostname: "api.example.com".to_string(),
                    address: "10.0.0.1".to_string(),
                    port: 443,
                    protocol: "HTTPS".to_string(),
                    labels: std::collections::HashMap::new(),
                    allowed_services: vec![],
                },
                lattice_proto::SubtreeService {
                    name: "db".to_string(),
                    namespace: "data".to_string(),
                    cluster: "cluster-b".to_string(),
                    removed: false,
                    hostname: "db.example.com".to_string(),
                    address: "10.0.0.2".to_string(),
                    port: 5432,
                    protocol: "TCP".to_string(),
                    labels: std::collections::HashMap::new(),
                    allowed_services: vec![],
                },
            ],
            is_full_sync: false,
        };

        let grouped = group_subtree_routes_by_cluster(&state, "parent").unwrap();
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped["cluster-a"].len(), 1);
        assert_eq!(grouped["cluster-a"][0].service_name, "api");
        assert_eq!(grouped["cluster-b"].len(), 1);
        assert_eq!(grouped["cluster-b"][0].service_name, "db");
    }

    #[test]
    fn test_group_routes_empty_cluster_falls_back_to_sender() {
        let state = SubtreeState {
            clusters: vec![],
            services: vec![lattice_proto::SubtreeService {
                name: "svc".to_string(),
                namespace: "ns".to_string(),
                cluster: String::new(),
                removed: false,
                hostname: "svc.example.com".to_string(),
                address: "10.0.0.1".to_string(),
                port: 80,
                protocol: "HTTP".to_string(),
                labels: std::collections::HashMap::new(),
                allowed_services: vec![],
            }],
            is_full_sync: false,
        };

        let grouped = group_subtree_routes_by_cluster(&state, "sender-cluster").unwrap();
        assert_eq!(grouped.len(), 1);
        assert!(grouped.contains_key("sender-cluster"));
    }
}
