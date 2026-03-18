//! Agent connection tracking
//!
//! Manages the registry of connected agents and their state.
//! Includes connection notification for resilient request handling.
//!
//! # Traits
//!
//! - `K8sResponseRegistry`: Pending K8s API response tracking (for tunnel tests)

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use lattice_proto::{AgentState, CellCommand, ExecData, KubernetesResponse};
use moka::future::Cache;
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{debug, info, warn};

use lattice_move::{BatchAck, CompleteAck};

// ============================================================================
// Traits for Testability
// ============================================================================

/// Trait for tracking pending K8s API responses
///
/// Extracted for testing tunnel logic without a full AgentRegistry.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait K8sResponseRegistry: Send + Sync {
    /// Register a channel for receiving K8s API responses
    async fn register_pending_k8s_response(&self, request_id: &str, sender: K8sResponseSender);

    /// Get the sender for streaming responses (does not remove)
    async fn get_pending_k8s_response(&self, request_id: &str) -> Option<K8sResponseSender>;

    /// Take and remove the pending response sender
    async fn take_pending_k8s_response(&self, request_id: &str) -> Option<K8sResponseSender>;

    /// Check if a request is pending
    fn has_pending_k8s_response(&self, request_id: &str) -> bool;
}

/// Notification sent when an agent connects (new or reconnection)
#[derive(Clone, Debug)]
pub struct ConnectionNotification {
    /// The cluster that connected
    pub cluster_name: String,
    /// Command channel for the connected agent
    pub command_tx: mpsc::Sender<CellCommand>,
}

/// Represents an agent (connected or disconnected)
///
/// Agents stay in the registry after disconnection to:
/// - Detect reconnections (vs first-time connections)
/// - Preserve state like pivot_complete across brief disconnections
/// - Allow resilient tunnels to wait for known agents to reconnect
pub struct AgentConnection {
    /// Cluster name this agent manages
    pub cluster_name: String,
    /// Agent version
    pub agent_version: String,
    /// Kubernetes version on the cluster
    pub kubernetes_version: String,
    /// Current agent state
    pub state: AgentState,
    /// Channel to send commands to this agent (only valid when connected)
    pub command_tx: mpsc::Sender<CellCommand>,
    /// Whether CAPI is installed and ready on this cluster
    pub capi_ready: bool,
    /// Whether pivot has completed successfully
    pub pivot_complete: bool,
    /// Whether the agent is currently connected
    pub connected: bool,
    /// Latest cluster health from heartbeat
    pub health: Option<lattice_proto::ClusterHealth>,
    /// Timestamp of last heartbeat
    pub last_heartbeat: Option<std::time::Instant>,
    /// SHA-256 hash of the child's LatticeCluster spec (from last heartbeat)
    pub spec_hash: Vec<u8>,
    /// SHA-256 hash of the child's LatticeCluster status (from last heartbeat)
    pub status_hash: Vec<u8>,
    /// Operator image running on this child (from heartbeat)
    pub lattice_image: Option<String>,
    /// When the agent last disconnected (None if never disconnected or currently connected)
    pub disconnected_at: Option<Instant>,
    /// Connection generation — incremented on each register(). Used by unregister()
    /// to avoid stomping a newer connection's state when a zombie task cleans up.
    pub generation: u64,
    /// When the last PeerRouteSync was sent to this child.
    /// Used to force periodic token refresh even when route hashes match.
    pub last_peer_sync: Option<Instant>,
}

impl AgentConnection {
    /// Create a new agent connection
    pub fn new(
        cluster_name: String,
        agent_version: String,
        kubernetes_version: String,
        command_tx: mpsc::Sender<CellCommand>,
    ) -> Self {
        Self {
            cluster_name,
            agent_version,
            kubernetes_version,
            state: AgentState::Provisioning,
            command_tx,
            capi_ready: false,
            pivot_complete: false,
            connected: true,
            health: None,
            last_heartbeat: None,
            spec_hash: vec![],
            status_hash: vec![],
            lattice_image: None,
            disconnected_at: None,
            generation: 0,
            last_peer_sync: None,
        }
    }

    /// Update agent state
    pub fn set_state(&mut self, state: AgentState) {
        self.state = state;
    }

    /// Set CAPI ready status
    pub fn set_capi_ready(&mut self, ready: bool) {
        self.capi_ready = ready;
    }

    /// Set pivot complete status
    pub fn set_pivot_complete(&mut self, complete: bool) {
        self.pivot_complete = complete;
    }

    /// Check if agent is ready for pivot.
    ///
    /// Agent must be in a healthy state AND have CAPI installed.
    /// Failed clusters are excluded — pivoting CAPI resources to a broken
    /// cluster risks making them unrecoverable.
    pub fn is_ready_for_pivot(&self) -> bool {
        let valid_state = matches!(
            self.state,
            AgentState::Provisioning | AgentState::Ready | AgentState::Degraded
        );
        valid_state && self.capi_ready
    }

    /// Send a command to this agent
    pub async fn send_command(&self, command: CellCommand) -> Result<(), SendError> {
        self.command_tx
            .send(command)
            .await
            .map_err(|_| SendError::ChannelClosed)
    }
}

/// Error sending to an agent
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// The agent's channel is closed (disconnected)
    #[error("agent channel closed")]
    ChannelClosed,
}

/// CAPI manifests received from child during unpivot
#[derive(Clone, Debug, Default)]
pub struct UnpivotManifests {
    /// CAPI manifests received during unpivot
    pub capi_manifests: Vec<Vec<u8>>,
    /// Namespace to import into
    pub namespace: String,
}

/// CAPI manifests exported during pivot (deleted after MoveCompleteAck)
#[derive(Clone, Debug, Default)]
pub struct PivotSourceManifests {
    /// CAPI manifests exported during pivot
    pub capi_manifests: Vec<Vec<u8>>,
    /// Source namespace where resources live
    pub namespace: String,
}

/// Sender type for streaming K8s API responses
pub type K8sResponseSender = mpsc::Sender<KubernetesResponse>;

/// Sender type for streaming exec data (stdout/stderr from agent)
pub type ExecDataSender = mpsc::Sender<ExecData>;

/// Configuration for kubeconfig proxy patching
///
/// Contains the URL and CA certificate needed to patch kubeconfig Secrets
/// to route through the authenticated K8s API proxy (with Cedar authorization).
#[derive(Clone, Debug)]
pub struct KubeconfigProxyConfig {
    /// Base URL of the auth proxy (e.g., "https://lattice-cell.lattice-system.svc:8082")
    pub url: String,
    /// PEM-encoded CA certificate for the proxy
    pub ca_cert_pem: String,
}

/// Registry of agents (connected and disconnected)
///
/// Thread-safe registry using DashMap for concurrent access.
/// Agents remain in the registry after disconnection to detect reconnections
/// and allow resilient tunnels to wait for known agents.
pub struct AgentRegistry {
    agents: DashMap<String, AgentConnection>,
    unpivot_manifests: DashMap<String, UnpivotManifests>,
    /// CAPI manifests exported during pivot (deleted after MoveCompleteAck)
    pivot_source_manifests: DashMap<String, PivotSourceManifests>,
    /// Clusters with teardown in progress (prevents concurrent teardown spawns).
    /// Stores the time the teardown started; guards older than TEARDOWN_GUARD_TTL are stale.
    teardown_in_progress: DashMap<String, Instant>,
    /// Pending batch acks keyed by request_id (CellCommand.command_id).
    /// Bounded by MAX_PENDING_ACKS to prevent unbounded growth if agent disconnects mid-pivot.
    pending_batch_acks: DashMap<String, oneshot::Sender<BatchAck>>,
    /// Pending complete acks keyed by request_id (CellCommand.command_id).
    /// Bounded by MAX_PENDING_ACKS to prevent unbounded growth if agent disconnects mid-pivot.
    pending_complete_acks: DashMap<String, oneshot::Sender<CompleteAck>>,
    /// Pending K8s API proxy responses keyed by request_id
    /// Uses mpsc::Sender to support streaming responses (watches).
    /// TTL evicts leaked entries when the agent dies mid-request.
    pending_k8s_responses: Cache<String, K8sResponseSender>,
    /// Pending exec data responses keyed by request_id.
    /// Routes stdout/stderr from agent exec sessions to proxy handlers.
    /// TTL evicts leaked entries when the agent dies mid-session.
    pending_exec_data: moka::sync::Cache<String, ExecDataSender>,
    /// Proxy configuration for kubeconfig patching
    proxy_config: std::sync::OnceLock<KubeconfigProxyConfig>,
    /// Broadcast channel for agent reconnection notifications
    /// Allows waiting requests to retry when an agent reconnects
    connection_tx: broadcast::Sender<ConnectionNotification>,
}

/// Channel capacity for connection notifications
const CONNECTION_CHANNEL_CAPACITY: usize = 64;

/// Maximum age of a teardown guard before it's considered stale.
/// If an agent crashes mid-teardown, this prevents the guard from blocking forever.
const TEARDOWN_GUARD_TTL: Duration = Duration::from_secs(600);

/// Heartbeat staleness threshold (3x the 30s agent heartbeat interval).
/// Connected agents that haven't sent a heartbeat within this window are considered stale.
pub const HEARTBEAT_STALE_THRESHOLD: Duration = Duration::from_secs(90);

/// Maximum number of pending batch/complete acks.
/// Prevents unbounded memory growth if agents disconnect mid-pivot.
const MAX_PENDING_ACKS: usize = 1000;

/// TTL for pending K8s API responses and exec data in the cache.
/// Entries older than this are evicted to prevent unbounded memory growth
/// from unmatched request/response pairs.
const PENDING_RESPONSE_TTL: Duration = Duration::from_secs(300);

/// Register a pending ack in a capacity-bounded DashMap.
/// Evicts one entry if at capacity to prevent unbounded memory growth.
fn register_pending<T>(map: &DashMap<String, T>, request_id: &str, sender: T, label: &str) {
    if map.len() >= MAX_PENDING_ACKS {
        warn!(request_id = %request_id, "Pending {} map at capacity ({}), evicting one entry", label, MAX_PENDING_ACKS);
        if let Some(entry) = map.iter().next() {
            map.remove(entry.key());
        }
    }
    map.insert(request_id.to_string(), sender);
    debug!(request_id = %request_id, "Registered pending {}", label);
}

impl Default for AgentRegistry {
    fn default() -> Self {
        let (connection_tx, _) = broadcast::channel(CONNECTION_CHANNEL_CAPACITY);
        Self {
            agents: DashMap::new(),
            unpivot_manifests: DashMap::new(),
            pivot_source_manifests: DashMap::new(),
            teardown_in_progress: DashMap::new(),
            pending_batch_acks: DashMap::new(),
            pending_complete_acks: DashMap::new(),
            pending_k8s_responses: Cache::builder().time_to_live(PENDING_RESPONSE_TTL).build(),
            pending_exec_data: moka::sync::Cache::builder()
                .time_to_live(PENDING_RESPONSE_TTL)
                .build(),
            proxy_config: std::sync::OnceLock::new(),
            connection_tx,
        }
    }
}

impl AgentRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the proxy configuration for kubeconfig patching (can only be set once)
    pub fn set_proxy_config(&self, config: KubeconfigProxyConfig) {
        let _ = self.proxy_config.set(config);
    }

    /// Get the proxy configuration
    pub fn get_proxy_config(&self) -> Option<KubeconfigProxyConfig> {
        self.proxy_config.get().cloned()
    }

    /// Register an agent connection (new or reconnection).
    ///
    /// Notifies waiting requests via the connection broadcast channel so both
    /// the resilient tunnel and SubtreeForwarder can pick up new agents.
    /// Returns the generation number — pass it to `unregister()` so stale
    /// tasks don't stomp newer connections.
    pub fn register(&self, mut connection: AgentConnection) -> u64 {
        let cluster_name = connection.cluster_name.clone();
        let command_tx = connection.command_tx.clone();
        connection.connected = true;

        // Atomic read-modify-write: preserve pivot_complete from any existing
        // entry, detect reconnect, and capture generation — all within a single
        // DashMap shard lock to prevent TOCTOU races.
        let (is_reconnect, generation) = match self.agents.entry(cluster_name.clone()) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                if entry.get().pivot_complete {
                    connection.pivot_complete = true;
                }
                connection.generation = entry.get().generation + 1;
                let gen = connection.generation;
                entry.insert(connection);
                (true, gen)
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                let gen = connection.generation; // 0 for new connections
                entry.insert(connection);
                (false, gen)
            }
        };

        if is_reconnect {
            info!(cluster = %cluster_name, "Agent reconnected");
        } else {
            info!(cluster = %cluster_name, "Agent connected (first time)");
        }

        // Always notify waiting requests — handles both initial connections
        // and reconnections. Ignore send errors (no receivers is fine).
        let _ = self.connection_tx.send(ConnectionNotification {
            cluster_name,
            command_tx,
        });

        generation
    }

    /// Mark an agent as disconnected, but only if the generation matches.
    ///
    /// When an agent reconnects, the old connection's task eventually cleans up
    /// and calls unregister. Without the generation check, it would stomp the
    /// new connection's state. The generation ensures only the task that owns
    /// the current connection can mark it disconnected.
    pub fn unregister(&self, cluster_name: &str, generation: u64) {
        if let Some(mut agent) = self.agents.get_mut(cluster_name) {
            if agent.generation != generation {
                debug!(
                    cluster = %cluster_name,
                    current_gen = agent.generation,
                    cleanup_gen = generation,
                    "Ignoring unregister from stale connection"
                );
                return;
            }
            Self::mark_disconnected(&mut agent);
            info!(cluster = %cluster_name, "Agent disconnected");
        }
    }

    /// Mark an agent as disconnected (sets `connected = false` and records
    /// the disconnection timestamp). Single source of truth for disconnection.
    fn mark_disconnected(agent: &mut AgentConnection) {
        agent.connected = false;
        agent.disconnected_at = Some(Instant::now());
    }

    /// Get an agent connection by cluster name
    pub fn get(
        &self,
        cluster_name: &str,
    ) -> Option<dashmap::mapref::one::Ref<'_, String, AgentConnection>> {
        self.agents.get(cluster_name)
    }

    /// Get a mutable agent connection by cluster name
    pub fn get_mut(
        &self,
        cluster_name: &str,
    ) -> Option<dashmap::mapref::one::RefMut<'_, String, AgentConnection>> {
        self.agents.get_mut(cluster_name)
    }

    /// Get the number of connected agents
    pub fn len(&self) -> usize {
        self.agents.iter().filter(|r| r.connected).count()
    }

    /// Check if registry has no connected agents
    pub fn is_empty(&self) -> bool {
        !self.agents.iter().any(|r| r.connected)
    }

    /// List all connected cluster names
    pub fn list_clusters(&self) -> Vec<String> {
        self.agents
            .iter()
            .filter(|r| r.connected)
            .map(|r| r.key().clone())
            .collect()
    }

    /// Check if a cluster is known (has connected at least once)
    pub fn is_known(&self, cluster_name: &str) -> bool {
        self.agents.contains_key(cluster_name)
    }

    /// Wait for an agent to be connected, returning its command channel.
    ///
    /// If the agent is already connected, returns immediately.
    /// Otherwise, subscribes to connection notifications and waits up to `timeout`.
    /// Works for both never-connected agents and disconnected agents.
    pub async fn wait_for_connection(
        &self,
        cluster_name: &str,
        timeout: std::time::Duration,
    ) -> Option<mpsc::Sender<CellCommand>> {
        // Fast path: already connected with a live channel
        if let Some(agent) = self.get(cluster_name) {
            if agent.connected && !agent.command_tx.is_closed() {
                return Some(agent.command_tx.clone());
            }
        }

        // Subscribe before checking again (avoid race between check and subscribe)
        let mut rx = self.subscribe_connections();
        let deadline = tokio::time::Instant::now() + timeout;

        // Check again after subscribing (agent may have connected between our check and subscribe)
        if let Some(agent) = self.get(cluster_name) {
            if agent.connected && !agent.command_tx.is_closed() {
                return Some(agent.command_tx.clone());
            }
        }

        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    warn!(cluster = %cluster_name, "Timed out waiting for agent connection");
                    return None;
                }
                result = rx.recv() => {
                    match result {
                        Ok(notification) if notification.cluster_name == cluster_name => {
                            return Some(notification.command_tx);
                        }
                        Ok(_) => continue,
                        Err(_) => return None,
                    }
                }
            }
        }
    }

    /// Update agent state
    pub fn update_state(&self, cluster_name: &str, state: AgentState) {
        if let Some(mut agent) = self.agents.get_mut(cluster_name) {
            debug!(cluster = %cluster_name, ?state, "Agent state updated");
            agent.set_state(state);
        } else {
            warn!(cluster = %cluster_name, "Attempted to update state for unknown agent");
        }
    }

    /// Set CAPI ready status for an agent
    pub fn set_capi_ready(&self, cluster_name: &str, ready: bool) {
        if let Some(mut agent) = self.agents.get_mut(cluster_name) {
            info!(cluster = %cluster_name, capi_ready = ready, "Agent CAPI status updated");
            agent.set_capi_ready(ready);
        } else {
            warn!(cluster = %cluster_name, "Attempted to set CAPI ready for unknown agent");
        }
    }

    /// Set pivot complete status for an agent
    pub fn set_pivot_complete(&self, cluster_name: &str, complete: bool) {
        if let Some(mut agent) = self.agents.get_mut(cluster_name) {
            debug!(cluster = %cluster_name, pivot_complete = complete, "Agent pivot status updated");
            agent.set_pivot_complete(complete);
        }
    }

    /// Update cluster health from heartbeat
    pub fn update_health(&self, cluster_name: &str, health: lattice_proto::ClusterHealth) {
        if let Some(mut agent) = self.agents.get_mut(cluster_name) {
            agent.health = Some(health);
            agent.last_heartbeat = Some(std::time::Instant::now());
        }
    }

    /// Update the operator image reported by an agent heartbeat.
    pub fn update_lattice_image(&self, cluster_name: &str, image: String) {
        if !image.is_empty() {
            if let Some(mut agent) = self.agents.get_mut(cluster_name) {
                agent.lattice_image = Some(image);
            }
        }
    }

    /// Update the Kubernetes version reported by an agent heartbeat.
    pub fn update_kubernetes_version(&self, cluster_name: &str, version: String) {
        if !version.is_empty() {
            if let Some(mut agent) = self.agents.get_mut(cluster_name) {
                agent.kubernetes_version = version;
            }
        }
    }

    /// Update spec/status hashes from heartbeat and detect if a state sync is needed.
    ///
    /// Returns true if either hash changed (or this is the first heartbeat with hashes),
    /// indicating the cell should send a RequestStateSync command.
    pub fn update_hashes(
        &self,
        cluster_name: &str,
        new_spec_hash: &[u8],
        new_status_hash: &[u8],
    ) -> bool {
        if new_spec_hash.is_empty() && new_status_hash.is_empty() {
            return false;
        }

        if let Some(mut agent) = self.agents.get_mut(cluster_name) {
            let first_hashes = agent.spec_hash.is_empty() && agent.status_hash.is_empty();
            let spec_changed = agent.spec_hash != new_spec_hash;
            let status_changed = agent.status_hash != new_status_hash;

            agent.spec_hash = new_spec_hash.to_vec();
            agent.status_hash = new_status_hash.to_vec();

            first_hashes || spec_changed || status_changed
        } else {
            false
        }
    }

    /// Get the latest cluster health for a cluster
    pub fn get_health(&self, cluster_name: &str) -> Option<lattice_proto::ClusterHealth> {
        self.agents.get(cluster_name).and_then(|a| a.health.clone())
    }

    /// Get the age of the last heartbeat in seconds
    pub fn heartbeat_age_seconds(&self, cluster_name: &str) -> Option<f64> {
        self.agents
            .get(cluster_name)
            .and_then(|a| a.last_heartbeat.map(|t| t.elapsed().as_secs_f64()))
    }

    /// Collect health for all connected agents as ChildClusterHealth structs.
    ///
    /// Used by the cluster controller to populate children_health on the CRD status.
    pub fn collect_children_health(&self) -> Vec<lattice_common::crd::ChildClusterHealth> {
        self.agents
            .iter()
            .filter(|r| r.connected)
            .map(|r| {
                let agent = r.value();
                let clamp = |v: i32| v.max(0) as u32;
                let (ready_nodes, total_nodes, ready_cp, total_cp) =
                    if let Some(ref h) = agent.health {
                        (
                            clamp(h.ready_nodes),
                            clamp(h.total_nodes),
                            clamp(h.ready_control_plane),
                            clamp(h.total_control_plane),
                        )
                    } else {
                        (0, 0, 0, 0)
                    };
                let last_heartbeat = agent.last_heartbeat.map(|t| {
                    let age = t.elapsed().as_secs();
                    format!("{}s ago", age)
                });
                let pool_resources = if let Some(ref h) = agent.health {
                    h.pool_resources
                        .iter()
                        .map(|p| lattice_common::crd::PoolResourceSummary {
                            pool_name: p.pool_name.clone(),
                            ready_nodes: p.ready_nodes as u32,
                            total_nodes: p.total_nodes as u32,
                            node_cpu_millis: p.node_cpu_millis,
                            node_memory_bytes: p.node_memory_bytes,
                            node_gpu_count: p.node_gpu_count as u32,
                            gpu_type: p.gpu_type.clone(),
                            allocated_cpu_millis: p.allocated_cpu_millis,
                            allocated_memory_bytes: p.allocated_memory_bytes,
                            allocated_gpu_count: p.allocated_gpu_count as u32,
                        })
                        .collect()
                } else {
                    vec![]
                };
                lattice_common::crd::ChildClusterHealth {
                    name: agent.cluster_name.clone(),
                    ready_nodes,
                    total_nodes,
                    ready_control_plane: ready_cp,
                    total_control_plane: total_cp,
                    agent_state: format!("{:?}", agent.state),
                    last_heartbeat,
                    pool_resources,
                    lattice_image: agent.lattice_image.clone(),
                    kubernetes_version: if agent.kubernetes_version.is_empty() {
                        None
                    } else {
                        Some(agent.kubernetes_version.clone())
                    },
                }
            })
            .collect()
    }

    /// Send a command to a specific agent
    pub async fn send_command(
        &self,
        cluster_name: &str,
        command: CellCommand,
    ) -> Result<(), SendError> {
        match self.agents.get(cluster_name) {
            Some(agent) => agent.send_command(command).await,
            None => Err(SendError::ChannelClosed),
        }
    }

    /// Store CAPI manifests received from child during unpivot
    pub fn set_unpivot_manifests(&self, cluster_name: &str, manifests: UnpivotManifests) {
        info!(
            cluster = %cluster_name,
            manifest_count = manifests.capi_manifests.len(),
            namespace = %manifests.namespace,
            "Stored unpivot manifests from child"
        );
        self.unpivot_manifests
            .insert(cluster_name.to_string(), manifests);
    }

    /// Get and remove unpivot manifests for a cluster
    pub fn take_unpivot_manifests(&self, cluster_name: &str) -> Option<UnpivotManifests> {
        self.unpivot_manifests.remove(cluster_name).map(|(_, m)| m)
    }

    /// Check if unpivot manifests are stored for a cluster
    pub fn has_unpivot_manifests(&self, cluster_name: &str) -> bool {
        self.unpivot_manifests.contains_key(cluster_name)
    }

    /// Store CAPI manifests exported during pivot (to delete after MoveCompleteAck)
    pub fn set_pivot_source_manifests(&self, cluster_name: &str, manifests: PivotSourceManifests) {
        info!(
            cluster = %cluster_name,
            manifest_count = manifests.capi_manifests.len(),
            namespace = %manifests.namespace,
            "Stored pivot source manifests for deletion"
        );
        self.pivot_source_manifests
            .insert(cluster_name.to_string(), manifests);
    }

    /// Get and remove pivot source manifests for a cluster
    pub fn take_pivot_source_manifests(&self, cluster_name: &str) -> Option<PivotSourceManifests> {
        self.pivot_source_manifests
            .remove(cluster_name)
            .map(|(_, m)| m)
    }

    /// Mark teardown as in progress for a cluster
    ///
    /// Returns true if we successfully started (wasn't already in progress).
    /// Stale guards older than TEARDOWN_GUARD_TTL are cleared automatically
    /// to recover from agent crashes during teardown.
    ///
    /// Uses DashMap's entry API for atomic check-and-insert to prevent
    /// concurrent callers from both returning true.
    pub fn start_teardown(&self, cluster_name: &str) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.teardown_in_progress.entry(cluster_name.to_string()) {
            Entry::Occupied(mut entry) => {
                if entry.get().elapsed() < TEARDOWN_GUARD_TTL {
                    false
                } else {
                    warn!(
                        cluster = %cluster_name,
                        age_secs = entry.get().elapsed().as_secs(),
                        "clearing stale teardown guard"
                    );
                    entry.insert(Instant::now());
                    true
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(Instant::now());
                true
            }
        }
    }

    /// Clear teardown in progress for a cluster
    pub fn finish_teardown(&self, cluster_name: &str) {
        self.teardown_in_progress.remove(cluster_name);
    }

    // =========================================================================
    // Pending acknowledgment tracking (request-response correlation)
    // =========================================================================

    /// Register a pending batch ack channel.
    /// The request_id should be the CellCommand.command_id.
    pub fn register_pending_batch_ack(&self, request_id: &str, sender: oneshot::Sender<BatchAck>) {
        register_pending(&self.pending_batch_acks, request_id, sender, "batch ack");
    }

    /// Take the pending batch ack sender.
    pub fn take_pending_batch_ack(&self, request_id: &str) -> Option<oneshot::Sender<BatchAck>> {
        self.pending_batch_acks.remove(request_id).map(|(_, v)| v)
    }

    /// Register a pending complete ack channel.
    pub fn register_pending_complete_ack(
        &self,
        request_id: &str,
        sender: oneshot::Sender<CompleteAck>,
    ) {
        register_pending(
            &self.pending_complete_acks,
            request_id,
            sender,
            "complete ack",
        );
    }

    /// Take the pending complete ack sender.
    pub fn take_pending_complete_ack(
        &self,
        request_id: &str,
    ) -> Option<oneshot::Sender<CompleteAck>> {
        self.pending_complete_acks
            .remove(request_id)
            .map(|(_, v)| v)
    }

    // =========================================================================
    // Exec data response tracking
    // =========================================================================

    /// Register a pending exec data channel
    ///
    /// The request_id should be the ExecRequest.request_id.
    /// Routes stdout/stderr from agent to proxy handler.
    pub fn register_pending_exec_data(&self, request_id: &str, sender: ExecDataSender) {
        self.pending_exec_data
            .insert(request_id.to_string(), sender);
        debug!(request_id = %request_id, "Registered pending exec data");
    }

    /// Get the pending exec data sender (does not remove)
    ///
    /// Returns a clone of the sender for streaming responses.
    pub fn get_pending_exec_data(&self, request_id: &str) -> Option<ExecDataSender> {
        self.pending_exec_data.get(request_id)
    }

    /// Remove and return the pending exec data sender
    ///
    /// Use this when the stream ends or on cancellation.
    /// Safe to call from sync contexts (e.g. Drop impls).
    pub fn take_pending_exec_data(&self, request_id: &str) -> Option<ExecDataSender> {
        let value = self.pending_exec_data.get(request_id);
        if value.is_some() {
            self.pending_exec_data.invalidate(request_id);
        }
        value
    }

    /// Check if an exec session is pending
    pub fn has_pending_exec_data(&self, request_id: &str) -> bool {
        self.pending_exec_data.get(request_id).is_some()
    }
}

// ============================================================================
// Trait Implementations
// ============================================================================

#[async_trait::async_trait]
impl K8sResponseRegistry for AgentRegistry {
    async fn register_pending_k8s_response(&self, request_id: &str, sender: K8sResponseSender) {
        self.pending_k8s_responses
            .insert(request_id.to_string(), sender)
            .await;
        debug!(request_id = %request_id, "Registered pending K8s API response");
    }

    async fn get_pending_k8s_response(&self, request_id: &str) -> Option<K8sResponseSender> {
        self.pending_k8s_responses.get(request_id).await
    }

    async fn take_pending_k8s_response(&self, request_id: &str) -> Option<K8sResponseSender> {
        self.pending_k8s_responses.remove(request_id).await
    }

    fn has_pending_k8s_response(&self, request_id: &str) -> bool {
        self.pending_k8s_responses.contains_key(request_id)
    }
}

impl AgentRegistry {
    /// Subscribe to agent connection notifications (both new and reconnections)
    pub fn subscribe_connections(&self) -> broadcast::Receiver<ConnectionNotification> {
        self.connection_tx.subscribe()
    }

    /// Check if an agent is connected
    pub fn is_connected(&self, cluster_name: &str) -> bool {
        self.agents
            .get(cluster_name)
            .map(|a| a.connected)
            .unwrap_or(false)
    }

    /// Get command channel only if agent is currently connected with a live channel.
    /// Returns None immediately if not connected — never waits.
    pub fn get_connected_command_tx(&self, cluster_name: &str) -> Option<mpsc::Sender<CellCommand>> {
        let agent = self.agents.get(cluster_name)?;
        if agent.connected && !agent.command_tx.is_closed() {
            Some(agent.command_tx.clone())
        } else {
            None
        }
    }

    /// Check if a peer route sync is needed for token refresh.
    /// Returns true if no sync has been sent, or the last sync is older than the threshold.
    pub fn needs_peer_sync(&self, cluster_name: &str, max_age: Duration) -> bool {
        self.agents
            .get(cluster_name)
            .map(|a| {
                a.last_peer_sync
                    .map(|t| t.elapsed() > max_age)
                    .unwrap_or(true)
            })
            .unwrap_or(false)
    }

    /// Record that a PeerRouteSync was sent to a child.
    pub fn mark_peer_sync(&self, cluster_name: &str) {
        if let Some(mut agent) = self.agents.get_mut(cluster_name) {
            agent.last_peer_sync = Some(Instant::now());
        }
    }

    /// Detect agents whose heartbeat is stale and forcibly mark them disconnected.
    ///
    /// When a gRPC stream silently dies (TCP half-open, network partition), the
    /// agent stops sending heartbeats but the cell never gets a stream close event.
    /// The `command_tx` buffer fills up and all proxy requests hang.
    ///
    /// This method detects the stale heartbeat and marks the agent disconnected,
    /// which causes `wait_for_connection` to wait for a fresh reconnect instead
    /// of returning the dead channel.
    ///
    /// Returns the names of agents that were disconnected.
    pub fn disconnect_stale_agents(&self, threshold: Duration) -> Vec<String> {
        let stale: Vec<String> = self
            .agents
            .iter()
            .filter(|r| {
                let agent = r.value();
                agent.connected
                    && agent
                        .last_heartbeat
                        .map(|t| t.elapsed() > threshold)
                        .unwrap_or(false)
            })
            .map(|r| r.key().clone())
            .collect();

        for name in &stale {
            if let Some(mut agent) = self.agents.get_mut(name) {
                Self::mark_disconnected(&mut agent);
                warn!(
                    cluster = %name,
                    "Forcibly disconnected agent: heartbeat stale for {:?}",
                    threshold
                );
            }
        }

        stale
    }

    /// Remove agents that have been disconnected longer than `max_age`.
    ///
    /// Returns the number of agents removed. Also cleans up associated
    /// unpivot/pivot manifests for removed agents.
    pub fn cleanup_stale_disconnected(&self, max_age: Duration) -> usize {
        let stale: Vec<String> = self
            .agents
            .iter()
            .filter(|r| {
                let agent = r.value();
                !agent.connected
                    && agent
                        .disconnected_at
                        .map(|t| t.elapsed() > max_age)
                        .unwrap_or(false)
            })
            .map(|r| r.key().clone())
            .collect();

        let count = stale.len();
        for name in &stale {
            self.agents.remove(name);
            self.unpivot_manifests.remove(name);
            self.pivot_source_manifests.remove(name);
            info!(cluster = %name, "Removed stale disconnected agent from registry");
        }
        count
    }
}

/// Wrap registry in Arc for sharing across tasks
pub type SharedAgentRegistry = Arc<AgentRegistry>;

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_connection(name: &str) -> (AgentConnection, mpsc::Receiver<CellCommand>) {
        let (tx, rx) = mpsc::channel(16);
        let conn = AgentConnection::new(
            name.to_string(),
            "1.0.0".to_string(),
            "1.32.0".to_string(),
            tx,
        );
        (conn, rx)
    }

    #[test]
    fn test_registry_register_and_get() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("test-cluster");

        registry.register(conn);

        assert!(registry.is_connected("test-cluster"));
        assert!(!registry.is_connected("other-cluster"));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_registry_unregister() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("test-cluster");

        registry.register(conn);
        registry.unregister("test-cluster", 0);

        // Agent is still known but not connected
        assert!(!registry.is_connected("test-cluster"));
        assert!(registry.is_known("test-cluster"));
        assert!(registry.is_empty()); // No connected agents
    }

    #[test]
    fn test_connection_is_ready_for_pivot() {
        let (mut conn, _rx) = create_test_connection("test");

        // Without CAPI ready, not ready for pivot
        assert!(!conn.is_ready_for_pivot());

        // With CAPI ready, valid states allow pivot
        conn.capi_ready = true;
        assert!(conn.is_ready_for_pivot());

        conn.state = AgentState::Pivoting;
        assert!(!conn.is_ready_for_pivot());

        conn.state = AgentState::Failed;
        assert!(
            !conn.is_ready_for_pivot(),
            "failed clusters must not be eligible for pivot"
        );
    }

    #[tokio::test]
    async fn test_send_command() {
        let registry = AgentRegistry::new();
        let (conn, mut rx) = create_test_connection("test-cluster");

        registry.register(conn);

        let command = CellCommand {
            command_id: "cmd-1".to_string(),
            command: None,
        };

        registry
            .send_command("test-cluster", command)
            .await
            .expect("send should succeed");

        let received = rx.recv().await.expect("should receive command");
        assert_eq!(received.command_id, "cmd-1");
    }

    #[tokio::test]
    async fn test_send_to_unknown_agent() {
        let registry = AgentRegistry::new();
        let result = registry
            .send_command(
                "unknown",
                CellCommand {
                    command_id: "x".to_string(),
                    command: None,
                },
            )
            .await;

        assert!(matches!(result, Err(SendError::ChannelClosed)));
    }

    #[test]
    fn test_unpivot_manifests() {
        let registry = AgentRegistry::new();

        let manifests = UnpivotManifests {
            capi_manifests: vec![b"manifest1".to_vec()],
            namespace: "capi-system".to_string(),
        };

        registry.set_unpivot_manifests("test", manifests);
        assert!(registry.has_unpivot_manifests("test"));

        let retrieved = registry.take_unpivot_manifests("test").unwrap();
        assert_eq!(retrieved.capi_manifests.len(), 1);

        assert!(!registry.has_unpivot_manifests("test"));
    }

    // =========================================================================
    // Connection State Tests
    // =========================================================================

    #[test]
    fn test_connection_set_state() {
        let (mut conn, _rx) = create_test_connection("test");
        assert_eq!(conn.state, AgentState::Provisioning);

        conn.set_state(AgentState::Ready);
        assert_eq!(conn.state, AgentState::Ready);
    }

    #[test]
    fn test_connection_set_capi_ready() {
        let (mut conn, _rx) = create_test_connection("test");
        assert!(!conn.capi_ready);

        conn.set_capi_ready(true);
        assert!(conn.capi_ready);

        conn.set_capi_ready(false);
        assert!(!conn.capi_ready);
    }

    #[test]
    fn test_connection_set_pivot_complete() {
        let (mut conn, _rx) = create_test_connection("test");
        assert!(!conn.pivot_complete);

        conn.set_pivot_complete(true);
        assert!(conn.pivot_complete);
    }

    // =========================================================================
    // Registry Update Tests
    // =========================================================================

    #[test]
    fn test_registry_update_state() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("test-cluster");

        registry.register(conn);
        registry.update_state("test-cluster", AgentState::Ready);

        let agent = registry.get("test-cluster").unwrap();
        assert_eq!(agent.state, AgentState::Ready);
    }

    #[test]
    fn test_registry_update_state_unknown_agent() {
        let registry = AgentRegistry::new();
        // Should not panic
        registry.update_state("unknown", AgentState::Ready);
    }

    #[test]
    fn test_registry_set_capi_ready() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("test-cluster");

        registry.register(conn);
        registry.set_capi_ready("test-cluster", true);

        let agent = registry.get("test-cluster").unwrap();
        assert!(agent.capi_ready);
    }

    #[test]
    fn test_registry_set_capi_ready_unknown_agent() {
        let registry = AgentRegistry::new();
        // Should not panic
        registry.set_capi_ready("unknown", true);
    }

    #[test]
    fn test_registry_set_pivot_complete() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("test-cluster");

        registry.register(conn);
        registry.set_pivot_complete("test-cluster", true);

        let agent = registry.get("test-cluster").unwrap();
        assert!(agent.pivot_complete);
    }

    #[test]
    fn test_registry_list_clusters() {
        let registry = AgentRegistry::new();
        let (conn1, _rx1) = create_test_connection("cluster-a");
        let (conn2, _rx2) = create_test_connection("cluster-b");

        registry.register(conn1);
        registry.register(conn2);

        let clusters = registry.list_clusters();
        assert_eq!(clusters.len(), 2);
        assert!(clusters.contains(&"cluster-a".to_string()));
        assert!(clusters.contains(&"cluster-b".to_string()));
    }

    #[test]
    fn test_registry_get_mut() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("test-cluster");

        registry.register(conn);

        {
            let mut agent = registry.get_mut("test-cluster").unwrap();
            agent.set_state(AgentState::Degraded);
        }

        let agent = registry.get("test-cluster").unwrap();
        assert_eq!(agent.state, AgentState::Degraded);
    }

    // =========================================================================
    // Pivot Source Manifests Tests
    // =========================================================================

    #[test]
    fn test_pivot_source_manifests() {
        let registry = AgentRegistry::new();

        let manifests = PivotSourceManifests {
            capi_manifests: vec![b"cluster-1.yaml".to_vec(), b"machine-1.yaml".to_vec()],
            namespace: "default".to_string(),
        };

        registry.set_pivot_source_manifests("test-cluster", manifests);

        let retrieved = registry
            .take_pivot_source_manifests("test-cluster")
            .unwrap();
        assert_eq!(retrieved.capi_manifests.len(), 2);
        assert_eq!(retrieved.namespace, "default");

        // Should be gone after take
        assert!(registry
            .take_pivot_source_manifests("test-cluster")
            .is_none());
    }

    // =========================================================================
    // Struct Default Tests
    // =========================================================================

    #[test]
    fn test_unpivot_manifests_default() {
        let m = UnpivotManifests::default();
        assert!(m.capi_manifests.is_empty());
        assert!(m.namespace.is_empty());
    }

    #[test]
    fn test_pivot_source_manifests_default() {
        let m = PivotSourceManifests::default();
        assert!(m.capi_manifests.is_empty());
        assert!(m.namespace.is_empty());
    }

    // =========================================================================
    // Is Ready For Pivot Edge Cases
    // =========================================================================

    #[test]
    fn test_is_ready_for_pivot_all_states() {
        let (mut conn, _rx) = create_test_connection("test");
        conn.capi_ready = true;

        // Valid states for pivot
        conn.state = AgentState::Provisioning;
        assert!(conn.is_ready_for_pivot());

        conn.state = AgentState::Ready;
        assert!(conn.is_ready_for_pivot());

        conn.state = AgentState::Degraded;
        assert!(conn.is_ready_for_pivot());

        // Invalid states for pivot
        conn.state = AgentState::Failed;
        assert!(
            !conn.is_ready_for_pivot(),
            "failed clusters must not be eligible for pivot"
        );

        conn.state = AgentState::Pivoting;
        assert!(!conn.is_ready_for_pivot());

        conn.state = AgentState::Unknown;
        assert!(!conn.is_ready_for_pivot());
    }

    // =========================================================================
    // Pending Ack Tests
    // =========================================================================

    #[tokio::test]
    async fn test_pending_batch_ack_roundtrip() {
        let registry = AgentRegistry::new();
        let (tx, rx) = oneshot::channel::<BatchAck>();

        registry.register_pending_batch_ack("req-123", tx);

        let sender = registry
            .take_pending_batch_ack("req-123")
            .expect("should have pending ack");

        let ack = BatchAck {
            mappings: vec![("src-1".to_string(), "tgt-1".to_string())],
            errors: vec![],
        };
        sender.send(ack).expect("channel should be open");

        let received = rx.await.expect("should receive ack");
        assert_eq!(received.mappings.len(), 1);
    }

    #[test]
    fn test_pending_batch_ack_take_nonexistent() {
        let registry = AgentRegistry::new();
        assert!(registry.take_pending_batch_ack("nonexistent").is_none());
    }

    #[tokio::test]
    async fn test_pending_complete_ack_roundtrip() {
        let registry = AgentRegistry::new();
        let (tx, rx) = oneshot::channel::<CompleteAck>();

        registry.register_pending_complete_ack("req-456", tx);

        let sender = registry
            .take_pending_complete_ack("req-456")
            .expect("should have pending ack");

        let ack = CompleteAck {
            success: true,
            error: String::new(),
            resources_created: 42,
        };
        sender.send(ack).expect("channel should be open");

        let received = rx.await.expect("should receive ack");
        assert!(received.success);
        assert_eq!(received.resources_created, 42);
    }

    #[test]
    fn test_pending_complete_ack_take_nonexistent() {
        let registry = AgentRegistry::new();
        assert!(registry.take_pending_complete_ack("nonexistent").is_none());
    }

    // =========================================================================
    // K8s API Proxy Response Tests
    // =========================================================================

    #[tokio::test]
    async fn test_pending_k8s_response_roundtrip() {
        let registry = AgentRegistry::new();
        let (tx, mut rx) = mpsc::channel::<KubernetesResponse>(16);

        registry
            .register_pending_k8s_response("k8s-req-123", tx)
            .await;
        assert!(registry.has_pending_k8s_response("k8s-req-123"));

        // Get sender and send a response
        let sender = registry
            .get_pending_k8s_response("k8s-req-123")
            .await
            .expect("should have pending response");

        let response = KubernetesResponse {
            request_id: "k8s-req-123".to_string(),
            status_code: 200,
            body: b"{}".to_vec(),
            ..Default::default()
        };
        sender.send(response).await.expect("channel should be open");

        let received = rx.recv().await.expect("should receive response");
        assert_eq!(received.request_id, "k8s-req-123");
        assert_eq!(received.status_code, 200);
    }

    #[tokio::test]
    async fn test_pending_k8s_response_streaming() {
        let registry = AgentRegistry::new();
        let (tx, mut rx) = mpsc::channel::<KubernetesResponse>(16);

        registry
            .register_pending_k8s_response("watch-123", tx)
            .await;

        // Send multiple streaming responses
        for i in 0..3 {
            let sender = registry
                .get_pending_k8s_response("watch-123")
                .await
                .expect("should have pending response");

            let response = KubernetesResponse {
                request_id: "watch-123".to_string(),
                status_code: 200,
                streaming: true,
                stream_end: i == 2,
                ..Default::default()
            };
            sender.send(response).await.expect("channel should be open");
        }

        // On stream end, take the sender to remove it
        let _ = registry.take_pending_k8s_response("watch-123").await;
        assert!(!registry.has_pending_k8s_response("watch-123"));

        // Verify we received all responses
        for i in 0..3 {
            let received = rx.recv().await.expect("should receive response");
            assert_eq!(received.stream_end, i == 2);
        }
    }

    #[tokio::test]
    async fn test_pending_k8s_response_take_nonexistent() {
        let registry = AgentRegistry::new();
        assert!(registry
            .take_pending_k8s_response("nonexistent")
            .await
            .is_none());
    }

    #[test]
    fn test_pending_k8s_response_has_nonexistent() {
        let registry = AgentRegistry::new();
        assert!(!registry.has_pending_k8s_response("nonexistent"));
    }

    #[test]
    fn test_proxy_config_set_and_get() {
        let registry = AgentRegistry::new();

        // Initially no config
        assert!(registry.get_proxy_config().is_none());

        // Set config
        let config = KubeconfigProxyConfig {
            url: "https://proxy.example.com:8082".to_string(),
            ca_cert_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
        };
        registry.set_proxy_config(config.clone());

        // Get config
        let retrieved = registry.get_proxy_config().expect("config should exist");
        assert_eq!(retrieved.url, "https://proxy.example.com:8082");
        assert!(retrieved.ca_cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_connection_notification() {
        let registry = AgentRegistry::new();
        let mut rx = registry.subscribe_connections();

        // First connection — broadcasts notification
        let (conn1, _rx1) = create_test_connection("test-cluster");
        registry.register(conn1);
        let notification = rx
            .try_recv()
            .expect("should receive notification on first connection");
        assert_eq!(notification.cluster_name, "test-cluster");
        assert!(registry.is_connected("test-cluster"));
        assert!(registry.is_known("test-cluster"));

        // Disconnect
        registry.unregister("test-cluster", 0);
        assert!(!registry.is_connected("test-cluster"));
        assert!(registry.is_known("test-cluster"));

        // Reconnection — also broadcasts notification
        let (conn2, _rx2) = create_test_connection("test-cluster");
        registry.register(conn2);
        let notification = rx
            .try_recv()
            .expect("should receive notification on reconnection");
        assert_eq!(notification.cluster_name, "test-cluster");
        assert!(registry.is_connected("test-cluster"));
    }

    #[test]
    fn test_is_known_unknown_cluster() {
        let registry = AgentRegistry::new();
        assert!(!registry.is_known("never-seen"));
        assert!(!registry.is_connected("never-seen"));
    }

    // =========================================================================
    // Teardown Guard Tests
    // =========================================================================

    #[test]
    fn test_teardown_guard_blocks() {
        let registry = AgentRegistry::new();

        // First call should succeed
        assert!(registry.start_teardown("test-cluster"));

        // Second call should be blocked (guard still fresh)
        assert!(!registry.start_teardown("test-cluster"));
    }

    #[test]
    fn test_teardown_guard_stale_expires() {
        let registry = AgentRegistry::new();

        // Manually insert a stale guard (700 seconds ago, past the 600s TTL)
        let stale_time = Instant::now() - Duration::from_secs(700);
        registry
            .teardown_in_progress
            .insert("test-cluster".to_string(), stale_time);

        // start_teardown should clear the stale guard and succeed
        assert!(registry.start_teardown("test-cluster"));
    }

    #[test]
    fn test_teardown_guard_fresh_blocks() {
        let registry = AgentRegistry::new();

        // Insert a guard that's 500 seconds old (within the 600s TTL)
        let recent_time = Instant::now() - Duration::from_secs(500);
        registry
            .teardown_in_progress
            .insert("test-cluster".to_string(), recent_time);

        // start_teardown should still be blocked
        assert!(!registry.start_teardown("test-cluster"));
    }

    #[test]
    fn test_teardown_finish_clears_guard() {
        let registry = AgentRegistry::new();

        assert!(registry.start_teardown("test-cluster"));
        registry.finish_teardown("test-cluster");

        // After finish, a new teardown should succeed
        assert!(registry.start_teardown("test-cluster"));
    }

    #[test]
    fn test_pivot_complete_preserved_across_reconnection() {
        let registry = AgentRegistry::new();

        // First connection
        let (conn1, _rx1) = create_test_connection("test-cluster");
        registry.register(conn1);
        registry.set_pivot_complete("test-cluster", true);

        // Verify pivot_complete is set
        {
            let agent = registry.get("test-cluster").unwrap();
            assert!(agent.pivot_complete);
        }

        // Disconnect
        registry.unregister("test-cluster", 0);

        // Reconnect with new connection (would normally have pivot_complete=false)
        let (conn2, _rx2) = create_test_connection("test-cluster");
        registry.register(conn2);

        // pivot_complete should be preserved from before
        let agent = registry.get("test-cluster").unwrap();
        assert!(agent.pivot_complete);
    }

    // =========================================================================
    // Heartbeat Staleness Tests
    // =========================================================================

    #[test]
    fn test_disconnect_stale_agents_none_stale() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("cluster-a");
        registry.register(conn);

        // Fresh heartbeat
        registry.update_health(
            "cluster-a",
            lattice_proto::ClusterHealth {
                ready_nodes: 1,
                total_nodes: 1,
                ..Default::default()
            },
        );

        let stale = registry.disconnect_stale_agents(HEARTBEAT_STALE_THRESHOLD);
        assert!(stale.is_empty());
        assert!(registry.get("cluster-a").unwrap().connected);
    }

    #[test]
    fn test_disconnect_stale_agents_marks_disconnected() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("cluster-a");
        registry.register(conn);

        // Manually set a stale heartbeat (100 seconds ago, past the 90s threshold)
        if let Some(mut agent) = registry.get_mut("cluster-a") {
            agent.last_heartbeat = Some(Instant::now() - Duration::from_secs(100));
        }

        let stale = registry.disconnect_stale_agents(HEARTBEAT_STALE_THRESHOLD);
        assert_eq!(stale, vec!["cluster-a"]);
        // Must actually be disconnected now
        assert!(!registry.get("cluster-a").unwrap().connected);
        assert!(registry.get("cluster-a").unwrap().disconnected_at.is_some());
    }

    #[test]
    fn test_disconnect_stale_agents_already_disconnected_excluded() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("cluster-a");
        registry.register(conn);

        // Set a stale heartbeat then disconnect
        if let Some(mut agent) = registry.get_mut("cluster-a") {
            agent.last_heartbeat = Some(Instant::now() - Duration::from_secs(200));
        }
        registry.unregister("cluster-a", 0);

        // Already disconnected agents should NOT be double-disconnected
        let stale = registry.disconnect_stale_agents(HEARTBEAT_STALE_THRESHOLD);
        assert!(stale.is_empty());
    }

    #[test]
    fn test_disconnect_stale_agents_no_heartbeat_yet() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("cluster-a");
        registry.register(conn);

        // No heartbeat received yet (still in handshake) — don't disconnect
        let stale = registry.disconnect_stale_agents(HEARTBEAT_STALE_THRESHOLD);
        assert!(stale.is_empty());
    }

    // =========================================================================
    // update_hashes Tests
    // =========================================================================

    #[test]
    fn test_update_hashes_first_update_returns_true() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("cluster-a");
        registry.register(conn);

        let spec_hash = vec![1, 2, 3];
        let status_hash = vec![4, 5, 6];

        let changed = registry.update_hashes("cluster-a", &spec_hash, &status_hash);
        assert!(changed, "First hash update should trigger sync");
    }

    #[test]
    fn test_update_hashes_same_hashes_returns_false() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("cluster-a");
        registry.register(conn);

        let spec_hash = vec![1, 2, 3];
        let status_hash = vec![4, 5, 6];

        // First update (sets initial hashes)
        registry.update_hashes("cluster-a", &spec_hash, &status_hash);

        // Same hashes again
        let changed = registry.update_hashes("cluster-a", &spec_hash, &status_hash);
        assert!(!changed, "Identical hashes should not trigger sync");
    }

    #[test]
    fn test_update_hashes_changed_spec_returns_true() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("cluster-a");
        registry.register(conn);

        let spec_hash = vec![1, 2, 3];
        let status_hash = vec![4, 5, 6];

        // Set initial hashes
        registry.update_hashes("cluster-a", &spec_hash, &status_hash);

        // Change spec hash only
        let new_spec_hash = vec![7, 8, 9];
        let changed = registry.update_hashes("cluster-a", &new_spec_hash, &status_hash);
        assert!(changed, "Changed spec hash should trigger sync");
    }

    #[test]
    fn test_update_hashes_changed_status_returns_true() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("cluster-a");
        registry.register(conn);

        let spec_hash = vec![1, 2, 3];
        let status_hash = vec![4, 5, 6];

        // Set initial hashes
        registry.update_hashes("cluster-a", &spec_hash, &status_hash);

        // Change status hash only
        let new_status_hash = vec![10, 11, 12];
        let changed = registry.update_hashes("cluster-a", &spec_hash, &new_status_hash);
        assert!(changed, "Changed status hash should trigger sync");
    }

    #[test]
    fn test_update_hashes_empty_hashes_returns_false() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("cluster-a");
        registry.register(conn);

        let changed = registry.update_hashes("cluster-a", &[], &[]);
        assert!(!changed, "Empty hashes should not trigger sync");
    }

    #[test]
    fn test_update_hashes_unknown_cluster_returns_false() {
        let registry = AgentRegistry::new();

        let spec_hash = vec![1, 2, 3];
        let status_hash = vec![4, 5, 6];

        let changed = registry.update_hashes("nonexistent", &spec_hash, &status_hash);
        assert!(!changed, "Unknown cluster should not trigger sync");
    }

    // =========================================================================
    // Stale Agent Cleanup Tests
    // =========================================================================

    #[test]
    fn test_cleanup_removes_stale_disconnected_agents() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("stale-cluster");
        registry.register(conn);
        registry.unregister("stale-cluster", 0);

        // Backdate disconnected_at past the threshold
        if let Some(mut agent) = registry.get_mut("stale-cluster") {
            agent.disconnected_at = Some(Instant::now() - Duration::from_secs(7200));
        }

        let removed = registry.cleanup_stale_disconnected(Duration::from_secs(3600));
        assert_eq!(removed, 1);
        assert!(!registry.is_known("stale-cluster"));
    }

    #[test]
    fn test_cleanup_preserves_recently_disconnected() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("recent-cluster");
        registry.register(conn);
        registry.unregister("recent-cluster", 0);

        let removed = registry.cleanup_stale_disconnected(Duration::from_secs(3600));
        assert_eq!(removed, 0);
        assert!(registry.is_known("recent-cluster"));
    }

    #[test]
    fn test_cleanup_preserves_connected_agents() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("active-cluster");
        registry.register(conn);

        let removed = registry.cleanup_stale_disconnected(Duration::from_secs(0));
        assert_eq!(removed, 0);
        assert!(registry.is_connected("active-cluster"));
    }

    #[test]
    fn test_cleanup_also_removes_associated_manifests() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("manifest-cluster");
        registry.register(conn);

        registry.set_unpivot_manifests(
            "manifest-cluster",
            UnpivotManifests {
                capi_manifests: vec![b"data".to_vec()],
                namespace: "ns".to_string(),
            },
        );
        registry.set_pivot_source_manifests(
            "manifest-cluster",
            PivotSourceManifests {
                capi_manifests: vec![b"data".to_vec()],
                namespace: "ns".to_string(),
            },
        );

        registry.unregister("manifest-cluster", 0);
        if let Some(mut agent) = registry.get_mut("manifest-cluster") {
            agent.disconnected_at = Some(Instant::now() - Duration::from_secs(7200));
        }

        registry.cleanup_stale_disconnected(Duration::from_secs(3600));
        assert!(!registry.has_unpivot_manifests("manifest-cluster"));
        assert!(registry
            .take_pivot_source_manifests("manifest-cluster")
            .is_none());
    }

    #[test]
    fn test_unregister_sets_disconnected_at() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("cluster-a");
        registry.register(conn);

        // Initially no disconnected_at
        {
            let agent = registry.get("cluster-a").unwrap();
            assert!(agent.disconnected_at.is_none());
        }

        registry.unregister("cluster-a", 0);

        let agent = registry.get("cluster-a").unwrap();
        assert!(agent.disconnected_at.is_some());
    }
}
