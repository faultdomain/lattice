//! Agent connection tracking
//!
//! Manages the registry of connected agents and their state.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::proto::{AgentState, CellCommand, KubeProxyRequest, KubeProxyResponse};

/// Represents a connected agent
pub struct AgentConnection {
    /// Cluster name this agent manages
    pub cluster_name: String,
    /// Agent version
    pub agent_version: String,
    /// Kubernetes version on the cluster
    pub kubernetes_version: String,
    /// Current agent state
    pub state: AgentState,
    /// Channel to send commands to this agent
    pub command_tx: mpsc::Sender<CellCommand>,
    /// Whether CAPI is installed and ready on this cluster
    ///
    /// Set to true when agent reports BootstrapComplete with capi_ready=true.
    /// This must be true before pivot can proceed, since clusterctl move
    /// requires CAPI to be installed on the target cluster.
    pub capi_ready: bool,
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

    /// Check if agent is ready for pivot
    ///
    /// Agent must be in a valid state AND have CAPI installed.
    /// CAPI is required because clusterctl move needs CAPI CRDs on the target.
    /// Failed state is included to allow retry after pivot failure.
    pub fn is_ready_for_pivot(&self) -> bool {
        let valid_state = matches!(
            self.state,
            AgentState::Provisioning
                | AgentState::Ready
                | AgentState::Degraded
                | AgentState::Failed
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// The agent's channel is closed (disconnected)
    ChannelClosed,
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::ChannelClosed => write!(f, "agent channel closed"),
        }
    }
}

impl std::error::Error for SendError {}

/// Post-pivot manifests to send to an agent after PivotComplete
#[derive(Clone, Debug, Default)]
pub struct PostPivotManifests {
    /// LatticeCluster CRD definition YAML
    pub crd_yaml: Option<String>,
    /// LatticeCluster resource YAML (the cluster's spec)
    pub cluster_yaml: Option<String>,
    /// Flux manifests (base controllers + GitRepository + Kustomization + credential Secret)
    pub flux_manifests: Vec<String>,
    /// CiliumNetworkPolicy for the operator (applied after Cilium CRDs exist)
    pub network_policy_yaml: Option<String>,
}

/// Sender for streaming proxy responses
pub type ProxyResponseSender = mpsc::Sender<KubeProxyResponse>;

/// Proxy channel state for a single cluster
///
/// Holds the channels needed to proxy K8s API requests to an agent.
/// Supports streaming responses - multiple response chunks per request.
pub struct ProxyChannels {
    /// Channel to send proxy requests to the agent
    pub request_tx: mpsc::Sender<KubeProxyRequest>,
    /// Pending response senders keyed by request ID (mpsc for streaming)
    pub pending: Arc<RwLock<HashMap<String, ProxyResponseSender>>>,
    /// Counter for generating unique request IDs
    request_counter: AtomicU64,
}

impl ProxyChannels {
    /// Create new proxy channels
    pub fn new(request_tx: mpsc::Sender<KubeProxyRequest>) -> Self {
        Self {
            request_tx,
            pending: Arc::new(RwLock::new(HashMap::new())),
            request_counter: AtomicU64::new(0),
        }
    }

    /// Generate a unique request ID for this cluster
    pub fn next_request_id(&self, cluster_name: &str) -> String {
        let id = self.request_counter.fetch_add(1, Ordering::SeqCst);
        format!("{}-central-{}", cluster_name, id)
    }

    /// Register a pending request with its response sender
    pub async fn register_pending(&self, request_id: String, sender: ProxyResponseSender) {
        let mut pending = self.pending.write().await;
        pending.insert(request_id, sender);
    }

    /// Remove a pending request (e.g., on timeout or completion)
    pub async fn remove_pending(&self, request_id: &str) {
        let mut pending = self.pending.write().await;
        pending.remove(request_id);
    }

    /// Handle a response chunk from the agent
    ///
    /// For streaming responses, multiple chunks may arrive with the same request_id.
    /// The sender is kept until is_final=true or the channel is closed.
    pub async fn handle_response(&self, response: KubeProxyResponse) {
        let request_id = response.request_id.clone();
        let is_final = response.is_final || !response.is_streaming;

        let sender = {
            let mut pending = self.pending.write().await;
            if is_final {
                pending.remove(&request_id)
            } else {
                pending.get(&request_id).cloned()
            }
        };

        if let Some(tx) = sender {
            if tx.send(response).await.is_err() {
                debug!(request_id = %request_id, "Response channel closed");
                // Clean up if send failed
                let mut pending = self.pending.write().await;
                pending.remove(&request_id);
            }
        } else {
            debug!(request_id = %request_id, "No pending request for response");
        }
    }
}

/// Registry of connected agents
///
/// Thread-safe registry using DashMap for concurrent access from
/// multiple gRPC handlers.
#[derive(Default)]
pub struct AgentRegistry {
    agents: DashMap<String, AgentConnection>,
    /// Manifests to send to agents after PivotComplete
    post_pivot_manifests: DashMap<String, PostPivotManifests>,
    /// Proxy channels for each cluster (for central proxy)
    proxy_channels: DashMap<String, Arc<ProxyChannels>>,
    /// CAPI manifests received from agents during unpivot
    unpivot_manifests: DashMap<String, Vec<Vec<u8>>>,
}

impl AgentRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            agents: DashMap::new(),
            post_pivot_manifests: DashMap::new(),
            proxy_channels: DashMap::new(),
            unpivot_manifests: DashMap::new(),
        }
    }

    /// Register proxy channels for a cluster
    ///
    /// Called when an agent's proxy stream connects to store the channels
    /// needed for the central proxy to route requests.
    pub fn register_proxy_channels(&self, cluster_name: &str, channels: Arc<ProxyChannels>) {
        info!(cluster = %cluster_name, "Proxy channels registered");
        self.proxy_channels
            .insert(cluster_name.to_string(), channels);
    }

    /// Get proxy channels for a cluster
    pub fn get_proxy_channels(&self, cluster_name: &str) -> Option<Arc<ProxyChannels>> {
        self.proxy_channels.get(cluster_name).map(|r| r.clone())
    }

    /// Remove proxy channels for a cluster
    pub fn remove_proxy_channels(&self, cluster_name: &str) {
        if self.proxy_channels.remove(cluster_name).is_some() {
            info!(cluster = %cluster_name, "Proxy channels removed");
        }
    }

    /// Register a new agent connection
    pub fn register(&self, connection: AgentConnection) {
        let cluster_name = connection.cluster_name.clone();
        info!(cluster = %cluster_name, "Agent registered");
        self.agents.insert(cluster_name, connection);
    }

    /// Unregister an agent
    pub fn unregister(&self, cluster_name: &str) {
        if self.agents.remove(cluster_name).is_some() {
            info!(cluster = %cluster_name, "Agent unregistered");
        }
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

    /// Check if an agent is connected
    pub fn is_connected(&self, cluster_name: &str) -> bool {
        self.agents.contains_key(cluster_name)
    }

    /// Get the number of connected agents
    pub fn len(&self) -> usize {
        self.agents.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    /// List all connected cluster names
    pub fn list_clusters(&self) -> Vec<String> {
        self.agents.iter().map(|r| r.key().clone()).collect()
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
    ///
    /// Called when agent reports BootstrapComplete with capi_ready flag.
    /// This must be true before pivot can proceed.
    pub fn set_capi_ready(&self, cluster_name: &str, ready: bool) {
        if let Some(mut agent) = self.agents.get_mut(cluster_name) {
            info!(cluster = %cluster_name, capi_ready = ready, "Agent CAPI status updated");
            agent.set_capi_ready(ready);
        } else {
            warn!(cluster = %cluster_name, "Attempted to set CAPI ready for unknown agent");
        }
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

    /// Store manifests to send after pivot completes
    ///
    /// These manifests (LatticeCluster CRD and resource) will be sent
    /// to the agent via ApplyManifestsCommand after PivotComplete is received.
    pub fn set_post_pivot_manifests(&self, cluster_name: &str, manifests: PostPivotManifests) {
        info!(cluster = %cluster_name, "Stored post-pivot manifests");
        self.post_pivot_manifests
            .insert(cluster_name.to_string(), manifests);
    }

    /// Get and remove post-pivot manifests for a cluster
    ///
    /// Returns None if no manifests were stored or if they've already been consumed.
    pub fn take_post_pivot_manifests(&self, cluster_name: &str) -> Option<PostPivotManifests> {
        self.post_pivot_manifests
            .remove(cluster_name)
            .map(|(_, m)| m)
    }

    /// Check if post-pivot manifests are stored for a cluster
    pub fn has_post_pivot_manifests(&self, cluster_name: &str) -> bool {
        self.post_pivot_manifests.contains_key(cluster_name)
    }

    /// Store CAPI manifests received during unpivot
    ///
    /// These manifests need to be applied to this (parent) cluster so CAPI
    /// can properly delete the infrastructure when the child terminates.
    pub fn set_unpivot_manifests(&self, cluster_name: &str, manifests: Vec<Vec<u8>>) {
        info!(
            cluster = %cluster_name,
            count = manifests.len(),
            "Storing unpivot manifests"
        );
        self.unpivot_manifests
            .insert(cluster_name.to_string(), manifests);
    }

    /// Get and remove unpivot manifests for a cluster
    ///
    /// Returns None if no manifests were stored or if they've already been consumed.
    pub fn take_unpivot_manifests(&self, cluster_name: &str) -> Option<Vec<Vec<u8>>> {
        self.unpivot_manifests.remove(cluster_name).map(|(_, m)| m)
    }

    /// Check if unpivot manifests are stored for a cluster
    pub fn has_unpivot_manifests(&self, cluster_name: &str) -> bool {
        self.unpivot_manifests.contains_key(cluster_name)
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
        assert!(registry.is_connected("test-cluster"));

        registry.unregister("test-cluster");
        assert!(!registry.is_connected("test-cluster"));
        assert!(registry.is_empty());
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
    fn test_registry_update_state() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("test-cluster");

        registry.register(conn);
        registry.update_state("test-cluster", AgentState::Ready);

        let agent = registry.get("test-cluster").unwrap();
        assert_eq!(agent.state, AgentState::Ready);
    }

    #[test]
    fn test_connection_is_ready_for_pivot() {
        let (mut conn, _rx) = create_test_connection("test");

        // Without CAPI ready, should never be ready for pivot
        conn.state = AgentState::Provisioning;
        assert!(
            !conn.is_ready_for_pivot(),
            "should not be ready without CAPI"
        );

        // With CAPI ready, valid states allow pivot
        conn.capi_ready = true;

        conn.state = AgentState::Provisioning;
        assert!(conn.is_ready_for_pivot());

        conn.state = AgentState::Ready;
        assert!(conn.is_ready_for_pivot());

        conn.state = AgentState::Pivoting;
        assert!(!conn.is_ready_for_pivot());

        // Failed state allows retry
        conn.state = AgentState::Failed;
        assert!(conn.is_ready_for_pivot());
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
            .unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.command_id, "cmd-1");
    }

    #[tokio::test]
    async fn test_send_command_to_unknown_agent() {
        let registry = AgentRegistry::new();

        let command = CellCommand {
            command_id: "cmd-1".to_string(),
            command: None,
        };

        let result = registry.send_command("unknown", command).await;
        assert!(matches!(result, Err(SendError::ChannelClosed)));
    }

    // Story: Agent lifecycle - from connection to disconnect
    //
    // This test demonstrates the full lifecycle of an agent connection:
    // 1. Agent connects and registers with the cell
    // 2. Agent starts in Provisioning state
    // 3. Agent completes bootstrap and transitions to Ready
    // 4. Agent can receive commands and proxy requests
    // 5. Agent disconnects (channel closed)
    #[tokio::test]
    async fn story_agent_lifecycle_connect_to_disconnect() {
        let registry = AgentRegistry::new();

        // Act 1: Agent connects and registers
        let (conn, mut cmd_rx) = create_test_connection("workload-cluster-1");
        assert_eq!(conn.state, AgentState::Provisioning);
        registry.register(conn);
        assert!(registry.is_connected("workload-cluster-1"));
        assert_eq!(registry.len(), 1);

        // Act 2: Agent transitions through states during bootstrap and CAPI becomes ready
        registry.update_state("workload-cluster-1", AgentState::Ready);
        registry.set_capi_ready("workload-cluster-1", true);
        {
            let agent = registry.get("workload-cluster-1").unwrap();
            assert_eq!(agent.state, AgentState::Ready);
            assert!(agent.is_ready_for_pivot());
        }

        // Act 3: Cell sends a pivot command to the agent
        let pivot_command = CellCommand {
            command_id: "pivot-001".to_string(),
            command: None, // Would contain pivot payload
        };
        registry
            .send_command("workload-cluster-1", pivot_command)
            .await
            .unwrap();

        // Agent receives the command
        let received = cmd_rx.recv().await.unwrap();
        assert_eq!(received.command_id, "pivot-001");

        // Act 4: Agent begins pivoting
        registry.update_state("workload-cluster-1", AgentState::Pivoting);
        {
            let agent = registry.get("workload-cluster-1").unwrap();
            assert!(!agent.is_ready_for_pivot()); // Can't pivot while pivoting
        }

        // Act 5: Agent disconnects (simulated by dropping receiver)
        drop(cmd_rx);

        // Sending to disconnected agent fails gracefully
        let result = registry
            .send_command(
                "workload-cluster-1",
                CellCommand {
                    command_id: "should-fail".to_string(),
                    command: None,
                },
            )
            .await;
        assert!(matches!(result, Err(SendError::ChannelClosed)));

        // Act 6: Cleanup - unregister the agent
        registry.unregister("workload-cluster-1");
        assert!(!registry.is_connected("workload-cluster-1"));
        assert!(registry.is_empty());
    }

    // Story: Multiple clusters connecting to a cell
    //
    // In production, a management cluster (cell) manages many workload clusters.
    // This test shows how multiple agents register and receive independent commands.
    #[tokio::test]
    async fn story_cell_manages_multiple_clusters() {
        let registry = AgentRegistry::new();

        // Three workload clusters connect
        let (conn_prod, mut rx_prod) = create_test_connection("prod-us-west");
        let (conn_staging, mut rx_staging) = create_test_connection("staging-us-east");
        let (conn_dev, _rx_dev) = create_test_connection("dev-local");

        registry.register(conn_prod);
        registry.register(conn_staging);
        registry.register(conn_dev);

        // Verify all clusters are tracked
        let clusters = registry.list_clusters();
        assert_eq!(clusters.len(), 3);
        assert!(clusters.contains(&"prod-us-west".to_string()));
        assert!(clusters.contains(&"staging-us-east".to_string()));
        assert!(clusters.contains(&"dev-local".to_string()));

        // Each cluster can transition independently
        registry.update_state("prod-us-west", AgentState::Ready);
        registry.update_state("staging-us-east", AgentState::Pivoting);
        // dev-local stays in Provisioning

        assert_eq!(
            registry.get("prod-us-west").unwrap().state,
            AgentState::Ready
        );
        assert_eq!(
            registry.get("staging-us-east").unwrap().state,
            AgentState::Pivoting
        );
        assert_eq!(
            registry.get("dev-local").unwrap().state,
            AgentState::Provisioning
        );

        // Send targeted commands to specific clusters
        registry
            .send_command(
                "prod-us-west",
                CellCommand {
                    command_id: "reconcile-prod".to_string(),
                    command: None,
                },
            )
            .await
            .unwrap();

        registry
            .send_command(
                "staging-us-east",
                CellCommand {
                    command_id: "pivot-staging".to_string(),
                    command: None,
                },
            )
            .await
            .unwrap();

        // Each cluster receives only its command
        let prod_cmd = rx_prod.recv().await.unwrap();
        assert_eq!(prod_cmd.command_id, "reconcile-prod");

        let staging_cmd = rx_staging.recv().await.unwrap();
        assert_eq!(staging_cmd.command_id, "pivot-staging");

        // Sending to unknown cluster fails
        let result = registry
            .send_command(
                "nonexistent",
                CellCommand {
                    command_id: "x".to_string(),
                    command: None,
                },
            )
            .await;
        assert!(matches!(result, Err(SendError::ChannelClosed)));
    }

    // Story: Graceful handling of edge cases and errors
    //
    // The registry must handle edge cases without panicking:
    // - Operations on unknown clusters
    // - State updates during transitions
    #[test]
    fn story_registry_handles_edge_cases_gracefully() {
        let registry = AgentRegistry::new();

        // Operating on empty registry
        assert!(registry.is_empty());
        assert!(registry.get("nonexistent").is_none());
        assert!(registry.get_mut("nonexistent").is_none());

        // These should NOT panic - just log and continue
        registry.update_state("ghost-cluster", AgentState::Ready);
        registry.unregister("ghost-cluster");

        // Registry still works after edge cases
        let (conn, _rx) = create_test_connection("real-cluster");
        registry.register(conn);
        assert_eq!(registry.len(), 1);
    }

    // Story: Agent state transitions follow valid paths
    //
    // Agents transition through states: Provisioning -> Ready/Degraded/Failed
    // The is_ready_for_pivot check guards against invalid pivot attempts.
    // Pivot also requires CAPI to be installed and ready.
    #[test]
    fn story_agent_state_transitions() {
        let (mut conn, _rx) = create_test_connection("transitioning-cluster");

        // Initial state after connection - no CAPI yet
        assert_eq!(conn.state, AgentState::Provisioning);
        assert!(!conn.is_ready_for_pivot(), "Cannot pivot without CAPI");

        // CAPI is installed and ready
        conn.capi_ready = true;
        assert!(
            conn.is_ready_for_pivot(),
            "Can pivot from Provisioning with CAPI"
        );

        // Successfully bootstrapped
        conn.set_state(AgentState::Ready);
        assert!(conn.is_ready_for_pivot(), "Can pivot from Ready");

        // Cluster having issues but still operational
        conn.set_state(AgentState::Degraded);
        assert!(
            conn.is_ready_for_pivot(),
            "Can pivot from Degraded (recovery)"
        );

        // Active pivot in progress
        conn.set_state(AgentState::Pivoting);
        assert!(!conn.is_ready_for_pivot(), "Cannot double-pivot");

        // Failed state allows retry
        conn.set_state(AgentState::Failed);
        assert!(conn.is_ready_for_pivot(), "Can retry pivot after failure");
    }

    // Story: Direct agent communication for real-time operations
    #[tokio::test]
    async fn story_direct_agent_communication() {
        let (conn, mut rx) = create_test_connection("direct-comm-cluster");

        // Direct command send
        conn.send_command(CellCommand {
            command_id: "health-check".to_string(),
            command: None,
        })
        .await
        .unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.command_id, "health-check");

        // When agent disconnects, sends fail
        drop(rx);
        let result = conn
            .send_command(CellCommand {
                command_id: "will-fail".to_string(),
                command: None,
            })
            .await;
        assert!(matches!(result, Err(SendError::ChannelClosed)));
    }

    // Story: Registry mutable access for state updates
    #[test]
    fn story_registry_mutable_access() {
        let registry = AgentRegistry::new();
        let (conn, _rx) = create_test_connection("mutable-cluster");
        registry.register(conn);

        // Get mutable access to update state
        if let Some(mut agent) = registry.get_mut("mutable-cluster") {
            agent.set_state(AgentState::Ready);
        }

        // Verify the update persisted
        let agent = registry.get("mutable-cluster").unwrap();
        assert_eq!(agent.state, AgentState::Ready);
    }

    #[test]
    fn test_registry_default() {
        let registry = AgentRegistry::default();
        assert!(registry.is_empty());
    }

    // ==========================================================================
    // ProxyChannels Tests
    // ==========================================================================

    #[test]
    fn test_proxy_channels_creation() {
        let (tx, _rx) = mpsc::channel(32);
        let channels = ProxyChannels::new(tx);
        assert!(channels.pending.try_read().is_ok());
    }

    #[test]
    fn test_proxy_channels_next_request_id() {
        let (tx, _rx) = mpsc::channel(32);
        let channels = ProxyChannels::new(tx);

        let id1 = channels.next_request_id("my-cluster");
        let id2 = channels.next_request_id("my-cluster");
        let id3 = channels.next_request_id("my-cluster");

        assert!(id1.contains("my-cluster"));
        assert!(id1.contains("-central-"));
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
    }

    #[test]
    fn test_proxy_channels_request_id_format() {
        let (tx, _rx) = mpsc::channel(32);
        let channels = ProxyChannels::new(tx);

        let id = channels.next_request_id("test-cluster");
        // Format: "{cluster_name}-central-{counter}"
        assert!(id.starts_with("test-cluster-central-"));
    }

    #[tokio::test]
    async fn test_proxy_channels_handle_response() {
        use crate::proto::KubeProxyResponse;

        let (tx, _rx) = mpsc::channel(32);
        let channels = ProxyChannels::new(tx);

        // Create a pending request with mpsc channel for streaming
        let request_id = channels.next_request_id("test");
        let (response_tx, mut response_rx) = mpsc::channel(16);

        channels
            .register_pending(request_id.clone(), response_tx)
            .await;

        // Handle a non-streaming response (is_final implied)
        channels
            .handle_response(KubeProxyResponse {
                request_id: request_id.clone(),
                status_code: 200,
                headers: vec![],
                body: b"test".to_vec(),
                error: String::new(),
                is_streaming: false,
                is_final: false,
            })
            .await;

        // Response should be received
        let response = response_rx.recv().await.expect("should receive response");
        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, b"test");
    }

    #[tokio::test]
    async fn test_proxy_channels_streaming_response() {
        use crate::proto::KubeProxyResponse;

        let (tx, _rx) = mpsc::channel(32);
        let channels = ProxyChannels::new(tx);

        let request_id = channels.next_request_id("test");
        let (response_tx, mut response_rx) = mpsc::channel(16);

        channels
            .register_pending(request_id.clone(), response_tx)
            .await;

        // First chunk (streaming, not final)
        channels
            .handle_response(KubeProxyResponse {
                request_id: request_id.clone(),
                status_code: 200,
                headers: vec![],
                body: b"chunk1".to_vec(),
                error: String::new(),
                is_streaming: true,
                is_final: false,
            })
            .await;

        // Second chunk (final)
        channels
            .handle_response(KubeProxyResponse {
                request_id: request_id.clone(),
                status_code: 0,
                headers: vec![],
                body: b"chunk2".to_vec(),
                error: String::new(),
                is_streaming: true,
                is_final: true,
            })
            .await;

        // Both chunks should be received
        let chunk1 = response_rx.recv().await.expect("should receive chunk1");
        assert_eq!(chunk1.body, b"chunk1");
        assert!(!chunk1.is_final);

        let chunk2 = response_rx.recv().await.expect("should receive chunk2");
        assert_eq!(chunk2.body, b"chunk2");
        assert!(chunk2.is_final);
    }

    #[tokio::test]
    async fn test_proxy_channels_handle_response_unknown_id() {
        use crate::proto::KubeProxyResponse;

        let (tx, _rx) = mpsc::channel(32);
        let channels = ProxyChannels::new(tx);

        // Handle response for unknown request - should not panic
        channels
            .handle_response(KubeProxyResponse {
                request_id: "unknown-id".to_string(),
                status_code: 200,
                headers: vec![],
                body: vec![],
                error: String::new(),
                is_streaming: false,
                is_final: false,
            })
            .await;
        // No assertion needed - just verify it doesn't panic
    }

    #[test]
    fn test_registry_proxy_channels() {
        let registry = AgentRegistry::new();
        let (tx, _rx) = mpsc::channel(32);
        let channels = std::sync::Arc::new(ProxyChannels::new(tx));

        // Initially no channels
        assert!(registry.get_proxy_channels("my-cluster").is_none());

        // Register channels
        registry.register_proxy_channels("my-cluster", channels.clone());
        assert!(registry.get_proxy_channels("my-cluster").is_some());

        // Remove channels
        registry.remove_proxy_channels("my-cluster");
        assert!(registry.get_proxy_channels("my-cluster").is_none());
    }

    #[test]
    fn test_registry_remove_nonexistent_proxy_channels() {
        let registry = AgentRegistry::new();
        // Should not panic
        registry.remove_proxy_channels("nonexistent");
    }
}
