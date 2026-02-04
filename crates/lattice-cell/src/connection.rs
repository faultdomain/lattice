//! Agent connection tracking
//!
//! Manages the registry of connected agents and their state.

use std::sync::Arc;

use dashmap::DashMap;
use lattice_proto::{AgentState, CellCommand, ExecData, KubernetesResponse};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

// Re-export from lattice_move to avoid duplicate type definitions
pub use lattice_move::{BatchAck, CompleteAck};

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
    pub capi_ready: bool,
    /// Whether pivot has completed successfully
    pub pivot_complete: bool,
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

    /// Check if agent is ready for pivot
    ///
    /// Agent must be in a valid state AND have CAPI installed.
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
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// The agent's channel is closed (disconnected)
    #[error("agent channel closed")]
    ChannelClosed,
}

/// CAPI manifests received from child during unpivot
#[derive(Clone, Debug, Default)]
pub struct UnpivotManifests {
    /// CAPI manifests exported via clusterctl move --to-directory
    pub capi_manifests: Vec<Vec<u8>>,
    /// Namespace to import into
    pub namespace: String,
}

/// CAPI manifests exported during pivot (deleted after MoveCompleteAck)
#[derive(Clone, Debug, Default)]
pub struct PivotSourceManifests {
    /// CAPI manifests exported via clusterctl move --to-directory
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

/// Registry of connected agents
///
/// Thread-safe registry using DashMap for concurrent access.
pub struct AgentRegistry {
    agents: DashMap<String, AgentConnection>,
    unpivot_manifests: DashMap<String, UnpivotManifests>,
    /// CAPI manifests exported during pivot (deleted after MoveCompleteAck)
    pivot_source_manifests: DashMap<String, PivotSourceManifests>,
    /// Clusters with teardown in progress (prevents concurrent teardown spawns)
    teardown_in_progress: DashMap<String, ()>,
    /// Pending batch acks keyed by request_id (CellCommand.command_id)
    pending_batch_acks: DashMap<String, oneshot::Sender<BatchAck>>,
    /// Pending complete acks keyed by request_id (CellCommand.command_id)
    pending_complete_acks: DashMap<String, oneshot::Sender<CompleteAck>>,
    /// Pending K8s API proxy responses keyed by request_id
    /// Uses mpsc::Sender to support streaming responses (watches)
    pending_k8s_responses: DashMap<String, K8sResponseSender>,
    /// Pending exec data responses keyed by request_id
    /// Routes stdout/stderr from agent exec sessions to proxy handlers
    pending_exec_data: DashMap<String, ExecDataSender>,
    /// Proxy configuration for kubeconfig patching
    proxy_config: std::sync::RwLock<Option<KubeconfigProxyConfig>>,
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self {
            agents: DashMap::new(),
            unpivot_manifests: DashMap::new(),
            pivot_source_manifests: DashMap::new(),
            teardown_in_progress: DashMap::new(),
            pending_batch_acks: DashMap::new(),
            pending_complete_acks: DashMap::new(),
            pending_k8s_responses: DashMap::new(),
            pending_exec_data: DashMap::new(),
            proxy_config: std::sync::RwLock::new(None),
        }
    }
}

impl AgentRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the proxy configuration for kubeconfig patching
    pub fn set_proxy_config(&self, config: KubeconfigProxyConfig) {
        if let Ok(mut guard) = self.proxy_config.write() {
            *guard = Some(config);
        }
    }

    /// Get the proxy configuration
    pub fn get_proxy_config(&self) -> Option<KubeconfigProxyConfig> {
        self.proxy_config.read().ok().and_then(|g| g.clone())
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
            // Clear teardown guard when agent disconnects
            self.teardown_in_progress.remove(cluster_name);
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
    pub fn start_teardown(&self, cluster_name: &str) -> bool {
        if self.teardown_in_progress.contains_key(cluster_name) {
            false
        } else {
            self.teardown_in_progress
                .insert(cluster_name.to_string(), ());
            true
        }
    }

    /// Clear teardown in progress for a cluster
    pub fn finish_teardown(&self, cluster_name: &str) {
        self.teardown_in_progress.remove(cluster_name);
    }

    // =========================================================================
    // Pending acknowledgment tracking (request-response correlation)
    // =========================================================================

    /// Register a pending batch ack channel
    ///
    /// The request_id should be the CellCommand.command_id.
    pub fn register_pending_batch_ack(&self, request_id: &str, sender: oneshot::Sender<BatchAck>) {
        self.pending_batch_acks
            .insert(request_id.to_string(), sender);
        debug!(request_id = %request_id, "Registered pending batch ack");
    }

    /// Take the pending batch ack sender
    pub fn take_pending_batch_ack(&self, request_id: &str) -> Option<oneshot::Sender<BatchAck>> {
        self.pending_batch_acks
            .remove(request_id)
            .map(|(_, sender)| sender)
    }

    /// Register a pending complete ack channel
    pub fn register_pending_complete_ack(
        &self,
        request_id: &str,
        sender: oneshot::Sender<CompleteAck>,
    ) {
        self.pending_complete_acks
            .insert(request_id.to_string(), sender);
        debug!(request_id = %request_id, "Registered pending complete ack");
    }

    /// Take the pending complete ack sender
    pub fn take_pending_complete_ack(
        &self,
        request_id: &str,
    ) -> Option<oneshot::Sender<CompleteAck>> {
        self.pending_complete_acks
            .remove(request_id)
            .map(|(_, sender)| sender)
    }

    // =========================================================================
    // K8s API Proxy response tracking
    // =========================================================================

    /// Register a pending K8s API response channel
    ///
    /// The request_id should be the KubernetesRequest.request_id.
    /// Uses mpsc::Sender to support streaming responses (watches).
    pub fn register_pending_k8s_response(&self, request_id: &str, sender: K8sResponseSender) {
        self.pending_k8s_responses
            .insert(request_id.to_string(), sender);
        debug!(request_id = %request_id, "Registered pending K8s API response");
    }

    /// Get the pending K8s response sender (does not remove)
    ///
    /// Returns a clone of the sender for streaming responses.
    pub fn get_pending_k8s_response(&self, request_id: &str) -> Option<K8sResponseSender> {
        self.pending_k8s_responses
            .get(request_id)
            .map(|r| r.clone())
    }

    /// Remove and return the pending K8s response sender
    ///
    /// Use this when the stream ends (stream_end=true) or for single responses.
    pub fn take_pending_k8s_response(&self, request_id: &str) -> Option<K8sResponseSender> {
        self.pending_k8s_responses
            .remove(request_id)
            .map(|(_, sender)| sender)
    }

    /// Check if a K8s API request is pending
    pub fn has_pending_k8s_response(&self, request_id: &str) -> bool {
        self.pending_k8s_responses.contains_key(request_id)
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
        self.pending_exec_data.get(request_id).map(|r| r.clone())
    }

    /// Remove and return the pending exec data sender
    ///
    /// Use this when the stream ends or on cancellation.
    pub fn take_pending_exec_data(&self, request_id: &str) -> Option<ExecDataSender> {
        self.pending_exec_data
            .remove(request_id)
            .map(|(_, sender)| sender)
    }

    /// Check if an exec session is pending
    pub fn has_pending_exec_data(&self, request_id: &str) -> bool {
        self.pending_exec_data.contains_key(request_id)
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
        registry.unregister("test-cluster");

        assert!(!registry.is_connected("test-cluster"));
        assert!(registry.is_empty());
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

        conn.state = AgentState::Failed;
        assert!(conn.is_ready_for_pivot());

        // Invalid states for pivot
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

        registry.register_pending_k8s_response("k8s-req-123", tx);
        assert!(registry.has_pending_k8s_response("k8s-req-123"));

        // Get sender and send a response
        let sender = registry
            .get_pending_k8s_response("k8s-req-123")
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

        registry.register_pending_k8s_response("watch-123", tx);

        // Send multiple streaming responses
        for i in 0..3 {
            let sender = registry
                .get_pending_k8s_response("watch-123")
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
        let _ = registry.take_pending_k8s_response("watch-123");
        assert!(!registry.has_pending_k8s_response("watch-123"));

        // Verify we received all responses
        for i in 0..3 {
            let received = rx.recv().await.expect("should receive response");
            assert_eq!(received.stream_end, i == 2);
        }
    }

    #[test]
    fn test_pending_k8s_response_take_nonexistent() {
        let registry = AgentRegistry::new();
        assert!(registry.take_pending_k8s_response("nonexistent").is_none());
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
}
