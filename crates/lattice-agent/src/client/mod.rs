//! gRPC client for agent (workload cluster)
//!
//! Connects to the parent cell and maintains persistent streams for
//! control messages.
//!
//! # Certificate Flow
//!
//! Before connecting with mTLS, the agent must obtain a signed certificate:
//! 1. Generate keypair locally (private key never leaves agent)
//! 2. Submit CSR to cell's HTTP endpoint (non-mTLS)
//! 3. Receive signed certificate from cell
//! 4. Use certificate for mTLS gRPC connection

mod capi;
pub mod config;
mod connection;
mod deletion;

pub use config::{AgentClientConfig, AgentCredentials, CertificateError, ClientError, ClientState};

use std::sync::Arc;
use std::time::Instant;

use moka::future::Cache;
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::info;

use crate::commands::StoredExecSession;
use crate::kube_client::{InClusterClientProvider, KubeClientProvider};
use crate::watch::WatchRegistry;
use crate::{SharedExecForwarder, SharedK8sForwarder};
use lattice_common::{CsrRequest, CsrResponse};
use lattice_infra::pki::AgentCertRequest;
use lattice_proto::{
    agent_message::Payload, AgentMessage, AgentReady, AgentState, BootstrapComplete,
};

use config::{CSR_CONNECT_TIMEOUT, CSR_REQUEST_TIMEOUT, EXEC_SESSION_CACHE_TTL};

/// Agent gRPC client
///
/// Maintains persistent connection to the parent cell and handles
/// bidirectional communication.
pub struct AgentClient {
    config: AgentClientConfig,
    /// Environment config for K8s service discovery
    env_config: Arc<dyn crate::config::K8sEnvConfig>,
    /// Provider for creating K8s clients
    kube_provider: Arc<dyn KubeClientProvider>,
    state: Arc<RwLock<ClientState>>,
    agent_state: Arc<RwLock<AgentState>>,
    /// Sender for outgoing messages
    message_tx: Option<mpsc::Sender<AgentMessage>>,
    /// Shutdown signal
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Time when the agent was started (for uptime tracking)
    start_time: Instant,
    /// Handle to heartbeat task for cleanup
    heartbeat_handle: Option<tokio::task::JoinHandle<()>>,
    /// Handle to command handler task for cleanup
    command_handler_handle: Option<tokio::task::JoinHandle<()>>,
    /// Handle to deletion watcher task for unpivot detection
    deletion_watcher_handle: Option<tokio::task::JoinHandle<()>>,
    /// Handle to subtree watcher task for state bubbling
    subtree_watcher_handle: Option<tokio::task::JoinHandle<()>>,
    /// Registry for tracking active K8s API watches
    watch_registry: Arc<WatchRegistry>,
    /// Registry for tracking active exec sessions
    exec_registry: Arc<crate::exec::ExecRegistry>,
    /// Registry for tracking forwarded exec sessions (to child clusters)
    forwarded_exec_sessions: Arc<Cache<String, StoredExecSession>>,
    /// Optional forwarder for routing K8s requests to child clusters.
    /// When None, requests targeting other clusters return 404.
    forwarder: Option<SharedK8sForwarder>,
    /// Optional forwarder for routing exec requests to child clusters.
    /// When None, exec requests targeting other clusters return an error.
    exec_forwarder: Option<SharedExecForwarder>,
}

/// Builder for AgentClient with fluent configuration
pub struct AgentClientBuilder {
    config: AgentClientConfig,
    env_config: Arc<dyn crate::config::K8sEnvConfig>,
    kube_provider: Arc<dyn KubeClientProvider>,
    forwarder: Option<SharedK8sForwarder>,
    exec_forwarder: Option<SharedExecForwarder>,
}

impl AgentClientBuilder {
    /// Create a new builder with the given configuration
    pub fn new(config: AgentClientConfig) -> Self {
        Self {
            config,
            env_config: Arc::new(crate::config::OsEnvConfig),
            kube_provider: Arc::new(InClusterClientProvider),
            forwarder: None,
            exec_forwarder: None,
        }
    }

    /// Set custom environment configuration (for testing)
    pub fn env_config(mut self, env_config: Arc<dyn crate::config::K8sEnvConfig>) -> Self {
        self.env_config = env_config;
        self
    }

    /// Set custom Kubernetes client provider (for testing)
    pub fn kube_provider(mut self, provider: Arc<dyn KubeClientProvider>) -> Self {
        self.kube_provider = provider;
        self
    }

    /// Set forwarders for hierarchical K8s request routing
    pub fn forwarders(
        mut self,
        k8s_forwarder: SharedK8sForwarder,
        exec_forwarder: SharedExecForwarder,
    ) -> Self {
        self.forwarder = Some(k8s_forwarder);
        self.exec_forwarder = Some(exec_forwarder);
        self
    }

    /// Build the AgentClient
    pub fn build(self) -> AgentClient {
        AgentClient {
            config: self.config,
            env_config: self.env_config,
            kube_provider: self.kube_provider,
            state: Arc::new(RwLock::new(ClientState::Disconnected)),
            agent_state: Arc::new(RwLock::new(AgentState::Provisioning)),
            message_tx: None,
            shutdown_tx: None,
            start_time: Instant::now(),
            heartbeat_handle: None,
            command_handler_handle: None,
            deletion_watcher_handle: None,
            subtree_watcher_handle: None,
            watch_registry: Arc::new(WatchRegistry::new()),
            exec_registry: Arc::new(crate::exec::ExecRegistry::new()),
            forwarded_exec_sessions: Arc::new(
                Cache::builder()
                    .time_to_live(EXEC_SESSION_CACHE_TTL)
                    .max_capacity(1000)
                    .build(),
            ),
            forwarder: self.forwarder,
            exec_forwarder: self.exec_forwarder,
        }
    }
}

impl AgentClient {
    /// Create a new agent client with the given configuration.
    /// Without forwarders, requests targeting other clusters return 404/error.
    pub fn new(config: AgentClientConfig) -> Self {
        AgentClientBuilder::new(config).build()
    }

    /// Create a builder for configuring the agent client
    pub fn builder(config: AgentClientConfig) -> AgentClientBuilder {
        AgentClientBuilder::new(config)
    }

    /// Get the agent uptime in seconds
    pub fn uptime_seconds(&self) -> i64 {
        self.start_time.elapsed().as_secs() as i64
    }

    /// Get the Kubernetes API server endpoint from environment
    fn api_server_endpoint(&self) -> String {
        crate::config::api_server_endpoint(self.env_config.as_ref())
    }

    /// Create a K8s client using the injected provider
    async fn create_client(&self) -> Result<kube::Client, kube::Error> {
        self.kube_provider.create().await
    }

    /// Create a K8s client with logging, using the injected provider
    async fn create_client_logged(&self, purpose: &str) -> Option<kube::Client> {
        crate::kube_client::create_client_logged(self.kube_provider.as_ref(), purpose).await
    }

    /// Request a signed certificate from the cell
    ///
    /// This is the first step in connecting to the cell with mTLS.
    /// The agent generates a keypair locally, sends the CSR to the cell's
    /// HTTP endpoint, and receives a signed certificate.
    ///
    /// # Arguments
    /// * `http_endpoint` - Cell's HTTP endpoint for CSR signing
    /// * `cluster_id` - The cluster ID to include in the certificate
    /// * `ca_cert_pem` - CA certificate PEM for verifying cell's TLS certificate
    ///
    /// # Returns
    /// Agent credentials including the signed certificate, private key, and CA cert
    pub async fn request_certificate(
        http_endpoint: &str,
        cluster_id: &str,
        ca_cert_pem: &str,
    ) -> Result<AgentCredentials, CertificateError> {
        info!(cluster_id = %cluster_id, "Generating keypair and CSR");

        // Generate keypair and CSR locally (private key never leaves agent)
        let cert_request = AgentCertRequest::new(cluster_id)
            .map_err(|e| CertificateError::CsrError(e.to_string()))?;

        let csr_pem = cert_request.csr_pem().to_string();
        let key_pem = zeroize::Zeroizing::new(cert_request.private_key_pem().to_string());

        // Submit CSR to cell
        let url = format!("{}/api/clusters/{}/csr", http_endpoint, cluster_id);
        info!(url = %url, "Submitting CSR to cell");

        // Build HTTP client with CA certificate for TLS verification
        let ca_cert = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())
            .map_err(|e| CertificateError::HttpError(format!("Invalid CA certificate: {}", e)))?;

        let http_client = reqwest::Client::builder()
            .add_root_certificate(ca_cert)
            .connect_timeout(CSR_CONNECT_TIMEOUT)
            .timeout(CSR_REQUEST_TIMEOUT)
            .build()
            .map_err(|e| {
                CertificateError::HttpError(format!("Failed to build HTTP client: {}", e))
            })?;

        let response = http_client
            .post(&url)
            .json(&CsrRequest { csr_pem })
            .send()
            .await
            .map_err(|e| CertificateError::HttpError(format!("{:#}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(CertificateError::HttpError(format!(
                "CSR signing failed: {} - {}",
                status, body
            )));
        }

        let csr_response: CsrResponse = response
            .json()
            .await
            .map_err(|e| CertificateError::InvalidResponse(e.to_string()))?;

        info!(cluster_id = %cluster_id, "Certificate received from cell");

        Ok(AgentCredentials {
            cert_pem: csr_response.certificate_pem,
            key_pem,
            ca_cert_pem: csr_response.ca_certificate_pem,
        })
    }

    /// Get current client state
    pub async fn state(&self) -> ClientState {
        *self.state.read().await
    }

    /// Get current agent state
    pub async fn agent_state(&self) -> AgentState {
        *self.agent_state.read().await
    }

    /// Set agent state
    pub async fn set_agent_state(&self, state: AgentState) {
        *self.agent_state.write().await = state;
    }

    /// Disconnect from the cell and clean up spawned tasks
    ///
    /// Sends shutdown signal to command handler and aborts both spawned tasks.
    /// Sets client state to Disconnected.
    pub async fn disconnect(&mut self) {
        // Send shutdown signal to command handler task
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Abort heartbeat task
        if let Some(handle) = self.heartbeat_handle.take() {
            handle.abort();
        }

        // Abort command handler task (if it didn't exit from shutdown signal)
        if let Some(handle) = self.command_handler_handle.take() {
            handle.abort();
        }

        // Abort deletion watcher task
        if let Some(handle) = self.deletion_watcher_handle.take() {
            handle.abort();
        }

        // Abort subtree watcher task
        if let Some(handle) = self.subtree_watcher_handle.take() {
            handle.abort();
        }

        // Clear message sender
        self.message_tx = None;

        // Update state
        *self.state.write().await = ClientState::Disconnected;
        info!("Agent client disconnected and cleaned up");
    }

    /// Send the ready message to cell
    async fn send_ready(&self) -> Result<(), ClientError> {
        // Get K8s version from in-cluster client
        let k8s_version = if let Some(client) = self.create_client_logged("version check").await {
            match client.apiserver_version().await {
                Ok(info) => format!("v{}.{}", info.major, info.minor),
                Err(_) => "unknown".to_string(),
            }
        } else {
            "unknown".to_string()
        };

        let msg = AgentMessage {
            cluster_name: self.config.cluster_name.clone(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: self.config.agent_version.clone(),
                kubernetes_version: k8s_version,
                state: (*self.agent_state.read().await).into(),
                api_server_endpoint: self.api_server_endpoint(),
                protocol_version: lattice_proto::PROTOCOL_VERSION,
            })),
        };

        self.send_message(msg).await
    }

    /// Send a message to the cell
    async fn send_message(&self, msg: AgentMessage) -> Result<(), ClientError> {
        match &self.message_tx {
            Some(tx) => tx.send(msg).await.map_err(|_| ClientError::ChannelClosed),
            None => Err(ClientError::NotConnected),
        }
    }

    /// Send bootstrap complete notification
    pub async fn send_bootstrap_complete(
        &self,
        capi_ready: bool,
        installed_providers: Vec<String>,
    ) -> Result<(), ClientError> {
        let msg = AgentMessage {
            cluster_name: self.config.cluster_name.clone(),
            payload: Some(Payload::BootstrapComplete(BootstrapComplete {
                capi_ready,
                installed_providers,
            })),
        };

        self.send_message(msg).await
    }
}

impl Drop for AgentClient {
    fn drop(&mut self) {
        // Abort spawned tasks on drop to prevent orphaned tasks
        if let Some(handle) = self.heartbeat_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.command_handler_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.deletion_watcher_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.subtree_watcher_handle.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use lattice_proto::{grpc_max_message_size, Heartbeat};

    #[test]
    fn test_client_creation() {
        let config = AgentClientConfig {
            cluster_name: "test-cluster".to_string(),
            ..Default::default()
        };
        let client = AgentClient::new(config);
        // Client starts disconnected
        assert!(client.message_tx.is_none());
        assert!(client.shutdown_tx.is_none());
    }

    #[tokio::test]
    async fn test_initial_state() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        assert_eq!(client.state().await, ClientState::Disconnected);
        assert_eq!(client.agent_state().await, AgentState::Provisioning);
    }

    #[tokio::test]
    async fn test_set_agent_state() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        client.set_agent_state(AgentState::Ready).await;
        assert_eq!(client.agent_state().await, AgentState::Ready);

        client.set_agent_state(AgentState::Pivoting).await;
        assert_eq!(client.agent_state().await, AgentState::Pivoting);

        client.set_agent_state(AgentState::Failed).await;
        assert_eq!(client.agent_state().await, AgentState::Failed);
    }

    #[tokio::test]
    async fn test_shutdown_without_connection() {
        let config = AgentClientConfig::default();
        let mut client = AgentClient::new(config);

        // Shutdown should be safe even when not connected
        client.disconnect().await;
        assert_eq!(client.state().await, ClientState::Disconnected);
    }

    // Test send methods return errors when not connected
    #[tokio::test]
    async fn test_send_message_not_connected() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        let msg = AgentMessage {
            cluster_name: "test".to_string(),
            payload: None,
        };

        let result = client.send_message(msg).await;
        assert_eq!(result, Err(ClientError::NotConnected));
    }

    #[tokio::test]
    async fn test_send_bootstrap_complete_not_connected() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        let result = client
            .send_bootstrap_complete(true, vec!["docker".to_string()])
            .await;
        assert_eq!(result, Err(ClientError::NotConnected));
    }

    // Test send with connected channel
    #[tokio::test]
    async fn test_send_message_with_channel() {
        let config = AgentClientConfig {
            cluster_name: "test-cluster".to_string(),
            ..Default::default()
        };
        let mut client = AgentClient::new(config);

        // Manually set up message channel
        let (tx, mut rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: None,
        };

        let result = client.send_message(msg).await;
        assert!(result.is_ok());

        // Verify message was received
        let received = rx.recv().await.expect("message should be received");
        assert_eq!(received.cluster_name, "test-cluster");
    }

    #[tokio::test]
    async fn test_send_bootstrap_complete_with_channel() {
        let config = AgentClientConfig {
            cluster_name: "test-cluster".to_string(),
            ..Default::default()
        };
        let mut client = AgentClient::new(config);

        let (tx, mut rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        let result = client
            .send_bootstrap_complete(true, vec!["docker".to_string()])
            .await;
        assert!(result.is_ok());

        let received = rx.recv().await.expect("message should be received");
        match received.payload {
            Some(Payload::BootstrapComplete(bc)) => {
                assert!(bc.capi_ready);
                assert_eq!(bc.installed_providers, vec!["docker"]);
            }
            _ => panic!("Expected BootstrapComplete payload"),
        }
    }

    // Test channel closed scenario
    #[tokio::test]
    async fn test_send_message_channel_closed() {
        let config = AgentClientConfig::default();
        let mut client = AgentClient::new(config);

        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        // Drop receiver to close channel
        drop(rx);

        let msg = AgentMessage {
            cluster_name: "test".to_string(),
            payload: None,
        };

        let result = client.send_message(msg).await;
        assert_eq!(result, Err(ClientError::ChannelClosed));
    }

    // ==========================================================================
    // Story Tests: Agent Connection Flows
    // ==========================================================================

    /// Story: When a new agent is created, it starts in a disconnected state
    #[tokio::test]
    async fn new_agent_starts_disconnected() {
        let config = AgentClientConfig {
            cluster_name: "workload-east-1".to_string(),
            cell_grpc_endpoint: "https://cell.example.com:443".to_string(),
            cell_http_endpoint: "http://cell.example.com:8080".to_string(),
            ..Default::default()
        };

        let client = AgentClient::new(config);

        assert_eq!(client.state().await, ClientState::Disconnected);
        assert_eq!(client.agent_state().await, AgentState::Provisioning);
        assert!(client.message_tx.is_none());
        assert!(client.shutdown_tx.is_none());
    }

    /// Story: Agent progresses through lifecycle states during provisioning
    #[tokio::test]
    async fn agent_state_lifecycle_transitions() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        assert_eq!(client.agent_state().await, AgentState::Provisioning);

        client.set_agent_state(AgentState::Pivoting).await;
        assert_eq!(client.agent_state().await, AgentState::Pivoting);

        client.set_agent_state(AgentState::Ready).await;
        assert_eq!(client.agent_state().await, AgentState::Ready);
    }

    /// Story: When an agent fails to provision, it enters the failed state
    #[tokio::test]
    async fn agent_enters_failed_state_on_error() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        client.set_agent_state(AgentState::Failed).await;
        assert_eq!(client.agent_state().await, AgentState::Failed);
    }

    /// Story: Agent can be in degraded state when issues occur but still operational
    #[tokio::test]
    async fn agent_degraded_state_for_partial_issues() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        client.set_agent_state(AgentState::Degraded).await;
        assert_eq!(client.agent_state().await, AgentState::Degraded);
    }

    // ==========================================================================
    // Story Tests: Message Sending When Connected
    // ==========================================================================

    /// Story: Agent sends bootstrap complete after CAPI providers are installed
    #[tokio::test]
    async fn agent_reports_bootstrap_completion() {
        let config = AgentClientConfig {
            cluster_name: "bootstrap-test".to_string(),
            ..Default::default()
        };
        let mut client = AgentClient::new(config);

        let (tx, mut rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        let result = client
            .send_bootstrap_complete(true, vec!["docker".to_string(), "kubeadm".to_string()])
            .await;
        assert!(result.is_ok());

        let msg = rx.recv().await.expect("message should be received");
        match msg.payload {
            Some(Payload::BootstrapComplete(bc)) => {
                assert!(bc.capi_ready);
                assert_eq!(bc.installed_providers, vec!["docker", "kubeadm"]);
            }
            _ => panic!("Expected BootstrapComplete payload"),
        }
    }

    /// Story: Agent reports partial bootstrap (CAPI not yet ready)
    #[tokio::test]
    async fn agent_reports_partial_bootstrap() {
        let config = AgentClientConfig {
            cluster_name: "partial-bootstrap".to_string(),
            ..Default::default()
        };
        let mut client = AgentClient::new(config);

        let (tx, mut rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        let result = client.send_bootstrap_complete(false, vec![]).await;
        assert!(result.is_ok());

        let msg = rx.recv().await.expect("message should be received");
        match msg.payload {
            Some(Payload::BootstrapComplete(bc)) => {
                assert!(!bc.capi_ready);
                assert!(bc.installed_providers.is_empty());
            }
            _ => panic!("Expected BootstrapComplete payload"),
        }
    }

    // ==========================================================================
    // Story Tests: Error Scenarios
    // ==========================================================================

    /// Story: When agent is not connected, sending messages fails gracefully
    #[tokio::test]
    async fn sending_when_not_connected_returns_error() {
        let config = AgentClientConfig {
            cluster_name: "disconnected-agent".to_string(),
            ..Default::default()
        };
        let client = AgentClient::new(config);

        assert_eq!(
            client.send_bootstrap_complete(true, vec![]).await,
            Err(ClientError::NotConnected)
        );
    }

    /// Story: When the message channel closes unexpectedly, sends return ChannelClosed
    #[tokio::test]
    async fn channel_closure_detected_on_send() {
        let config = AgentClientConfig {
            cluster_name: "channel-closed-test".to_string(),
            ..Default::default()
        };
        let mut client = AgentClient::new(config);

        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        drop(rx);

        assert_eq!(
            client.send_bootstrap_complete(true, vec![]).await,
            Err(ClientError::ChannelClosed)
        );
    }

    // ==========================================================================
    // Story Tests: Client Shutdown
    // ==========================================================================

    /// Story: Agent can shutdown cleanly even when not connected
    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let config = AgentClientConfig::default();
        let mut client = AgentClient::new(config);

        client.disconnect().await;
        assert_eq!(client.state().await, ClientState::Disconnected);

        client.disconnect().await;
        assert_eq!(client.state().await, ClientState::Disconnected);
    }

    /// Story: Agent shutdown signals background tasks to stop
    #[tokio::test]
    async fn shutdown_signals_background_tasks() {
        let config = AgentClientConfig::default();
        let mut client = AgentClient::new(config);

        let (tx, mut rx) = oneshot::channel::<()>();
        client.shutdown_tx = Some(tx);

        client.disconnect().await;

        match rx.try_recv() {
            Ok(()) => {}
            Err(_) => panic!("Shutdown signal should have been sent"),
        }
    }

    // ==========================================================================
    // Story Tests: AgentReady Message Format
    // ==========================================================================

    /// Story: When connected, agent sends ready message with proper format
    #[tokio::test]
    async fn ready_message_includes_agent_info() {
        let config = AgentClientConfig {
            cluster_name: "ready-test-cluster".to_string(),
            agent_version: "1.5.0".to_string(),
            ..Default::default()
        };

        let msg = AgentMessage {
            cluster_name: config.cluster_name.clone(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: config.agent_version.clone(),
                kubernetes_version: "unknown".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: String::new(),
                protocol_version: lattice_proto::PROTOCOL_VERSION,
            })),
        };

        assert_eq!(msg.cluster_name, "ready-test-cluster");
        match msg.payload {
            Some(Payload::Ready(ready)) => {
                assert_eq!(ready.agent_version, "1.5.0");
                assert_eq!(ready.kubernetes_version, "unknown");
                assert_eq!(ready.state, i32::from(AgentState::Provisioning));
                assert!(ready.protocol_version > 0);
            }
            _ => panic!("Expected Ready payload"),
        }
    }

    /// Story: AgentReady state reflects current agent state
    #[tokio::test]
    async fn ready_message_reflects_current_state() {
        let states = [
            AgentState::Provisioning,
            AgentState::Pivoting,
            AgentState::Ready,
            AgentState::Degraded,
            AgentState::Failed,
        ];

        for state in states {
            let msg = AgentMessage {
                cluster_name: "state-test".to_string(),
                payload: Some(Payload::Ready(AgentReady {
                    agent_version: "1.0.0".to_string(),
                    kubernetes_version: "v1.28.0".to_string(),
                    state: state.into(),
                    api_server_endpoint: "https://127.0.0.1:6443".to_string(),
                    protocol_version: lattice_proto::PROTOCOL_VERSION,
                })),
            };

            match msg.payload {
                Some(Payload::Ready(ready)) => {
                    assert_eq!(ready.state, i32::from(state));
                }
                _ => panic!("Expected Ready payload"),
            }
        }
    }

    // ==========================================================================
    // Story Tests: Heartbeat Message Format
    // ==========================================================================

    /// Story: Heartbeat messages include timestamp and state
    #[tokio::test]
    async fn heartbeat_message_format() {
        let timestamp = prost_types::Timestamp::from(std::time::SystemTime::now());

        let msg = AgentMessage {
            cluster_name: "heartbeat-cluster".to_string(),
            payload: Some(Payload::Heartbeat(Heartbeat {
                state: AgentState::Ready.into(),
                timestamp: Some(timestamp),
                uptime_seconds: 3600,
                health: None,
            })),
        };

        match msg.payload {
            Some(Payload::Heartbeat(hb)) => {
                assert_eq!(hb.state, i32::from(AgentState::Ready));
                assert!(hb.timestamp.is_some());
                assert_eq!(hb.uptime_seconds, 3600);
            }
            _ => panic!("Expected Heartbeat payload"),
        }
    }

    // ==========================================================================
    // Story Tests: AgentState Transitions
    // ==========================================================================

    /// Story: AgentState values match proto definitions
    #[test]
    fn agent_state_proto_conversion() {
        assert_eq!(i32::from(AgentState::Unknown), 0);
        assert_eq!(i32::from(AgentState::Provisioning), 1);
        assert_eq!(i32::from(AgentState::Pivoting), 2);
        assert_eq!(i32::from(AgentState::Ready), 3);
        assert_eq!(i32::from(AgentState::Degraded), 4);
        assert_eq!(i32::from(AgentState::Failed), 5);
    }

    // ==========================================================================
    // Story Tests: Concurrent State Access
    // ==========================================================================

    /// Story: Agent state can be accessed concurrently from multiple tasks
    #[tokio::test]
    async fn concurrent_state_access() {
        let config = AgentClientConfig::default();
        let client = Arc::new(AgentClient::new(config));

        let mut handles = vec![];
        for _ in 0..10 {
            let client = Arc::clone(&client);
            handles.push(tokio::spawn(async move {
                for _ in 0..100 {
                    let _ = client.state().await;
                    let _ = client.agent_state().await;
                }
            }));
        }

        for handle in handles {
            handle.await.expect("task should complete");
        }
    }

    /// Story: Agent state can be written while being read
    #[tokio::test]
    async fn concurrent_state_read_write() {
        let config = AgentClientConfig::default();
        let client = Arc::new(AgentClient::new(config));

        let writer_client = Arc::clone(&client);
        let writer = tokio::spawn(async move {
            for i in 0..100 {
                let state = if i % 2 == 0 {
                    AgentState::Ready
                } else {
                    AgentState::Provisioning
                };
                writer_client.set_agent_state(state).await;
            }
        });

        let mut readers = vec![];
        for _ in 0..5 {
            let client = Arc::clone(&client);
            readers.push(tokio::spawn(async move {
                for _ in 0..100 {
                    let _ = client.agent_state().await;
                }
            }));
        }

        writer.await.expect("writer task should complete");
        for reader in readers {
            reader.await.expect("reader task should complete");
        }
    }

    // ==========================================================================
    // Story Tests: Uptime Tracking
    // ==========================================================================

    /// Story: Agent tracks uptime from creation
    #[test]
    fn agent_tracks_uptime() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        let uptime = client.uptime_seconds();
        assert!(uptime >= 0);
        assert!(uptime < 2);
    }

    /// Story: Agent uptime increases over time
    #[tokio::test]
    async fn agent_uptime_increases() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        let uptime1 = client.uptime_seconds();

        tokio::time::sleep(Duration::from_millis(100)).await;

        let uptime2 = client.uptime_seconds();

        assert!(uptime2 >= uptime1);
    }

    // ==========================================================================
    // Story Tests: API Server Endpoint Detection
    // ==========================================================================

    /// Story: API server endpoint uses injected config
    #[test]
    fn api_server_endpoint_uses_config() {
        use crate::config::MockK8sEnvConfig;

        let mut mock = MockK8sEnvConfig::new();
        mock.expect_kubernetes_service_host()
            .returning(|| Some("10.96.0.1".to_string()));
        mock.expect_kubernetes_service_port()
            .returning(|| "443".to_string());

        let config = AgentClientConfig::default();
        let client = AgentClient::builder(config)
            .env_config(Arc::new(mock))
            .build();

        assert_eq!(client.api_server_endpoint(), "https://10.96.0.1:443");
    }

    /// Story: API server endpoint is empty when host not configured
    #[test]
    fn api_server_endpoint_empty_without_host() {
        use crate::config::MockK8sEnvConfig;

        let mut mock = MockK8sEnvConfig::new();
        mock.expect_kubernetes_service_host().returning(|| None);

        let config = AgentClientConfig::default();
        let client = AgentClient::builder(config)
            .env_config(Arc::new(mock))
            .build();

        assert!(client.api_server_endpoint().is_empty());
    }

    // ==========================================================================
    // gRPC Max Message Size
    // ==========================================================================

    #[test]
    fn test_grpc_max_message_size_default() {
        std::env::remove_var("LATTICE_GRPC_MAX_MESSAGE_SIZE");
        assert_eq!(grpc_max_message_size(), 16 * 1024 * 1024);
    }
}
