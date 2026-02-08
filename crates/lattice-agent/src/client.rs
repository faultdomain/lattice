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

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use futures::StreamExt;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::time::interval;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Endpoint;
use tracing::{debug, error, info, warn};

use crate::commands::apply_manifests::extract_manifest_info_bytes;
use crate::commands::{self, CommandContext, StoredExecSession};
use lattice_capi::installer::{
    copy_credentials_to_provider_namespace, CapiInstaller, CapiProviderConfig, NativeInstaller,
};
use lattice_common::crd::{CloudProvider, LatticeCluster, ProviderType};
use lattice_common::{capi_namespace, CsrRequest, CsrResponse, LATTICE_SYSTEM_NAMESPACE};
use lattice_infra::pki::AgentCertRequest;
use lattice_proto::lattice_agent_client::LatticeAgentClient;
use lattice_proto::{
    agent_message::Payload, AgentMessage, AgentReady, AgentState, BootstrapComplete,
    ClusterDeleting, Heartbeat, MoveObject,
};

use crate::kube_client::{InClusterClientProvider, KubeClientProvider};
use crate::subtree::SubtreeSender;
use crate::watch::WatchRegistry;
use crate::{SharedExecForwarder, SharedK8sForwarder};
use lattice_infra::ClientMtlsConfig;

/// Configuration for the agent client
#[derive(Clone, Debug)]
pub struct AgentClientConfig {
    /// Cell gRPC endpoint (e.g., "https://cell.example.com:443")
    pub cell_grpc_endpoint: String,
    /// Cell HTTP endpoint for CSR signing (e.g., "https://cell.example.com:8080")
    pub cell_http_endpoint: String,
    /// Cluster name this agent manages
    pub cluster_name: String,
    /// Agent version string
    pub agent_version: String,
    /// Heartbeat interval
    pub heartbeat_interval: Duration,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// CA certificate PEM (for verifying cell)
    pub ca_cert_pem: Option<String>,
}

impl Default for AgentClientConfig {
    fn default() -> Self {
        Self {
            cell_grpc_endpoint: "https://localhost:50051".to_string(),
            cell_http_endpoint: "http://localhost:8080".to_string(),
            cluster_name: "unknown".to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            heartbeat_interval: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            ca_cert_pem: None,
        }
    }
}

/// Credentials for mTLS connection
#[derive(Clone)]
pub struct AgentCredentials {
    /// Agent certificate PEM (signed by cell CA)
    pub cert_pem: String,
    /// Agent private key PEM
    pub key_pem: String,
    /// CA certificate PEM (for verifying cell)
    pub ca_cert_pem: String,
}

/// Error type for certificate operations
#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    HttpError(String),
    /// CSR generation failed
    #[error("CSR generation failed: {0}")]
    CsrError(String),
    /// Invalid response
    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

/// Agent client state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientState {
    /// Not connected to cell
    Disconnected,
    /// Connecting to cell
    Connecting,
    /// Connected and streaming
    Connected,
    /// Connection failed
    Failed,
}

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
    forwarded_exec_sessions: Arc<DashMap<String, StoredExecSession>>,
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
            forwarded_exec_sessions: Arc::new(DashMap::new()),
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
        let key_pem = cert_request.private_key_pem().to_string();

        // Submit CSR to cell
        let url = format!("{}/api/clusters/{}/csr", http_endpoint, cluster_id);
        info!(url = %url, "Submitting CSR to cell");

        // Build HTTP client with CA certificate for TLS verification
        let ca_cert = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())
            .map_err(|e| CertificateError::HttpError(format!("Invalid CA certificate: {}", e)))?;

        let http_client = reqwest::Client::builder()
            .add_root_certificate(ca_cert)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(10))
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

    /// Connect to the cell with mTLS using the provided credentials
    pub async fn connect_with_mtls(
        &mut self,
        credentials: &AgentCredentials,
    ) -> Result<(), ClientError> {
        *self.state.write().await = ClientState::Connecting;

        info!(endpoint = %self.config.cell_grpc_endpoint, "Connecting to cell with mTLS");

        // Build mTLS config
        let domain = extract_domain(&self.config.cell_grpc_endpoint)
            .map_err(ClientError::InvalidEndpoint)?;
        let mtls_config = ClientMtlsConfig::new(
            credentials.cert_pem.clone(),
            credentials.key_pem.clone(),
            credentials.ca_cert_pem.clone(),
            domain,
        );

        let tls_config = mtls_config
            .to_tonic_config()
            .map_err(|e| ClientError::TlsError(e.to_string()))?;

        // Create channel with TLS, keep-alive, and lazy connection for auto-reconnect
        let channel = Endpoint::from_shared(self.config.cell_grpc_endpoint.clone())
            .map_err(|e| ClientError::InvalidEndpoint(e.to_string()))?
            .connect_timeout(self.config.connect_timeout)
            .keep_alive_timeout(Duration::from_secs(20))
            .keep_alive_while_idle(true)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .tls_config(tls_config)
            .map_err(|e| ClientError::TlsError(e.to_string()))?
            .connect_lazy();

        self.start_streams(channel).await
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

    /// Connect to the cell and start streaming (without TLS - for testing only)
    #[cfg(test)]
    pub async fn connect(&mut self) -> Result<(), ClientError> {
        *self.state.write().await = ClientState::Connecting;

        info!(endpoint = %self.config.cell_grpc_endpoint, "Connecting to cell (insecure)");

        // Create channel to cell
        let endpoint = Endpoint::from_shared(self.config.cell_grpc_endpoint.clone())
            .map_err(|e| ClientError::InvalidEndpoint(e.to_string()))?
            .connect_timeout(self.config.connect_timeout);

        let channel = endpoint
            .connect()
            .await
            .map_err(|e| ClientError::ConnectionFailed(e.to_string()))?;

        self.start_streams(channel).await
    }

    /// Start the gRPC streams on an established channel
    async fn start_streams(
        &mut self,
        channel: tonic::transport::Channel,
    ) -> Result<(), ClientError> {
        let max_msg_size = grpc_max_message_size();
        let mut client = LatticeAgentClient::new(channel.clone())
            .max_decoding_message_size(max_msg_size)
            .max_encoding_message_size(max_msg_size);

        // Create message channel
        let (message_tx, message_rx) = mpsc::channel::<AgentMessage>(32);
        self.message_tx = Some(message_tx.clone());

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        self.shutdown_tx = Some(shutdown_tx);

        // Start the control stream
        let outbound = ReceiverStream::new(message_rx);
        let response = client
            .stream_messages(outbound)
            .await
            .map_err(|e| ClientError::StreamFailed(e.to_string()))?;

        let mut inbound = response.into_inner();

        *self.state.write().await = ClientState::Connected;
        info!("Connected to cell");

        // Send ready message first to establish connection
        // This registers the agent on the server side
        self.send_ready().await?;

        // Install CAPI on this cluster - required for resource move during pivot
        // Retry up to 3 times with backoff for slow clusters (RKE2 image pulls)
        info!("Installing CAPI on local cluster");
        let mut capi_ready = false;
        let mut installed_providers = vec![];

        let capi_install_timeout = Duration::from_secs(600); // 10 minutes per attempt
        for attempt in 1..=3 {
            match tokio::time::timeout(capi_install_timeout, self.install_capi()).await {
                Ok(Ok(provider)) => {
                    info!("CAPI installed, waiting for CRDs");
                    if self.wait_for_capi_crds(120).await {
                        info!("CAPI is ready");
                        capi_ready = true;
                        installed_providers = vec![provider];
                        break;
                    } else {
                        warn!(
                            attempt,
                            "CAPI CRDs not available after timeout, retrying..."
                        );
                    }
                }
                Ok(Err(e)) => {
                    warn!(attempt, error = %e, "Failed to install CAPI, retrying...");
                }
                Err(_) => {
                    warn!(
                        attempt,
                        "CAPI installation timed out after 10 minutes, retrying..."
                    );
                }
            }
            if attempt < 3 {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        }

        if !capi_ready {
            return Err(ClientError::CapiInstallFailed(
                "failed after 3 attempts - cluster cannot self-manage".to_string(),
            ));
        }

        // Send bootstrap complete with CAPI status
        self.send_bootstrap_complete(capi_ready, installed_providers)
            .await?;

        // Send full subtree state to parent and start watcher for changes
        // This enables the parent cell to know about all clusters in our subtree
        // for routing K8s API requests and authorization decisions
        if let Some(k8s_client) = self.create_client_logged("subtree watcher").await {
            let subtree_sender = SubtreeSender::new(self.config.cluster_name.clone(), k8s_client);

            // Send full state on connect
            subtree_sender.send_full_state(&message_tx).await;

            // Spawn watcher to send deltas on LatticeCluster changes
            // spawn_watcher consumes the sender and runs until the channel closes
            self.subtree_watcher_handle = Some(subtree_sender.spawn_watcher(message_tx.clone()));
        }

        // Clone for spawned tasks
        let config = self.config.clone();
        let state = self.state.clone();
        let agent_state = self.agent_state.clone();
        let message_tx_clone = message_tx.clone();
        let watch_registry = self.watch_registry.clone();
        let exec_registry = self.exec_registry.clone();
        let forwarder = self.forwarder.clone();
        let exec_forwarder = self.exec_forwarder.clone();
        let forwarded_exec_sessions = self.forwarded_exec_sessions.clone();
        let kube_provider = self.kube_provider.clone();

        // Spawn heartbeat task and store handle
        let heartbeat_interval = self.config.heartbeat_interval;
        let heartbeat_state = agent_state.clone();
        let heartbeat_tx = message_tx.clone();
        let cluster_name = config.cluster_name.clone();
        let start_time = self.start_time;
        let heartbeat_kube_provider = kube_provider.clone();

        self.heartbeat_handle = Some(tokio::spawn(async move {
            let mut ticker = interval(heartbeat_interval);
            loop {
                ticker.tick().await;

                let current_state = *heartbeat_state.read().await;
                let health =
                    crate::health::gather_cluster_health(heartbeat_kube_provider.as_ref()).await;
                let msg = AgentMessage {
                    cluster_name: cluster_name.clone(),
                    payload: Some(Payload::Heartbeat(Heartbeat {
                        state: current_state.into(),
                        timestamp: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
                        uptime_seconds: start_time.elapsed().as_secs() as i64,
                        health,
                    })),
                };

                if heartbeat_tx.send(msg).await.is_err() {
                    debug!("Heartbeat channel closed");
                    break;
                }
            }
        }));

        // Spawn deletion watcher task - detects cluster deletion and starts unpivot loop.
        // Handles both:
        // - Runtime deletion: cluster deleted while agent is running
        // - Crash recovery: cluster was being deleted when agent crashed/restarted
        // Polls every 5 seconds, so crash recovery has at most 5s latency.
        let deletion_tx = message_tx.clone();
        let deletion_provider = self.kube_provider.clone();
        self.deletion_watcher_handle = Some(tokio::spawn(async move {
            let poll_interval = Duration::from_secs(5);
            loop {
                tokio::time::sleep(poll_interval).await;

                // Check if cluster is being deleted
                if let Some((namespace, cluster_name)) =
                    Self::check_cluster_deleting(deletion_provider.as_ref()).await
                {
                    info!(
                        cluster = %cluster_name,
                        namespace = %namespace,
                        "Detected cluster deletion during runtime - starting unpivot"
                    );

                    // Start the unpivot retry loop (runs until CAPI deletes us)
                    Self::run_unpivot_loop(
                        deletion_tx,
                        &cluster_name,
                        &namespace,
                        deletion_provider.as_ref(),
                    )
                    .await;

                    // run_unpivot_loop only exits when the channel closes (disconnect)
                    // so we break here
                    break;
                }
            }
        }));

        // Create command context for handler
        let command_ctx = CommandContext::new(
            config.cluster_name.clone(),
            message_tx_clone.clone(),
            agent_state.clone(),
            watch_registry.clone(),
            exec_registry.clone(),
            forwarder,
            exec_forwarder,
            forwarded_exec_sessions,
            kube_provider,
        );

        // Spawn command handler task and store handle
        self.command_handler_handle = Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(result) = inbound.next() => {
                        match result {
                            Ok(command) => {
                                commands::handle_command(&command, &command_ctx).await;
                            }
                            Err(e) => {
                                error!(error = %e, "Error receiving command");
                                break;
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        info!("Shutdown signal received");
                        break;
                    }
                    else => break,
                }
            }

            // Cancel all active sessions on disconnect
            watch_registry.cancel_all();
            exec_registry.cancel_all();

            // Reset agent state if we were mid-pivot - allows retry on reconnect
            let current_agent_state = *agent_state.read().await;
            if current_agent_state == AgentState::Pivoting {
                warn!("Connection lost during pivot - resetting to Provisioning for retry");
                *agent_state.write().await = AgentState::Provisioning;
            }

            *state.write().await = ClientState::Disconnected;
            info!("Disconnected from cell");
        }));

        Ok(())
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

    /// Check if the local LatticeCluster is being deleted
    ///
    /// Returns Some((namespace, cluster_name)) if the cluster has a deletion timestamp,
    /// indicating we should start the unpivot retry loop.
    async fn check_cluster_deleting(
        kube_provider: &dyn KubeClientProvider,
    ) -> Option<(String, String)> {
        let client =
            crate::kube_client::create_client_logged(kube_provider, "cluster deletion check")
                .await?;
        let clusters: kube::Api<LatticeCluster> = kube::Api::all(client);
        let list = clusters
            .list(&kube::api::ListParams::default())
            .await
            .ok()?;

        let cluster = list.items.first()?;
        if cluster.metadata.deletion_timestamp.is_some() {
            let name = cluster.metadata.name.clone()?;
            let namespace = capi_namespace(&name);
            Some((namespace, name))
        } else {
            None
        }
    }

    /// Run the unpivot retry loop
    ///
    /// Uses native CAPI discovery (same logic as pivot) to export resources.
    /// Keeps sending ClusterDeleting to parent every 5s until parent imports.
    /// No ACK is needed - the cluster will simply be deleted at the infrastructure level.
    async fn run_unpivot_loop(
        message_tx: mpsc::Sender<AgentMessage>,
        cluster_name: &str,
        namespace: &str,
        kube_provider: &dyn KubeClientProvider,
    ) {
        let base_interval = Duration::from_secs(5);
        let max_interval = Duration::from_secs(60);
        let mut current_interval = base_interval;

        loop {
            // Create K8s client for this iteration
            let Some(client) =
                crate::kube_client::create_client_logged(kube_provider, "unpivot").await
            else {
                tokio::time::sleep(current_interval).await;
                current_interval = (current_interval * 2).min(max_interval);
                continue;
            };

            // Discover and prepare CAPI resources (same logic as pivot)
            match lattice_move::prepare_move_objects(&client, namespace, cluster_name).await {
                Ok(objects) => {
                    // Log each object being sent for debugging
                    for obj in &objects {
                        let (kind, name) = extract_manifest_info_bytes(&obj.manifest);
                        info!(
                            cluster = %cluster_name,
                            kind = %kind,
                            name = %name,
                            source_uid = %obj.source_uid,
                            owners = obj.owners.len(),
                            "Unpivot: sending object"
                        );
                    }
                    info!(
                        cluster = %cluster_name,
                        namespace = %namespace,
                        object_count = objects.len(),
                        "Sending ClusterDeleting to parent (unpivot)"
                    );

                    // Convert to proto format using From impl
                    let proto_objects: Vec<MoveObject> =
                        objects.into_iter().map(Into::into).collect();

                    let msg = AgentMessage {
                        cluster_name: cluster_name.to_string(),
                        payload: Some(Payload::ClusterDeleting(ClusterDeleting {
                            namespace: namespace.to_string(),
                            objects: proto_objects,
                            cluster_name: cluster_name.to_string(),
                        })),
                    };

                    if message_tx.send(msg).await.is_err() {
                        warn!("Unpivot message channel closed, stopping retry loop");
                        break;
                    }

                    // Success — reset to base interval
                    current_interval = base_interval;
                }
                Err(e) => {
                    warn!(
                        cluster = %cluster_name,
                        error = %e,
                        "Failed to prepare CAPI for unpivot, will retry"
                    );
                    // Backoff on failure
                    current_interval = (current_interval * 2).min(max_interval);
                }
            }

            tokio::time::sleep(current_interval).await;
        }
    }

    /// Install CAPI and infrastructure provider
    ///
    /// Reads provider type from LatticeCluster CRD, then:
    /// 1. Copies provider credentials from lattice-system to provider namespace
    /// 2. Installs cert-manager + CAPI providers from bundled manifests
    async fn install_capi(&self) -> Result<String, std::io::Error> {
        use kube::api::ListParams;

        let client = self
            .create_client()
            .await
            .map_err(|e| std::io::Error::other(format!("failed to create K8s client: {}", e)))?;

        let clusters: kube::Api<LatticeCluster> = kube::Api::all(client.clone());
        let list = clusters
            .list(&ListParams::default())
            .await
            .map_err(|e| std::io::Error::other(format!("failed to list LatticeCluster: {}", e)))?;

        let cluster = list
            .items
            .first()
            .ok_or_else(|| std::io::Error::other("no LatticeCluster found"))?;

        let infrastructure = cluster.spec.provider.provider_type();
        let provider_str = infrastructure.to_string();

        info!(infrastructure = %provider_str, "Installing CAPI providers");

        // Copy credentials from CloudProvider to CAPI provider namespace
        if infrastructure != ProviderType::Docker {
            let cloud_providers: kube::Api<CloudProvider> =
                kube::Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
            let cp = cloud_providers
                .get(&cluster.spec.provider_ref)
                .await
                .map_err(|e| {
                    std::io::Error::other(format!(
                        "CloudProvider '{}' not found: {}",
                        cluster.spec.provider_ref, e
                    ))
                })?;

            let secret_ref = cp.spec.credentials_secret_ref.as_ref().ok_or_else(|| {
                std::io::Error::other(format!(
                    "CloudProvider '{}' missing credentials_secret_ref",
                    cluster.spec.provider_ref
                ))
            })?;

            copy_credentials_to_provider_namespace(&client, infrastructure, secret_ref)
                .await
                .map_err(|e| {
                    std::io::Error::other(format!("Failed to copy provider credentials: {}", e))
                })?;
        }

        let config = CapiProviderConfig::new(infrastructure)
            .map_err(|e| std::io::Error::other(format!("Failed to create CAPI config: {}", e)))?;
        NativeInstaller::new()
            .ensure(&config)
            .await
            .map_err(|e| std::io::Error::other(format!("CAPI installation failed: {}", e)))?;

        info!(infrastructure = %provider_str, "CAPI providers installed successfully");
        Ok(provider_str)
    }

    /// Wait for CAPI CRDs to be available
    ///
    /// Uses kube-rs to check if the clusters.cluster.x-k8s.io CRD exists.
    /// Returns true if CRD becomes available within timeout_secs.
    async fn wait_for_capi_crds(&self, timeout_secs: u64) -> bool {
        use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
        use kube::api::Api;
        use tokio::time::{sleep, Duration};

        let Some(client) = self.create_client_logged("CRD check").await else {
            return false;
        };

        let crds: Api<CustomResourceDefinition> = Api::all(client);

        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            match crds.get("clusters.cluster.x-k8s.io").await {
                Ok(_) => return true,
                Err(_) => {
                    debug!("CAPI CRDs not yet available, waiting...");
                    // 5s base + up to 3s jitter to avoid thundering herd
                    let jitter_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.subsec_millis() as u64 % 3000)
                        .unwrap_or(0);
                    sleep(Duration::from_secs(5) + Duration::from_millis(jitter_ms)).await;
                }
            }
        }

        false
    }
}

/// Client errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// Invalid endpoint URL
    InvalidEndpoint(String),
    /// Connection to cell failed
    ConnectionFailed(String),
    /// Stream creation failed
    StreamFailed(String),
    /// TLS configuration error
    TlsError(String),
    /// Not connected to cell
    NotConnected,
    /// Channel closed
    ChannelClosed,
    /// CAPI installation failed
    CapiInstallFailed(String),
    /// Kubernetes API error
    K8sApiError(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::InvalidEndpoint(e) => write!(f, "invalid endpoint: {}", e),
            ClientError::ConnectionFailed(e) => write!(f, "connection failed: {}", e),
            ClientError::StreamFailed(e) => write!(f, "stream failed: {}", e),
            ClientError::TlsError(e) => write!(f, "TLS error: {}", e),
            ClientError::NotConnected => write!(f, "not connected"),
            ClientError::ChannelClosed => write!(f, "channel closed"),
            ClientError::CapiInstallFailed(e) => write!(f, "CAPI installation failed: {}", e),
            ClientError::K8sApiError(e) => write!(f, "Kubernetes API error: {}", e),
        }
    }
}

impl std::error::Error for ClientError {}

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

const DEFAULT_GRPC_MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

fn grpc_max_message_size() -> usize {
    std::env::var("LATTICE_GRPC_MAX_MESSAGE_SIZE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_GRPC_MAX_MESSAGE_SIZE)
}

/// Extract domain name from a URL for TLS verification
fn extract_domain(url: &str) -> Result<String, String> {
    if url.is_empty() {
        return Err("URL is empty".to_string());
    }

    // Remove protocol prefix if present
    let without_protocol = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    // Take everything before the port or path
    let domain = without_protocol
        .split(':')
        .next()
        .and_then(|s| s.split('/').next())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("URL has no domain: {}", url))?;

    Ok(domain.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AgentClientConfig::default();
        assert_eq!(config.heartbeat_interval, Duration::from_secs(30));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.cluster_name, "unknown");
        assert_eq!(config.cell_grpc_endpoint, "https://localhost:50051");
        assert_eq!(config.cell_http_endpoint, "http://localhost:8080");
        assert!(config.ca_cert_pem.is_none());
    }

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

    // Test extract_domain with various inputs
    #[test]
    fn test_extract_domain_https() {
        assert_eq!(
            extract_domain("https://cell.example.com:443"),
            Ok("cell.example.com".to_string())
        );
    }

    #[test]
    fn test_extract_domain_http() {
        assert_eq!(
            extract_domain("http://localhost:8080"),
            Ok("localhost".to_string())
        );
    }

    #[test]
    fn test_extract_domain_no_port() {
        assert_eq!(
            extract_domain("https://cell.example.com"),
            Ok("cell.example.com".to_string())
        );
    }

    #[test]
    fn test_extract_domain_with_path() {
        assert_eq!(
            extract_domain("https://cell.example.com:443/api/v1"),
            Ok("cell.example.com".to_string())
        );
    }

    #[test]
    fn test_extract_domain_no_protocol() {
        assert_eq!(
            extract_domain("cell.example.com:443"),
            Ok("cell.example.com".to_string())
        );
    }

    #[test]
    fn test_extract_domain_ip_address() {
        assert_eq!(
            extract_domain("https://192.168.1.1:8080"),
            Ok("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_extract_domain_empty_string() {
        assert!(extract_domain("").is_err());
    }

    #[test]
    fn test_extract_domain_protocol_only() {
        assert!(extract_domain("https://").is_err());
    }

    #[test]
    fn test_credentials_struct() {
        let creds = AgentCredentials {
            cert_pem: "cert".to_string(),
            key_pem: "key".to_string(),
            ca_cert_pem: "ca".to_string(),
        };
        assert_eq!(creds.cert_pem, "cert");
        assert_eq!(creds.key_pem, "key");
        assert_eq!(creds.ca_cert_pem, "ca");
    }

    // Test CertificateError display
    #[test]
    fn test_certificate_error_http_display() {
        let err = CertificateError::HttpError("connection refused".to_string());
        assert_eq!(err.to_string(), "HTTP request failed: connection refused");
    }

    #[test]
    fn test_certificate_error_csr_display() {
        let err = CertificateError::CsrError("invalid key".to_string());
        assert_eq!(err.to_string(), "CSR generation failed: invalid key");
    }

    #[test]
    fn test_certificate_error_invalid_response_display() {
        let err = CertificateError::InvalidResponse("malformed json".to_string());
        assert_eq!(err.to_string(), "invalid response: malformed json");
    }

    // Test ClientError display
    #[test]
    fn test_client_error_invalid_endpoint_display() {
        let err = ClientError::InvalidEndpoint("bad url".to_string());
        assert_eq!(err.to_string(), "invalid endpoint: bad url");
    }

    #[test]
    fn test_client_error_connection_failed_display() {
        let err = ClientError::ConnectionFailed("timeout".to_string());
        assert_eq!(err.to_string(), "connection failed: timeout");
    }

    #[test]
    fn test_client_error_stream_failed_display() {
        let err = ClientError::StreamFailed("broken pipe".to_string());
        assert_eq!(err.to_string(), "stream failed: broken pipe");
    }

    #[test]
    fn test_client_error_tls_display() {
        let err = ClientError::TlsError("certificate expired".to_string());
        assert_eq!(err.to_string(), "TLS error: certificate expired");
    }

    #[test]
    fn test_client_error_not_connected_display() {
        let err = ClientError::NotConnected;
        assert_eq!(err.to_string(), "not connected");
    }

    #[test]
    fn test_client_error_channel_closed_display() {
        let err = ClientError::ChannelClosed;
        assert_eq!(err.to_string(), "channel closed");
    }

    #[test]
    fn test_client_error_is_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(ClientError::NotConnected);
        assert!(err.to_string().contains("not connected"));
    }

    // Test ClientState enum
    #[test]
    fn test_client_state_equality() {
        assert_eq!(ClientState::Disconnected, ClientState::Disconnected);
        assert_eq!(ClientState::Connecting, ClientState::Connecting);
        assert_eq!(ClientState::Connected, ClientState::Connected);
        assert_eq!(ClientState::Failed, ClientState::Failed);
        assert_ne!(ClientState::Disconnected, ClientState::Connected);
    }

    #[test]
    fn test_client_state_copy() {
        let state = ClientState::Connected;
        let copied = state;
        assert_eq!(state, copied);
    }

    #[test]
    fn test_client_state_debug() {
        let state = ClientState::Connecting;
        let debug_str = format!("{:?}", state);
        assert_eq!(debug_str, "Connecting");
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

    // Test handle_command with various command types
    // Note: handle_command tests have been moved to the commands module tests
    // (see commands/status_request.rs and commands/apply_manifests.rs)

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
    //
    // These tests document the agent client behavior through user stories,
    // focusing on what happens during various connection and communication
    // scenarios between a workload cluster agent and its parent cell.

    /// Story: When a new agent is created, it starts in a disconnected state
    ///
    /// A newly created agent client should not be connected to any cell.
    /// It needs to go through the certificate request and mTLS connection
    /// process before it can communicate with the cell.
    #[tokio::test]
    async fn story_new_agent_starts_disconnected() {
        let config = AgentClientConfig {
            cluster_name: "workload-east-1".to_string(),
            cell_grpc_endpoint: "https://cell.example.com:443".to_string(),
            cell_http_endpoint: "http://cell.example.com:8080".to_string(),
            ..Default::default()
        };

        let client = AgentClient::new(config);

        // Agent starts in disconnected state
        assert_eq!(client.state().await, ClientState::Disconnected);

        // Agent starts in provisioning state (just created)
        assert_eq!(client.agent_state().await, AgentState::Provisioning);

        // No message channel established yet
        assert!(client.message_tx.is_none());

        // No shutdown channel yet
        assert!(client.shutdown_tx.is_none());
    }

    /// Story: Agent progresses through lifecycle states during provisioning
    ///
    /// The agent tracks its own state throughout its lifecycle:
    /// Provisioning -> Pivoting -> Ready (or Failed)
    #[tokio::test]
    async fn story_agent_state_lifecycle_transitions() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        // Initial state is Provisioning (cluster being set up)
        assert_eq!(client.agent_state().await, AgentState::Provisioning);

        // When pivot starts, state changes to Pivoting
        client.set_agent_state(AgentState::Pivoting).await;
        assert_eq!(client.agent_state().await, AgentState::Pivoting);

        // When pivot succeeds, state changes to Ready
        client.set_agent_state(AgentState::Ready).await;
        assert_eq!(client.agent_state().await, AgentState::Ready);
    }

    /// Story: When an agent fails to provision, it enters the failed state
    #[tokio::test]
    async fn story_agent_enters_failed_state_on_error() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        // Something goes wrong during provisioning
        client.set_agent_state(AgentState::Failed).await;
        assert_eq!(client.agent_state().await, AgentState::Failed);
    }

    /// Story: Agent can be in degraded state when issues occur but still operational
    #[tokio::test]
    async fn story_agent_degraded_state_for_partial_issues() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        // Cluster has issues but is still operational
        client.set_agent_state(AgentState::Degraded).await;
        assert_eq!(client.agent_state().await, AgentState::Degraded);
    }

    // ==========================================================================
    // Story Tests: Message Sending When Connected
    // ==========================================================================

    /// Story: Agent sends bootstrap complete after CAPI providers are installed
    #[tokio::test]
    async fn story_agent_reports_bootstrap_completion() {
        let config = AgentClientConfig {
            cluster_name: "bootstrap-test".to_string(),
            ..Default::default()
        };
        let mut client = AgentClient::new(config);

        let (tx, mut rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        // CAPI ready with docker provider
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
    async fn story_agent_reports_partial_bootstrap() {
        let config = AgentClientConfig {
            cluster_name: "partial-bootstrap".to_string(),
            ..Default::default()
        };
        let mut client = AgentClient::new(config);

        let (tx, mut rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        // CAPI not ready yet, no providers
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
    async fn story_sending_when_not_connected_returns_error() {
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
    async fn story_channel_closure_detected_on_send() {
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
    ///
    /// Shutdown should be idempotent and safe to call in any state.
    #[tokio::test]
    async fn story_shutdown_is_idempotent() {
        let config = AgentClientConfig::default();
        let mut client = AgentClient::new(config);

        // First shutdown - should be safe
        client.disconnect().await;
        assert_eq!(client.state().await, ClientState::Disconnected);

        // Second shutdown - should also be safe
        client.disconnect().await;
        assert_eq!(client.state().await, ClientState::Disconnected);
    }

    /// Story: Agent shutdown signals background tasks to stop
    #[tokio::test]
    async fn story_shutdown_signals_background_tasks() {
        let config = AgentClientConfig::default();
        let mut client = AgentClient::new(config);

        // Simulate having a shutdown channel (as if we were connected)
        let (tx, mut rx) = oneshot::channel::<()>();
        client.shutdown_tx = Some(tx);

        // Shutdown should send the signal
        client.disconnect().await;

        // The receiver should get the signal (not be cancelled)
        // Note: After send, the rx will receive Ok(())
        match rx.try_recv() {
            Ok(()) => {} // Signal received
            Err(_) => panic!("Shutdown signal should have been sent"),
        }
    }

    // Note: Command handling tests have been moved to the commands module
    // (see commands/status_request.rs, commands/apply_manifests.rs, etc.)

    // ==========================================================================
    // Story Tests: Configuration
    // ==========================================================================

    /// Story: Agent configuration can be customized for different environments
    #[test]
    fn story_agent_config_customization() {
        let config = AgentClientConfig {
            cell_grpc_endpoint: "https://cell.prod.example.com:443".to_string(),
            cell_http_endpoint: "http://cell.prod.example.com:8080".to_string(),
            cluster_name: "prod-us-west-2-cluster-42".to_string(),
            agent_version: "2.0.0".to_string(),
            heartbeat_interval: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(30),
            ca_cert_pem: Some(
                "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----".to_string(),
            ),
        };

        assert_eq!(
            config.cell_grpc_endpoint,
            "https://cell.prod.example.com:443"
        );
        assert_eq!(config.heartbeat_interval, Duration::from_secs(60));
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert!(config.ca_cert_pem.is_some());
    }

    /// Story: Default configuration provides sensible defaults
    #[test]
    fn story_default_config_sensible_values() {
        let config = AgentClientConfig::default();

        // 30 second heartbeat is reasonable for cell health monitoring
        assert_eq!(config.heartbeat_interval, Duration::from_secs(30));

        // 10 second connect timeout balances responsiveness with network delays
        assert_eq!(config.connect_timeout, Duration::from_secs(10));

        // Default endpoints point to localhost for development
        assert!(config.cell_grpc_endpoint.contains("localhost"));
        assert!(config.cell_http_endpoint.contains("localhost"));
    }

    // ==========================================================================
    // Story Tests: Domain Extraction
    // ==========================================================================

    /// Story: Domain extraction for TLS works with various URL formats
    ///
    /// The agent needs to extract the domain name from URLs for TLS verification.
    /// This should work with HTTPS, HTTP, with/without ports, and IP addresses.
    #[test]
    fn story_domain_extraction_handles_various_formats() {
        // Standard HTTPS with port
        assert_eq!(
            extract_domain("https://cell.example.com:443"),
            Ok("cell.example.com".to_string())
        );

        // HTTP for bootstrap endpoint
        assert_eq!(
            extract_domain("http://cell.example.com:8080"),
            Ok("cell.example.com".to_string())
        );

        // Without port
        assert_eq!(
            extract_domain("https://cell.example.com"),
            Ok("cell.example.com".to_string())
        );

        // With path (shouldn't happen but handle gracefully)
        assert_eq!(
            extract_domain("https://cell.example.com:443/api/v1"),
            Ok("cell.example.com".to_string())
        );

        // IP address
        assert_eq!(
            extract_domain("https://172.18.255.1:443"),
            Ok("172.18.255.1".to_string())
        );

        // Raw host:port (no protocol)
        assert_eq!(
            extract_domain("cell.example.com:443"),
            Ok("cell.example.com".to_string())
        );

        // Edge cases - errors preserve context
        assert!(extract_domain("").is_err());
        assert!(extract_domain("https://").is_err());
    }

    // ==========================================================================
    // Story Tests: Certificate Errors
    // ==========================================================================

    /// Story: Certificate errors provide actionable information
    ///
    /// When certificate operations fail, error messages should help
    /// diagnose the issue.
    #[test]
    fn story_certificate_errors_are_descriptive() {
        // HTTP errors during CSR submission
        let http_err = CertificateError::HttpError("connection refused".to_string());
        let msg = http_err.to_string();
        assert!(msg.contains("HTTP request failed"));
        assert!(msg.contains("connection refused"));

        // CSR generation errors
        let csr_err = CertificateError::CsrError("invalid key size".to_string());
        let msg = csr_err.to_string();
        assert!(msg.contains("CSR generation failed"));
        assert!(msg.contains("invalid key size"));

        // Invalid response from cell
        let resp_err = CertificateError::InvalidResponse("JSON parse error".to_string());
        let msg = resp_err.to_string();
        assert!(msg.contains("invalid response"));
        assert!(msg.contains("JSON parse error"));
    }

    /// Story: Client errors cover all connection failure modes
    #[test]
    fn story_client_errors_cover_failure_modes() {
        // Invalid endpoint URL
        let err = ClientError::InvalidEndpoint("not a valid URL".to_string());
        assert!(err.to_string().contains("invalid endpoint"));

        // Connection failed (network issues)
        let err = ClientError::ConnectionFailed("tcp connect error".to_string());
        assert!(err.to_string().contains("connection failed"));

        // Stream setup failed
        let err = ClientError::StreamFailed("status: UNAVAILABLE".to_string());
        assert!(err.to_string().contains("stream failed"));

        // TLS configuration error
        let err = ClientError::TlsError("certificate expired".to_string());
        assert!(err.to_string().contains("TLS error"));

        // Not connected
        let err = ClientError::NotConnected;
        assert!(err.to_string().contains("not connected"));

        // Channel closed
        let err = ClientError::ChannelClosed;
        assert!(err.to_string().contains("channel closed"));
    }

    /// Story: Client errors implement std::error::Error for error handling chains
    #[test]
    fn story_client_errors_implement_error_trait() {
        fn takes_error(_: &dyn std::error::Error) {}

        let err = ClientError::NotConnected;
        takes_error(&err);

        let err = ClientError::ConnectionFailed("test".to_string());
        takes_error(&err);
    }

    // ==========================================================================
    // Story Tests: Credentials Structure
    // ==========================================================================

    /// Story: Agent credentials are cloneable for use in multiple contexts
    #[test]
    fn story_credentials_can_be_cloned() {
        let creds = AgentCredentials {
            cert_pem: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----".to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----".to_string(),
            ca_cert_pem: "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
                .to_string(),
        };

        let cloned = creds.clone();
        assert_eq!(cloned.cert_pem, creds.cert_pem);
        assert_eq!(cloned.key_pem, creds.key_pem);
        assert_eq!(cloned.ca_cert_pem, creds.ca_cert_pem);
    }

    // ==========================================================================
    // Story Tests: AgentReady Message Format
    // ==========================================================================

    /// Story: When connected, agent sends ready message with proper format
    ///
    /// The AgentReady message includes version information and current state.
    #[tokio::test]
    async fn story_ready_message_includes_agent_info() {
        // Test the message format that send_ready would produce
        let config = AgentClientConfig {
            cluster_name: "ready-test-cluster".to_string(),
            agent_version: "1.5.0".to_string(),
            ..Default::default()
        };

        // Verify the Ready message structure
        let msg = AgentMessage {
            cluster_name: config.cluster_name.clone(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: config.agent_version.clone(),
                kubernetes_version: "unknown".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: String::new(),
            })),
        };

        assert_eq!(msg.cluster_name, "ready-test-cluster");
        match msg.payload {
            Some(Payload::Ready(ready)) => {
                assert_eq!(ready.agent_version, "1.5.0");
                assert_eq!(ready.kubernetes_version, "unknown");
                assert_eq!(ready.state, i32::from(AgentState::Provisioning));
            }
            _ => panic!("Expected Ready payload"),
        }
    }

    /// Story: AgentReady state reflects current agent state
    #[tokio::test]
    async fn story_ready_message_reflects_current_state() {
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
    async fn story_heartbeat_message_format() {
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
    // Story Tests: Configuration Cloneability
    // ==========================================================================

    /// Story: AgentClientConfig is cloneable for sharing across components
    #[test]
    fn story_config_is_cloneable() {
        let config = AgentClientConfig {
            cell_grpc_endpoint: "https://cell:443".to_string(),
            cell_http_endpoint: "http://cell:8080".to_string(),
            cluster_name: "clone-test".to_string(),
            agent_version: "2.0.0".to_string(),
            heartbeat_interval: Duration::from_secs(45),
            connect_timeout: Duration::from_secs(15),
            ca_cert_pem: Some("cert".to_string()),
        };

        let cloned = config.clone();

        assert_eq!(cloned.cell_grpc_endpoint, config.cell_grpc_endpoint);
        assert_eq!(cloned.cell_http_endpoint, config.cell_http_endpoint);
        assert_eq!(cloned.cluster_name, config.cluster_name);
        assert_eq!(cloned.agent_version, config.agent_version);
        assert_eq!(cloned.heartbeat_interval, config.heartbeat_interval);
        assert_eq!(cloned.connect_timeout, config.connect_timeout);
        assert_eq!(cloned.ca_cert_pem, config.ca_cert_pem);
    }

    /// Story: AgentClientConfig is debuggable for logging
    #[test]
    fn story_config_is_debuggable() {
        let config = AgentClientConfig {
            cluster_name: "debug-test".to_string(),
            ..Default::default()
        };

        let debug = format!("{:?}", config);
        assert!(debug.contains("debug-test"));
        assert!(debug.contains("AgentClientConfig"));
    }

    // ==========================================================================
    // Story Tests: ClientState Transitions
    // ==========================================================================

    /// Story: Client state machine covers all states
    #[test]
    fn story_client_state_values() {
        // Verify all states exist and are distinct
        let states = [
            ClientState::Disconnected,
            ClientState::Connecting,
            ClientState::Connected,
            ClientState::Failed,
        ];

        // All states should be distinct
        for (i, state_a) in states.iter().enumerate() {
            for (j, state_b) in states.iter().enumerate() {
                if i == j {
                    assert_eq!(state_a, state_b);
                } else {
                    assert_ne!(state_a, state_b);
                }
            }
        }
    }

    /// Story: Client state is clone and copy
    #[test]
    fn story_client_state_is_copy() {
        let state = ClientState::Connected;
        let copied = state; // Copy
        let also_copied = state; // Also copy (Copy trait means clone() isn't needed)

        assert_eq!(state, copied);
        assert_eq!(state, also_copied);
        assert_eq!(copied, also_copied);
    }

    // ==========================================================================
    // Story Tests: AgentState Transitions
    // ==========================================================================

    /// Story: AgentState values match proto definitions
    #[test]
    fn story_agent_state_proto_conversion() {
        // Verify conversion to proto i32 values
        assert_eq!(i32::from(AgentState::Unknown), 0);
        assert_eq!(i32::from(AgentState::Provisioning), 1);
        assert_eq!(i32::from(AgentState::Pivoting), 2);
        assert_eq!(i32::from(AgentState::Ready), 3);
        assert_eq!(i32::from(AgentState::Degraded), 4);
        assert_eq!(i32::from(AgentState::Failed), 5);
    }

    // ==========================================================================
    // Story Tests: Error Equality
    // ==========================================================================

    /// Story: ClientError types are comparable for testing
    #[test]
    fn story_client_errors_are_comparable() {
        // Same error type and content should be equal
        assert_eq!(
            ClientError::InvalidEndpoint("test".to_string()),
            ClientError::InvalidEndpoint("test".to_string())
        );

        // Different content should be different
        assert_ne!(
            ClientError::InvalidEndpoint("a".to_string()),
            ClientError::InvalidEndpoint("b".to_string())
        );

        // Different types should be different
        assert_ne!(
            ClientError::InvalidEndpoint("test".to_string()),
            ClientError::ConnectionFailed("test".to_string())
        );

        // Unit variants are equal to themselves
        assert_eq!(ClientError::NotConnected, ClientError::NotConnected);
        assert_eq!(ClientError::ChannelClosed, ClientError::ChannelClosed);
        assert_ne!(ClientError::NotConnected, ClientError::ChannelClosed);
    }

    // ==========================================================================
    // Story Tests: Concurrent State Access
    // ==========================================================================

    /// Story: Agent state can be accessed concurrently from multiple tasks
    #[tokio::test]
    async fn story_concurrent_state_access() {
        let config = AgentClientConfig::default();
        let client = Arc::new(AgentClient::new(config));

        // Spawn multiple readers
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

        // All should complete without deadlock
        for handle in handles {
            handle.await.expect("task should complete");
        }
    }

    /// Story: Agent state can be written while being read
    #[tokio::test]
    async fn story_concurrent_state_read_write() {
        let config = AgentClientConfig::default();
        let client = Arc::new(AgentClient::new(config));

        // Writer task
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

        // Reader tasks
        let mut readers = vec![];
        for _ in 0..5 {
            let client = Arc::clone(&client);
            readers.push(tokio::spawn(async move {
                for _ in 0..100 {
                    let _ = client.agent_state().await;
                }
            }));
        }

        // All should complete without issues
        writer.await.expect("writer task should complete");
        for reader in readers {
            reader.await.expect("reader task should complete");
        }
    }

    // ==========================================================================
    // Story Tests: Uptime Tracking
    // ==========================================================================

    /// Story: Agent tracks uptime from creation
    ///
    /// The agent should track its uptime from the moment it's created,
    /// not from when it connects to the cell.
    #[test]
    fn story_agent_tracks_uptime() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        // Immediately after creation, uptime should be 0 (or very close to it)
        let uptime = client.uptime_seconds();
        assert!(uptime >= 0);
        assert!(uptime < 2); // Should be < 2 seconds
    }

    /// Story: Agent uptime increases over time
    #[tokio::test]
    async fn story_agent_uptime_increases() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        let uptime1 = client.uptime_seconds();

        // Wait a moment
        tokio::time::sleep(Duration::from_millis(100)).await;

        let uptime2 = client.uptime_seconds();

        // Uptime should be at least as much as before (may not have crossed second boundary)
        assert!(uptime2 >= uptime1);
    }

    // ==========================================================================
    // Story Tests: API Server Endpoint Detection
    // ==========================================================================
    //
    // Note: Core endpoint logic is tested in config::tests.
    // These tests verify AgentClient correctly uses the injected config.

    /// Story: API server endpoint uses injected config
    #[test]
    fn story_api_server_endpoint_uses_config() {
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
    fn story_api_server_endpoint_empty_without_host() {
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
        // When env var is not set, should return 16 MiB
        std::env::remove_var("LATTICE_GRPC_MAX_MESSAGE_SIZE");
        assert_eq!(grpc_max_message_size(), 16 * 1024 * 1024);
    }

    // Note: Ack helper tests moved to the commands module
    // (see commands/move_batch.rs and commands/move_complete.rs)
}
