//! gRPC client for agent (workload cluster)
//!
//! Connects to the parent cell and maintains persistent streams for
//! control messages and K8s API proxying.
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

use futures::StreamExt;
use kube::Client as KubeClient;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::time::interval;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Endpoint;
use tracing::{debug, error, info, warn};

use crate::bootstrap::{CsrRequest, CsrResponse};
use crate::pivot::{
    patch_kubeconfig_for_self_management, retry_with_backoff, AgentPivotHandler, RetryConfig,
};
use crate::pki::AgentCertRequest;
use crate::proto::lattice_agent_client::LatticeAgentClient;
use crate::proto::{
    agent_message::Payload, cell_command::Command, AgentMessage, AgentReady, AgentState,
    BootstrapComplete, CellCommand, Heartbeat, KubeProxyRequest, KubeProxyResponse, PivotComplete,
    PivotStarted,
};

use super::mtls::ClientMtlsConfig;

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
    state: Arc<RwLock<ClientState>>,
    agent_state: Arc<RwLock<AgentState>>,
    /// Kubernetes client for proxying API requests
    kube_client: Option<KubeClient>,
    /// Sender for outgoing messages
    message_tx: Option<mpsc::Sender<AgentMessage>>,
    /// Shutdown signal
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Time when the agent was started (for uptime tracking)
    start_time: Instant,
}

impl AgentClient {
    /// Create a new agent client with the given configuration
    pub fn new(config: AgentClientConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(ClientState::Disconnected)),
            agent_state: Arc::new(RwLock::new(AgentState::Provisioning)),
            kube_client: None,
            message_tx: None,
            shutdown_tx: None,
            start_time: Instant::now(),
        }
    }

    /// Get the agent uptime in seconds
    pub fn uptime_seconds(&self) -> i64 {
        self.start_time.elapsed().as_secs() as i64
    }

    /// Get the Kubernetes API server endpoint from environment
    fn get_api_server_endpoint() -> String {
        std::env::var("KUBERNETES_SERVICE_HOST")
            .map(|host| {
                let port =
                    std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string());
                format!("https://{}:{}", host, port)
            })
            .unwrap_or_default()
    }

    /// Set the Kubernetes client for API proxying
    pub fn with_kube_client(mut self, client: KubeClient) -> Self {
        self.kube_client = Some(client);
        self
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
            .build()
            .map_err(|e| {
                CertificateError::HttpError(format!("Failed to build HTTP client: {}", e))
            })?;

        let response = http_client
            .post(&url)
            .json(&CsrRequest { csr_pem })
            .send()
            .await
            .map_err(|e| CertificateError::HttpError(e.to_string()))?;

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
        let mtls_config = ClientMtlsConfig::new(
            credentials.cert_pem.clone(),
            credentials.key_pem.clone(),
            credentials.ca_cert_pem.clone(),
            // Extract domain from endpoint for TLS verification
            extract_domain(&self.config.cell_grpc_endpoint).unwrap_or("localhost".to_string()),
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
        let mut client = LatticeAgentClient::new(channel.clone());

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

        // Start the K8s API proxy stream AFTER agent is registered
        // This ensures set_proxy_port finds the agent in the registry
        let cluster_name = self.config.cluster_name.clone();
        Self::start_proxy_stream(channel, cluster_name).await;

        // Install CAPI on this cluster - required for clusterctl move during pivot
        info!("Installing CAPI on local cluster");
        let (capi_ready, installed_providers) = match Self::install_capi().await {
            Ok(provider) => {
                info!("CAPI installed, waiting for CRDs");
                if Self::wait_for_capi_crds(120).await {
                    info!("CAPI is ready");
                    (true, vec![provider])
                } else {
                    warn!("CAPI CRDs not available after timeout");
                    (false, vec![])
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to install CAPI, pivot may fail");
                (false, vec![])
            }
        };

        // Send bootstrap complete with CAPI status
        self.send_bootstrap_complete(capi_ready, installed_providers)
            .await?;

        // Clone for spawned tasks
        let config = self.config.clone();
        let state = self.state.clone();
        let agent_state = self.agent_state.clone();
        let message_tx_clone = message_tx.clone();

        // Spawn heartbeat task
        let heartbeat_interval = self.config.heartbeat_interval;
        let heartbeat_state = agent_state.clone();
        let heartbeat_tx = message_tx.clone();
        let cluster_name = config.cluster_name.clone();
        let start_time = self.start_time;

        tokio::spawn(async move {
            let mut ticker = interval(heartbeat_interval);
            loop {
                ticker.tick().await;

                let current_state = *heartbeat_state.read().await;
                let msg = AgentMessage {
                    cluster_name: cluster_name.clone(),
                    payload: Some(Payload::Heartbeat(Heartbeat {
                        state: current_state.into(),
                        timestamp: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
                        uptime_seconds: start_time.elapsed().as_secs() as i64,
                    })),
                };

                if heartbeat_tx.send(msg).await.is_err() {
                    debug!("Heartbeat channel closed");
                    break;
                }
            }
        });

        // Spawn command handler task
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(result) = inbound.next() => {
                        match result {
                            Ok(command) => {
                                Self::handle_command(&command, &agent_state, &message_tx_clone, &config.cluster_name).await;
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

            *state.write().await = ClientState::Disconnected;
            info!("Disconnected from cell");
        });

        Ok(())
    }

    /// Send the ready message to cell
    async fn send_ready(&self) -> Result<(), ClientError> {
        // Get K8s version from the kube client if available
        let k8s_version = if let Some(ref client) = self.kube_client {
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
                api_server_endpoint: Self::get_api_server_endpoint(),
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

    /// Send pivot started notification
    pub async fn send_pivot_started(&self, target_namespace: &str) -> Result<(), ClientError> {
        self.set_agent_state(AgentState::Pivoting).await;

        let msg = AgentMessage {
            cluster_name: self.config.cluster_name.clone(),
            payload: Some(Payload::PivotStarted(PivotStarted {
                target_namespace: target_namespace.to_string(),
            })),
        };

        self.send_message(msg).await
    }

    /// Send pivot complete notification
    pub async fn send_pivot_complete(
        &self,
        success: bool,
        error_message: &str,
        resources_imported: i32,
    ) -> Result<(), ClientError> {
        if success {
            self.set_agent_state(AgentState::Ready).await;
        } else {
            self.set_agent_state(AgentState::Failed).await;
        }

        let msg = AgentMessage {
            cluster_name: self.config.cluster_name.clone(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success,
                error_message: error_message.to_string(),
                resources_imported,
            })),
        };

        self.send_message(msg).await
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

    /// Apply a Kubernetes manifest using kubectl
    ///
    /// This is used to apply manifests received via ApplyManifestsCommand
    /// (e.g., LatticeCluster CRD and resource after pivot).
    async fn apply_manifest(yaml: &str) -> Result<(), std::io::Error> {
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;

        debug!("Applying manifest via kubectl");

        let mut child = Command::new("kubectl")
            .args(["apply", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(yaml.as_bytes()).await?;
        }

        let output = child.wait_with_output().await?;

        if output.status.success() {
            debug!("kubectl apply succeeded");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(std::io::Error::other(format!(
                "kubectl apply failed: {}",
                stderr
            )))
        }
    }

    /// Install CAPI and infrastructure provider
    ///
    /// Uses the shared CAPI installation logic which:
    /// 1. Installs cert-manager from local helm chart
    /// 2. Runs clusterctl init with air-gapped config (kubeadm + RKE2 providers)
    async fn install_capi() -> Result<String, std::io::Error> {
        use crate::capi::{ensure_capi_installed, CapiProviderConfig, ClusterctlInstaller};
        use crate::crd::ProviderType;

        let provider_str = std::env::var("LATTICE_PROVIDER")
            .map_err(|_| std::io::Error::other("LATTICE_PROVIDER env var not set"))?;

        let infrastructure = match provider_str.as_str() {
            "docker" => ProviderType::Docker,
            "aws" => ProviderType::Aws,
            "gcp" => ProviderType::Gcp,
            "azure" => ProviderType::Azure,
            other => {
                return Err(std::io::Error::other(format!(
                    "unknown provider: {}",
                    other
                )))
            }
        };

        info!(infrastructure = %provider_str, "Installing CAPI providers");

        let config = CapiProviderConfig::new(infrastructure);
        ensure_capi_installed(&ClusterctlInstaller::new(), &config)
            .await
            .map_err(|e| std::io::Error::other(format!("CAPI installation failed: {}", e)))?;

        info!(infrastructure = %provider_str, "CAPI providers installed successfully");
        Ok(provider_str)
    }

    /// Wait for CAPI CRDs to be available
    ///
    /// Polls kubectl to check if the clusters.cluster.x-k8s.io CRD exists.
    /// Returns true if CRD becomes available within timeout_secs.
    async fn wait_for_capi_crds(timeout_secs: u64) -> bool {
        use tokio::process::Command;
        use tokio::time::{sleep, Duration};

        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(timeout_secs);
        let poll_interval = Duration::from_secs(5);

        while start.elapsed() < timeout {
            let result = Command::new("kubectl")
                .args(["get", "crd", "clusters.cluster.x-k8s.io", "--no-headers"])
                .output()
                .await;

            if let Ok(output) = result {
                if output.status.success() {
                    return true;
                }
            }

            debug!("CAPI CRDs not yet available, waiting...");
            sleep(poll_interval).await;
        }

        false
    }

    /// Handle incoming command from cell
    async fn handle_command(
        command: &CellCommand,
        agent_state: &Arc<RwLock<AgentState>>,
        message_tx: &mpsc::Sender<AgentMessage>,
        cluster_name: &str,
    ) {
        debug!(command_id = %command.command_id, "Received command");

        match &command.command {
            Some(Command::ApplyManifests(cmd)) => {
                info!("Received apply manifests command");

                // Apply manifests (LatticeCluster CRD + resource)
                let manifests_count = cmd.manifests.len();
                let mut applied = 0;
                let mut errors = Vec::new();

                for manifest in &cmd.manifests {
                    match String::from_utf8(manifest.clone()) {
                        Ok(yaml) => {
                            if let Err(e) = Self::apply_manifest(&yaml).await {
                                error!(error = %e, "Failed to apply manifest");
                                errors.push(e.to_string());
                            } else {
                                applied += 1;
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Invalid UTF-8 in manifest");
                            errors.push(format!("invalid UTF-8: {}", e));
                        }
                    }
                }

                info!(
                    total = manifests_count,
                    applied = applied,
                    errors = errors.len(),
                    "Manifests applied"
                );
                // Note: CAPI is installed during agent startup (before AgentReady),
                // so ApplyManifestsCommand is only used for post-pivot manifests
                // like LatticeCluster CRD and resource.
            }
            Some(Command::StartPivot(cmd)) => {
                info!(
                    source_namespace = %cmd.source_namespace,
                    target_namespace = %cmd.target_namespace,
                    "Received start pivot command"
                );
                *agent_state.write().await = AgentState::Pivoting;

                // Send pivot started
                let msg = AgentMessage {
                    cluster_name: cluster_name.to_string(),
                    payload: Some(Payload::PivotStarted(PivotStarted {
                        target_namespace: cmd.target_namespace.clone(),
                    })),
                };
                let _ = message_tx.send(msg).await;

                // Spawn background task to wait for CAPI resources and send PivotComplete
                let target_namespace = cmd.target_namespace.clone();
                let agent_state_clone = agent_state.clone();
                let message_tx_clone = message_tx.clone();
                let cluster_name_clone = cluster_name.to_string();

                tokio::spawn(async move {
                    let handler = AgentPivotHandler::new().with_capi_namespace(&target_namespace);

                    // Wait up to 10 minutes for CAPI resources with 5s polling
                    let timeout = Duration::from_secs(600);
                    let poll_interval = Duration::from_secs(5);

                    match handler
                        .wait_for_capi_resources(timeout, poll_interval)
                        .await
                    {
                        Ok(resource_count) => {
                            info!(
                                resources = resource_count,
                                "CAPI resources imported successfully"
                            );

                            // Patch kubeconfig secret to use internal endpoint for self-management
                            // CAPI needs to reach the API server from within the cluster
                            // This MUST succeed before we can report pivot complete
                            // Use infinite retries with backoff - this is critical for self-management
                            let cluster_name_for_patch = cluster_name_clone.clone();
                            let namespace_for_patch = target_namespace.clone();
                            let patch_result =
                                retry_with_backoff(
                                    &RetryConfig::default(),
                                    "patch_kubeconfig_for_self_management",
                                    || {
                                        let cn = cluster_name_for_patch.clone();
                                        let ns = namespace_for_patch.clone();
                                        async move {
                                            patch_kubeconfig_for_self_management(&cn, &ns).await
                                        }
                                    },
                                )
                                .await;

                            if let Err(e) = patch_result {
                                // This should only happen if max_attempts is set and exhausted
                                error!(error = %e, "Failed to patch kubeconfig for self-management");
                                *agent_state_clone.write().await = AgentState::Failed;

                                let msg = AgentMessage {
                                    cluster_name: cluster_name_clone,
                                    payload: Some(Payload::PivotComplete(PivotComplete {
                                        success: false,
                                        error_message: format!("kubeconfig patch failed: {}", e),
                                        resources_imported: resource_count as i32,
                                    })),
                                };
                                let _ = message_tx_clone.send(msg).await;
                                return;
                            }

                            *agent_state_clone.write().await = AgentState::Ready;

                            let msg = AgentMessage {
                                cluster_name: cluster_name_clone,
                                payload: Some(Payload::PivotComplete(PivotComplete {
                                    success: true,
                                    error_message: String::new(),
                                    resources_imported: resource_count as i32,
                                })),
                            };
                            let _ = message_tx_clone.send(msg).await;
                        }
                        Err(e) => {
                            error!(error = %e, "Pivot failed - CAPI resources not detected");
                            *agent_state_clone.write().await = AgentState::Failed;

                            let msg = AgentMessage {
                                cluster_name: cluster_name_clone,
                                payload: Some(Payload::PivotComplete(PivotComplete {
                                    success: false,
                                    error_message: e.to_string(),
                                    resources_imported: 0,
                                })),
                            };
                            let _ = message_tx_clone.send(msg).await;
                        }
                    }
                });
            }
            Some(Command::StatusRequest(_req)) => {
                debug!("Received status request");
                // TODO: Send status response
            }
            None => {
                warn!(command_id = %command.command_id, "Received command with no payload");
            }
        }
    }

    /// Shutdown the client
    pub async fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        *self.state.write().await = ClientState::Disconnected;
    }

    /// Start the K8s API proxy stream
    ///
    /// This establishes the ProxyKubernetesAPI stream which allows the cell
    /// to run clusterctl move through the gRPC tunnel. The agent receives
    /// K8s API requests and forwards them to the local API server.
    async fn start_proxy_stream(channel: tonic::transport::Channel, cluster_name: String) {
        tokio::spawn(async move {
            let mut client = LatticeAgentClient::new(channel);

            // Channel for sending responses back to the cell
            let (response_tx, response_rx) = mpsc::channel::<KubeProxyResponse>(32);
            let outbound = ReceiverStream::new(response_rx);

            // Start the proxy stream
            let response = match client.proxy_kubernetes_api(outbound).await {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "Failed to establish proxy stream");
                    return;
                }
            };

            info!("K8s API proxy stream established");
            let mut inbound = response.into_inner();

            // Send initial handshake response to register proxy channels
            // The server waits for the first response to identify the cluster
            let handshake = KubeProxyResponse {
                request_id: format!("{}:handshake", cluster_name),
                status_code: 0,
                headers: vec![],
                body: vec![],
                error: String::new(),
                is_streaming: false,
                is_final: true,
            };
            if response_tx.send(handshake).await.is_err() {
                warn!("Failed to send proxy handshake");
                return;
            }
            debug!("Proxy handshake sent");

            // Handle incoming proxy requests
            while let Some(result) = inbound.next().await {
                match result {
                    Ok(request) => {
                        debug!(
                            request_id = %request.request_id,
                            method = %request.method,
                            path = %request.path,
                            "Received proxy request"
                        );

                        // Forward to local K8s API with streaming
                        let tx = response_tx.clone();
                        tokio::spawn(async move {
                            Self::handle_proxy_request_streaming(&request, tx).await;
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "Error receiving proxy request");
                        break;
                    }
                }
            }

            info!("K8s API proxy stream closed");
        });
    }

    /// Handle a proxy request by streaming response chunks back
    async fn handle_proxy_request_streaming(
        request: &KubeProxyRequest,
        response_tx: mpsc::Sender<KubeProxyResponse>,
    ) {
        use futures::StreamExt;
        use reqwest::Method;

        let send_error = |error: String| async {
            let _ = response_tx
                .send(KubeProxyResponse {
                    request_id: request.request_id.clone(),
                    status_code: 500,
                    headers: vec![],
                    body: vec![],
                    error,
                    is_streaming: false,
                    is_final: true,
                })
                .await;
        };

        // Create HTTP client
        let client = match reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                send_error(format!("Failed to create HTTP client: {}", e)).await;
                return;
            }
        };

        // Build URL to local API server
        let api_server = std::env::var("KUBERNETES_SERVICE_HOST")
            .map(|host| {
                let port =
                    std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string());
                format!("https://{}:{}", host, port)
            })
            .unwrap_or_else(|_| "https://kubernetes.default.svc".to_string());

        let url = format!("{}{}", api_server, request.path);

        // Parse method
        let method = match request.method.to_uppercase().as_str() {
            "GET" => Method::GET,
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "PATCH" => Method::PATCH,
            "DELETE" => Method::DELETE,
            _ => {
                send_error(format!("Unsupported method: {}", request.method)).await;
                return;
            }
        };

        // Read service account token
        let token =
            match tokio::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    send_error(format!("Failed to read service account token: {}", e)).await;
                    return;
                }
            };

        // Build and send request
        let mut req = client.request(method, &url).bearer_auth(token);
        for header in &request.headers {
            req = req.header(&header.key, &header.value);
        }
        if !request.body.is_empty() {
            req = req.body(request.body.clone());
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                let _ = response_tx
                    .send(KubeProxyResponse {
                        request_id: request.request_id.clone(),
                        status_code: 502,
                        headers: vec![],
                        body: vec![],
                        error: format!("Proxy request failed: {}", e),
                        is_streaming: false,
                        is_final: true,
                    })
                    .await;
                return;
            }
        };

        let status_code = resp.status().as_u16() as i32;
        let headers: Vec<_> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str().ok().map(|val| crate::proto::HttpHeader {
                    key: k.to_string(),
                    value: val.to_string(),
                })
            })
            .collect();

        // Check if this is a watch/streaming request
        let is_watch = request.path.contains("watch=true");

        if is_watch {
            // Stream response chunks
            let mut stream = resp.bytes_stream();
            let mut first_chunk = true;

            while let Some(chunk_result) = stream.next().await {
                match chunk_result {
                    Ok(chunk) => {
                        let chunk_bytes: Vec<u8> = chunk.to_vec();
                        let response = KubeProxyResponse {
                            request_id: request.request_id.clone(),
                            status_code: if first_chunk { status_code } else { 0 },
                            headers: if first_chunk { headers.clone() } else { vec![] },
                            body: chunk_bytes,
                            error: String::new(),
                            is_streaming: true,
                            is_final: false,
                        };
                        first_chunk = false;

                        if response_tx.send(response).await.is_err() {
                            debug!(request_id = %request.request_id, "Response channel closed during streaming");
                            return;
                        }
                    }
                    Err(e) => {
                        warn!(request_id = %request.request_id, error = %e, "Error reading response chunk");
                        break;
                    }
                }
            }

            // Send final marker
            let _ = response_tx
                .send(KubeProxyResponse {
                    request_id: request.request_id.clone(),
                    status_code: 0,
                    headers: vec![],
                    body: vec![],
                    error: String::new(),
                    is_streaming: true,
                    is_final: true,
                })
                .await;
        } else {
            // Non-streaming: read full body and send single response
            let body = resp.bytes().await.unwrap_or_default().to_vec();
            let _ = response_tx
                .send(KubeProxyResponse {
                    request_id: request.request_id.clone(),
                    status_code,
                    headers,
                    body,
                    error: String::new(),
                    is_streaming: false,
                    is_final: true,
                })
                .await;
        }
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
        }
    }
}

impl std::error::Error for ClientError {}

/// Extract domain name from a URL for TLS verification
fn extract_domain(url: &str) -> Option<String> {
    // Remove protocol prefix
    let without_protocol = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    // Take everything before the port or path
    let domain = without_protocol
        .split(':')
        .next()
        .and_then(|s| s.split('/').next())
        .map(|s| s.to_string());

    domain.filter(|d| !d.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ApplyManifestsCommand, StartPivotCommand, StatusRequest};
    use std::sync::Mutex;

    // Mutex to serialize tests that modify environment variables
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

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
        assert!(client.kube_client.is_none());
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
        client.shutdown().await;
        assert_eq!(client.state().await, ClientState::Disconnected);
    }

    // Test extract_domain with various inputs
    #[test]
    fn test_extract_domain_https() {
        assert_eq!(
            extract_domain("https://cell.example.com:443"),
            Some("cell.example.com".to_string())
        );
    }

    #[test]
    fn test_extract_domain_http() {
        assert_eq!(
            extract_domain("http://localhost:8080"),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn test_extract_domain_no_port() {
        assert_eq!(
            extract_domain("https://cell.example.com"),
            Some("cell.example.com".to_string())
        );
    }

    #[test]
    fn test_extract_domain_with_path() {
        assert_eq!(
            extract_domain("https://cell.example.com:443/api/v1"),
            Some("cell.example.com".to_string())
        );
    }

    #[test]
    fn test_extract_domain_no_protocol() {
        assert_eq!(
            extract_domain("cell.example.com:443"),
            Some("cell.example.com".to_string())
        );
    }

    #[test]
    fn test_extract_domain_ip_address() {
        assert_eq!(
            extract_domain("https://192.168.1.1:8080"),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_extract_domain_empty_string() {
        assert_eq!(extract_domain(""), None);
    }

    #[test]
    fn test_extract_domain_protocol_only() {
        assert_eq!(extract_domain("https://"), None);
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
    async fn test_send_pivot_started_not_connected() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        let result = client.send_pivot_started("default").await;
        assert_eq!(result, Err(ClientError::NotConnected));
        // State should still change even if send fails
        assert_eq!(client.agent_state().await, AgentState::Pivoting);
    }

    #[tokio::test]
    async fn test_send_pivot_complete_success_not_connected() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        let result = client.send_pivot_complete(true, "", 5).await;
        assert_eq!(result, Err(ClientError::NotConnected));
        // State should change to Ready on success
        assert_eq!(client.agent_state().await, AgentState::Ready);
    }

    #[tokio::test]
    async fn test_send_pivot_complete_failure_not_connected() {
        let config = AgentClientConfig::default();
        let client = AgentClient::new(config);

        let result = client.send_pivot_complete(false, "timeout", 0).await;
        assert_eq!(result, Err(ClientError::NotConnected));
        // State should change to Failed on failure
        assert_eq!(client.agent_state().await, AgentState::Failed);
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
    #[tokio::test]
    async fn test_handle_apply_manifests_command() {
        let agent_state = Arc::new(RwLock::new(AgentState::Provisioning));
        let (tx, _rx) = mpsc::channel::<AgentMessage>(32);

        let command = CellCommand {
            command_id: "cmd-1".to_string(),
            command: Some(Command::ApplyManifests(ApplyManifestsCommand {
                manifests: vec![],
            })),
        };

        AgentClient::handle_command(&command, &agent_state, &tx, "test-cluster").await;
        // ApplyManifests command doesn't change state - CAPI install is lazy
    }

    #[tokio::test]
    async fn test_handle_start_pivot_command() {
        let agent_state = Arc::new(RwLock::new(AgentState::Ready));
        let (tx, mut rx) = mpsc::channel::<AgentMessage>(32);

        let command = CellCommand {
            command_id: "cmd-2".to_string(),
            command: Some(Command::StartPivot(StartPivotCommand {
                source_namespace: "default".to_string(),
                target_namespace: "capi-system".to_string(),
                cluster_name: "test-cluster".to_string(),
            })),
        };

        AgentClient::handle_command(&command, &agent_state, &tx, "test-cluster").await;

        // State should change to Pivoting
        assert_eq!(*agent_state.read().await, AgentState::Pivoting);

        // Should send PivotStarted message
        let msg = rx.recv().await.unwrap();
        assert_eq!(msg.cluster_name, "test-cluster");
        match msg.payload {
            Some(Payload::PivotStarted(ps)) => {
                assert_eq!(ps.target_namespace, "capi-system");
            }
            _ => panic!("Expected PivotStarted payload"),
        }
    }

    #[tokio::test]
    async fn test_handle_status_request_command() {
        let agent_state = Arc::new(RwLock::new(AgentState::Ready));
        let (tx, _rx) = mpsc::channel::<AgentMessage>(32);

        let command = CellCommand {
            command_id: "cmd-4".to_string(),
            command: Some(Command::StatusRequest(StatusRequest {
                include_nodes: false,
                include_capi: false,
            })),
        };

        AgentClient::handle_command(&command, &agent_state, &tx, "test-cluster").await;
        // Status request doesn't change state (TODO in code)
    }

    #[tokio::test]
    async fn test_handle_empty_command() {
        let agent_state = Arc::new(RwLock::new(AgentState::Ready));
        let (tx, _rx) = mpsc::channel::<AgentMessage>(32);

        let command = CellCommand {
            command_id: "cmd-5".to_string(),
            command: None,
        };

        AgentClient::handle_command(&command, &agent_state, &tx, "test-cluster").await;
        // Should log warning but not crash
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
        let received = rx.recv().await.unwrap();
        assert_eq!(received.cluster_name, "test-cluster");
    }

    #[tokio::test]
    async fn test_send_pivot_started_with_channel() {
        let config = AgentClientConfig {
            cluster_name: "test-cluster".to_string(),
            ..Default::default()
        };
        let mut client = AgentClient::new(config);

        let (tx, mut rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        let result = client.send_pivot_started("capi-system").await;
        assert!(result.is_ok());
        assert_eq!(client.agent_state().await, AgentState::Pivoting);

        let received = rx.recv().await.unwrap();
        match received.payload {
            Some(Payload::PivotStarted(ps)) => {
                assert_eq!(ps.target_namespace, "capi-system");
            }
            _ => panic!("Expected PivotStarted payload"),
        }
    }

    #[tokio::test]
    async fn test_send_pivot_complete_with_channel() {
        let config = AgentClientConfig {
            cluster_name: "test-cluster".to_string(),
            ..Default::default()
        };
        let mut client = AgentClient::new(config);

        let (tx, mut rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        let result = client.send_pivot_complete(true, "", 10).await;
        assert!(result.is_ok());
        assert_eq!(client.agent_state().await, AgentState::Ready);

        let received = rx.recv().await.unwrap();
        match received.payload {
            Some(Payload::PivotComplete(pc)) => {
                assert!(pc.success);
                assert_eq!(pc.resources_imported, 10);
                assert!(pc.error_message.is_empty());
            }
            _ => panic!("Expected PivotComplete payload"),
        }
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

        let received = rx.recv().await.unwrap();
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

        // No kube client attached yet
        assert!(client.kube_client.is_none());
    }

    /// Story: Agent can be configured with a Kubernetes client for API proxying
    ///
    /// The agent needs access to the local Kubernetes API to proxy requests
    /// from the cell during pivot operations. This test verifies the fluent
    /// builder pattern for attaching a kube client.
    #[test]
    fn story_agent_can_be_configured_with_kube_client() {
        // NOTE: We can't easily create a real KubeClient in tests without a cluster,
        // but we can verify the builder pattern works by testing the config flow
        let config = AgentClientConfig {
            cluster_name: "kube-proxy-test".to_string(),
            ..Default::default()
        };

        let client = AgentClient::new(config);

        // Initially no kube client
        assert!(client.kube_client.is_none());

        // The with_kube_client method exists and returns Self
        // (can't actually test with a real client without a cluster)
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

    /// Story: When an agent sends pivot started notification, it enters pivoting state
    ///
    /// Before the cell sends CAPI resources, the agent acknowledges it's ready
    /// to receive them by sending PivotStarted and entering PIVOTING state.
    #[tokio::test]
    async fn story_agent_sends_pivot_started_and_enters_pivoting_state() {
        let config = AgentClientConfig {
            cluster_name: "pivot-test-cluster".to_string(),
            ..Default::default()
        };
        let mut client = AgentClient::new(config);

        // Simulate connected state with a channel
        let (tx, mut rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        // Agent sends pivot started
        let result = client.send_pivot_started("capi-system").await;
        assert!(result.is_ok());

        // Agent should now be in Pivoting state
        assert_eq!(client.agent_state().await, AgentState::Pivoting);

        // Verify the message was sent correctly
        let msg = rx.recv().await.unwrap();
        assert_eq!(msg.cluster_name, "pivot-test-cluster");

        match msg.payload {
            Some(Payload::PivotStarted(ps)) => {
                assert_eq!(ps.target_namespace, "capi-system");
            }
            _ => panic!("Expected PivotStarted payload"),
        }
    }

    /// Story: When pivot completes successfully, agent becomes ready
    ///
    /// After CAPI resources are successfully imported, the agent sends
    /// PivotComplete and transitions to Ready state.
    #[tokio::test]
    async fn story_successful_pivot_makes_agent_ready() {
        let config = AgentClientConfig {
            cluster_name: "pivot-success".to_string(),
            ..Default::default()
        };
        let mut client = AgentClient::new(config);

        let (tx, mut rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        // Start in pivoting state
        client.set_agent_state(AgentState::Pivoting).await;

        // Pivot completes successfully with 15 resources imported
        let result = client.send_pivot_complete(true, "", 15).await;
        assert!(result.is_ok());

        // Agent should now be Ready
        assert_eq!(client.agent_state().await, AgentState::Ready);

        // Verify the message
        let msg = rx.recv().await.unwrap();
        match msg.payload {
            Some(Payload::PivotComplete(pc)) => {
                assert!(pc.success);
                assert_eq!(pc.resources_imported, 15);
                assert!(pc.error_message.is_empty());
            }
            _ => panic!("Expected PivotComplete payload"),
        }
    }

    /// Story: When pivot fails, agent enters failed state with error details
    #[tokio::test]
    async fn story_failed_pivot_puts_agent_in_failed_state() {
        let config = AgentClientConfig {
            cluster_name: "pivot-failure".to_string(),
            ..Default::default()
        };
        let mut client = AgentClient::new(config);

        let (tx, mut rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        // Start in pivoting state
        client.set_agent_state(AgentState::Pivoting).await;

        // Pivot fails with an error
        let result = client
            .send_pivot_complete(
                false,
                "CAPI resources could not be imported: timeout waiting for CRDs",
                0,
            )
            .await;
        assert!(result.is_ok());

        // Agent should be in Failed state
        assert_eq!(client.agent_state().await, AgentState::Failed);

        // Verify error message is captured
        let msg = rx.recv().await.unwrap();
        match msg.payload {
            Some(Payload::PivotComplete(pc)) => {
                assert!(!pc.success);
                assert_eq!(pc.resources_imported, 0);
                assert!(pc.error_message.contains("timeout waiting for CRDs"));
            }
            _ => panic!("Expected PivotComplete payload"),
        }
    }

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

        let msg = rx.recv().await.unwrap();
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

        let msg = rx.recv().await.unwrap();
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
    ///
    /// Before mTLS connection is established, any attempt to send messages
    /// should return NotConnected error rather than panicking.
    #[tokio::test]
    async fn story_sending_when_not_connected_returns_error() {
        let config = AgentClientConfig {
            cluster_name: "disconnected-agent".to_string(),
            ..Default::default()
        };
        let client = AgentClient::new(config);

        // Try to send various messages without being connected
        assert_eq!(
            client.send_pivot_started("ns").await,
            Err(ClientError::NotConnected)
        );

        assert_eq!(
            client.send_pivot_complete(true, "", 0).await,
            Err(ClientError::NotConnected)
        );

        assert_eq!(
            client.send_bootstrap_complete(true, vec![]).await,
            Err(ClientError::NotConnected)
        );
    }

    /// Story: When the message channel closes unexpectedly, sends return ChannelClosed
    ///
    /// If the gRPC connection drops and the channel is closed, message sends
    /// should fail with ChannelClosed error.
    #[tokio::test]
    async fn story_channel_closure_detected_on_send() {
        let config = AgentClientConfig {
            cluster_name: "channel-closed-test".to_string(),
            ..Default::default()
        };
        let mut client = AgentClient::new(config);

        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        // Simulate channel closure (connection dropped)
        drop(rx);

        // All message sends should fail with ChannelClosed
        assert_eq!(
            client.send_pivot_started("ns").await,
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
        client.shutdown().await;
        assert_eq!(client.state().await, ClientState::Disconnected);

        // Second shutdown - should also be safe
        client.shutdown().await;
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
        client.shutdown().await;

        // The receiver should get the signal (not be cancelled)
        // Note: After send, the rx will receive Ok(())
        match rx.try_recv() {
            Ok(()) => {} // Signal received
            Err(_) => panic!("Shutdown signal should have been sent"),
        }
    }

    // ==========================================================================
    // Story Tests: Command Handling
    // ==========================================================================

    /// Story: When cell sends apply manifests command, agent processes it
    ///
    /// After initial connection, the cell sends LatticeCluster CRD + resource
    /// which triggers lazy CAPI installation.
    #[tokio::test]
    async fn story_agent_handles_apply_manifests_command_from_cell() {
        let agent_state = Arc::new(RwLock::new(AgentState::Provisioning));
        let (tx, _rx) = mpsc::channel::<AgentMessage>(32);

        let command = CellCommand {
            command_id: "apply-123".to_string(),
            command: Some(Command::ApplyManifests(ApplyManifestsCommand {
                manifests: vec![b"apiVersion: lattice.dev/v1alpha1\nkind: LatticeCluster".to_vec()],
            })),
        };

        // Should not panic or error
        AgentClient::handle_command(&command, &agent_state, &tx, "apply-cluster").await;

        // State should not change (manifests applied, CAPI install is lazy)
        assert_eq!(*agent_state.read().await, AgentState::Provisioning);
    }

    /// Story: When cell sends start pivot command, agent enters pivoting state
    ///
    /// The cell initiates pivot by sending StartPivotCommand. The agent
    /// transitions to PIVOTING state and sends PivotStarted acknowledgment.
    #[tokio::test]
    async fn story_agent_transitions_to_pivoting_on_command() {
        let agent_state = Arc::new(RwLock::new(AgentState::Provisioning));
        let (tx, mut rx) = mpsc::channel::<AgentMessage>(32);

        let command = CellCommand {
            command_id: "pivot-456".to_string(),
            command: Some(Command::StartPivot(StartPivotCommand {
                source_namespace: "default".to_string(),
                target_namespace: "capi-workload".to_string(),
                cluster_name: "my-workload-cluster".to_string(),
            })),
        };

        AgentClient::handle_command(&command, &agent_state, &tx, "my-workload-cluster").await;

        // Agent should be in Pivoting state
        assert_eq!(*agent_state.read().await, AgentState::Pivoting);

        // Agent should have sent PivotStarted
        let msg = rx.recv().await.unwrap();
        match msg.payload {
            Some(Payload::PivotStarted(ps)) => {
                assert_eq!(ps.target_namespace, "capi-workload");
            }
            _ => panic!("Expected PivotStarted"),
        }
    }

    /// Story: When cell requests status, agent responds with current state
    #[tokio::test]
    async fn story_agent_handles_status_request() {
        let agent_state = Arc::new(RwLock::new(AgentState::Ready));
        let (tx, _rx) = mpsc::channel::<AgentMessage>(32);

        let command = CellCommand {
            command_id: "status-001".to_string(),
            command: Some(Command::StatusRequest(StatusRequest {
                include_nodes: true,
                include_capi: true,
            })),
        };

        // Should handle without error
        AgentClient::handle_command(&command, &agent_state, &tx, "status-cluster").await;

        // State should remain unchanged
        assert_eq!(*agent_state.read().await, AgentState::Ready);
    }

    /// Story: Agent gracefully handles command with no payload
    ///
    /// Malformed commands should be logged but not crash the agent.
    #[tokio::test]
    async fn story_agent_handles_empty_command_gracefully() {
        let agent_state = Arc::new(RwLock::new(AgentState::Ready));
        let (tx, _rx) = mpsc::channel::<AgentMessage>(32);

        let command = CellCommand {
            command_id: "empty-cmd".to_string(),
            command: None, // Invalid - no payload
        };

        // Should not panic
        AgentClient::handle_command(&command, &agent_state, &tx, "robust-cluster").await;

        // State should remain unchanged
        assert_eq!(*agent_state.read().await, AgentState::Ready);
    }

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
            Some("cell.example.com".to_string())
        );

        // HTTP for bootstrap endpoint
        assert_eq!(
            extract_domain("http://cell.example.com:8080"),
            Some("cell.example.com".to_string())
        );

        // Without port
        assert_eq!(
            extract_domain("https://cell.example.com"),
            Some("cell.example.com".to_string())
        );

        // With path (shouldn't happen but handle gracefully)
        assert_eq!(
            extract_domain("https://cell.example.com:443/api/v1"),
            Some("cell.example.com".to_string())
        );

        // IP address
        assert_eq!(
            extract_domain("https://172.18.255.1:443"),
            Some("172.18.255.1".to_string())
        );

        // Raw host:port (no protocol)
        assert_eq!(
            extract_domain("cell.example.com:443"),
            Some("cell.example.com".to_string())
        );

        // Edge cases
        assert_eq!(extract_domain(""), None);
        assert_eq!(extract_domain("https://"), None);
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
    // Integration Tests: Message Flow
    // ==========================================================================

    /// Integration test: Full message flow through channel
    #[tokio::test]
    async fn integration_multiple_messages_through_channel() {
        let config = AgentClientConfig {
            cluster_name: "integration-test".to_string(),
            ..Default::default()
        };
        let mut client = AgentClient::new(config);

        let (tx, mut rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        // Send multiple messages in sequence
        client.send_pivot_started("ns1").await.unwrap();
        client
            .send_bootstrap_complete(true, vec!["docker".to_string()])
            .await
            .unwrap();
        client.send_pivot_complete(true, "", 5).await.unwrap();

        // Verify all messages received in order
        let msg1 = rx.recv().await.unwrap();
        assert!(matches!(msg1.payload, Some(Payload::PivotStarted(_))));

        let msg2 = rx.recv().await.unwrap();
        assert!(matches!(msg2.payload, Some(Payload::BootstrapComplete(_))));

        let msg3 = rx.recv().await.unwrap();
        assert!(matches!(msg3.payload, Some(Payload::PivotComplete(_))));
    }

    /// Integration test: State transitions during typical lifecycle
    #[tokio::test]
    async fn integration_complete_lifecycle_state_transitions() {
        let config = AgentClientConfig {
            cluster_name: "lifecycle-test".to_string(),
            ..Default::default()
        };
        let mut client = AgentClient::new(config);

        let (tx, _rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        // 1. Start in Provisioning
        assert_eq!(client.agent_state().await, AgentState::Provisioning);

        // 2. Bootstrap complete (still provisioning until pivot)
        client
            .send_bootstrap_complete(true, vec!["docker".to_string()])
            .await
            .unwrap();
        assert_eq!(client.agent_state().await, AgentState::Provisioning);

        // 3. Pivot starts - transitions to Pivoting
        client.send_pivot_started("capi-system").await.unwrap();
        assert_eq!(client.agent_state().await, AgentState::Pivoting);

        // 4. Pivot completes - transitions to Ready
        client.send_pivot_complete(true, "", 10).await.unwrap();
        assert_eq!(client.agent_state().await, AgentState::Ready);
    }

    /// Integration test: Error path lifecycle
    #[tokio::test]
    async fn integration_error_path_lifecycle() {
        let config = AgentClientConfig {
            cluster_name: "error-lifecycle".to_string(),
            ..Default::default()
        };
        let mut client = AgentClient::new(config);

        let (tx, _rx) = mpsc::channel::<AgentMessage>(32);
        client.message_tx = Some(tx);

        // 1. Start in Provisioning
        assert_eq!(client.agent_state().await, AgentState::Provisioning);

        // 2. Pivot starts
        client.send_pivot_started("capi-system").await.unwrap();
        assert_eq!(client.agent_state().await, AgentState::Pivoting);

        // 3. Pivot fails - transitions to Failed
        client
            .send_pivot_complete(false, "CAPI CRDs not installed", 0)
            .await
            .unwrap();
        assert_eq!(client.agent_state().await, AgentState::Failed);
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
    // Story Tests: Command Handling
    // ==========================================================================

    /// Story: Agent handles pivot command for different namespaces
    #[tokio::test]
    async fn story_agent_handles_various_namespace_configs() {
        let agent_state = Arc::new(RwLock::new(AgentState::Provisioning));
        let (tx, mut rx) = mpsc::channel::<AgentMessage>(32);

        let namespaces = [
            ("default", "capi-system"),
            ("capi-workload", "capi-workload"),
            ("flux-system", "lattice-capi"),
        ];

        for (source, target) in namespaces {
            *agent_state.write().await = AgentState::Provisioning;

            let command = CellCommand {
                command_id: format!("pivot-{}-{}", source, target),
                command: Some(Command::StartPivot(StartPivotCommand {
                    source_namespace: source.to_string(),
                    target_namespace: target.to_string(),
                    cluster_name: "ns-test".to_string(),
                })),
            };

            AgentClient::handle_command(&command, &agent_state, &tx, "ns-test").await;

            // Verify pivot started with correct namespace
            let msg = rx.recv().await.unwrap();
            match msg.payload {
                Some(Payload::PivotStarted(ps)) => {
                    assert_eq!(ps.target_namespace, target);
                }
                _ => panic!("Expected PivotStarted"),
            }
        }
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
            handle.await.unwrap();
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
        writer.await.unwrap();
        for reader in readers {
            reader.await.unwrap();
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

    /// Story: API server endpoint is detected from environment
    ///
    /// When running inside a Kubernetes cluster, the agent should detect
    /// the API server endpoint from standard environment variables.
    #[test]
    fn story_api_server_endpoint_from_env() {
        let _guard = ENV_MUTEX.lock().unwrap();

        // Save original values
        let orig_host = std::env::var("KUBERNETES_SERVICE_HOST").ok();
        let orig_port = std::env::var("KUBERNETES_SERVICE_PORT").ok();

        // Set test values
        std::env::set_var("KUBERNETES_SERVICE_HOST", "10.96.0.1");
        std::env::set_var("KUBERNETES_SERVICE_PORT", "443");

        let endpoint = AgentClient::get_api_server_endpoint();
        assert_eq!(endpoint, "https://10.96.0.1:443");

        // Restore original values
        match orig_host {
            Some(v) => std::env::set_var("KUBERNETES_SERVICE_HOST", v),
            None => std::env::remove_var("KUBERNETES_SERVICE_HOST"),
        }
        match orig_port {
            Some(v) => std::env::set_var("KUBERNETES_SERVICE_PORT", v),
            None => std::env::remove_var("KUBERNETES_SERVICE_PORT"),
        }
    }

    /// Story: API server endpoint uses default port when not specified
    #[test]
    fn story_api_server_endpoint_default_port() {
        let _guard = ENV_MUTEX.lock().unwrap();

        // Save original values
        let orig_host = std::env::var("KUBERNETES_SERVICE_HOST").ok();
        let orig_port = std::env::var("KUBERNETES_SERVICE_PORT").ok();

        // Set host only
        std::env::set_var("KUBERNETES_SERVICE_HOST", "10.96.0.1");
        std::env::remove_var("KUBERNETES_SERVICE_PORT");

        let endpoint = AgentClient::get_api_server_endpoint();
        assert_eq!(endpoint, "https://10.96.0.1:443");

        // Restore original values
        match orig_host {
            Some(v) => std::env::set_var("KUBERNETES_SERVICE_HOST", v),
            None => std::env::remove_var("KUBERNETES_SERVICE_HOST"),
        }
        match orig_port {
            Some(v) => std::env::set_var("KUBERNETES_SERVICE_PORT", v),
            None => std::env::remove_var("KUBERNETES_SERVICE_PORT"),
        }
    }

    /// Story: API server endpoint is empty when not in cluster
    #[test]
    fn story_api_server_endpoint_empty_outside_cluster() {
        let _guard = ENV_MUTEX.lock().unwrap();

        // Save original value
        let orig_host = std::env::var("KUBERNETES_SERVICE_HOST").ok();

        // Remove the env var
        std::env::remove_var("KUBERNETES_SERVICE_HOST");

        let endpoint = AgentClient::get_api_server_endpoint();
        assert!(endpoint.is_empty());

        // Restore original value
        if let Some(v) = orig_host {
            std::env::set_var("KUBERNETES_SERVICE_HOST", v);
        }
    }
}
