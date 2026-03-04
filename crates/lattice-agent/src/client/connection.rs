//! Connection establishment logic for the agent client.
//!
//! Contains mTLS connection setup, gRPC stream initialization,
//! and URL domain extraction.

use futures::StreamExt;
use tokio::sync::{mpsc, oneshot};
use tokio::time::interval;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Endpoint;
use tracing::{debug, error, info, warn};

use crate::commands::{self, CommandContext};
use crate::subtree::SubtreeSender;
use lattice_proto::lattice_agent_client::LatticeAgentClient;
use lattice_proto::{
    agent_message::Payload, grpc_max_message_size, AgentMessage, AgentState, Heartbeat,
};

use super::config::{
    CAPI_INSTALL_RETRY_DELAY, CAPI_INSTALL_TIMEOUT, DELETION_POLL_INTERVAL,
    GRPC_KEEP_ALIVE_TIMEOUT, HTTP2_KEEP_ALIVE_INTERVAL,
};
use super::{AgentClient, AgentCredentials, ClientError, ClientState};
use lattice_infra::ClientMtlsConfig;

impl AgentClient {
    /// Connect to the cell with mTLS using the provided credentials
    pub async fn connect_with_mtls(
        &mut self,
        credentials: &AgentCredentials,
    ) -> Result<(), ClientError> {
        *self.state.write().await = ClientState::Connecting;

        info!(endpoint = %self.config.cell_grpc_endpoint, "Connecting to cell with mTLS");

        // Build mTLS config
        let domain = extract_domain(&self.config.cell_grpc_endpoint)?;
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
            .keep_alive_timeout(GRPC_KEEP_ALIVE_TIMEOUT)
            .keep_alive_while_idle(true)
            .http2_keep_alive_interval(HTTP2_KEEP_ALIVE_INTERVAL)
            .tls_config(tls_config)
            .map_err(|e| ClientError::TlsError(e.to_string()))?
            .connect_lazy();

        self.start_streams(channel).await
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
    pub(super) async fn start_streams(
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
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        self.shutdown_tx = Some(shutdown_tx);

        // Start the control stream
        let outbound = ReceiverStream::new(message_rx);
        let response = client
            .stream_messages(outbound)
            .await
            .map_err(|e| ClientError::StreamFailed(e.to_string()))?;

        let inbound = response.into_inner();

        *self.state.write().await = ClientState::Connected;
        info!("Connected to cell");

        // Send ready message first to establish connection
        // This registers the agent on the server side
        self.send_ready().await?;

        // Install CAPI with retries, then send bootstrap complete
        let (capi_ready, installed_providers) = self.install_capi_with_retries().await?;
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

        // Spawn background tasks
        self.spawn_heartbeat_task(message_tx.clone());
        self.spawn_deletion_watcher_task(message_tx.clone());
        self.spawn_command_handler_task(inbound, shutdown_rx);

        Ok(())
    }

    /// Install CAPI on this cluster with up to 3 retry attempts.
    ///
    /// Each attempt has a timeout and waits for CRDs to become available.
    /// Returns `(capi_ready, installed_providers)` on success, or
    /// `ClientError::CapiInstallFailed` after all attempts are exhausted.
    async fn install_capi_with_retries(&self) -> Result<(bool, Vec<String>), ClientError> {
        info!("Installing CAPI on local cluster");

        let capi_install_timeout = CAPI_INSTALL_TIMEOUT;
        for attempt in 1..=3 {
            match tokio::time::timeout(capi_install_timeout, self.install_capi()).await {
                Ok(Ok(provider)) => {
                    info!("CAPI installed, waiting for CRDs");
                    if self.wait_for_capi_crds(120).await {
                        info!("CAPI is ready");
                        return Ok((true, vec![provider]));
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
                tokio::time::sleep(CAPI_INSTALL_RETRY_DELAY).await;
            }
        }

        Err(ClientError::CapiInstallFailed(
            "failed after 3 attempts - cluster cannot self-manage".to_string(),
        ))
    }

    /// Spawn the periodic heartbeat task that sends cluster health to the cell.
    ///
    /// Sends a `Heartbeat` message at `self.config.heartbeat_interval` containing
    /// the current agent state, timestamp, uptime, and cluster health.
    /// Sets `self.heartbeat_handle`.
    fn spawn_heartbeat_task(&mut self, message_tx: mpsc::Sender<AgentMessage>) {
        let heartbeat_interval = self.config.heartbeat_interval;
        let heartbeat_state = self.agent_state.clone();
        let cluster_name = self.config.cluster_name.clone();
        let start_time = self.start_time;
        let heartbeat_kube_provider = self.kube_provider.clone();

        self.heartbeat_handle = Some(tokio::spawn(async move {
            let mut ticker = interval(heartbeat_interval);
            loop {
                ticker.tick().await;

                let current_state = *heartbeat_state.read().await;
                let health =
                    crate::health::gather_cluster_health(heartbeat_kube_provider.as_ref()).await;

                // Compute spec/status hashes for state sync detection
                let (spec_hash, status_hash) =
                    compute_cluster_hashes(heartbeat_kube_provider.as_ref(), &cluster_name).await;

                let msg = AgentMessage {
                    cluster_name: cluster_name.clone(),
                    payload: Some(Payload::Heartbeat(Heartbeat {
                        state: current_state.into(),
                        timestamp: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
                        uptime_seconds: start_time.elapsed().as_secs() as i64,
                        health,
                        spec_hash,
                        status_hash,
                    })),
                };

                if message_tx.send(msg).await.is_err() {
                    debug!("Heartbeat channel closed");
                    break;
                }
            }
        }));
    }

    /// Spawn the deletion watcher task that detects cluster deletion and starts unpivot.
    ///
    /// Handles both runtime deletion (cluster deleted while agent is running) and
    /// crash recovery (cluster was being deleted when agent crashed/restarted).
    /// Polls every `DELETION_POLL_INTERVAL`. Sets `self.deletion_watcher_handle`.
    fn spawn_deletion_watcher_task(&mut self, message_tx: mpsc::Sender<AgentMessage>) {
        let deletion_provider = self.kube_provider.clone();

        self.deletion_watcher_handle = Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(DELETION_POLL_INTERVAL).await;

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
                        message_tx,
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
    }

    /// Spawn the command handler task that processes inbound commands from the cell.
    ///
    /// Reads commands from the inbound gRPC stream and dispatches them via
    /// `commands::handle_command`. On disconnect, cancels all active watch/exec
    /// sessions and resets pivot state if interrupted mid-pivot.
    /// Sets `self.command_handler_handle`.
    fn spawn_command_handler_task(
        &mut self,
        mut inbound: tonic::Streaming<lattice_proto::CellCommand>,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) {
        let state = self.state.clone();
        let agent_state = self.agent_state.clone();
        let watch_registry = self.watch_registry.clone();
        let exec_registry = self.exec_registry.clone();

        let command_ctx = CommandContext::new(
            self.config.cluster_name.clone(),
            self.message_tx
                .clone()
                .expect("message_tx set before spawn"),
            agent_state.clone(),
            watch_registry.clone(),
            exec_registry.clone(),
            self.forwarder.clone(),
            self.exec_forwarder.clone(),
            self.forwarded_exec_sessions.clone(),
            self.kube_provider.clone(),
        );

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
    }
}

/// Extract domain name from a URL for TLS verification
pub(super) fn extract_domain(endpoint: &str) -> Result<String, ClientError> {
    if endpoint.is_empty() {
        return Err(ClientError::InvalidEndpoint("URL is empty".to_string()));
    }
    // Ensure we have a scheme for url::Url to parse correctly
    let with_scheme = if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("https://{}", endpoint)
    };
    let parsed = url::Url::parse(&with_scheme)
        .map_err(|e| ClientError::InvalidEndpoint(format!("invalid URL '{}': {}", endpoint, e)))?;
    parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .map(|h| h.to_string())
        .ok_or_else(|| ClientError::InvalidEndpoint(format!("URL has no host: {}", endpoint)))
}

/// Compute SHA-256 hashes of this cluster's LatticeCluster spec and status.
///
/// Returns `(spec_hash, status_hash)` — empty vectors if the CRD can't be read
/// (best-effort, don't block heartbeats on hash failures).
async fn compute_cluster_hashes(
    kube_provider: &dyn crate::kube_client::KubeClientProvider,
    cluster_name: &str,
) -> (Vec<u8>, Vec<u8>) {
    let client = match kube_provider.create().await {
        Ok(c) => c,
        Err(_) => return (vec![], vec![]),
    };

    let api: kube::Api<lattice_common::crd::LatticeCluster> = kube::Api::all(client);
    let cluster = match api.get(cluster_name).await {
        Ok(c) => c,
        Err(_) => return (vec![], vec![]),
    };

    let spec_hash = match serde_json::to_vec(&cluster.spec) {
        Ok(json) => lattice_common::kube_utils::sha256(&json),
        Err(_) => vec![],
    };

    let status_hash = match cluster.status.as_ref() {
        Some(status) => match serde_json::to_vec(status) {
            Ok(json) => lattice_common::kube_utils::sha256(&json),
            Err(_) => vec![],
        },
        None => lattice_common::kube_utils::sha256(b"{}"),
    };

    (spec_hash, status_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_extract_domain_ipv6() {
        assert_eq!(
            extract_domain("https://[::1]:8080"),
            Ok("[::1]".to_string())
        );
    }

    /// Story: Domain extraction for TLS works with various URL formats
    #[test]
    fn domain_extraction_handles_various_formats() {
        assert_eq!(
            extract_domain("https://cell.example.com:443"),
            Ok("cell.example.com".to_string())
        );

        assert_eq!(
            extract_domain("http://cell.example.com:8080"),
            Ok("cell.example.com".to_string())
        );

        assert_eq!(
            extract_domain("https://cell.example.com"),
            Ok("cell.example.com".to_string())
        );

        assert_eq!(
            extract_domain("https://cell.example.com:443/api/v1"),
            Ok("cell.example.com".to_string())
        );

        assert_eq!(
            extract_domain("https://172.18.255.1:443"),
            Ok("172.18.255.1".to_string())
        );

        assert_eq!(
            extract_domain("cell.example.com:443"),
            Ok("cell.example.com".to_string())
        );

        assert!(extract_domain("").is_err());
        assert!(extract_domain("https://").is_err());
    }
}
