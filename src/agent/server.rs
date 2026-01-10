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
use std::sync::Arc;

use futures::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, error, info, instrument, warn};

use crate::proto::lattice_agent_server::{LatticeAgent, LatticeAgentServer};
use crate::proto::{
    agent_message::Payload, AgentMessage, AgentState, CellCommand, KubeProxyRequest,
    KubeProxyResponse,
};

use super::connection::{AgentConnection, AgentRegistry, SharedAgentRegistry};
use super::mtls::ServerMtlsConfig;

/// gRPC server for agent communication
pub struct AgentServer {
    registry: SharedAgentRegistry,
}

/// Handle an agent message (standalone function to avoid temporary object creation)
async fn handle_agent_message_impl(
    registry: &AgentRegistry,
    msg: &AgentMessage,
    command_tx: &mpsc::Sender<CellCommand>,
) {
    let cluster_name = &msg.cluster_name;

    match &msg.payload {
        Some(Payload::Ready(ready)) => {
            info!(
                cluster = %cluster_name,
                agent_version = %ready.agent_version,
                k8s_version = %ready.kubernetes_version,
                "Agent ready"
            );

            // Register the agent
            let conn = AgentConnection::new(
                cluster_name.clone(),
                ready.agent_version.clone(),
                ready.kubernetes_version.clone(),
                command_tx.clone(),
            );
            registry.register(conn);
            registry.update_state(cluster_name, ready.state());
        }
        Some(Payload::BootstrapComplete(bc)) => {
            info!(
                cluster = %cluster_name,
                capi_ready = bc.capi_ready,
                installed_providers = ?bc.installed_providers,
                "Bootstrap complete"
            );
        }
        Some(Payload::PivotStarted(ps)) => {
            info!(
                cluster = %cluster_name,
                target_namespace = %ps.target_namespace,
                "Pivot started"
            );
            registry.update_state(cluster_name, AgentState::Pivoting);
        }
        Some(Payload::PivotComplete(pc)) => {
            if pc.success {
                info!(
                    cluster = %cluster_name,
                    resources_imported = pc.resources_imported,
                    "Pivot complete"
                );
                registry.update_state(cluster_name, AgentState::Ready);

                // Send post-pivot manifests (LatticeCluster CRD + resource)
                if let Some(manifests) = registry.take_post_pivot_manifests(cluster_name) {
                    let mut manifest_bytes = Vec::new();

                    // Clone the YAML strings so we can restore on failure
                    let crd_yaml = manifests.crd_yaml.clone();
                    let cluster_yaml = manifests.cluster_yaml.clone();

                    if let Some(ref crd) = crd_yaml {
                        manifest_bytes.push(crd.clone().into_bytes());
                    }
                    if let Some(ref cluster) = cluster_yaml {
                        manifest_bytes.push(cluster.clone().into_bytes());
                    }

                    if !manifest_bytes.is_empty() {
                        info!(
                            cluster = %cluster_name,
                            manifest_count = manifest_bytes.len(),
                            "Sending post-pivot ApplyManifestsCommand with LatticeCluster"
                        );

                        let apply_cmd = CellCommand {
                            command_id: format!("post-pivot-apply-{}", cluster_name),
                            command: Some(crate::proto::cell_command::Command::ApplyManifests(
                                crate::proto::ApplyManifestsCommand {
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
                                super::connection::PostPivotManifests {
                                    crd_yaml,
                                    cluster_yaml,
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
        None => {
            warn!(cluster = %cluster_name, "Received message with no payload");
        }
    }
}

impl AgentServer {
    /// Create a new agent server with the given registry
    pub fn new(registry: SharedAgentRegistry) -> Self {
        Self { registry }
    }

    /// Create a new agent server with a fresh registry
    pub fn with_new_registry() -> (Self, SharedAgentRegistry) {
        let registry = Arc::new(AgentRegistry::new());
        let server = Self::new(registry.clone());
        (server, registry)
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = Self::new(registry);
        let tls_config = mtls_config.to_tonic_config()?;

        info!(%addr, "Starting gRPC server with mTLS");

        Server::builder()
            .tls_config(tls_config)?
            .add_service(server.into_service())
            .serve(addr)
            .await?;

        Ok(())
    }

    /// Start the gRPC server without TLS (for testing only)
    #[cfg(test)]
    pub async fn serve_insecure(
        registry: SharedAgentRegistry,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let server = Self::new(registry);

        warn!(%addr, "Starting gRPC server WITHOUT TLS - for testing only!");

        Server::builder()
            .add_service(server.into_service())
            .serve(addr)
            .await?;

        Ok(())
    }

    /// Handle an agent message (delegates to standalone function)
    /// Only used in tests - production code uses handle_agent_message_impl directly.
    #[cfg(test)]
    pub(crate) async fn handle_agent_message(
        &self,
        msg: &AgentMessage,
        command_tx: &mpsc::Sender<CellCommand>,
    ) {
        handle_agent_message_impl(&self.registry, msg, command_tx).await
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

        // Clone registry for the spawned task
        let registry = self.registry.clone();
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
                        handle_agent_message_impl(&registry, &msg, &command_tx_clone).await;
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

    type ProxyKubernetesAPIStream =
        Pin<Box<dyn Stream<Item = Result<KubeProxyRequest, Status>> + Send + 'static>>;

    #[instrument(skip(self, request))]
    async fn proxy_kubernetes_api(
        &self,
        request: Request<Streaming<KubeProxyResponse>>,
    ) -> Result<Response<Self::ProxyKubernetesAPIStream>, Status> {
        let remote_addr = request.remote_addr();
        info!(?remote_addr, "New K8s API proxy connection");

        let mut inbound = request.into_inner();

        // Channel for sending proxy requests to the agent (cell -> agent)
        let (request_tx, request_rx) = mpsc::channel::<KubeProxyRequest>(32);

        // Channel for receiving proxy responses from the agent (agent -> cell)
        let (response_tx, response_rx) = mpsc::channel::<KubeProxyResponse>(32);

        let registry = self.registry.clone();

        // Spawn task to handle incoming responses and route them
        tokio::spawn(async move {
            let mut cluster_name: Option<String> = None;
            // Wrap in Option so we can take ownership once for registration
            let mut response_rx_opt = Some(response_rx);

            // Wait for first response to identify the cluster and register channels
            while let Some(result) = inbound.next().await {
                match result {
                    Ok(response) => {
                        // Extract cluster name from first response if not yet known
                        if response_rx_opt.is_some() && !response.request_id.is_empty() {
                            // Request ID format: "{cluster_name}:{uuid}"
                            if let Some(name) = response.request_id.split(':').next() {
                                cluster_name = Some(name.to_string());
                                // Register proxy channels with the agent connection
                                // Note: response_rx ownership is transferred here
                                if let Some(rx) = response_rx_opt.take() {
                                    registry.set_proxy_channels(name, request_tx.clone(), rx);
                                    debug!(cluster = %name, "K8s API proxy channels registered");
                                }
                            }
                        }

                        debug!(
                            request_id = %response.request_id,
                            status = response.status_code,
                            "Proxy response received"
                        );

                        // Forward to response channel for the waiting request
                        // After registration, response_rx is owned by registry
                        // so response_tx.send() delivers to registry holder
                        if let Err(e) = response_tx.send(response).await {
                            error!(error = %e, "Failed to forward proxy response");
                            break;
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Error receiving proxy response");
                        break;
                    }
                }
            }

            // Cleanup proxy channels on disconnect
            if let Some(name) = cluster_name {
                debug!(cluster = %name, "K8s API proxy disconnected");
                // Clear proxy channels from the agent connection
                if let Some(mut agent) = registry.get_mut(&name) {
                    agent.proxy_tx = None;
                    agent.proxy_rx = None;
                }
            }
        });

        // Return stream of requests to send to agent
        let outbound = ReceiverStream::new(request_rx);
        Ok(Response::new(Box::pin(outbound.map(Ok))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        agent_message::Payload, AgentReady, BootstrapComplete, ClusterHealth, Heartbeat,
        PivotComplete, PivotStarted, StatusResponse,
    };

    #[test]
    fn test_server_creation() {
        let (_server, registry) = AgentServer::with_new_registry();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_server_creation_with_registry() {
        let registry = Arc::new(AgentRegistry::new());
        let _server = AgentServer::new(registry.clone());
        assert!(registry.is_empty());
    }

    #[test]
    fn test_into_service() {
        let (server, _) = AgentServer::with_new_registry();
        let _service = server.into_service();
    }

    // Test handle_agent_message with Ready payload
    #[tokio::test]
    async fn test_handle_ready_message() {
        let (server, registry) = AgentServer::with_new_registry();
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

        server.handle_agent_message(&msg, &tx).await;

        // Verify agent was registered
        assert!(!registry.is_empty());
        let conn = registry.get("test-cluster").unwrap();
        assert_eq!(conn.cluster_name, "test-cluster");
        assert_eq!(conn.agent_version, "0.1.0");
        assert_eq!(conn.kubernetes_version, "1.28.0");
        assert_eq!(conn.state, AgentState::Provisioning);
    }

    #[tokio::test]
    async fn test_handle_ready_message_updates_existing() {
        let (server, registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // First ready message
        let msg1 = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&msg1, &tx).await;

        // Second ready message with updated state
        let msg2 = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&msg2, &tx).await;

        let conn = registry.get("test-cluster").unwrap();
        assert_eq!(conn.state, AgentState::Ready);
    }

    // Test handle_agent_message with BootstrapComplete payload
    #[tokio::test]
    async fn test_handle_bootstrap_complete_message() {
        let (server, _registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::BootstrapComplete(BootstrapComplete {
                capi_ready: true,
                installed_providers: vec!["docker".to_string()],
            })),
        };

        // Should not panic
        server.handle_agent_message(&msg, &tx).await;
    }

    // Test handle_agent_message with PivotStarted payload
    #[tokio::test]
    async fn test_handle_pivot_started_message() {
        let (server, registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // First register the agent
        let ready_msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&ready_msg, &tx).await;

        // Then send pivot started
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::PivotStarted(PivotStarted {
                target_namespace: "capi-system".to_string(),
            })),
        };
        server.handle_agent_message(&msg, &tx).await;

        // Verify state changed to Pivoting
        let conn = registry.get("test-cluster").unwrap();
        assert_eq!(conn.state, AgentState::Pivoting);
    }

    // Test handle_agent_message with PivotComplete (success)
    #[tokio::test]
    async fn test_handle_pivot_complete_success_message() {
        let (server, registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // First register the agent
        let ready_msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Pivoting.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&ready_msg, &tx).await;

        // Send pivot complete (success)
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: true,
                error_message: String::new(),
                resources_imported: 5,
            })),
        };
        server.handle_agent_message(&msg, &tx).await;

        // Verify state changed to Ready
        let conn = registry.get("test-cluster").unwrap();
        assert_eq!(conn.state, AgentState::Ready);
    }

    // Test handle_agent_message with PivotComplete (failure)
    #[tokio::test]
    async fn test_handle_pivot_complete_failure_message() {
        let (server, registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // First register the agent
        let ready_msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Pivoting.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&ready_msg, &tx).await;

        // Send pivot complete (failure)
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: false,
                error_message: "clusterctl failed".to_string(),
                resources_imported: 0,
            })),
        };
        server.handle_agent_message(&msg, &tx).await;

        // Verify state changed to Failed
        let conn = registry.get("test-cluster").unwrap();
        assert_eq!(conn.state, AgentState::Failed);
    }

    // Test handle_agent_message with Heartbeat payload
    #[tokio::test]
    async fn test_handle_heartbeat_message() {
        let (server, registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // First register the agent
        let ready_msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&ready_msg, &tx).await;

        // Send heartbeat
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Heartbeat(Heartbeat {
                state: AgentState::Ready.into(),
                timestamp: None,
                uptime_seconds: 3600,
            })),
        };
        server.handle_agent_message(&msg, &tx).await;

        // State should remain Ready
        let conn = registry.get("test-cluster").unwrap();
        assert_eq!(conn.state, AgentState::Ready);
    }

    // Test handle_agent_message with ClusterHealth payload
    #[tokio::test]
    async fn test_handle_cluster_health_message() {
        let (server, _registry) = AgentServer::with_new_registry();
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
        server.handle_agent_message(&msg, &tx).await;
    }

    // Test handle_agent_message with StatusResponse payload
    #[tokio::test]
    async fn test_handle_status_response_message() {
        let (server, _registry) = AgentServer::with_new_registry();
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
        server.handle_agent_message(&msg, &tx).await;
    }

    // Test handle_agent_message with no payload
    #[tokio::test]
    async fn test_handle_empty_payload_message() {
        let (server, _registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: None,
        };

        // Should not panic, just log warning
        server.handle_agent_message(&msg, &tx).await;
    }

    // Test registry interactions through server
    #[tokio::test]
    async fn test_multiple_agents_registration() {
        let (server, registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // Register first agent
        let msg1 = AgentMessage {
            cluster_name: "cluster-1".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://api.cluster1:6443".to_string(),
            })),
        };
        server.handle_agent_message(&msg1, &tx).await;

        // Register second agent
        let msg2 = AgentMessage {
            cluster_name: "cluster-2".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.2.0".to_string(),
                kubernetes_version: "1.29.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://api.cluster2:6443".to_string(),
            })),
        };
        server.handle_agent_message(&msg2, &tx).await;

        // Verify both are registered
        assert_eq!(registry.len(), 2);

        let conn1 = registry.get("cluster-1").unwrap();
        assert_eq!(conn1.agent_version, "0.1.0");

        let conn2 = registry.get("cluster-2").unwrap();
        assert_eq!(conn2.agent_version, "0.2.0");
    }

    // Test state transitions through messages
    #[tokio::test]
    async fn test_full_state_transition_lifecycle() {
        let (server, registry) = AgentServer::with_new_registry();
        let (tx, _rx) = mpsc::channel::<CellCommand>(32);

        // Initial: Provisioning
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&msg, &tx).await;
        assert_eq!(
            registry.get("test-cluster").unwrap().state,
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
        server.handle_agent_message(&msg, &tx).await;
        assert_eq!(
            registry.get("test-cluster").unwrap().state,
            AgentState::Ready
        );

        // Pivot started
        let msg = AgentMessage {
            cluster_name: "test-cluster".to_string(),
            payload: Some(Payload::PivotStarted(PivotStarted {
                target_namespace: "capi-system".to_string(),
            })),
        };
        server.handle_agent_message(&msg, &tx).await;
        assert_eq!(
            registry.get("test-cluster").unwrap().state,
            AgentState::Pivoting
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
        server.handle_agent_message(&msg, &tx).await;
        assert_eq!(
            registry.get("test-cluster").unwrap().state,
            AgentState::Ready
        );
    }

    // ==========================================================================
    // Integration Tests: Real gRPC Server
    // ==========================================================================

    use crate::proto::lattice_agent_client::LatticeAgentClient;
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::transport::Channel;

    /// Integration test: Start gRPC server and connect a client
    #[tokio::test]
    async fn integration_grpc_server_accepts_connection() {
        let registry = Arc::new(AgentRegistry::new());
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Start server in background
        let registry_clone = registry.clone();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        // Give server time to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect client
        let endpoint = format!("http://{}", actual_addr);
        let channel = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();

        let mut client = LatticeAgentClient::new(channel);

        // Create message stream
        let (_tx, rx) = mpsc::channel::<AgentMessage>(32);
        let outbound = ReceiverStream::new(rx);

        // Start streaming
        let response = client.stream_messages(outbound).await;
        assert!(response.is_ok());

        // Clean up
        server_handle.abort();
    }

    /// Integration test: Agent sends ready message and gets registered
    #[tokio::test]
    async fn integration_agent_ready_registers_in_registry() {
        let registry = Arc::new(AgentRegistry::new());
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let registry_clone = registry.clone();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect client
        let endpoint = format!("http://{}", actual_addr);
        let channel = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();

        let mut client = LatticeAgentClient::new(channel);

        // Create message stream
        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        let outbound = ReceiverStream::new(rx);

        // Start streaming
        let response = client.stream_messages(outbound).await.unwrap();
        let _inbound = response.into_inner();

        // Send ready message
        tx.send(AgentMessage {
            cluster_name: "integration-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "1.0.0".to_string(),
                kubernetes_version: "1.30.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        })
        .await
        .unwrap();

        // Give server time to process
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Verify agent was registered
        assert!(!registry.is_empty());
        let conn = registry.get("integration-cluster");
        assert!(conn.is_some());
        let conn = conn.unwrap();
        assert_eq!(conn.agent_version, "1.0.0");
        assert_eq!(conn.kubernetes_version, "1.30.0");

        // Clean up
        server_handle.abort();
    }

    /// Integration test: Cell sends command to agent
    #[tokio::test]
    async fn integration_cell_sends_command_to_agent() {
        use crate::proto::{cell_command::Command, ApplyManifestsCommand};

        let registry = Arc::new(AgentRegistry::new());
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let registry_clone = registry.clone();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let endpoint = format!("http://{}", actual_addr);
        let channel = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();

        let mut client = LatticeAgentClient::new(channel);

        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        let outbound = ReceiverStream::new(rx);

        let response = client.stream_messages(outbound).await.unwrap();
        let mut inbound = response.into_inner();

        // Send ready message to register
        tx.send(AgentMessage {
            cluster_name: "cmd-test-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "1.0.0".to_string(),
                kubernetes_version: "1.30.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        })
        .await
        .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Send command through registry
        let conn = registry.get("cmd-test-cluster").unwrap();
        let send_result = conn
            .send_command(CellCommand {
                command_id: "cmd-1".to_string(),
                command: Some(Command::ApplyManifests(ApplyManifestsCommand {
                    manifests: vec![],
                })),
            })
            .await;

        assert!(send_result.is_ok());

        // Receive command on agent side
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(1), inbound.next()).await;

        assert!(received.is_ok());
        let cmd = received.unwrap().unwrap().unwrap();
        assert_eq!(cmd.command_id, "cmd-1");

        server_handle.abort();
    }

    /// Integration test: Agent disconnect unregisters from registry
    #[tokio::test]
    async fn integration_agent_disconnect_unregisters() {
        let registry = Arc::new(AgentRegistry::new());
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let registry_clone = registry.clone();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let endpoint = format!("http://{}", actual_addr);
        let channel = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();

        let mut client = LatticeAgentClient::new(channel);

        let (tx, rx) = mpsc::channel::<AgentMessage>(32);
        let outbound = ReceiverStream::new(rx);

        let response = client.stream_messages(outbound).await.unwrap();

        // Send ready message
        tx.send(AgentMessage {
            cluster_name: "disconnect-test".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "1.0.0".to_string(),
                kubernetes_version: "1.30.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        })
        .await
        .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(registry.get("disconnect-test").is_some());

        // Drop the sender to simulate disconnect
        drop(tx);
        drop(response);

        // Give server time to detect disconnect
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Agent should be unregistered
        assert!(registry.get("disconnect-test").is_none());

        server_handle.abort();
    }

    /// Integration test: Multiple agents can connect simultaneously
    #[tokio::test]
    async fn integration_multiple_agents_connect() {
        let registry = Arc::new(AgentRegistry::new());
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let registry_clone = registry.clone();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let server = AgentServer::new(registry_clone);
            tonic::transport::Server::builder()
                .add_service(server.into_service())
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect first agent
        let endpoint = format!("http://{}", actual_addr);
        let channel1 = Channel::from_shared(endpoint.clone())
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client1 = LatticeAgentClient::new(channel1);

        let (tx1, rx1) = mpsc::channel::<AgentMessage>(32);
        let _resp1 = client1
            .stream_messages(ReceiverStream::new(rx1))
            .await
            .unwrap();

        tx1.send(AgentMessage {
            cluster_name: "agent-1".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "1.0.0".to_string(),
                kubernetes_version: "1.30.0".to_string(),
                state: AgentState::Ready.into(),
                api_server_endpoint: "https://agent1:6443".to_string(),
            })),
        })
        .await
        .unwrap();

        // Connect second agent
        let channel2 = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client2 = LatticeAgentClient::new(channel2);

        let (tx2, rx2) = mpsc::channel::<AgentMessage>(32);
        let _resp2 = client2
            .stream_messages(ReceiverStream::new(rx2))
            .await
            .unwrap();

        tx2.send(AgentMessage {
            cluster_name: "agent-2".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "2.0.0".to_string(),
                kubernetes_version: "1.29.0".to_string(),
                state: AgentState::Provisioning.into(),
                api_server_endpoint: "https://agent2:6443".to_string(),
            })),
        })
        .await
        .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Both should be registered
        assert_eq!(registry.len(), 2);
        assert!(registry.get("agent-1").is_some());
        assert!(registry.get("agent-2").is_some());

        server_handle.abort();
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
    /// This is critical for self-management: after pivot, the workload cluster
    /// needs its own LatticeCluster CRD and resource to manage itself.
    #[tokio::test]
    async fn test_pivot_complete_sends_post_pivot_manifests() {
        use crate::agent::connection::PostPivotManifests;

        let (server, registry) = AgentServer::with_new_registry();
        let (tx, mut rx) = mpsc::channel::<CellCommand>(32);

        // Register agent
        let ready_msg = AgentMessage {
            cluster_name: "self-managed-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Pivoting.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&ready_msg, &tx).await;

        // Store post-pivot manifests
        let crd_yaml = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n...";
        let cluster_yaml = "apiVersion: lattice.dev/v1alpha1\nkind: LatticeCluster\n...";
        registry.set_post_pivot_manifests(
            "self-managed-cluster",
            PostPivotManifests {
                crd_yaml: Some(crd_yaml.to_string()),
                cluster_yaml: Some(cluster_yaml.to_string()),
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
        server.handle_agent_message(&pivot_msg, &tx).await;

        // Verify ApplyManifestsCommand was sent with manifests
        let cmd = rx.try_recv().expect("should have received a command");
        assert!(
            cmd.command_id.starts_with("post-pivot-apply-"),
            "command_id should indicate post-pivot apply"
        );

        match cmd.command {
            Some(crate::proto::cell_command::Command::ApplyManifests(apply)) => {
                assert_eq!(
                    apply.manifests.len(),
                    2,
                    "should include both CRD and cluster manifests"
                );
                // Verify manifest contents
                let manifest1 = String::from_utf8(apply.manifests[0].clone()).unwrap();
                let manifest2 = String::from_utf8(apply.manifests[1].clone()).unwrap();
                assert!(manifest1.contains("CustomResourceDefinition"));
                assert!(manifest2.contains("LatticeCluster"));
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
        let (server, registry) = AgentServer::with_new_registry();
        let (tx, mut rx) = mpsc::channel::<CellCommand>(32);

        // Register agent (no manifests stored)
        let ready_msg = AgentMessage {
            cluster_name: "no-manifests-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Pivoting.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&ready_msg, &tx).await;

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
        server.handle_agent_message(&pivot_msg, &tx).await;

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
        use crate::agent::connection::PostPivotManifests;

        let (server, registry) = AgentServer::with_new_registry();
        let (tx, mut rx) = mpsc::channel::<CellCommand>(32);

        // Register agent
        let ready_msg = AgentMessage {
            cluster_name: "failed-pivot-cluster".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Pivoting.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&ready_msg, &tx).await;

        // Store manifests (they should remain after failed pivot)
        registry.set_post_pivot_manifests(
            "failed-pivot-cluster",
            PostPivotManifests {
                crd_yaml: Some("crd".to_string()),
                cluster_yaml: Some("cluster".to_string()),
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
        server.handle_agent_message(&pivot_msg, &tx).await;

        // No command should be sent
        assert!(
            rx.try_recv().is_err(),
            "should not send manifests on pivot failure"
        );

        // State should be Failed
        let conn = registry.get("failed-pivot-cluster").unwrap();
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
        use crate::agent::connection::PostPivotManifests;

        let (server, registry) = AgentServer::with_new_registry();
        let (tx, rx) = mpsc::channel::<CellCommand>(32);

        // Register agent
        let ready_msg = AgentMessage {
            cluster_name: "restore-test".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Pivoting.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&ready_msg, &tx).await;

        // Store manifests
        registry.set_post_pivot_manifests(
            "restore-test",
            PostPivotManifests {
                crd_yaml: Some("crd-yaml-content".to_string()),
                cluster_yaml: Some("cluster-yaml-content".to_string()),
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
        server.handle_agent_message(&pivot_msg, &tx).await;

        // Manifests should be restored for retry (can be sent on reconnect)
        assert!(
            registry.has_post_pivot_manifests("restore-test"),
            "manifests should be restored after send failure for retry"
        );

        // Verify the restored manifests still have their content
        let manifests = registry.take_post_pivot_manifests("restore-test").unwrap();
        assert_eq!(manifests.crd_yaml, Some("crd-yaml-content".to_string()));
        assert_eq!(
            manifests.cluster_yaml,
            Some("cluster-yaml-content".to_string())
        );
    }

    /// Story: Post-pivot manifests with only CRD (no cluster resource)
    /// should still be sent correctly.
    #[tokio::test]
    async fn test_pivot_complete_with_partial_manifests() {
        use crate::agent::connection::PostPivotManifests;

        let (server, registry) = AgentServer::with_new_registry();
        let (tx, mut rx) = mpsc::channel::<CellCommand>(32);

        // Register agent
        let ready_msg = AgentMessage {
            cluster_name: "partial-manifests".to_string(),
            payload: Some(Payload::Ready(AgentReady {
                agent_version: "0.1.0".to_string(),
                kubernetes_version: "1.28.0".to_string(),
                state: AgentState::Pivoting.into(),
                api_server_endpoint: "https://api.test:6443".to_string(),
            })),
        };
        server.handle_agent_message(&ready_msg, &tx).await;

        // Store only CRD (no cluster yaml)
        registry.set_post_pivot_manifests(
            "partial-manifests",
            PostPivotManifests {
                crd_yaml: Some("apiVersion: apiextensions.k8s.io/v1\nkind: CRD".to_string()),
                cluster_yaml: None,
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
        server.handle_agent_message(&pivot_msg, &tx).await;

        // Should receive command with only one manifest
        let cmd = rx.try_recv().expect("should have received a command");
        match cmd.command {
            Some(crate::proto::cell_command::Command::ApplyManifests(apply)) => {
                assert_eq!(
                    apply.manifests.len(),
                    1,
                    "should include only the CRD manifest"
                );
            }
            _ => panic!("expected ApplyManifestsCommand"),
        }
    }
}
