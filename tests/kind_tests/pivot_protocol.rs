//! Protocol integration tests for the pivot message flow
//!
//! These tests verify the gRPC communication protocol between agents and cells
//! works correctly. They **simulate** agent messages rather than running real
//! infrastructure - use `pivot_e2e.rs` for actual end-to-end testing.
//!
//! What these tests verify:
//! - gRPC server accepts agent connections
//! - Message protocol (Ready, PivotStarted, PivotComplete) works correctly
//! - AgentRegistry tracks state transitions properly
//! - Post-pivot BootstrapCommand is sent after PivotComplete
//! - Error handling for failed pivots
//! - Concurrent agent connections don't interfere
//!
//! What these tests do NOT verify:
//! - Actual CAPD cluster provisioning
//! - Real agent binary deployment
//! - Real clusterctl move execution
//! - Workload cluster self-management
//!
//! # Running
//!
//! ```bash
//! cargo test --test kind pivot_protocol -- --ignored --nocapture
//! ```

use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, DeleteParams, PostParams};
use kube::{Client, CustomResourceExt};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;

use lattice::agent::connection::{AgentRegistry, PostPivotManifests};
use lattice::agent::server::AgentServer;
use lattice::bootstrap::{BootstrapState, DefaultManifestGenerator};
use lattice::crd::{
    BootstrapProvider, KubernetesSpec, LatticeCluster, LatticeClusterSpec, NodeSpec, ProviderSpec,
    ProviderType,
};
use lattice::pki::CertificateAuthority;
use lattice::proto::agent_message::Payload;
use lattice::proto::cell_command::Command as CellCommandType;
use lattice::proto::lattice_agent_client::LatticeAgentClient;
use lattice::proto::{
    AgentMessage, AgentReady, AgentState, PivotComplete, PivotStarted, StartPivotCommand,
};

use super::helpers::ensure_test_cluster;

// =============================================================================
// Test Configuration
// =============================================================================

/// Timeout for the entire e2e test
const E2E_TIMEOUT: Duration = Duration::from_secs(600); // 10 minutes

/// Timeout for individual operations
const OPERATION_TIMEOUT: Duration = Duration::from_secs(120); // 2 minutes

/// Name of the workload cluster being provisioned
const WORKLOAD_CLUSTER_NAME: &str = "e2e-workload";

// =============================================================================
// Helper Functions
// =============================================================================

/// Check if CAPD is installed on the cluster
async fn is_capd_installed(client: &Client) -> bool {
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    crds.get("dockerclusters.infrastructure.cluster.x-k8s.io")
        .await
        .is_ok()
}

/// Install CAPI and CAPD on the cluster
async fn install_capi_capd() -> Result<(), String> {
    println!("Installing Cluster API and CAPD provider...");

    // Initialize clusterctl with CAPD
    let output = Command::new("clusterctl")
        .args(["init", "--infrastructure", "docker", "--wait-providers"])
        .output()
        .map_err(|e| format!("failed to run clusterctl: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "already installed" errors
        if !stderr.contains("already installed") && !stderr.contains("already exists") {
            return Err(format!("clusterctl init failed: {stderr}"));
        }
    }

    println!("CAPI and CAPD installed successfully");
    Ok(())
}

/// Create a sample workload cluster spec
fn workload_cluster_spec(name: &str) -> LatticeCluster {
    LatticeCluster {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        spec: LatticeClusterSpec {
            provider: ProviderSpec {
                type_: ProviderType::Docker,
                kubernetes: KubernetesSpec {
                    version: "1.31.0".to_string(),
                    cert_sans: Some(vec!["127.0.0.1".to_string(), "localhost".to_string()]),
                    bootstrap: BootstrapProvider::default(),
                },
            },
            nodes: NodeSpec {
                control_plane: 1,
                workers: 1,
            },
            networking: None,
            endpoints: None, // This is a workload cluster, not a cell
            environment: Some("test".to_string()),
            region: Some("local".to_string()),
            workload: None,
        },
        status: None,
    }
}

/// Cleanup workload cluster resources
async fn cleanup_workload_cluster(client: &Client, name: &str) {
    println!("Cleaning up workload cluster '{name}'...");

    // Delete LatticeCluster
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let _ = api.delete(name, &DeleteParams::default()).await;

    // Delete CAPI Cluster if exists
    let output = Command::new("kubectl")
        .args([
            "delete",
            "cluster",
            name,
            "--ignore-not-found",
            "--timeout=60s",
        ])
        .output();

    if let Ok(o) = output {
        if !o.status.success() {
            println!(
                "Warning: failed to delete CAPI cluster: {}",
                String::from_utf8_lossy(&o.stderr)
            );
        }
    }

    // Wait for cleanup
    sleep(Duration::from_secs(5)).await;
}

// =============================================================================
// E2E Test: Full Pivot Flow
// =============================================================================

/// Story: Complete pivot flow from provisioning to self-management
///
/// This test exercises the entire cluster lifecycle:
/// 1. Cell provisions workload cluster via CAPI/CAPD
/// 2. Agent bootstraps and connects via gRPC
/// 3. Cell orchestrates pivot
/// 4. Agent becomes self-managing
#[tokio::test]
#[ignore = "requires kind cluster with CAPD - run with: cargo test --test integration pivot_e2e -- --ignored --nocapture"]
async fn story_complete_pivot_flow_from_provisioning_to_self_management() {
    // Set up test timeout
    let result = timeout(E2E_TIMEOUT, async { run_pivot_e2e_test().await }).await;

    match result {
        Ok(Ok(())) => println!("E2E test completed successfully!"),
        Ok(Err(e)) => panic!("E2E test failed: {e}"),
        Err(_) => panic!("E2E test timed out after {:?}", E2E_TIMEOUT),
    }
}

async fn run_pivot_e2e_test() -> Result<(), String> {
    println!("\n=== Starting Pivot E2E Test ===\n");

    // Step 1: Ensure management cluster is ready
    println!("Step 1: Setting up management cluster...");
    let client = ensure_test_cluster()
        .await
        .map_err(|e| format!("Failed to setup test cluster: {e}"))?;

    // Step 2: Install CAPI/CAPD if not already installed
    println!("Step 2: Checking CAPI/CAPD installation...");
    if !is_capd_installed(&client).await {
        install_capi_capd().await?;
        // Wait for CAPI controllers to be ready
        sleep(Duration::from_secs(30)).await;
    } else {
        println!("CAPI/CAPD already installed");
    }

    // Step 3: Cleanup any previous test resources
    println!("Step 3: Cleaning up previous test resources...");
    cleanup_workload_cluster(&client, WORKLOAD_CLUSTER_NAME).await;

    // Step 4: Set up cell infrastructure (bootstrap server + gRPC server)
    println!("Step 4: Setting up cell infrastructure...");
    let (registry, grpc_addr, bootstrap_state, ca) = setup_cell_infrastructure().await?;

    // Step 5: Create LatticeCluster resource
    println!("Step 5: Creating LatticeCluster resource...");
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let cluster = workload_cluster_spec(WORKLOAD_CLUSTER_NAME);
    api.create(&PostParams::default(), &cluster)
        .await
        .map_err(|e| format!("Failed to create LatticeCluster: {e}"))?;

    // Register cluster for bootstrap (format: host:http_port:grpc_port)
    let cluster_manifest = serde_json::to_string(&cluster).expect("serialize cluster");
    let token = bootstrap_state.register_cluster(lattice::bootstrap::ClusterRegistration {
        cluster_id: WORKLOAD_CLUSTER_NAME.to_string(),
        cell_endpoint: format!("{}:8443:{}", grpc_addr.ip(), grpc_addr.port()),
        ca_certificate: ca.ca_cert_pem().to_string(),
        cluster_manifest,
        networking: None,
        provider: "docker".to_string(),
        bootstrap: lattice::crd::BootstrapProvider::default(),
    });
    println!("  Bootstrap token generated: {}...", &token.as_str()[..16]);

    // Step 6: Simulate agent bootstrap and connection
    // In a real scenario, CAPI would provision the cluster and kubeadm would
    // call the bootstrap endpoint. Here we simulate the agent connecting.
    println!("Step 6: Simulating agent bootstrap and connection...");
    let (agent_tx, mut agent_commands) =
        simulate_agent_connection(&registry, grpc_addr, WORKLOAD_CLUSTER_NAME).await?;

    // Step 7: Verify agent is registered
    println!("Step 7: Verifying agent registration...");
    sleep(Duration::from_millis(500)).await;
    assert!(
        registry.is_connected(WORKLOAD_CLUSTER_NAME),
        "Agent should be registered in cell"
    );
    println!("  Agent registered successfully!");

    // Step 8: Store post-pivot manifests (simulating controller behavior)
    println!("Step 8: Storing post-pivot manifests...");
    let crd_yaml = serde_yaml::to_string(&LatticeCluster::crd())
        .map_err(|e| format!("Failed to serialize CRD: {e}"))?;
    let cluster_yaml =
        serde_yaml::to_string(&cluster).map_err(|e| format!("Failed to serialize cluster: {e}"))?;

    registry.set_post_pivot_manifests(
        WORKLOAD_CLUSTER_NAME,
        PostPivotManifests {
            crd_yaml: Some(crd_yaml),
            cluster_yaml: Some(cluster_yaml),
        },
    );
    println!("  Post-pivot manifests stored");

    // Step 9: Trigger pivot command
    println!("Step 9: Sending pivot command to agent...");
    let pivot_cmd = lattice::proto::CellCommand {
        command_id: format!("pivot-{}", uuid::Uuid::new_v4()),
        command: Some(CellCommandType::StartPivot(StartPivotCommand {
            cluster_name: WORKLOAD_CLUSTER_NAME.to_string(),
            source_namespace: "default".to_string(),
            target_namespace: "capi-system".to_string(),
        })),
    };

    registry
        .send_command(WORKLOAD_CLUSTER_NAME, pivot_cmd)
        .await
        .map_err(|e| format!("Failed to send pivot command: {e}"))?;
    println!("  Pivot command sent");

    // Step 10: Wait for agent to receive pivot command
    println!("Step 10: Waiting for agent to process pivot command...");
    let received_cmd = timeout(OPERATION_TIMEOUT, agent_commands.recv())
        .await
        .map_err(|_| "Timeout waiting for pivot command")?
        .ok_or("Agent command channel closed")?;

    match received_cmd.command {
        Some(CellCommandType::StartPivot(p)) => {
            println!(
                "  Agent received pivot command for cluster: {}",
                p.cluster_name
            );
        }
        _ => return Err("Expected pivot command".to_string()),
    }

    // Step 11: Simulate agent sending PivotStarted
    println!("Step 11: Agent sending PivotStarted...");
    agent_tx
        .send(AgentMessage {
            cluster_name: WORKLOAD_CLUSTER_NAME.to_string(),
            payload: Some(Payload::PivotStarted(PivotStarted {
                target_namespace: "capi-system".to_string(),
            })),
        })
        .await
        .map_err(|e| format!("Failed to send PivotStarted: {e}"))?;

    sleep(Duration::from_millis(200)).await;

    // Verify state transitioned to Pivoting
    let agent = registry
        .get(WORKLOAD_CLUSTER_NAME)
        .ok_or("Agent not found")?;
    assert_eq!(
        agent.state,
        AgentState::Pivoting,
        "Agent should be in Pivoting state"
    );
    drop(agent);
    println!("  Agent state: Pivoting");

    // Step 12: Simulate agent sending PivotComplete
    println!("Step 12: Agent sending PivotComplete...");
    agent_tx
        .send(AgentMessage {
            cluster_name: WORKLOAD_CLUSTER_NAME.to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: true,
                error_message: String::new(),
                resources_imported: 5,
            })),
        })
        .await
        .map_err(|e| format!("Failed to send PivotComplete: {e}"))?;

    sleep(Duration::from_millis(500)).await;

    // Step 13: Verify agent received post-pivot ApplyManifestsCommand
    println!("Step 13: Verifying post-pivot ApplyManifestsCommand...");
    let apply_cmd = timeout(Duration::from_secs(5), agent_commands.recv())
        .await
        .map_err(|_| "Timeout waiting for ApplyManifestsCommand")?
        .ok_or("Agent command channel closed")?;

    match apply_cmd.command {
        Some(CellCommandType::ApplyManifests(a)) => {
            assert!(!a.manifests.is_empty(), "Should have manifests");
            println!(
                "  Received ApplyManifestsCommand with {} manifests",
                a.manifests.len()
            );
        }
        _ => return Err("Expected ApplyManifestsCommand after pivot".to_string()),
    }

    // Step 14: Verify agent state is Ready
    println!("Step 14: Verifying final agent state...");
    let agent = registry
        .get(WORKLOAD_CLUSTER_NAME)
        .ok_or("Agent not found")?;
    assert_eq!(
        agent.state,
        AgentState::Ready,
        "Agent should be in Ready state after pivot"
    );
    println!("  Agent state: Ready");

    // Step 15: Verify post-pivot manifests were consumed
    println!("Step 15: Verifying manifests consumed...");
    assert!(
        !registry.has_post_pivot_manifests(WORKLOAD_CLUSTER_NAME),
        "Post-pivot manifests should have been consumed"
    );
    println!("  Manifests consumed successfully");

    // Cleanup
    println!("\nStep 16: Cleaning up...");
    cleanup_workload_cluster(&client, WORKLOAD_CLUSTER_NAME).await;

    println!("\n=== Pivot E2E Test Completed Successfully! ===\n");
    Ok(())
}

/// Set up cell infrastructure (gRPC server + bootstrap state)
async fn setup_cell_infrastructure() -> Result<
    (
        Arc<AgentRegistry>,
        SocketAddr,
        Arc<BootstrapState>,
        Arc<CertificateAuthority>,
    ),
    String,
> {
    // Create CA
    let ca = Arc::new(
        CertificateAuthority::new("E2E Test CA")
            .map_err(|e| format!("Failed to create CA: {e}"))?,
    );

    // Create bootstrap state
    let bootstrap_state = Arc::new(BootstrapState::new(
        DefaultManifestGenerator::new().unwrap(),
        Duration::from_secs(3600),
        ca.clone(),
        "test:latest".to_string(),
        None,
    ));

    // Create agent registry and gRPC server
    let registry = Arc::new(AgentRegistry::new());
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let registry_clone = registry.clone();
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("Failed to bind listener: {e}"))?;
    let actual_addr = listener.local_addr().unwrap();

    // Start gRPC server in background
    tokio::spawn(async move {
        let server = AgentServer::new(registry_clone);
        let _ = tonic::transport::Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await;
    });

    // Wait for server to start
    sleep(Duration::from_millis(100)).await;

    println!("  gRPC server listening on {}", actual_addr);
    println!("  Bootstrap state ready");

    Ok((registry, actual_addr, bootstrap_state, ca))
}

/// Simulate an agent connecting to the cell
async fn simulate_agent_connection(
    _registry: &Arc<AgentRegistry>,
    grpc_addr: SocketAddr,
    cluster_name: &str,
) -> Result<
    (
        mpsc::Sender<AgentMessage>,
        mpsc::Receiver<lattice::proto::CellCommand>,
    ),
    String,
> {
    let endpoint = format!("http://{}", grpc_addr);
    let channel = Channel::from_shared(endpoint)
        .map_err(|e| format!("Invalid endpoint: {e}"))?
        .connect()
        .await
        .map_err(|e| format!("Failed to connect to gRPC server: {e}"))?;

    let mut client = LatticeAgentClient::new(channel);

    // Create channels for agent communication
    let (tx, rx) = mpsc::channel::<AgentMessage>(32);
    let outbound = ReceiverStream::new(rx);

    // Start streaming
    let response = client
        .stream_messages(outbound)
        .await
        .map_err(|e| format!("Failed to start stream: {e}"))?;

    let mut inbound = response.into_inner();

    // Create channel to receive commands
    let (cmd_tx, cmd_rx) = mpsc::channel::<lattice::proto::CellCommand>(32);

    // Spawn task to forward inbound commands
    tokio::spawn(async move {
        use tokio_stream::StreamExt;
        while let Some(Ok(cmd)) = inbound.next().await {
            if cmd_tx.send(cmd).await.is_err() {
                break;
            }
        }
    });

    // Send initial Ready message
    tx.send(AgentMessage {
        cluster_name: cluster_name.to_string(),
        payload: Some(Payload::Ready(AgentReady {
            agent_version: "1.0.0-test".to_string(),
            kubernetes_version: "1.31.0".to_string(),
            state: AgentState::Provisioning.into(),
            api_server_endpoint: format!("https://{}:6443", cluster_name),
        })),
    })
    .await
    .map_err(|e| format!("Failed to send Ready: {e}"))?;

    Ok((tx, cmd_rx))
}

// =============================================================================
// Additional E2E Tests
// =============================================================================

/// Story: Pivot failure is handled gracefully
///
/// When pivot fails, the agent reports PivotComplete with success=false,
/// and the cell updates state to Failed without sending BootstrapCommand.
#[tokio::test]
#[ignore = "requires kind cluster - run with: cargo test --test integration pivot_failure -- --ignored"]
async fn story_pivot_failure_handled_gracefully() {
    let _client = ensure_test_cluster()
        .await
        .expect("failed to setup cluster");

    let (registry, grpc_addr, _bootstrap_state, _ca) = setup_cell_infrastructure()
        .await
        .expect("failed to setup cell");

    let cluster_name = "e2e-pivot-fail";

    // Connect agent
    let (agent_tx, mut agent_commands) =
        simulate_agent_connection(&registry, grpc_addr, cluster_name)
            .await
            .expect("failed to connect agent");

    sleep(Duration::from_millis(200)).await;

    // Store manifests
    registry.set_post_pivot_manifests(
        cluster_name,
        PostPivotManifests {
            crd_yaml: Some("test".to_string()),
            cluster_yaml: Some("test".to_string()),
        },
    );

    // Send pivot command
    registry
        .send_command(
            cluster_name,
            lattice::proto::CellCommand {
                command_id: "pivot-fail-test".to_string(),
                command: Some(CellCommandType::StartPivot(StartPivotCommand {
                    cluster_name: cluster_name.to_string(),
                    source_namespace: "default".to_string(),
                    target_namespace: "capi-system".to_string(),
                })),
            },
        )
        .await
        .expect("failed to send command");

    // Receive pivot command
    let _ = timeout(Duration::from_secs(5), agent_commands.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    // Send PivotComplete with failure
    agent_tx
        .send(AgentMessage {
            cluster_name: cluster_name.to_string(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: false,
                error_message: "clusterctl move failed: connection refused".to_string(),
                resources_imported: 0,
            })),
        })
        .await
        .expect("failed to send PivotComplete");

    sleep(Duration::from_millis(200)).await;

    // Verify agent state is Failed
    let agent = registry.get(cluster_name).expect("agent not found");
    assert_eq!(agent.state, AgentState::Failed, "Should be in Failed state");

    // Verify manifests were NOT consumed (still available for retry)
    assert!(
        registry.has_post_pivot_manifests(cluster_name),
        "Manifests should NOT be consumed on failure"
    );
}

/// Story: Multiple clusters can pivot concurrently
///
/// The cell can manage multiple cluster pivots simultaneously without
/// interference between them.
#[tokio::test]
#[ignore = "requires kind cluster - run with: cargo test --test integration concurrent_pivots -- --ignored"]
async fn story_multiple_clusters_pivot_concurrently() {
    let _client = ensure_test_cluster()
        .await
        .expect("failed to setup cluster");

    let (registry, grpc_addr, _bootstrap_state, _ca) = setup_cell_infrastructure()
        .await
        .expect("failed to setup cell");

    let clusters = ["concurrent-a", "concurrent-b", "concurrent-c"];

    // Connect all agents
    let mut agents = Vec::new();
    for name in &clusters {
        let (tx, rx) = simulate_agent_connection(&registry, grpc_addr, name)
            .await
            .expect("failed to connect agent");
        agents.push((name.to_string(), tx, rx));
    }

    sleep(Duration::from_millis(200)).await;

    // Verify all registered
    for name in &clusters {
        assert!(registry.is_connected(name), "{} should be registered", name);
    }

    // Store manifests for all
    for name in &clusters {
        registry.set_post_pivot_manifests(
            name,
            PostPivotManifests {
                crd_yaml: Some(format!("crd-{}", name)),
                cluster_yaml: Some(format!("cluster-{}", name)),
            },
        );
    }

    // Send pivot commands to all concurrently
    for name in &clusters {
        registry
            .send_command(
                name,
                lattice::proto::CellCommand {
                    command_id: format!("pivot-{}", name),
                    command: Some(CellCommandType::StartPivot(StartPivotCommand {
                        cluster_name: name.to_string(),
                        source_namespace: "default".to_string(),
                        target_namespace: "capi-system".to_string(),
                    })),
                },
            )
            .await
            .expect("failed to send command");
    }

    // All agents complete pivot
    for (name, tx, _rx) in &agents {
        tx.send(AgentMessage {
            cluster_name: name.clone(),
            payload: Some(Payload::PivotComplete(PivotComplete {
                success: true,
                error_message: String::new(),
                resources_imported: 3,
            })),
        })
        .await
        .expect("failed to send PivotComplete");
    }

    sleep(Duration::from_millis(500)).await;

    // Verify all are Ready
    for name in &clusters {
        let agent = registry.get(*name).expect("agent not found");
        assert_eq!(agent.state, AgentState::Ready, "{} should be Ready", name);
    }

    // Verify all manifests consumed
    for name in &clusters {
        assert!(
            !registry.has_post_pivot_manifests(name),
            "{} manifests should be consumed",
            name
        );
    }
}
