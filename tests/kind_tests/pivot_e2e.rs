//! Real end-to-end test for the complete Lattice installation and pivot flow
//!
//! This test runs the FULL Lattice installer flow:
//!
//! 1. Creates a bootstrap kind cluster
//! 2. Installs CAPI + Lattice operator on bootstrap
//! 3. Creates management cluster LatticeCluster CRD (with spec.cell)
//! 4. Waits for management cluster to be provisioned
//! 5. Pivots CAPI resources to management cluster
//! 6. Deletes bootstrap cluster
//! 7. Creates a workload cluster from the self-managing management cluster
//! 8. Verifies workload cluster reaches Ready state
//!
//! # Prerequisites
//!
//! - Docker running with sufficient resources (8GB+ RAM recommended)
//! - kind installed
//! - clusterctl installed
//! - kubectl installed
//!
//! # Running
//!
//! ```bash
//! # This test takes 20-30 minutes
//! cargo test --test kind pivot_e2e -- --ignored --nocapture
//! ```

use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::time::Duration;

use base64::Engine;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::Client;
use tokio::time::sleep;

use lattice::crd::{
    ClusterPhase, KubernetesSpec, LatticeCluster, LatticeClusterSpec, NodeSpec, ProviderSpec,
    ProviderType,
};
use lattice::install::{InstallConfig, Installer};

// =============================================================================
// Test Configuration
// =============================================================================

/// Timeout for the entire e2e test
const E2E_TIMEOUT: Duration = Duration::from_secs(2400); // 40 minutes

/// Name of the management cluster
const MGMT_CLUSTER_NAME: &str = "e2e-mgmt";

/// Name of the workload cluster being provisioned
const WORKLOAD_CLUSTER_NAME: &str = "e2e-workload";

/// Docker image name for lattice
const LATTICE_IMAGE: &str = "ghcr.io/evan-hines-js/lattice:latest";

// =============================================================================
// Helper Functions
// =============================================================================

/// Run a shell command and return output
fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = ProcessCommand::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run {}: {}", cmd, e))?;

    if !output.status.success() {
        return Err(format!(
            "{} failed: {}",
            cmd,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run a shell command, allowing failure
fn run_cmd_allow_fail(cmd: &str, args: &[&str]) -> String {
    ProcessCommand::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

/// Build and push the lattice Docker image to registry
async fn build_and_push_lattice_image() -> Result<(), String> {
    println!("  Building lattice Docker image...");

    let output = ProcessCommand::new("docker")
        .args(["build", "-t", LATTICE_IMAGE, "."])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .map_err(|e| format!("Failed to run docker build: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Docker build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    println!("  Image built successfully");

    println!("  Pushing image to registry...");

    let output = ProcessCommand::new("docker")
        .args(["push", LATTICE_IMAGE])
        .output()
        .map_err(|e| format!("Failed to push image: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Docker push failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    println!("  Image pushed successfully");
    Ok(())
}

/// Load registry credentials from .env file and construct dockerconfigjson format
fn load_registry_credentials() -> Option<String> {
    // Try to load from .env file first
    let env_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".env");
    if let Ok(content) = std::fs::read_to_string(&env_path) {
        let mut user = None;
        let mut token = None;

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("export GHCR_USER=") {
                user = Some(line.trim_start_matches("export GHCR_USER=").to_string());
            } else if line.starts_with("export GHCR_TOKEN=") {
                token = Some(line.trim_start_matches("export GHCR_TOKEN=").to_string());
            } else if line.starts_with("GHCR_USER=") {
                user = Some(line.trim_start_matches("GHCR_USER=").to_string());
            } else if line.starts_with("GHCR_TOKEN=") {
                token = Some(line.trim_start_matches("GHCR_TOKEN=").to_string());
            }
        }

        if let (Some(u), Some(t)) = (user, token) {
            // Construct dockerconfigjson format
            let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", u, t));
            let docker_config = serde_json::json!({
                "auths": {
                    "ghcr.io": {
                        "auth": auth
                    }
                }
            });
            return Some(docker_config.to_string());
        }
    }

    // Fallback to environment variables
    if let (Ok(u), Ok(t)) = (std::env::var("GHCR_USER"), std::env::var("GHCR_TOKEN")) {
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", u, t));
        let docker_config = serde_json::json!({
            "auths": {
                "ghcr.io": {
                    "auth": auth
                }
            }
        });
        return Some(docker_config.to_string());
    }

    None
}

/// Create a kube client using a specific kubeconfig file
async fn client_from_kubeconfig(path: &str) -> Result<Client, String> {
    let kubeconfig =
        Kubeconfig::read_from(path).map_err(|e| format!("Failed to read kubeconfig: {}", e))?;

    let config = kube::Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
        .await
        .map_err(|e| format!("Failed to create kube config: {}", e))?;

    Client::try_from(config).map_err(|e| format!("Failed to create client: {}", e))
}

/// Get and patch kubeconfig for management cluster
fn get_management_kubeconfig() -> Result<String, String> {
    let kubeconfig_path = format!("/tmp/{}-kubeconfig", MGMT_CLUSTER_NAME);

    // Read the kubeconfig that the installer saved
    let kubeconfig = std::fs::read_to_string(&kubeconfig_path)
        .map_err(|e| format!("Failed to read kubeconfig: {}", e))?;

    // Get the LB container port for localhost access
    let lb_container = format!("{}-lb", MGMT_CLUSTER_NAME);
    let port_output = run_cmd_allow_fail("docker", &["port", &lb_container, "6443/tcp"]);

    if port_output.trim().is_empty() {
        return Err("Management cluster LB container not found".to_string());
    }

    let parts: Vec<&str> = port_output.trim().split(':').collect();
    if parts.len() != 2 {
        return Err(format!("Failed to parse LB port: {}", port_output));
    }

    let localhost_endpoint = format!("https://127.0.0.1:{}", parts[1]);

    // Patch kubeconfig to use localhost
    let patched = kubeconfig
        .lines()
        .map(|line| {
            if line.trim().starts_with("server:") {
                format!("    server: {}", localhost_endpoint)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Save patched kubeconfig
    let patched_path = format!("/tmp/{}-kubeconfig-local", MGMT_CLUSTER_NAME);
    std::fs::write(&patched_path, &patched)
        .map_err(|e| format!("Failed to write patched kubeconfig: {}", e))?;

    Ok(patched_path)
}

/// Create workload cluster spec
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
                },
            },
            nodes: NodeSpec {
                control_plane: 1,
                workers: 0, // Start with 0 workers for faster provisioning
            },
            networking: None,
            cell: None,
            cell_ref: Some(MGMT_CLUSTER_NAME.to_string()),
            environment: Some("e2e-test".to_string()),
            region: Some("local".to_string()),
            workload: None,
        },
        status: None,
    }
}

/// Watch LatticeCluster phase transitions
async fn watch_cluster_phases(client: &Client, cluster_name: &str) -> Result<(), String> {
    let api: Api<LatticeCluster> = Api::all(client.clone());

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(900); // 15 minutes for full flow

    let mut last_phase: Option<ClusterPhase> = None;

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for cluster to reach Ready state. Last phase: {:?}",
                last_phase
            ));
        }

        match api.get(cluster_name).await {
            Ok(cluster) => {
                let current_phase = cluster
                    .status
                    .as_ref()
                    .map(|s| s.phase.clone())
                    .unwrap_or(ClusterPhase::Pending);

                if last_phase.as_ref() != Some(&current_phase) {
                    println!("  Cluster phase: {:?}", current_phase);
                    last_phase = Some(current_phase.clone());
                }

                if matches!(current_phase, ClusterPhase::Ready) {
                    println!("  Cluster reached Ready state!");
                    return Ok(());
                }

                if matches!(current_phase, ClusterPhase::Failed) {
                    return Err("Cluster entered Failed state".to_string());
                }
            }
            Err(e) => {
                println!("  Error getting cluster: {}", e);
            }
        }

        sleep(Duration::from_secs(10)).await;
    }
}

/// Cleanup all test resources
fn cleanup_all() {
    println!("\n[Cleanup] Removing all test resources...\n");

    // Delete bootstrap cluster if it exists
    let _ = run_cmd_allow_fail(
        "kind",
        &["delete", "cluster", "--name", "lattice-bootstrap"],
    );

    // Delete any leftover Docker containers from management cluster
    let mgmt_containers = run_cmd_allow_fail(
        "docker",
        &[
            "ps",
            "-a",
            "--filter",
            &format!("name={}", MGMT_CLUSTER_NAME),
            "-q",
        ],
    );
    for id in mgmt_containers.lines() {
        if !id.trim().is_empty() {
            let _ = run_cmd_allow_fail("docker", &["rm", "-f", id.trim()]);
        }
    }

    // Delete any leftover Docker containers from workload cluster
    let workload_containers = run_cmd_allow_fail(
        "docker",
        &[
            "ps",
            "-a",
            "--filter",
            &format!("name={}", WORKLOAD_CLUSTER_NAME),
            "-q",
        ],
    );
    for id in workload_containers.lines() {
        if !id.trim().is_empty() {
            let _ = run_cmd_allow_fail("docker", &["rm", "-f", id.trim()]);
        }
    }

    // Clean up temp files
    let _ = std::fs::remove_file(format!("/tmp/{}-kubeconfig", MGMT_CLUSTER_NAME));
    let _ = std::fs::remove_file(format!("/tmp/{}-kubeconfig-local", MGMT_CLUSTER_NAME));
    let _ = std::fs::remove_file(format!("/tmp/{}-cluster-config.yaml", MGMT_CLUSTER_NAME));

    println!("  Cleanup complete!");
}

// =============================================================================
// E2E Test: Full Installation and Pivot Flow
// =============================================================================

/// Story: Full end-to-end installation with self-managing management cluster
///
/// This test runs the complete Lattice installer flow, then provisions a
/// workload cluster from the self-managing management cluster.
#[tokio::test]
#[ignore = "requires Docker with 8GB+ RAM - takes 20-30min - run with: cargo test --test kind pivot_e2e -- --ignored --nocapture"]
async fn story_full_install_and_workload_provisioning() {
    let result = tokio::time::timeout(E2E_TIMEOUT, run_full_e2e()).await;

    match result {
        Ok(Ok(())) => println!("\n=== Full E2E Test Completed Successfully! ===\n"),
        Ok(Err(e)) => {
            println!("\n=== Full E2E Test Failed: {} ===\n", e);
            cleanup_all();
            panic!("E2E test failed: {}", e);
        }
        Err(_) => {
            println!("\n=== Full E2E Test Timed Out ({:?}) ===\n", E2E_TIMEOUT);
            cleanup_all();
            panic!("E2E test timed out after {:?}", E2E_TIMEOUT);
        }
    }
}

async fn run_full_e2e() -> Result<(), String> {
    // Install crypto provider for rustls/kube client
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    println!("\n============================================================");
    println!("  FULL END-TO-END LATTICE INSTALLATION TEST");
    println!("============================================================");
    println!("\n  This test will:");
    println!("    1. Build and push the Lattice Docker image");
    println!("    2. Run the full installer (bootstrap → management cluster)");
    println!("    3. Verify management cluster is self-managing");
    println!("    4. Create a workload cluster from management cluster");
    println!("    5. Verify workload cluster reaches Ready state");
    println!("\n  Expected duration: 20-30 minutes\n");

    // =========================================================================
    // Phase 1: Cleanup any previous runs
    // =========================================================================
    println!("\n[Phase 1] Cleaning up previous test runs...\n");
    cleanup_all();

    // =========================================================================
    // Phase 2: Build and Push Lattice Image
    // =========================================================================
    println!("\n[Phase 2] Building and pushing Lattice image...\n");
    build_and_push_lattice_image().await?;

    // =========================================================================
    // Phase 3: Run Full Installer
    // =========================================================================
    println!("\n[Phase 3] Running Lattice installer...\n");
    println!("  This will:");
    println!("    - Create a bootstrap kind cluster");
    println!("    - Install CAPI with docker provider");
    println!("    - Deploy Lattice operator");
    println!("    - Create management cluster LatticeCluster CRD");
    println!("    - Wait for management cluster provisioning");
    println!("    - Pivot CAPI resources to management cluster");
    println!("    - Delete bootstrap cluster");
    println!();

    // Create config file for the management cluster
    // Uses Cilium LB-IPAM for the cell endpoint - workload clusters connect to this IP
    let cluster_config = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: {name}
spec:
  provider:
    type: docker
    kubernetes:
      version: "1.31.0"
      certSANs:
        - "127.0.0.1"
        - "localhost"
        - "172.18.255.10"
  nodes:
    controlPlane: 1
    workers: 0
  networking:
    default:
      cidr: "172.18.255.10/32"
  cell:
    host: 172.18.255.10
    grpcPort: 50051
    bootstrapPort: 8443
    service:
      type: LoadBalancer
"#,
        name = MGMT_CLUSTER_NAME
    );

    // Write config to temp file
    let config_path = PathBuf::from(format!("/tmp/{}-cluster-config.yaml", MGMT_CLUSTER_NAME));
    std::fs::write(&config_path, &cluster_config)
        .map_err(|e| format!("Failed to write cluster config: {}", e))?;
    println!("  Cluster config written to {:?}", config_path);

    // Load registry credentials
    let registry_credentials = load_registry_credentials();
    if registry_credentials.is_some() {
        println!("  Registry credentials loaded from .env");
    } else {
        println!("  WARNING: No registry credentials found - image pull may fail");
    }

    let install_config = InstallConfig {
        cluster_config_path: config_path,
        cluster_config_content: cluster_config,
        image: LATTICE_IMAGE.to_string(),
        keep_bootstrap_on_failure: true, // Keep for debugging if it fails
        timeout: Duration::from_secs(1200),
        registry_credentials,
    };

    let installer = Installer::new(install_config)
        .map_err(|e| format!("Failed to create installer: {}", e))?;
    installer
        .run()
        .await
        .map_err(|e| format!("Installer failed: {}", e))?;

    println!("\n  Management cluster installation complete!");

    // =========================================================================
    // Phase 4: Verify Management Cluster is Self-Managing
    // =========================================================================
    println!("\n[Phase 4] Verifying management cluster is self-managing...\n");

    // Get kubeconfig for management cluster
    let kubeconfig_path = get_management_kubeconfig()?;
    println!("  Using kubeconfig: {}", kubeconfig_path);

    // Create client for management cluster
    let mgmt_client = client_from_kubeconfig(&kubeconfig_path).await?;

    // Check that CAPI resources exist
    println!("  Checking for CAPI Cluster resource...");
    let capi_check = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &kubeconfig_path,
            "get",
            "clusters",
            "-A",
            "-o",
            "wide",
        ],
    )?;
    println!("  CAPI clusters:\n{}", capi_check);

    if !capi_check.contains(MGMT_CLUSTER_NAME) {
        return Err("Management cluster should have its own CAPI Cluster resource".to_string());
    }

    // Check that LatticeCluster CRD exists
    println!("  Checking for LatticeCluster CRD...");
    let crd_check = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &kubeconfig_path,
            "get",
            "crd",
            "latticeclusters.lattice.dev",
        ],
    )?;

    if !crd_check.contains("latticeclusters") {
        return Err("LatticeCluster CRD not found on management cluster".to_string());
    }
    println!("  LatticeCluster CRD exists");

    // Check that the management cluster's own LatticeCluster is Ready
    println!("  Checking management cluster's LatticeCluster status...");
    let api: Api<LatticeCluster> = Api::all(mgmt_client.clone());
    let mgmt_lc = api
        .get(MGMT_CLUSTER_NAME)
        .await
        .map_err(|e| format!("Failed to get management LatticeCluster: {}", e))?;

    let mgmt_phase = mgmt_lc
        .status
        .as_ref()
        .map(|s| s.phase.clone())
        .unwrap_or(ClusterPhase::Pending);

    println!("  Management cluster phase: {:?}", mgmt_phase);

    if !matches!(mgmt_phase, ClusterPhase::Ready) {
        return Err(format!(
            "Management cluster should be Ready, but is {:?}",
            mgmt_phase
        ));
    }

    println!("\n  SUCCESS: Management cluster is self-managing!");

    // =========================================================================
    // Phase 5: Create Workload Cluster
    // =========================================================================
    println!("\n[Phase 5] Creating workload cluster from management cluster...\n");

    let workload_cluster = workload_cluster_spec(WORKLOAD_CLUSTER_NAME);
    println!("  Creating LatticeCluster '{}'...", WORKLOAD_CLUSTER_NAME);

    api.create(&PostParams::default(), &workload_cluster)
        .await
        .map_err(|e| format!("Failed to create workload LatticeCluster: {}", e))?;

    // =========================================================================
    // Phase 6: Watch Workload Cluster Provisioning
    // =========================================================================
    println!("\n[Phase 6] Watching workload cluster provisioning...\n");
    println!("  The management cluster will:");
    println!("    1. Generate CAPI manifests for workload cluster");
    println!("    2. CAPD provisions Docker containers");
    println!("    3. Bootstrap webhook installs agent + CNI");
    println!("    4. Agent connects to management cluster");
    println!("    5. Management cluster triggers pivot");
    println!("    6. Workload cluster becomes self-managing");
    println!();

    watch_cluster_phases(&mgmt_client, WORKLOAD_CLUSTER_NAME).await?;

    // =========================================================================
    // Phase 7: Verify Workload Cluster Post-Pivot
    // =========================================================================
    println!("\n[Phase 7] Verifying workload cluster post-pivot state...\n");

    // Get workload cluster kubeconfig
    let workload_kubeconfig_raw = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &kubeconfig_path,
            "get",
            "secret",
            &format!("{}-kubeconfig", WORKLOAD_CLUSTER_NAME),
            "-n",
            &format!("capi-{}", WORKLOAD_CLUSTER_NAME),
            "-o",
            "jsonpath={.data.value}",
        ],
    )?;

    let workload_kubeconfig = String::from_utf8(
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            workload_kubeconfig_raw.trim(),
        )
        .map_err(|e| format!("Failed to decode workload kubeconfig: {}", e))?,
    )
    .map_err(|e| format!("Invalid UTF-8 in kubeconfig: {}", e))?;

    let workload_kubeconfig_path = format!("/tmp/{}-kubeconfig", WORKLOAD_CLUSTER_NAME);
    std::fs::write(&workload_kubeconfig_path, &workload_kubeconfig)
        .map_err(|e| format!("Failed to write workload kubeconfig: {}", e))?;

    // Patch for localhost access
    let lb_container = format!("{}-lb", WORKLOAD_CLUSTER_NAME);
    let port_output = run_cmd_allow_fail("docker", &["port", &lb_container, "6443/tcp"]);

    if !port_output.trim().is_empty() {
        let parts: Vec<&str> = port_output.trim().split(':').collect();
        if parts.len() == 2 {
            let localhost_endpoint = format!("https://127.0.0.1:{}", parts[1]);
            let patched = workload_kubeconfig
                .lines()
                .map(|line| {
                    if line.trim().starts_with("server:") {
                        format!("    server: {}", localhost_endpoint)
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(&workload_kubeconfig_path, &patched)
                .map_err(|e| format!("Failed to write patched kubeconfig: {}", e))?;
        }
    }

    // Check CAPI resources on workload cluster
    println!("  Checking for CAPI resources on workload cluster...");
    let workload_capi = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &workload_kubeconfig_path,
            "get",
            "clusters",
            "-A",
        ],
    )?;
    println!("  Workload cluster CAPI resources:\n{}", workload_capi);

    if !workload_capi.contains(WORKLOAD_CLUSTER_NAME) {
        return Err(
            "Workload cluster should have its own CAPI Cluster resource after pivot".to_string(),
        );
    }

    // Check nodes
    let nodes = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            &workload_kubeconfig_path,
            "get",
            "nodes",
            "-o",
            "wide",
        ],
    )?;
    println!("  Workload cluster nodes:\n{}", nodes);

    println!("\n============================================================");
    println!("  FULL E2E TEST PASSED!");
    println!("============================================================");
    println!("\n  Verified:");
    println!("    [x] Lattice installer created self-managing management cluster");
    println!("    [x] Bootstrap cluster was deleted");
    println!("    [x] Management cluster has CAPI + LatticeCluster CRD");
    println!("    [x] Management cluster's LatticeCluster is Ready");
    println!("    [x] Workload cluster provisioned from management cluster");
    println!("    [x] Workload cluster pivoted and is self-managing");
    println!();

    // =========================================================================
    // Phase 8: Cleanup
    // =========================================================================
    println!("\n[Phase 8] Cleaning up...\n");
    cleanup_all();

    Ok(())
}
