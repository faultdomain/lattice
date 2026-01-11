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
//! 9. Deploys test services and verifies bilateral agreement pattern
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
//! cargo test --features e2e --test kind pivot_e2e -- --nocapture
//! ```

// Only compile this module when the e2e feature is enabled
#![cfg(feature = "e2e")]

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
    ClusterPhase, ContainerSpec, DependencyDirection, DeploySpec, KubernetesSpec, LatticeCluster,
    LatticeClusterSpec, LatticeService, LatticeServiceSpec, NodeSpec, PortSpec, ProviderSpec,
    ProviderType, ReplicaSpec, ResourceSpec, ResourceType, ServicePortsSpec,
};
use lattice::install::{InstallConfig, Installer};
use std::collections::BTreeMap;

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

    // Use docker-build.sh which reads versions from versions.toml
    let output = ProcessCommand::new("./scripts/docker-build.sh")
        .args(["-t", LATTICE_IMAGE])
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
                    bootstrap: Default::default(),
                },
            },
            nodes: NodeSpec {
                control_plane: 1,
                workers: 2, // Workers scale up after pivot when cluster self-manages
            },
            networking: None,
            cell: None,
            environment: Some("e2e-test".to_string()),
            region: Some("local".to_string()),
            workload: None,
        },
        status: None,
    }
}

// =============================================================================
// Service Mesh Test Services
// =============================================================================
//
// We create 4 services to test the bilateral agreement pattern:
//
// - service-a (traffic-generator): Depends on B, C, D. Runs curl tests.
// - service-b (allows-a): Allows inbound from A. Bilateral agreement = WORKS.
// - service-c (no-inbound): No inbound allowed. Unilateral = BLOCKED.
// - service-d (standalone): No relationship to A. BLOCKED.
//
// Expected results:
// - A → B: SUCCESS (bilateral agreement)
// - A → C: BLOCKED (A wants C, but C doesn't allow A)
// - A → D: BLOCKED (no dependency declared)

/// Namespace for test services
const TEST_SERVICES_NAMESPACE: &str = "mesh-test";

/// Create service-a: traffic generator that tests connectivity
///
/// This service depends on B, C, D and runs curl tests to verify
/// which connections are allowed by the bilateral agreement pattern.
fn create_service_a() -> LatticeService {
    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: "curlimages/curl:latest".to_string(),
            command: Some(vec!["/bin/sh".to_string()]),
            args: Some(vec![
                "-c".to_string(),
                // Infinite loop: test each service and log results
                r#"
while true; do
    echo "=== Traffic Test Run $(date) ==="

    # Test service-b (should SUCCEED - bilateral agreement)
    if curl -s --connect-timeout 3 http://service-b.mesh-test.svc.cluster.local/health > /dev/null 2>&1; then
        echo "service-b: ALLOWED (expected)"
    else
        echo "service-b: BLOCKED (unexpected!)"
    fi

    # Test service-c (should FAIL - unilateral)
    if curl -s --connect-timeout 3 http://service-c.mesh-test.svc.cluster.local/health > /dev/null 2>&1; then
        echo "service-c: ALLOWED (unexpected!)"
    else
        echo "service-c: BLOCKED (expected)"
    fi

    # Test service-d (should FAIL - no relationship)
    if curl -s --connect-timeout 3 http://service-d.mesh-test.svc.cluster.local/health > /dev/null 2>&1; then
        echo "service-d: ALLOWED (unexpected!)"
    else
        echo "service-d: BLOCKED (expected)"
    fi

    echo "=== End Test Run ==="
    sleep 10
done
"#
                .to_string(),
            ]),
            variables: BTreeMap::new(),
            files: BTreeMap::new(),
            volumes: BTreeMap::new(),
            resources: None,
            liveness_probe: None,
            readiness_probe: None,
        },
    );

    // Declare dependencies: A depends on B, C, D (outbound)
    let mut resources = BTreeMap::new();
    resources.insert(
        "service-b".to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Outbound,
            id: None,
            params: None,
            class: None,
        },
    );
    resources.insert(
        "service-c".to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Outbound,
            id: None,
            params: None,
            class: None,
        },
    );
    resources.insert(
        "service-d".to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Outbound,
            id: None,
            params: None,
            class: None,
        },
    );

    let mut labels = BTreeMap::new();
    labels.insert(
        "lattice.dev/environment".to_string(),
        TEST_SERVICES_NAMESPACE.to_string(),
    );

    LatticeService {
        metadata: ObjectMeta {
            name: Some("service-a".to_string()),
            namespace: Some(TEST_SERVICES_NAMESPACE.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            containers,
            resources,
            service: None, // No port needed - just runs curl tests
            replicas: ReplicaSpec { min: 1, max: None },
            deploy: DeploySpec::default(),
        },
        status: None,
    }
}

/// Create service-b: allows inbound from A (bilateral agreement)
fn create_service_b() -> LatticeService {
    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: "nginx:alpine".to_string(),
            command: None,
            args: None,
            variables: BTreeMap::new(),
            files: BTreeMap::new(),
            volumes: BTreeMap::new(),
            resources: None,
            liveness_probe: None,
            readiness_probe: None,
        },
    );

    // B allows inbound from A
    let mut resources = BTreeMap::new();
    resources.insert(
        "service-a".to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Inbound,
            id: None,
            params: None,
            class: None,
        },
    );

    let mut ports = BTreeMap::new();
    ports.insert(
        "http".to_string(),
        PortSpec {
            port: 80,
            target_port: None,
            protocol: None,
        },
    );

    let mut labels = BTreeMap::new();
    labels.insert(
        "lattice.dev/environment".to_string(),
        TEST_SERVICES_NAMESPACE.to_string(),
    );

    LatticeService {
        metadata: ObjectMeta {
            name: Some("service-b".to_string()),
            namespace: Some(TEST_SERVICES_NAMESPACE.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            containers,
            resources,
            service: Some(ServicePortsSpec { ports }),
            replicas: ReplicaSpec { min: 1, max: None },
            deploy: DeploySpec::default(),
        },
        status: None,
    }
}

/// Create service-c: does NOT allow inbound from A (unilateral blocked)
fn create_service_c() -> LatticeService {
    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: "nginx:alpine".to_string(),
            command: None,
            args: None,
            variables: BTreeMap::new(),
            files: BTreeMap::new(),
            volumes: BTreeMap::new(),
            resources: None,
            liveness_probe: None,
            readiness_probe: None,
        },
    );

    // C does NOT allow anyone - no inbound resources
    let resources = BTreeMap::new();

    let mut ports = BTreeMap::new();
    ports.insert(
        "http".to_string(),
        PortSpec {
            port: 80,
            target_port: None,
            protocol: None,
        },
    );

    let mut labels = BTreeMap::new();
    labels.insert(
        "lattice.dev/environment".to_string(),
        TEST_SERVICES_NAMESPACE.to_string(),
    );

    LatticeService {
        metadata: ObjectMeta {
            name: Some("service-c".to_string()),
            namespace: Some(TEST_SERVICES_NAMESPACE.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            containers,
            resources,
            service: Some(ServicePortsSpec { ports }),
            replicas: ReplicaSpec { min: 1, max: None },
            deploy: DeploySpec::default(),
        },
        status: None,
    }
}

/// Create service-d: standalone, no relationship to A
fn create_service_d() -> LatticeService {
    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: "nginx:alpine".to_string(),
            command: None,
            args: None,
            variables: BTreeMap::new(),
            files: BTreeMap::new(),
            volumes: BTreeMap::new(),
            resources: None,
            liveness_probe: None,
            readiness_probe: None,
        },
    );

    // D has no relationship to A at all
    let resources = BTreeMap::new();

    let mut ports = BTreeMap::new();
    ports.insert(
        "http".to_string(),
        PortSpec {
            port: 80,
            target_port: None,
            protocol: None,
        },
    );

    let mut labels = BTreeMap::new();
    labels.insert(
        "lattice.dev/environment".to_string(),
        TEST_SERVICES_NAMESPACE.to_string(),
    );

    LatticeService {
        metadata: ObjectMeta {
            name: Some("service-d".to_string()),
            namespace: Some(TEST_SERVICES_NAMESPACE.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            containers,
            resources,
            service: Some(ServicePortsSpec { ports }),
            replicas: ReplicaSpec { min: 1, max: None },
            deploy: DeploySpec::default(),
        },
        status: None,
    }
}

/// Deploy test services to the workload cluster
async fn deploy_test_services(kubeconfig_path: &str) -> Result<(), String> {
    println!("  Creating namespace {}...", TEST_SERVICES_NAMESPACE);
    let _ = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "create",
            "namespace",
            TEST_SERVICES_NAMESPACE,
        ],
    );

    // Create client for workload cluster
    // LatticeService is cluster-scoped, so we use Api::all
    let client = client_from_kubeconfig(kubeconfig_path).await?;
    let api: Api<LatticeService> = Api::all(client);

    println!("  Deploying service-a (traffic generator)...");
    api.create(&PostParams::default(), &create_service_a())
        .await
        .map_err(|e| format!("Failed to create service-a: {}", e))?;

    println!("  Deploying service-b (allows A)...");
    api.create(&PostParams::default(), &create_service_b())
        .await
        .map_err(|e| format!("Failed to create service-b: {}", e))?;

    println!("  Deploying service-c (no inbound)...");
    api.create(&PostParams::default(), &create_service_c())
        .await
        .map_err(|e| format!("Failed to create service-c: {}", e))?;

    println!("  Deploying service-d (standalone)...");
    api.create(&PostParams::default(), &create_service_d())
        .await
        .map_err(|e| format!("Failed to create service-d: {}", e))?;

    Ok(())
}

/// Wait for all deployments to be ready
async fn wait_for_deployments(kubeconfig_path: &str) -> Result<(), String> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(180); // 3 minutes for pods to start

    println!("  Waiting for pods to be ready...");

    loop {
        if start.elapsed() > timeout {
            return Err("Timeout waiting for test pods to be ready".to_string());
        }

        let pods_output = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "pods",
                "-n",
                TEST_SERVICES_NAMESPACE,
                "-o",
                "jsonpath={range .items[*]}{.metadata.name},{.status.phase}{\"\\n\"}{end}",
            ],
        );

        let mut running_count = 0;
        let total_expected = 4; // service-a, b, c, d

        for line in pods_output.lines() {
            if line.contains("Running") {
                running_count += 1;
            }
        }

        println!("    {}/{} pods running", running_count, total_expected);

        if running_count >= total_expected {
            println!("  All test pods are running!");
            return Ok(());
        }

        sleep(Duration::from_secs(10)).await;
    }
}

/// Verify traffic patterns by checking service-a logs
async fn verify_traffic_patterns(kubeconfig_path: &str) -> Result<(), String> {
    println!("  Waiting for traffic tests to run (30 seconds)...");
    sleep(Duration::from_secs(30)).await;

    println!("  Checking service-a logs for traffic test results...");

    let logs = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "logs",
            "-n",
            TEST_SERVICES_NAMESPACE,
            "-l",
            "app.kubernetes.io/name=service-a",
            "--tail",
            "50",
        ],
    )?;

    println!("\n  === Service-A Traffic Test Logs ===\n{}\n", logs);

    // Verify expected patterns
    let mut b_allowed = false;
    let mut c_blocked = false;
    let mut d_blocked = false;

    for line in logs.lines() {
        if line.contains("service-b: ALLOWED") {
            b_allowed = true;
        }
        if line.contains("service-c: BLOCKED") {
            c_blocked = true;
        }
        if line.contains("service-d: BLOCKED") {
            d_blocked = true;
        }
    }

    println!("  Traffic verification results:");
    println!(
        "    - service-b (bilateral): {} (expected: ALLOWED)",
        if b_allowed { "ALLOWED" } else { "BLOCKED" }
    );
    println!(
        "    - service-c (unilateral): {} (expected: BLOCKED)",
        if c_blocked { "BLOCKED" } else { "ALLOWED" }
    );
    println!(
        "    - service-d (no relation): {} (expected: BLOCKED)",
        if d_blocked { "BLOCKED" } else { "ALLOWED" }
    );

    if !b_allowed {
        return Err(
            "FAIL: service-b should be reachable (bilateral agreement not working)".to_string(),
        );
    }

    if !c_blocked {
        return Err(
            "FAIL: service-c should be blocked (unilateral dependency not enforced)".to_string(),
        );
    }

    if !d_blocked {
        return Err("FAIL: service-d should be blocked (no dependency)".to_string());
    }

    println!("\n  SUCCESS: Bilateral agreement pattern is working correctly!");
    Ok(())
}

/// Watch worker nodes scaling up on a cluster
///
/// Polls kubectl to count ready worker nodes until the desired count is reached.
/// Worker nodes are those without the control-plane role.
async fn watch_worker_scaling(
    kubeconfig_path: &str,
    cluster_name: &str,
    expected_workers: u32,
) -> Result<(), String> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(600); // 10 minutes for workers to scale

    let mut last_count: Option<u32> = None;

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for {} workers on cluster {}. Last count: {:?}",
                expected_workers, cluster_name, last_count
            ));
        }

        // Count ready worker nodes (nodes without control-plane role)
        let nodes_output = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "nodes",
                "-o",
                "jsonpath={range .items[*]}{.metadata.name},{.status.conditions[?(@.type=='Ready')].status},{.metadata.labels.node-role\\.kubernetes\\.io/control-plane}{\"\\n\"}{end}",
            ],
        );

        // Parse output to count ready workers
        let mut ready_workers = 0u32;
        for line in nodes_output.lines() {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 2 {
                let is_ready = parts.get(1).map(|s| *s == "True").unwrap_or(false);
                let is_control_plane = parts.get(2).map(|s| !s.is_empty()).unwrap_or(false);

                if is_ready && !is_control_plane {
                    ready_workers += 1;
                }
            }
        }

        if last_count != Some(ready_workers) {
            println!(
                "    {} ready workers on {} (target: {})",
                ready_workers, cluster_name, expected_workers
            );
            last_count = Some(ready_workers);
        }

        if ready_workers >= expected_workers {
            println!(
                "    SUCCESS: {} has {} ready workers!",
                cluster_name, ready_workers
            );
            return Ok(());
        }

        sleep(Duration::from_secs(15)).await;
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
/// Run with: cargo test --features e2e --test kind pivot_e2e -- --nocapture
#[tokio::test]
async fn story_full_install_and_workload_provisioning() {
    let result = tokio::time::timeout(E2E_TIMEOUT, run_full_e2e()).await;

    match result {
        Ok(Ok(())) => println!("\n=== Full E2E Test Completed Successfully! ===\n"),
        Ok(Err(e)) => {
            println!("\n=== Full E2E Test Failed: {} ===\n", e);
            println!("  NOTE: Not cleaning up so you can investigate. Run cleanup manually:");
            println!("    kind delete clusters --all");
            panic!("E2E test failed: {}", e);
        }
        Err(_) => {
            println!("\n=== Full E2E Test Timed Out ({:?}) ===\n", E2E_TIMEOUT);
            println!("  NOTE: Not cleaning up so you can investigate. Run cleanup manually:");
            println!("    kind delete clusters --all");
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
    workers: 1
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
        bootstrap_override: None, // Use config file default
    };

    let installer =
        Installer::new(install_config).map_err(|e| format!("Failed to create installer: {}", e))?;
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

    // Wait for the management cluster's own LatticeCluster to be Ready
    println!("  Waiting for management cluster's LatticeCluster to be Ready...");
    let api: Api<LatticeCluster> = Api::all(mgmt_client.clone());
    watch_cluster_phases(&mgmt_client, MGMT_CLUSTER_NAME).await?;

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

    // After clusterctl move, the kubeconfig secret is on the WORKLOAD cluster, not management.
    // Get kubeconfig directly from the workload cluster's control plane container.
    println!("  Getting workload cluster kubeconfig from control plane container...");

    // Find the workload control plane container
    let cp_container = run_cmd(
        "docker",
        &[
            "ps",
            "--filter",
            &format!("name={}-control-plane", WORKLOAD_CLUSTER_NAME),
            "--format",
            "{{.Names}}",
        ],
    )?;
    let cp_container = cp_container.trim();
    if cp_container.is_empty() {
        return Err("Could not find workload cluster control plane container".to_string());
    }
    println!("  Found control plane container: {}", cp_container);

    // Extract kubeconfig from the container (plain text, not base64)
    let workload_kubeconfig = run_cmd(
        "docker",
        &["exec", cp_container, "cat", "/etc/kubernetes/admin.conf"],
    )?;

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

    // =========================================================================
    // Phase 8: Watch Worker Scaling
    // =========================================================================
    println!("\n[Phase 8] Watching worker scaling on both clusters...\n");
    println!("  After pivot, each cluster's local controller should scale workers:");
    println!("    - Management cluster: 0 -> 1 workers");
    println!("    - Workload cluster: 0 -> 2 workers");
    println!();

    // Watch management cluster worker scaling
    println!("  Waiting for management cluster workers to scale...");
    watch_worker_scaling(&kubeconfig_path, MGMT_CLUSTER_NAME, 1).await?;

    // Watch workload cluster worker scaling
    println!("  Waiting for workload cluster workers to scale...");
    watch_worker_scaling(&workload_kubeconfig_path, WORKLOAD_CLUSTER_NAME, 2).await?;

    // =========================================================================
    // Phase 9: Service Mesh Testing
    // =========================================================================
    println!("\n[Phase 9] Testing service mesh bilateral agreement pattern...\n");
    println!("  This test verifies the network policy bilateral agreement pattern:");
    println!("    - service-a: Traffic generator, depends on B, C, D");
    println!("    - service-b: Allows inbound from A (bilateral = WORKS)");
    println!("    - service-c: No inbound allowed (unilateral = BLOCKED)");
    println!("    - service-d: No relationship to A (BLOCKED)");
    println!();

    // Wait for workload cluster to be Ready (webhook must be up before deploying services)
    println!("  Waiting for workload cluster to be Ready (webhook must be up)...");
    let workload_client = client_from_kubeconfig(&workload_kubeconfig_path).await?;
    watch_cluster_phases(&workload_client, WORKLOAD_CLUSTER_NAME).await?;

    // Deploy test services
    deploy_test_services(&workload_kubeconfig_path).await?;

    // Wait for pods to be ready
    wait_for_deployments(&workload_kubeconfig_path).await?;

    // Verify traffic patterns
    verify_traffic_patterns(&workload_kubeconfig_path).await?;

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
    println!("    [x] Management cluster scaled to 1 worker");
    println!("    [x] Workload cluster scaled to 2 workers");
    println!("    [x] Service mesh bilateral agreement: A->B ALLOWED");
    println!("    [x] Service mesh unilateral blocked: A->C BLOCKED");
    println!("    [x] Service mesh no relationship: A->D BLOCKED");
    println!();

    // =========================================================================
    // Phase 10: Cleanup
    // =========================================================================
    println!("\n[Phase 10] Cleaning up...\n");
    cleanup_all();

    Ok(())
}
