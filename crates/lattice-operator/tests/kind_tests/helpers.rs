//! Test helpers for integration tests
//!
//! Provides utilities for managing kind clusters and Kubernetes resources.

use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, DeleteParams, PostParams};
use kube::{Client, Config, CustomResourceExt};
use tokio::sync::OnceCell;
use tokio::time::sleep;

use lattice_operator::crd::LatticeCluster;
#[cfg(feature = "provider-e2e")]
use lattice_operator::crd::{BootstrapProvider, ClusterPhase};

// =============================================================================
// Docker Network Constants
// =============================================================================

/// Docker network subnet for kind/CAPD clusters
/// This must be pinned because Cilium LB-IPAM uses IPs from this range (172.18.255.x)
#[cfg(feature = "provider-e2e")]
pub const DOCKER_KIND_SUBNET: &str = "172.18.0.0/16";
#[cfg(feature = "provider-e2e")]
pub const DOCKER_KIND_GATEWAY: &str = "172.18.0.1";

/// Name of the kind cluster used for integration tests
pub const TEST_CLUSTER_NAME: &str = "lattice-integration-test";

/// Global lock to ensure cluster is created only once
static CLUSTER_INIT: OnceLock<Result<(), String>> = OnceLock::new();

/// Track if CRD has been installed (async-safe)
static CRD_INSTALLED: OnceCell<Result<(), String>> = OnceCell::const_new();

/// Check if a kind cluster with the given name exists
pub fn kind_cluster_exists(name: &str) -> bool {
    let output = Command::new("kind")
        .args(["get", "clusters"])
        .output()
        .expect("failed to run kind");

    let clusters = String::from_utf8_lossy(&output.stdout);
    clusters.lines().any(|line| line.trim() == name)
}

/// Create a kind cluster for testing
pub fn create_kind_cluster(name: &str) -> Result<(), String> {
    if kind_cluster_exists(name) {
        println!("Kind cluster '{name}' already exists, reusing it");
        return Ok(());
    }

    println!("Creating kind cluster '{name}'...");
    let output = Command::new("kind")
        .args(["create", "cluster", "--name", name, "--wait", "60s"])
        .output()
        .map_err(|e| format!("failed to run kind: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "failed to create kind cluster: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    println!("Kind cluster '{name}' created successfully");
    Ok(())
}

/// Delete a kind cluster
#[allow(dead_code)]
pub fn delete_kind_cluster(name: &str) -> Result<(), String> {
    if !kind_cluster_exists(name) {
        return Ok(());
    }

    println!("Deleting kind cluster '{name}'...");
    let output = Command::new("kind")
        .args(["delete", "cluster", "--name", name])
        .output()
        .map_err(|e| format!("failed to run kind: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "failed to delete kind cluster: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

/// Install the LatticeCluster CRD into the cluster
pub async fn install_crd(client: &Client) -> Result<(), kube::Error> {
    let crd = LatticeCluster::crd();
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());

    // Check if CRD already exists
    match crds.get(&crd.metadata.name.clone().unwrap()).await {
        Ok(_) => {
            println!("CRD already installed, deleting and reinstalling...");
            crds.delete(
                &crd.metadata.name.clone().unwrap(),
                &DeleteParams::default(),
            )
            .await?;
            // Wait for deletion
            sleep(Duration::from_secs(2)).await;
        }
        Err(kube::Error::Api(e)) if e.code == 404 => {
            // CRD doesn't exist, continue with installation
        }
        Err(e) => return Err(e),
    }

    println!("Installing LatticeCluster CRD...");
    crds.create(&PostParams::default(), &crd).await?;

    // Wait for CRD to be established
    sleep(Duration::from_secs(2)).await;

    println!("CRD installed successfully");
    Ok(())
}

/// Create a Kubernetes client connected to the test cluster
pub async fn create_test_client() -> Result<Client, String> {
    // Use the kind cluster context directly without modifying kubeconfig
    let context_name = format!("kind-{TEST_CLUSTER_NAME}");

    let config = Config::from_kubeconfig(&kube::config::KubeConfigOptions {
        context: Some(context_name),
        ..Default::default()
    })
    .await
    .map_err(|e| format!("failed to load kubeconfig: {e}"))?;

    Client::try_from(config).map_err(|e| format!("failed to create client: {e}"))
}

/// Ensure the test cluster is ready (thread-safe, cluster created once)
///
/// Returns a fresh Client for each call - clients should not be shared across test threads.
pub async fn ensure_test_cluster() -> Result<Client, String> {
    // Install default crypto provider (required for rustls)
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Ensure cluster is created exactly once using OnceLock (sync is fine for shell commands)
    let cluster_result = CLUSTER_INIT.get_or_init(|| create_kind_cluster(TEST_CLUSTER_NAME));

    // Check if cluster creation succeeded
    cluster_result.clone()?;

    // Create a fresh client for this test
    let client = create_test_client().await?;

    // Install CRD if not already installed (async-safe)
    let crd_result = CRD_INSTALLED
        .get_or_init(|| async {
            let client = create_test_client().await?;
            install_crd(&client)
                .await
                .map_err(|e| format!("failed to install CRD: {e}"))
        })
        .await;

    crd_result.clone()?;

    Ok(client)
}

// =============================================================================
// Docker Network Helpers
// =============================================================================

/// Ensure the Docker "kind" network exists with the correct subnet
///
/// Docker assigns subnets dynamically when creating networks. If the "kind" network
/// is recreated (e.g., after `docker network rm` or system restart), it may get a
/// different subnet. This breaks Cilium LB-IPAM which expects IPs in 172.18.255.x.
///
/// This function ensures the network exists with the pinned subnet.
#[cfg(feature = "provider-e2e")]
pub fn ensure_docker_network() -> Result<(), String> {
    println!(
        "  Ensuring Docker 'kind' network has correct subnet ({})...",
        DOCKER_KIND_SUBNET
    );

    // Check if the network exists
    let inspect_output = Command::new("docker")
        .args([
            "network",
            "inspect",
            "kind",
            "--format",
            "{{range .IPAM.Config}}{{.Subnet}}{{end}}",
        ])
        .output();

    match inspect_output {
        Ok(output) if output.status.success() => {
            let current_subnet = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if current_subnet == DOCKER_KIND_SUBNET {
                println!("  Docker 'kind' network already has correct subnet");
                return Ok(());
            }
            // Network exists but with wrong subnet - need to recreate
            println!(
                "  Docker 'kind' network has wrong subnet ({}), recreating...",
                current_subnet
            );

            // Check if any containers are using the network
            let containers = run_cmd_allow_fail(
                "docker",
                &[
                    "network",
                    "inspect",
                    "kind",
                    "--format",
                    "{{range .Containers}}{{.Name}} {{end}}",
                ],
            );
            if !containers.trim().is_empty() {
                return Err(format!(
                    "Cannot recreate 'kind' network - containers still attached: {}. Stop them first.",
                    containers.trim()
                ));
            }

            // Remove the network
            run_cmd("docker", &["network", "rm", "kind"])?;
        }
        _ => {
            // Network doesn't exist
            println!("  Docker 'kind' network doesn't exist, creating...");
        }
    }

    // Create the network with the correct subnet
    run_cmd(
        "docker",
        &[
            "network",
            "create",
            "--driver=bridge",
            &format!("--subnet={}", DOCKER_KIND_SUBNET),
            &format!("--gateway={}", DOCKER_KIND_GATEWAY),
            "kind",
        ],
    )?;

    println!(
        "  Docker 'kind' network created with subnet {}",
        DOCKER_KIND_SUBNET
    );
    Ok(())
}

// =============================================================================
// Command Execution Helpers
// =============================================================================

/// Run a shell command and return output
#[cfg(feature = "provider-e2e")]
pub fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cmd)
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

/// Run a shell command, allowing failure (returns empty string on error)
#[cfg(feature = "provider-e2e")]
pub fn run_cmd_allow_fail(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

// =============================================================================
// Kubeconfig Helpers for Docker-based Clusters
// =============================================================================

/// Get the kubeconfig path inside the container based on bootstrap provider
#[cfg(feature = "provider-e2e")]
pub fn get_kubeconfig_path_for_bootstrap(bootstrap: &BootstrapProvider) -> &'static str {
    match bootstrap {
        BootstrapProvider::Kubeadm => "/etc/kubernetes/admin.conf",
        BootstrapProvider::Rke2 => "/etc/rancher/rke2/rke2.yaml",
    }
}

/// Extract and patch kubeconfig for a Docker-based (CAPD) cluster
///
/// This function:
/// 1. Finds the control plane container for the cluster
/// 2. Extracts the kubeconfig from inside the container
/// 3. Patches the server URL to use localhost with the correct port mapping
/// 4. Writes the patched kubeconfig to the specified output path
///
/// # Arguments
/// * `cluster_name` - Name of the cluster (used to find containers)
/// * `bootstrap` - Bootstrap provider (determines kubeconfig path inside container)
/// * `output_path` - Path where the patched kubeconfig will be written
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` with descriptive error on failure
#[cfg(feature = "provider-e2e")]
pub fn extract_docker_cluster_kubeconfig(
    cluster_name: &str,
    bootstrap: &BootstrapProvider,
    output_path: &str,
) -> Result<(), String> {
    // Find the control plane container
    let cp_container = run_cmd(
        "docker",
        &[
            "ps",
            "--filter",
            &format!("name={}-control-plane", cluster_name),
            "--format",
            "{{.Names}}",
        ],
    )?;
    let cp_container = cp_container.trim();
    if cp_container.is_empty() {
        return Err(format!(
            "Could not find control plane container for cluster '{}'",
            cluster_name
        ));
    }
    println!("  Found control plane container: {}", cp_container);

    // Extract kubeconfig from the container
    let kubeconfig_container_path = get_kubeconfig_path_for_bootstrap(bootstrap);
    println!("  Extracting kubeconfig from {}", kubeconfig_container_path);
    let kubeconfig = run_cmd(
        "docker",
        &["exec", cp_container, "cat", kubeconfig_container_path],
    )?;

    // Write initial kubeconfig
    std::fs::write(output_path, &kubeconfig)
        .map_err(|e| format!("Failed to write kubeconfig to {}: {}", output_path, e))?;

    // Find the load balancer port mapping and patch the kubeconfig for localhost access
    let lb_container = format!("{}-lb", cluster_name);
    let port_output = run_cmd_allow_fail("docker", &["port", &lb_container, "6443/tcp"]);

    if !port_output.trim().is_empty() {
        let parts: Vec<&str> = port_output.trim().split(':').collect();
        if parts.len() == 2 {
            let localhost_endpoint = format!("https://127.0.0.1:{}", parts[1]);
            println!("  Patching kubeconfig server to {}", localhost_endpoint);
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
            std::fs::write(output_path, &patched)
                .map_err(|e| format!("Failed to write patched kubeconfig: {}", e))?;
        }
    } else {
        println!(
            "  Warning: Could not find load balancer port mapping for {}",
            lb_container
        );
    }

    Ok(())
}

// =============================================================================
// Cluster Status Watching
// =============================================================================

/// Watch LatticeCluster phase transitions until Ready or Failed
///
/// # Arguments
/// * `client` - Kubernetes client
/// * `cluster_name` - Name of the cluster to watch
/// * `timeout_secs` - Timeout in seconds (default 1800 = 30 minutes if None)
#[cfg(feature = "provider-e2e")]
pub async fn watch_cluster_phases(
    client: &Client,
    cluster_name: &str,
    timeout_secs: Option<u64>,
) -> Result<(), String> {
    let api: Api<LatticeCluster> = Api::all(client.clone());

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(1800));

    let mut last_phase: Option<ClusterPhase> = None;

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for cluster {} to reach Ready state. Last phase: {:?}",
                cluster_name, last_phase
            ));
        }

        match api.get(cluster_name).await {
            Ok(cluster) => {
                let current_phase = cluster
                    .status
                    .as_ref()
                    .map(|s| s.phase.clone())
                    .unwrap_or(ClusterPhase::Pending);

                // Only print when phase changes
                if last_phase.as_ref() != Some(&current_phase) {
                    println!("  Cluster {} phase: {:?}", cluster_name, current_phase);
                    last_phase = Some(current_phase.clone());
                }

                if matches!(current_phase, ClusterPhase::Ready) {
                    println!("  Cluster {} reached Ready state!", cluster_name);
                    return Ok(());
                }

                if matches!(current_phase, ClusterPhase::Failed) {
                    let msg = cluster
                        .status
                        .as_ref()
                        .and_then(|s| s.message.as_deref())
                        .unwrap_or("unknown error");
                    return Err(format!("Cluster {} failed: {}", cluster_name, msg));
                }
            }
            Err(e) => {
                println!(
                    "  Warning: failed to get cluster {} status: {}",
                    cluster_name, e
                );
            }
        }

        sleep(Duration::from_secs(10)).await;
    }
}

/// Watch for worker nodes to scale to expected count
///
/// Worker nodes are those without the control-plane role.
#[cfg(feature = "provider-e2e")]
pub async fn watch_worker_scaling(
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

        // Count ready worker nodes using label selector to exclude control-plane
        let nodes_output = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "nodes",
                "-l",
                "!node-role.kubernetes.io/control-plane",
                "-o",
                "jsonpath={range .items[*]}{.status.conditions[?(@.type=='Ready')].status}{\"\\n\"}{end}",
            ],
        );

        // Count ready workers (only worker nodes returned due to label selector)
        let ready_workers = nodes_output.lines().filter(|line| *line == "True").count() as u32;

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

/// Verify control-plane taints are restored on a cluster
///
/// Checks that control-plane nodes have the NoSchedule taint.
#[cfg(feature = "provider-e2e")]
pub async fn verify_control_plane_taints(
    kubeconfig_path: &str,
    _bootstrap: &BootstrapProvider,
) -> Result<(), String> {
    println!("  Verifying control-plane taints are restored...");

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(45);

    loop {
        if start.elapsed() > timeout {
            return Err("Timeout waiting for control-plane taints to be restored".to_string());
        }

        // Get control-plane nodes and their taints
        let taints_output = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "nodes",
                "-l",
                "node-role.kubernetes.io/control-plane",
                "-o",
                "jsonpath={range .items[*]}{.metadata.name}: {.spec.taints[*].key}{\"\\n\"}{end}",
            ],
        );

        // Check if control-plane taint exists
        let has_taint = taints_output
            .lines()
            .any(|line| line.contains("node-role.kubernetes.io/control-plane"));

        if has_taint {
            println!("    Control-plane taints verified");
            return Ok(());
        }

        sleep(Duration::from_secs(5)).await;
    }
}
