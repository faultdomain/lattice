//! Test helpers for e2e tests
//!
//! Provides utilities for Docker-based cluster testing.

#[cfg(feature = "provider-e2e")]
use std::process::Command;
#[cfg(feature = "provider-e2e")]
use std::time::Duration;
#[cfg(feature = "provider-e2e")]
use tokio::time::sleep;
#[cfg(feature = "provider-e2e")]
use tracing::info;

#[cfg(feature = "provider-e2e")]
use kube::config::{KubeConfigOptions, Kubeconfig};
#[cfg(feature = "provider-e2e")]
use kube::Client;

#[cfg(feature = "provider-e2e")]
use lattice_operator::crd::{BootstrapProvider, ClusterPhase};

// =============================================================================
// Kubernetes Client
// =============================================================================

/// Create a kube client from a kubeconfig file with proper timeouts
#[cfg(feature = "provider-e2e")]
pub async fn client_from_kubeconfig(path: &str) -> Result<Client, String> {
    let kubeconfig =
        Kubeconfig::read_from(path).map_err(|e| format!("Failed to read kubeconfig: {}", e))?;

    let mut config =
        kube::Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
            .await
            .map_err(|e| format!("Failed to create kube config: {}", e))?;

    config.connect_timeout = Some(Duration::from_secs(10));
    config.read_timeout = Some(Duration::from_secs(30));

    Client::try_from(config).map_err(|e| format!("Failed to create client: {}", e))
}

// =============================================================================
// Docker Network Constants
// =============================================================================

/// Docker network subnet for kind/CAPD clusters
/// This must be pinned because Cilium LB-IPAM uses IPs from this range (172.18.255.x)
#[cfg(feature = "provider-e2e")]
pub const DOCKER_KIND_SUBNET: &str = "172.18.0.0/16";
#[cfg(feature = "provider-e2e")]
pub const DOCKER_KIND_GATEWAY: &str = "172.18.0.1";

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
    info!(
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
                info!("  Docker 'kind' network already has correct subnet");
                return Ok(());
            }
            // Network exists but with wrong subnet - need to recreate
            info!(
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
            info!("  Docker 'kind' network doesn't exist, creating...");
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

    info!(
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
    info!("  Found control plane container: {}", cp_container);

    // Extract kubeconfig from the container (with retries - file may not exist immediately)
    let kubeconfig_container_path = get_kubeconfig_path_for_bootstrap(bootstrap);
    info!("  Extracting kubeconfig from {}", kubeconfig_container_path);

    let mut kubeconfig = String::new();
    let max_retries = 60; // 5 minutes with 5s intervals
    for attempt in 1..=max_retries {
        match run_cmd(
            "docker",
            &["exec", cp_container, "cat", kubeconfig_container_path],
        ) {
            Ok(content) => {
                kubeconfig = content;
                break;
            }
            Err(e) => {
                if attempt == max_retries {
                    return Err(format!(
                        "Failed to extract kubeconfig after {} attempts: {}",
                        max_retries, e
                    ));
                }
                info!(
                    "  Waiting for kubeconfig to be available (attempt {}/{})...",
                    attempt, max_retries
                );
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }
    }

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
            info!("  Patching kubeconfig server to {}", localhost_endpoint);
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
        info!(
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
    client: &kube::Client,
    cluster_name: &str,
    timeout_secs: Option<u64>,
) -> Result<(), String> {
    use kube::Api;
    use lattice_operator::crd::LatticeCluster;

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

                if last_phase.as_ref() != Some(&current_phase) {
                    info!("Cluster {} phase: {:?}", cluster_name, current_phase);
                    last_phase = Some(current_phase.clone());
                }

                if matches!(current_phase, ClusterPhase::Ready) {
                    info!("Cluster {} reached Ready state!", cluster_name);
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
                info!(
                    "Warning: failed to get cluster {} status: {}",
                    cluster_name, e
                );
            }
        }

        sleep(Duration::from_secs(10)).await;
    }
}

/// Watch LatticeCluster and extract kubeconfig during Provisioning phase
///
/// For cloud providers (Proxmox, AWS, etc.), the kubeconfig secret is moved
/// during pivot. This function extracts it BEFORE pivot so it can be used
/// to access the cluster after pivot completes.
///
/// # Arguments
/// * `mgmt_kubeconfig` - Path to management cluster kubeconfig
/// * `cluster_name` - Name of the cluster to watch
/// * `timeout_secs` - Timeout in seconds (default 1800 = 30 minutes if None)
/// * `kubeconfig_output_path` - Path to write workload cluster kubeconfig
#[cfg(feature = "provider-e2e")]
pub async fn watch_cluster_phases_with_kubeconfig(
    mgmt_kubeconfig: &str,
    cluster_name: &str,
    timeout_secs: Option<u64>,
    kubeconfig_output_path: &str,
) -> Result<(), String> {
    use kube::Api;
    use lattice_operator::crd::LatticeCluster;

    let client = client_from_kubeconfig(mgmt_kubeconfig).await?;
    let api: Api<LatticeCluster> = Api::all(client.clone());

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(1800));

    let mut last_phase: Option<ClusterPhase> = None;
    let mut kubeconfig_extracted = false;

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

                if last_phase.as_ref() != Some(&current_phase) {
                    info!("Cluster {} phase: {:?}", cluster_name, current_phase);
                    last_phase = Some(current_phase.clone());
                }

                // Extract kubeconfig during Provisioning (before pivot moves it)
                if !kubeconfig_extracted
                    && matches!(
                        current_phase,
                        ClusterPhase::Provisioning | ClusterPhase::Pivoting
                    )
                {
                    if let Ok(()) = try_extract_kubeconfig(
                        mgmt_kubeconfig,
                        cluster_name,
                        kubeconfig_output_path,
                    ) {
                        info!(
                            "Kubeconfig extracted to {} (before pivot)",
                            kubeconfig_output_path
                        );
                        kubeconfig_extracted = true;
                    }
                }

                if matches!(current_phase, ClusterPhase::Ready) {
                    info!("Cluster {} reached Ready state!", cluster_name);
                    if !kubeconfig_extracted {
                        return Err(format!(
                            "Cluster {} is Ready but kubeconfig was not extracted before pivot",
                            cluster_name
                        ));
                    }
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
                info!(
                    "Warning: failed to get cluster {} status: {}",
                    cluster_name, e
                );
            }
        }

        sleep(Duration::from_secs(10)).await;
    }
}

/// Try to extract kubeconfig from CAPI secret (non-blocking, returns error if not found)
#[cfg(feature = "provider-e2e")]
fn try_extract_kubeconfig(
    mgmt_kubeconfig: &str,
    cluster_name: &str,
    output_path: &str,
) -> Result<(), String> {
    use base64::Engine;

    let namespace = format!("capi-{}", cluster_name);
    let secret_name = format!("{}-kubeconfig", cluster_name);

    let result = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            mgmt_kubeconfig,
            "get",
            "secret",
            &secret_name,
            "-n",
            &namespace,
            "-o",
            "jsonpath={.data.value}",
        ],
    );

    match result {
        Ok(output) if !output.trim().is_empty() => {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(output.trim())
                .map_err(|e| format!("Failed to decode kubeconfig: {}", e))?;

            let kubeconfig = String::from_utf8(decoded)
                .map_err(|e| format!("Kubeconfig is not valid UTF-8: {}", e))?;

            std::fs::write(output_path, &kubeconfig)
                .map_err(|e| format!("Failed to write kubeconfig: {}", e))?;

            Ok(())
        }
        _ => Err("Kubeconfig secret not found yet".to_string()),
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
            info!(
                "    {} ready workers on {} (target: {})",
                ready_workers, cluster_name, expected_workers
            );
            last_count = Some(ready_workers);
        }

        if ready_workers >= expected_workers {
            info!(
                "    SUCCESS: {} has {} ready workers!",
                cluster_name, ready_workers
            );
            return Ok(());
        }

        sleep(Duration::from_secs(15)).await;
    }
}

// =============================================================================
// Shared Test Configuration
// =============================================================================

#[cfg(feature = "provider-e2e")]
use std::path::PathBuf;

#[cfg(feature = "provider-e2e")]
use lattice_operator::crd::LatticeCluster;

/// Get the workspace root directory
#[cfg(feature = "provider-e2e")]
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("lattice-cli crate should have a parent directory")
        .parent()
        .expect("crates directory should have a parent (workspace root)")
        .to_path_buf()
}

/// Get the fixtures directory for cluster configs
#[cfg(feature = "provider-e2e")]
pub fn cluster_fixtures_dir() -> PathBuf {
    workspace_root().join("crates/lattice-cli/tests/e2e/fixtures/clusters")
}

/// Get the fixtures directory for service configs
#[cfg(feature = "provider-e2e")]
#[allow(dead_code)] // Used by media_server_e2e (currently disabled)
pub fn service_fixtures_dir() -> PathBuf {
    workspace_root().join("crates/lattice-cli/tests/e2e/fixtures/services")
}

/// Build and push the lattice Docker image
#[cfg(feature = "provider-e2e")]
pub async fn build_and_push_lattice_image(image: &str) -> Result<(), String> {
    info!("  Building lattice Docker image...");

    let output = Command::new("./scripts/dev/docker-build.sh")
        .args(["-t", image])
        .env("DOCKER_BUILDKIT", "1")
        .current_dir(workspace_root())
        .output()
        .map_err(|e| format!("Failed to run docker build: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Docker build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    info!("  Image built successfully");
    info!("  Pushing image to registry...");

    let output = Command::new("docker")
        .args(["push", image])
        .output()
        .map_err(|e| format!("Failed to push image: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Docker push failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    info!("  Image pushed successfully");
    Ok(())
}

/// Load registry credentials from .env file or environment
#[cfg(feature = "provider-e2e")]
pub fn load_registry_credentials() -> Option<String> {
    use base64::Engine;

    let env_path = workspace_root().join(".env");
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
            let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", u, t));
            return Some(serde_json::json!({"auths": {"ghcr.io": {"auth": auth}}}).to_string());
        }
    }

    if let (Ok(u), Ok(t)) = (std::env::var("GHCR_USER"), std::env::var("GHCR_TOKEN")) {
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", u, t));
        return Some(serde_json::json!({"auths": {"ghcr.io": {"auth": auth}}}).to_string());
    }

    None
}

/// Load a LatticeCluster config from a fixture file or env var
#[cfg(feature = "provider-e2e")]
pub fn load_cluster_config(
    env_var: &str,
    default_fixture: &str,
) -> Result<(String, LatticeCluster), String> {
    let path = match std::env::var(env_var) {
        Ok(p) => PathBuf::from(p),
        Err(_) => cluster_fixtures_dir().join(default_fixture),
    };

    if !path.exists() {
        return Err(format!("Cluster config not found: {}", path.display()));
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    let cluster: LatticeCluster = serde_yaml::from_str(&content)
        .map_err(|e| format!("Invalid YAML in {}: {}", path.display(), e))?;

    info!("  Loaded cluster config: {}", path.display());
    Ok((content, cluster))
}

/// Load a LatticeService config from a fixture file
#[cfg(feature = "provider-e2e")]
#[allow(dead_code)] // Used by media_server_e2e (currently disabled)
pub fn load_service_config(
    filename: &str,
) -> Result<lattice_operator::crd::LatticeService, String> {
    let path = service_fixtures_dir().join(filename);

    if !path.exists() {
        return Err(format!("Service config not found: {}", path.display()));
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    let service: lattice_operator::crd::LatticeService = serde_yaml::from_str(&content)
        .map_err(|e| format!("Invalid YAML in {}: {}", path.display(), e))?;

    Ok(service)
}

/// Get a localhost-accessible kubeconfig for a Docker cluster
#[cfg(feature = "provider-e2e")]
pub fn get_docker_kubeconfig(cluster_name: &str) -> Result<String, String> {
    let kubeconfig_path = format!("/tmp/{}-kubeconfig", cluster_name);
    let kubeconfig = std::fs::read_to_string(&kubeconfig_path)
        .map_err(|e| format!("Failed to read kubeconfig: {}", e))?;

    let lb_container = format!("{}-lb", cluster_name);
    let port_output = run_cmd_allow_fail("docker", &["port", &lb_container, "6443/tcp"]);

    if port_output.trim().is_empty() {
        return Err(format!("LB container {} not found", lb_container));
    }

    let parts: Vec<&str> = port_output.trim().split(':').collect();
    if parts.len() != 2 {
        return Err(format!("Failed to parse LB port: {}", port_output));
    }

    let localhost_endpoint = format!("https://127.0.0.1:{}", parts[1]);
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

    let patched_path = format!("/tmp/{}-kubeconfig-local", cluster_name);
    std::fs::write(&patched_path, &patched)
        .map_err(|e| format!("Failed to write kubeconfig: {}", e))?;

    Ok(patched_path)
}

// =============================================================================
// Docker Cleanup Helpers
// =============================================================================

/// Force delete all Docker containers for a cluster (Docker provider only)
#[cfg(feature = "provider-e2e")]
pub fn force_delete_docker_cluster(cluster_name: &str) {
    let containers = run_cmd_allow_fail(
        "docker",
        &[
            "ps",
            "-a",
            "--filter",
            &format!("name={}", cluster_name),
            "-q",
        ],
    );
    for id in containers.lines() {
        if !id.trim().is_empty() {
            let _ = run_cmd_allow_fail("docker", &["rm", "-f", id.trim()]);
        }
    }
}

/// Check if all containers for a cluster are deleted
#[cfg(feature = "provider-e2e")]
pub fn docker_containers_deleted(cluster_name: &str) -> bool {
    let containers = run_cmd_allow_fail(
        "docker",
        &[
            "ps",
            "-a",
            "--filter",
            &format!("name={}", cluster_name),
            "-q",
        ],
    );
    containers.trim().is_empty()
}
