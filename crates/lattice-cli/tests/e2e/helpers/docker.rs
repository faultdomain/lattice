//! Docker network, command execution, and kubeconfig helpers for e2e tests
#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use lattice_common::crd::BootstrapProvider;
use lattice_common::retry::{retry_with_backoff, RetryConfig};
use tracing::info;

use super::{kubeconfig_local_path, kubeconfig_path, DOCKER_KIND_GATEWAY, DOCKER_KIND_SUBNET};

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
pub async fn ensure_docker_network() -> Result<(), String> {
    info!(
        "Ensuring Docker 'kind' network has correct subnet ({})...",
        DOCKER_KIND_SUBNET
    );

    // Check if the network exists
    let inspect_output = std::process::Command::new("docker")
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
                info!("Docker 'kind' network already has correct subnet");
                return Ok(());
            }
            // Network exists but with wrong subnet - need to recreate
            info!(
                "Docker 'kind' network has wrong subnet ({}), recreating...",
                current_subnet
            );

            // Check if any containers are using the network
            let containers = run_cmd(
                "docker",
                &[
                    "network",
                    "inspect",
                    "kind",
                    "--format",
                    "{{range .Containers}}{{.Name}} {{end}}",
                ],
            )
            .await?;
            if !containers.trim().is_empty() {
                return Err(format!(
                    "Cannot recreate 'kind' network - containers still attached: {}. Stop them first.",
                    containers.trim()
                ));
            }

            // Remove the network
            run_cmd("docker", &["network", "rm", "kind"]).await?;
        }
        _ => {
            // Network doesn't exist
            info!("Docker 'kind' network doesn't exist, creating...");
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
    )
    .await?;

    info!(
        "Docker 'kind' network created with subnet {}",
        DOCKER_KIND_SUBNET
    );
    Ok(())
}

// =============================================================================
// Command Execution Helpers
// =============================================================================

/// Run a shell command with 30s timeout (async, non-blocking).
pub async fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::process::Command::new(cmd)
            .args(args)
            .output()
            .await
            .map_err(|e| format!("Failed to spawn {}: {}", cmd, e))
    })
    .await
    .map_err(|_| format!("{} timed out after 30s", cmd))??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{} failed: {}", cmd, stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Run a kubectl command with built-in retry (3 attempts, exponential backoff).
///
/// ALL kubectl invocations should go through this function so transient
/// proxy / port-forward hiccups don't kill the test run.
///
/// Retries transient errors (connection refused, timeout, etc.) forever.
/// Returns permanent errors (NotFound, Forbidden, etc.) immediately.
pub async fn run_kubectl(args: &[&str]) -> Result<String, String> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

    // The inner closure returns Ok(Ok(output)) for success, Ok(Err(e)) for
    // permanent errors (stops retrying), and Err(e) for transient errors (retried).
    // AlreadyExists is treated as success — the desired state is achieved.
    let result: Result<Result<String, String>, String> =
        retry_with_backoff(&RetryConfig::with_max_attempts(60), "kubectl", || {
            let args = args.clone();
            async move {
                let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                match run_cmd("kubectl", &args_ref).await {
                    Ok(output) => Ok(Ok(output)),
                    Err(e) if is_already_exists(&e) => Ok(Ok(e)),
                    Err(e) if is_transient_kubectl_error(&e) => Err(e),
                    Err(e) => Ok(Err(e)),
                }
            }
        })
        .await;

    match result {
        Ok(inner) => inner,
        Err(e) => Err(e),
    }
}

fn is_already_exists(error: &str) -> bool {
    error.contains("AlreadyExists") || error.contains("already exists")
}

/// Whether a kubectl error is transient (connection-level) and worth retrying.
///
/// Permanent errors (NotFound, Forbidden, etc.) return immediately since retrying
/// won't change the outcome. Transient errors (connection refused, timeout, etc.)
/// are retried because they resolve when the API server recovers.
fn is_transient_kubectl_error(error: &str) -> bool {
    error.contains("Unable to connect to the server")
        || error.contains("connection refused")
        || error.contains("was refused")
        || error.contains("connection reset")
        || error.contains("i/o timeout")
        || error.contains("TLS handshake timeout")
        || error.contains("no such host")
        || error.contains("dial tcp")
        || error.contains("EOF")
        || error.contains("broken pipe")
        || error.contains("transport is closing")
        || error.contains("context deadline exceeded")
        || error.contains("the object has been modified")
        || error.contains("InternalError")
        || error.contains("ServiceUnavailable")
        || error.contains("client rate limiter")
        || error.contains("net/http")
        || error.contains("timed out")
        || error.contains("the server could not find the requested resource")
        || error.contains("couldn't get current server API group list")
        // Exec credential plugin failures (lattice token) are transient — the
        // underlying issue is usually a momentary connection problem to the API server.
        || error.contains("getting credentials")
        || error.contains("logged in to the server")
}

// =============================================================================
// Kubeconfig Helpers for Docker-based Clusters
// =============================================================================

/// Get the kubeconfig path inside the container based on bootstrap provider
fn get_kubeconfig_path_for_bootstrap(bootstrap: &BootstrapProvider) -> &'static str {
    match bootstrap {
        BootstrapProvider::Kubeadm => "/etc/kubernetes/admin.conf",
        BootstrapProvider::Rke2 => "/etc/rancher/rke2/rke2.yaml",
    }
}

/// Patch a kubeconfig's server URL to use localhost with the given endpoint
fn patch_kubeconfig_server(kubeconfig: &str, endpoint: &str) -> Result<String, String> {
    let mut config: serde_json::Value = lattice_common::yaml::parse_yaml(kubeconfig)
        .map_err(|e| format!("Failed to parse kubeconfig: {}", e))?;

    if let Some(clusters) = config.get_mut("clusters").and_then(|c| c.as_array_mut()) {
        for cluster in clusters {
            if let Some(cluster_data) = cluster.get_mut("cluster") {
                if let Some(server) = cluster_data.get_mut("server") {
                    *server = serde_json::Value::String(endpoint.to_string());
                }
            }
        }
    }

    serde_json::to_string(&config).map_err(|e| format!("Failed to serialize kubeconfig: {}", e))
}

/// Parse docker port output (e.g., "0.0.0.0:12345") into a localhost endpoint
fn parse_lb_port(port_output: &str) -> Option<String> {
    let trimmed = port_output.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parts: Vec<&str> = trimmed.split(':').collect();
    if parts.len() == 2 {
        Some(format!("https://127.0.0.1:{}", parts[1]))
    } else {
        None
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
pub async fn extract_docker_cluster_kubeconfig(
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
    )
    .await?;
    let cp_container = cp_container.trim();
    if cp_container.is_empty() {
        return Err(format!(
            "Could not find control plane container for cluster '{}'",
            cluster_name
        ));
    }
    info!("Found control plane container: {}", cp_container);

    // Extract kubeconfig from the container (with retries - file may not exist immediately)
    let kubeconfig_container_path = get_kubeconfig_path_for_bootstrap(bootstrap);
    info!("Extracting kubeconfig from {}", kubeconfig_container_path);

    let cp = cp_container.to_string();
    let kubeconfig = retry_with_backoff(
        &RetryConfig {
            max_attempts: 60,
            initial_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 1.0,
        },
        "extract_kubeconfig",
        || {
            let cp = cp.clone();
            async move { run_cmd("docker", &["exec", &cp, "cat", kubeconfig_container_path]).await }
        },
    )
    .await?;

    // Find the load balancer port mapping and patch the kubeconfig for localhost access
    let lb_container = format!("{}-lb", cluster_name);
    let final_kubeconfig = match run_cmd("docker", &["port", &lb_container, "6443/tcp"]).await {
        Ok(port_output) => {
            if let Some(endpoint) = parse_lb_port(&port_output) {
                info!("Patching kubeconfig server to {}", endpoint);
                patch_kubeconfig_server(&kubeconfig, &endpoint)?
            } else {
                info!(
                    "Warning: Could not parse load balancer port mapping for {}",
                    lb_container
                );
                kubeconfig
            }
        }
        Err(_) => {
            info!(
                "Warning: Could not find load balancer container {}",
                lb_container
            );
            kubeconfig
        }
    };

    std::fs::write(output_path, &final_kubeconfig)
        .map_err(|e| format!("Failed to write kubeconfig to {}: {}", output_path, e))?;

    Ok(())
}

/// Get a localhost-accessible kubeconfig for a Docker cluster
pub async fn get_docker_kubeconfig(cluster_name: &str) -> Result<String, String> {
    let kc_path = kubeconfig_path(cluster_name);
    let kubeconfig = std::fs::read_to_string(&kc_path)
        .map_err(|e| format!("Failed to read kubeconfig {}: {}", kc_path, e))?;

    let lb_container = format!("{}-lb", cluster_name);
    let port_output = run_cmd("docker", &["port", &lb_container, "6443/tcp"])
        .await
        .map_err(|_| format!("LB container {} not found", lb_container))?;

    let endpoint = parse_lb_port(&port_output)
        .ok_or_else(|| format!("LB container {} has invalid port output", lb_container))?;

    let patched = patch_kubeconfig_server(&kubeconfig, &endpoint)?;

    let patched_path = kubeconfig_local_path(cluster_name);
    std::fs::write(&patched_path, &patched)
        .map_err(|e| format!("Failed to write kubeconfig: {}", e))?;

    Ok(patched_path)
}

// =============================================================================
// Docker Cleanup Helpers
// =============================================================================

/// Force delete all Docker containers for a cluster (Docker provider only)
pub async fn force_delete_docker_cluster(cluster_name: &str) {
    if let Ok(containers) = run_cmd(
        "docker",
        &[
            "ps",
            "-a",
            "--filter",
            &format!("name={}", cluster_name),
            "-q",
        ],
    )
    .await
    {
        for id in containers.lines() {
            if !id.trim().is_empty() {
                let _ = run_cmd("docker", &["rm", "-f", id.trim()]).await;
            }
        }
    }
}

/// Check if all containers for a cluster are deleted
pub async fn docker_containers_deleted(cluster_name: &str) -> bool {
    match run_cmd(
        "docker",
        &[
            "ps",
            "-a",
            "--filter",
            &format!("name={}", cluster_name),
            "-q",
        ],
    )
    .await
    {
        Ok(containers) => containers.trim().is_empty(),
        Err(_) => true, // If docker command fails, assume deleted
    }
}
