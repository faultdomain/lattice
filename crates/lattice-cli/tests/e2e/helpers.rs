//! Test helpers for e2e tests
//!
//! Provides utilities for Docker-based cluster testing.

#[cfg(feature = "provider-e2e")]
use std::sync::OnceLock;
#[cfg(feature = "provider-e2e")]
use std::{process::Command, time::Duration};

#[cfg(feature = "provider-e2e")]
use kube::{
    config::{KubeConfigOptions, Kubeconfig},
    Client,
};
#[cfg(feature = "provider-e2e")]
use lattice_common::{
    capi_namespace, kubeconfig_secret_name,
    retry::{retry_with_backoff, RetryConfig},
    LATTICE_SYSTEM_NAMESPACE,
};
#[cfg(feature = "provider-e2e")]
use lattice_operator::crd::{BootstrapProvider, ClusterPhase};
#[cfg(feature = "provider-e2e")]
use tokio::time::sleep;
#[cfg(feature = "provider-e2e")]
use tracing::info;

// =============================================================================
// Shared Constants
// =============================================================================

/// Default Lattice container image for E2E tests
#[cfg(feature = "provider-e2e")]
pub const DEFAULT_LATTICE_IMAGE: &str = "ghcr.io/evan-hines-js/lattice:latest";

/// Standard cluster names for E2E tests
#[cfg(feature = "provider-e2e")]
pub const MGMT_CLUSTER_NAME: &str = "e2e-mgmt";
#[cfg(feature = "provider-e2e")]
pub const WORKLOAD_CLUSTER_NAME: &str = "e2e-workload";
#[cfg(feature = "provider-e2e")]
pub const WORKLOAD2_CLUSTER_NAME: &str = "e2e-workload2";

/// Get management cluster name from env or use default
#[cfg(feature = "provider-e2e")]
pub fn get_mgmt_cluster_name() -> String {
    std::env::var("LATTICE_MGMT_CLUSTER_NAME").unwrap_or_else(|_| MGMT_CLUSTER_NAME.to_string())
}

/// Get workload cluster name from env or use default
#[cfg(feature = "provider-e2e")]
pub fn get_workload_cluster_name() -> String {
    std::env::var("LATTICE_WORKLOAD_CLUSTER_NAME")
        .unwrap_or_else(|_| WORKLOAD_CLUSTER_NAME.to_string())
}

/// Get workload2 cluster name from env or use default
#[cfg(feature = "provider-e2e")]
pub fn get_workload2_cluster_name() -> String {
    std::env::var("LATTICE_WORKLOAD2_CLUSTER_NAME")
        .unwrap_or_else(|_| WORKLOAD2_CLUSTER_NAME.to_string())
}

/// Get child cluster name from env or use default (alias for workload)
#[cfg(feature = "provider-e2e")]
pub fn get_child_cluster_name() -> String {
    std::env::var("LATTICE_CHILD_CLUSTER_NAME")
        .or_else(|_| std::env::var("LATTICE_WORKLOAD_CLUSTER_NAME"))
        .unwrap_or_else(|_| WORKLOAD_CLUSTER_NAME.to_string())
}

/// Label selector for lattice-operator pods
#[cfg(feature = "provider-e2e")]
pub const OPERATOR_LABEL: &str = "app=lattice-operator";

// =============================================================================
// Unique Run ID for Parallel Test Execution
// =============================================================================

/// Unique run ID for this test process.
/// Uses process ID and timestamp to ensure uniqueness across parallel runs.
#[cfg(feature = "provider-e2e")]
static RUN_ID: OnceLock<String> = OnceLock::new();

/// Get the unique run ID for this test process.
#[cfg(feature = "provider-e2e")]
pub fn run_id() -> &'static str {
    RUN_ID.get_or_init(|| {
        format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
                % 1_000_000
        )
    })
}

/// Generate a unique kubeconfig path for a cluster.
///
/// The path includes the run ID as a suffix to allow parallel test execution.
/// Example: `/tmp/e2e-mgmt-kubeconfig-8156-965202`
#[cfg(feature = "provider-e2e")]
pub fn kubeconfig_path(cluster_name: &str) -> String {
    format!("/tmp/{}-kubeconfig-{}", cluster_name, run_id())
}

/// Generate a unique localhost-patched kubeconfig path for a cluster.
/// Example: `/tmp/e2e-mgmt-kubeconfig-local-8156-965202`
#[cfg(feature = "provider-e2e")]
pub fn kubeconfig_local_path(cluster_name: &str) -> String {
    format!("/tmp/{}-kubeconfig-local-{}", cluster_name, run_id())
}

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

    config.connect_timeout = Some(Duration::from_secs(5));
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
        "Ensuring Docker 'kind' network has correct subnet ({})...",
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
            )?;
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
    )?;

    info!(
        "Docker 'kind' network created with subnet {}",
        DOCKER_KIND_SUBNET
    );
    Ok(())
}

// =============================================================================
// Command Execution Helpers
// =============================================================================

/// Run a shell command with 30s timeout
#[cfg(feature = "provider-e2e")]
pub fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, String> {
    use std::io::Read;
    use std::process::Stdio;

    let timeout = Duration::from_secs(30);

    let mut child = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn {}: {}", cmd, e))?;

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                if let Some(ref mut out) = child.stdout {
                    let _ = out.read_to_string(&mut stdout);
                }
                if let Some(ref mut err) = child.stderr {
                    let _ = err.read_to_string(&mut stderr);
                }
                if !status.success() {
                    return Err(format!("{} failed: {}", cmd, stderr));
                }
                return Ok(stdout);
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{} timed out after {:?}", cmd, timeout));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("Error waiting for {}: {}", cmd, e)),
        }
    }
}

// =============================================================================
// HTTP Testing Helpers
// =============================================================================

/// Result of an HTTP request to the proxy
#[cfg(feature = "provider-e2e")]
pub struct HttpResponse {
    /// HTTP status code (0 if connection failed)
    pub status_code: u16,
    /// Response body
    pub body: String,
}

#[cfg(feature = "provider-e2e")]
impl HttpResponse {
    /// Check if the response indicates success (2xx)
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    /// Check if the response is a 403 Forbidden
    pub fn is_forbidden(&self) -> bool {
        self.status_code == 403
    }

    /// Check if the response is a 401 Unauthorized
    pub fn is_unauthorized(&self) -> bool {
        self.status_code == 401
    }
}

/// Make an authenticated HTTP GET request to the proxy.
///
/// Uses curl with the provided bearer token and returns both status code and body.
/// Returns status_code 0 on connection failure or timeout.
#[cfg(feature = "provider-e2e")]
pub fn http_get_with_token(url: &str, token: &str, timeout_secs: u32) -> HttpResponse {
    // Use -w to append status code after body with a delimiter
    let output = match run_cmd(
        "curl",
        &[
            "-s",
            "-w",
            "\n__HTTP_STATUS__%{http_code}",
            "-H",
            &format!("Authorization: Bearer {}", token),
            "--insecure",
            "--max-time",
            &timeout_secs.to_string(),
            url,
        ],
    ) {
        Ok(out) => out,
        Err(e) => {
            return HttpResponse {
                status_code: 0,
                body: e,
            }
        }
    };

    // Parse body and status code from combined output
    if let Some(idx) = output.rfind("\n__HTTP_STATUS__") {
        let body = output[..idx].to_string();
        let status_str = &output[idx + 16..]; // Skip "\n__HTTP_STATUS__"
        let status_code = status_str.trim().parse().unwrap_or(0);
        HttpResponse { status_code, body }
    } else {
        HttpResponse {
            status_code: 0,
            body: output,
        }
    }
}

/// Make an authenticated HTTP GET request with automatic retries for transient errors.
///
/// Retries on:
/// - Connection failures (status_code == 0)
/// - 502 Bad Gateway
/// - 503 Service Unavailable
/// - 504 Gateway Timeout
///
/// Does NOT retry on:
/// - 4xx errors (401, 403, 404, etc.) - these are permanent failures
/// - 2xx success - returns immediately
/// - 5xx other than 502-504 - likely permanent server errors
#[cfg(feature = "provider-e2e")]
pub async fn http_get_with_retry(
    url: &str,
    token: &str,
    timeout_secs: u32,
) -> Result<HttpResponse, String> {
    let retry_config = RetryConfig {
        max_attempts: 5,
        initial_delay: Duration::from_secs(2),
        max_delay: Duration::from_secs(15),
        backoff_multiplier: 2.0,
    };

    let url = url.to_string();
    let token = token.to_string();

    retry_with_backoff(&retry_config, "http_request", || {
        let url = url.clone();
        let token = token.clone();
        async move {
            let resp = http_get_with_token(&url, &token, timeout_secs);

            // Success - return immediately
            if resp.is_success() {
                return Ok(resp);
            }

            // Transient errors - retry
            if resp.status_code == 0
                || resp.status_code == 502
                || resp.status_code == 503
                || resp.status_code == 504
            {
                return Err(format!(
                    "Transient error (status {}): {}",
                    resp.status_code, resp.body
                ));
            }

            // Permanent errors (4xx, other 5xx) - return as-is, don't retry
            Ok(resp)
        }
    })
    .await
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

/// Patch a kubeconfig's server URL to use localhost with the given endpoint
#[cfg(feature = "provider-e2e")]
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
#[cfg(feature = "provider-e2e")]
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
    info!("Found control plane container: {}", cp_container);

    // Extract kubeconfig from the container (with retries - file may not exist immediately)
    let kubeconfig_container_path = get_kubeconfig_path_for_bootstrap(bootstrap);
    info!("Extracting kubeconfig from {}", kubeconfig_container_path);

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
                    "Waiting for kubeconfig to be available (attempt {}/{})...",
                    attempt, max_retries
                );
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }
    }

    // Find the load balancer port mapping and patch the kubeconfig for localhost access
    let lb_container = format!("{}-lb", cluster_name);
    let final_kubeconfig = match run_cmd("docker", &["port", &lb_container, "6443/tcp"]) {
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

                if matches!(current_phase, ClusterPhase::Ready | ClusterPhase::Pivoted) {
                    info!(
                        "Cluster {} is operational ({:?})!",
                        cluster_name, current_phase
                    );
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

                if matches!(current_phase, ClusterPhase::Ready | ClusterPhase::Pivoted) {
                    info!(
                        "Cluster {} is operational ({:?})!",
                        cluster_name, current_phase
                    );
                    if !kubeconfig_extracted {
                        return Err(format!(
                            "Cluster {} is operational but kubeconfig was not extracted before pivot",
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

    let namespace = capi_namespace(cluster_name);
    let secret_name = kubeconfig_secret_name(cluster_name);

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

/// Count ready nodes from kubectl jsonpath output (lines of "True"/"False")
#[cfg(feature = "provider-e2e")]
pub fn count_ready_nodes(output: &str) -> u32 {
    output.lines().filter(|line| *line == "True").count() as u32
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
        let output = run_cmd(
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
        )
        .unwrap_or_default();
        let ready_workers = count_ready_nodes(&output);

        if last_count != Some(ready_workers) {
            info!(
                "  {} ready workers on {} (target: {})",
                ready_workers, cluster_name, expected_workers
            );
            last_count = Some(ready_workers);
        }

        if ready_workers >= expected_workers {
            info!(
                "  SUCCESS: {} has {} ready workers!",
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
pub fn service_fixtures_dir() -> PathBuf {
    workspace_root().join("crates/lattice-cli/tests/e2e/fixtures/services")
}

/// Build and push the lattice Docker image
#[cfg(feature = "provider-e2e")]
pub async fn build_and_push_lattice_image(image: &str) -> Result<(), String> {
    info!("Building lattice Docker image...");

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

    info!("Image built successfully");
    info!("Pushing image to registry...");

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

    info!("Image pushed successfully");
    Ok(())
}

// =============================================================================
// Operator Management
// =============================================================================

/// Rebuild image, push to registry, and restart operator pods on all clusters.
///
/// This combines the three operations needed for operator updates:
/// 1. Build and push Docker image
/// 2. Delete operator pods on all clusters to force image pull (bottom-up order)
/// 3. Wait for operator deployments to be ready
///
/// # Arguments
///
/// * `image` - Docker image tag (e.g., "ghcr.io/evan-hines-js/lattice:latest")
/// * `kubeconfigs` - List of (cluster_name, kubeconfig_path) tuples
#[cfg(feature = "provider-e2e")]
pub async fn rebuild_and_restart_operators(
    image: &str,
    kubeconfigs: &[(&str, &str)],
) -> Result<(), String> {
    // 1. Build and push image
    build_and_push_lattice_image(image).await?;

    // 2. Delete operator pods in REVERSE order (bottom-up: children first, then parents)
    // This prevents port-forward breaks - parent's proxy must stay alive while deleting children
    info!(
        "Restarting operators on {} cluster(s) (bottom-up)...",
        kubeconfigs.len()
    );
    for (cluster_name, kubeconfig) in kubeconfigs.iter().rev() {
        delete_operator_pods(cluster_name, kubeconfig);
    }

    // 3. Wait for operators to be ready (also bottom-up so children are ready before parents need them)
    for (cluster_name, kubeconfig) in kubeconfigs.iter().rev() {
        wait_for_operator_ready(cluster_name, kubeconfig, None).await?;
    }

    info!(
        "Image rebuilt and operators restarted on {} cluster(s)",
        kubeconfigs.len()
    );
    Ok(())
}

/// Delete operator pods to trigger image pull.
#[cfg(feature = "provider-e2e")]
pub fn delete_operator_pods(cluster_name: &str, kubeconfig: &str) {
    let msg = match run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "delete",
            "pod",
            "-n",
            LATTICE_SYSTEM_NAMESPACE,
            "-l",
            OPERATOR_LABEL,
            "--wait=false",
        ],
    ) {
        Ok(output) if output.contains("deleted") => "deleted operator pod",
        Ok(_) => "no pod found",
        Err(_) => "no pod found or not accessible",
    };
    info!("[{}] {}", cluster_name, msg);
}

/// Wait for operator deployment to be ready.
#[cfg(feature = "provider-e2e")]
pub async fn wait_for_operator_ready(
    cluster_name: &str,
    kubeconfig: &str,
    timeout_secs: Option<u64>,
) -> Result<(), String> {
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(300));
    let start = std::time::Instant::now();

    info!("[{}] Waiting for operator to be ready...", cluster_name);

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for operator on {} to be ready",
                cluster_name
            ));
        }

        if let Ok(output) = run_cmd(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig,
                "rollout",
                "status",
                "deployment/lattice-operator",
                "-n",
                LATTICE_SYSTEM_NAMESPACE,
                "--timeout=10s",
            ],
        ) {
            if output.contains("successfully rolled out") {
                info!("[{}] Operator is ready", cluster_name);
                return Ok(());
            }
        }

        sleep(Duration::from_secs(5)).await;
    }
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

    let value = lattice_common::yaml::parse_yaml(&content)
        .map_err(|e| format!("Invalid YAML in {}: {}", path.display(), e))?;
    let cluster: LatticeCluster = serde_json::from_value(value)
        .map_err(|e| format!("Invalid cluster config in {}: {}", path.display(), e))?;

    info!("Loaded cluster config: {}", path.display());
    Ok((content, cluster))
}

/// Load a LatticeService config from a fixture file
#[cfg(feature = "provider-e2e")]
pub fn load_service_config(
    filename: &str,
) -> Result<lattice_operator::crd::LatticeService, String> {
    let path = service_fixtures_dir().join(filename);

    if !path.exists() {
        return Err(format!("Service config not found: {}", path.display()));
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    let value = lattice_common::yaml::parse_yaml(&content)
        .map_err(|e| format!("Invalid YAML in {}: {}", path.display(), e))?;
    let service: lattice_operator::crd::LatticeService = serde_json::from_value(value)
        .map_err(|e| format!("Invalid service config in {}: {}", path.display(), e))?;

    Ok(service)
}

/// Get a localhost-accessible kubeconfig for a Docker cluster
#[cfg(feature = "provider-e2e")]
pub fn get_docker_kubeconfig(cluster_name: &str) -> Result<String, String> {
    let kc_path = kubeconfig_path(cluster_name);
    let kubeconfig = std::fs::read_to_string(&kc_path)
        .map_err(|e| format!("Failed to read kubeconfig {}: {}", kc_path, e))?;

    let lb_container = format!("{}-lb", cluster_name);
    let port_output = run_cmd("docker", &["port", &lb_container, "6443/tcp"])
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
#[cfg(feature = "provider-e2e")]
pub fn force_delete_docker_cluster(cluster_name: &str) {
    if let Ok(containers) = run_cmd(
        "docker",
        &[
            "ps",
            "-a",
            "--filter",
            &format!("name={}", cluster_name),
            "-q",
        ],
    ) {
        for id in containers.lines() {
            if !id.trim().is_empty() {
                let _ = run_cmd("docker", &["rm", "-f", id.trim()]);
            }
        }
    }
}

/// Check if all containers for a cluster are deleted
#[cfg(feature = "provider-e2e")]
pub fn docker_containers_deleted(cluster_name: &str) -> bool {
    match run_cmd(
        "docker",
        &[
            "ps",
            "-a",
            "--filter",
            &format!("name={}", cluster_name),
            "-q",
        ],
    ) {
        Ok(containers) => containers.trim().is_empty(),
        Err(_) => true, // If docker command fails, assume deleted
    }
}

// =============================================================================
// Cluster Verification and Deletion
// =============================================================================

#[cfg(feature = "provider-e2e")]
use super::providers::InfraProvider;

/// Verify a cluster has its own CAPI resources after pivot
#[cfg(feature = "provider-e2e")]
pub async fn verify_cluster_capi_resources(
    kubeconfig: &str,
    cluster_name: &str,
) -> Result<(), String> {
    let nodes_output = run_cmd(
        "kubectl",
        &["--kubeconfig", kubeconfig, "get", "nodes", "-o", "wide"],
    )?;
    info!("Cluster nodes:\n{}", nodes_output);

    let capi_output = run_cmd(
        "kubectl",
        &["--kubeconfig", kubeconfig, "get", "clusters", "-A"],
    )?;
    info!("CAPI clusters:\n{}", capi_output);

    if !capi_output.contains(cluster_name) {
        return Err(format!(
            "Cluster {} should have its own CAPI Cluster resource after pivot",
            cluster_name
        ));
    }

    Ok(())
}

// =============================================================================
// Proxy URL Resolution (Infrastructure Helpers)
// =============================================================================

/// The auth proxy runs as part of the lattice-cell service on port 8082
/// (8081 is the CAPI proxy for internal CAPI controller access)
#[cfg(feature = "provider-e2e")]
const PROXY_SERVICE_NAME: &str = "lattice-cell";
#[cfg(feature = "provider-e2e")]
const PROXY_PORT: u16 = 8082;

/// Check if the lattice-cell proxy service exists
#[cfg(feature = "provider-e2e")]
pub fn proxy_service_exists(kubeconfig: &str) -> bool {
    run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "get",
            "svc",
            PROXY_SERVICE_NAME,
            "-n",
            LATTICE_SYSTEM_NAMESPACE,
            "-o",
            "name",
        ],
    )
    .is_ok()
}

/// Base port for deterministic port allocation.
#[cfg(feature = "provider-e2e")]
const PROXY_PORT_BASE: u16 = 19000;
/// Range of ports for deterministic allocation (19000-28999).
#[cfg(feature = "provider-e2e")]
const PROXY_PORT_RANGE: u16 = 10000;

/// Get a deterministic port based on kubeconfig path.
///
/// This ensures that if a port-forward dies and restarts, it uses the same
/// local port, keeping any generated kubeconfigs valid.
#[cfg(feature = "provider-e2e")]
pub fn deterministic_port(kubeconfig: &str) -> u16 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    kubeconfig.hash(&mut hasher);
    PROXY_PORT_BASE + ((hasher.finish() % PROXY_PORT_RANGE as u64) as u16)
}

/// Start a port-forward to the proxy service on a specific local port.
///
/// On macOS, Docker networks aren't accessible from the host, so we use
/// kubectl port-forward to create a tunnel to the service.
///
/// Uses a deterministic port based on the kubeconfig path. This ensures that
/// if the port-forward dies and restarts, it uses the same local port, keeping
/// any generated kubeconfigs valid.
///
/// Returns the localhost URL and the port-forward process handle.
/// The caller should keep the handle alive for the duration of proxy access.
#[cfg(feature = "provider-e2e")]
pub fn start_proxy_port_forward(
    kubeconfig: &str,
    local_port: u16,
) -> Result<(String, std::process::Child), String> {
    use std::process::{Command, Stdio};

    if !proxy_service_exists(kubeconfig) {
        return Err(format!(
            "{} service not found - proxy may not be deployed",
            PROXY_SERVICE_NAME
        ));
    }

    info!(
        "[Helpers] Starting port-forward to {}:{} on localhost:{} (kubeconfig: {})",
        PROXY_SERVICE_NAME, PROXY_PORT, local_port, kubeconfig
    );

    // Start kubectl port-forward in background
    let mut child = Command::new("kubectl")
        .args([
            "--kubeconfig",
            kubeconfig,
            "port-forward",
            &format!("svc/{}", PROXY_SERVICE_NAME),
            &format!("{}:{}", local_port, PROXY_PORT),
            "-n",
            LATTICE_SYSTEM_NAMESPACE,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start port-forward: {}", e))?;

    let url = format!("https://127.0.0.1:{}", local_port);

    // Poll /healthz until ready (up to 60 seconds)
    for attempt in 1..=60 {
        // Check if port-forward process died
        if let Ok(Some(status)) = child.try_wait() {
            let stderr_msg = child
                .stderr
                .take()
                .and_then(|mut stderr| {
                    let mut buf = String::new();
                    use std::io::Read;
                    stderr.read_to_string(&mut buf).ok()?;
                    Some(buf)
                })
                .unwrap_or_default();
            return Err(format!(
                "Port-forward process died unexpectedly with status: {}. kubeconfig: {}, stderr: {}",
                status, kubeconfig, stderr_msg
            ));
        }

        // Try to hit the health endpoint
        let health_url = format!("{}/healthz", url);
        if let Ok(output) = run_cmd(
            "curl",
            &[
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--insecure",
                "--max-time",
                "2",
                &health_url,
            ],
        ) {
            if output.trim() == "200" {
                info!(
                    "[Helpers] Port-forward ready at {} (attempt {})",
                    url, attempt
                );
                return Ok((url, child));
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Clean up the failed port-forward
    let _ = child.kill();
    Err(format!(
        "Port-forward to {} failed to become ready after 60 seconds (kubeconfig: {})",
        url, kubeconfig
    ))
}

/// Get proxy URL, creating a port-forward if necessary.
///
/// This is a convenience wrapper that uses an existing proxy URL if provided,
/// or creates a new port-forward if not. Uses a deterministic port based on
/// the kubeconfig path, so if the port-forward dies and restarts, it uses the
/// same port and kubeconfigs remain valid.
///
/// # Arguments
/// * `kubeconfig` - Kubeconfig for the cluster
/// * `existing_url` - Optional existing proxy URL to reuse
///
/// # Returns
/// Tuple of (proxy_url, optional_port_forward_handle)
#[cfg(feature = "provider-e2e")]
pub fn get_or_create_proxy(
    kubeconfig: &str,
    existing_url: Option<&str>,
) -> Result<(String, Option<std::process::Child>), String> {
    match existing_url {
        Some(url) => {
            info!("[Helpers] Using existing proxy URL: {}", url);
            Ok((url.to_string(), None))
        }
        None => {
            info!("[Helpers] Creating new port-forward to proxy...");
            let port = deterministic_port(kubeconfig);
            let (url, pf) = start_proxy_port_forward(kubeconfig, port)?;
            Ok((url, Some(pf)))
        }
    }
}

// =============================================================================
// ServiceAccount Token Helpers
// =============================================================================

/// Get a ServiceAccount token using kubectl create token
///
/// Duration is 8 hours for long-running E2E tests. Use `refresh_sa_token()`
/// if you need to refresh an expired token.
#[cfg(feature = "provider-e2e")]
pub fn get_sa_token(kubeconfig: &str, namespace: &str, sa_name: &str) -> Result<String, String> {
    get_sa_token_with_duration(kubeconfig, namespace, sa_name, "8h")
}

/// Get a ServiceAccount token with custom duration
#[cfg(feature = "provider-e2e")]
pub fn get_sa_token_with_duration(
    kubeconfig: &str,
    namespace: &str,
    sa_name: &str,
    duration: &str,
) -> Result<String, String> {
    let token = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig,
            "create",
            "token",
            sa_name,
            "-n",
            namespace,
            &format!("--duration={}", duration),
        ],
    )?;
    Ok(token.trim().to_string())
}

// =============================================================================
// Cluster Deletion Helpers
// =============================================================================

/// Delete a cluster via kubectl and wait for cleanup
///
/// The operator handles deletion via finalizers, so we just initiate deletion
/// and wait for the finalizer to complete (resource to be gone).
#[cfg(feature = "provider-e2e")]
pub async fn delete_cluster_and_wait(
    cluster_kubeconfig: &str,
    parent_kubeconfig: &str,
    cluster_name: &str,
    provider: InfraProvider,
) -> Result<(), String> {
    info!("Deleting cluster {}...", cluster_name);

    // Initiate deletion on the cluster itself with --wait=false
    // We can't wait for completion because:
    // 1. The finalizer (lattice.dev/unpivot) blocks deletion
    // 2. The unpivot flow sends CAPI manifests to parent
    // 3. Parent imports and deletes via CAPI, which kills the infrastructure
    // 4. The cluster's API server dies before the finalizer is removed
    // So we just initiate deletion and wait for parent confirmation
    run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            cluster_kubeconfig,
            "delete",
            "latticecluster",
            cluster_name,
            "--wait=false",
        ],
    )?;
    info!("LatticeCluster deletion initiated (async)");

    // Wait for the LatticeCluster to be fully deleted from parent
    info!("Waiting for LatticeCluster to be deleted from parent...");
    for attempt in 1..=60 {
        sleep(Duration::from_secs(10)).await;

        // If the command fails (not found) or returns empty, the resource is deleted
        let deleted = match run_cmd(
            "kubectl",
            &[
                "--kubeconfig",
                parent_kubeconfig,
                "get",
                "latticecluster",
                cluster_name,
                "-o",
                "name",
            ],
        ) {
            Ok(output) => output.trim().is_empty(),
            Err(_) => true, // Error means not found
        };

        if deleted {
            info!("LatticeCluster deleted from parent");
            break;
        }

        if attempt == 60 {
            return Err(format!(
                "Timeout waiting for {} deletion after 10 minutes",
                cluster_name
            ));
        }

        info!("Still waiting... (attempt {}/60)", attempt);
    }

    // For Docker, verify containers are cleaned up
    if provider == InfraProvider::Docker {
        info!("Waiting for Docker containers to be cleaned up...");
        for attempt in 1..=30 {
            sleep(Duration::from_secs(5)).await;

            if docker_containers_deleted(cluster_name) {
                info!("Docker containers cleaned up by CAPI");
                break;
            }

            if attempt == 30 {
                return Err(format!(
                    "Timeout waiting for {} containers to be deleted",
                    cluster_name
                ));
            }

            info!(
                "Still waiting for container cleanup... (attempt {}/30)",
                attempt
            );
        }
    }

    Ok(())
}

// =============================================================================
// YAML Apply with Retry
// =============================================================================

/// Apply YAML manifest via kubectl with retry for transient failures.
///
/// Handles API server readiness issues by retrying with exponential backoff.
#[cfg(feature = "provider-e2e")]
pub async fn apply_yaml_with_retry(kubeconfig: &str, yaml: &str) -> Result<(), String> {
    let retry_config = RetryConfig {
        max_attempts: 5,
        initial_delay: Duration::from_millis(500),
        max_delay: Duration::from_secs(5),
        backoff_multiplier: 2.0,
    };

    let kubeconfig_owned = kubeconfig.to_string();
    let yaml_owned = yaml.to_string();

    retry_with_backoff(&retry_config, "kubectl_apply", || {
        let kubeconfig = kubeconfig_owned.clone();
        let yaml = yaml_owned.clone();
        async move { apply_yaml_internal(&kubeconfig, &yaml) }
    })
    .await
}

#[cfg(feature = "provider-e2e")]
fn apply_yaml_internal(kubeconfig: &str, yaml: &str) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("kubectl")
        .args(["--kubeconfig", kubeconfig, "apply", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn kubectl: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(yaml.as_bytes())
            .map_err(|e| format!("Failed to write to kubectl stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for kubectl: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "kubectl apply failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

// =============================================================================
// Proxy Session
// =============================================================================

/// A resilient session for accessing clusters through the parent's proxy.
///
/// Manages a port-forward to the proxy service and provides methods to generate
/// kubeconfigs for child clusters. Uses a deterministic port based on the
/// kubeconfig path, so if the port-forward dies and restarts, kubeconfigs
/// remain valid.
///
/// Key features:
/// - Self-healing: call `ensure_alive()` to restart the port-forward if it died
/// - Deterministic ports: same kubeconfig always gets the same local port
/// - Automatic cleanup: port-forward is killed on drop
///
/// # Example
///
/// ```ignore
/// let mut session = ProxySession::start(mgmt_kubeconfig)?;
/// let workload_kc = session.kubeconfig_for("e2e-workload").await?;
///
/// // Later, after chaos monkey may have killed the operator pod:
/// session.ensure_alive()?;  // Restart port-forward if dead
///
/// // Use workload_kc with kubectl...
/// // Port-forward stays alive while session is in scope
/// ```
#[cfg(feature = "provider-e2e")]
pub struct ProxySession {
    /// Kubeconfig for the cluster this session connects to
    kubeconfig: String,
    /// Fixed local port (deterministic based on kubeconfig)
    port: u16,
    /// Proxy URL (localhost for Docker, LoadBalancer IP for cloud)
    pub url: String,
    /// SA token for authentication
    token: String,
    /// Port-forward process (only for Docker)
    port_forward: Option<std::process::Child>,
    /// Whether to rewrite server URLs to localhost (Docker only)
    use_localhost: bool,
}

#[cfg(feature = "provider-e2e")]
impl ProxySession {
    /// Start a proxy session for Docker (uses port-forward).
    ///
    /// Creates a port-forward to the lattice-cell service and obtains an SA token.
    /// Uses a deterministic port based on the kubeconfig path.
    pub fn start(kubeconfig: &str) -> Result<Self, String> {
        let port = deterministic_port(kubeconfig);
        let (url, port_forward) = start_proxy_port_forward(kubeconfig, port)?;
        let token = get_sa_token(kubeconfig, LATTICE_SYSTEM_NAMESPACE, "lattice-operator")?;

        Ok(Self {
            kubeconfig: kubeconfig.to_string(),
            port,
            url,
            token,
            port_forward: Some(port_forward),
            use_localhost: true,
        })
    }

    /// Start a proxy session for cloud providers (direct access to LoadBalancer).
    ///
    /// No port-forward needed - the LoadBalancer IP is directly accessible.
    pub fn start_cloud(kubeconfig: &str, lb_url: &str) -> Result<Self, String> {
        let token = get_sa_token(kubeconfig, LATTICE_SYSTEM_NAMESPACE, "lattice-operator")?;

        Ok(Self {
            kubeconfig: kubeconfig.to_string(),
            port: 0, // Not used for cloud
            url: lb_url.to_string(),
            token,
            port_forward: None,
            use_localhost: false,
        })
    }

    /// Ensure the port-forward is alive, restarting if it died (Docker only).
    ///
    /// This is useful when running with chaos monkey, which may kill operator
    /// pods and break the port-forward connection. Call this before making
    /// requests through the proxy to ensure the connection is healthy.
    ///
    /// For cloud providers, this is a no-op since they don't use port-forward.
    pub fn ensure_alive(&mut self) -> Result<(), String> {
        // Cloud providers don't use port-forward
        if !self.use_localhost {
            return Ok(());
        }

        // Check and restart port-forward if needed
        if let Some(ref mut child) = self.port_forward {
            if let Ok(Some(status)) = child.try_wait() {
                info!(
                    "[ProxySession] Port-forward died (status: {}), restarting on port {}...",
                    status, self.port
                );
                let (_, new_pf) = start_proxy_port_forward(&self.kubeconfig, self.port)?;
                self.port_forward = Some(new_pf);
                info!("[ProxySession] Port-forward restarted successfully");
            }
        } else {
            info!(
                "[ProxySession] No port-forward exists, starting on port {}...",
                self.port
            );
            let (_, new_pf) = start_proxy_port_forward(&self.kubeconfig, self.port)?;
            self.port_forward = Some(new_pf);
        }
        Ok(())
    }

    /// Refresh the ServiceAccount token.
    ///
    /// Call this if you encounter authentication failures after the token has
    /// expired. Note that previously generated proxy kubeconfigs will still
    /// use the old token - you'll need to regenerate them with `kubeconfig_for()`.
    pub fn refresh_token(&mut self) -> Result<(), String> {
        info!("[ProxySession] Refreshing SA token...");
        self.token = get_sa_token(&self.kubeconfig, LATTICE_SYSTEM_NAMESPACE, "lattice-operator")?;
        info!("[ProxySession] Token refreshed successfully");
        Ok(())
    }

    /// Get the current token (for debugging or manual use).
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Fetch a kubeconfig for a child cluster from the proxy's /kubeconfig endpoint.
    ///
    /// The endpoint returns a kubeconfig with proper CA cert and all accessible clusters.
    /// We set the current-context to the requested cluster.
    pub async fn kubeconfig_for(&self, cluster_name: &str) -> Result<String, String> {
        info!(
            "[ProxySession] Fetching kubeconfig for {} from /kubeconfig endpoint...",
            cluster_name
        );

        // Fetch kubeconfig from the endpoint with SA token auth
        // Use format=sa so the kubeconfig uses exec plugin for token refresh
        let url = format!(
            "{}/kubeconfig?format=sa&kubeconfig={}&namespace={}&service_account=lattice-operator",
            self.url,
            urlencoding::encode(&self.kubeconfig),
            LATTICE_SYSTEM_NAMESPACE
        );

        // Bootstrap problem: we need the CA cert to verify TLS, but we get it from this request.
        // Skip verification for this one request; the returned kubeconfig has the CA cert
        // so all subsequent kubectl commands will verify TLS properly.
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let response = client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| format!("Failed to fetch kubeconfig: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!(
                "Failed to fetch kubeconfig: HTTP {} - {}",
                status, body
            ));
        }

        let mut kubeconfig: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse kubeconfig: {}", e))?;

        // For Docker: replace server URLs to use localhost port-forward
        // The endpoint returns LoadBalancer IPs which aren't accessible from localhost on Docker
        // For cloud: keep the LoadBalancer IPs as they're directly accessible
        if self.use_localhost {
            if let Some(clusters) = kubeconfig["clusters"].as_array_mut() {
                for cluster in clusters {
                    if let Some(server) = cluster["cluster"]["server"].as_str() {
                        // Replace the host:port with our localhost port-forward
                        // e.g., https://172.18.255.10:8082/clusters/foo -> https://127.0.0.1:19123/clusters/foo
                        if let Some(path_start) = server.find("/clusters/") {
                            let new_server = format!(
                                "https://127.0.0.1:{}{}",
                                self.port,
                                &server[path_start..]
                            );
                            cluster["cluster"]["server"] = serde_json::Value::String(new_server);
                        }
                    }
                }
            }
        }

        // Set current-context to the requested cluster
        kubeconfig["current-context"] = serde_json::Value::String(cluster_name.to_string());

        let kubeconfig_str = serde_json::to_string_pretty(&kubeconfig)
            .map_err(|e| format!("Failed to serialize kubeconfig: {}", e))?;

        // Write to temp file
        let path = format!("/tmp/{}-proxy-kubeconfig-{}", cluster_name, run_id());
        std::fs::write(&path, &kubeconfig_str)
            .map_err(|e| format!("Failed to write kubeconfig: {}", e))?;

        info!("[ProxySession] Kubeconfig written to {}", path);
        Ok(path)
    }
}

#[cfg(feature = "provider-e2e")]
impl Drop for ProxySession {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.port_forward {
            info!("[ProxySession] Stopping port-forward on port {}", self.port);
            let _ = child.kill();
        }
    }
}
