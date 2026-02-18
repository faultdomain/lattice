//! Cluster management helpers: HTTP testing, status watching, operator management,
//! config loading, proxy, SA tokens, deletion, ProxySession, teardown, namespaces.
#![cfg(feature = "provider-e2e")]

use std::path::PathBuf;
use std::time::Duration;

use kube::api::Api;
use lattice_common::crd::{ClusterPhase, LatticeCluster, LatticeExternalService};
use lattice_common::retry::{retry_with_backoff, RetryConfig};
use lattice_common::LATTICE_SYSTEM_NAMESPACE;
use tracing::{info, warn};

use super::super::providers::InfraProvider;
use super::docker::{docker_containers_deleted, run_cmd, run_kubectl};
use super::{run_id, wait_for_condition, OPERATOR_LABEL};

use lattice_cli::commands::port_forward::PortForward as ResilientPortForward;

// =============================================================================
// HTTP Testing Helpers
// =============================================================================

/// Result of an HTTP request to the proxy
pub struct HttpResponse {
    /// HTTP status code (0 if connection failed)
    pub status_code: u16,
    /// Response body
    pub body: String,
}

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
async fn http_get_with_token(url: &str, token: &str, timeout_secs: u32) -> HttpResponse {
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
    )
    .await
    {
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
///
/// Retries on any non-success response until max attempts exhausted.
pub async fn http_get_with_retry(
    url: &str,
    token: &str,
    timeout_secs: u32,
) -> Result<HttpResponse, String> {
    let retry_config = RetryConfig {
        max_attempts: 15,
        initial_delay: Duration::from_secs(2),
        max_delay: Duration::from_secs(10),
        backoff_multiplier: 1.5,
    };

    let url = url.to_string();
    let token = token.to_string();

    retry_with_backoff(&retry_config, "http_request", || {
        let url = url.clone();
        let token = token.clone();
        async move {
            let resp = http_get_with_token(&url, &token, timeout_secs).await;

            // Don't retry 4xx errors - these are intentional responses
            if resp.status_code >= 400 && resp.status_code < 500 {
                return Ok(resp);
            }

            // Retry everything else (success or 5xx/connection errors)
            if resp.is_success() {
                Ok(resp)
            } else {
                Err(format!("HTTP {} - {}", resp.status_code, resp.body))
            }
        }
    })
    .await
    .map_err(|e| e.to_string())
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
pub async fn watch_cluster_phases(
    client: &kube::Client,
    cluster_name: &str,
    timeout_secs: Option<u64>,
) -> Result<(), String> {
    use std::sync::Mutex;

    let api: Api<LatticeCluster> = Api::all(client.clone());
    let last_phase: Mutex<Option<ClusterPhase>> = Mutex::new(None);

    wait_for_condition(
        &format!("cluster {} to reach Ready", cluster_name),
        Duration::from_secs(timeout_secs.unwrap_or(1800)),
        Duration::from_secs(10),
        || {
            let api = api.clone();
            let last_phase = &last_phase;
            async move {
                match api.get(cluster_name).await {
                    Ok(cluster) => {
                        let current_phase = cluster
                            .status
                            .as_ref()
                            .map(|s| s.phase)
                            .unwrap_or(ClusterPhase::Pending);

                        {
                            let mut lp = last_phase.lock().unwrap();
                            if lp.as_ref() != Some(&current_phase) {
                                info!("Cluster {} phase: {:?}", cluster_name, current_phase);
                                *lp = Some(current_phase);
                            }
                        }

                        if matches!(current_phase, ClusterPhase::Ready | ClusterPhase::Pivoted) {
                            info!(
                                "Cluster {} is operational ({:?})!",
                                cluster_name, current_phase
                            );
                            return Ok(true);
                        }

                        if matches!(current_phase, ClusterPhase::Failed) {
                            let msg = cluster
                                .status
                                .as_ref()
                                .and_then(|s| s.message.as_deref())
                                .unwrap_or("unknown error");
                            return Err(format!("Cluster {} failed: {}", cluster_name, msg));
                        }

                        Ok(false)
                    }
                    Err(e) => {
                        info!(
                            "Warning: failed to get cluster {} status: {}",
                            cluster_name, e
                        );
                        Ok(false)
                    }
                }
            }
        },
    )
    .await
}

/// Count ready nodes from kubectl jsonpath output (lines of "True"/"False")
pub fn count_ready_nodes(output: &str) -> u32 {
    output.lines().filter(|line| *line == "True").count() as u32
}

/// Watch for worker nodes to scale to expected count
///
/// Worker nodes are those without the control-plane role.
pub async fn watch_worker_scaling(
    kubeconfig_path: &str,
    cluster_name: &str,
    expected_workers: u32,
) -> Result<(), String> {
    use std::sync::Mutex;

    let last_count: Mutex<Option<u32>> = Mutex::new(None);

    wait_for_condition(
        &format!("{} workers on {}", expected_workers, cluster_name),
        Duration::from_secs(600),
        Duration::from_secs(15),
        || {
            let last_count = &last_count;
            async move {
                let output = run_kubectl(
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
                .await
                .unwrap_or_default();
                let ready_workers = count_ready_nodes(&output);

                {
                    let mut lc = last_count.lock().unwrap();
                    if *lc != Some(ready_workers) {
                        info!(
                            "  {} ready workers on {} (target: {})",
                            ready_workers, cluster_name, expected_workers
                        );
                        *lc = Some(ready_workers);
                    }
                }

                if ready_workers >= expected_workers {
                    info!(
                        "  SUCCESS: {} has {} ready workers!",
                        cluster_name, ready_workers
                    );
                    return Ok(true);
                }

                Ok(false)
            }
        },
    )
    .await
}

// =============================================================================
// Shared Test Configuration
// =============================================================================

/// Get the workspace root directory
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("lattice-cli crate should have a parent directory")
        .parent()
        .expect("crates directory should have a parent (workspace root)")
        .to_path_buf()
}

/// Get the fixtures directory for cluster configs
fn cluster_fixtures_dir() -> PathBuf {
    workspace_root().join("crates/lattice-cli/tests/e2e/fixtures/clusters")
}

/// Get the fixtures directory for service configs
fn service_fixtures_dir() -> PathBuf {
    workspace_root().join("crates/lattice-cli/tests/e2e/fixtures/services")
}

/// Build and push the lattice Docker image
pub async fn build_and_push_lattice_image(image: &str) -> Result<(), String> {
    info!("Building lattice Docker image...");

    let output = std::process::Command::new("./scripts/dev/docker-build.sh")
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

    let output = std::process::Command::new("docker")
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
        delete_operator_pods(cluster_name, kubeconfig).await;
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
async fn delete_operator_pods(cluster_name: &str, kubeconfig: &str) {
    let msg = match run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "pod",
        "-n",
        LATTICE_SYSTEM_NAMESPACE,
        "-l",
        OPERATOR_LABEL,
        "--wait=false",
    ])
    .await
    {
        Ok(output) if output.contains("deleted") => "deleted operator pod",
        Ok(_) => "no pod found",
        Err(_) => "no pod found or not accessible",
    };
    info!("[{}] {}", cluster_name, msg);
}

/// Wait for operator deployment to be ready.
pub async fn wait_for_operator_ready(
    cluster_name: &str,
    kubeconfig: &str,
    timeout_secs: Option<u64>,
) -> Result<(), String> {
    info!("[{}] Waiting for operator to be ready...", cluster_name);

    wait_for_condition(
        &format!("operator on {} to be ready", cluster_name),
        Duration::from_secs(timeout_secs.unwrap_or(300)),
        Duration::from_secs(5),
        || async move {
            if let Ok(output) = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "rollout",
                "status",
                "deployment/lattice-operator",
                "-n",
                LATTICE_SYSTEM_NAMESPACE,
                "--timeout=10s",
            ])
            .await
            {
                if output.contains("successfully rolled out") {
                    info!("[{}] Operator is ready", cluster_name);
                    return Ok(true);
                }
            }
            Ok(false)
        },
    )
    .await
}

/// Load registry credentials from .env file or environment
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

/// Load any deserializable K8s resource from a YAML fixture file in the services directory.
pub fn load_fixture_config<T: serde::de::DeserializeOwned>(filename: &str) -> Result<T, String> {
    let path = service_fixtures_dir().join(filename);

    if !path.exists() {
        return Err(format!("Fixture config not found: {}", path.display()));
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    let value = lattice_common::yaml::parse_yaml(&content)
        .map_err(|e| format!("Invalid YAML in {}: {}", path.display(), e))?;
    serde_json::from_value(value)
        .map_err(|e| format!("Invalid config in {}: {}", path.display(), e))
}

/// Load a LatticeService from a YAML fixture file in the services directory.
pub fn load_service_config(filename: &str) -> Result<lattice_common::crd::LatticeService, String> {
    load_fixture_config(filename)
}

/// Load a LatticeExternalService from a YAML fixture file in the services directory.
pub fn load_external_service_config(filename: &str) -> Result<LatticeExternalService, String> {
    load_fixture_config(filename)
}

// =============================================================================
// Cluster Verification and Deletion
// =============================================================================

/// Verify a cluster has its own CAPI resources after pivot
pub async fn verify_cluster_capi_resources(
    kubeconfig: &str,
    cluster_name: &str,
) -> Result<(), String> {
    let nodes_output =
        run_kubectl(&["--kubeconfig", kubeconfig, "get", "nodes", "-o", "wide"]).await?;
    info!("Cluster nodes:\n{}", nodes_output);

    let capi_output = run_kubectl(&["--kubeconfig", kubeconfig, "get", "clusters", "-A"]).await?;
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
const PROXY_SERVICE_NAME: &str = "lattice-cell";
const PROXY_PORT: u16 = 8082;

/// Check if the lattice-cell proxy service exists
pub async fn proxy_service_exists(kubeconfig: &str) -> bool {
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "svc",
        PROXY_SERVICE_NAME,
        "-n",
        LATTICE_SYSTEM_NAMESPACE,
        "-o",
        "name",
    ])
    .await
    .is_ok()
}

/// Get the LoadBalancer URL for the proxy service (for cloud providers).
///
/// Waits up to 2 minutes for the LoadBalancer to get an external IP.
async fn get_proxy_loadbalancer_url(kubeconfig: &str) -> Result<String, String> {
    wait_for_condition(
        "LoadBalancer IP to be assigned",
        Duration::from_secs(300),
        Duration::from_secs(5),
        || async move {
            let result = run_kubectl(
                &[
                    "--kubeconfig",
                    kubeconfig,
                    "get",
                    "svc",
                    PROXY_SERVICE_NAME,
                    "-n",
                    LATTICE_SYSTEM_NAMESPACE,
                    "-o",
                    "jsonpath={.status.loadBalancer.ingress[0].ip}{.status.loadBalancer.ingress[0].hostname}",
                ],
            )
            .await;

            if let Ok(addr) = result {
                let addr = addr.trim().to_string();
                if !addr.is_empty() {
                    return Ok(Some(format!("https://{}:{}", addr, PROXY_PORT)));
                }
            }
            Ok(None)
        },
    )
    .await
}

/// Get proxy URL, creating a resilient port-forward if necessary.
///
/// If an existing URL is provided, verifies it's healthy first. If unhealthy,
/// creates a fresh resilient port-forward with automatic restart capability.
pub async fn get_or_create_proxy(
    kubeconfig: &str,
    existing_url: Option<&str>,
) -> Result<(String, Option<ResilientPortForward>), String> {
    use lattice_cli::commands::port_forward::check_health;

    if let Some(url) = existing_url {
        if check_health(url, Duration::from_secs(5), None).await {
            info!("[Helpers] Using existing proxy URL: {}", url);
            return Ok((url.to_string(), None));
        }
        info!("[Helpers] Existing proxy URL unhealthy, creating fresh port-forward...");
    }

    let pf = ResilientPortForward::start(kubeconfig, PROXY_PORT)
        .await
        .map_err(|e| e.to_string())?;
    let url = pf.url.clone();
    Ok((url, Some(pf)))
}

// =============================================================================
// ServiceAccount Token Helpers
// =============================================================================

/// Get a ServiceAccount token using kubectl create token
///
/// Duration is 8 hours for long-running E2E tests. Use `refresh_sa_token()`
/// if you need to refresh an expired token.
pub async fn get_sa_token(
    kubeconfig: &str,
    namespace: &str,
    sa_name: &str,
) -> Result<String, String> {
    let token = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "create",
        "token",
        sa_name,
        "-n",
        namespace,
        "--duration=8h",
    ])
    .await?;
    Ok(token.trim().to_string())
}

// =============================================================================
// Cluster Deletion Helpers
// =============================================================================

/// Delete a cluster via kubectl and wait for cleanup
///
/// The operator handles deletion via finalizers, so we just initiate deletion
/// and wait for the finalizer to complete (resource to be gone).
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
    // So we just initiate deletion and wait for parent confirmation.
    //
    // We retry until the phase changes from Ready because transient proxy/network
    // issues can cause the delete to silently fail (kubectl returns success but the
    // request never reaches the API server).
    wait_for_condition(
        &format!("{} deletion initiated", cluster_name),
        Duration::from_secs(120),
        Duration::from_secs(5),
        || {
            let cluster_kubeconfig = cluster_kubeconfig.to_string();
            let cluster_name = cluster_name.to_string();
            async move {
                // Issue the delete (idempotent — safe to retry)
                let _ = run_kubectl(&[
                    "--kubeconfig",
                    &cluster_kubeconfig,
                    "delete",
                    "latticecluster",
                    &cluster_name,
                    "--wait=false",
                ])
                .await;

                // Check that the phase is no longer Ready
                match run_kubectl(&[
                    "--kubeconfig",
                    &cluster_kubeconfig,
                    "get",
                    "latticecluster",
                    &cluster_name,
                    "-o",
                    "jsonpath={.status.phase}",
                ])
                .await
                {
                    Ok(phase) if phase.trim() == "Ready" => {
                        info!("LatticeCluster still Ready, retrying delete...");
                        Ok(false)
                    }
                    // Not Ready, not found, or error — deletion is underway
                    _ => Ok(true),
                }
            }
        },
    )
    .await?;
    info!("LatticeCluster deletion initiated (async)");

    // Wait for the LatticeCluster to be fully deleted from parent
    info!("Waiting for LatticeCluster to be deleted from parent...");
    wait_for_condition(
        &format!("{} CR deletion from parent", cluster_name),
        Duration::from_secs(600),
        Duration::from_secs(10),
        || async move {
            let deleted = match run_kubectl(&[
                "--kubeconfig",
                parent_kubeconfig,
                "get",
                "latticecluster",
                cluster_name,
                "-o",
                "name",
            ])
            .await
            {
                Ok(output) => output.trim().is_empty(),
                Err(_) => true,
            };
            if deleted {
                info!("LatticeCluster deleted from parent");
            }
            Ok(deleted)
        },
    )
    .await?;

    // For Docker, verify containers are cleaned up
    if provider == InfraProvider::Docker {
        info!("Waiting for Docker containers to be cleaned up...");
        wait_for_condition(
            &format!("{} Docker container cleanup", cluster_name),
            Duration::from_secs(300),
            Duration::from_secs(5),
            || async move {
                let deleted = docker_containers_deleted(cluster_name).await;
                if deleted {
                    info!("Docker containers cleaned up by CAPI");
                }
                Ok(deleted)
            },
        )
        .await?;
    }

    Ok(())
}

// =============================================================================
// Proxy Session
// =============================================================================

/// A resilient session for accessing clusters through the parent's proxy.
///
/// Manages a port-forward to the proxy service and provides methods to generate
/// kubeconfigs for child clusters.
///
/// Key features:
/// - **Auto-healing**: Background watchdog automatically restarts port-forward when it dies
/// - **Deterministic ports**: Same kubeconfig always gets the same local port
/// - **Automatic cleanup**: Port-forward is killed on drop
///
/// # Example
///
/// ```ignore
/// let session = ProxySession::start(mgmt_kubeconfig)?;
/// let workload_kc = session.kubeconfig_for("e2e-workload").await?;
/// // Port-forward auto-restarts if it dies - no manual intervention needed
/// ```
pub struct ProxySession {
    /// Kubeconfig for the cluster this session connects to
    kubeconfig: String,
    /// Proxy URL (localhost for Docker, LoadBalancer IP for cloud)
    pub url: String,
    /// SA token for authentication
    token: String,
    /// Resilient port-forward with automatic restart (Docker only, None for cloud)
    port_forward: Option<ResilientPortForward>,
}

impl ProxySession {
    /// Start a proxy session using port-forward (for Docker/kind).
    ///
    /// For cloud providers with LoadBalancer, use `start_cloud` instead.
    pub async fn start(kubeconfig: &str) -> Result<Self, String> {
        let pf = ResilientPortForward::start(kubeconfig, PROXY_PORT)
            .await
            .map_err(|e| e.to_string())?;
        let url = pf.url.clone();
        let token = get_sa_token(kubeconfig, LATTICE_SYSTEM_NAMESPACE, "lattice-operator").await?;

        info!(
            "[ProxySession] To reproduce manually:\n  kubectl --kubeconfig={} port-forward svc/{} {}:{} -n {}",
            kubeconfig, PROXY_SERVICE_NAME, pf.port(), PROXY_PORT, LATTICE_SYSTEM_NAMESPACE,
        );

        Ok(Self {
            kubeconfig: kubeconfig.to_string(),
            url,
            token,
            port_forward: Some(pf),
        })
    }

    /// Start a proxy session for cloud providers (fetches LoadBalancer URL).
    pub async fn start_cloud(kubeconfig: &str) -> Result<Self, String> {
        let lb_url = get_proxy_loadbalancer_url(kubeconfig).await?;
        let token = get_sa_token(kubeconfig, LATTICE_SYSTEM_NAMESPACE, "lattice-operator").await?;

        Ok(Self {
            kubeconfig: kubeconfig.to_string(),
            url: lb_url,
            token,
            port_forward: None,
        })
    }

    /// Start a proxy session, choosing port-forward or LoadBalancer based on provider.
    pub async fn start_for_provider(
        kubeconfig: &str,
        provider: InfraProvider,
    ) -> Result<Self, String> {
        match provider {
            InfraProvider::Docker => Self::start(kubeconfig).await,
            _ => Self::start_cloud(kubeconfig).await,
        }
    }

    /// Wait until the proxy is healthy (useful after operations that disrupt connectivity).
    ///
    /// Uses notification-based waiting: if the watchdog is restarting the
    /// port-forward, this returns as soon as the restart completes instead
    /// of polling. The 60s budget gives the warm restart (30s max) time to
    /// complete plus margin. Returns Ok immediately for cloud providers.
    pub async fn ensure_alive(&mut self) -> Result<(), String> {
        let Some(ref pf) = self.port_forward else {
            return Ok(()); // Cloud providers don't use port-forward
        };

        pf.wait_for_ready(Duration::from_secs(60))
            .await
            .map_err(|e| e.to_string())
    }

    /// Returns true if using localhost port-forward (Docker), false for cloud.
    fn uses_localhost(&self) -> bool {
        self.port_forward.is_some()
    }

    /// Get the local port (only valid for Docker).
    fn local_port(&self) -> u16 {
        self.port_forward.as_ref().map(|pf| pf.port()).unwrap_or(0)
    }

    /// Refresh the ServiceAccount token.
    ///
    /// Call this if you encounter authentication failures after the token has
    /// expired. Note that previously generated proxy kubeconfigs will still
    /// use the old token - you'll need to regenerate them with `kubeconfig_for()`.
    pub async fn refresh_token(&mut self) -> Result<(), String> {
        info!("[ProxySession] Refreshing SA token...");
        self.token = get_sa_token(
            &self.kubeconfig,
            LATTICE_SYSTEM_NAMESPACE,
            "lattice-operator",
        )
        .await?;
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
    ///
    /// This function retries until the cluster appears in the subtree (max 2 minutes).
    /// The cluster may not be immediately available if the agent hasn't connected yet.
    pub async fn kubeconfig_for(&self, cluster_name: &str) -> Result<String, String> {
        info!(
            "[ProxySession] Fetching kubeconfig for {} from /kubeconfig endpoint...",
            cluster_name
        );

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

        let uses_localhost = self.uses_localhost();
        let local_port = self.local_port();
        let token = self.token.clone();

        wait_for_condition(
            &format!("cluster '{}' to appear in subtree", cluster_name),
            Duration::from_secs(300),
            Duration::from_secs(5),
            || {
                let client = &client;
                let url = &url;
                let token = &token;
                async move {
                    let response = match client.get(url.as_str()).bearer_auth(token).send().await {
                        Ok(r) => r,
                        Err(e) => {
                            warn!(
                                "[ProxySession] Network error fetching kubeconfig: {}, retrying...",
                                e
                            );
                            return Ok(None);
                        }
                    };

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

                    if uses_localhost {
                        if let Some(clusters) = kubeconfig["clusters"].as_array_mut() {
                            for cluster in clusters {
                                if let Some(server) = cluster["cluster"]["server"].as_str() {
                                    if let Some(path_start) = server.find("/clusters/") {
                                        let new_server = format!(
                                            "https://127.0.0.1:{}{}",
                                            local_port,
                                            &server[path_start..]
                                        );
                                        cluster["cluster"]["server"] =
                                            serde_json::Value::String(new_server);
                                    }
                                }
                            }
                        }
                    }

                    let available_contexts: Vec<String> = kubeconfig["contexts"]
                        .as_array()
                        .map(|contexts| {
                            contexts
                                .iter()
                                .filter_map(|ctx| ctx["name"].as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();

                    if available_contexts.contains(&cluster_name.to_string()) {
                        kubeconfig["current-context"] =
                            serde_json::Value::String(cluster_name.to_string());

                        let kubeconfig_str = serde_json::to_string_pretty(&kubeconfig)
                            .map_err(|e| format!("Failed to serialize kubeconfig: {}", e))?;

                        let path =
                            format!("/tmp/{}-proxy-kubeconfig-{}", cluster_name, run_id());
                        std::fs::write(&path, &kubeconfig_str)
                            .map_err(|e| format!("Failed to write kubeconfig: {}", e))?;

                        info!("[ProxySession] Kubeconfig written to {}", path);
                        return Ok(Some(path));
                    }

                    info!(
                        "[ProxySession] Cluster '{}' not in subtree yet (available: {:?}), retrying...",
                        cluster_name, available_contexts
                    );
                    Ok(None)
                }
            },
        )
        .await
    }
}

// Note: No explicit Drop needed for ProxySession - PortForward handles its own cleanup

// =============================================================================
// Teardown Helpers
// =============================================================================

/// Uninstall the management cluster using the Lattice uninstaller.
///
/// This is the standard teardown for E2E tests - it runs the full uninstall flow
/// which handles CAPI resource cleanup, helm uninstall, and bootstrap cluster deletion.
pub async fn teardown_mgmt_cluster(
    mgmt_kubeconfig: &str,
    mgmt_cluster_name: &str,
) -> Result<(), String> {
    use lattice_cli::commands::uninstall::{UninstallArgs, Uninstaller};

    info!("Tearing down management cluster...");

    let uninstall_args = UninstallArgs {
        kubeconfig: std::path::PathBuf::from(mgmt_kubeconfig),
        name: Some(mgmt_cluster_name.to_string()),
        yes: true,
        keep_bootstrap_on_failure: false,
        run_id: Some(run_id().to_string()),
    };

    let uninstaller = Uninstaller::new(&uninstall_args)
        .await
        .map_err(|e| format!("Failed to create uninstaller: {}", e))?;

    uninstaller
        .run()
        .await
        .map_err(|e| format!("Uninstall failed: {}", e))?;

    info!("SUCCESS: Management cluster uninstalled!");
    Ok(())
}

// =============================================================================
// Namespace Helpers
// =============================================================================

/// Delete a namespace (non-blocking).
pub async fn delete_namespace(kubeconfig_path: &str, namespace: &str) {
    info!("[Namespace] Deleting namespace {}...", namespace);
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig_path,
        "delete",
        "namespace",
        namespace,
        "--wait=false",
        "--ignore-not-found",
    ])
    .await;
}

/// Ensure a fresh namespace exists by deleting if present and waiting for full cleanup.
///
/// This is important for re-running tests - stale resources cause conflicts.
pub async fn ensure_fresh_namespace(kubeconfig_path: &str, namespace: &str) -> Result<(), String> {
    // Check if namespace exists
    let ns_exists = run_kubectl(&[
        "--kubeconfig",
        kubeconfig_path,
        "get",
        "namespace",
        namespace,
        "-o",
        "name",
    ])
    .await
    .is_ok();

    if ns_exists {
        info!(
            "[Namespace] Namespace {} exists, deleting for fresh start...",
            namespace
        );
        delete_namespace(kubeconfig_path, namespace).await;

        wait_for_condition(
            &format!("namespace {} deletion", namespace),
            Duration::from_secs(300),
            Duration::from_secs(5),
            || async move {
                let deleted = match run_kubectl(&[
                    "--kubeconfig",
                    kubeconfig_path,
                    "get",
                    "namespace",
                    namespace,
                    "-o",
                    "name",
                ])
                .await
                {
                    Ok(output) => output.trim().is_empty(),
                    Err(_) => true,
                };
                if deleted {
                    info!("[Namespace] Namespace {} fully deleted", namespace);
                } else {
                    let phase = run_kubectl(&[
                        "--kubeconfig",
                        kubeconfig_path,
                        "get",
                        "namespace",
                        namespace,
                        "-o",
                        "jsonpath={.status.phase}",
                    ])
                    .await
                    .unwrap_or_default();
                    info!(
                        "[Namespace] Waiting for namespace {} deletion (phase: {})...",
                        namespace,
                        phase.trim()
                    );
                }
                Ok(deleted)
            },
        )
        .await?;
    }

    // Create fresh namespace with retry for transient connection failures
    info!("[Namespace] Creating fresh namespace {}...", namespace);
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig_path,
        "create",
        "namespace",
        namespace,
    ])
    .await?;

    Ok(())
}
