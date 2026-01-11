//! Pivot logic for cluster self-management
//!
//! The pivot process transfers CAPI resources from the cell to a workload cluster,
//! making the workload cluster self-managing.
//!
//! # Flow
//!
//! 1. Cell triggers pivot via gRPC control stream
//! 2. Agent enters PIVOTING state
//! 3. Cell executes `clusterctl move --to-kubeconfig <proxy>` through K8s API proxy
//! 4. CAPI resources are created on workload cluster
//! 5. Agent detects resources and confirms pivot complete
//!
//! # Why Pivot Matters
//!
//! - Workload clusters become independent of cell
//! - Each cluster can self-heal and self-manage
//! - Cell failure doesn't affect workload clusters
//! - Enables air-gapped operation after provisioning

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use thiserror::Error;
use tokio::time::timeout;
use tracing::{debug, info};

// Re-export retry utilities for convenience
pub use crate::retry::{retry_with_backoff, RetryConfig};

/// Pivot errors
#[derive(Debug, Error)]
pub enum PivotError {
    /// Clusterctl command failed
    #[error("clusterctl failed: {0}")]
    ClusterctlFailed(String),

    /// Kubeconfig generation failed
    #[error("kubeconfig generation failed: {0}")]
    KubeconfigFailed(String),

    /// Pivot timed out
    #[error("pivot timed out")]
    Timeout,

    /// Agent not connected
    #[error("agent not connected: {0}")]
    AgentNotConnected(String),

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result of a pivot operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PivotResult {
    /// Whether pivot was successful
    pub success: bool,
    /// Number of resources moved
    pub resources_moved: u32,
    /// Error message if failed
    pub error: Option<String>,
}

/// Command output for testability
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// Whether command succeeded
    pub success: bool,
    /// Standard output
    pub stdout: String,
    /// Standard error
    pub stderr: String,
}

impl From<Output> for CommandOutput {
    fn from(output: Output) -> Self {
        Self {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        }
    }
}

/// Trait for executing external commands (allows mocking in tests)
pub trait CommandRunner: Send + Sync {
    /// Execute clusterctl move command
    fn run_clusterctl_move(
        &self,
        target_kubeconfig: &Path,
        namespace: &str,
        cluster_name: &str,
        source_kubeconfig: Option<PathBuf>,
    ) -> Result<CommandOutput, PivotError>;

    /// Execute kubectl to check for CAPI resources
    fn run_kubectl_get(
        &self,
        resource_type: &str,
        namespace: &str,
    ) -> Result<CommandOutput, PivotError>;
}

/// Real command runner that executes actual system commands
#[derive(Default, Clone)]
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run_clusterctl_move(
        &self,
        target_kubeconfig: &Path,
        namespace: &str,
        cluster_name: &str,
        source_kubeconfig: Option<PathBuf>,
    ) -> Result<CommandOutput, PivotError> {
        let mut cmd = Command::new("clusterctl");
        cmd.arg("move")
            .arg("--to-kubeconfig")
            .arg(target_kubeconfig)
            .arg("--namespace")
            .arg(namespace)
            .arg("--filter-cluster")
            .arg(cluster_name);

        if let Some(ref source) = source_kubeconfig {
            cmd.arg("--kubeconfig").arg(source);
        }

        debug!(command = ?cmd, "Executing clusterctl move");

        let output = cmd
            .output()
            .map_err(|e| PivotError::ClusterctlFailed(format!("failed to execute: {}", e)))?;

        Ok(CommandOutput::from(output))
    }

    fn run_kubectl_get(
        &self,
        resource_type: &str,
        namespace: &str,
    ) -> Result<CommandOutput, PivotError> {
        let output = Command::new("kubectl")
            .args(["get", resource_type, "-n", namespace, "--no-headers"])
            .output()
            .map_err(|e| PivotError::Internal(format!("kubectl failed: {}", e)))?;

        Ok(CommandOutput::from(output))
    }
}

/// Pivot orchestrator for the cell side
pub struct PivotOrchestrator<R: CommandRunner = RealCommandRunner> {
    /// Timeout for pivot operations
    pivot_timeout: Duration,
    /// CAPI namespace to move resources from
    capi_namespace: String,
    /// Command runner for executing external commands
    runner: R,
}

impl PivotOrchestrator<RealCommandRunner> {
    /// Create a new pivot orchestrator with the real command runner
    pub fn new(pivot_timeout: Duration) -> Self {
        Self {
            pivot_timeout,
            capi_namespace: "default".to_string(),
            runner: RealCommandRunner,
        }
    }
}

impl<R: CommandRunner> PivotOrchestrator<R> {
    /// Create a new pivot orchestrator with a custom command runner
    pub fn with_runner(pivot_timeout: Duration, runner: R) -> Self {
        Self {
            pivot_timeout,
            capi_namespace: "default".to_string(),
            runner,
        }
    }

    /// Set the CAPI namespace
    pub fn with_capi_namespace(mut self, namespace: &str) -> Self {
        self.capi_namespace = namespace.to_string();
        self
    }

    /// Get the configured timeout
    pub fn timeout(&self) -> Duration {
        self.pivot_timeout
    }

    /// Get the configured namespace
    pub fn namespace(&self) -> &str {
        &self.capi_namespace
    }

    /// Execute pivot using clusterctl move
    ///
    /// # Arguments
    /// * `cluster_name` - Name of the cluster to pivot
    /// * `proxy_kubeconfig_path` - Path to kubeconfig pointing to the proxy
    /// * `source_kubeconfig` - Path to kubeconfig for the cell (source)
    pub async fn execute_pivot(
        &self,
        cluster_name: &str,
        proxy_kubeconfig_path: &Path,
        source_kubeconfig: Option<&Path>,
    ) -> Result<PivotResult, PivotError>
    where
        R: 'static + Clone,
    {
        info!(
            cluster = %cluster_name,
            target_kubeconfig = ?proxy_kubeconfig_path,
            "Starting pivot with clusterctl move"
        );

        let namespace = self.capi_namespace.clone();
        let cluster = cluster_name.to_string();
        let target = proxy_kubeconfig_path.to_path_buf();
        let source = source_kubeconfig.map(|p| p.to_path_buf());
        let runner = self.runner.clone();

        // Execute with timeout
        let result = timeout(self.pivot_timeout, async move {
            tokio::task::spawn_blocking(move || {
                let output = runner.run_clusterctl_move(&target, &namespace, &cluster, source)?;

                if output.success {
                    let resources = extract_resource_count(&output.stdout);
                    Ok(PivotResult {
                        success: true,
                        resources_moved: resources,
                        error: None,
                    })
                } else {
                    Err(PivotError::ClusterctlFailed(output.stderr))
                }
            })
            .await
            .map_err(|e| PivotError::Internal(e.to_string()))?
        })
        .await
        .map_err(|_| PivotError::Timeout)??;

        info!(
            cluster = %cluster_name,
            resources = result.resources_moved,
            "Pivot complete"
        );

        Ok(result)
    }

    /// Generate a temporary proxy kubeconfig file
    pub fn write_proxy_kubeconfig(kubeconfig_content: &str, path: &Path) -> Result<(), PivotError> {
        std::fs::write(path, kubeconfig_content)
            .map_err(|e| PivotError::KubeconfigFailed(e.to_string()))?;
        Ok(())
    }
}

/// Extract resource count from clusterctl output
pub fn extract_resource_count(output: &str) -> u32 {
    // clusterctl outputs lines like "Moving cluster.x-k8s.io/v1beta1, Kind=Cluster"
    output
        .lines()
        .filter(|line| line.contains("Moving") || line.contains("Creating"))
        .count() as u32
}

/// Pivot handler for the agent side
pub struct AgentPivotHandler<R: CommandRunner = RealCommandRunner> {
    /// CAPI namespace to watch
    capi_namespace: String,
    /// Command runner
    runner: R,
}

impl AgentPivotHandler<RealCommandRunner> {
    /// Create a new agent pivot handler
    pub fn new() -> Self {
        Self {
            capi_namespace: "default".to_string(),
            runner: RealCommandRunner,
        }
    }
}

impl<R: CommandRunner> AgentPivotHandler<R> {
    /// Create with a custom runner
    pub fn with_runner(runner: R) -> Self {
        Self {
            capi_namespace: "default".to_string(),
            runner,
        }
    }

    /// Set the CAPI namespace
    pub fn with_capi_namespace(mut self, namespace: &str) -> Self {
        self.capi_namespace = namespace.to_string();
        self
    }

    /// Get the configured namespace
    pub fn namespace(&self) -> &str {
        &self.capi_namespace
    }

    /// Check if CAPI resources exist in the cluster
    pub fn check_capi_resources_present(&self) -> Result<bool, PivotError> {
        let output = self
            .runner
            .run_kubectl_get("clusters.cluster.x-k8s.io", &self.capi_namespace)?;

        let has_resources =
            !output.stdout.trim().is_empty() && !output.stdout.contains("No resources found");

        debug!(
            has_resources = has_resources,
            output = %output.stdout.trim(),
            "Checked for CAPI resources"
        );

        Ok(has_resources)
    }

    /// Wait for CAPI resources to be imported
    pub async fn wait_for_capi_resources(
        &self,
        timeout_duration: Duration,
        poll_interval: Duration,
    ) -> Result<u32, PivotError> {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout_duration {
            if self.check_capi_resources_present()? {
                let count = self.count_capi_resources()?;
                info!(count = count, "CAPI resources detected");
                return Ok(count);
            }

            tokio::time::sleep(poll_interval).await;
        }

        Err(PivotError::Timeout)
    }

    /// Count CAPI resources in the namespace
    fn count_capi_resources(&self) -> Result<u32, PivotError> {
        let resource_types = [
            "clusters.cluster.x-k8s.io",
            "machines.cluster.x-k8s.io",
            "machinedeployments.cluster.x-k8s.io",
            "kubeadmcontrolplanes.controlplane.cluster.x-k8s.io",
        ];

        let mut total = 0;

        for resource_type in &resource_types {
            let output = self
                .runner
                .run_kubectl_get(resource_type, &self.capi_namespace)?;
            let count = output
                .stdout
                .lines()
                .filter(|l| !l.trim().is_empty())
                .count();
            total += count as u32;
        }

        Ok(total)
    }
}

impl Default for AgentPivotHandler<RealCommandRunner> {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Kubeconfig Patching for Self-Management
// =============================================================================

/// Patch the kubeconfig secret to use the internal Kubernetes service endpoint.
///
/// After clusterctl move, the kubeconfig secret contains the external network IP
/// (e.g., 172.18.0.3:6443 for Docker, or cloud provider load balancer IP).
/// For self-managing clusters, CAPI needs to reach the API server from within
/// the cluster, which requires using the internal service endpoint
/// (kubernetes.default.svc:443) instead.
///
/// This function patches ALL cluster entries in the kubeconfig, not just the first one,
/// to handle multi-cluster kubeconfigs correctly.
///
/// # Arguments
/// * `cluster_name` - Name of the cluster (used to find the secret `{cluster_name}-kubeconfig`)
/// * `namespace` - Namespace where the kubeconfig secret resides
///
/// # Errors
/// Returns an error if the secret cannot be found, parsed, or patched.
pub async fn patch_kubeconfig_for_self_management(
    cluster_name: &str,
    namespace: &str,
) -> Result<(), PivotError> {
    info!(cluster = %cluster_name, namespace = %namespace, "Patching kubeconfig for self-management");

    // Get in-cluster client
    let client = kube::Client::try_default()
        .await
        .map_err(|e| PivotError::Internal(format!("failed to create k8s client: {}", e)))?;

    // Get the kubeconfig secret
    let secrets: Api<Secret> = Api::namespaced(client, namespace);
    let secret_name = format!("{}-kubeconfig", cluster_name);

    let secret = secrets.get(&secret_name).await.map_err(|e| {
        PivotError::Internal(format!(
            "failed to get kubeconfig secret '{}': {}",
            secret_name, e
        ))
    })?;

    // Get the kubeconfig data
    let data = secret
        .data
        .ok_or_else(|| PivotError::Internal("kubeconfig secret has no data".to_string()))?;
    let kubeconfig_bytes = data
        .get("value")
        .ok_or_else(|| PivotError::Internal("kubeconfig secret missing 'value' key".to_string()))?;

    // Parse the kubeconfig
    let kubeconfig_str = String::from_utf8(kubeconfig_bytes.0.clone())
        .map_err(|e| PivotError::Internal(format!("kubeconfig is not valid UTF-8: {}", e)))?;

    // Parse as YAML and update the server URL
    let mut kubeconfig: serde_yaml::Value = serde_yaml::from_str(&kubeconfig_str)
        .map_err(|e| PivotError::Internal(format!("failed to parse kubeconfig YAML: {}", e)))?;

    // Update ALL cluster server URLs to internal endpoint
    let mut updated_count = 0;
    if let Some(clusters) = kubeconfig
        .get_mut("clusters")
        .and_then(|c| c.as_sequence_mut())
    {
        for cluster in clusters {
            if let Some(cluster_config) = cluster.get_mut("cluster") {
                if let Some(server) = cluster_config.get_mut("server") {
                    let old_server = server.as_str().unwrap_or("unknown").to_string();
                    // Only patch if it's not already using the internal endpoint
                    if !old_server.contains("kubernetes.default.svc") {
                        *server = serde_yaml::Value::String(
                            "https://kubernetes.default.svc:443".to_string(),
                        );
                        info!(
                            cluster = %cluster_name,
                            old_server = %old_server,
                            new_server = "https://kubernetes.default.svc:443",
                            "Updated kubeconfig server URL"
                        );
                        updated_count += 1;
                    }
                }
            }
        }
    }

    if updated_count == 0 {
        debug!(cluster = %cluster_name, "Kubeconfig already uses internal endpoint, skipping patch");
        return Ok(());
    }

    // Serialize back to YAML
    let updated_kubeconfig = serde_yaml::to_string(&kubeconfig)
        .map_err(|e| PivotError::Internal(format!("failed to serialize kubeconfig: {}", e)))?;

    // Encode as base64
    let encoded = STANDARD.encode(updated_kubeconfig.as_bytes());

    // Patch the secret
    let patch = serde_json::json!({
        "data": {
            "value": encoded
        }
    });

    secrets
        .patch(
            &secret_name,
            &PatchParams::apply("lattice"),
            &Patch::Merge(&patch),
        )
        .await
        .map_err(|e| PivotError::Internal(format!("failed to patch kubeconfig secret: {}", e)))?;

    info!(
        cluster = %cluster_name,
        updated_servers = updated_count,
        "Kubeconfig patched for self-management"
    );
    Ok(())
}

/// Patch a child cluster's kubeconfig to use the central proxy
///
/// Updates the server URL to point to the internal central proxy service
/// with path-based routing: `/cluster/{cluster_name}`. Includes CA cert for TLS.
///
/// # Arguments
/// * `cluster_name` - Name of the child cluster
/// * `namespace` - Namespace where the kubeconfig secret exists
/// * `proxy_url` - URL of the central proxy (e.g., "https://lattice-proxy.lattice-system.svc:8081")
/// * `ca_cert_pem` - CA certificate PEM for TLS verification
pub async fn patch_kubeconfig_for_child_cluster(
    cluster_name: &str,
    namespace: &str,
    proxy_url: &str,
    ca_cert_pem: &str,
) -> Result<(), PivotError> {
    let client = Client::try_default()
        .await
        .map_err(|e| PivotError::Internal(format!("failed to create k8s client: {}", e)))?;

    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let secret_name = format!("{}-kubeconfig", cluster_name);

    info!(
        cluster = %cluster_name,
        namespace = %namespace,
        secret = %secret_name,
        "Patching kubeconfig for child cluster to use central proxy"
    );

    // Get the current kubeconfig secret
    let secret = secrets.get(&secret_name).await.map_err(|e| {
        PivotError::Internal(format!(
            "failed to get kubeconfig secret '{}': {}",
            secret_name, e
        ))
    })?;

    let kubeconfig_bytes = secret
        .data
        .as_ref()
        .and_then(|d| d.get("value"))
        .ok_or_else(|| PivotError::Internal("kubeconfig secret missing 'value' key".to_string()))?;

    let kubeconfig_str = String::from_utf8(kubeconfig_bytes.0.clone())
        .map_err(|e| PivotError::Internal(format!("kubeconfig is not valid UTF-8: {}", e)))?;

    let mut kubeconfig: serde_yaml::Value = serde_yaml::from_str(&kubeconfig_str)
        .map_err(|e| PivotError::Internal(format!("failed to parse kubeconfig YAML: {}", e)))?;

    // Build the proxy URL with path-based cluster routing
    let proxy_server = format!("{}/cluster/{}", proxy_url, cluster_name);

    // Update ALL cluster server URLs to proxy endpoint
    let mut updated_count = 0;
    if let Some(clusters) = kubeconfig
        .get_mut("clusters")
        .and_then(|c| c.as_sequence_mut())
    {
        for cluster in clusters {
            if let Some(cluster_config) = cluster.get_mut("cluster") {
                if let Some(server) = cluster_config.get_mut("server") {
                    let old_server = server.as_str().unwrap_or("unknown").to_string();
                    // Only patch if not already using the proxy (check for /cluster/ path)
                    if !old_server.contains("/cluster/") {
                        *server = serde_yaml::Value::String(proxy_server.clone());
                        // Set certificate-authority-data to our CA cert for TLS
                        let ca_cert_b64 = STANDARD.encode(ca_cert_pem.as_bytes());
                        cluster_config["certificate-authority-data"] =
                            serde_yaml::Value::String(ca_cert_b64);
                        info!(
                            cluster = %cluster_name,
                            old_server = %old_server,
                            new_server = %proxy_server,
                            "Updated kubeconfig server URL to use central proxy"
                        );
                        updated_count += 1;
                    }
                }
            }
        }
    }

    if updated_count == 0 {
        debug!(
            cluster = %cluster_name,
            "Kubeconfig already uses central proxy, skipping patch"
        );
        return Ok(());
    }

    let updated_kubeconfig = serde_yaml::to_string(&kubeconfig)
        .map_err(|e| PivotError::Internal(format!("failed to serialize kubeconfig: {}", e)))?;

    let encoded = STANDARD.encode(updated_kubeconfig.as_bytes());

    let patch = serde_json::json!({
        "data": {
            "value": encoded
        }
    });

    secrets
        .patch(
            &secret_name,
            &PatchParams::apply("lattice"),
            &Patch::Merge(&patch),
        )
        .await
        .map_err(|e| PivotError::Internal(format!("failed to patch kubeconfig secret: {}", e)))?;

    info!(
        cluster = %cluster_name,
        updated_servers = updated_count,
        "Kubeconfig patched to use central proxy"
    );
    Ok(())
}

/// URL for the internal central proxy service (HTTPS)
pub const CENTRAL_PROXY_SERVICE_URL: &str = "https://lattice-proxy.lattice-system.svc:8081";

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::NamedTempFile;

    // ==========================================================================
    // Mock Command Runner for Testing
    // ==========================================================================
    //
    // A configurable mock that allows tests to specify expected behavior
    // for external commands without actually executing them.

    type ClusterctlMockFn = Box<
        dyn Fn(&Path, &str, &str, Option<PathBuf>) -> Result<CommandOutput, PivotError>
            + Send
            + Sync,
    >;
    type KubectlMockFn = Box<dyn Fn(&str, &str) -> Result<CommandOutput, PivotError> + Send + Sync>;

    /// Mock command runner for testing
    #[derive(Clone)]
    pub struct MockCommandRunner {
        clusterctl_fn: std::sync::Arc<Mutex<Option<ClusterctlMockFn>>>,
        kubectl_fn: std::sync::Arc<Mutex<Option<KubectlMockFn>>>,
    }

    impl MockCommandRunner {
        pub fn new() -> Self {
            Self {
                clusterctl_fn: std::sync::Arc::new(Mutex::new(None)),
                kubectl_fn: std::sync::Arc::new(Mutex::new(None)),
            }
        }

        pub fn with_clusterctl<F>(self, f: F) -> Self
        where
            F: Fn(&Path, &str, &str, Option<PathBuf>) -> Result<CommandOutput, PivotError>
                + Send
                + Sync
                + 'static,
        {
            *self.clusterctl_fn.lock().unwrap() = Some(Box::new(f));
            self
        }

        pub fn with_kubectl<F>(self, f: F) -> Self
        where
            F: Fn(&str, &str) -> Result<CommandOutput, PivotError> + Send + Sync + 'static,
        {
            *self.kubectl_fn.lock().unwrap() = Some(Box::new(f));
            self
        }
    }

    impl CommandRunner for MockCommandRunner {
        fn run_clusterctl_move(
            &self,
            target_kubeconfig: &Path,
            namespace: &str,
            cluster_name: &str,
            source_kubeconfig: Option<PathBuf>,
        ) -> Result<CommandOutput, PivotError> {
            let guard = self.clusterctl_fn.lock().unwrap();
            match &*guard {
                Some(f) => f(
                    target_kubeconfig,
                    namespace,
                    cluster_name,
                    source_kubeconfig,
                ),
                None => Ok(CommandOutput {
                    success: true,
                    stdout: String::new(),
                    stderr: String::new(),
                }),
            }
        }

        fn run_kubectl_get(
            &self,
            resource_type: &str,
            namespace: &str,
        ) -> Result<CommandOutput, PivotError> {
            let guard = self.kubectl_fn.lock().unwrap();
            match &*guard {
                Some(f) => f(resource_type, namespace),
                None => Ok(CommandOutput {
                    success: true,
                    stdout: String::new(),
                    stderr: String::new(),
                }),
            }
        }
    }

    // ==========================================================================
    // Story Tests: Pivot Operation Lifecycle
    // ==========================================================================
    //
    // The pivot operation moves CAPI resources from the cell to a workload cluster,
    // making the workload cluster fully self-managing.

    /// Story: Successful pivot moves resources to target cluster
    ///
    /// When clusterctl move succeeds, we extract the resource count from output
    /// and return a successful result.
    #[tokio::test]
    async fn story_successful_pivot_moves_resources() {
        let mock = MockCommandRunner::new().with_clusterctl(|_, _, _, _| {
            Ok(CommandOutput {
                success: true,
                stdout: r#"Performing move...
Moving cluster.x-k8s.io/v1beta1, Kind=Cluster, ns/my-cluster
Moving cluster.x-k8s.io/v1beta1, Kind=Machine, ns/my-cluster-cp-0
Moving cluster.x-k8s.io/v1beta1, Kind=MachineDeployment, ns/my-cluster-md-0
Creating cluster.x-k8s.io/v1beta1, Kind=Cluster
Done."#
                    .to_string(),
                stderr: String::new(),
            })
        });

        let orchestrator = PivotOrchestrator::with_runner(Duration::from_secs(300), mock);

        let temp_kubeconfig = NamedTempFile::new().unwrap();
        let result = orchestrator
            .execute_pivot("my-cluster", temp_kubeconfig.path(), None)
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.resources_moved, 4); // 3 Moving + 1 Creating
        assert!(result.error.is_none());
    }

    /// Story: Failed pivot returns error with details
    ///
    /// When clusterctl move fails, we capture stderr and return it in the error.
    #[tokio::test]
    async fn story_failed_pivot_returns_error_details() {
        let mock = MockCommandRunner::new().with_clusterctl(|_, _, _, _| {
            Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "Error: unable to connect to target cluster".to_string(),
            })
        });

        let orchestrator = PivotOrchestrator::with_runner(Duration::from_secs(300), mock);

        let temp_kubeconfig = NamedTempFile::new().unwrap();
        let result = orchestrator
            .execute_pivot("my-cluster", temp_kubeconfig.path(), None)
            .await;

        assert!(result.is_err());
        match result {
            Err(PivotError::ClusterctlFailed(msg)) => {
                assert!(msg.contains("unable to connect"));
            }
            _ => panic!("Expected ClusterctlFailed error"),
        }
    }

    /// Story: Pivot with source kubeconfig for non-default context
    ///
    /// When pivoting from a cell that isn't the default context,
    /// we pass the source kubeconfig to clusterctl.
    #[tokio::test]
    async fn story_pivot_with_explicit_source_kubeconfig() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let source_was_some = std::sync::Arc::new(AtomicBool::new(false));
        let source_was_some_clone = source_was_some.clone();

        let mock = MockCommandRunner::new().with_clusterctl(move |_, _, _, source| {
            source_was_some_clone.store(source.is_some(), Ordering::SeqCst);
            Ok(CommandOutput {
                success: true,
                stdout: "Moving cluster.x-k8s.io/v1beta1, Kind=Cluster".to_string(),
                stderr: String::new(),
            })
        });

        let orchestrator = PivotOrchestrator::with_runner(Duration::from_secs(300), mock);

        let target = NamedTempFile::new().unwrap();
        let source = NamedTempFile::new().unwrap();

        let result = orchestrator
            .execute_pivot("cluster", target.path(), Some(source.path()))
            .await
            .unwrap();

        assert!(result.success);
        assert!(
            source_was_some.load(Ordering::SeqCst),
            "Source kubeconfig should have been passed"
        );
    }

    /// Story: Agent detects CAPI resources after pivot
    ///
    /// After pivot, the agent checks for CAPI resources to confirm success.
    #[test]
    fn story_agent_detects_capi_resources_after_pivot() {
        let mock = MockCommandRunner::new().with_kubectl(|_, _| {
            Ok(CommandOutput {
                success: true,
                stdout: "my-cluster   True   v1.28.0   5m\n".to_string(),
                stderr: String::new(),
            })
        });

        let handler = AgentPivotHandler::with_runner(mock);
        let has_resources = handler.check_capi_resources_present().unwrap();

        assert!(has_resources);
    }

    /// Story: Agent detects no CAPI resources before pivot
    ///
    /// Before pivot completes, no CAPI resources exist on the workload cluster.
    #[test]
    fn story_agent_detects_no_capi_resources_before_pivot() {
        let mock = MockCommandRunner::new().with_kubectl(|_, _| {
            Ok(CommandOutput {
                success: true,
                stdout: "No resources found in default namespace.\n".to_string(),
                stderr: String::new(),
            })
        });

        let handler = AgentPivotHandler::with_runner(mock);
        let has_resources = handler.check_capi_resources_present().unwrap();

        assert!(!has_resources);
    }

    /// Story: Agent counts all CAPI resource types
    ///
    /// The agent counts clusters, machines, machinedeployments, and control planes.
    #[test]
    fn story_agent_counts_all_capi_resource_types() {
        let mock = MockCommandRunner::new().with_kubectl(|resource_type, _| {
            let stdout = match resource_type {
                "clusters.cluster.x-k8s.io" => "my-cluster   True",
                "machines.cluster.x-k8s.io" => "cp-0   Running\ncp-1   Running\nworker-0   Running",
                "machinedeployments.cluster.x-k8s.io" => "md-0   3   3   3",
                "kubeadmcontrolplanes.controlplane.cluster.x-k8s.io" => "cp   Initialized",
                _ => "",
            };
            Ok(CommandOutput {
                success: true,
                stdout: stdout.to_string(),
                stderr: String::new(),
            })
        });

        let handler = AgentPivotHandler::with_runner(mock);
        let count = handler.count_capi_resources().unwrap();

        // 1 cluster + 3 machines + 1 machinedeployment + 1 controlplane = 6
        assert_eq!(count, 6);
    }

    /// Story: Kubeconfig is written for clusterctl
    ///
    /// Before pivot, we write a temporary kubeconfig for the target cluster.
    #[test]
    fn story_kubeconfig_written_for_clusterctl() {
        let temp = NamedTempFile::new().unwrap();
        let kubeconfig = r#"
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: http://127.0.0.1:8080
  name: proxy
"#;

        let result =
            PivotOrchestrator::<RealCommandRunner>::write_proxy_kubeconfig(kubeconfig, temp.path());
        assert!(result.is_ok());

        let written = std::fs::read_to_string(temp.path()).unwrap();
        assert!(written.contains("server: http://127.0.0.1:8080"));
    }

    /// Story: Kubeconfig write fails for invalid path
    #[test]
    fn story_kubeconfig_write_fails_for_invalid_path() {
        let result = PivotOrchestrator::<RealCommandRunner>::write_proxy_kubeconfig(
            "content",
            Path::new("/nonexistent/directory/kubeconfig"),
        );

        assert!(result.is_err());
        match result {
            Err(PivotError::KubeconfigFailed(_)) => {}
            _ => panic!("Expected KubeconfigFailed"),
        }
    }

    // ==========================================================================
    // Resource Count Extraction Tests
    // ==========================================================================

    #[test]
    fn test_extract_resource_count_mixed() {
        let output = r#"
Moving cluster.x-k8s.io/v1beta1, Kind=Cluster
Moving cluster.x-k8s.io/v1beta1, Kind=Machine
Creating some-resource
Other log line
"#;
        assert_eq!(extract_resource_count(output), 3);
    }

    #[test]
    fn test_extract_resource_count_empty() {
        assert_eq!(extract_resource_count(""), 0);
    }

    #[test]
    fn test_extract_resource_count_no_matches() {
        assert_eq!(extract_resource_count("Some random output"), 0);
    }

    // ==========================================================================
    // Configuration Tests
    // ==========================================================================

    #[test]
    fn test_orchestrator_configuration() {
        let orchestrator =
            PivotOrchestrator::new(Duration::from_secs(600)).with_capi_namespace("capi-system");

        assert_eq!(orchestrator.timeout(), Duration::from_secs(600));
        assert_eq!(orchestrator.namespace(), "capi-system");
    }

    #[test]
    fn test_handler_configuration() {
        let handler = AgentPivotHandler::new().with_capi_namespace("my-namespace");

        assert_eq!(handler.namespace(), "my-namespace");
    }

    #[test]
    fn test_handler_default() {
        let handler = AgentPivotHandler::default();
        assert_eq!(handler.namespace(), "default");
    }

    // ==========================================================================
    // Error Display Tests
    // ==========================================================================

    #[test]
    fn test_error_display() {
        assert_eq!(
            PivotError::ClusterctlFailed("cmd error".to_string()).to_string(),
            "clusterctl failed: cmd error"
        );
        assert_eq!(
            PivotError::KubeconfigFailed("io error".to_string()).to_string(),
            "kubeconfig generation failed: io error"
        );
        assert_eq!(PivotError::Timeout.to_string(), "pivot timed out");
        assert_eq!(
            PivotError::AgentNotConnected("cluster-1".to_string()).to_string(),
            "agent not connected: cluster-1"
        );
        assert_eq!(
            PivotError::Internal("panic".to_string()).to_string(),
            "internal error: panic"
        );
    }

    // ==========================================================================
    // CommandOutput Tests
    // ==========================================================================

    #[test]
    fn test_command_output_from_std_output() {
        // We can't easily create Output, so test CommandOutput directly
        let output = CommandOutput {
            success: true,
            stdout: "hello".to_string(),
            stderr: "".to_string(),
        };

        assert!(output.success);
        assert_eq!(output.stdout, "hello");
    }

    #[test]
    fn test_pivot_result_equality() {
        let r1 = PivotResult {
            success: true,
            resources_moved: 5,
            error: None,
        };
        let r2 = PivotResult {
            success: true,
            resources_moved: 5,
            error: None,
        };
        assert_eq!(r1, r2);
    }

    // ==========================================================================
    // Story Tests: CAPI Export
    // ==========================================================================
    //
    // "When exporting cluster resources, the pivot manager should..."

    /// When exporting cluster resources, the pivot manager should pass the
    /// correct namespace and cluster name to clusterctl.
    #[tokio::test]
    async fn when_exporting_resources_should_pass_correct_namespace() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let namespace_correct = Arc::new(AtomicBool::new(false));
        let cluster_correct = Arc::new(AtomicBool::new(false));
        let ns_clone = namespace_correct.clone();
        let cl_clone = cluster_correct.clone();

        let mock = MockCommandRunner::new().with_clusterctl(move |_, namespace, cluster, _| {
            ns_clone.store(namespace == "capi-system", Ordering::SeqCst);
            cl_clone.store(cluster == "production-cluster", Ordering::SeqCst);
            Ok(CommandOutput {
                success: true,
                stdout: "Moving cluster.x-k8s.io/v1beta1, Kind=Cluster".to_string(),
                stderr: String::new(),
            })
        });

        let orchestrator = PivotOrchestrator::with_runner(Duration::from_secs(300), mock)
            .with_capi_namespace("capi-system");

        let temp_kubeconfig = NamedTempFile::new().unwrap();
        let result = orchestrator
            .execute_pivot("production-cluster", temp_kubeconfig.path(), None)
            .await;

        assert!(result.is_ok());
        assert!(
            namespace_correct.load(Ordering::SeqCst),
            "Expected namespace 'capi-system' to be passed to clusterctl"
        );
        assert!(
            cluster_correct.load(Ordering::SeqCst),
            "Expected cluster 'production-cluster' to be passed to clusterctl"
        );
    }

    /// When exporting cluster resources, the pivot manager should use the
    /// target kubeconfig path for the destination cluster.
    #[tokio::test]
    async fn when_exporting_resources_should_use_target_kubeconfig() {
        use std::sync::{Arc, Mutex as StdMutex};

        let captured_path = Arc::new(StdMutex::new(PathBuf::new()));
        let path_clone = captured_path.clone();

        let mock = MockCommandRunner::new().with_clusterctl(move |target, _, _, _| {
            *path_clone.lock().unwrap() = target.to_path_buf();
            Ok(CommandOutput {
                success: true,
                stdout: "Moving cluster.x-k8s.io/v1beta1, Kind=Cluster".to_string(),
                stderr: String::new(),
            })
        });

        let orchestrator = PivotOrchestrator::with_runner(Duration::from_secs(300), mock);

        let temp_kubeconfig = NamedTempFile::new().unwrap();
        let expected_path = temp_kubeconfig.path().to_path_buf();
        let _ = orchestrator
            .execute_pivot("cluster", temp_kubeconfig.path(), None)
            .await;

        assert_eq!(*captured_path.lock().unwrap(), expected_path);
    }

    // ==========================================================================
    // Story Tests: CAPI Import
    // ==========================================================================
    //
    // "When importing cluster resources, the pivot manager should..."

    /// When importing cluster resources, the agent should detect when resources
    /// appear in the target namespace.
    #[tokio::test]
    async fn when_importing_resources_agent_should_detect_arrival() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        // Simulate resources appearing after 2 checks
        let check_count = Arc::new(AtomicU32::new(0));
        let check_count_clone = check_count.clone();

        let mock = MockCommandRunner::new().with_kubectl(move |_, _| {
            let count = check_count_clone.fetch_add(1, Ordering::SeqCst);
            if count < 2 {
                // No resources yet
                Ok(CommandOutput {
                    success: true,
                    stdout: "No resources found in default namespace.\n".to_string(),
                    stderr: String::new(),
                })
            } else {
                // Resources have arrived
                Ok(CommandOutput {
                    success: true,
                    stdout: "my-cluster   True   v1.28.0   5m\n".to_string(),
                    stderr: String::new(),
                })
            }
        });

        let handler = AgentPivotHandler::with_runner(mock);
        let result = handler
            .wait_for_capi_resources(Duration::from_secs(5), Duration::from_millis(10))
            .await;

        assert!(result.is_ok());
        // Should have checked at least 3 times (2 misses + 1 hit)
        assert!(check_count.load(Ordering::SeqCst) >= 3);
    }

    /// When importing cluster resources, the agent should count all resource types.
    #[tokio::test]
    async fn when_importing_resources_agent_should_count_all_types() {
        let mock = MockCommandRunner::new().with_kubectl(|resource_type, _| {
            let stdout = match resource_type {
                "clusters.cluster.x-k8s.io" => "cluster-1   True",
                "machines.cluster.x-k8s.io" => "machine-1   Running\nmachine-2   Running",
                "machinedeployments.cluster.x-k8s.io" => "md-0   2   2   2",
                "kubeadmcontrolplanes.controlplane.cluster.x-k8s.io" => "kcp   Initialized",
                _ => "",
            };
            Ok(CommandOutput {
                success: true,
                stdout: stdout.to_string(),
                stderr: String::new(),
            })
        });

        let handler = AgentPivotHandler::with_runner(mock);
        let result = handler
            .wait_for_capi_resources(Duration::from_secs(5), Duration::from_millis(10))
            .await;

        // 1 cluster + 2 machines + 1 md + 1 kcp = 5
        assert_eq!(result.unwrap(), 5);
    }

    // ==========================================================================
    // Story Tests: Pivot Orchestration
    // ==========================================================================
    //
    // "When a pivot command is received, the agent should..."

    /// When a pivot command is received and times out waiting for resources,
    /// the agent should return a Timeout error.
    #[tokio::test]
    async fn when_pivot_received_and_no_resources_appear_should_timeout() {
        let mock = MockCommandRunner::new().with_kubectl(|_, _| {
            // Resources never appear
            Ok(CommandOutput {
                success: true,
                stdout: "No resources found in default namespace.\n".to_string(),
                stderr: String::new(),
            })
        });

        let handler = AgentPivotHandler::with_runner(mock);
        let result = handler
            .wait_for_capi_resources(Duration::from_millis(50), Duration::from_millis(10))
            .await;

        assert!(matches!(result, Err(PivotError::Timeout)));
    }

    /// When a pivot command is received, the agent should check the correct namespace.
    #[tokio::test]
    async fn when_pivot_received_should_check_correct_namespace() {
        use std::sync::{Arc, Mutex as StdMutex};

        let captured_namespace = Arc::new(StdMutex::new(String::new()));
        let ns_clone = captured_namespace.clone();

        let mock = MockCommandRunner::new().with_kubectl(move |_, namespace| {
            *ns_clone.lock().unwrap() = namespace.to_string();
            Ok(CommandOutput {
                success: true,
                stdout: "cluster-1   True\n".to_string(),
                stderr: String::new(),
            })
        });

        let handler = AgentPivotHandler::with_runner(mock).with_capi_namespace("workload-ns");
        let _ = handler
            .wait_for_capi_resources(Duration::from_secs(1), Duration::from_millis(10))
            .await;

        assert_eq!(*captured_namespace.lock().unwrap(), "workload-ns");
    }

    // ==========================================================================
    // Story Tests: Error Recovery
    // ==========================================================================
    //
    // "When pivot fails, the system should..."

    /// When pivot fails due to clusterctl error, the system should return
    /// a ClusterctlFailed error with the stderr message.
    #[tokio::test]
    async fn when_pivot_fails_should_return_clusterctl_error() {
        let mock = MockCommandRunner::new().with_clusterctl(|_, _, _, _| {
            Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "Error: cluster 'test' not found in namespace 'default'".to_string(),
            })
        });

        let orchestrator = PivotOrchestrator::with_runner(Duration::from_secs(300), mock);

        let temp_kubeconfig = NamedTempFile::new().unwrap();
        let result = orchestrator
            .execute_pivot("test", temp_kubeconfig.path(), None)
            .await;

        match result {
            Err(PivotError::ClusterctlFailed(msg)) => {
                assert!(msg.contains("cluster 'test' not found"));
            }
            other => panic!("Expected ClusterctlFailed, got {:?}", other),
        }
    }

    /// When pivot fails due to command execution error, the system should
    /// return an appropriate error.
    #[tokio::test]
    async fn when_pivot_command_fails_to_execute_should_return_error() {
        let mock = MockCommandRunner::new().with_clusterctl(|_, _, _, _| {
            Err(PivotError::ClusterctlFailed(
                "failed to execute: No such file or directory".to_string(),
            ))
        });

        let orchestrator = PivotOrchestrator::with_runner(Duration::from_secs(300), mock);

        let temp_kubeconfig = NamedTempFile::new().unwrap();
        let result = orchestrator
            .execute_pivot("cluster", temp_kubeconfig.path(), None)
            .await;

        assert!(matches!(result, Err(PivotError::ClusterctlFailed(_))));
    }

    /// When kubectl fails during resource check, the system should propagate
    /// the error.
    #[test]
    fn when_kubectl_fails_should_propagate_error() {
        let mock = MockCommandRunner::new().with_kubectl(|_, _| {
            Err(PivotError::Internal(
                "kubectl: command not found".to_string(),
            ))
        });

        let handler = AgentPivotHandler::with_runner(mock);
        let result = handler.check_capi_resources_present();

        assert!(matches!(result, Err(PivotError::Internal(_))));
    }

    /// When kubectl fails during wait, the system should stop waiting and
    /// return the error.
    #[tokio::test]
    async fn when_kubectl_fails_during_wait_should_return_error() {
        let mock = MockCommandRunner::new()
            .with_kubectl(|_, _| Err(PivotError::Internal("connection refused".to_string())));

        let handler = AgentPivotHandler::with_runner(mock);
        let result = handler
            .wait_for_capi_resources(Duration::from_secs(5), Duration::from_millis(10))
            .await;

        match result {
            Err(PivotError::Internal(msg)) => {
                assert!(msg.contains("connection refused"));
            }
            other => panic!("Expected Internal error, got {:?}", other),
        }
    }

    // ==========================================================================
    // Story Tests: Edge Cases
    // ==========================================================================

    /// When resources exist but output is empty lines, should not count them.
    #[test]
    fn when_output_has_empty_lines_should_not_count_them() {
        let mock = MockCommandRunner::new().with_kubectl(|resource_type, _| {
            let stdout = match resource_type {
                "clusters.cluster.x-k8s.io" => "\n\n",
                "machines.cluster.x-k8s.io" => "machine-1   Running\n\n",
                _ => "",
            };
            Ok(CommandOutput {
                success: true,
                stdout: stdout.to_string(),
                stderr: String::new(),
            })
        });

        let handler = AgentPivotHandler::with_runner(mock);
        let count = handler.count_capi_resources().unwrap();

        // Only 1 machine line, empty lines should not count
        assert_eq!(count, 1);
    }

    /// When pivot output has no Moving/Creating lines, resource count should be zero.
    #[tokio::test]
    async fn when_pivot_output_has_no_resource_lines_count_should_be_zero() {
        let mock = MockCommandRunner::new().with_clusterctl(|_, _, _, _| {
            Ok(CommandOutput {
                success: true,
                stdout: "Performing move...\nDone.".to_string(),
                stderr: String::new(),
            })
        });

        let orchestrator = PivotOrchestrator::with_runner(Duration::from_secs(300), mock);

        let temp_kubeconfig = NamedTempFile::new().unwrap();
        let result = orchestrator
            .execute_pivot("cluster", temp_kubeconfig.path(), None)
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.resources_moved, 0);
    }

    // ==========================================================================
    // CommandOutput From std::process::Output Tests
    // ==========================================================================

    /// Test that CommandOutput correctly converts from std::process::Output.
    /// This tests the From implementation for lines 75-83.
    #[test]
    fn test_command_output_from_process_output() {
        // Create a successful output manually using std::process::Command
        // We need to run an actual command to get a real Output
        let output = std::process::Command::new("echo")
            .arg("hello world")
            .output()
            .expect("Failed to run echo command");

        let cmd_output = CommandOutput::from(output);
        assert!(cmd_output.success);
        assert!(cmd_output.stdout.contains("hello world"));
        assert!(cmd_output.stderr.is_empty());
    }

    /// Test CommandOutput from a failing command.
    #[test]
    fn test_command_output_from_failing_command() {
        // Run a command that exits with non-zero status
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg("exit 1")
            .output()
            .expect("Failed to run sh command");

        let cmd_output = CommandOutput::from(output);
        assert!(!cmd_output.success);
    }

    /// Test CommandOutput captures stderr.
    #[test]
    fn test_command_output_captures_stderr() {
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg("echo 'error message' >&2")
            .output()
            .expect("Failed to run sh command");

        let cmd_output = CommandOutput::from(output);
        assert!(cmd_output.stderr.contains("error message"));
    }

    // ==========================================================================
    // Debug Trait Tests
    // ==========================================================================

    #[test]
    fn test_pivot_error_debug() {
        let err = PivotError::Timeout;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Timeout"));
    }

    #[test]
    fn test_pivot_result_debug() {
        let result = PivotResult {
            success: true,
            resources_moved: 3,
            error: None,
        };
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("success: true"));
        assert!(debug_str.contains("resources_moved: 3"));
    }

    #[test]
    fn test_command_output_debug() {
        let output = CommandOutput {
            success: true,
            stdout: "test output".to_string(),
            stderr: String::new(),
        };
        let debug_str = format!("{:?}", output);
        assert!(debug_str.contains("test output"));
    }

    #[test]
    fn test_pivot_result_clone() {
        let result = PivotResult {
            success: true,
            resources_moved: 5,
            error: Some("test".to_string()),
        };
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    #[test]
    fn test_command_output_clone() {
        let output = CommandOutput {
            success: false,
            stdout: "out".to_string(),
            stderr: "err".to_string(),
        };
        let cloned = output.clone();
        assert_eq!(output.success, cloned.success);
        assert_eq!(output.stdout, cloned.stdout);
        assert_eq!(output.stderr, cloned.stderr);
    }
}
