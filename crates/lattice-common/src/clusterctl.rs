//! Shared clusterctl move execution with retry and unpause logic
//!
//! All command executions have timeouts and retry logic to handle transient failures.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kube::api::{Api, Patch, PatchParams};
use kube::core::DynamicObject;
use kube::discovery::ApiResource;
use thiserror::Error;
use tokio::process::Command;
use tracing::{info, warn};

use crate::kube_utils;

/// Timeout for clusterctl commands
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Default retry configuration
const MAX_ATTEMPTS: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(5);

/// RAII wrapper for temporary directories that ensures cleanup on drop.
///
/// This wrapper logs cleanup failures instead of silently ignoring them.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a new temporary directory with the given name prefix.
    fn new(prefix: &str) -> Result<Self, ClusterctlError> {
        let path = std::env::temp_dir().join(format!("{}-{}", prefix, std::process::id()));
        // Clean up any stale directory from previous runs
        if path.exists() {
            if let Err(e) = std::fs::remove_dir_all(&path) {
                warn!(path = %path.display(), error = %e, "failed to clean stale temp directory");
            }
        }
        std::fs::create_dir_all(&path).map_err(|e| {
            ClusterctlError::ExecutionFailed(format!(
                "failed to create temp directory {}: {}",
                path.display(),
                e
            ))
        })?;
        Ok(Self { path })
    }

    /// Get the path to the temporary directory.
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.path) {
            warn!(path = %self.path.display(), error = %e, "failed to clean up temp directory");
        }
    }
}

/// Type alias for retry callback functions.
type RetryCallback<'a> =
    Box<dyn Fn() -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync + 'a>;

/// Configuration for retry operations.
struct RetryConfig<'a> {
    /// Operation name for logging (e.g., "export", "import")
    operation: &'a str,
    /// Context identifier for logging (e.g., cluster name or namespace)
    context_name: &'a str,
    /// Optional callback to run between retry attempts
    on_retry: Option<RetryCallback<'a>>,
    /// Delay between retries (defaults to RETRY_DELAY)
    retry_delay: Duration,
}

/// Execute an operation with retry logic.
///
/// This is a generic retry wrapper that eliminates duplication between
/// export_for_pivot and import_from_manifests.
async fn with_retry<T, F, Fut>(
    config: RetryConfig<'_>,
    mut operation_fn: F,
) -> Result<T, ClusterctlError>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let mut last_error = String::new();

    for attempt in 1..=MAX_ATTEMPTS {
        match operation_fn(attempt).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = e;
                if attempt < MAX_ATTEMPTS {
                    warn!(
                        operation = %config.operation,
                        context = %config.context_name,
                        attempt,
                        error = %last_error,
                        "{} failed, retrying",
                        config.operation
                    );
                    if let Some(ref on_retry) = config.on_retry {
                        on_retry().await;
                    }
                    tokio::time::sleep(config.retry_delay).await;
                }
            }
        }
    }

    Err(ClusterctlError::RetriesExhausted {
        attempts: MAX_ATTEMPTS,
        last_error,
    })
}

/// CAPI Cluster resource definition
fn cluster_api_resource() -> ApiResource {
    ApiResource {
        group: "cluster.x-k8s.io".into(),
        version: "v1beta1".into(),
        kind: "Cluster".into(),
        api_version: "cluster.x-k8s.io/v1beta1".into(),
        plural: "clusters".into(),
    }
}

/// Errors from clusterctl move operations
#[derive(Debug, Error)]
pub enum ClusterctlError {
    /// Command execution failed (filesystem, spawn, etc)
    #[error("failed: {0}")]
    ExecutionFailed(String),

    /// All retry attempts exhausted
    #[error("failed after {attempts} attempts: {last_error}")]
    RetriesExhausted {
        /// Number of attempts made
        attempts: u32,
        /// Last error message
        last_error: String,
    },
}

/// Run a command with timeout
async fn run_command(cmd: &mut Command, description: &str) -> Result<(), String> {
    info!("{}", description);
    let output = tokio::time::timeout(COMMAND_TIMEOUT, cmd.output())
        .await
        .map_err(|_| {
            warn!("{} timed out after {:?}", description, COMMAND_TIMEOUT);
            format!("timed out after {:?}", COMMAND_TIMEOUT)
        })?
        .map_err(|e| {
            warn!("{} spawn failed: {}", description, e);
            format!("failed to execute: {}", e)
        })?;

    if output.status.success() {
        info!("{} succeeded", description);
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&output.stderr).to_string();
        warn!("{} failed: {}", description, err);
        Err(err)
    }
}

/// Export CAPI resources for pivot/unpivot
pub async fn export_for_pivot(
    kubeconfig: Option<&Path>,
    namespace: &str,
    cluster_name: &str,
) -> Result<Vec<Vec<u8>>, ClusterctlError> {
    let temp_dir = TempDir::new(&format!("lattice-export-{}", cluster_name))?;

    // Clone values needed for the retry callback
    let kubeconfig_path = kubeconfig.map(|p| p.to_path_buf());
    let ns = namespace.to_string();
    let cn = cluster_name.to_string();

    let config = RetryConfig {
        operation: "export",
        context_name: cluster_name,
        on_retry: Some(Box::new(move || {
            let kc = kubeconfig_path.clone();
            let ns = ns.clone();
            let cn = cn.clone();
            Box::pin(async move {
                // Unpause CAPI cluster before retry to recover from partial move state
                if let Err(e) = unpause_capi_cluster(kc.as_deref(), &ns, &cn).await {
                    warn!(
                        cluster = %cn,
                        error = %e,
                        "failed to unpause CAPI cluster before retry"
                    );
                }
            })
        })),
        retry_delay: RETRY_DELAY,
    };

    with_retry(config, |_attempt| {
        let export_path = temp_dir.path().to_path_buf();
        let kubeconfig = kubeconfig.map(|p| p.to_path_buf());
        let namespace = namespace.to_string();
        let cluster_name = cluster_name.to_string();

        async move {
            // Reset directory for each attempt
            if let Err(e) = std::fs::remove_dir_all(&export_path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!(path = %export_path.display(), error = %e, "failed to reset export directory");
                }
            }
            std::fs::create_dir_all(&export_path)
                .map_err(|e| format!("failed to create export dir: {}", e))?;

            let mut cmd = Command::new("clusterctl");
            cmd.arg("move")
                .arg("--to-directory")
                .arg(&export_path)
                .arg("--namespace")
                .arg(&namespace);

            if let Some(kc) = kubeconfig.as_ref() {
                cmd.arg("--kubeconfig").arg(kc);
            }

            run_command(
                &mut cmd,
                &format!("clusterctl move --to-directory (cluster={})", cluster_name),
            )
            .await?;

            let manifests = read_yaml_files(&export_path)
                .map_err(|e| format!("failed to read exported manifests: {}", e))?;

            info!(
                operation = "export",
                cluster = %cluster_name,
                manifest_count = manifests.len(),
                "CAPI export complete"
            );

            Ok(manifests)
        }
    })
    .await
    // TempDir is dropped here, ensuring cleanup
}

/// Import CAPI resources from manifest bytes (used during unpivot)
pub async fn import_from_manifests(
    kubeconfig: Option<&Path>,
    namespace: &str,
    manifests: &[Vec<u8>],
) -> Result<(), ClusterctlError> {
    let temp_dir = TempDir::new(&format!("lattice-import-{}", namespace))?;

    let config = RetryConfig {
        operation: "import",
        context_name: namespace,
        on_retry: None, // No special action needed between import retries
        retry_delay: RETRY_DELAY,
    };

    with_retry(config, |_attempt| {
        let import_path = temp_dir.path().to_path_buf();
        let kubeconfig = kubeconfig.map(|p| p.to_path_buf());
        let namespace = namespace.to_string();
        let manifests = manifests.to_vec();

        async move {
            // Reset directory for each attempt
            if let Err(e) = std::fs::remove_dir_all(&import_path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!(path = %import_path.display(), error = %e, "failed to reset import directory");
                }
            }
            std::fs::create_dir_all(&import_path)
                .map_err(|e| format!("failed to create import dir: {}", e))?;

            // Write manifests to temporary files
            for (i, manifest) in manifests.iter().enumerate() {
                std::fs::write(import_path.join(format!("{}.yaml", i)), manifest)
                    .map_err(|e| format!("failed to write manifest {}: {}", i, e))?;
            }

            let mut cmd = Command::new("clusterctl");
            cmd.arg("move")
                .arg("--from-directory")
                .arg(&import_path)
                .arg("--namespace")
                .arg(&namespace);

            if let Some(kc) = kubeconfig.as_ref() {
                cmd.arg("--to-kubeconfig").arg(kc);
            }

            run_command(
                &mut cmd,
                &format!("clusterctl move --from-directory (namespace={})", namespace),
            )
            .await?;

            info!(
                operation = "import",
                namespace = %namespace,
                manifest_count = manifests.len(),
                "CAPI import complete"
            );

            Ok(())
        }
    })
    .await
    // TempDir is dropped here, ensuring cleanup
}

/// Unpause a CAPI cluster (call before retrying after failed move)
pub async fn unpause_capi_cluster(
    kubeconfig: Option<&Path>,
    namespace: &str,
    cluster_name: &str,
) -> Result<(), ClusterctlError> {
    let client = kube_utils::create_client(kubeconfig)
        .await
        .map_err(|e| ClusterctlError::ExecutionFailed(e.to_string()))?;
    let api: Api<DynamicObject> = Api::namespaced_with(client, namespace, &cluster_api_resource());
    let patch = serde_json::json!({"spec": {"paused": false}});

    match api
        .patch(cluster_name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
    {
        Ok(_) => info!(cluster = %cluster_name, "CAPI cluster unpaused"),
        Err(e) => warn!(cluster = %cluster_name, error = %e, "unpause failed (may not exist)"),
    }

    Ok(())
}

/// Check if a CAPI cluster exists and is ready for pivot
///
/// Returns true if the Cluster resource exists and has Ready=True condition.
pub async fn is_capi_cluster_ready(
    kubeconfig: Option<&Path>,
    namespace: &str,
    cluster_name: &str,
) -> Result<bool, ClusterctlError> {
    let client = kube_utils::create_client(kubeconfig)
        .await
        .map_err(|e| ClusterctlError::ExecutionFailed(e.to_string()))?;
    is_cluster_ready(&client, namespace, cluster_name).await
}

/// Check if cluster has InfrastructureReady=True condition
async fn is_cluster_ready(
    client: &kube::Client,
    namespace: &str,
    cluster_name: &str,
) -> Result<bool, ClusterctlError> {
    let api: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), namespace, &cluster_api_resource());

    match api.get(cluster_name).await {
        Ok(cluster) => {
            let is_ready = cluster
                .data
                .get("status")
                .and_then(|s| s.get("conditions"))
                .and_then(|c| c.as_array())
                .map(|conditions| {
                    conditions.iter().any(|cond| {
                        cond.get("type").and_then(|t| t.as_str()) == Some("InfrastructureReady")
                            && cond.get("status").and_then(|s| s.as_str()) == Some("True")
                    })
                })
                .unwrap_or(false);
            Ok(is_ready)
        }
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(false),
        Err(e) => Err(ClusterctlError::ExecutionFailed(format!(
            "failed to get cluster: {}",
            e
        ))),
    }
}

/// Wait for CAPI cluster to have InfrastructureReady=True
///
/// Used after importing CAPI resources to ensure controllers have reconciled
/// before triggering deletion.
pub async fn wait_for_infrastructure_ready(
    client: &kube::Client,
    namespace: &str,
    cluster_name: &str,
    timeout: std::time::Duration,
) -> Result<(), ClusterctlError> {
    use std::time::Instant;

    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(ClusterctlError::ExecutionFailed(
                "timeout waiting for cluster infrastructure to be ready".to_string(),
            ));
        }

        match is_cluster_ready(client, namespace, cluster_name).await {
            Ok(true) => {
                info!(cluster = %cluster_name, "Cluster infrastructure ready");
                return Ok(());
            }
            Ok(false) => {
                info!(cluster = %cluster_name, "Waiting for infrastructure ready...");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            Err(e) => {
                warn!(error = %e, "Error checking cluster status");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}

/// Delete a CAPI Cluster resource
pub async fn delete_cluster(
    client: &kube::Client,
    namespace: &str,
    cluster_name: &str,
) -> Result<(), ClusterctlError> {
    use kube::api::DeleteParams;

    let api: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), namespace, &cluster_api_resource());

    api.delete(cluster_name, &DeleteParams::default())
        .await
        .map_err(|e| {
            ClusterctlError::ExecutionFailed(format!("failed to delete cluster: {}", e))
        })?;

    info!(cluster = %cluster_name, "Cluster deletion initiated");
    Ok(())
}

/// Wait for CAPI Cluster to be fully deleted
///
/// Waits for the Cluster resource to return 404, indicating all
/// infrastructure (VPCs, instances, etc.) has been cleaned up.
pub async fn wait_for_cluster_deletion(
    client: &kube::Client,
    namespace: &str,
    cluster_name: &str,
    timeout: std::time::Duration,
) -> Result<(), ClusterctlError> {
    use std::time::Instant;

    let api: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), namespace, &cluster_api_resource());
    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(ClusterctlError::ExecutionFailed(
                "timeout waiting for cluster deletion".to_string(),
            ));
        }

        match api.get(cluster_name).await {
            Ok(_) => {
                info!(cluster = %cluster_name, "Waiting for cluster deletion...");
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {
                info!(cluster = %cluster_name, "Cluster deleted");
                return Ok(());
            }
            Err(e) => {
                warn!(error = %e, "Error checking cluster status");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}

/// Configuration for cluster teardown
#[derive(Debug, Clone)]
pub struct TeardownConfig {
    /// Timeout for waiting for infrastructure ready
    pub ready_timeout: Duration,
    /// Timeout for waiting for deletion to complete
    pub deletion_timeout: Duration,
}

impl Default for TeardownConfig {
    fn default() -> Self {
        Self {
            ready_timeout: Duration::from_secs(300),    // 5 minutes
            deletion_timeout: Duration::from_secs(600), // 10 minutes
        }
    }
}

/// Teardown a CAPI-managed cluster
///
/// This is the shared logic for both `lattice uninstall` (CLI) and unpivot (controller).
/// The flow is:
/// 1. Import manifests (if provided) via clusterctl move --from-directory
/// 2. Unpause CAPI cluster to allow reconciliation
/// 3. Wait for InfrastructureReady=True
/// 4. Delete the Cluster resource
/// 5. Wait for cluster deletion (infrastructure cleanup)
///
/// # Arguments
/// * `client` - Kubernetes client for the cluster where CAPI is running
/// * `namespace` - CAPI namespace (e.g., "capi-{cluster_name}")
/// * `cluster_name` - Name of the CAPI Cluster resource
/// * `manifests` - Optional CAPI manifests to import before teardown
/// * `config` - Teardown configuration (timeouts)
/// * `kubeconfig` - Optional kubeconfig path for clusterctl commands (None = in-cluster)
pub async fn teardown_cluster(
    client: &kube::Client,
    namespace: &str,
    cluster_name: &str,
    manifests: Option<&[Vec<u8>]>,
    config: &TeardownConfig,
    kubeconfig: Option<&Path>,
) -> Result<(), ClusterctlError> {
    // Step 1: Import manifests if provided
    if let Some(manifests) = manifests {
        if !manifests.is_empty() {
            info!(
                cluster = %cluster_name,
                manifest_count = manifests.len(),
                "Importing CAPI manifests"
            );
            import_from_manifests(kubeconfig, namespace, manifests).await?;
        }
    }

    // Step 2: Unpause CAPI cluster to allow reconciliation
    info!(cluster = %cluster_name, "Unpausing CAPI cluster");
    unpause_capi_cluster(kubeconfig, namespace, cluster_name).await?;

    // Step 3: Wait for infrastructure ready
    info!(cluster = %cluster_name, "Waiting for infrastructure ready");
    wait_for_infrastructure_ready(client, namespace, cluster_name, config.ready_timeout).await?;

    // Step 4: Delete the Cluster resource
    info!(cluster = %cluster_name, "Deleting CAPI Cluster resource");
    delete_cluster(client, namespace, cluster_name).await?;

    // Step 5: Wait for cluster deletion (infrastructure cleanup)
    info!(cluster = %cluster_name, "Waiting for infrastructure cleanup");
    wait_for_cluster_deletion(client, namespace, cluster_name, config.deletion_timeout).await?;

    info!(cluster = %cluster_name, "Cluster teardown complete");
    Ok(())
}

fn read_yaml_files(dir: &Path) -> Result<Vec<Vec<u8>>, ClusterctlError> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| ClusterctlError::ExecutionFailed(format!("failed to read dir: {}", e)))?;

    let mut manifests = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e == "yaml").unwrap_or(false) {
            let content = std::fs::read(&path).map_err(|e| {
                ClusterctlError::ExecutionFailed(format!(
                    "failed to read {}: {}",
                    path.display(),
                    e
                ))
            })?;
            manifests.push(content);
        }
    }
    Ok(manifests)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_error_display() {
        let err = ClusterctlError::RetriesExhausted {
            attempts: 3,
            last_error: "timeout".to_string(),
        };
        assert!(err.to_string().contains("3 attempts"));
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn test_temp_dir_creates_directory() {
        let temp_dir = TempDir::new("test-create").expect("should create temp dir");
        assert!(temp_dir.path().exists());
        assert!(temp_dir.path().is_dir());
    }

    #[test]
    fn test_temp_dir_cleanup_on_drop() {
        let path = {
            let temp_dir = TempDir::new("test-cleanup").expect("should create temp dir");
            let path = temp_dir.path().to_path_buf();
            assert!(path.exists());
            path
        };
        // After drop, directory should be cleaned up
        assert!(!path.exists());
    }

    #[test]
    fn test_temp_dir_cleans_stale_directory() {
        // Create a directory that would conflict
        let stale_path = std::env::temp_dir().join(format!("test-stale-{}", std::process::id()));
        std::fs::create_dir_all(&stale_path).expect("should create stale dir");
        std::fs::write(stale_path.join("old.txt"), "old content").expect("should write old file");

        // Creating TempDir with same prefix should clean the stale directory
        let temp_dir = TempDir::new("test-stale").expect("should create temp dir");
        assert!(temp_dir.path().exists());
        assert!(!temp_dir.path().join("old.txt").exists()); // Old file should be gone
    }

    /// Fast retry delay for tests
    const TEST_RETRY_DELAY: Duration = Duration::from_millis(1);

    #[tokio::test]
    async fn test_with_retry_succeeds_first_attempt() {
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let config = RetryConfig {
            operation: "test",
            context_name: "test-context",
            on_retry: None,
            retry_delay: TEST_RETRY_DELAY,
        };

        let result: Result<String, ClusterctlError> = with_retry(config, |_| {
            let count = attempt_count_clone.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok("success".to_string())
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.expect("retry should succeed"), "success");
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_with_retry_succeeds_after_failures() {
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let config = RetryConfig {
            operation: "test",
            context_name: "test-context",
            on_retry: None,
            retry_delay: TEST_RETRY_DELAY,
        };

        let result: Result<String, ClusterctlError> = with_retry(config, |attempt| {
            let count = attempt_count_clone.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                if attempt < 3 {
                    Err("transient error".to_string())
                } else {
                    Ok("success".to_string())
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(
            result.expect("retry should succeed after failures"),
            "success"
        );
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_with_retry_exhausts_attempts() {
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let config = RetryConfig {
            operation: "test",
            context_name: "test-context",
            on_retry: None,
            retry_delay: TEST_RETRY_DELAY,
        };

        let result: Result<String, ClusterctlError> = with_retry(config, |_| {
            let count = attempt_count_clone.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                Err("persistent error".to_string())
            }
        })
        .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ClusterctlError::RetriesExhausted {
                attempts,
                last_error,
            } => {
                assert_eq!(attempts, MAX_ATTEMPTS);
                assert_eq!(last_error, "persistent error");
            }
            _ => panic!("expected RetriesExhausted error"),
        }
        assert_eq!(attempt_count.load(Ordering::SeqCst), MAX_ATTEMPTS);
    }

    #[tokio::test]
    async fn test_with_retry_calls_on_retry_callback() {
        let retry_count = Arc::new(AtomicU32::new(0));
        let retry_count_clone = retry_count.clone();

        let config = RetryConfig {
            operation: "test",
            context_name: "test-context",
            on_retry: Some(Box::new(move || {
                let count = retry_count_clone.clone();
                Box::pin(async move {
                    count.fetch_add(1, Ordering::SeqCst);
                })
            })),
            retry_delay: TEST_RETRY_DELAY,
        };

        let _: Result<String, ClusterctlError> = with_retry(config, |attempt| async move {
            if attempt < 3 {
                Err("transient error".to_string())
            } else {
                Ok("success".to_string())
            }
        })
        .await;

        // on_retry should be called twice (after attempt 1 and 2, not after success on 3)
        assert_eq!(retry_count.load(Ordering::SeqCst), 2);
    }
}
