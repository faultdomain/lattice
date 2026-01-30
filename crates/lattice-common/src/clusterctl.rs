//! Shared clusterctl move execution with retry and unpause logic
//!
//! All command executions have timeouts and retry logic to handle transient failures.

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::time::Duration;

use kube::api::{Api, DeleteParams, Patch, PatchParams};
use kube::core::DynamicObject;
use kube::discovery::ApiResource;
use thiserror::Error;
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::kube_utils;

/// Timeout for clusterctl commands
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Default retry configuration
const MAX_ATTEMPTS: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(5);

/// RAII wrapper for temporary directories that ensures cleanup on drop.
/// Only used in tests now.
#[cfg(test)]
struct TempDir {
    path: PathBuf,
}

#[cfg(test)]
impl TempDir {
    /// Create a new temporary directory with the given name prefix.
    fn new(prefix: &str) -> Result<Self, ClusterctlError> {
        let path = std::env::temp_dir().join(format!("{}-{}", prefix, std::process::id()));
        // Clean up any stale directory from previous runs
        if path.exists() {
            if let Err(e) = std::fs::remove_dir_all(&path) {
                eprintln!(
                    "failed to clean stale temp directory {}: {}",
                    path.display(),
                    e
                );
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

#[cfg(test)]
impl Drop for TempDir {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.path) {
            eprintln!(
                "failed to clean up temp directory {}: {}",
                self.path.display(),
                e
            );
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
/// Generic retry wrapper for clusterctl operations that may fail transiently.
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

/// Move CAPI resources directly between clusters using --to-kubeconfig
///
/// This is the preferred method when you have access to both kubeconfigs.
/// Unlike the two-step export/import, this:
/// 1. Moves resources in one command
/// 2. Automatically deletes source resources after successful import
/// 3. Handles pause/unpause correctly
pub async fn move_to_kubeconfig(
    source_kubeconfig: &Path,
    target_kubeconfig: &Path,
    namespace: &str,
    cluster_name: &str,
) -> Result<(), ClusterctlError> {
    let config = RetryConfig {
        operation: "move",
        context_name: cluster_name,
        on_retry: Some(Box::new({
            let kc = source_kubeconfig.to_path_buf();
            let ns = namespace.to_string();
            let cn = cluster_name.to_string();
            move || {
                let kc = kc.clone();
                let ns = ns.clone();
                let cn = cn.clone();
                Box::pin(async move {
                    // Unpause before retry to recover from partial move state
                    if let Err(e) = unpause_capi_cluster(Some(&kc), &ns, &cn).await {
                        warn!(
                            cluster = %cn,
                            error = %e,
                            "failed to unpause CAPI cluster before retry"
                        );
                    }
                })
            }
        })),
        retry_delay: RETRY_DELAY,
    };

    with_retry(config, |_attempt| {
        let source_kc = source_kubeconfig.to_path_buf();
        let target_kc = target_kubeconfig.to_path_buf();
        let namespace = namespace.to_string();
        let cluster_name = cluster_name.to_string();

        async move {
            let mut cmd = Command::new("clusterctl");
            cmd.arg("move")
                .arg("--kubeconfig")
                .arg(&source_kc)
                .arg("--to-kubeconfig")
                .arg(&target_kc)
                .arg("--namespace")
                .arg(&namespace);

            run_command(
                &mut cmd,
                &format!("clusterctl move --to-kubeconfig (cluster={})", cluster_name),
            )
            .await?;

            info!(
                cluster = %cluster_name,
                namespace = %namespace,
                "CAPI move complete (source resources deleted)"
            );

            Ok(())
        }
    })
    .await
}

/// Pause a CAPI cluster (call after export to keep cluster dormant until deletion)
///
/// This is needed because `clusterctl move --to-directory` unpauses the cluster
/// after export. For distributed pivot, we want the parent's CAPI resources to
/// remain paused until the child confirms successful import.
pub async fn pause_capi_cluster(
    kubeconfig: Option<&Path>,
    namespace: &str,
    cluster_name: &str,
) -> Result<(), ClusterctlError> {
    let client = kube_utils::create_client(kubeconfig)
        .await
        .map_err(|e| ClusterctlError::ExecutionFailed(e.to_string()))?;
    let api: Api<DynamicObject> = Api::namespaced_with(client, namespace, &cluster_api_resource());
    let patch = serde_json::json!({"spec": {"paused": true}});

    api.patch(cluster_name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| {
            ClusterctlError::ExecutionFailed(format!(
                "failed to pause cluster {}: {}",
                cluster_name, e
            ))
        })?;

    info!(cluster = %cluster_name, "CAPI cluster paused");
    Ok(())
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
/// 1. Unpause CAPI cluster to allow reconciliation
/// 2. Wait for InfrastructureReady=True
/// 3. Delete the Cluster resource
/// 4. Wait for cluster deletion (infrastructure cleanup)
///
/// # Arguments
/// * `client` - Kubernetes client for the cluster where CAPI is running
/// * `namespace` - CAPI namespace (e.g., "capi-{cluster_name}")
/// * `cluster_name` - Name of the CAPI Cluster resource
/// * `config` - Teardown configuration (timeouts)
/// * `kubeconfig` - Optional kubeconfig path for kubectl/clusterctl commands (None = in-cluster)
pub async fn teardown_cluster(
    client: &kube::Client,
    namespace: &str,
    cluster_name: &str,
    config: &TeardownConfig,
    kubeconfig: Option<&Path>,
) -> Result<(), ClusterctlError> {
    // Step 1: Unpause CAPI cluster to allow reconciliation
    info!(cluster = %cluster_name, "Unpausing CAPI cluster");
    unpause_capi_cluster(kubeconfig, namespace, cluster_name).await?;

    // Step 2: Wait for infrastructure ready
    info!(cluster = %cluster_name, "Waiting for infrastructure ready");
    wait_for_infrastructure_ready(client, namespace, cluster_name, config.ready_timeout).await?;

    // Step 3: Delete the Cluster resource
    info!(cluster = %cluster_name, "Deleting CAPI Cluster resource");
    delete_cluster(client, namespace, cluster_name).await?;

    // Step 4: Wait for cluster deletion (infrastructure cleanup)
    info!(cluster = %cluster_name, "Waiting for infrastructure cleanup");
    wait_for_cluster_deletion(client, namespace, cluster_name, config.deletion_timeout).await?;

    info!(cluster = %cluster_name, "Cluster teardown complete");
    Ok(())
}

/// Annotation added before deletion (matches clusterctl behavior)
const DELETE_FOR_MOVE_ANNOTATION: &str = "clusterctl.cluster.x-k8s.io/delete-for-move";

/// Resource identity extracted from manifests
#[derive(Debug, Clone)]
struct ResourceIdentity {
    api_version: String,
    kind: String,
    namespace: String,
    name: String,
}

/// Delete order for CAPI resources (children before parents)
/// Lower number = delete first
fn deletion_priority(kind: &str) -> u32 {
    match kind {
        // Delete leaf resources first
        "Machine" => 0,
        "MachineSet" => 1,
        "MachineDeployment" => 2,
        "KubeadmConfig" | "KubeadmConfigTemplate" => 3,
        "MachineHealthCheck" => 4,
        // Infrastructure resources
        "DockerMachine" | "DockerMachineTemplate" => 5,
        "AWSMachine" | "AWSMachineTemplate" => 5,
        "AzureMachine" | "AzureMachineTemplate" => 5,
        "GCPMachine" | "GCPMachineTemplate" => 5,
        "VSphereVM" | "VSphereMachine" | "VSphereMachineTemplate" => 5,
        // Control plane
        "KubeadmControlPlane" | "KubeadmControlPlaneTemplate" => 6,
        // Infrastructure cluster resources
        "DockerCluster" | "DockerClusterTemplate" => 7,
        "AWSCluster" | "AWSClusterTemplate" => 7,
        "AzureCluster" | "AzureClusterTemplate" => 7,
        "GCPCluster" | "GCPClusterTemplate" => 7,
        "VSphereCluster" | "VSphereClusterTemplate" => 7,
        // Cluster is deleted last
        "Cluster" => 10,
        "ClusterClass" => 11,
        // Secrets and ConfigMaps somewhere in between
        "Secret" | "ConfigMap" => 8,
        // Unknown resources - delete before Cluster but after known children
        _ => 9,
    }
}

/// Parse manifests to extract resource identities
fn parse_manifest_identities(manifests: &[Vec<u8>]) -> Vec<ResourceIdentity> {
    let mut identities = Vec::new();

    for manifest in manifests {
        let manifest_str = String::from_utf8_lossy(manifest);

        // Parse as YAML - each manifest file may contain multiple documents
        let docs = match crate::yaml::parse_yaml_multi(&manifest_str) {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "Failed to parse manifest YAML");
                continue;
            }
        };

        for doc in docs {
            let api_version = doc.get("apiVersion").and_then(|v| v.as_str());
            let kind = doc.get("kind").and_then(|v| v.as_str());
            let metadata = doc.get("metadata");

            if let (Some(api_version), Some(kind), Some(metadata)) = (api_version, kind, metadata) {
                let name = metadata
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let namespace = metadata
                    .get("namespace")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();

                if !name.is_empty() {
                    identities.push(ResourceIdentity {
                        api_version: api_version.to_string(),
                        kind: kind.to_string(),
                        namespace: namespace.to_string(),
                        name: name.to_string(),
                    });
                }
            }
        }
    }

    identities
}

/// Build ApiResource from apiVersion and kind
fn api_resource_from_identity(identity: &ResourceIdentity) -> ApiResource {
    let (group, version) = match identity.api_version.split_once('/') {
        Some((g, v)) => (g.to_string(), v.to_string()),
        None => (String::new(), identity.api_version.clone()), // core API group
    };

    // Pluralize kind (simple heuristic - works for CAPI resources)
    let plural = pluralize_kind(&identity.kind);

    ApiResource {
        group,
        version: version.clone(),
        kind: identity.kind.clone(),
        api_version: identity.api_version.clone(),
        plural,
    }
}

/// Simple pluralization for Kubernetes kinds
fn pluralize_kind(kind: &str) -> String {
    let lower = kind.to_lowercase();
    if lower.ends_with("ss") {
        // e.g., "ClusterClass" -> "clusterclasses"
        format!("{}es", lower)
    } else if lower.ends_with('s') {
        lower
    } else {
        format!("{}s", lower)
    }
}

/// Delete a single resource with finalizer removal (force delete)
///
/// Follows clusterctl's approach:
/// 1. Add delete-for-move annotation
/// 2. Remove finalizers to prevent infrastructure deletion
/// 3. Delete the resource
async fn delete_resource_for_move(
    client: &kube::Client,
    identity: &ResourceIdentity,
) -> Result<(), ClusterctlError> {
    let api_resource = api_resource_from_identity(identity);
    let api: Api<DynamicObject> = if identity.namespace.is_empty() {
        Api::all_with(client.clone(), &api_resource)
    } else {
        Api::namespaced_with(client.clone(), &identity.namespace, &api_resource)
    };

    // Check if resource exists
    let obj = match api.get(&identity.name).await {
        Ok(o) => o,
        Err(kube::Error::Api(e)) if e.code == 404 => {
            debug!(
                kind = %identity.kind,
                name = %identity.name,
                "Resource already deleted"
            );
            return Ok(());
        }
        Err(e) => {
            return Err(ClusterctlError::ExecutionFailed(format!(
                "failed to get {} {}: {}",
                identity.kind, identity.name, e
            )));
        }
    };

    // Step 1: Add delete-for-move annotation
    let annotation_patch = serde_json::json!({
        "metadata": {
            "annotations": {
                DELETE_FOR_MOVE_ANNOTATION: ""
            }
        }
    });
    if let Err(e) = api
        .patch(
            &identity.name,
            &PatchParams::default(),
            &Patch::Merge(&annotation_patch),
        )
        .await
    {
        warn!(
            kind = %identity.kind,
            name = %identity.name,
            error = %e,
            "Failed to add delete-for-move annotation"
        );
    }

    // Step 2: Remove finalizers to prevent CAPI from deleting infrastructure
    // (The child cluster now owns the infrastructure)
    if !obj
        .metadata
        .finalizers
        .as_ref()
        .is_none_or(|f| f.is_empty())
    {
        let finalizer_patch = serde_json::json!({
            "metadata": {
                "finalizers": null
            }
        });
        if let Err(e) = api
            .patch(
                &identity.name,
                &PatchParams::default(),
                &Patch::Merge(&finalizer_patch),
            )
            .await
        {
            warn!(
                kind = %identity.kind,
                name = %identity.name,
                error = %e,
                "Failed to remove finalizers"
            );
        }
    }

    // Step 3: Delete the resource
    match api.delete(&identity.name, &DeleteParams::default()).await {
        Ok(_) => {
            debug!(
                kind = %identity.kind,
                name = %identity.name,
                "Resource deleted"
            );
            Ok(())
        }
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()), // Already gone
        Err(e) => Err(ClusterctlError::ExecutionFailed(format!(
            "failed to delete {} {}: {}",
            identity.kind, identity.name, e
        ))),
    }
}

/// Delete CAPI resources from source cluster after successful pivot
///
/// This is called after the child cluster confirms successful import of CAPI resources.
/// We delete the source resources with finalizer removal to prevent CAPI from
/// attempting to delete the infrastructure (which is now managed by the child).
///
/// Resources are deleted in reverse dependency order: children before parents.
pub async fn delete_pivoted_capi_resources(
    client: &kube::Client,
    manifests: &[Vec<u8>],
) -> Result<usize, ClusterctlError> {
    // Parse manifests to get resource identities
    let mut identities = parse_manifest_identities(manifests);

    if identities.is_empty() {
        return Ok(0);
    }

    // Sort by deletion priority (children before parents)
    identities.sort_by_key(|id| deletion_priority(&id.kind));

    // Group by priority for logging
    let mut by_kind: HashMap<String, usize> = HashMap::new();
    for id in &identities {
        *by_kind.entry(id.kind.clone()).or_default() += 1;
    }
    info!(
        resources = ?by_kind,
        total = identities.len(),
        "Deleting pivoted CAPI resources from source cluster"
    );

    // Delete each resource
    let mut deleted = 0;
    for identity in &identities {
        if let Err(e) = delete_resource_for_move(client, identity).await {
            warn!(
                kind = %identity.kind,
                name = %identity.name,
                error = %e,
                "Failed to delete resource, continuing with remaining"
            );
        } else {
            deleted += 1;
        }
    }

    info!(
        deleted,
        total = identities.len(),
        "CAPI resource deletion complete"
    );
    Ok(deleted)
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

    // ==========================================================================
    // CAPI Resource Deletion Tests (Pure Functions)
    // ==========================================================================

    #[test]
    fn test_deletion_priority_children_before_parents() {
        // Children should have lower priority (deleted first)
        assert!(deletion_priority("Machine") < deletion_priority("MachineSet"));
        assert!(deletion_priority("MachineSet") < deletion_priority("MachineDeployment"));
        assert!(deletion_priority("MachineDeployment") < deletion_priority("KubeadmControlPlane"));
        assert!(deletion_priority("KubeadmControlPlane") < deletion_priority("DockerCluster"));
        assert!(deletion_priority("DockerCluster") < deletion_priority("Cluster"));
        assert!(deletion_priority("Cluster") < deletion_priority("ClusterClass"));
    }

    #[test]
    fn test_deletion_priority_infrastructure_resources() {
        // Infrastructure machine resources have same priority
        assert_eq!(
            deletion_priority("DockerMachine"),
            deletion_priority("AWSMachine")
        );
        assert_eq!(
            deletion_priority("AWSMachine"),
            deletion_priority("GCPMachine")
        );

        // Infrastructure cluster resources have same priority
        assert_eq!(
            deletion_priority("DockerCluster"),
            deletion_priority("AWSCluster")
        );
    }

    #[test]
    fn test_deletion_priority_unknown_resources() {
        // Unknown resources should be deleted after known children but before Cluster
        let unknown_priority = deletion_priority("SomeUnknownResource");
        assert!(unknown_priority < deletion_priority("Cluster"));
        assert!(unknown_priority > deletion_priority("Secret"));
    }

    #[test]
    fn test_pluralize_kind_standard() {
        assert_eq!(pluralize_kind("Cluster"), "clusters");
        assert_eq!(pluralize_kind("Machine"), "machines");
        assert_eq!(pluralize_kind("MachineDeployment"), "machinedeployments");
    }

    #[test]
    fn test_pluralize_kind_ss_suffix() {
        // Kinds ending in "ss" should get "es" suffix
        assert_eq!(pluralize_kind("ClusterClass"), "clusterclasses");
    }

    #[test]
    fn test_parse_manifest_identities_single_doc() {
        let manifest = br#"
apiVersion: cluster.x-k8s.io/v1beta1
kind: Cluster
metadata:
  name: test-cluster
  namespace: capi-test
spec:
  controlPlaneRef:
    kind: KubeadmControlPlane
"#
        .to_vec();

        let identities = parse_manifest_identities(&[manifest]);

        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].api_version, "cluster.x-k8s.io/v1beta1");
        assert_eq!(identities[0].kind, "Cluster");
        assert_eq!(identities[0].name, "test-cluster");
        assert_eq!(identities[0].namespace, "capi-test");
    }

    #[test]
    fn test_parse_manifest_identities_multi_doc() {
        let manifest = br#"
apiVersion: cluster.x-k8s.io/v1beta1
kind: Cluster
metadata:
  name: test-cluster
  namespace: capi-test
---
apiVersion: controlplane.cluster.x-k8s.io/v1beta1
kind: KubeadmControlPlane
metadata:
  name: test-control-plane
  namespace: capi-test
"#
        .to_vec();

        let identities = parse_manifest_identities(&[manifest]);

        assert_eq!(identities.len(), 2);
        assert_eq!(identities[0].kind, "Cluster");
        assert_eq!(identities[1].kind, "KubeadmControlPlane");
    }

    #[test]
    fn test_parse_manifest_identities_skips_invalid() {
        let valid = br#"
apiVersion: cluster.x-k8s.io/v1beta1
kind: Cluster
metadata:
  name: test-cluster
  namespace: capi-test
"#
        .to_vec();

        let invalid = b"not: valid: yaml: ::: ".to_vec();

        let identities = parse_manifest_identities(&[invalid, valid]);

        // Should parse the valid manifest and skip the invalid one
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].kind, "Cluster");
    }

    #[test]
    fn test_parse_manifest_identities_skips_nameless() {
        let manifest = br#"
apiVersion: cluster.x-k8s.io/v1beta1
kind: Cluster
metadata:
  namespace: capi-test
"#
        .to_vec();

        let identities = parse_manifest_identities(&[manifest]);

        // Should skip resources without names
        assert!(identities.is_empty());
    }

    #[test]
    fn test_api_resource_from_identity_with_group() {
        let identity = ResourceIdentity {
            api_version: "cluster.x-k8s.io/v1beta1".to_string(),
            kind: "Cluster".to_string(),
            namespace: "default".to_string(),
            name: "test".to_string(),
        };

        let api_resource = api_resource_from_identity(&identity);

        assert_eq!(api_resource.group, "cluster.x-k8s.io");
        assert_eq!(api_resource.version, "v1beta1");
        assert_eq!(api_resource.kind, "Cluster");
        assert_eq!(api_resource.plural, "clusters");
    }

    #[test]
    fn test_api_resource_from_identity_core_api() {
        let identity = ResourceIdentity {
            api_version: "v1".to_string(),
            kind: "Secret".to_string(),
            namespace: "default".to_string(),
            name: "test".to_string(),
        };

        let api_resource = api_resource_from_identity(&identity);

        assert_eq!(api_resource.group, ""); // Core API has empty group
        assert_eq!(api_resource.version, "v1");
        assert_eq!(api_resource.kind, "Secret");
        assert_eq!(api_resource.plural, "secrets");
    }

    #[test]
    fn test_resources_sorted_by_deletion_priority() {
        let manifests = vec![
            br#"
apiVersion: cluster.x-k8s.io/v1beta1
kind: Cluster
metadata:
  name: test-cluster
  namespace: capi-test
"#
            .to_vec(),
            br#"
apiVersion: cluster.x-k8s.io/v1beta1
kind: Machine
metadata:
  name: test-machine
  namespace: capi-test
"#
            .to_vec(),
            br#"
apiVersion: cluster.x-k8s.io/v1beta1
kind: MachineDeployment
metadata:
  name: test-md
  namespace: capi-test
"#
            .to_vec(),
        ];

        let mut identities = parse_manifest_identities(&manifests);
        identities.sort_by_key(|id| deletion_priority(&id.kind));

        // Should be sorted: Machine -> MachineDeployment -> Cluster
        assert_eq!(identities[0].kind, "Machine");
        assert_eq!(identities[1].kind, "MachineDeployment");
        assert_eq!(identities[2].kind, "Cluster");
    }
}
