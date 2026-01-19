//! Shared clusterctl move execution with retry and unpause logic
//!
//! All command executions have timeouts and retry logic to handle transient failures.

use std::path::Path;
use std::time::Duration;

use kube::api::{Api, Patch, PatchParams};
use kube::core::DynamicObject;
use kube::discovery::ApiResource;
use thiserror::Error;
use tokio::process::Command;
use tracing::{info, warn};

/// Timeout for clusterctl commands
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Default retry configuration
const MAX_ATTEMPTS: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(5);

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

/// Create a kube client from optional kubeconfig path
async fn create_client(kubeconfig: Option<&Path>) -> Result<kube::Client, ClusterctlError> {
    match kubeconfig {
        Some(path) => {
            let kubeconfig = kube::config::Kubeconfig::read_from(path)
                .map_err(|e| ClusterctlError::ExecutionFailed(format!("failed to read kubeconfig: {}", e)))?;
            let config = kube::Config::from_custom_kubeconfig(kubeconfig, &Default::default())
                .await
                .map_err(|e| ClusterctlError::ExecutionFailed(format!("failed to load kubeconfig: {}", e)))?;
            kube::Client::try_from(config)
                .map_err(|e| ClusterctlError::ExecutionFailed(format!("failed to create client: {}", e)))
        }
        None => kube::Client::try_default()
            .await
            .map_err(|e| ClusterctlError::ExecutionFailed(format!("failed to create client: {}", e))),
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
    let export_path = std::env::temp_dir().join(format!(
        "lattice-export-{}-{}",
        cluster_name,
        std::process::id()
    ));

    let mut last_error = String::new();

    for attempt in 1..=MAX_ATTEMPTS {
        let _ = std::fs::remove_dir_all(&export_path);
        std::fs::create_dir_all(&export_path).map_err(|e| {
            ClusterctlError::ExecutionFailed(format!("failed to create export dir: {}", e))
        })?;

        let mut cmd = Command::new("clusterctl");
        cmd.arg("move")
            .arg("--to-directory")
            .arg(&export_path)
            .arg("--namespace")
            .arg(namespace);

        if let Some(kc) = kubeconfig {
            cmd.arg("--kubeconfig").arg(kc);
        }

        match run_command(&mut cmd, "clusterctl move --to-directory").await {
            Ok(()) => {
                let manifests = read_yaml_files(&export_path)?;
                let _ = std::fs::remove_dir_all(&export_path);
                info!(cluster = %cluster_name, count = manifests.len(), "CAPI export complete");
                return Ok(manifests);
            }
            Err(e) => {
                last_error = e;
                if attempt < MAX_ATTEMPTS {
                    warn!(cluster = %cluster_name, attempt, error = %last_error, "export failed, retrying");
                    let _ = unpause_capi_cluster(kubeconfig, namespace, cluster_name).await;
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
        }
    }

    let _ = std::fs::remove_dir_all(&export_path);
    Err(ClusterctlError::RetriesExhausted {
        attempts: MAX_ATTEMPTS,
        last_error,
    })
}

/// Import CAPI resources from manifest bytes (used during unpivot)
pub async fn import_from_manifests(
    kubeconfig: Option<&Path>,
    namespace: &str,
    manifests: &[Vec<u8>],
) -> Result<(), ClusterctlError> {
    let import_path = std::env::temp_dir().join(format!(
        "lattice-import-{}-{}",
        namespace,
        std::process::id()
    ));

    let mut last_error = String::new();

    for attempt in 1..=MAX_ATTEMPTS {
        let _ = std::fs::remove_dir_all(&import_path);
        std::fs::create_dir_all(&import_path).map_err(|e| {
            ClusterctlError::ExecutionFailed(format!("failed to create import dir: {}", e))
        })?;

        for (i, manifest) in manifests.iter().enumerate() {
            std::fs::write(import_path.join(format!("{}.yaml", i)), manifest).map_err(|e| {
                ClusterctlError::ExecutionFailed(format!("failed to write manifest: {}", e))
            })?;
        }

        let mut cmd = Command::new("clusterctl");
        cmd.arg("move")
            .arg("--from-directory")
            .arg(&import_path)
            .arg("--namespace")
            .arg(namespace);

        if let Some(kc) = kubeconfig {
            cmd.arg("--to-kubeconfig").arg(kc);
        }

        match run_command(&mut cmd, "clusterctl move --from-directory").await {
            Ok(()) => {
                let _ = std::fs::remove_dir_all(&import_path);
                info!(namespace = %namespace, count = manifests.len(), "CAPI import complete");
                return Ok(());
            }
            Err(e) => {
                last_error = e;
                if attempt < MAX_ATTEMPTS {
                    warn!(namespace = %namespace, attempt, error = %last_error, "import failed, retrying");
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
        }
    }

    let _ = std::fs::remove_dir_all(&import_path);
    Err(ClusterctlError::RetriesExhausted {
        attempts: MAX_ATTEMPTS,
        last_error,
    })
}

/// Unpause a CAPI cluster (call before retrying after failed move)
pub async fn unpause_capi_cluster(
    kubeconfig: Option<&Path>,
    namespace: &str,
    cluster_name: &str,
) -> Result<(), ClusterctlError> {
    let client = create_client(kubeconfig).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client, namespace, &cluster_api_resource());
    let patch = serde_json::json!({"spec": {"paused": false}});

    match api.patch(cluster_name, &PatchParams::default(), &Patch::Merge(&patch)).await {
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
    let client = create_client(kubeconfig).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client, namespace, &cluster_api_resource());

    match api.get(cluster_name).await {
        Ok(cluster) => {
            // Check for Ready condition in status.conditions
            let is_ready = cluster
                .data
                .get("status")
                .and_then(|s| s.get("conditions"))
                .and_then(|c| c.as_array())
                .map(|conditions| {
                    conditions.iter().any(|cond| {
                        cond.get("type").and_then(|t| t.as_str()) == Some("Ready")
                            && cond.get("status").and_then(|s| s.as_str()) == Some("True")
                    })
                })
                .unwrap_or(false);
            Ok(is_ready)
        }
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(false),
        Err(e) => Err(ClusterctlError::ExecutionFailed(format!("failed to get cluster: {}", e))),
    }
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

    #[test]
    fn test_error_display() {
        let err = ClusterctlError::RetriesExhausted {
            attempts: 3,
            last_error: "timeout".to_string(),
        };
        assert!(err.to_string().contains("3 attempts"));
        assert!(err.to_string().contains("timeout"));
    }
}
