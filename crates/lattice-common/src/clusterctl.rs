//! Shared clusterctl move execution with retry and unpause logic
//!
//! This module provides a unified implementation for executing `clusterctl move`
//! that is used by both the CLI (bootstrap → management) and the operator
//! (management → workload cluster pivots).
//!
//! # Features
//! - Configurable retry with exponential backoff
//! - Automatic cluster unpause on failure (clusterctl pauses clusters during move)
//! - Proper error handling and logging

use std::path::Path;
use std::time::Duration;

use thiserror::Error;
use tokio::process::Command;
use tracing::{info, warn};

/// Errors from clusterctl move operations
#[derive(Debug, Error)]
pub enum ClusterctlError {
    /// clusterctl command failed
    #[error("clusterctl move failed: {0}")]
    MoveFailed(String),

    /// Failed to execute command
    #[error("failed to execute clusterctl: {0}")]
    ExecutionFailed(String),

    /// Failed to unpause cluster
    #[error("failed to unpause cluster: {0}")]
    UnpauseFailed(String),

    /// All retries exhausted
    #[error("clusterctl move failed after {attempts} attempts: {last_error}")]
    RetriesExhausted {
        /// Number of attempts made
        attempts: u32,
        /// Last error message
        last_error: String,
    },
}

/// Configuration for clusterctl move execution
#[derive(Debug, Clone)]
pub struct ClusterctlMoveConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial delay between retries
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Multiplier for exponential backoff
    pub backoff_multiplier: f64,
}

impl Default for ClusterctlMoveConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_delay: Duration::from_secs(10),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 1.5,
        }
    }
}

/// Execute clusterctl move with retry and automatic unpause on failure
///
/// # Arguments
/// * `source_kubeconfig` - Optional path to source cluster kubeconfig (if None, uses default context)
/// * `target_kubeconfig` - Path to target cluster kubeconfig
/// * `namespace` - CAPI namespace containing resources to move
/// * `cluster_name` - Name of the cluster being moved (for unpause)
/// * `config` - Retry configuration
///
/// # Returns
/// Ok(()) on success, or ClusterctlError on failure after all retries
pub async fn execute_move(
    source_kubeconfig: Option<&Path>,
    target_kubeconfig: &Path,
    namespace: &str,
    cluster_name: &str,
    config: &ClusterctlMoveConfig,
) -> Result<(), ClusterctlError> {
    let mut last_error = String::new();
    let mut delay = config.initial_delay;

    for attempt in 1..=config.max_attempts {
        // Build clusterctl move command
        let mut cmd = Command::new("clusterctl");
        cmd.arg("move")
            .arg("--to-kubeconfig")
            .arg(target_kubeconfig)
            .arg("--namespace")
            .arg(namespace);

        if let Some(source) = source_kubeconfig {
            cmd.arg("--kubeconfig").arg(source);
        }

        let output = cmd
            .output()
            .await
            .map_err(|e| ClusterctlError::ExecutionFailed(e.to_string()))?;

        if output.status.success() {
            info!(
                cluster = %cluster_name,
                namespace = %namespace,
                "clusterctl move completed successfully"
            );
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        last_error = stderr.clone();

        if attempt < config.max_attempts {
            warn!(
                cluster = %cluster_name,
                attempt = attempt,
                max_attempts = config.max_attempts,
                delay_secs = delay.as_secs(),
                error = %stderr.trim(),
                "clusterctl move failed, will retry"
            );

            // Unpause the cluster before retrying - clusterctl pauses clusters during move
            // and may leave them paused on failure
            if let Err(e) = unpause_cluster(source_kubeconfig, namespace, cluster_name).await {
                warn!(
                    cluster = %cluster_name,
                    error = %e,
                    "Failed to unpause cluster (may already be unpaused)"
                );
            } else {
                info!(cluster = %cluster_name, "Unpaused cluster for retry");
            }

            tokio::time::sleep(delay).await;
            delay = Duration::from_secs_f64(
                (delay.as_secs_f64() * config.backoff_multiplier)
                    .min(config.max_delay.as_secs_f64()),
            );
        }
    }

    Err(ClusterctlError::RetriesExhausted {
        attempts: config.max_attempts,
        last_error,
    })
}

/// Export CAPI resources to a directory using `clusterctl move --to-directory`
///
/// This exports all CAPI resources for a cluster to YAML files in the specified directory.
/// Used during unpivot to extract resources before sending them to the parent cluster.
///
/// # Arguments
/// * `kubeconfig` - Optional path to source cluster kubeconfig
/// * `namespace` - CAPI namespace containing resources to export
/// * `output_dir` - Directory to write YAML files to
///
/// # Returns
/// Ok(Vec<Vec<u8>>) containing the raw YAML content of each exported file
pub async fn export_to_directory(
    kubeconfig: Option<&Path>,
    namespace: &str,
    output_dir: &Path,
) -> Result<Vec<Vec<u8>>, ClusterctlError> {
    // Ensure output directory exists
    std::fs::create_dir_all(output_dir).map_err(|e| {
        ClusterctlError::ExecutionFailed(format!("failed to create output dir: {}", e))
    })?;

    let mut cmd = Command::new("clusterctl");
    cmd.arg("move")
        .arg("--to-directory")
        .arg(output_dir)
        .arg("--namespace")
        .arg(namespace);

    if let Some(kc) = kubeconfig {
        cmd.arg("--kubeconfig").arg(kc);
    }

    let output = cmd
        .output()
        .await
        .map_err(|e| ClusterctlError::ExecutionFailed(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ClusterctlError::MoveFailed(stderr.to_string()));
    }

    info!(
        namespace = %namespace,
        output_dir = %output_dir.display(),
        "clusterctl move --to-directory completed"
    );

    // Read all YAML files from the output directory
    let mut manifests = Vec::new();
    let entries = std::fs::read_dir(output_dir).map_err(|e| {
        ClusterctlError::ExecutionFailed(format!("failed to read output dir: {}", e))
    })?;

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

    info!(count = manifests.len(), "exported CAPI manifests");
    Ok(manifests)
}

/// Import CAPI resources from a directory using `clusterctl move --from-directory`
///
/// This imports all CAPI resources from YAML files in the specified directory.
/// Used during unpivot to restore resources received from a child cluster.
///
/// # Arguments
/// * `kubeconfig` - Optional path to target cluster kubeconfig
/// * `namespace` - CAPI namespace to import resources into
/// * `input_dir` - Directory containing YAML files to import
///
/// # Returns
/// Ok(()) on success
pub async fn import_from_directory(
    kubeconfig: Option<&Path>,
    namespace: &str,
    input_dir: &Path,
) -> Result<(), ClusterctlError> {
    let mut cmd = Command::new("clusterctl");
    cmd.arg("move")
        .arg("--from-directory")
        .arg(input_dir)
        .arg("--namespace")
        .arg(namespace);

    if let Some(kc) = kubeconfig {
        cmd.arg("--to-kubeconfig").arg(kc);
    }

    let output = cmd
        .output()
        .await
        .map_err(|e| ClusterctlError::ExecutionFailed(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ClusterctlError::MoveFailed(stderr.to_string()));
    }

    info!(
        namespace = %namespace,
        input_dir = %input_dir.display(),
        "clusterctl move --from-directory completed"
    );

    Ok(())
}

/// Import CAPI resources from raw manifest bytes
///
/// Convenience function that writes manifests to a temp directory and then
/// calls `import_from_directory`. Used when manifests are received over the wire.
///
/// # Arguments
/// * `kubeconfig` - Optional path to target cluster kubeconfig
/// * `namespace` - CAPI namespace to import resources into
/// * `manifests` - Raw YAML content of each manifest file
///
/// # Returns
/// Ok(()) on success
pub async fn import_from_manifests(
    kubeconfig: Option<&Path>,
    namespace: &str,
    manifests: &[Vec<u8>],
) -> Result<(), ClusterctlError> {
    // Create temp directory with timestamp + pid for uniqueness
    let unique_id = format!(
        "{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        std::process::id()
    );
    let import_dir = format!("/tmp/lattice-import-{}", unique_id);
    let import_path = Path::new(&import_dir);

    std::fs::create_dir_all(import_path).map_err(|e| {
        ClusterctlError::ExecutionFailed(format!("failed to create import dir: {}", e))
    })?;

    // Write manifests to files
    for (i, manifest) in manifests.iter().enumerate() {
        let file_path = import_path.join(format!("manifest-{}.yaml", i));
        std::fs::write(&file_path, manifest).map_err(|e| {
            ClusterctlError::ExecutionFailed(format!("failed to write manifest: {}", e))
        })?;
    }

    // Run clusterctl move --from-directory
    let result = import_from_directory(kubeconfig, namespace, import_path).await;

    // Clean up temp directory
    let _ = std::fs::remove_dir_all(import_path);

    result
}

/// Unpause a CAPI cluster
///
/// clusterctl move pauses clusters during the move operation. If the move fails
/// partway through, the cluster may be left in a paused state, preventing retries.
async fn unpause_cluster(
    kubeconfig: Option<&Path>,
    namespace: &str,
    cluster_name: &str,
) -> Result<(), ClusterctlError> {
    let mut cmd = Command::new("kubectl");

    if let Some(kc) = kubeconfig {
        cmd.arg("--kubeconfig").arg(kc);
    }

    cmd.args([
        "patch",
        "cluster",
        cluster_name,
        "-n",
        namespace,
        "--type=merge",
        "-p",
        r#"{"spec":{"paused":false}}"#,
    ]);

    let output = cmd
        .output()
        .await
        .map_err(|e| ClusterctlError::UnpauseFailed(e.to_string()))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Don't fail if cluster doesn't exist or is already unpaused
        if stderr.contains("not found") || stderr.contains("NotFound") {
            Ok(())
        } else {
            Err(ClusterctlError::UnpauseFailed(stderr.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ClusterctlMoveConfig::default();
        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.initial_delay, Duration::from_secs(10));
        assert_eq!(config.max_delay, Duration::from_secs(60));
        assert!((config.backoff_multiplier - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_error_display() {
        let err = ClusterctlError::MoveFailed("connection refused".to_string());
        assert!(err.to_string().contains("connection refused"));

        let err = ClusterctlError::RetriesExhausted {
            attempts: 5,
            last_error: "timeout".to_string(),
        };
        assert!(err.to_string().contains("5 attempts"));
        assert!(err.to_string().contains("timeout"));
    }
}
