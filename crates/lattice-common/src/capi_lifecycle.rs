//! CAPI cluster lifecycle helpers
//!
//! Pure kube-rs operations for pausing, unpausing, deleting, and tearing down
//! CAPI clusters. No external tool dependencies.

use std::path::Path;
use std::time::Duration;

use kube::api::{Api, DeleteParams, Patch, PatchParams};
use kube::core::DynamicObject;
use kube::discovery::ApiResource;
use kube::Client;
use thiserror::Error;
use tracing::{info, warn};

use crate::kube_utils;

/// Errors from CAPI cluster operations
#[derive(Debug, Error)]
pub enum CapiLifecycleError {
    /// Operation failed
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

/// Get CAPI Cluster resource definition using discovery
async fn cluster_api_resource(client: &Client) -> Result<ApiResource, CapiLifecycleError> {
    kube_utils::build_api_resource_with_discovery(client, "cluster.x-k8s.io", "Cluster")
        .await
        .map_err(|e| CapiLifecycleError::ExecutionFailed(format!("API discovery failed: {}", e)))
}

/// Set the paused state of a CAPI cluster
async fn set_capi_cluster_paused(
    kubeconfig: Option<&Path>,
    namespace: &str,
    cluster_name: &str,
    paused: bool,
) -> Result<(), CapiLifecycleError> {
    let client = kube_utils::create_client(kubeconfig, None, None)
        .await
        .map_err(|e| CapiLifecycleError::ExecutionFailed(e.to_string()))?;
    let ar = cluster_api_resource(&client).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client, namespace, &ar);
    let patch = serde_json::json!({"spec": {"paused": paused}});

    let action = if paused { "pause" } else { "unpause" };
    api.patch(cluster_name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| {
            CapiLifecycleError::ExecutionFailed(format!(
                "failed to {} cluster {}: {}",
                action, cluster_name, e
            ))
        })?;

    info!(cluster = %cluster_name, paused = paused, "CAPI cluster pause state updated");
    Ok(())
}

/// Pause a CAPI cluster
pub async fn pause_capi_cluster(
    kubeconfig: Option<&Path>,
    namespace: &str,
    cluster_name: &str,
) -> Result<(), CapiLifecycleError> {
    set_capi_cluster_paused(kubeconfig, namespace, cluster_name, true).await
}

/// Unpause a CAPI cluster (required before deletion - CAPI won't delete paused clusters)
pub async fn unpause_capi_cluster(
    kubeconfig: Option<&Path>,
    namespace: &str,
    cluster_name: &str,
) -> Result<(), CapiLifecycleError> {
    set_capi_cluster_paused(kubeconfig, namespace, cluster_name, false).await
}

/// Check if cluster has InfrastructureReady=True condition
async fn is_cluster_ready(
    client: &kube::Client,
    namespace: &str,
    cluster_name: &str,
) -> Result<bool, CapiLifecycleError> {
    let ar = cluster_api_resource(client).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

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
        Err(e) => Err(CapiLifecycleError::ExecutionFailed(format!(
            "failed to get cluster: {}",
            e
        ))),
    }
}

/// Wait for CAPI cluster to have InfrastructureReady=True
pub async fn wait_for_infrastructure_ready(
    client: &kube::Client,
    namespace: &str,
    cluster_name: &str,
    timeout: std::time::Duration,
) -> Result<(), CapiLifecycleError> {
    use std::time::Instant;

    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(CapiLifecycleError::ExecutionFailed(
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
) -> Result<(), CapiLifecycleError> {
    let ar = cluster_api_resource(client).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    api.delete(cluster_name, &DeleteParams::default())
        .await
        .map_err(|e| {
            CapiLifecycleError::ExecutionFailed(format!("failed to delete cluster: {}", e))
        })?;

    info!(cluster = %cluster_name, "Cluster deletion initiated");
    Ok(())
}

/// Wait for CAPI Cluster to be fully deleted
pub async fn wait_for_cluster_deletion(
    client: &kube::Client,
    namespace: &str,
    cluster_name: &str,
    timeout: std::time::Duration,
) -> Result<(), CapiLifecycleError> {
    use std::time::Instant;

    let ar = cluster_api_resource(client).await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);
    let start = Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(CapiLifecycleError::ExecutionFailed(
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
/// 1. Unpause CAPI cluster to allow reconciliation
/// 2. Wait for InfrastructureReady=True
/// 3. Delete the Cluster resource
/// 4. Wait for cluster deletion (infrastructure cleanup)
pub async fn teardown_cluster(
    client: &kube::Client,
    namespace: &str,
    cluster_name: &str,
    config: &TeardownConfig,
    kubeconfig: Option<&Path>,
) -> Result<(), CapiLifecycleError> {
    info!(cluster = %cluster_name, "Unpausing CAPI cluster");
    unpause_capi_cluster(kubeconfig, namespace, cluster_name).await?;

    info!(cluster = %cluster_name, "Waiting for infrastructure ready");
    wait_for_infrastructure_ready(client, namespace, cluster_name, config.ready_timeout).await?;

    info!(cluster = %cluster_name, "Deleting CAPI Cluster resource");
    delete_cluster(client, namespace, cluster_name).await?;

    info!(cluster = %cluster_name, "Waiting for infrastructure cleanup");
    wait_for_cluster_deletion(client, namespace, cluster_name, config.deletion_timeout).await?;

    info!(cluster = %cluster_name, "Cluster teardown complete");
    Ok(())
}

/// Annotation added before deletion (CAPI move convention)
pub const DELETE_FOR_MOVE_ANNOTATION: &str = "clusterctl.cluster.x-k8s.io/delete-for-move";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = CapiLifecycleError::RetriesExhausted {
            attempts: 3,
            last_error: "timeout".to_string(),
        };
        assert!(err.to_string().contains("3 attempts"));
        assert!(err.to_string().contains("timeout"));
    }
}
