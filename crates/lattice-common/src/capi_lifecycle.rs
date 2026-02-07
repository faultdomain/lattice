//! CAPI cluster lifecycle helpers
//!
//! Pure kube-rs operations for pausing, unpausing, deleting, and tearing down
//! CAPI clusters. No external tool dependencies.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use kube::api::{Api, DeleteParams, Patch, PatchParams};
use kube::core::DynamicObject;
use kube::discovery::ApiResource;
use kube::Client;
use thiserror::Error;
use tracing::{debug, info, warn};

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
    let client = kube_utils::create_client(kubeconfig)
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

/// Check if a CAPI cluster exists and is ready
///
/// Returns true if the Cluster resource exists and has InfrastructureReady=True.
pub async fn is_capi_cluster_ready(
    kubeconfig: Option<&Path>,
    namespace: &str,
    cluster_name: &str,
) -> Result<bool, CapiLifecycleError> {
    let client = kube_utils::create_client(kubeconfig)
        .await
        .map_err(|e| CapiLifecycleError::ExecutionFailed(e.to_string()))?;
    is_cluster_ready(&client, namespace, cluster_name).await
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

/// Resource identity extracted from manifests
#[derive(Debug, Clone)]
struct ResourceIdentity {
    api_version: String,
    kind: String,
    namespace: String,
    name: String,
}

/// Delete order for CAPI resources (children before parents)
fn deletion_priority(kind: &str) -> u32 {
    match kind {
        "Machine" => 0,
        "MachineSet" => 1,
        "MachineDeployment" => 2,
        "KubeadmConfig" | "KubeadmConfigTemplate" => 3,
        "MachineHealthCheck" => 4,
        "DockerMachine" | "DockerMachineTemplate" => 5,
        "AWSMachine" | "AWSMachineTemplate" => 5,
        "AzureMachine" | "AzureMachineTemplate" => 5,
        "GCPMachine" | "GCPMachineTemplate" => 5,
        "VSphereVM" | "VSphereMachine" | "VSphereMachineTemplate" => 5,
        "KubeadmControlPlane" | "KubeadmControlPlaneTemplate" => 6,
        "DockerCluster" | "DockerClusterTemplate" => 7,
        "AWSCluster" | "AWSClusterTemplate" => 7,
        "AzureCluster" | "AzureClusterTemplate" => 7,
        "GCPCluster" | "GCPClusterTemplate" => 7,
        "VSphereCluster" | "VSphereClusterTemplate" => 7,
        "Cluster" => 10,
        "ClusterClass" => 11,
        "Secret" | "ConfigMap" => 8,
        _ => 9,
    }
}

/// Parse manifests to extract resource identities
fn parse_manifest_identities(manifests: &[Vec<u8>]) -> Vec<ResourceIdentity> {
    let mut identities = Vec::new();

    for manifest in manifests {
        let manifest_str = String::from_utf8_lossy(manifest);

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

/// Build ApiResource from identity
fn api_resource_from_identity(identity: &ResourceIdentity) -> ApiResource {
    kube_utils::build_api_resource(&identity.api_version, &identity.kind)
}

/// Annotation added before deletion (CAPI move convention)
pub const DELETE_FOR_MOVE_ANNOTATION: &str = "clusterctl.cluster.x-k8s.io/delete-for-move";

/// Delete a single resource with finalizer removal (force delete)
async fn delete_resource_for_move(
    client: &kube::Client,
    identity: &ResourceIdentity,
) -> Result<(), CapiLifecycleError> {
    let api_resource = api_resource_from_identity(identity);
    let api: Api<DynamicObject> = if identity.namespace.is_empty() {
        Api::all_with(client.clone(), &api_resource)
    } else {
        Api::namespaced_with(client.clone(), &identity.namespace, &api_resource)
    };

    let obj = match api.get(&identity.name).await {
        Ok(o) => o,
        Err(kube::Error::Api(e)) if e.code == 404 => {
            debug!(kind = %identity.kind, name = %identity.name, "Resource already deleted");
            return Ok(());
        }
        Err(e) => {
            return Err(CapiLifecycleError::ExecutionFailed(format!(
                "failed to get {} {}: {}",
                identity.kind, identity.name, e
            )));
        }
    };

    let annotation_patch = serde_json::json!({
        "metadata": { "annotations": { DELETE_FOR_MOVE_ANNOTATION: "" } }
    });
    if let Err(e) = api
        .patch(
            &identity.name,
            &PatchParams::default(),
            &Patch::Merge(&annotation_patch),
        )
        .await
    {
        warn!(kind = %identity.kind, name = %identity.name, error = %e, "Failed to add delete-for-move annotation");
    }

    if !obj
        .metadata
        .finalizers
        .as_ref()
        .is_none_or(|f| f.is_empty())
    {
        let finalizer_patch = serde_json::json!({ "metadata": { "finalizers": null } });
        if let Err(e) = api
            .patch(
                &identity.name,
                &PatchParams::default(),
                &Patch::Merge(&finalizer_patch),
            )
            .await
        {
            warn!(kind = %identity.kind, name = %identity.name, error = %e, "Failed to remove finalizers");
        }
    }

    match api.delete(&identity.name, &DeleteParams::default()).await {
        Ok(_) => {
            debug!(kind = %identity.kind, name = %identity.name, "Resource deleted");
            Ok(())
        }
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => Err(CapiLifecycleError::ExecutionFailed(format!(
            "failed to delete {} {}: {}",
            identity.kind, identity.name, e
        ))),
    }
}

/// Delete CAPI resources from source cluster after successful pivot
///
/// Resources are deleted in reverse dependency order: children before parents.
pub async fn delete_pivoted_capi_resources(
    client: &kube::Client,
    manifests: &[Vec<u8>],
) -> Result<usize, CapiLifecycleError> {
    let mut identities = parse_manifest_identities(manifests);

    if identities.is_empty() {
        return Ok(0);
    }

    identities.sort_by_key(|id| deletion_priority(&id.kind));

    let mut by_kind: HashMap<String, usize> = HashMap::new();
    for id in &identities {
        *by_kind.entry(id.kind.clone()).or_default() += 1;
    }
    info!(
        resources = ?by_kind,
        total = identities.len(),
        "Deleting pivoted CAPI resources from source cluster"
    );

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

    info!(deleted, total = identities.len(), "CAPI resource deletion complete");
    Ok(deleted)
}

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

    #[test]
    fn test_deletion_priority_children_before_parents() {
        assert!(deletion_priority("Machine") < deletion_priority("MachineSet"));
        assert!(deletion_priority("MachineSet") < deletion_priority("MachineDeployment"));
        assert!(deletion_priority("MachineDeployment") < deletion_priority("KubeadmControlPlane"));
        assert!(deletion_priority("KubeadmControlPlane") < deletion_priority("DockerCluster"));
        assert!(deletion_priority("DockerCluster") < deletion_priority("Cluster"));
        assert!(deletion_priority("Cluster") < deletion_priority("ClusterClass"));
    }

    #[test]
    fn test_deletion_priority_infrastructure_resources() {
        assert_eq!(
            deletion_priority("DockerMachine"),
            deletion_priority("AWSMachine")
        );
        assert_eq!(
            deletion_priority("AWSMachine"),
            deletion_priority("GCPMachine")
        );
        assert_eq!(
            deletion_priority("DockerCluster"),
            deletion_priority("AWSCluster")
        );
    }

    #[test]
    fn test_deletion_priority_unknown_resources() {
        let unknown_priority = deletion_priority("SomeUnknownResource");
        assert!(unknown_priority < deletion_priority("Cluster"));
        assert!(unknown_priority > deletion_priority("Secret"));
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
        assert_eq!(api_resource.group, "");
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

        assert_eq!(identities[0].kind, "Machine");
        assert_eq!(identities[1].kind, "MachineDeployment");
        assert_eq!(identities[2].kind, "Cluster");
    }
}
