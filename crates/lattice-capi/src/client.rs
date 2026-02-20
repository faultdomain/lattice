//! CAPI (Cluster API) client for applying and managing CAPI resources
//!
//! Provides a trait-based abstraction for CAPI operations, allowing tests to mock
//! Kubernetes interactions while production code uses real API calls.

use async_trait::async_trait;
use kube::api::{Api, DynamicObject, ListParams, Patch, PatchParams};
use kube::Client;
use tracing::{debug, info};

#[cfg(test)]
use mockall::automock;

use crate::provider::{control_plane_name, pool_resource_suffix, CAPIManifest};
use lattice_common::crd::BootstrapProvider;
use lattice_common::kube_utils::build_api_resource;
use lattice_common::Error;

/// Trait abstracting CAPI resource operations
///
/// This trait allows mocking CAPI operations in tests while using the
/// real Kubernetes client for applying manifests in production.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait CAPIClient: Send + Sync {
    /// Apply CAPI manifests to provision cluster infrastructure
    async fn apply_manifests(
        &self,
        manifests: &[CAPIManifest],
        namespace: &str,
    ) -> Result<(), Error>;

    /// Check if CAPI infrastructure is ready for a cluster
    ///
    /// Returns true when:
    /// - CAPI Cluster object is Provisioned/Ready
    /// - ControlPlane is initialized
    /// - No machines are still provisioning
    async fn is_infrastructure_ready(
        &self,
        cluster_name: &str,
        namespace: &str,
        bootstrap: BootstrapProvider,
    ) -> Result<bool, Error>;

    /// Get the current replica count of a pool's MachineDeployment
    async fn get_pool_replicas(
        &self,
        cluster_name: &str,
        pool_id: &str,
        namespace: &str,
    ) -> Result<Option<u32>, Error>;

    /// Scale a pool's MachineDeployment to the desired replica count
    async fn scale_pool(
        &self,
        cluster_name: &str,
        pool_id: &str,
        namespace: &str,
        replicas: u32,
    ) -> Result<(), Error>;

    /// Delete a CAPI Cluster resource
    async fn delete_capi_cluster(&self, cluster_name: &str, namespace: &str) -> Result<(), Error>;

    /// Check if a CAPI Cluster resource exists
    async fn capi_cluster_exists(&self, cluster_name: &str, namespace: &str)
        -> Result<bool, Error>;

    /// Check if cluster is stable (not scaling, not provisioning)
    ///
    /// Returns true when:
    /// - CAPI Cluster is Ready
    /// - All MachineDeployments have converged (readyReplicas == replicas)
    /// - No machines are in transitional states (Provisioning, Pending, Deleting)
    ///
    /// Use this before deletion to avoid disrupting in-progress operations.
    async fn is_cluster_stable(&self, cluster_name: &str, namespace: &str) -> Result<bool, Error>;

    /// Get the version from the control plane resource (KubeadmControlPlane or RKE2ControlPlane).
    ///
    /// Returns `spec.version` (e.g., "v1.32.0" or "v1.32.0+rke2r1").
    async fn get_cp_version(
        &self,
        cluster_name: &str,
        namespace: &str,
        bootstrap: BootstrapProvider,
    ) -> Result<Option<String>, Error>;

    /// Patch the version on the control plane resource.
    async fn update_cp_version(
        &self,
        cluster_name: &str,
        namespace: &str,
        bootstrap: BootstrapProvider,
        version: &str,
    ) -> Result<(), Error>;

    /// Get the version from a pool's MachineDeployment (`spec.template.spec.version`).
    async fn get_pool_version(
        &self,
        cluster_name: &str,
        pool_id: &str,
        namespace: &str,
    ) -> Result<Option<String>, Error>;

    /// Patch the version on a pool's MachineDeployment.
    async fn update_pool_version(
        &self,
        cluster_name: &str,
        pool_id: &str,
        namespace: &str,
        version: &str,
    ) -> Result<(), Error>;

    /// Get the underlying kube Client for advanced operations
    fn kube_client(&self) -> Client;
}

/// Real CAPI client implementation using DynamicObject for untyped resources
pub struct CAPIClientImpl {
    client: Client,
}

impl CAPIClientImpl {
    /// Create a new CAPIClientImpl
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Get API for CAPI Cluster resources using discovery
    async fn capi_cluster_api(&self, namespace: &str) -> Result<Api<DynamicObject>, Error> {
        let ar = lattice_common::kube_utils::build_api_resource_with_discovery(
            &self.client,
            "cluster.x-k8s.io",
            "Cluster",
        )
        .await?;
        Ok(Api::namespaced_with(self.client.clone(), namespace, &ar))
    }

    /// Apply a manifest with optional owner reference
    async fn apply_manifest(
        &self,
        manifest: &CAPIManifest,
        namespace: &str,
        owner_ref: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        let ar = build_api_resource(&manifest.api_version, &manifest.kind);

        let metadata = build_manifest_metadata(
            &manifest.metadata.name,
            namespace,
            &manifest.metadata.labels,
            owner_ref.as_ref(),
        );

        let mut obj_value = serde_json::json!({
            "apiVersion": manifest.api_version,
            "kind": manifest.kind,
            "metadata": metadata,
        });

        if let Some(ref data) = manifest.data {
            obj_value["data"] = data.clone();
        }
        if let Some(ref spec) = manifest.spec {
            obj_value["spec"] = spec.clone();
        }

        let obj: DynamicObject =
            serde_json::from_value(obj_value).map_err(|e| Error::serialization(e.to_string()))?;

        let api: Api<DynamicObject> = Api::namespaced_with(self.client.clone(), namespace, &ar);
        api.patch(
            &manifest.metadata.name,
            &PatchParams::apply("lattice-controller").force(),
            &Patch::Apply(&obj),
        )
        .await?;

        info!(
            kind = %manifest.kind,
            name = %manifest.metadata.name,
            namespace = %namespace,
            "Applied CAPI manifest"
        );

        Ok(())
    }

    /// Get owner reference for a DockerCluster
    async fn get_docker_cluster_owner_ref(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<serde_json::Value, Error> {
        let ar = lattice_common::kube_utils::build_api_resource_with_discovery(
            &self.client,
            "infrastructure.cluster.x-k8s.io",
            "DockerCluster",
        )
        .await?;

        let api: Api<DynamicObject> = Api::namespaced_with(self.client.clone(), namespace, &ar);
        let dc = api.get(name).await?;
        let uid = dc
            .metadata
            .uid
            .ok_or_else(|| Error::internal("DockerCluster has no UID"))?;

        Ok(build_docker_cluster_owner_ref(name, &uid, &ar.api_version))
    }
}

#[async_trait]
impl CAPIClient for CAPIClientImpl {
    async fn apply_manifests(
        &self,
        manifests: &[CAPIManifest],
        namespace: &str,
    ) -> Result<(), Error> {
        // Separate HAProxy ConfigMap from other manifests - it needs special handling
        // to include owner reference pointing to DockerCluster
        let (haproxy_cm, other_manifests): (Vec<_>, Vec<_>) = manifests
            .iter()
            .partition(|m| m.kind == "ConfigMap" && m.metadata.name.ends_with("-lb-config"));

        let haproxy_configmap = haproxy_cm.first().cloned();
        let docker_cluster_name = manifests
            .iter()
            .find(|m| m.kind == "DockerCluster")
            .map(|m| m.metadata.name.clone());

        // Apply all non-ConfigMap manifests first (includes DockerCluster)
        for manifest in &other_manifests {
            self.apply_manifest(manifest, namespace, None).await?;
        }

        // Apply HAProxy ConfigMap with owner reference to DockerCluster
        if let (Some(cm), Some(dc_name)) = (haproxy_configmap, docker_cluster_name) {
            let owner_ref = self
                .get_docker_cluster_owner_ref(namespace, &dc_name)
                .await?;
            self.apply_manifest(cm, namespace, Some(owner_ref)).await?;
        }

        Ok(())
    }

    async fn is_infrastructure_ready(
        &self,
        cluster_name: &str,
        namespace: &str,
        bootstrap: BootstrapProvider,
    ) -> Result<bool, Error> {
        // Check 1: CAPI Cluster object is Ready/Provisioned
        let cluster_api = self.capi_cluster_api(namespace).await?;
        let cluster_ready = match cluster_api.get(cluster_name).await {
            Ok(cluster) => {
                let mut ready = false;
                if let Some(status) = cluster.data.get("status") {
                    if let Some(phase) = status.get("phase").and_then(|p| p.as_str()) {
                        if phase == "Provisioned" {
                            ready = true;
                        }
                    }
                    if !ready {
                        if let Some(conditions) =
                            status.get("conditions").and_then(|c| c.as_array())
                        {
                            for condition in conditions {
                                if condition.get("type").and_then(|t| t.as_str()) == Some("Ready")
                                    && condition.get("status").and_then(|s| s.as_str())
                                        == Some("True")
                                {
                                    ready = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                ready
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => false,
            Err(e) => return Err(e.into()),
        };

        if !cluster_ready {
            debug!(cluster = %cluster_name, "CAPI Cluster not ready yet");
            return Ok(false);
        }

        // Check 2: Control plane is Initialized
        let (cp_kind, cp_group) = match bootstrap {
            BootstrapProvider::Kubeadm => ("KubeadmControlPlane", "controlplane.cluster.x-k8s.io"),
            BootstrapProvider::Rke2 => ("RKE2ControlPlane", "controlplane.cluster.x-k8s.io"),
        };

        let cp_ar = lattice_common::kube_utils::build_api_resource_with_discovery(
            &self.client,
            cp_group,
            cp_kind,
        )
        .await?;
        let cp_api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), namespace, &cp_ar);

        let cp_name = control_plane_name(cluster_name);
        let cp_initialized = match cp_api.get(&cp_name).await {
            Ok(cp) => {
                if let Some(status) = cp.data.get("status") {
                    // RKE2ControlPlane uses status.initialized
                    // KubeadmControlPlane uses status.initialization.controlPlaneInitialized
                    let rke2_initialized = status.get("initialized").and_then(|i| i.as_bool());
                    let kubeadm_initialized = status
                        .get("initialization")
                        .and_then(|init| init.get("controlPlaneInitialized"))
                        .and_then(|i| i.as_bool());
                    rke2_initialized.or(kubeadm_initialized).unwrap_or(false)
                } else {
                    false
                }
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(cluster = %cluster_name, cp_kind = %cp_kind, "ControlPlane not found");
                false
            }
            Err(e) => return Err(e.into()),
        };

        if !cp_initialized {
            debug!(cluster = %cluster_name, cp_kind = %cp_kind, "ControlPlane not initialized yet");
            return Ok(false);
        }

        // Check 3: No machines are still provisioning
        let machine_ar = lattice_common::kube_utils::build_api_resource_with_discovery(
            &self.client,
            "cluster.x-k8s.io",
            "Machine",
        )
        .await?;
        let machine_api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), namespace, &machine_ar);

        let machines = machine_api
            .list(
                &ListParams::default()
                    .labels(&format!("cluster.x-k8s.io/cluster-name={}", cluster_name)),
            )
            .await?;

        for machine in &machines.items {
            if let Some(status) = machine.data.get("status") {
                if let Some(phase) = status.get("phase").and_then(|p| p.as_str()) {
                    if phase == "Provisioning" || phase == "Pending" {
                        debug!(
                            cluster = %cluster_name,
                            machine = ?machine.metadata.name,
                            phase = %phase,
                            "Machine still provisioning"
                        );
                        return Ok(false);
                    }
                }
            }
        }

        info!(
            cluster = %cluster_name,
            cp_kind = %cp_kind,
            "Infrastructure fully ready (Cluster ready, ControlPlane initialized, all machines running)"
        );
        Ok(true)
    }

    async fn get_pool_replicas(
        &self,
        cluster_name: &str,
        pool_id: &str,
        namespace: &str,
    ) -> Result<Option<u32>, Error> {
        let ar = lattice_common::kube_utils::build_api_resource_with_discovery(
            &self.client,
            "cluster.x-k8s.io",
            "MachineDeployment",
        )
        .await?;
        let api: Api<DynamicObject> = Api::namespaced_with(self.client.clone(), namespace, &ar);

        let md_name = format!("{}-{}", cluster_name, pool_resource_suffix(pool_id));

        match api.get(&md_name).await {
            Ok(md) => {
                let replicas = md
                    .data
                    .get("spec")
                    .and_then(|s| s.get("replicas"))
                    .and_then(|r| r.as_i64())
                    .and_then(|r| u32::try_from(r).ok());
                debug!(
                    cluster = %cluster_name,
                    pool = %pool_id,
                    replicas = ?replicas,
                    "Got MachineDeployment replicas for pool"
                );
                Ok(replicas)
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(cluster = %cluster_name, pool = %pool_id, "MachineDeployment not found for pool");
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn scale_pool(
        &self,
        cluster_name: &str,
        pool_id: &str,
        namespace: &str,
        replicas: u32,
    ) -> Result<(), Error> {
        let ar = lattice_common::kube_utils::build_api_resource_with_discovery(
            &self.client,
            "cluster.x-k8s.io",
            "MachineDeployment",
        )
        .await?;
        let api: Api<DynamicObject> = Api::namespaced_with(self.client.clone(), namespace, &ar);

        let md_name = format!("{}-{}", cluster_name, pool_resource_suffix(pool_id));
        let patch = serde_json::json!({ "spec": { "replicas": replicas } });

        api.patch(&md_name, &PatchParams::default(), &Patch::Merge(&patch))
            .await?;

        info!(
            cluster = %cluster_name,
            pool = %pool_id,
            replicas = replicas,
            "Scaled MachineDeployment for pool"
        );
        Ok(())
    }

    async fn delete_capi_cluster(&self, cluster_name: &str, namespace: &str) -> Result<(), Error> {
        let api = self.capi_cluster_api(namespace).await?;
        match api.delete(cluster_name, &Default::default()).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(cluster = %cluster_name, "CAPI Cluster not found (already deleted)");
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn capi_cluster_exists(
        &self,
        cluster_name: &str,
        namespace: &str,
    ) -> Result<bool, Error> {
        let api = self.capi_cluster_api(namespace).await?;
        match api.get(cluster_name).await {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    async fn is_cluster_stable(&self, cluster_name: &str, namespace: &str) -> Result<bool, Error> {
        // Check 1: CAPI Cluster is Provisioned
        let cluster_api = self.capi_cluster_api(namespace).await?;
        match cluster_api.get(cluster_name).await {
            Ok(cluster) => {
                let phase = cluster
                    .data
                    .get("status")
                    .and_then(|s| s.get("phase"))
                    .and_then(|p| p.as_str());

                if phase != Some("Provisioned") {
                    debug!(cluster = %cluster_name, phase = ?phase, "Cluster not Provisioned");
                    return Ok(false);
                }
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(cluster = %cluster_name, "CAPI Cluster not found");
                return Ok(false);
            }
            Err(e) => return Err(e.into()),
        }

        // Check 2: No machines in transitional states
        let machine_ar = lattice_common::kube_utils::build_api_resource_with_discovery(
            &self.client,
            "cluster.x-k8s.io",
            "Machine",
        )
        .await?;
        let machine_api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), namespace, &machine_ar);

        let machines = machine_api
            .list(
                &ListParams::default()
                    .labels(&format!("cluster.x-k8s.io/cluster-name={}", cluster_name)),
            )
            .await?;

        for machine in &machines.items {
            let phase = machine
                .data
                .get("status")
                .and_then(|s| s.get("phase"))
                .and_then(|p| p.as_str());

            if matches!(phase, Some("Provisioning" | "Pending" | "Deleting")) {
                debug!(
                    cluster = %cluster_name,
                    machine = ?machine.metadata.name,
                    phase = ?phase,
                    "Machine in transitional state"
                );
                return Ok(false);
            }
        }

        debug!(cluster = %cluster_name, "Cluster is stable");
        Ok(true)
    }

    async fn get_cp_version(
        &self,
        cluster_name: &str,
        namespace: &str,
        bootstrap: BootstrapProvider,
    ) -> Result<Option<String>, Error> {
        let (cp_kind, cp_group) = match bootstrap {
            BootstrapProvider::Kubeadm => ("KubeadmControlPlane", "controlplane.cluster.x-k8s.io"),
            BootstrapProvider::Rke2 => ("RKE2ControlPlane", "controlplane.cluster.x-k8s.io"),
        };

        let ar = lattice_common::kube_utils::build_api_resource_with_discovery(
            &self.client,
            cp_group,
            cp_kind,
        )
        .await?;
        let api: Api<DynamicObject> = Api::namespaced_with(self.client.clone(), namespace, &ar);

        let cp_name = control_plane_name(cluster_name);
        match api.get(&cp_name).await {
            Ok(cp) => {
                let version = cp
                    .data
                    .get("spec")
                    .and_then(|s| s.get("version"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                debug!(cluster = %cluster_name, version = ?version, "Got control plane version");
                Ok(version)
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(cluster = %cluster_name, "ControlPlane not found");
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn update_cp_version(
        &self,
        cluster_name: &str,
        namespace: &str,
        bootstrap: BootstrapProvider,
        version: &str,
    ) -> Result<(), Error> {
        let (cp_kind, cp_group) = match bootstrap {
            BootstrapProvider::Kubeadm => ("KubeadmControlPlane", "controlplane.cluster.x-k8s.io"),
            BootstrapProvider::Rke2 => ("RKE2ControlPlane", "controlplane.cluster.x-k8s.io"),
        };

        let ar = lattice_common::kube_utils::build_api_resource_with_discovery(
            &self.client,
            cp_group,
            cp_kind,
        )
        .await?;
        let api: Api<DynamicObject> = Api::namespaced_with(self.client.clone(), namespace, &ar);

        let cp_name = control_plane_name(cluster_name);
        let patch = serde_json::json!({ "spec": { "version": version } });

        api.patch(&cp_name, &PatchParams::default(), &Patch::Merge(&patch))
            .await?;

        info!(
            cluster = %cluster_name,
            version = %version,
            kind = %cp_kind,
            "Patched control plane version"
        );
        Ok(())
    }

    async fn get_pool_version(
        &self,
        cluster_name: &str,
        pool_id: &str,
        namespace: &str,
    ) -> Result<Option<String>, Error> {
        let ar = lattice_common::kube_utils::build_api_resource_with_discovery(
            &self.client,
            "cluster.x-k8s.io",
            "MachineDeployment",
        )
        .await?;
        let api: Api<DynamicObject> = Api::namespaced_with(self.client.clone(), namespace, &ar);

        let md_name = format!("{}-{}", cluster_name, pool_resource_suffix(pool_id));

        match api.get(&md_name).await {
            Ok(md) => {
                let version = md
                    .data
                    .get("spec")
                    .and_then(|s| s.get("template"))
                    .and_then(|t| t.get("spec"))
                    .and_then(|s| s.get("version"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                debug!(
                    cluster = %cluster_name,
                    pool = %pool_id,
                    version = ?version,
                    "Got MachineDeployment version for pool"
                );
                Ok(version)
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(cluster = %cluster_name, pool = %pool_id, "MachineDeployment not found for pool");
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn update_pool_version(
        &self,
        cluster_name: &str,
        pool_id: &str,
        namespace: &str,
        version: &str,
    ) -> Result<(), Error> {
        let ar = lattice_common::kube_utils::build_api_resource_with_discovery(
            &self.client,
            "cluster.x-k8s.io",
            "MachineDeployment",
        )
        .await?;
        let api: Api<DynamicObject> = Api::namespaced_with(self.client.clone(), namespace, &ar);

        let md_name = format!("{}-{}", cluster_name, pool_resource_suffix(pool_id));
        let patch = serde_json::json!({
            "spec": {
                "template": {
                    "spec": {
                        "version": version
                    }
                }
            }
        });

        api.patch(&md_name, &PatchParams::default(), &Patch::Merge(&patch))
            .await?;

        info!(
            cluster = %cluster_name,
            pool = %pool_id,
            version = %version,
            "Patched MachineDeployment version for pool"
        );
        Ok(())
    }

    fn kube_client(&self) -> Client {
        self.client.clone()
    }
}

/// Build owner reference JSON for a DockerCluster
fn build_docker_cluster_owner_ref(name: &str, uid: &str, api_version: &str) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": api_version,
        "kind": "DockerCluster",
        "name": name,
        "uid": uid,
        "blockOwnerDeletion": true
    })
}

/// Build manifest metadata JSON with optional owner reference
fn build_manifest_metadata(
    name: &str,
    namespace: &str,
    labels: &Option<std::collections::BTreeMap<String, String>>,
    owner_ref: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut metadata = serde_json::json!({
        "name": name,
        "namespace": namespace,
        "labels": labels,
    });

    if let Some(owner) = owner_ref {
        metadata["ownerReferences"] = serde_json::json!([owner]);
    }

    metadata
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_owner_ref_has_correct_structure() {
        let owner_ref = build_docker_cluster_owner_ref(
            "my-cluster",
            "abc-123-uid",
            "infrastructure.cluster.x-k8s.io/v1beta2",
        );

        assert_eq!(
            owner_ref["apiVersion"],
            "infrastructure.cluster.x-k8s.io/v1beta2"
        );
        assert_eq!(owner_ref["kind"], "DockerCluster");
        assert_eq!(owner_ref["name"], "my-cluster");
        assert_eq!(owner_ref["uid"], "abc-123-uid");
        assert_eq!(owner_ref["blockOwnerDeletion"], true);
    }

    #[test]
    fn build_metadata_without_owner() {
        let labels: Option<std::collections::BTreeMap<String, String>> = Some(
            [("app".to_string(), "test".to_string())]
                .into_iter()
                .collect(),
        );
        let metadata = build_manifest_metadata("my-resource", "my-namespace", &labels, None);

        assert_eq!(metadata["name"], "my-resource");
        assert_eq!(metadata["namespace"], "my-namespace");
        assert_eq!(metadata["labels"]["app"], "test");
        assert!(metadata.get("ownerReferences").is_none());
    }

    #[test]
    fn build_metadata_with_owner() {
        let owner = build_docker_cluster_owner_ref(
            "parent-cluster",
            "parent-uid",
            "infrastructure.cluster.x-k8s.io/v1beta1",
        );
        let metadata = build_manifest_metadata("my-resource", "my-namespace", &None, Some(&owner));

        assert_eq!(metadata["name"], "my-resource");
        assert_eq!(metadata["namespace"], "my-namespace");
        assert!(metadata["ownerReferences"].is_array());
        assert_eq!(metadata["ownerReferences"][0]["name"], "parent-cluster");
        assert_eq!(metadata["ownerReferences"][0]["uid"], "parent-uid");
    }

    #[test]
    fn build_metadata_with_no_labels() {
        let metadata = build_manifest_metadata("resource", "ns", &None, None);

        assert_eq!(metadata["name"], "resource");
        assert_eq!(metadata["namespace"], "ns");
        assert!(metadata["labels"].is_null());
    }
}
