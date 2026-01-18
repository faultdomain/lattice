//! LatticeCluster controller implementation
//!
//! This module implements the reconciliation logic for LatticeCluster resources.
//! It follows the Kubernetes controller pattern: observe current state, determine
//! desired state, calculate diff, and apply changes.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, DynamicObject, GroupVersionKind, ListParams, Patch, PatchParams, PostParams};
use kube::discovery::ApiResource;
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use lattice_common::clusterctl::{execute_move, ClusterctlMoveConfig};
use tracing::{debug, error, info, instrument, warn};

#[cfg(test)]
use mockall::automock;

use crate::agent::connection::SharedAgentRegistry;
use crate::bootstrap::DefaultManifestGenerator;
use crate::capi::{ensure_capi_installed, CapiInstaller, CapiProviderConfig};
use crate::crd::{
    BootstrapProvider, ClusterPhase, Condition, ConditionStatus, LatticeCluster,
    LatticeClusterStatus,
};
use crate::parent::ParentServers;
use crate::proto::{cell_command, AgentState, CellCommand, StartPivotCommand};
use crate::provider::{create_provider, CAPIManifest};
use crate::Error;

/// Trait abstracting Kubernetes client operations for LatticeCluster
///
/// This trait allows mocking the Kubernetes client in tests while using
/// the real client in production.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait KubeClient: Send + Sync {
    /// Patch the status of a LatticeCluster
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the cluster to update
    /// * `status` - New status to apply
    async fn patch_status(&self, name: &str, status: &LatticeClusterStatus) -> Result<(), Error>;

    /// Get the count of ready worker nodes
    ///
    /// Worker nodes are nodes without the control-plane role label.
    async fn get_ready_worker_count(&self) -> Result<u32, Error>;

    /// Check if control plane nodes have the NoSchedule taint
    async fn are_control_plane_nodes_tainted(&self) -> Result<bool, Error>;

    /// Apply NoSchedule taint to all control plane nodes
    async fn taint_control_plane_nodes(&self) -> Result<(), Error>;

    /// Ensure a namespace exists, creating it if it doesn't
    async fn ensure_namespace(&self, name: &str) -> Result<(), Error>;

    /// Get a LatticeCluster by name
    async fn get_cluster(&self, name: &str) -> Result<Option<LatticeCluster>, Error>;

    /// Get a Secret by name and namespace
    async fn get_secret(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<k8s_openapi::api::core::v1::Secret>, Error>;

    /// Ensure the cell LoadBalancer Service exists
    ///
    /// Creates a LoadBalancer Service in lattice-system namespace to expose
    /// cell servers (bootstrap + gRPC) for workload cluster provisioning.
    async fn ensure_cell_service(
        &self,
        load_balancer_ip: &str,
        bootstrap_port: u16,
        grpc_port: u16,
    ) -> Result<(), Error>;

    /// Ensure the central proxy ClusterIP Service exists
    ///
    /// Creates a ClusterIP Service in lattice-system namespace to expose
    /// the central K8s API proxy. CAPI uses this to reach workload cluster APIs.
    async fn ensure_proxy_service(&self, proxy_port: u16) -> Result<(), Error>;

    /// Check if the MutatingWebhookConfiguration for LatticeService deployments exists
    async fn is_webhook_config_ready(&self) -> Result<bool, Error>;

    /// Copy a secret from one namespace to another
    ///
    /// If the secret already exists in the target namespace, this is a no-op.
    /// Used to copy provider credentials to each cluster's CAPI namespace.
    async fn copy_secret_to_namespace(
        &self,
        name: &str,
        source_namespace: &str,
        target_namespace: &str,
    ) -> Result<(), Error>;
}

/// Trait abstracting CAPI resource operations
///
/// This trait allows mocking CAPI operations in tests while using the
/// real Kubernetes client for applying manifests in production.
#[cfg_attr(test, automock)]
#[async_trait]
pub trait CAPIClient: Send + Sync {
    /// Apply CAPI manifests to provision cluster infrastructure
    ///
    /// # Arguments
    ///
    /// * `manifests` - List of CAPI manifests to apply
    /// * `namespace` - Namespace to apply manifests in
    async fn apply_manifests(
        &self,
        manifests: &[CAPIManifest],
        namespace: &str,
    ) -> Result<(), Error>;

    /// Check if CAPI infrastructure is ready for a cluster
    ///
    /// # Arguments
    ///
    /// * `cluster_name` - Name of the cluster to check
    /// * `namespace` - Namespace where CAPI resources exist
    /// * `bootstrap` - Bootstrap provider (kubeadm or rke2)
    ///
    /// # Returns
    ///
    /// True if infrastructure is ready, false otherwise
    async fn is_infrastructure_ready(
        &self,
        cluster_name: &str,
        namespace: &str,
        bootstrap: BootstrapProvider,
    ) -> Result<bool, Error>;

    /// Get the current replica count of a cluster's MachineDeployment
    ///
    /// Returns None if no MachineDeployment exists for the cluster.
    async fn get_machine_deployment_replicas(
        &self,
        cluster_name: &str,
        namespace: &str,
    ) -> Result<Option<u32>, Error>;

    /// Scale a cluster's MachineDeployment to the desired replica count
    ///
    /// Creates the MachineDeployment if it doesn't exist.
    async fn scale_machine_deployment(
        &self,
        cluster_name: &str,
        namespace: &str,
        replicas: u32,
    ) -> Result<(), Error>;
}

/// Real Kubernetes client implementation
pub struct KubeClientImpl {
    client: Client,
}

impl KubeClientImpl {
    /// Create a new KubeClientImpl wrapping the given kube Client
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl KubeClient for KubeClientImpl {
    async fn patch_status(&self, name: &str, status: &LatticeClusterStatus) -> Result<(), Error> {
        let api: Api<LatticeCluster> = Api::all(self.client.clone());

        let status_patch = serde_json::json!({
            "status": status
        });

        api.patch_status(
            name,
            &PatchParams::apply("lattice-controller"),
            &Patch::Merge(&status_patch),
        )
        .await?;

        Ok(())
    }

    async fn get_ready_worker_count(&self) -> Result<u32, Error> {
        use k8s_openapi::api::core::v1::Node;

        let api: Api<Node> = Api::all(self.client.clone());
        let nodes = api.list(&Default::default()).await?;

        let ready_workers = nodes
            .items
            .iter()
            .filter(|node| is_ready_worker_node(node))
            .count() as u32;

        Ok(ready_workers)
    }

    async fn are_control_plane_nodes_tainted(&self) -> Result<bool, Error> {
        use k8s_openapi::api::core::v1::Node;

        let api: Api<Node> = Api::all(self.client.clone());
        let nodes = api.list(&Default::default()).await?;

        // Check all control plane nodes have the NoSchedule taint
        // and all etcd nodes have the NoExecute taint (RKE2)
        for node in nodes.items.iter() {
            // Check control-plane taint
            if is_control_plane_node(node) && !has_control_plane_taint(node) {
                return Ok(false);
            }

            // Check etcd taint (RKE2 nodes)
            if is_etcd_node(node) && !has_etcd_taint(node) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn taint_control_plane_nodes(&self) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::Node;

        let api: Api<Node> = Api::all(self.client.clone());
        let nodes = api.list(&Default::default()).await?;

        for node in nodes.items.iter() {
            let is_cp = is_control_plane_node(node);
            let is_etcd = is_etcd_node(node);

            // Skip nodes that aren't control-plane or etcd
            if !is_cp && !is_etcd {
                continue;
            }

            let node_name = node
                .metadata
                .name
                .as_ref()
                .ok_or_else(|| Error::provider("node has no name".to_string()))?;

            // Build list of taints to apply based on node roles
            let mut taints_to_apply = Vec::new();

            if is_cp && !has_control_plane_taint(node) {
                taints_to_apply.push(serde_json::json!({
                    "key": "node-role.kubernetes.io/control-plane",
                    "effect": "NoSchedule"
                }));
            }

            if is_etcd && !has_etcd_taint(node) {
                taints_to_apply.push(serde_json::json!({
                    "key": "node-role.kubernetes.io/etcd",
                    "effect": "NoExecute"
                }));
            }

            if taints_to_apply.is_empty() {
                debug!(node = %node_name, "node already has required taints");
                continue;
            }

            // Apply taints (strategic merge patch adds to existing taints)
            info!(node = %node_name, taints = ?taints_to_apply, "applying taints to node");

            let patch = serde_json::json!({
                "spec": {
                    "taints": taints_to_apply
                }
            });

            api.patch(
                node_name,
                &PatchParams::apply("lattice-controller"),
                &Patch::Strategic(&patch),
            )
            .await?;

            info!(node = %node_name, "node tainted successfully");
        }

        Ok(())
    }

    async fn ensure_namespace(&self, name: &str) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::Namespace;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

        let api: Api<Namespace> = Api::all(self.client.clone());

        // Check if namespace already exists
        match api.get(name).await {
            Ok(_) => {
                debug!(namespace = %name, "namespace already exists");
                return Ok(());
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                // Namespace doesn't exist, create it
            }
            Err(e) => return Err(e.into()),
        }

        // Create the namespace
        let ns = Namespace {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                labels: Some(std::collections::BTreeMap::from([(
                    "app.kubernetes.io/managed-by".to_string(),
                    "lattice".to_string(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        };

        info!(namespace = %name, "creating namespace for CAPI resources");
        api.create(&Default::default(), &ns).await?;
        info!(namespace = %name, "namespace created");

        Ok(())
    }

    async fn get_cluster(&self, name: &str) -> Result<Option<LatticeCluster>, Error> {
        let api: Api<LatticeCluster> = Api::all(self.client.clone());
        match api.get(name).await {
            Ok(cluster) => Ok(Some(cluster)),
            Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_secret(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<k8s_openapi::api::core::v1::Secret>, Error> {
        use k8s_openapi::api::core::v1::Secret;
        let api: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        match api.get(name).await {
            Ok(secret) => Ok(Some(secret)),
            Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn copy_secret_to_namespace(
        &self,
        name: &str,
        source_namespace: &str,
        target_namespace: &str,
    ) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::Secret;

        let target_api: Api<Secret> = Api::namespaced(self.client.clone(), target_namespace);

        // Check if secret already exists in target namespace
        match target_api.get(name).await {
            Ok(_) => {
                debug!(
                    secret = %name,
                    source = %source_namespace,
                    target = %target_namespace,
                    "secret already exists in target namespace"
                );
                return Ok(());
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                // Secret doesn't exist, will copy it
            }
            Err(e) => return Err(e.into()),
        }

        // Get the source secret
        let source_secret = self
            .get_secret(name, source_namespace)
            .await?
            .ok_or_else(|| {
                Error::Bootstrap(format!(
                    "source secret {}/{} not found",
                    source_namespace, name
                ))
            })?;

        // Create a copy in the target namespace (strip server-managed fields)
        let target_secret = Secret {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(target_namespace.to_string()),
                labels: source_secret.metadata.labels.clone(),
                annotations: source_secret.metadata.annotations.clone(),
                ..Default::default()
            },
            type_: source_secret.type_.clone(),
            data: source_secret.data.clone(),
            string_data: source_secret.string_data.clone(),
            immutable: source_secret.immutable,
        };

        info!(
            secret = %name,
            source = %source_namespace,
            target = %target_namespace,
            "copying secret to target namespace"
        );
        target_api
            .create(&PostParams::default(), &target_secret)
            .await?;

        Ok(())
    }

    async fn ensure_cell_service(
        &self,
        load_balancer_ip: &str,
        bootstrap_port: u16,
        grpc_port: u16,
    ) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
        use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

        let api: Api<Service> = Api::namespaced(self.client.clone(), "lattice-system");

        let mut labels = std::collections::BTreeMap::new();
        labels.insert("app".to_string(), "lattice-operator".to_string());

        let service = Service {
            metadata: ObjectMeta {
                name: Some("lattice-cell".to_string()),
                namespace: Some("lattice-system".to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                type_: Some("LoadBalancer".to_string()),
                load_balancer_ip: Some(load_balancer_ip.to_string()),
                selector: Some(labels),
                ports: Some(vec![
                    ServicePort {
                        name: Some("bootstrap".to_string()),
                        port: bootstrap_port as i32,
                        target_port: Some(IntOrString::Int(bootstrap_port as i32)),
                        protocol: Some("TCP".to_string()),
                        ..Default::default()
                    },
                    ServicePort {
                        name: Some("grpc".to_string()),
                        port: grpc_port as i32,
                        target_port: Some(IntOrString::Int(grpc_port as i32)),
                        protocol: Some("TCP".to_string()),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };

        // Check if service exists
        match api.get("lattice-cell").await {
            Ok(_) => {
                debug!("cell service already exists");
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                info!("creating cell LoadBalancer service");
                api.create(&PostParams::default(), &service).await?;
            }
            Err(e) => return Err(e.into()),
        }

        Ok(())
    }

    async fn ensure_proxy_service(&self, proxy_port: u16) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
        use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

        let api: Api<Service> = Api::namespaced(self.client.clone(), "lattice-system");

        let mut labels = std::collections::BTreeMap::new();
        labels.insert("app".to_string(), "lattice-operator".to_string());

        let service = Service {
            metadata: ObjectMeta {
                name: Some("lattice-proxy".to_string()),
                namespace: Some("lattice-system".to_string()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                type_: Some("ClusterIP".to_string()),
                selector: Some(labels),
                ports: Some(vec![ServicePort {
                    name: Some("https".to_string()),
                    port: proxy_port as i32,
                    target_port: Some(IntOrString::Int(proxy_port as i32)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        // Check if service exists
        match api.get("lattice-proxy").await {
            Ok(_) => {
                debug!("proxy service already exists");
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                info!("creating central proxy ClusterIP service");
                api.create(&PostParams::default(), &service).await?;
            }
            Err(e) => return Err(e.into()),
        }

        Ok(())
    }

    async fn is_webhook_config_ready(&self) -> Result<bool, Error> {
        use k8s_openapi::api::admissionregistration::v1::MutatingWebhookConfiguration;

        let api: Api<MutatingWebhookConfiguration> = Api::all(self.client.clone());
        match api.get("lattice-deployment-mutator").await {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
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

    /// Discover the ApiResource for a given API version and kind using kube-rs discovery.
    ///
    /// This queries the API server to get the correct plural form and other metadata.
    async fn discover_api_resource(
        &self,
        api_version: &str,
        kind: &str,
    ) -> Result<kube::discovery::ApiResource, Error> {
        use kube::discovery::Discovery;

        let (group, version) = parse_api_version(api_version);

        // Run discovery to find the resource
        let discovery = Discovery::new(self.client.clone())
            .run()
            .await
            .map_err(|e| Error::serialization(format!("API discovery failed: {}", e)))?;

        // Search for the matching kind in the discovered resources
        for api_group in discovery.groups() {
            // Check if this is the right group
            let group_name = api_group.name();
            if group_name != group {
                continue;
            }

            // Get all resources in this group and search for our kind
            for (ar, _caps) in api_group.recommended_resources() {
                if ar.kind == kind && ar.version == version {
                    return Ok(ar.clone());
                }
            }
        }

        // If not found via discovery, fall back to constructing it manually
        // This can happen if the CRD was just installed and discovery cache is stale
        debug!(
            api_version = %api_version,
            kind = %kind,
            "Resource not found in discovery, using fallback pluralization"
        );

        Ok(kube::discovery::ApiResource {
            group: group.to_string(),
            version: version.to_string(),
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            plural: pluralize_kind(kind),
        })
    }

    /// Get API for CAPI Cluster resources
    fn capi_cluster_api(&self, namespace: &str) -> Api<kube::api::DynamicObject> {
        use kube::discovery::ApiResource;
        let ar = ApiResource {
            group: "cluster.x-k8s.io".to_string(),
            version: "v1beta1".to_string(),
            api_version: "cluster.x-k8s.io/v1beta1".to_string(),
            kind: "Cluster".to_string(),
            plural: "clusters".to_string(),
        };
        Api::namespaced_with(self.client.clone(), namespace, &ar)
    }
}

#[async_trait]
impl CAPIClient for CAPIClientImpl {
    async fn apply_manifests(
        &self,
        manifests: &[CAPIManifest],
        namespace: &str,
    ) -> Result<(), Error> {
        use kube::api::DynamicObject;

        for manifest in manifests {
            // Discover the API resource from the API server
            let ar = self
                .discover_api_resource(&manifest.api_version, &manifest.kind)
                .await?;

            // Create dynamic object from manifest
            // ConfigMaps use 'data' instead of 'spec'
            let mut obj_value = serde_json::json!({
                "apiVersion": manifest.api_version,
                "kind": manifest.kind,
                "metadata": {
                    "name": manifest.metadata.name,
                    "namespace": namespace,
                    "labels": manifest.metadata.labels,
                },
            });

            // Add spec or data depending on what the manifest has
            if let Some(ref data) = manifest.data {
                obj_value["data"] = data.clone();
            }
            if let Some(ref spec) = manifest.spec {
                obj_value["spec"] = spec.clone();
            }

            let obj: DynamicObject = serde_json::from_value(obj_value)
                .map_err(|e| Error::serialization(e.to_string()))?;

            // Apply using server-side apply
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
        let cluster_api = self.capi_cluster_api(namespace);
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

        // Check 2: Control plane is Initialized (KubeadmControlPlane or RKE2ControlPlane)
        // clusterctl move requires this before it will proceed
        let (cp_kind, cp_group) = match bootstrap {
            BootstrapProvider::Kubeadm => ("KubeadmControlPlane", "controlplane.cluster.x-k8s.io"),
            BootstrapProvider::Rke2 => ("RKE2ControlPlane", "controlplane.cluster.x-k8s.io"),
        };

        let cp_api: Api<DynamicObject> = Api::namespaced_with(
            self.client.clone(),
            namespace,
            &ApiResource::from_gvk(&GroupVersionKind {
                group: cp_group.to_string(),
                version: "v1beta1".to_string(),
                kind: cp_kind.to_string(),
            }),
        );

        let cp_name = format!("{}-control-plane", cluster_name);
        let cp_initialized = match cp_api.get(&cp_name).await {
            Ok(cp) => {
                if let Some(status) = cp.data.get("status") {
                    status
                        .get("initialized")
                        .and_then(|i| i.as_bool())
                        .unwrap_or(false)
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
        // clusterctl move will fail if any machines are in provisioning state
        let machine_api: Api<DynamicObject> = Api::namespaced_with(
            self.client.clone(),
            namespace,
            &ApiResource::from_gvk(&GroupVersionKind {
                group: "cluster.x-k8s.io".to_string(),
                version: "v1beta1".to_string(),
                kind: "Machine".to_string(),
            }),
        );

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

    async fn get_machine_deployment_replicas(
        &self,
        cluster_name: &str,
        namespace: &str,
    ) -> Result<Option<u32>, Error> {
        let api: Api<DynamicObject> = Api::namespaced_with(
            self.client.clone(),
            namespace,
            &ApiResource::from_gvk(&GroupVersionKind {
                group: "cluster.x-k8s.io".to_string(),
                version: "v1beta1".to_string(),
                kind: "MachineDeployment".to_string(),
            }),
        );

        // MachineDeployment name follows pattern: {cluster_name}-md-0
        let md_name = format!("{}-md-0", cluster_name);

        match api.get(&md_name).await {
            Ok(md) => {
                let replicas = md
                    .data
                    .get("spec")
                    .and_then(|s: &serde_json::Value| s.get("replicas"))
                    .and_then(|r: &serde_json::Value| r.as_i64())
                    .map(|r| r as u32);
                debug!(
                    cluster = %cluster_name,
                    replicas = ?replicas,
                    "Got MachineDeployment replicas"
                );
                Ok(replicas)
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(cluster = %cluster_name, "MachineDeployment not found");
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn scale_machine_deployment(
        &self,
        cluster_name: &str,
        namespace: &str,
        replicas: u32,
    ) -> Result<(), Error> {
        use kube::api::{Patch, PatchParams};

        let api: Api<DynamicObject> = Api::namespaced_with(
            self.client.clone(),
            namespace,
            &ApiResource::from_gvk(&GroupVersionKind {
                group: "cluster.x-k8s.io".to_string(),
                version: "v1beta1".to_string(),
                kind: "MachineDeployment".to_string(),
            }),
        );

        // MachineDeployment name follows pattern: {cluster_name}-md-0
        let md_name = format!("{}-md-0", cluster_name);

        let patch = serde_json::json!({
            "spec": { "replicas": replicas }
        });

        api.patch(&md_name, &PatchParams::default(), &Patch::Merge(&patch))
            .await?;

        info!(
            cluster = %cluster_name,
            replicas = replicas,
            "Scaled MachineDeployment"
        );
        Ok(())
    }
}

/// Parse API version into group and version components
fn parse_api_version(api_version: &str) -> (&str, &str) {
    if let Some(idx) = api_version.rfind('/') {
        (&api_version[..idx], &api_version[idx + 1..])
    } else {
        // Core API (e.g., "v1")
        ("", api_version)
    }
}

/// Known CAPI resource pluralizations.
///
/// Kubernetes uses non-standard pluralization rules (all lowercase, no hyphens).
/// We maintain this static map for known CAPI kinds to avoid runtime discovery
/// overhead. All CAPI kinds we generate are well-known and listed here.
///
/// If a kind is not in this map, we fall back to standard pluralization rules
/// (lowercase + 's'), which works for most Kubernetes resources.
const CAPI_KIND_PLURALS: &[(&str, &str)] = &[
    // Core CAPI types (cluster.x-k8s.io)
    ("cluster", "clusters"),
    ("machine", "machines"),
    ("machinedeployment", "machinedeployments"),
    ("machineset", "machinesets"),
    ("machinepool", "machinepools"),
    // Control plane provider (controlplane.cluster.x-k8s.io)
    ("kubeadmcontrolplane", "kubeadmcontrolplanes"),
    (
        "kubeadmcontrolplanetemplate",
        "kubeadmcontrolplanetemplates",
    ),
    // Bootstrap provider (bootstrap.cluster.x-k8s.io)
    ("kubeadmconfig", "kubeadmconfigs"),
    ("kubeadmconfigtemplate", "kubeadmconfigtemplates"),
    // Docker infrastructure provider (infrastructure.cluster.x-k8s.io)
    ("dockercluster", "dockerclusters"),
    ("dockerclustertemplate", "dockerclustertemplates"),
    ("dockermachine", "dockermachines"),
    ("dockermachinetemplate", "dockermachinetemplates"),
    ("dockermachinepool", "dockermachinepools"),
    ("dockermachinepooltemplate", "dockermachinepooltemplates"),
    // AWS infrastructure provider
    ("awscluster", "awsclusters"),
    ("awsmachine", "awsmachines"),
    ("awsmachinetemplate", "awsmachinetemplates"),
    ("awsmanagedcluster", "awsmanagedclusters"),
    ("awsmanagedmachinepool", "awsmanagedmachinepools"),
    // GCP infrastructure provider
    ("gcpcluster", "gcpclusters"),
    ("gcpmachine", "gcpmachines"),
    ("gcpmachinetemplate", "gcpmachinetemplates"),
    // Azure infrastructure provider
    ("azurecluster", "azureclusters"),
    ("azuremachine", "azuremachines"),
    ("azuremachinetemplate", "azuremachinetemplates"),
    ("azuremanagedcluster", "azuremanagedclusters"),
    ("azuremanagedmachinepool", "azuremanagedmachinepools"),
    // IPAddress management (ipam.cluster.x-k8s.io)
    ("ipaddress", "ipaddresses"),
    ("ipaddressclaim", "ipaddressclaims"),
];

/// Convert a Kind to its plural form for Kubernetes API resources.
///
/// Uses a static lookup for known CAPI kinds, falling back to standard
/// pluralization (lowercase + 's') for unknown kinds.
fn pluralize_kind(kind: &str) -> String {
    let lower = kind.to_lowercase();

    // Look up in known CAPI kinds
    for (singular, plural) in CAPI_KIND_PLURALS {
        if *singular == lower {
            return (*plural).to_string();
        }
    }

    // Fallback: simple pluralization (works for most K8s resources)
    // Handles common patterns: deployment->deployments, service->services
    if lower.ends_with('s') || lower.ends_with("ch") || lower.ends_with("sh") {
        format!("{}es", lower)
    } else if lower.ends_with('y') && !lower.ends_with("ay") && !lower.ends_with("ey") {
        // policy -> policies, but not gateway -> gateways
        format!("{}ies", &lower[..lower.len() - 1])
    } else {
        format!("{}s", lower)
    }
}

// =============================================================================
// Pure Functions - Extracted for Unit Testability
// =============================================================================
// These functions contain pure decision logic with no I/O. They can be
// thoroughly unit tested without mocking Kubernetes or network connections.

/// Check if the cluster being reconciled is the cluster we're running on.
///
/// When true, we skip provisioning since we ARE this cluster.
pub fn is_self_cluster(cluster_name: &str, self_cluster_name: Option<&str>) -> bool {
    self_cluster_name
        .map(|self_name| self_name == cluster_name)
        .unwrap_or(false)
}

/// Check if a node is a control plane node based on labels.
pub fn is_control_plane_node(node: &k8s_openapi::api::core::v1::Node) -> bool {
    node.metadata
        .labels
        .as_ref()
        .map(|l| l.contains_key("node-role.kubernetes.io/control-plane"))
        .unwrap_or(false)
}

/// Check if a node has the Ready condition set to True.
pub fn is_node_ready(node: &k8s_openapi::api::core::v1::Node) -> bool {
    node.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .map(|conds| {
            conds
                .iter()
                .any(|c| c.type_ == "Ready" && c.status == "True")
        })
        .unwrap_or(false)
}

/// Check if a node is a ready worker (not control plane and Ready).
///
/// This is used to count ready workers for scaling decisions.
pub fn is_ready_worker_node(node: &k8s_openapi::api::core::v1::Node) -> bool {
    !is_control_plane_node(node) && is_node_ready(node)
}

/// Check if a control plane node has the NoSchedule taint.
pub fn has_control_plane_taint(node: &k8s_openapi::api::core::v1::Node) -> bool {
    node.spec
        .as_ref()
        .and_then(|s| s.taints.as_ref())
        .map(|taints| {
            taints.iter().any(|t| {
                t.key == "node-role.kubernetes.io/control-plane" && t.effect == "NoSchedule"
            })
        })
        .unwrap_or(false)
}

/// Check if a node is an etcd node by looking for the etcd role label.
/// RKE2 uses this label to identify nodes running etcd.
pub fn is_etcd_node(node: &k8s_openapi::api::core::v1::Node) -> bool {
    node.metadata
        .labels
        .as_ref()
        .map(|labels| labels.contains_key("node-role.kubernetes.io/etcd"))
        .unwrap_or(false)
}

/// Check if an etcd node has the NoExecute taint.
/// RKE2 applies this taint to etcd nodes by default.
pub fn has_etcd_taint(node: &k8s_openapi::api::core::v1::Node) -> bool {
    node.spec
        .as_ref()
        .and_then(|s| s.taints.as_ref())
        .map(|taints| {
            taints
                .iter()
                .any(|t| t.key == "node-role.kubernetes.io/etcd" && t.effect == "NoExecute")
        })
        .unwrap_or(false)
}

/// Actions that can be taken during the pivot phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PivotAction {
    /// Pivot is complete, transition to Ready
    Complete,
    /// Execute clusterctl move (agent ready with proxy)
    ExecuteMove,
    /// Wait for agent proxy to become available
    WaitForProxy,
    /// Send StartPivotCommand to agent
    SendPivotCommand,
    /// Wait for agent to connect
    WaitForAgent,
}

/// Determine what pivot action to take based on current state.
///
/// This encapsulates the pivot state machine logic in a pure function.
pub fn determine_pivot_action(
    is_pivot_complete: bool,
    is_pivot_in_progress: bool,
    is_proxy_available: bool,
    is_agent_connected: bool,
) -> PivotAction {
    if is_pivot_complete {
        PivotAction::Complete
    } else if is_pivot_in_progress && is_proxy_available {
        PivotAction::ExecuteMove
    } else if is_pivot_in_progress {
        PivotAction::WaitForProxy
    } else if is_agent_connected {
        PivotAction::SendPivotCommand
    } else {
        PivotAction::WaitForAgent
    }
}

// =============================================================================
// End Pure Functions
// =============================================================================

/// Trait abstracting pivot operations for testability
#[cfg_attr(test, automock)]
#[async_trait]
pub trait PivotOperations: Send + Sync {
    /// Trigger pivot for a cluster via connected agent
    ///
    /// Sends StartPivotCommand to the agent and executes clusterctl move
    async fn trigger_pivot(
        &self,
        cluster_name: &str,
        source_namespace: &str,
        target_namespace: &str,
    ) -> Result<(), Error>;

    /// Check if agent is ready for pivot
    fn is_agent_ready(&self, cluster_name: &str) -> bool;

    /// Check if pivot is already in progress
    fn is_pivot_in_progress(&self, cluster_name: &str) -> bool;

    /// Check if pivot is complete (agent reports Ready state)
    fn is_pivot_complete(&self, cluster_name: &str) -> bool;

    /// Check if the agent's K8s API proxy is available
    fn is_proxy_available(&self, cluster_name: &str) -> bool;

    /// Execute clusterctl move through the agent's K8s API proxy
    ///
    /// This starts a local proxy server, generates a kubeconfig pointing to it,
    /// and executes `clusterctl move --to-kubeconfig <proxy-kubeconfig>`.
    async fn execute_clusterctl_move(
        &self,
        cluster_name: &str,
        namespace: &str,
    ) -> Result<(), Error>;

    /// Store post-pivot manifests to send after PivotComplete
    ///
    /// These manifests (LatticeCluster CRD + resource + GitOps resources + network policy)
    /// will be sent to the agent via ApplyManifestsCommand after pivot succeeds.
    fn store_post_pivot_manifests(
        &self,
        cluster_name: &str,
        crd_yaml: Option<String>,
        cluster_yaml: Option<String>,
        flux_manifests: Vec<String>,
        network_policy_yaml: Option<String>,
    );
}

/// Controller context containing shared state and clients
///
/// The context is shared across all reconciliation calls and holds
/// resources that are expensive to create (like Kubernetes clients).
///
/// CAPI resources are created in per-cluster namespaces (`capi-{cluster_name}`)
/// to enable clean pivot operations.
///
/// Use [`ContextBuilder`] to construct instances:
///
/// ```text
/// let ctx = Context::builder(client)
///     .parent_servers(servers)
///     .build();
/// ```
pub struct Context {
    /// Kubernetes client for API operations (trait object for testability)
    pub kube: Arc<dyn KubeClient>,
    /// CAPI client for applying manifests
    pub capi: Arc<dyn CAPIClient>,
    /// CAPI installer for installing CAPI and providers
    pub capi_installer: Arc<dyn CapiInstaller>,
    /// Cell servers (started at application startup)
    pub parent_servers: Option<Arc<ParentServers<DefaultManifestGenerator>>>,
    /// Name of the cluster this controller is running on (from LATTICE_CLUSTER_NAME env var)
    /// When reconciling this cluster, we skip provisioning since we ARE this cluster
    pub self_cluster_name: Option<String>,
}

impl Context {
    /// Create a builder for constructing a Context
    pub fn builder(client: Client) -> ContextBuilder {
        ContextBuilder::new(client)
    }

    /// Create a new controller context with the given Kubernetes client
    ///
    /// This is a convenience method equivalent to `Context::builder(client).build()`.
    pub fn new(client: Client) -> Self {
        Self::builder(client).build()
    }

    /// Create a new controller context with cell servers for dynamic startup
    ///
    /// Cell servers will start automatically when Pending LatticeCluster CRDs are detected.
    /// Cell endpoint configuration is read from the LatticeCluster CRD's spec.endpoints.
    pub fn new_with_cell(
        client: Client,
        parent_servers: Arc<ParentServers<DefaultManifestGenerator>>,
    ) -> Self {
        Self::builder(client).parent_servers(parent_servers).build()
    }

    /// Create a context for testing with custom mock clients
    ///
    /// This method is primarily for unit tests where a real Kubernetes
    /// client is not available. For production code, use [`Context::builder`].
    #[cfg(test)]
    pub fn for_testing(
        kube: Arc<dyn KubeClient>,
        capi: Arc<dyn CAPIClient>,
        capi_installer: Arc<dyn CapiInstaller>,
    ) -> Self {
        Self {
            kube,
            capi,
            capi_installer,
            parent_servers: None,
            self_cluster_name: None,
        }
    }
}

/// Builder for constructing [`Context`] instances
///
/// # Examples
///
/// Basic context for agent mode:
/// ```text
/// let ctx = Context::builder(client).build();
/// ```
///
/// Full cell context:
/// ```text
/// let ctx = Context::builder(client)
///     .parent_servers(servers)
///     .build();
/// ```
///
/// Testing with mock clients:
/// ```text
/// let ctx = Context::builder(client)
///     .kube_client(mock_kube)
///     .capi_client(mock_capi)
///     .build();
/// ```
pub struct ContextBuilder {
    client: Client,
    kube: Option<Arc<dyn KubeClient>>,
    capi: Option<Arc<dyn CAPIClient>>,
    capi_installer: Option<Arc<dyn CapiInstaller>>,
    parent_servers: Option<Arc<ParentServers<DefaultManifestGenerator>>>,
    self_cluster_name: Option<String>,
}

impl ContextBuilder {
    /// Create a new builder with the given Kubernetes client
    fn new(client: Client) -> Self {
        Self {
            client,
            kube: None,
            capi: None,
            capi_installer: None,
            parent_servers: None,
            self_cluster_name: None,
        }
    }

    /// Set the cluster name this controller is running on (from LATTICE_CLUSTER_NAME env var)
    pub fn self_cluster_name(mut self, name: impl Into<String>) -> Self {
        self.self_cluster_name = Some(name.into());
        self
    }

    /// Override the Kubernetes client (primarily for testing)
    pub fn kube_client(mut self, kube: Arc<dyn KubeClient>) -> Self {
        self.kube = Some(kube);
        self
    }

    /// Override the CAPI client (primarily for testing)
    pub fn capi_client(mut self, capi: Arc<dyn CAPIClient>) -> Self {
        self.capi = Some(capi);
        self
    }

    /// Override the CAPI installer (primarily for testing)
    pub fn capi_installer(mut self, installer: Arc<dyn CapiInstaller>) -> Self {
        self.capi_installer = Some(installer);
        self
    }

    /// Set cell servers for on-demand startup
    pub fn parent_servers(mut self, servers: Arc<ParentServers<DefaultManifestGenerator>>) -> Self {
        self.parent_servers = Some(servers);
        self
    }

    /// Build the Context
    pub fn build(self) -> Context {
        use crate::capi::ClusterctlInstaller;

        Context {
            kube: self
                .kube
                .unwrap_or_else(|| Arc::new(KubeClientImpl::new(self.client.clone()))),
            capi: self
                .capi
                .unwrap_or_else(|| Arc::new(CAPIClientImpl::new(self.client.clone()))),
            capi_installer: self
                .capi_installer
                .unwrap_or_else(|| Arc::new(ClusterctlInstaller::new())),
            parent_servers: self.parent_servers,
            self_cluster_name: self.self_cluster_name,
        }
    }
}

/// Reconcile a LatticeCluster resource
///
/// This function implements the main reconciliation loop for LatticeCluster.
/// It observes the current state, determines the desired state, and makes
/// incremental changes to converge on the desired state.
///
/// # Arguments
///
/// * `cluster` - The LatticeCluster resource to reconcile
/// * `ctx` - Shared controller context
///
/// # Returns
///
/// Returns an `Action` indicating when to requeue the resource, or an error
/// if reconciliation failed.
#[instrument(skip(cluster, ctx), fields(cluster = %cluster.name_any()))]
pub async fn reconcile(cluster: Arc<LatticeCluster>, ctx: Arc<Context>) -> Result<Action, Error> {
    let name = cluster.name_any();
    info!("reconciling cluster");

    // Validate the cluster spec
    if let Err(e) = cluster.spec.validate() {
        warn!(error = %e, "cluster validation failed");
        update_cluster_status(
            &cluster,
            &ctx,
            ClusterPhase::Failed,
            Some(&e.to_string()),
            false,
        )
        .await?;
        // Don't requeue for validation errors - they require spec changes
        return Ok(Action::await_change());
    }

    // Check if we're reconciling our own cluster (the one we're running on)
    // This is critical: the ClusterController should only do full reconciliation
    // (worker scaling, tainting, etc.) for its OWN cluster. For workload clusters
    // provisioned by this cell, we only handle CAPI provisioning and pivot.
    let is_self = is_self_cluster(&name, ctx.self_cluster_name.as_deref());

    // Get current status, defaulting to Pending if not set
    let current_phase = cluster
        .status
        .as_ref()
        .map(|s| s.phase.clone())
        .unwrap_or(ClusterPhase::Pending);

    debug!(?current_phase, is_self, "current cluster phase");

    // State machine: transition based on current phase
    match current_phase {
        ClusterPhase::Pending => {
            // Check if we're the management cluster (have cell spec)
            // This must happen BEFORE the self-cluster check so the management cluster
            // gets its LoadBalancer service created even when reconciling itself.

            // Create LoadBalancer Service if this cluster has a cell spec
            // This exposes cell servers for workload clusters to reach bootstrap + gRPC endpoints
            // Note: Cell servers are started at application startup, not on-demand
            if let Some(ref cell_spec) = cluster.spec.endpoints {
                info!(host = %cell_spec.host, "ensuring LoadBalancer Service for cell servers");
                ctx.kube
                    .ensure_cell_service(
                        &cell_spec.host,
                        cell_spec.bootstrap_port,
                        cell_spec.grpc_port,
                    )
                    .await?;
                info!("cell LoadBalancer Service created/updated");

                // Create ClusterIP Service for central K8s API proxy
                // CAPI uses this to reach workload cluster APIs via their path
                info!("ensuring ClusterIP Service for central proxy");
                ctx.kube
                    .ensure_proxy_service(crate::agent::proxy::CENTRAL_PROXY_PORT)
                    .await?;
                info!("central proxy ClusterIP Service created/updated");
            }

            // Check if we're reconciling our own cluster (the one we're running on)
            // If so, skip provisioning - we ARE this cluster, we don't need to create it
            // But we need to wait for CAPI resources to exist (from pivot) before going Ready
            if is_self {
                let capi_namespace = format!("capi-{}", name);

                // First check if CAPI resources exist (from pivot)
                // Don't try to patch kubeconfig until pivot has completed
                let bootstrap = cluster.spec.provider.kubernetes.bootstrap.clone();
                let capi_ready = ctx
                    .capi
                    .is_infrastructure_ready(&name, &capi_namespace, bootstrap)
                    .await
                    .unwrap_or(false);

                if !capi_ready {
                    debug!("self-cluster waiting for CAPI resources (pivot not complete yet)");
                    return Ok(Action::requeue(Duration::from_secs(10)));
                }

                // CAPI resources exist - now patch kubeconfig for self-management
                // CAPI needs to reach itself via kubernetes.default.svc, not external IP
                info!("CAPI resources found, patching kubeconfig for self-management");
                let cluster_name = name.clone();
                let namespace = capi_namespace.clone();
                let patch_result =
                    crate::retry::retry_with_backoff(
                        &crate::retry::RetryConfig::with_max_attempts(10),
                        "patch_kubeconfig_for_self_management",
                        || {
                            let cn = cluster_name.clone();
                            let ns = namespace.clone();
                            async move {
                                crate::pivot::patch_kubeconfig_for_self_management(&cn, &ns).await
                            }
                        },
                    )
                    .await;

                if let Err(e) = patch_result {
                    warn!(error = %e, "Failed to patch kubeconfig for self-management after retries");
                    return Ok(Action::requeue(Duration::from_secs(10)));
                }

                info!("self-cluster has CAPI resources ready");
                return try_transition_to_ready(&cluster, &ctx, true).await;
            }

            // Ensure CAPI is installed before provisioning
            info!("ensuring CAPI is installed for provider");
            let capi_config = CapiProviderConfig::new(cluster.spec.provider.provider_type())?;
            ensure_capi_installed(ctx.capi_installer.as_ref(), &capi_config).await?;

            // Generate and apply CAPI manifests, then transition to Provisioning
            info!("generating CAPI manifests for cluster");

            // Each cluster gets its own CAPI namespace for pivot isolation
            let capi_namespace = format!("capi-{}", name);

            // Ensure the namespace exists
            ctx.kube.ensure_namespace(&capi_namespace).await?;

            // Copy provider credentials to cluster namespace
            // This avoids race conditions when multiple clusters share credentials
            let provider = create_provider(cluster.spec.provider.provider_type(), &capi_namespace)?;
            for (secret_name, source_namespace) in provider.required_secrets(&cluster) {
                ctx.kube
                    .copy_secret_to_namespace(&secret_name, &source_namespace, &capi_namespace)
                    .await?;
            }

            // Get the appropriate provider based on cluster spec
            let manifests = generate_capi_manifests(&cluster, &ctx).await?;

            // Apply CAPI manifests to the cluster-specific namespace
            info!(count = manifests.len(), namespace = %capi_namespace, "applying CAPI manifests");
            ctx.capi
                .apply_manifests(&manifests, &capi_namespace)
                .await?;

            // Update status to Provisioning
            info!("transitioning to Provisioning phase");
            update_cluster_status(&cluster, &ctx, ClusterPhase::Provisioning, None, false).await?;
            Ok(Action::requeue(Duration::from_secs(5)))
        }
        ClusterPhase::Provisioning => {
            // Check if CAPI infrastructure is ready
            debug!("checking infrastructure status");

            // Each cluster gets its own CAPI namespace
            let capi_namespace = format!("capi-{}", name);

            // For child clusters, patch kubeconfig to use central proxy when agent connects
            // This allows CAPI to reach the workload cluster's API server
            if !is_self {
                if let Some(ref parent_servers) = ctx.parent_servers {
                    if parent_servers.is_running()
                        && parent_servers
                            .agent_registry()
                            .get_proxy_channels(&name)
                            .is_some()
                    {
                        // Proxy channels registered = agent connected, patch kubeconfig
                        let ca_cert_pem = parent_servers.ca().ca_cert_pem();
                        if let Err(e) = crate::pivot::patch_kubeconfig_for_child_cluster(
                            &name,
                            &capi_namespace,
                            crate::pivot::CENTRAL_PROXY_SERVICE_URL,
                            ca_cert_pem,
                        )
                        .await
                        {
                            debug!(error = %e, "Failed to patch kubeconfig for child cluster (may already be patched)");
                        }
                    }
                }
            }

            let bootstrap = cluster.spec.provider.kubernetes.bootstrap.clone();
            let is_ready = ctx
                .capi
                .is_infrastructure_ready(&name, &capi_namespace, bootstrap)
                .await?;

            if is_ready {
                // Infrastructure is ready, transition to Pivoting
                info!("infrastructure ready, transitioning to Pivoting phase");
                update_cluster_status(&cluster, &ctx, ClusterPhase::Pivoting, None, false).await?;
                Ok(Action::requeue(Duration::from_secs(5)))
            } else {
                // Still provisioning, requeue
                debug!("infrastructure not ready yet");
                Ok(Action::requeue(Duration::from_secs(30)))
            }
        }
        ClusterPhase::Pivoting => {
            // Each cluster gets its own CAPI namespace
            let capi_namespace = format!("capi-{}", name);

            // Check if pivot was already completed (persisted in status)
            // This handles controller restarts - we don't need to wait for agent reconnection
            if cluster
                .status
                .as_ref()
                .map(|s| s.pivot_complete)
                .unwrap_or(false)
            {
                info!("pivot already complete (from status)");
                return try_transition_to_ready(&cluster, &ctx, false).await;
            }

            // If we're reconciling our own LatticeCluster, pivot was already completed.
            // We received this CRD post-pivot (via ApplyManifestsCommand from parent or installer).
            if is_self_cluster(&name, ctx.self_cluster_name.as_deref()) {
                info!("reconciling self cluster, pivot already complete");
                return try_transition_to_ready(&cluster, &ctx, true).await;
            }

            // We're the parent cell, orchestrating pivot for a child cluster
            // Get pivot operations from parent_servers
            let pivot_ops: Option<Arc<dyn PivotOperations>> =
                if let Some(ref parent_servers) = ctx.parent_servers {
                    if parent_servers.is_running() {
                        Some(Arc::new(PivotOperationsImpl::new(
                            parent_servers.agent_registry(),
                            parent_servers.ca().ca_cert_pem().to_string(),
                        )))
                    } else {
                        None
                    }
                } else {
                    None
                };

            // Check if we have pivot operations configured (cell mode)
            if let Some(pivot_ops) = pivot_ops {
                // Determine pivot action using pure function
                let action = determine_pivot_action(
                    pivot_ops.is_pivot_complete(&name),
                    pivot_ops.is_pivot_in_progress(&name),
                    pivot_ops.is_proxy_available(&name),
                    pivot_ops.is_agent_ready(&name),
                );

                match action {
                    PivotAction::Complete => {
                        // Agent reports pivot complete - try to transition to Ready
                        info!("agent reports pivot complete");
                        try_transition_to_ready(&cluster, &ctx, true).await
                    }
                    PivotAction::ExecuteMove => {
                        // Agent in pivoting state with proxy available - execute clusterctl move
                        info!(
                            "agent in pivoting state with proxy available, executing clusterctl move"
                        );
                        match pivot_ops
                            .execute_clusterctl_move(&name, &capi_namespace)
                            .await
                        {
                            Ok(()) => {
                                info!("clusterctl move completed, waiting for agent to confirm");
                            }
                            Err(e) => {
                                warn!(error = %e, "clusterctl move failed, will retry");
                            }
                        }
                        Ok(Action::requeue(Duration::from_secs(10)))
                    }
                    PivotAction::WaitForProxy => {
                        // Pivot in progress but proxy not ready yet
                        debug!("pivot in progress, waiting for agent proxy to be available");
                        Ok(Action::requeue(Duration::from_secs(5)))
                    }
                    PivotAction::SendPivotCommand => {
                        // Agent ready for pivot - trigger it
                        // Store post-pivot manifests before triggering pivot
                        use kube::CustomResourceExt;
                        let crd_yaml = serde_yaml::to_string(&LatticeCluster::crd())
                            .map_err(|e| Error::serialization(e.to_string()))?;
                        // Use for_export() to strip managedFields and other server-set metadata
                        let cluster_yaml = serde_yaml::to_string(&cluster.for_export())
                            .map_err(|e| Error::serialization(e.to_string()))?;

                        // Generate GitOps manifests if parent has GitOps config
                        let flux_manifests = generate_flux_manifests_for_child(&ctx, &name).await?;

                        // Generate CiliumNetworkPolicy for operator (requires Cilium CRDs)
                        let network_policy_yaml = generate_network_policy_for_child(&ctx).await?;

                        pivot_ops.store_post_pivot_manifests(
                            &name,
                            Some(crd_yaml),
                            Some(cluster_yaml),
                            flux_manifests,
                            network_policy_yaml,
                        );

                        // Trigger pivot (sends StartPivotCommand)
                        info!("agent ready, triggering pivot");
                        match pivot_ops
                            .trigger_pivot(&name, &capi_namespace, &capi_namespace)
                            .await
                        {
                            Ok(()) => {
                                debug!("pivot triggered successfully, waiting for agent to enter pivoting state");
                            }
                            Err(e) => {
                                warn!(error = %e, "pivot trigger failed, will retry");
                            }
                        }
                        Ok(Action::requeue(Duration::from_secs(5)))
                    }
                    PivotAction::WaitForAgent => {
                        // No agent connected yet, wait
                        debug!("waiting for agent to connect and be ready for pivot");
                        Ok(Action::requeue(Duration::from_secs(10)))
                    }
                }
            } else {
                // No pivot operations - this is a non-cell mode
                debug!("no pivot operations configured");
                try_transition_to_ready(&cluster, &ctx, false).await
            }
        }
        ClusterPhase::Ready => {
            // Only do full reconciliation (worker scaling, tainting) for our OWN cluster.
            // For workload clusters we provisioned, they are now self-managing after pivot.
            // The CAPI resources have been moved to the workload cluster.
            if !is_self {
                debug!("cluster is ready (post-pivot), monitoring only - workload cluster is self-managing");
                return Ok(Action::requeue(Duration::from_secs(60)));
            }

            // Self-cluster: reconcile worker count and ensure control plane is tainted
            debug!("cluster is ready, reconciling worker count");

            // Each cluster has its own CAPI namespace
            let capi_namespace = format!("capi-{}", name);

            // Get desired worker count from spec
            let desired_workers = cluster.spec.nodes.workers;

            // Get current MachineDeployment replica count (desired by CAPI)
            let current_replicas = ctx
                .capi
                .get_machine_deployment_replicas(&name, &capi_namespace)
                .await
                .unwrap_or(None);

            // Scale MachineDeployment if replicas don't match spec
            // MachineDeployment always exists (created with replicas=0 if workers=0)
            if let Some(replicas) = current_replicas {
                if replicas != desired_workers {
                    info!(
                        current = replicas,
                        desired = desired_workers,
                        "Scaling MachineDeployment to match spec"
                    );
                    if let Err(e) = ctx
                        .capi
                        .scale_machine_deployment(&name, &capi_namespace, desired_workers)
                        .await
                    {
                        warn!(error = %e, "Failed to scale MachineDeployment, will retry");
                        return Ok(Action::requeue(Duration::from_secs(10)));
                    }
                }
            } else {
                // MachineDeployment not found - this shouldn't happen as we always create it
                warn!(
                    "MachineDeployment not found for cluster {}, will retry",
                    name
                );
                return Ok(Action::requeue(Duration::from_secs(10)));
            }

            // Get current ready worker count (actual running nodes)
            let ready_workers = ctx.kube.get_ready_worker_count().await.unwrap_or(0);

            debug!(
                desired = desired_workers,
                ready = ready_workers,
                "worker node status"
            );

            // If workers match spec, ensure control plane is tainted
            if ready_workers >= desired_workers {
                // Check if control plane nodes need tainting
                let tainted = ctx
                    .kube
                    .are_control_plane_nodes_tainted()
                    .await
                    .unwrap_or(true);

                if !tainted {
                    info!(
                        workers = ready_workers,
                        "workers ready, re-tainting control plane nodes"
                    );

                    if let Err(e) = ctx.kube.taint_control_plane_nodes().await {
                        warn!(error = %e, "failed to taint control plane nodes, will retry");
                    } else {
                        info!("control plane nodes tainted successfully");
                    }
                }

                Ok(Action::requeue(Duration::from_secs(60)))
            } else {
                // Workers not ready yet (CAPI still provisioning), poll faster
                debug!(
                    desired = desired_workers,
                    ready = ready_workers,
                    "waiting for workers to be provisioned by CAPI"
                );
                Ok(Action::requeue(Duration::from_secs(10)))
            }
        }
        ClusterPhase::Failed => {
            // Failed state requires manual intervention
            warn!("cluster is in Failed state, awaiting spec change");
            Ok(Action::await_change())
        }
    }
}

/// Try to transition cluster to Ready phase
///
/// Returns Ok(Action) if transitioned or needs requeue, Err if status update failed.
/// The cluster should not transition to Ready until:
/// 1. Cell servers are running (webhook endpoint is listening)
/// 2. MutatingWebhookConfiguration exists (K8s will route to webhook)
async fn try_transition_to_ready(
    cluster: &LatticeCluster,
    ctx: &Context,
    set_pivot_complete: bool,
) -> Result<Action, Error> {
    // Check cell servers are running (only if configured)
    // If parent_servers is None, we're in test mode or special configuration - skip check
    if let Some(ref parent_servers) = ctx.parent_servers {
        if !parent_servers.is_running() {
            debug!("cell servers not running yet, waiting before Ready");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    }

    // Check MutatingWebhookConfiguration exists
    match ctx.kube.is_webhook_config_ready().await {
        Ok(true) => {
            debug!("webhook configuration ready");
        }
        Ok(false) => {
            debug!("webhook configuration not found yet, waiting before Ready");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
        Err(e) => {
            warn!(error = %e, "failed to check webhook configuration, waiting");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    }

    // Webhook is ready, transition to Ready
    info!("webhook ready, transitioning cluster to Ready phase");
    update_cluster_status(cluster, ctx, ClusterPhase::Ready, None, set_pivot_complete).await?;
    Ok(Action::requeue(Duration::from_secs(60)))
}

/// Generate CAPI manifests for a cluster based on its provider type
async fn generate_capi_manifests(
    cluster: &LatticeCluster,
    ctx: &Context,
) -> Result<Vec<CAPIManifest>, Error> {
    use crate::provider::BootstrapInfo;

    // Each cluster gets its own CAPI namespace for pivot isolation
    let cluster_name = cluster
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| Error::validation("cluster must have a name"))?;
    let capi_namespace = format!("capi-{}", cluster_name);

    // Build bootstrap info - if parent_servers is running, we're a cell provisioning a cluster
    // that needs to connect back to us. During root install, LATTICE_ROOT_INSTALL=true skips this.
    let is_root_install = std::env::var("LATTICE_ROOT_INSTALL").is_ok();
    let running_parent_servers = if is_root_install {
        None
    } else {
        ctx.parent_servers.as_ref().filter(|s| s.is_running())
    };
    let bootstrap = if let Some(parent_servers) = running_parent_servers {
        let self_cluster_name = ctx.self_cluster_name.as_ref().ok_or_else(|| {
            Error::validation("self_cluster_name required when parent_servers is configured")
        })?;
        let self_cluster = ctx
            .kube
            .get_cluster(self_cluster_name)
            .await?
            .ok_or_else(|| Error::Bootstrap("self-cluster LatticeCluster not found".into()))?;
        let endpoints = self_cluster.spec.endpoints.as_ref().ok_or_else(|| {
            Error::validation("self-cluster must have spec.endpoints to provision clusters")
        })?;

        // Get bootstrap state from parent_servers
        let bootstrap_state = parent_servers.bootstrap_state().await.ok_or_else(|| {
            Error::Bootstrap("parent_servers running but bootstrap_state not available".into())
        })?;

        let ca_cert = bootstrap_state.ca_cert_pem().to_string();
        let cell_endpoint = endpoints.endpoint();
        let bootstrap_endpoint = endpoints.bootstrap_endpoint();

        // Serialize the LatticeCluster CRD to pass to workload cluster
        let cluster_manifest =
            serde_json::to_string(&cluster.for_export()).map_err(|e| Error::Serialization {
                message: format!("failed to serialize cluster: {}", e),
                kind: Some("LatticeCluster".to_string()),
            })?;

        // Register cluster and get token
        let proxmox_ipv4_pool = cluster
            .spec
            .provider
            .config
            .proxmox
            .as_ref()
            .map(|p| p.ipv4_pool.clone());
        let registration = crate::bootstrap::ClusterRegistration {
            cluster_id: cluster_name.to_string(),
            cell_endpoint: cell_endpoint.clone(),
            ca_certificate: ca_cert.clone(),
            cluster_manifest,
            networking: cluster.spec.networking.clone(),
            proxmox_ipv4_pool,
            provider: cluster.spec.provider.provider_type().to_string(),
            bootstrap: cluster.spec.provider.kubernetes.bootstrap.clone(),
        };
        let token = bootstrap_state.register_cluster(registration, false);

        BootstrapInfo::new(bootstrap_endpoint, token.as_str().to_string(), ca_cert)
    } else {
        // No parent_servers - self-provisioning (management cluster bootstrap)
        BootstrapInfo::default()
    };

    let provider = create_provider(cluster.spec.provider.provider_type(), &capi_namespace)?;
    provider.generate_capi_manifests(cluster, &bootstrap).await
}

/// Generate Flux GitOps manifests for a child cluster
///
/// Reads the parent cluster's GitOps config and credentials from the referenced Secret,
/// then generates the manifests that will be applied to the child cluster after pivot.
async fn generate_flux_manifests_for_child(
    ctx: &Context,
    child_name: &str,
) -> Result<Vec<String>, Error> {
    use crate::infra::ResolvedGitCredentials;

    // Get parent cluster's GitOps config
    let Some(ref self_name) = ctx.self_cluster_name else {
        return Ok(Vec::new());
    };

    let Some(parent_cluster) = ctx.kube.get_cluster(self_name).await? else {
        return Ok(Vec::new());
    };

    let Some(ref endpoints) = parent_cluster.spec.endpoints else {
        return Ok(Vec::new());
    };

    let Some(ref gitops) = endpoints.gitops else {
        return Ok(Vec::new());
    };

    // Read credentials from Secret if referenced
    let credentials = if let Some(ref secret_ref) = gitops.secret_ref {
        if let Some(secret) = ctx
            .kube
            .get_secret(&secret_ref.name, &secret_ref.namespace)
            .await?
        {
            let data = secret.data.unwrap_or_default();
            Some(ResolvedGitCredentials {
                ssh_identity: data.get("identity").map(|v| base64_encode(&v.0)),
                ssh_known_hosts: data.get("known_hosts").map(|v| base64_encode(&v.0)),
                https_username: data.get("username").map(|v| base64_encode(&v.0)),
                https_password: data.get("password").map(|v| base64_encode(&v.0)),
            })
        } else {
            warn!(
                secret = %secret_ref.name,
                namespace = %secret_ref.namespace,
                "GitOps secret not found, generating manifests without credentials"
            );
            None
        }
    } else {
        None
    };

    Ok(crate::infra::generate_gitops_resources(
        gitops,
        child_name,
        credentials.as_ref(),
    ))
}

/// Base64 encode bytes for Secret data
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Generate CiliumNetworkPolicy for child cluster's operator
///
/// Reads the parent cluster's endpoint config and generates a network policy
/// that allows the child's operator to communicate with its parent cell.
/// This is applied post-pivot when Cilium CRDs are available.
async fn generate_network_policy_for_child(ctx: &Context) -> Result<Option<String>, Error> {
    // Get parent cluster's endpoint
    let Some(ref self_name) = ctx.self_cluster_name else {
        return Ok(None);
    };

    let Some(parent_cluster) = ctx.kube.get_cluster(self_name).await? else {
        return Ok(None);
    };

    let Some(ref endpoints) = parent_cluster.spec.endpoints else {
        return Ok(None);
    };

    // Parse cell_endpoint: host:http_port:grpc_port
    let cell_endpoint = endpoints.endpoint();
    let parts: Vec<&str> = cell_endpoint.split(':').collect();
    if parts.len() != 3 {
        warn!(
            cell_endpoint = %cell_endpoint,
            "Invalid cell_endpoint format, expected host:http_port:grpc_port"
        );
        return Ok(None);
    }

    let parent_host = parts[0];
    let grpc_port: u16 = parts[2].parse().map_err(|_| {
        Error::validation(format!("Invalid gRPC port in cell_endpoint: {}", parts[2]))
    })?;

    Ok(Some(crate::infra::generate_operator_network_policy(
        Some(parent_host),
        grpc_port,
    )))
}

/// Error policy for the controller
///
/// This function is called when reconciliation fails. It determines
/// the requeue strategy using exponential backoff.
///
/// # Arguments
///
/// * `cluster` - The LatticeCluster that failed reconciliation
/// * `error` - The error that occurred
/// * `_ctx` - Shared controller context (unused but required by signature)
///
/// # Returns
///
/// Returns an `Action` to requeue the resource after a delay.
pub fn error_policy(cluster: Arc<LatticeCluster>, error: &Error, _ctx: Arc<Context>) -> Action {
    error!(
        ?error,
        cluster = %cluster.name_any(),
        "reconciliation failed"
    );

    // Exponential backoff: start at 5 seconds
    // In a full implementation, we would track retry count and increase delay
    Action::requeue(Duration::from_secs(5))
}

/// Update cluster status to the specified phase
///
/// This consolidates the status update logic for all phases. For Failed phase,
/// pass a custom error message. For other phases, pass None for the message.
///
/// # Arguments
///
/// * `cluster` - The cluster to update
/// * `ctx` - Controller context
/// * `phase` - The new phase to set
/// * `error_message` - Optional error message (for Failed phase)
/// * `set_pivot_complete` - Whether to set pivot_complete=true (for Ready phase after pivot)
async fn update_cluster_status(
    cluster: &LatticeCluster,
    ctx: &Context,
    phase: ClusterPhase,
    error_message: Option<&str>,
    set_pivot_complete: bool,
) -> Result<(), Error> {
    let name = cluster.name_any();

    let (condition_type, condition_status, reason, message) = match phase {
        ClusterPhase::Pending => (
            "Pending",
            ConditionStatus::Unknown,
            "AwaitingProvisioning",
            "Cluster is pending provisioning",
        ),
        ClusterPhase::Provisioning => (
            "Provisioning",
            ConditionStatus::True,
            "StartingProvisioning",
            "Provisioning cluster infrastructure",
        ),
        ClusterPhase::Pivoting => (
            "Pivoting",
            ConditionStatus::True,
            "StartingPivot",
            "Pivoting cluster to self-managed",
        ),
        ClusterPhase::Ready => (
            "Ready",
            ConditionStatus::True,
            "ClusterReady",
            "Cluster is self-managed and ready",
        ),
        ClusterPhase::Failed => (
            "Ready",
            ConditionStatus::False,
            "ValidationFailed",
            error_message.unwrap_or("Unknown error"),
        ),
    };

    let condition = Condition::new(condition_type, condition_status, reason, message);

    let mut status = LatticeClusterStatus::with_phase(phase.clone())
        .message(message)
        .condition(condition);

    // Set pivot_complete if requested (persists pivot completion across restarts)
    if set_pivot_complete {
        status = status.pivot_complete(true);
    }

    ctx.kube.patch_status(&name, &status).await?;

    if phase == ClusterPhase::Failed {
        warn!(message, "updated status to Failed");
    } else {
        info!("updated status to {:?}", phase);
    }

    Ok(())
}

/// Real implementation of PivotOperations using AgentRegistry and PivotOrchestrator
pub struct PivotOperationsImpl {
    /// Agent registry for sending commands
    agent_registry: SharedAgentRegistry,
    /// CA certificate PEM for central proxy TLS
    ca_cert_pem: String,
    /// Set of clusters where pivot has been triggered (to avoid double-triggering)
    pivot_in_progress: dashmap::DashSet<String>,
}

impl PivotOperationsImpl {
    /// Create a new PivotOperationsImpl
    pub fn new(agent_registry: SharedAgentRegistry, ca_cert_pem: String) -> Self {
        Self {
            agent_registry,
            ca_cert_pem,
            pivot_in_progress: dashmap::DashSet::new(),
        }
    }
}

#[async_trait]
impl PivotOperations for PivotOperationsImpl {
    async fn trigger_pivot(
        &self,
        cluster_name: &str,
        source_namespace: &str,
        target_namespace: &str,
    ) -> Result<(), Error> {
        // Check if pivot is already in progress
        if self.pivot_in_progress.contains(cluster_name) {
            debug!(cluster = %cluster_name, "pivot already in progress");
            return Ok(());
        }

        // Check if agent is connected
        let agent_ref = self.agent_registry.get(cluster_name);
        if agent_ref.is_none() {
            return Err(Error::pivot(format!(
                "agent not connected for cluster {}",
                cluster_name
            )));
        }

        // Mark pivot as in progress
        self.pivot_in_progress.insert(cluster_name.to_string());

        // Send StartPivotCommand to agent
        let command_id = uuid::Uuid::new_v4().to_string();
        let start_pivot_cmd = CellCommand {
            command_id,
            command: Some(cell_command::Command::StartPivot(StartPivotCommand {
                source_namespace: source_namespace.to_string(),
                target_namespace: target_namespace.to_string(),
                cluster_name: cluster_name.to_string(),
            })),
        };

        match self
            .agent_registry
            .send_command(cluster_name, start_pivot_cmd)
            .await
        {
            Ok(()) => {
                info!(cluster = %cluster_name, "StartPivotCommand sent to agent");
                // The actual clusterctl move will be triggered after agent confirms PivotStarted
                // This is handled by the gRPC server when it receives PivotStarted from agent
                Ok(())
            }
            Err(e) => {
                // Remove from in-progress on failure
                self.pivot_in_progress.remove(cluster_name);
                Err(Error::pivot(format!("failed to send pivot command: {}", e)))
            }
        }
    }

    fn is_agent_ready(&self, cluster_name: &str) -> bool {
        self.agent_registry
            .get(cluster_name)
            .is_some_and(|a| a.is_ready_for_pivot())
    }

    fn is_pivot_in_progress(&self, cluster_name: &str) -> bool {
        // Check in-memory set first, then agent state (handles controller restarts)
        self.pivot_in_progress.contains(cluster_name)
            || self
                .agent_registry
                .get(cluster_name)
                .is_some_and(|a| matches!(a.state, AgentState::Pivoting))
    }

    fn is_pivot_complete(&self, cluster_name: &str) -> bool {
        self.agent_registry
            .get(cluster_name)
            .is_some_and(|a| matches!(a.state, AgentState::Ready))
    }

    fn store_post_pivot_manifests(
        &self,
        cluster_name: &str,
        crd_yaml: Option<String>,
        cluster_yaml: Option<String>,
        flux_manifests: Vec<String>,
        network_policy_yaml: Option<String>,
    ) {
        use crate::agent::connection::PostPivotManifests;
        self.agent_registry.set_post_pivot_manifests(
            cluster_name,
            PostPivotManifests {
                crd_yaml,
                cluster_yaml,
                flux_manifests,
                network_policy_yaml,
            },
        );
    }

    fn is_proxy_available(&self, cluster_name: &str) -> bool {
        // Check for central proxy channels (not per-agent proxy port)
        self.agent_registry
            .get_proxy_channels(cluster_name)
            .is_some()
    }

    async fn execute_clusterctl_move(
        &self,
        cluster_name: &str,
        namespace: &str,
    ) -> Result<(), Error> {
        use crate::agent::generate_central_proxy_kubeconfig;
        use crate::pivot::CENTRAL_PROXY_SERVICE_URL;

        info!(cluster = %cluster_name, namespace = %namespace, "Executing clusterctl move via central proxy");

        // Generate kubeconfig pointing to central proxy with path-based routing
        let kubeconfig_content = generate_central_proxy_kubeconfig(
            cluster_name,
            CENTRAL_PROXY_SERVICE_URL,
            &self.ca_cert_pem,
        );

        // Write kubeconfig to temp file
        let kubeconfig_path = format!("/tmp/lattice-pivot-{}.kubeconfig", cluster_name);
        tokio::fs::write(&kubeconfig_path, &kubeconfig_content)
            .await
            .map_err(|e| Error::pivot(format!("failed to write kubeconfig: {}", e)))?;

        // Execute clusterctl move with retry and automatic unpause
        // No source kubeconfig - uses default context (parent cluster)
        let result = execute_move(
            None, // No source kubeconfig, uses default context
            std::path::Path::new(&kubeconfig_path),
            namespace,
            cluster_name,
            &ClusterctlMoveConfig::default(),
        )
        .await;

        // Clean up kubeconfig
        let _ = tokio::fs::remove_file(&kubeconfig_path).await;

        result.map_err(|e| Error::pivot(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        BootstrapProvider, EndpointsSpec, KubernetesSpec, LatticeClusterSpec, NodeSpec,
        ProviderConfig, ProviderSpec, ServiceSpec,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    /// Create a sample LatticeCluster for testing
    fn sample_cluster(name: &str) -> LatticeCluster {
        LatticeCluster {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec: LatticeClusterSpec {
                provider: ProviderSpec {
                    kubernetes: KubernetesSpec {
                        version: "1.32.0".to_string(),
                        cert_sans: None,
                        bootstrap: BootstrapProvider::default(),
                    },
                    config: ProviderConfig::docker(),
                },
                nodes: NodeSpec {
                    control_plane: 1,
                    workers: 2,
                },
                networking: None,
                endpoints: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        }
    }

    /// Create a sample cell (management cluster) for testing
    fn sample_parent(name: &str) -> LatticeCluster {
        let mut cluster = sample_cluster(name);
        cluster.spec.endpoints = Some(EndpointsSpec {
            host: "172.18.255.1".to_string(),
            grpc_port: 50051,
            bootstrap_port: 8443,
            service: ServiceSpec {
                type_: "LoadBalancer".to_string(),
            },
            gitops: None,
        });
        cluster
    }

    /// Create a cluster with a specific status phase
    fn cluster_with_phase(name: &str, phase: ClusterPhase) -> LatticeCluster {
        let mut cluster = sample_cluster(name);
        cluster.status = Some(LatticeClusterStatus::with_phase(phase));
        cluster
    }

    /// Create a cluster with invalid spec (zero control plane nodes)
    fn invalid_cluster(name: &str) -> LatticeCluster {
        let mut cluster = sample_cluster(name);
        cluster.spec.nodes.control_plane = 0;
        cluster
    }

    mod reconcile_logic {
        use super::*;

        #[test]
        fn test_validation_with_valid_cluster() {
            let cluster = sample_cluster("valid-cluster");
            assert!(cluster.spec.validate().is_ok());
        }

        #[test]
        fn test_validation_with_invalid_cluster() {
            let cluster = invalid_cluster("invalid-cluster");
            assert!(cluster.spec.validate().is_err());
        }

        #[test]
        fn test_cell_cluster_validation() {
            let cluster = sample_parent("mgmt");
            assert!(cluster.spec.validate().is_ok());
            assert!(cluster.spec.has_endpoints());
        }
    }

    mod status_helpers {
        use super::*;

        #[test]
        fn test_multiple_condition_types_are_preserved() {
            let provisioning = Condition::new(
                "Provisioning",
                ConditionStatus::True,
                "InProgress",
                "Infrastructure provisioning",
            );
            let ready = Condition::new(
                "Ready",
                ConditionStatus::False,
                "NotReady",
                "Waiting for infrastructure",
            );

            let status = LatticeClusterStatus::default()
                .condition(provisioning)
                .condition(ready);

            assert_eq!(status.conditions.len(), 2);
        }
    }

    /// Cluster Lifecycle State Machine Tests
    ///
    /// These tests verify the complete cluster lifecycle flow through the reconciler.
    /// Each test represents a story of what happens when a cluster is in a specific
    /// state and the controller reconciles it.
    ///
    /// Lifecycle: Pending -> Provisioning -> Pivoting -> Ready
    ///            (any state can transition to Failed on error)
    ///
    /// Test Philosophy:
    /// - Tests focus on OBSERVABLE OUTCOMES (Action returned, errors propagated)
    /// - We avoid verifying internal mock call parameters
    /// - Status capture allows verifying phase transitions without tight coupling
    mod cluster_lifecycle_flow {
        use super::*;
        use crate::capi::MockCapiInstaller;
        use std::sync::{Arc as StdArc, Mutex};

        /// Captured status update for verification without coupling to mock internals.
        /// This allows us to verify "status was updated to Provisioning" without
        /// using withf() matchers that couple tests to implementation details.
        #[derive(Clone)]
        struct StatusCapture {
            updates: StdArc<Mutex<Vec<LatticeClusterStatus>>>,
        }

        impl StatusCapture {
            fn new() -> Self {
                Self {
                    updates: StdArc::new(Mutex::new(Vec::new())),
                }
            }

            fn record(&self, status: LatticeClusterStatus) {
                self.updates.lock().unwrap().push(status);
            }

            fn last_phase(&self) -> Option<ClusterPhase> {
                self.updates.lock().unwrap().last().map(|s| s.phase.clone())
            }

            fn was_updated(&self) -> bool {
                !self.updates.lock().unwrap().is_empty()
            }
        }

        // ===== Test Fixture Helpers =====
        // These create mock contexts that capture status updates for verification

        /// Creates mock installer for CAPI (always succeeds)
        fn mock_capi_installer() -> Arc<MockCapiInstaller> {
            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));
            Arc::new(installer)
        }

        /// Creates a context that captures status updates for later verification.
        /// Use this when you need to verify WHAT phase was set, not HOW it was set.
        fn mock_context_with_status_capture() -> (Arc<Context>, StatusCapture) {
            let capture = StatusCapture::new();
            let capture_clone = capture.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                capture_clone.record(status.clone());
                Ok(())
            });
            mock.expect_ensure_namespace().returning(|_| Ok(()));

            let mut capi_mock = MockCAPIClient::new();
            capi_mock.expect_apply_manifests().returning(|_, _| Ok(()));

            (
                Arc::new(Context::for_testing(
                    Arc::new(mock),
                    Arc::new(capi_mock),
                    mock_capi_installer(),
                )),
                capture,
            )
        }

        /// Creates a context for read-only scenarios where no status updates happen.
        fn mock_context_readonly() -> Arc<Context> {
            let mut mock = MockKubeClient::new();
            // Default expectations for node operations (Ready phase)
            // Return 2 workers to match sample_cluster spec (so we get 60s requeue)
            mock.expect_get_ready_worker_count().returning(|| Ok(2));
            mock.expect_are_control_plane_nodes_tainted()
                .returning(|| Ok(true));
            mock.expect_taint_control_plane_nodes().returning(|| Ok(()));

            let mut capi_mock = MockCAPIClient::new();
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _, _| Ok(false));
            // MachineDeployment has 2 replicas to match spec - no scaling needed
            capi_mock
                .expect_get_machine_deployment_replicas()
                .returning(|_, _| Ok(Some(2)));
            Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                mock_capi_installer(),
            ))
        }

        /// Creates a context where infrastructure reports ready.
        fn mock_context_infra_ready_with_capture() -> (Arc<Context>, StatusCapture) {
            let capture = StatusCapture::new();
            let capture_clone = capture.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                capture_clone.record(status.clone());
                Ok(())
            });

            let mut capi_mock = MockCAPIClient::new();
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _, _| Ok(true));

            (
                Arc::new(Context::for_testing(
                    Arc::new(mock),
                    Arc::new(capi_mock),
                    mock_capi_installer(),
                )),
                capture,
            )
        }

        // ===== Lifecycle Flow Tests =====

        /// Story: When a user creates a new LatticeCluster, the controller should
        /// generate CAPI manifests and transition the cluster to Provisioning phase.
        /// This kicks off the infrastructure provisioning process.
        #[tokio::test]
        async fn story_new_cluster_starts_provisioning() {
            let cluster = Arc::new(sample_cluster("new-cluster"));
            let (ctx, capture) = mock_context_with_status_capture();

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Verify observable outcomes:
            // 1. Status was updated to Provisioning phase
            assert!(capture.was_updated(), "status should be updated");
            assert_eq!(capture.last_phase(), Some(ClusterPhase::Provisioning));
            // 2. Quick requeue to check provisioning progress
            assert_eq!(action, Action::requeue(Duration::from_secs(5)));
        }

        /// Story: A cluster explicitly in Pending phase should behave identically
        /// to a new cluster - both enter the provisioning pipeline.
        #[tokio::test]
        async fn story_pending_cluster_starts_provisioning() {
            let cluster = Arc::new(cluster_with_phase("pending-cluster", ClusterPhase::Pending));
            let (ctx, capture) = mock_context_with_status_capture();

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            assert!(capture.was_updated(), "status should be updated");
            assert_eq!(capture.last_phase(), Some(ClusterPhase::Provisioning));
            assert_eq!(action, Action::requeue(Duration::from_secs(5)));
        }

        /// Story: While infrastructure is being provisioned (VMs starting, etc.),
        /// the controller should keep checking until CAPI reports ready.
        #[tokio::test]
        async fn story_provisioning_cluster_waits_for_infrastructure() {
            let cluster = Arc::new(cluster_with_phase(
                "provisioning-cluster",
                ClusterPhase::Provisioning,
            ));
            let ctx = mock_context_readonly();

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Observable outcome: longer requeue interval while waiting
            assert_eq!(action, Action::requeue(Duration::from_secs(30)));
        }

        /// Story: Once infrastructure is ready, the cluster transitions to Pivoting
        /// phase where CAPI resources are moved into the cluster for self-management.
        #[tokio::test]
        async fn story_ready_infrastructure_triggers_pivot() {
            let cluster = Arc::new(cluster_with_phase(
                "ready-infra-cluster",
                ClusterPhase::Provisioning,
            ));
            let (ctx, capture) = mock_context_infra_ready_with_capture();

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Verify transition to Pivoting phase
            assert!(capture.was_updated(), "status should be updated");
            assert_eq!(capture.last_phase(), Some(ClusterPhase::Pivoting));
            // Quick requeue to monitor pivot progress
            assert_eq!(action, Action::requeue(Duration::from_secs(5)));
        }

        /// Story: Once a cluster is fully self-managing, the controller only needs
        /// periodic drift detection to ensure the cluster matches its spec.
        #[tokio::test]
        async fn story_ready_cluster_performs_drift_detection() {
            let cluster = Arc::new(cluster_with_phase("ready-cluster", ClusterPhase::Ready));
            let ctx = mock_context_readonly();

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Long requeue interval for healthy clusters
            assert_eq!(action, Action::requeue(Duration::from_secs(60)));
        }

        /// Story: A failed cluster requires human intervention to fix the spec.
        /// The controller waits for spec changes rather than retrying on a timer.
        #[tokio::test]
        async fn story_failed_cluster_awaits_human_intervention() {
            let cluster = Arc::new(cluster_with_phase("failed-cluster", ClusterPhase::Failed));
            let ctx = mock_context_readonly();

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Wait for spec changes, don't retry on timer
            assert_eq!(action, Action::await_change());
        }

        /// Story: Invalid cluster specs (like zero control plane nodes) should
        /// immediately fail rather than attempting to provision bad infrastructure.
        #[tokio::test]
        async fn story_invalid_spec_immediately_fails() {
            let cluster = Arc::new(invalid_cluster("invalid-cluster"));
            let (ctx, capture) = mock_context_with_status_capture();

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Verify transition to Failed phase
            assert!(capture.was_updated(), "status should be updated");
            assert_eq!(capture.last_phase(), Some(ClusterPhase::Failed));
            // Wait for user to fix the spec
            assert_eq!(action, Action::await_change());
        }

        // ===== Error Propagation Tests =====

        /// Story: When the Kubernetes API is unavailable, errors should propagate
        /// so the controller can apply exponential backoff.
        #[tokio::test]
        async fn story_kube_api_errors_trigger_retry() {
            let cluster = Arc::new(sample_cluster("error-cluster"));

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status()
                .returning(|_, _| Err(Error::provider("connection refused".to_string())));
            mock.expect_ensure_namespace().returning(|_| Ok(()));

            let mut capi_mock = MockCAPIClient::new();
            capi_mock.expect_apply_manifests().returning(|_, _| Ok(()));

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                mock_capi_installer(),
            ));

            let result = reconcile(cluster, ctx).await;

            // Observable outcome: error propagates for retry
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("connection refused"));
        }

        /// Story: CAPI manifest application failures should propagate so the
        /// error policy can handle retries.
        #[tokio::test]
        async fn story_capi_failures_trigger_retry() {
            let cluster = Arc::new(sample_cluster("capi-error-cluster"));

            let mut mock = MockKubeClient::new();
            mock.expect_ensure_namespace().returning(|_| Ok(()));

            let mut capi_mock = MockCAPIClient::new();
            capi_mock
                .expect_apply_manifests()
                .returning(|_, _| Err(Error::provider("CAPI apply failed".to_string())));

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                mock_capi_installer(),
            ));

            let result = reconcile(cluster, ctx).await;

            // Observable outcome: error with context propagates
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("CAPI apply failed"));
        }
    }

    mod error_policy_tests {
        use super::*;
        use crate::capi::MockCapiInstaller;
        use rstest::rstest;

        fn mock_context_no_updates() -> Arc<Context> {
            let mock = MockKubeClient::new();
            let capi_mock = MockCAPIClient::new();
            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));
            Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(installer),
            ))
        }

        #[rstest]
        #[case::provider_error(Error::provider("test error".to_string()))]
        #[case::validation_error(Error::validation("invalid spec".to_string()))]
        #[case::pivot_error(Error::pivot("pivot failed".to_string()))]
        fn test_error_policy_always_requeues_with_backoff(#[case] error: Error) {
            // error_policy should always requeue with 5s backoff regardless of error type
            let cluster = Arc::new(sample_cluster("test-cluster"));
            let ctx = mock_context_no_updates();

            let action = error_policy(cluster, &error, ctx);

            assert_eq!(action, Action::requeue(Duration::from_secs(5)));
        }
    }

    /// Tests for status update error handling
    ///
    /// Note: The actual status content (phase, message, conditions) is tested
    /// through the reconcile flow tests which verify the complete behavior.
    /// These tests focus on error propagation which is a separate concern.
    mod status_error_handling {
        use super::*;
        use crate::capi::MockCapiInstaller;

        /// Story: When the Kubernetes API fails during status update, the error
        /// should propagate up so the controller can retry the reconciliation.
        #[tokio::test]
        async fn test_kube_api_failure_propagates_error() {
            let cluster = sample_cluster("test-cluster");

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status()
                .returning(|_, _| Err(Error::provider("connection failed".to_string())));

            let capi_mock = MockCAPIClient::new();
            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));
            let ctx =
                Context::for_testing(Arc::new(mock), Arc::new(capi_mock), Arc::new(installer));

            let result =
                update_cluster_status(&cluster, &ctx, ClusterPhase::Provisioning, None, false)
                    .await;

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("connection failed"));
        }
    }

    /// Tests for CAPI resource API handling
    ///
    /// These tests verify that we correctly parse Kubernetes API versions and
    /// generate resource plural names - essential for dynamically creating
    /// CAPI resources. While these are internal helpers, they're tested
    /// directly because the production code path (apply_manifests) requires
    /// a live Kubernetes cluster.
    mod capi_api_handling {
        use super::*;

        /// Story: When applying CAPI resources, we need to parse API versions like
        /// "cluster.x-k8s.io/v1beta1" into group and version for the DynamicObject API.
        #[test]
        fn test_grouped_api_versions_are_parsed_correctly() {
            let (group, version) = parse_api_version("cluster.x-k8s.io/v1beta1");
            assert_eq!(group, "cluster.x-k8s.io");
            assert_eq!(version, "v1beta1");
        }

        /// Story: Core Kubernetes resources use versions like "v1" without a group.
        #[test]
        fn test_core_api_versions_have_empty_group() {
            let (group, version) = parse_api_version("v1");
            assert_eq!(group, "");
            assert_eq!(version, "v1");
        }

        /// Story: The Kubernetes API requires plural resource names. We must correctly
        /// pluralize all CAPI resource kinds to construct valid API paths.
        #[test]
        fn test_all_capi_resource_kinds_are_pluralized_correctly() {
            // Core CAPI kinds
            assert_eq!(pluralize_kind("Cluster"), "clusters");
            assert_eq!(pluralize_kind("Machine"), "machines");
            assert_eq!(pluralize_kind("MachineSet"), "machinesets");
            assert_eq!(pluralize_kind("MachineDeployment"), "machinedeployments");

            // Control plane kinds
            assert_eq!(
                pluralize_kind("KubeadmControlPlane"),
                "kubeadmcontrolplanes"
            );
            assert_eq!(
                pluralize_kind("KubeadmConfigTemplate"),
                "kubeadmconfigtemplates"
            );

            // Docker infrastructure kinds
            assert_eq!(pluralize_kind("DockerCluster"), "dockerclusters");
            assert_eq!(pluralize_kind("DockerMachine"), "dockermachines");
            assert_eq!(
                pluralize_kind("DockerMachineTemplate"),
                "dockermachinetemplates"
            );
        }

        /// Story: Unknown resource kinds should fall back to simple 's' suffix pluralization.
        #[test]
        fn test_unknown_kinds_use_fallback_pluralization() {
            assert_eq!(pluralize_kind("CustomResource"), "customresources");
        }
    }

    mod generate_manifests_tests {
        use super::*;
        use crate::capi::MockCapiInstaller;

        fn cluster_with_docker_config(name: &str) -> LatticeCluster {
            LatticeCluster {
                metadata: ObjectMeta {
                    name: Some(name.to_string()),
                    ..Default::default()
                },
                spec: LatticeClusterSpec {
                    provider: ProviderSpec {
                        kubernetes: KubernetesSpec {
                            version: "1.32.0".to_string(),
                            cert_sans: None,
                            bootstrap: BootstrapProvider::default(),
                        },
                        config: ProviderConfig::docker(),
                    },
                    nodes: NodeSpec {
                        control_plane: 1,
                        workers: 2,
                    },
                    networking: None,
                    endpoints: None,
                    environment: None,
                    region: None,
                    workload: None,
                },
                status: None,
            }
        }

        fn mock_context() -> Arc<Context> {
            let mock = MockKubeClient::new();
            let capi_mock = MockCAPIClient::new();
            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));
            Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(installer),
            ))
        }

        #[tokio::test]
        async fn test_generate_capi_manifests_docker_provider() {
            let cluster = cluster_with_docker_config("docker-cluster");
            let ctx = mock_context();
            let result = generate_capi_manifests(&cluster, &ctx).await;

            assert!(result.is_ok());
            let manifests = result.unwrap();
            // Docker provider should generate manifests
            assert!(!manifests.is_empty());
        }
    }

    /// API Version Parsing Tests
    ///
    /// These tests verify that Kubernetes API versions are correctly parsed
    /// into group and version components for dynamic resource creation.
    mod api_version_parsing {
        use super::*;

        /// Story: CAPI resources use grouped API versions like "cluster.x-k8s.io/v1beta1"
        /// which need to be split into group="cluster.x-k8s.io" and version="v1beta1"
        #[test]
        fn story_capi_api_versions_split_correctly() {
            let test_cases = vec![
                ("cluster.x-k8s.io/v1beta1", "cluster.x-k8s.io", "v1beta1"),
                (
                    "infrastructure.cluster.x-k8s.io/v1beta1",
                    "infrastructure.cluster.x-k8s.io",
                    "v1beta1",
                ),
                (
                    "controlplane.cluster.x-k8s.io/v1beta1",
                    "controlplane.cluster.x-k8s.io",
                    "v1beta1",
                ),
                (
                    "bootstrap.cluster.x-k8s.io/v1beta1",
                    "bootstrap.cluster.x-k8s.io",
                    "v1beta1",
                ),
            ];

            for (input, expected_group, expected_version) in test_cases {
                let (group, version) = parse_api_version(input);
                assert_eq!(group, expected_group, "group for {}", input);
                assert_eq!(version, expected_version, "version for {}", input);
            }
        }

        /// Story: Core Kubernetes resources use "v1" without a group prefix
        #[test]
        fn story_core_api_version_has_empty_group() {
            let (group, version) = parse_api_version("v1");
            assert_eq!(group, "");
            assert_eq!(version, "v1");
        }

        /// Story: Apps API group resources like Deployments
        #[test]
        fn story_apps_api_version_parses_correctly() {
            let (group, version) = parse_api_version("apps/v1");
            assert_eq!(group, "apps");
            assert_eq!(version, "v1");
        }
    }

    /// Resource Pluralization Tests
    ///
    /// The Kubernetes API requires plural resource names when constructing
    /// API paths. These tests verify all CAPI resource kinds are pluralized correctly.
    mod resource_pluralization {
        use super::*;

        /// Story: All standard CAPI resource kinds must pluralize correctly
        /// for the dynamic client to work with them.
        #[test]
        fn story_all_capi_kinds_have_correct_plurals() {
            // Core CAPI resources
            assert_eq!(pluralize_kind("Cluster"), "clusters");
            assert_eq!(pluralize_kind("Machine"), "machines");
            assert_eq!(pluralize_kind("MachineSet"), "machinesets");
            assert_eq!(pluralize_kind("MachineDeployment"), "machinedeployments");

            // Control plane resources
            assert_eq!(
                pluralize_kind("KubeadmControlPlane"),
                "kubeadmcontrolplanes"
            );
            assert_eq!(
                pluralize_kind("KubeadmConfigTemplate"),
                "kubeadmconfigtemplates"
            );

            // Docker provider resources
            assert_eq!(pluralize_kind("DockerCluster"), "dockerclusters");
            assert_eq!(pluralize_kind("DockerMachine"), "dockermachines");
            assert_eq!(
                pluralize_kind("DockerMachineTemplate"),
                "dockermachinetemplates"
            );
        }

        /// Story: Unknown resource kinds should use simple 's' suffix fallback
        /// so new resource types can still work without explicit mapping.
        #[test]
        fn story_unknown_kinds_use_fallback_pluralization() {
            assert_eq!(pluralize_kind("CustomCluster"), "customclusters");
            assert_eq!(pluralize_kind("MyResource"), "myresources");
            assert_eq!(pluralize_kind("SomeNewKind"), "somenewkinds");
        }

        /// Story: Pluralization is case-insensitive (Kubernetes convention)
        #[test]
        fn story_pluralization_is_case_insensitive() {
            assert_eq!(pluralize_kind("CLUSTER"), "clusters");
            assert_eq!(pluralize_kind("cluster"), "clusters");
            assert_eq!(pluralize_kind("Cluster"), "clusters");
        }
    }

    /// Infrastructure Ready Detection Tests
    ///
    /// These tests verify the controller correctly detects when CAPI
    /// infrastructure is ready based on the Cluster resource status.
    mod infrastructure_ready_detection {
        use super::*;
        use crate::capi::MockCapiInstaller;

        /// Story: When CAPI reports infrastructure NOT ready, the controller
        /// should continue polling with the Provisioning phase requeue interval.
        #[tokio::test]
        async fn story_not_ready_infrastructure_triggers_requeue() {
            let cluster = Arc::new(cluster_with_phase(
                "provisioning-cluster",
                ClusterPhase::Provisioning,
            ));

            let mock = MockKubeClient::new();
            let mut capi_mock = MockCAPIClient::new();

            // Infrastructure is NOT ready
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _, _| Ok(false));

            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(installer),
            ));

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Should requeue with longer interval while waiting
            assert_eq!(action, Action::requeue(Duration::from_secs(30)));
        }

        /// Story: When CAPI reports infrastructure IS ready, the controller
        /// should transition to Pivoting phase.
        #[tokio::test]
        async fn story_ready_infrastructure_triggers_phase_transition() {
            use std::sync::{Arc as StdArc, Mutex};

            let cluster = Arc::new(cluster_with_phase(
                "ready-cluster",
                ClusterPhase::Provisioning,
            ));

            let updates: StdArc<Mutex<Vec<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(Vec::new()));
            let updates_clone = updates.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                updates_clone.lock().unwrap().push(status.clone());
                Ok(())
            });

            let mut capi_mock = MockCAPIClient::new();
            // Infrastructure IS ready
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _, _| Ok(true));

            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(installer),
            ));

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Should transition to Pivoting and requeue quickly
            let recorded = updates.lock().unwrap();
            assert!(!recorded.is_empty());
            assert_eq!(recorded.last().unwrap().phase, ClusterPhase::Pivoting);
            assert_eq!(action, Action::requeue(Duration::from_secs(5)));
        }

        /// Story: When CAPI infrastructure check fails, error should propagate
        /// for retry with backoff.
        #[tokio::test]
        async fn story_infrastructure_check_failure_propagates_error() {
            let cluster = Arc::new(cluster_with_phase(
                "error-cluster",
                ClusterPhase::Provisioning,
            ));

            let mock = MockKubeClient::new();
            let mut capi_mock = MockCAPIClient::new();

            // Infrastructure check fails
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _, _| Err(Error::provider("CAPI API unavailable".to_string())));

            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(installer),
            ));

            let result = reconcile(cluster, ctx).await;

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("CAPI API unavailable"));
        }
    }

    /// CAPI Installation Flow Tests
    ///
    /// These tests verify the controller correctly handles CAPI installation.
    /// clusterctl init is always called (it's idempotent).
    mod capi_installation_flow {
        use super::*;
        use crate::capi::MockCapiInstaller;
        use std::sync::{Arc as StdArc, Mutex};

        /// Story: Controller always calls clusterctl init before provisioning
        /// (clusterctl init is idempotent - handles upgrades and no-ops).
        #[tokio::test]
        async fn story_capi_init_called_before_provisioning() {
            let cluster = Arc::new(sample_cluster("ready-to-provision"));

            let updates: StdArc<Mutex<Vec<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(Vec::new()));
            let updates_clone = updates.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                updates_clone.lock().unwrap().push(status.clone());
                Ok(())
            });
            mock.expect_ensure_namespace().returning(|_| Ok(()));

            let mut capi_mock = MockCAPIClient::new();
            capi_mock.expect_apply_manifests().returning(|_, _| Ok(()));

            let mut installer = MockCapiInstaller::new();
            // Installer should always be called (idempotent)
            installer.expect_ensure().times(1).returning(|_| Ok(()));

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(installer),
            ));

            let result = reconcile(cluster, ctx).await;

            assert!(result.is_ok());
            // Should have transitioned to Provisioning
            let recorded = updates.lock().unwrap();
            assert!(!recorded.is_empty());
        }

        /// Story: When CAPI installation fails, the error should propagate
        /// for retry with exponential backoff.
        #[tokio::test]
        async fn story_capi_installation_failure_propagates_error() {
            let cluster = Arc::new(sample_cluster("install-fails"));

            let mock = MockKubeClient::new();
            let capi_mock = MockCAPIClient::new();

            let mut installer = MockCapiInstaller::new();
            // Installation fails
            installer
                .expect_ensure()
                .returning(|_| Err(Error::capi_installation("clusterctl not found".to_string())));

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(installer),
            ));

            let result = reconcile(cluster, ctx).await;

            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("clusterctl"));
        }
    }

    /// Status Update Content Tests
    ///
    /// These tests verify that status updates contain the correct phase,
    /// message, and conditions as the cluster progresses through its lifecycle.
    mod status_update_content {
        use super::*;
        use crate::capi::MockCapiInstaller;
        use std::sync::{Arc as StdArc, Mutex};

        /// Story: When transitioning to Provisioning, the status should include
        /// a clear message and Provisioning condition for observability.
        #[tokio::test]
        async fn story_provisioning_status_has_correct_content() {
            let cluster = sample_cluster("new-cluster");

            let captured_status: StdArc<Mutex<Option<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(None));
            let captured_clone = captured_status.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                *captured_clone.lock().unwrap() = Some(status.clone());
                Ok(())
            });

            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));
            let ctx = Context::for_testing(
                Arc::new(mock),
                Arc::new(MockCAPIClient::new()),
                Arc::new(installer),
            );

            update_cluster_status(&cluster, &ctx, ClusterPhase::Provisioning, None, false)
                .await
                .unwrap();

            let status = captured_status.lock().unwrap().clone().unwrap();
            assert_eq!(status.phase, ClusterPhase::Provisioning);
            assert!(status.message.unwrap().contains("Provisioning"));
            assert!(!status.conditions.is_empty());

            let condition = &status.conditions[0];
            assert_eq!(condition.type_, "Provisioning");
            assert_eq!(condition.status, ConditionStatus::True);
        }

        /// Story: When transitioning to Pivoting, the status should indicate
        /// that the cluster is being transitioned to self-management.
        #[tokio::test]
        async fn story_pivoting_status_has_correct_content() {
            let cluster = sample_cluster("pivoting-cluster");

            let captured_status: StdArc<Mutex<Option<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(None));
            let captured_clone = captured_status.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                *captured_clone.lock().unwrap() = Some(status.clone());
                Ok(())
            });

            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));
            let ctx = Context::for_testing(
                Arc::new(mock),
                Arc::new(MockCAPIClient::new()),
                Arc::new(installer),
            );

            update_cluster_status(&cluster, &ctx, ClusterPhase::Pivoting, None, false)
                .await
                .unwrap();

            let status = captured_status.lock().unwrap().clone().unwrap();
            assert_eq!(status.phase, ClusterPhase::Pivoting);
            assert!(status.message.unwrap().contains("Pivoting"));

            let condition = &status.conditions[0];
            assert_eq!(condition.type_, "Pivoting");
            assert_eq!(condition.reason, "StartingPivot");
        }

        /// Story: When a cluster fails validation, the status should clearly
        /// indicate the failure reason so users can fix the configuration.
        #[tokio::test]
        async fn story_failed_status_includes_error_message() {
            let cluster = sample_cluster("invalid-cluster");

            let captured_status: StdArc<Mutex<Option<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(None));
            let captured_clone = captured_status.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                *captured_clone.lock().unwrap() = Some(status.clone());
                Ok(())
            });

            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));
            let ctx = Context::for_testing(
                Arc::new(mock),
                Arc::new(MockCAPIClient::new()),
                Arc::new(installer),
            );

            let error_msg = "control plane count must be at least 1";
            update_cluster_status(&cluster, &ctx, ClusterPhase::Failed, Some(error_msg), false)
                .await
                .unwrap();

            let status = captured_status.lock().unwrap().clone().unwrap();
            assert_eq!(status.phase, ClusterPhase::Failed);
            assert_eq!(status.message.as_ref().unwrap(), error_msg);

            let condition = &status.conditions[0];
            assert_eq!(condition.type_, "Ready");
            assert_eq!(condition.status, ConditionStatus::False);
            assert_eq!(condition.reason, "ValidationFailed");
            assert_eq!(condition.message, error_msg);
        }
    }

    /// Error Policy Behavior Tests
    ///
    /// These tests verify that the error policy correctly handles different
    /// types of errors and returns appropriate requeue actions.
    mod error_policy_behavior {
        use super::*;
        use crate::capi::MockCapiInstaller;

        fn mock_context_minimal() -> Arc<Context> {
            Arc::new(Context::for_testing(
                Arc::new(MockKubeClient::new()),
                Arc::new(MockCAPIClient::new()),
                Arc::new(MockCapiInstaller::new()),
            ))
        }

        /// Story: All errors should result in a requeue with backoff,
        /// regardless of error type, to handle transient failures.
        #[test]
        fn story_all_error_types_trigger_requeue() {
            let cluster = Arc::new(sample_cluster("error-cluster"));
            let ctx = mock_context_minimal();

            let error_types = vec![
                Error::provider("provider error".to_string()),
                Error::validation("validation error".to_string()),
                Error::pivot("pivot error".to_string()),
                Error::serialization("serialization error".to_string()),
                Error::capi_installation("capi error".to_string()),
            ];

            for error in error_types {
                let action = error_policy(cluster.clone(), &error, ctx.clone());
                assert_eq!(
                    action,
                    Action::requeue(Duration::from_secs(5)),
                    "error type {:?} should trigger 5s requeue",
                    error
                );
            }
        }

        /// Story: Error policy should work correctly with clusters in any phase.
        #[test]
        fn story_error_policy_works_for_all_phases() {
            let ctx = mock_context_minimal();

            let phases = vec![
                ClusterPhase::Pending,
                ClusterPhase::Provisioning,
                ClusterPhase::Pivoting,
                ClusterPhase::Ready,
                ClusterPhase::Failed,
            ];

            for phase in phases {
                let cluster = Arc::new(cluster_with_phase("test", phase.clone()));
                let error = Error::provider("test error".to_string());
                let action = error_policy(cluster, &error, ctx.clone());

                assert_eq!(
                    action,
                    Action::requeue(Duration::from_secs(5)),
                    "phase {:?} should trigger requeue",
                    phase
                );
            }
        }
    }

    /// PivotOperationsImpl Tests
    ///
    /// These tests verify the real implementation of PivotOperations
    /// that uses the AgentRegistry for pivot orchestration.
    mod pivot_operations_tests {
        use super::*;
        use crate::agent::connection::AgentRegistry;

        /// Story: Creating a new PivotOperationsImpl should work
        #[test]
        fn story_create_pivot_operations() {
            let registry = Arc::new(AgentRegistry::new());
            let ops = PivotOperationsImpl::new(registry, "test-ca-cert".to_string());
            // Just verify it can be created
            assert!(!ops.is_agent_ready("nonexistent-cluster"));
        }

        /// Story: Agent ready check should return false for unconnected cluster
        #[test]
        fn story_agent_not_ready_when_not_connected() {
            let registry = Arc::new(AgentRegistry::new());
            let ops = PivotOperationsImpl::new(registry, "test-ca-cert".to_string());

            assert!(!ops.is_agent_ready("test-cluster"));
        }

        /// Story: Pivot complete check should return false for unconnected cluster
        #[test]
        fn story_pivot_not_complete_when_not_connected() {
            let registry = Arc::new(AgentRegistry::new());
            let ops = PivotOperationsImpl::new(registry, "test-ca-cert".to_string());

            assert!(!ops.is_pivot_complete("test-cluster"));
        }

        /// Story: Trigger pivot should fail when agent is not connected
        #[tokio::test]
        async fn story_trigger_pivot_fails_when_no_agent() {
            let registry = Arc::new(AgentRegistry::new());
            let ops = PivotOperationsImpl::new(registry, "test-ca-cert".to_string());

            let result = ops
                .trigger_pivot("test-cluster", "default", "default")
                .await;

            assert!(result.is_err());
            match result {
                Err(Error::Pivot { message, .. }) => {
                    assert!(message.contains("agent not connected"));
                }
                _ => panic!("Expected Pivot error"),
            }
        }

        /// Story: Double-triggering pivot should be idempotent
        #[tokio::test]
        async fn story_double_trigger_is_idempotent() {
            let registry = Arc::new(AgentRegistry::new());
            let ops = PivotOperationsImpl::new(registry, "test-ca-cert".to_string());

            // First trigger fails (no agent)
            let _ = ops
                .trigger_pivot("test-cluster", "default", "default")
                .await;

            // Manually mark as in progress to test idempotency
            ops.pivot_in_progress.insert("test-cluster".to_string());

            // Second trigger should succeed (returns Ok, not error)
            let result = ops
                .trigger_pivot("test-cluster", "default", "default")
                .await;

            // Should succeed because it recognizes pivot is already in progress
            assert!(result.is_ok());
        }
    }

    // =========================================================================
    // Pure Function Tests
    // =========================================================================
    // These tests cover the extracted pure functions that contain decision logic.

    mod pure_functions {
        use super::*;
        use k8s_openapi::api::core::v1::{Node, NodeCondition, NodeSpec, NodeStatus, Taint};

        // --- is_self_cluster tests ---

        #[test]
        fn is_self_cluster_returns_true_when_names_match() {
            assert!(is_self_cluster("mgmt", Some("mgmt")));
        }

        #[test]
        fn is_self_cluster_returns_false_when_names_differ() {
            assert!(!is_self_cluster("workload", Some("mgmt")));
        }

        #[test]
        fn is_self_cluster_returns_false_when_no_self_name() {
            assert!(!is_self_cluster("mgmt", None));
        }

        // --- Node helper function tests ---

        fn make_node(name: &str, is_control_plane: bool, is_ready: bool, has_taint: bool) -> Node {
            let mut labels = std::collections::BTreeMap::new();
            if is_control_plane {
                labels.insert(
                    "node-role.kubernetes.io/control-plane".to_string(),
                    "".to_string(),
                );
            }

            let conditions = if is_ready {
                Some(vec![NodeCondition {
                    type_: "Ready".to_string(),
                    status: "True".to_string(),
                    ..Default::default()
                }])
            } else {
                Some(vec![NodeCondition {
                    type_: "Ready".to_string(),
                    status: "False".to_string(),
                    ..Default::default()
                }])
            };

            let taints = if has_taint {
                Some(vec![Taint {
                    key: "node-role.kubernetes.io/control-plane".to_string(),
                    effect: "NoSchedule".to_string(),
                    ..Default::default()
                }])
            } else {
                None
            };

            Node {
                metadata: ObjectMeta {
                    name: Some(name.to_string()),
                    labels: Some(labels),
                    ..Default::default()
                },
                spec: Some(NodeSpec {
                    taints,
                    ..Default::default()
                }),
                status: Some(NodeStatus {
                    conditions,
                    ..Default::default()
                }),
            }
        }

        #[test]
        fn is_control_plane_node_detects_control_plane_label() {
            let cp_node = make_node("cp-0", true, true, true);
            let worker = make_node("worker-0", false, true, false);

            assert!(is_control_plane_node(&cp_node));
            assert!(!is_control_plane_node(&worker));
        }

        #[test]
        fn is_node_ready_checks_ready_condition() {
            let ready_node = make_node("ready", false, true, false);
            let not_ready = make_node("not-ready", false, false, false);

            assert!(is_node_ready(&ready_node));
            assert!(!is_node_ready(&not_ready));
        }

        #[test]
        fn is_ready_worker_node_excludes_control_plane() {
            let ready_worker = make_node("worker", false, true, false);
            let ready_cp = make_node("cp", true, true, true);
            let not_ready_worker = make_node("worker-sick", false, false, false);

            assert!(is_ready_worker_node(&ready_worker));
            assert!(!is_ready_worker_node(&ready_cp)); // Control plane excluded
            assert!(!is_ready_worker_node(&not_ready_worker)); // Not ready excluded
        }

        #[test]
        fn has_control_plane_taint_detects_no_schedule() {
            let tainted = make_node("cp", true, true, true);
            let untainted = make_node("cp-no-taint", true, true, false);

            assert!(has_control_plane_taint(&tainted));
            assert!(!has_control_plane_taint(&untainted));
        }

        // --- determine_pivot_action tests ---

        #[test]
        fn pivot_action_complete_when_pivot_done() {
            assert_eq!(
                determine_pivot_action(true, false, false, false),
                PivotAction::Complete
            );
        }

        #[test]
        fn pivot_action_execute_move_when_proxy_ready() {
            assert_eq!(
                determine_pivot_action(false, true, true, true),
                PivotAction::ExecuteMove
            );
        }

        #[test]
        fn pivot_action_wait_for_proxy_when_in_progress_no_proxy() {
            assert_eq!(
                determine_pivot_action(false, true, false, true),
                PivotAction::WaitForProxy
            );
        }

        #[test]
        fn pivot_action_send_command_when_agent_connected() {
            assert_eq!(
                determine_pivot_action(false, false, false, true),
                PivotAction::SendPivotCommand
            );
        }

        #[test]
        fn pivot_action_wait_for_agent_when_nothing_ready() {
            assert_eq!(
                determine_pivot_action(false, false, false, false),
                PivotAction::WaitForAgent
            );
        }
    }
}
