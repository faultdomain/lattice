//! KubeClient trait and real implementation.
//!
//! This module defines the trait abstracting Kubernetes client operations
//! for the LatticeCluster controller, plus the concrete implementation.

use async_trait::async_trait;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::{Client, Resource};
use serde::de::DeserializeOwned;
use tracing::{debug, info};

#[cfg(test)]
use mockall::automock;

use lattice_common::crd::{LatticeCluster, LatticeClusterStatus};
use lattice_common::{Error, CELL_SERVICE_NAME, LATTICE_SYSTEM_NAMESPACE};

use super::pure::{is_control_plane_node, is_node_ready};
use super::FIELD_MANAGER;

/// Ready node counts and per-pool resource capacity returned by [`KubeClient::get_ready_node_counts`].
#[derive(Debug, Clone, PartialEq)]
pub struct NodeCounts {
    pub ready_control_plane: u32,
    pub ready_workers: u32,
    pub pool_resources: Vec<lattice_common::crd::PoolResourceSummary>,
}

/// Helper function to get a Kubernetes resource by name, returning None if not found.
///
/// This reduces boilerplate for the common pattern of handling 404 errors when
/// fetching resources that may or may not exist.
pub(crate) async fn get_optional<K>(api: &Api<K>, name: &str) -> Result<Option<K>, Error>
where
    K: Resource + Clone + DeserializeOwned + std::fmt::Debug,
{
    match api.get(name).await {
        Ok(resource) => Ok(Some(resource)),
        Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(None),
        Err(e) => Err(e.into()),
    }
}

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

    /// Get ready node counts (control plane and workers) in a single API call.
    ///
    /// Returns `(ready_control_plane, ready_workers)`.
    async fn get_ready_node_counts(&self) -> Result<NodeCounts, Error>;

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
    /// cell servers (bootstrap, gRPC, proxy, auth-proxy) for workload cluster provisioning.
    /// The LB address is auto-discovered from Service status.
    async fn ensure_cell_service(
        &self,
        bootstrap_port: u16,
        grpc_port: u16,
        proxy_port: u16,
        provider_type: &lattice_common::crd::ProviderType,
    ) -> Result<(), Error>;

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

    /// Add a finalizer to a LatticeCluster
    async fn add_cluster_finalizer(&self, cluster_name: &str, finalizer: &str)
        -> Result<(), Error>;

    /// Remove a finalizer from a LatticeCluster
    async fn remove_cluster_finalizer(
        &self,
        cluster_name: &str,
        finalizer: &str,
    ) -> Result<(), Error>;

    /// Delete a LatticeCluster by name
    async fn delete_cluster(&self, name: &str) -> Result<(), Error>;

    /// Get the cell host from the LoadBalancer Service status
    ///
    /// Returns the hostname or IP from the cell Service's LoadBalancer ingress.
    /// Returns None if the Service doesn't exist or has no ingress assigned yet.
    async fn get_cell_host(&self) -> Result<Option<String>, Error>;

    /// Delete the cell LoadBalancer Service
    ///
    /// Called during unpivot to clean up the LoadBalancer before cluster deletion.
    /// This prevents orphaning cloud load balancer resources.
    async fn delete_cell_service(&self) -> Result<(), Error>;

    /// Check if the cell LoadBalancer Service exists
    async fn cell_service_exists(&self) -> Result<bool, Error>;

    /// List all LatticeCluster resources
    async fn list_clusters(&self) -> Result<Vec<LatticeCluster>, Error>;

    /// Get a InfraProvider by name
    ///
    /// InfraProviders are namespaced in lattice-system.
    async fn get_cloud_provider(
        &self,
        name: &str,
    ) -> Result<Option<lattice_common::crd::InfraProvider>, Error>;

    /// Cordon a node (set spec.unschedulable = true).
    ///
    /// Prevents new pods from being scheduled on the node while letting
    /// existing pods continue running. Used for proactive GPU health warnings.
    async fn cordon_node(&self, name: &str) -> Result<(), Error>;

    /// Drain a node by evicting all non-DaemonSet pods.
    ///
    /// Uses the Eviction API to respect PodDisruptionBudgets. Skips pods
    /// owned by DaemonSets (mirror pods, monitoring, etc.).
    async fn drain_node(&self, name: &str) -> Result<(), Error>;

    /// Uncordon a node (set spec.unschedulable = false).
    ///
    /// Re-enables scheduling on a node that was previously cordoned.
    async fn uncordon_node(&self, name: &str) -> Result<(), Error>;

    /// Check if any pending pods with priority > 0 request GPU resources.
    ///
    /// Used by the GPU cordon budget logic to decide whether to selectively
    /// uncordon a node when pending high-priority GPU pods need capacity.
    async fn has_pending_gpu_pods(&self) -> Result<bool, Error>;

    /// List all nodes in the cluster.
    ///
    /// Used by the Ready phase to check GPU annotations on all nodes.
    async fn list_nodes(&self) -> Result<Vec<k8s_openapi::api::core::v1::Node>, Error>;
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
        lattice_common::kube_utils::patch_cluster_resource_status::<LatticeCluster>(
            &self.client,
            name,
            status,
            FIELD_MANAGER,
        )
        .await?;
        Ok(())
    }

    async fn get_ready_node_counts(&self) -> Result<NodeCounts, Error> {
        use k8s_openapi::api::core::v1::Node;

        let node_api: Api<Node> = Api::all(self.client.clone());
        let nodes = node_api.list(&Default::default()).await?;

        let mut ready_control_plane = 0u32;
        let mut ready_workers = 0u32;

        for node in &nodes.items {
            if is_node_ready(node) {
                if is_control_plane_node(node) {
                    ready_control_plane += 1;
                } else {
                    ready_workers += 1;
                }
            }
        }

        let pool_resources = lattice_common::resources::gather_pool_resources(&self.client).await;

        Ok(NodeCounts {
            ready_control_plane,
            ready_workers,
            pool_resources,
        })
    }

    async fn ensure_namespace(&self, name: &str) -> Result<(), Error> {
        let labels = std::collections::BTreeMap::from([(
            lattice_common::LABEL_MANAGED_BY.to_string(),
            lattice_common::LABEL_MANAGED_BY_LATTICE.to_string(),
        )]);
        lattice_common::kube_utils::ensure_namespace(
            &self.client,
            name,
            Some(&labels),
            FIELD_MANAGER,
        )
        .await?;
        debug!(namespace = %name, "ensured namespace exists");
        Ok(())
    }

    async fn get_cluster(&self, name: &str) -> Result<Option<LatticeCluster>, Error> {
        let api: Api<LatticeCluster> = Api::all(self.client.clone());
        get_optional(&api, name).await
    }

    async fn get_secret(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<k8s_openapi::api::core::v1::Secret>, Error> {
        use k8s_openapi::api::core::v1::Secret;
        let api: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        get_optional(&api, name).await
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
        if get_optional(&target_api, name).await?.is_some() {
            debug!(
                secret = %name,
                source = %source_namespace,
                target = %target_namespace,
                "secret already exists in target namespace"
            );
            return Ok(());
        }

        // Get the source secret
        let source_secret = self
            .get_secret(name, source_namespace)
            .await?
            .ok_or_else(|| {
                Error::bootstrap(format!(
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
        bootstrap_port: u16,
        grpc_port: u16,
        proxy_port: u16,
        provider_type: &lattice_common::crd::ProviderType,
    ) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::Service;

        let api: Api<Service> = Api::namespaced(self.client.clone(), LATTICE_SYSTEM_NAMESPACE);

        if get_optional(&api, CELL_SERVICE_NAME).await?.is_some() {
            debug!("cell service already exists");
        } else {
            info!("creating cell LoadBalancer service");
            let service = lattice_common::kube_utils::build_cell_service(
                bootstrap_port,
                grpc_port,
                proxy_port,
                provider_type,
            );
            api.create(&PostParams::default(), &service).await?;
        }

        Ok(())
    }

    async fn add_cluster_finalizer(
        &self,
        cluster_name: &str,
        finalizer: &str,
    ) -> Result<(), Error> {
        let api: Api<LatticeCluster> = Api::all(self.client.clone());

        // Get current cluster to read existing finalizers
        let cluster = match get_optional(&api, cluster_name).await? {
            Some(c) => c,
            None => {
                debug!(cluster = %cluster_name, "Cluster not found, skipping finalizer addition");
                return Ok(());
            }
        };
        let mut finalizers = cluster.metadata.finalizers.unwrap_or_default();

        // Don't add if already present
        if finalizers.contains(&finalizer.to_string()) {
            return Ok(());
        }

        finalizers.push(finalizer.to_string());

        let patch = serde_json::json!({
            "metadata": {
                "finalizers": finalizers
            }
        });

        api.patch(
            cluster_name,
            &PatchParams::apply(FIELD_MANAGER),
            &Patch::Merge(&patch),
        )
        .await?;

        Ok(())
    }

    async fn remove_cluster_finalizer(
        &self,
        cluster_name: &str,
        finalizer: &str,
    ) -> Result<(), Error> {
        let api: Api<LatticeCluster> = Api::all(self.client.clone());

        // Get current cluster to read existing finalizers
        let cluster = match get_optional(&api, cluster_name).await? {
            Some(c) => c,
            None => {
                debug!(cluster = %cluster_name, "Cluster not found, finalizer already removed");
                return Ok(());
            }
        };
        let finalizers: Vec<String> = cluster
            .metadata
            .finalizers
            .as_ref()
            .map(|f| f.iter().filter(|s| *s != finalizer).cloned().collect())
            .unwrap_or_default();

        let patch = serde_json::json!({
            "metadata": {
                "finalizers": finalizers
            }
        });

        api.patch(
            cluster_name,
            &PatchParams::apply(FIELD_MANAGER),
            &Patch::Merge(&patch),
        )
        .await?;

        Ok(())
    }

    async fn delete_cluster(&self, name: &str) -> Result<(), Error> {
        let api: Api<LatticeCluster> = Api::all(self.client.clone());
        match api.delete(name, &Default::default()).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(cluster = %name, "LatticeCluster not found (already deleted)");
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn get_cell_host(&self) -> Result<Option<String>, Error> {
        use k8s_openapi::api::core::v1::Service;

        let api: Api<Service> = Api::namespaced(self.client.clone(), LATTICE_SYSTEM_NAMESPACE);
        let svc = match get_optional(&api, CELL_SERVICE_NAME).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        // Get host from LoadBalancer ingress status
        let host = svc
            .status
            .and_then(|s| s.load_balancer)
            .and_then(|lb| lb.ingress)
            .and_then(|ingress| ingress.first().cloned())
            .and_then(|first| first.hostname.or(first.ip));

        Ok(host)
    }

    async fn delete_cell_service(&self) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::Service;
        use kube::api::DeleteParams;

        let api: Api<Service> = Api::namespaced(self.client.clone(), LATTICE_SYSTEM_NAMESPACE);
        match api
            .delete(CELL_SERVICE_NAME, &DeleteParams::default())
            .await
        {
            Ok(_) => {
                info!(
                    service = CELL_SERVICE_NAME,
                    "Deleted cell LoadBalancer service"
                );
                Ok(())
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(
                    service = CELL_SERVICE_NAME,
                    "Cell service not found (already deleted)"
                );
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn cell_service_exists(&self) -> Result<bool, Error> {
        use k8s_openapi::api::core::v1::Service;

        let api: Api<Service> = Api::namespaced(self.client.clone(), LATTICE_SYSTEM_NAMESPACE);
        Ok(get_optional(&api, CELL_SERVICE_NAME).await?.is_some())
    }

    async fn list_clusters(&self) -> Result<Vec<LatticeCluster>, Error> {
        let api: Api<LatticeCluster> = Api::all(self.client.clone());
        let list = api.list(&Default::default()).await?;
        Ok(list.items)
    }

    async fn get_cloud_provider(
        &self,
        name: &str,
    ) -> Result<Option<lattice_common::crd::InfraProvider>, Error> {
        use lattice_common::crd::InfraProvider;

        let api: Api<InfraProvider> =
            Api::namespaced(self.client.clone(), LATTICE_SYSTEM_NAMESPACE);
        get_optional(&api, name).await
    }

    async fn cordon_node(&self, name: &str) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::Node;

        let node_api: Api<Node> = Api::all(self.client.clone());
        let patch = serde_json::json!({
            "spec": {
                "unschedulable": true
            }
        });
        node_api
            .patch(name, &PatchParams::apply(FIELD_MANAGER), &Patch::Merge(&patch))
            .await?;
        info!(node = %name, "cordoned node");
        Ok(())
    }

    async fn drain_node(&self, name: &str) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::Pod;
        use kube::api::{EvictParams, ListParams};
        use lattice_common::resources::{parse_quantity_int, GPU_RESOURCE};

        let pod_api: Api<Pod> = Api::all(self.client.clone());
        let lp = ListParams::default().fields(&format!("spec.nodeName={}", name));
        let pods = pod_api.list(&lp).await?;

        for pod in &pods.items {
            let pod_name = match pod.metadata.name.as_deref() {
                Some(n) => n,
                None => continue,
            };
            let namespace = pod
                .metadata
                .namespace
                .as_deref()
                .unwrap_or("default");

            // Skip pods owned by DaemonSets
            let is_daemonset = pod
                .metadata
                .owner_references
                .as_ref()
                .map(|refs| refs.iter().any(|r| r.kind == "DaemonSet"))
                .unwrap_or(false);
            if is_daemonset {
                debug!(pod = %pod_name, "skipping DaemonSet pod during drain");
                continue;
            }

            // Skip terminal pods
            let phase = pod
                .status
                .as_ref()
                .and_then(|s| s.phase.as_deref())
                .unwrap_or("");
            if phase == "Succeeded" || phase == "Failed" {
                continue;
            }

            // Only evict pods that request GPU resources — leave CPU-only pods
            // running on the GPU node (the GPU failure doesn't affect them)
            let requests_gpu = pod.spec.as_ref().map(|spec| {
                spec.containers.iter().any(|c| {
                    c.resources
                        .as_ref()
                        .and_then(|r| r.requests.as_ref())
                        .and_then(|req| req.get(GPU_RESOURCE))
                        .map(|q| parse_quantity_int(Some(q)).unwrap_or(0) > 0)
                        .unwrap_or(false)
                })
            }).unwrap_or(false);

            if !requests_gpu {
                debug!(pod = %pod_name, "skipping non-GPU pod during GPU drain");
                continue;
            }

            let ns_pod_api: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
            match ns_pod_api
                .evict(pod_name, &EvictParams::default())
                .await
            {
                Ok(_) => {
                    debug!(pod = %pod_name, namespace, "evicted GPU pod");
                }
                Err(kube::Error::Api(ae)) if ae.code == 404 => {
                    debug!(pod = %pod_name, "pod already gone");
                }
                Err(kube::Error::Api(ae)) if ae.code == 429 => {
                    // PDB violation — skip for now, retry on next reconcile
                    debug!(pod = %pod_name, "PDB prevented eviction, will retry");
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }

        info!(node = %name, "drained node (GPU pods evicted)");
        Ok(())
    }

    async fn uncordon_node(&self, name: &str) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::Node;

        let node_api: Api<Node> = Api::all(self.client.clone());
        let patch = serde_json::json!({
            "spec": {
                "unschedulable": false
            }
        });
        node_api
            .patch(name, &PatchParams::apply(FIELD_MANAGER), &Patch::Merge(&patch))
            .await?;
        info!(node = %name, "uncordoned node");
        Ok(())
    }

    async fn has_pending_gpu_pods(&self) -> Result<bool, Error> {
        use k8s_openapi::api::core::v1::Pod;
        use kube::api::ListParams;
        use lattice_common::resources::GPU_RESOURCE;

        let pod_api: Api<Pod> = Api::all(self.client.clone());
        let lp = ListParams::default().fields("status.phase=Pending");
        let pods = pod_api.list(&lp).await?;

        let found = pods.items.iter().any(|pod| {
            let priority = pod
                .spec
                .as_ref()
                .and_then(|s| s.priority)
                .unwrap_or(0);
            if priority <= 0 {
                return false;
            }
            pod.spec
                .as_ref()
                .map(|spec| {
                    spec.containers.iter().any(|c| {
                        c.resources
                            .as_ref()
                            .and_then(|r| r.requests.as_ref())
                            .and_then(|req| req.get(GPU_RESOURCE))
                            .map(|q| lattice_common::resources::parse_quantity_int(Some(q)).unwrap_or(0) > 0)
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        });

        Ok(found)
    }

    async fn list_nodes(&self) -> Result<Vec<k8s_openapi::api::core::v1::Node>, Error> {
        use k8s_openapi::api::core::v1::Node;

        let node_api: Api<Node> = Api::all(self.client.clone());
        let nodes = node_api.list(&Default::default()).await?;
        Ok(nodes.items)
    }
}
