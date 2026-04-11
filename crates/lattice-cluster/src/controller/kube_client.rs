//! KubeClient trait and real implementation.
//!
//! This module defines the trait abstracting Kubernetes client operations
//! for the LatticeCluster controller, plus the concrete implementation.

use async_trait::async_trait;
use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::Client;
use tracing::{debug, info, warn};

#[cfg(test)]
use mockall::automock;

use lattice_common::crd::{LatticeCluster, LatticeClusterStatus};
use lattice_common::{Error, CELL_SERVICE_NAME, OPERATOR_NAME};
use lattice_core::LATTICE_SYSTEM_NAMESPACE;

use super::pure::{is_control_plane_node, is_node_ready};
use super::FIELD_MANAGER;

/// Ready node counts and per-pool resource capacity returned by [`KubeClient::get_ready_node_counts`].
#[derive(Debug, Clone, PartialEq)]
pub struct NodeCounts {
    pub ready_control_plane: u32,
    pub ready_workers: u32,
    pub pool_resources: Vec<lattice_common::crd::PoolResourceSummary>,
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

    /// Uncordon a node (set spec.unschedulable = false).
    ///
    /// Re-enables scheduling on a node that was previously cordoned.
    async fn uncordon_node(&self, name: &str) -> Result<(), Error>;

    /// Return the largest single-container GPU request among pending pods
    /// with priority > 0. Returns 0 if no such pods exist.
    ///
    /// Used by the GPU cordon budget logic to decide whether to selectively
    /// uncordon a node — only nodes with at least this many GPUs would help.
    async fn max_pending_gpu_request(&self) -> Result<u32, Error>;

    /// List all nodes in the cluster.
    ///
    /// Used by the Ready phase to check GPU annotations on all nodes.
    async fn list_nodes(&self) -> Result<Vec<k8s_openapi::api::core::v1::Node>, Error>;

    /// Get the container image of the lattice-operator Deployment.
    ///
    /// Reads the first container's image from the `lattice-operator` Deployment
    /// in `lattice-system`. Returns None if the Deployment doesn't exist.
    async fn get_operator_deployment_image(&self) -> Result<Option<String>, Error>;

    /// Patch the container image of the lattice-operator Deployment.
    ///
    /// Uses a strategic merge patch to update the first container's image.
    async fn patch_operator_deployment_image(&self, image: &str) -> Result<(), Error>;
}

/// Real Kubernetes client implementation
pub struct KubeClientImpl {
    client: Client,
    cache: lattice_cache::ResourceCache,
}

impl KubeClientImpl {
    /// Create a new KubeClientImpl wrapping the given kube Client and resource cache.
    ///
    /// Node reads (`get_ready_node_counts`, `list_nodes`) are served from the
    /// cache; all writes still go through the API server.
    pub fn new(client: Client, cache: lattice_cache::ResourceCache) -> Self {
        Self { client, cache }
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

        let nodes = self.cache.list::<Node>();

        let mut ready_control_plane = 0u32;
        let mut ready_workers = 0u32;

        for node in &nodes {
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
        match api.get_opt(name).await? {
            Some(c) => Ok(Some(c)),
            None => Ok(None),
        }
    }

    async fn get_secret(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<k8s_openapi::api::core::v1::Secret>, Error> {
        use k8s_openapi::api::core::v1::Secret;
        let api: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        match api.get_opt(name).await? {
            Some(s) => Ok(Some(s)),
            None => Ok(None),
        }
    }

    async fn ensure_cell_service(
        &self,
        bootstrap_port: u16,
        grpc_port: u16,
        proxy_port: u16,
        provider_type: &lattice_common::crd::ProviderType,
    ) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::Service;

        if self
            .cache
            .get_namespaced::<Service>(CELL_SERVICE_NAME, LATTICE_SYSTEM_NAMESPACE)
            .is_some()
        {
            debug!("cell service already exists");
        } else {
            info!("creating cell LoadBalancer service");
            let api: Api<Service> = Api::namespaced(self.client.clone(), LATTICE_SYSTEM_NAMESPACE);
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

        // Read from API for optimistic concurrency (read-modify-write needs fresh data)
        let cluster = match api.get_opt(cluster_name).await? {
            Some(c) => c,
            None => {
                debug!(cluster = %cluster_name, "Cluster not found, skipping finalizer addition");
                return Ok(());
            }
        };
        let mut finalizers = cluster.metadata.finalizers.clone().unwrap_or_default();

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

        // Read from API for optimistic concurrency (read-modify-write needs fresh data)
        let cluster = match api.get_opt(cluster_name).await? {
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

        let svc = match self
            .cache
            .get_namespaced::<Service>(CELL_SERVICE_NAME, LATTICE_SYSTEM_NAMESPACE)
        {
            Some(s) => s,
            None => return Ok(None),
        };

        // Get host from LoadBalancer ingress status
        let host = svc
            .status
            .as_ref()
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_ref())
            .and_then(|ingress| ingress.first())
            .and_then(|first| first.hostname.clone().or(first.ip.clone()));

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

        Ok(self
            .cache
            .get_namespaced::<Service>(CELL_SERVICE_NAME, LATTICE_SYSTEM_NAMESPACE)
            .is_some())
    }

    async fn list_clusters(&self) -> Result<Vec<LatticeCluster>, Error> {
        let api: Api<LatticeCluster> = Api::all(self.client.clone());
        Ok(api.list(&Default::default()).await?.items)
    }

    async fn get_cloud_provider(
        &self,
        name: &str,
    ) -> Result<Option<lattice_common::crd::InfraProvider>, Error> {
        use lattice_common::crd::InfraProvider;

        Ok(self
            .cache
            .get_namespaced::<InfraProvider>(name, LATTICE_SYSTEM_NAMESPACE)
            .map(|arc| (*arc).clone()))
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
            .patch(
                name,
                &PatchParams::apply(FIELD_MANAGER),
                &Patch::Merge(&patch),
            )
            .await?;
        info!(node = %name, "cordoned node");
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
            .patch(
                name,
                &PatchParams::apply(FIELD_MANAGER),
                &Patch::Merge(&patch),
            )
            .await?;
        info!(node = %name, "uncordoned node");
        Ok(())
    }

    async fn max_pending_gpu_request(&self) -> Result<u32, Error> {
        use k8s_openapi::api::core::v1::Pod;
        use lattice_common::resources::GPU_RESOURCE;

        let pods = self.cache.list_filtered::<Pod>(|pod| {
            pod.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Pending")
        });

        let max_req = pods
            .iter()
            .filter_map(|pod| {
                let spec = pod.spec.as_ref()?;
                if spec.priority.unwrap_or(0) <= 0 {
                    return None;
                }
                spec.containers
                    .iter()
                    .filter_map(|c| {
                        let q = c.resources.as_ref()?.requests.as_ref()?.get(GPU_RESOURCE)?;
                        let count = match lattice_common::resources::parse_quantity_int(Some(q)) {
                            Ok(v) => v,
                            Err(e) => {
                                let pod_name = pod.metadata.name.as_deref().unwrap_or("<unknown>");
                                warn!(pod = %pod_name, value = ?q, error = %e, "Failed to parse GPU request quantity, treating as 0");
                                0
                            }
                        };
                        if count > 0 {
                            Some(count as u32)
                        } else {
                            None
                        }
                    })
                    .max()
            })
            .max()
            .unwrap_or(0);

        Ok(max_req)
    }

    async fn list_nodes(&self) -> Result<Vec<k8s_openapi::api::core::v1::Node>, Error> {
        use k8s_openapi::api::core::v1::Node;

        let nodes = self.cache.list::<Node>();
        Ok(nodes.into_iter().map(|arc| (*arc).clone()).collect())
    }

    async fn get_operator_deployment_image(&self) -> Result<Option<String>, Error> {
        use k8s_openapi::api::apps::v1::Deployment;

        let deploy = match self
            .cache
            .get_namespaced::<Deployment>(OPERATOR_NAME, LATTICE_SYSTEM_NAMESPACE)
        {
            Some(d) => d,
            None => return Ok(None),
        };
        let image = deploy
            .spec
            .as_ref()
            .and_then(|s| s.template.spec.as_ref())
            .and_then(|s| s.containers.first())
            .and_then(|c| c.image.clone());
        Ok(image)
    }

    async fn patch_operator_deployment_image(&self, image: &str) -> Result<(), Error> {
        use k8s_openapi::api::apps::v1::Deployment;

        let api: Api<Deployment> = Api::namespaced(self.client.clone(), LATTICE_SYSTEM_NAMESPACE);
        let patch = serde_json::json!({
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": OPERATOR_NAME,
                            "image": image
                        }]
                    }
                }
            }
        });
        api.patch(
            OPERATOR_NAME,
            &PatchParams::apply(FIELD_MANAGER).force(),
            &Patch::Strategic(&patch),
        )
        .await?;
        info!(image = %image, "Patched lattice-operator Deployment image");
        Ok(())
    }
}
