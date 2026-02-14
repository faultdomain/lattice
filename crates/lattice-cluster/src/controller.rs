//! LatticeCluster controller implementation
//!
//! This module implements the reconciliation logic for LatticeCluster resources.
//! It follows the Kubernetes controller pattern: observe current state, determine
//! desired state, calculate diff, and apply changes.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;

use async_trait::async_trait;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::runtime::controller::Action;
use kube::{Client, Resource, ResourceExt};
use serde::de::DeserializeOwned;
use tracing::{debug, error, info, instrument, warn};

#[cfg(test)]
use lattice_common::NoopEventPublisher;
#[cfg(test)]
use mockall::automock;

use kube::runtime::events::EventType;
use lattice_common::crd::{ClusterPhase, LatticeCluster, LatticeClusterStatus, WorkerPoolSpec};

use lattice_common::events::{actions, reasons, EventPublisher};
use lattice_common::metrics::{self, ReconcileTimer};
use lattice_common::{
    capi_namespace, Error, KubeEventPublisher, CELL_SERVICE_NAME, LATTICE_SYSTEM_NAMESPACE,
    PARENT_CONFIG_SECRET,
};
use lattice_move::{CellMover, CellMoverConfig};
use lattice_proto::AgentState;

use lattice_capi::client::{CAPIClient, CAPIClientImpl};
use lattice_capi::installer::CapiInstaller;
use lattice_cell::{
    fetch_distributable_resources, DefaultManifestGenerator, ParentServers, SharedAgentRegistry,
};
use lattice_common::DistributableResources;

use crate::phases::{
    handle_pending, handle_pivoting, handle_provisioning, handle_ready, update_status,
};

/// Ready node counts returned by [`KubeClient::get_ready_node_counts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeCounts {
    pub ready_control_plane: u32,
    pub ready_workers: u32,
}

/// Helper function to get a Kubernetes resource by name, returning None if not found.
///
/// This reduces boilerplate for the common pattern of handling 404 errors when
/// fetching resources that may or may not exist.
async fn get_optional<K>(api: &Api<K>, name: &str) -> Result<Option<K>, Error>
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
    /// cell servers (bootstrap + gRPC) for workload cluster provisioning.
    /// The LB address is auto-discovered from Service status.
    async fn ensure_cell_service(&self, bootstrap_port: u16, grpc_port: u16) -> Result<(), Error>;

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

    /// Get a CloudProvider by name
    ///
    /// CloudProviders are namespaced in lattice-system.
    async fn get_cloud_provider(
        &self,
        name: &str,
    ) -> Result<Option<lattice_common::crd::CloudProvider>, Error>;
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

    async fn get_ready_node_counts(&self) -> Result<NodeCounts, Error> {
        use k8s_openapi::api::core::v1::Node;

        let api: Api<Node> = Api::all(self.client.clone());
        let nodes = api.list(&Default::default()).await?;

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

        Ok(NodeCounts {
            ready_control_plane,
            ready_workers,
        })
    }

    async fn ensure_namespace(&self, name: &str) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::Namespace;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

        let api: Api<Namespace> = Api::all(self.client.clone());

        // Check if namespace already exists
        if get_optional(&api, name).await?.is_some() {
            debug!(namespace = %name, "namespace already exists");
            return Ok(());
        }

        // Create the namespace
        let ns = Namespace {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                labels: Some(std::collections::BTreeMap::from([(
                    lattice_common::LABEL_MANAGED_BY.to_string(),
                    lattice_common::LABEL_MANAGED_BY_LATTICE.to_string(),
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

    async fn ensure_cell_service(&self, bootstrap_port: u16, grpc_port: u16) -> Result<(), Error> {
        use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
        use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

        let api: Api<Service> = Api::namespaced(self.client.clone(), LATTICE_SYSTEM_NAMESPACE);

        let mut labels = std::collections::BTreeMap::new();
        labels.insert("app".to_string(), "lattice-operator".to_string());

        let service = Service {
            metadata: ObjectMeta {
                name: Some(CELL_SERVICE_NAME.to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                labels: Some(labels.clone()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                type_: Some("LoadBalancer".to_string()),
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
        if get_optional(&api, CELL_SERVICE_NAME).await?.is_some() {
            debug!("cell service already exists");
        } else {
            info!("creating cell LoadBalancer service");
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
            &PatchParams::apply("lattice-controller"),
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
            &PatchParams::apply("lattice-controller"),
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
    ) -> Result<Option<lattice_common::crd::CloudProvider>, Error> {
        use lattice_common::crd::CloudProvider;

        let api: Api<CloudProvider> =
            Api::namespaced(self.client.clone(), LATTICE_SYSTEM_NAMESPACE);
        get_optional(&api, name).await
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
pub(crate) fn is_control_plane_node(node: &k8s_openapi::api::core::v1::Node) -> bool {
    node.metadata
        .labels
        .as_ref()
        .map(|l| l.contains_key("node-role.kubernetes.io/control-plane"))
        .unwrap_or(false)
}

/// Check if a node has the Ready condition set to True.
pub(crate) fn is_node_ready(node: &k8s_openapi::api::core::v1::Node) -> bool {
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

/// Actions that can be taken during the pivot phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PivotAction {
    /// Pivot is complete, transition to Ready
    Complete,
    /// Trigger pivot (trigger_pivot blocks until MoveCompleteAck)
    TriggerPivot,
    /// Wait for agent to connect
    WaitForAgent,
}

/// Determine what pivot action to take based on current state.
///
/// This encapsulates the pivot state machine logic in a pure function.
/// Note: trigger_pivot() is synchronous - it blocks until MoveCompleteAck.
pub fn determine_pivot_action(is_pivot_complete: bool, is_agent_connected: bool) -> PivotAction {
    if is_pivot_complete {
        PivotAction::Complete
    } else if is_agent_connected {
        PivotAction::TriggerPivot
    } else {
        PivotAction::WaitForAgent
    }
}

/// Action to take for pool scaling
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScalingAction {
    /// No action needed - replicas match desired or autoscaler manages the pool
    NoOp {
        /// Desired replicas (for status reporting)
        desired: u32,
        /// Whether autoscaling is enabled
        autoscaling: bool,
    },
    /// Scale the pool to the specified replica count
    Scale {
        /// Current replica count
        current: u32,
        /// Target replica count
        target: u32,
    },
    /// MachineDeployment not found - wait for it to be created
    WaitForMachineDeployment,
}

impl ScalingAction {
    /// Returns the desired replica count for status reporting
    pub fn desired_replicas(&self) -> u32 {
        match self {
            ScalingAction::NoOp { desired, .. } => *desired,
            ScalingAction::Scale { target, .. } => *target,
            ScalingAction::WaitForMachineDeployment => 0,
        }
    }

    /// Returns whether autoscaling is enabled
    pub fn is_autoscaling(&self) -> bool {
        matches!(
            self,
            ScalingAction::NoOp {
                autoscaling: true,
                ..
            }
        )
    }
}

/// Determine what scaling action to take for a worker pool.
///
/// This encapsulates the scaling decision logic in a pure function.
/// Uses `WorkerPoolSpec::is_autoscaling_enabled()` to check autoscaling status.
pub fn determine_scaling_action(
    pool_spec: &WorkerPoolSpec,
    current_replicas: Option<u32>,
) -> ScalingAction {
    if pool_spec.is_autoscaling_enabled() {
        // Autoscaling: use current replicas or fall back to min
        let desired = current_replicas.unwrap_or_else(|| pool_spec.min.unwrap_or(0));
        return ScalingAction::NoOp {
            desired,
            autoscaling: true,
        };
    }

    // Static scaling
    match current_replicas {
        Some(current) if current == pool_spec.replicas => ScalingAction::NoOp {
            desired: pool_spec.replicas,
            autoscaling: false,
        },
        Some(current) => ScalingAction::Scale {
            current,
            target: pool_spec.replicas,
        },
        None if pool_spec.replicas > 0 => ScalingAction::WaitForMachineDeployment,
        None => ScalingAction::NoOp {
            desired: 0,
            autoscaling: false,
        },
    }
}

/// Generate a warning message if spec.replicas is outside autoscaling bounds.
///
/// Returns None if autoscaling is disabled or replicas is within bounds.
pub fn autoscaling_warning(pool_spec: &WorkerPoolSpec) -> Option<String> {
    match (pool_spec.min, pool_spec.max) {
        (Some(min), Some(max)) if pool_spec.replicas < min || pool_spec.replicas > max => {
            Some(format!(
                "replicas ({}) ignored, autoscaler manages within [{}, {}]",
                pool_spec.replicas, min, max
            ))
        }
        _ => None,
    }
}

// =============================================================================
// End Pure Functions
// =============================================================================

/// Trait abstracting pivot operations for testability
#[cfg_attr(test, automock)]
#[async_trait]
pub trait PivotOperations: Send + Sync {
    /// Export CAPI manifests and send to agent for import.
    async fn trigger_pivot(
        &self,
        cluster_name: &str,
        source_namespace: &str,
        target_namespace: &str,
    ) -> Result<(), Error>;

    /// Check if agent is ready for pivot
    fn is_agent_ready(&self, cluster_name: &str) -> bool;

    /// Check if pivot is complete
    fn is_pivot_complete(&self, cluster_name: &str) -> bool;
}

/// Shared context for the LatticeCluster controller
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
    /// Raw Kubernetes client (for operations that need the concrete type, e.g. secret distribution)
    /// None only in tests using mocks
    pub client: Option<Client>,
    /// CAPI client for applying manifests
    pub capi: Arc<dyn CAPIClient>,
    /// CAPI installer for installing CAPI and providers
    pub capi_installer: Arc<dyn CapiInstaller>,
    /// Cell servers (started at application startup)
    pub parent_servers: Option<Arc<ParentServers<DefaultManifestGenerator>>>,
    /// Name of the cluster this controller is running on (from LATTICE_CLUSTER_NAME env var)
    /// When reconciling this cluster, we skip provisioning since we ARE this cluster
    pub self_cluster_name: Option<String>,
    /// Event publisher for emitting Kubernetes Events
    pub events: Arc<dyn EventPublisher>,
    /// Per-cluster error counts for exponential backoff in error_policy
    pub error_counts: DashMap<String, u32>,
}

impl Context {
    /// Create a builder for constructing a Context
    pub fn builder(client: Client) -> ContextBuilder {
        ContextBuilder::new(client)
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
            client: None, // Tests use mocks, not real client
            capi,
            capi_installer,
            parent_servers: None,
            self_cluster_name: None,
            events: Arc::new(NoopEventPublisher),
            error_counts: DashMap::new(),
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
    events: Option<Arc<dyn EventPublisher>>,
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
            events: None,
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

    /// Override the event publisher (primarily for testing)
    pub fn event_publisher(mut self, events: Arc<dyn EventPublisher>) -> Self {
        self.events = Some(events);
        self
    }

    /// Build the Context
    pub fn build(self) -> Context {
        use lattice_capi::installer::NativeInstaller;

        let events = self.events.unwrap_or_else(|| {
            Arc::new(KubeEventPublisher::new(
                self.client.clone(),
                "lattice-cluster-controller",
            ))
        });

        Context {
            kube: self
                .kube
                .unwrap_or_else(|| Arc::new(KubeClientImpl::new(self.client.clone()))),
            client: Some(self.client.clone()),
            capi: self
                .capi
                .unwrap_or_else(|| Arc::new(CAPIClientImpl::new(self.client.clone()))),
            capi_installer: self
                .capi_installer
                .unwrap_or_else(|| Arc::new(NativeInstaller::new())),
            parent_servers: self.parent_servers,
            self_cluster_name: self.self_cluster_name,
            events,
            error_counts: DashMap::new(),
        }
    }
}

/// Finalizer name for LatticeCluster unpivot handling
pub const CLUSTER_FINALIZER: &str = "lattice.dev/unpivot";

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
#[instrument(
    skip(cluster, ctx),
    fields(
        cluster = %cluster.name_any(),
        phase = ?cluster.status.as_ref().map(|s| &s.phase),
        otel.kind = "internal"
    )
)]
pub async fn reconcile(cluster: Arc<LatticeCluster>, ctx: Arc<Context>) -> Result<Action, Error> {
    let name = cluster.name_any();
    let timer = ReconcileTimer::start(&name);
    info!("reconciling cluster");

    // Check if we're reconciling our own cluster (the one we're running on)
    let is_self = is_self_cluster(&name, ctx.self_cluster_name.as_deref());

    // Handle deletion via finalizer
    // Root/management clusters cannot be unpivoted (they have nowhere to unpivot to)
    // Only self-managed workload clusters need unpivot handling
    if cluster.metadata.deletion_timestamp.is_some() {
        let result = handle_deletion(&cluster, &ctx, is_self).await;
        match &result {
            Ok(_) => timer.success(),
            Err(_) => timer.error("transient"),
        }
        return result;
    }

    // Ensure finalizer is present for clusters that need cleanup on deletion
    // Two cases:
    // 1. Self cluster with parent - needs unpivot (export CAPI to parent)
    // 2. Non-self cluster (child) - needs CAPI cleanup (delete infrastructure)
    if !has_finalizer(&cluster) {
        if is_self {
            // Check if parent config secret exists (indicates we have a parent)
            let has_parent = ctx
                .kube
                .get_secret(PARENT_CONFIG_SECRET, LATTICE_SYSTEM_NAMESPACE)
                .await?
                .is_some();

            if has_parent {
                info!("Adding finalizer (self cluster with parent - needs unpivot)");
                add_finalizer(&cluster, &ctx).await?;
                timer.success();
                return Ok(Action::requeue(Duration::from_secs(1)));
            }
        } else {
            // Non-self cluster (we're the parent) - add finalizer for CAPI cleanup
            info!("Adding finalizer (child cluster - needs CAPI cleanup on deletion)");
            add_finalizer(&cluster, &ctx).await?;
            timer.success();
            return Ok(Action::requeue(Duration::from_secs(1)));
        }
    }

    // Validate the cluster spec
    if let Err(e) = cluster.spec.validate() {
        warn!(error = %e, "cluster validation failed");
        ctx.events
            .publish(
                &cluster.object_ref(&()),
                EventType::Warning,
                reasons::VALIDATION_FAILED,
                actions::RECONCILE,
                Some(e.to_string()),
            )
            .await;
        update_status(
            &cluster,
            &ctx,
            ClusterPhase::Failed,
            Some(&e.to_string()),
            false,
        )
        .await?;
        timer.error("permanent");
        // Don't requeue for validation errors - they require spec changes
        return Ok(Action::await_change());
    }

    // Get current status, defaulting to Pending if not set
    let current_phase = cluster
        .status
        .as_ref()
        .map(|s| s.phase)
        .unwrap_or(ClusterPhase::Pending);

    debug!(?current_phase, is_self, "current cluster phase");

    // State machine: dispatch to phase handlers
    let result = match current_phase {
        ClusterPhase::Pending => handle_pending(&cluster, &ctx, is_self).await,
        ClusterPhase::Provisioning => handle_provisioning(&cluster, &ctx).await,
        ClusterPhase::Pivoting => handle_pivoting(&cluster, &ctx, is_self).await,
        ClusterPhase::Pivoted => {
            // Child cluster is self-managing after pivot — update status
            // from agent heartbeat health data if available
            debug!("child cluster is self-managing (pivoted), monitoring");
            if let Some(ref parent_servers) = ctx.parent_servers {
                if parent_servers.is_running() {
                    let registry = parent_servers.agent_registry();
                    if let Some(health) = registry.get_health(&name) {
                        let ready_cp = health.ready_control_plane as u32;
                        let ready_workers =
                            (health.ready_nodes - health.ready_control_plane).max(0) as u32;
                        let current_status = cluster.status.clone().unwrap_or_default();
                        let updated_status = LatticeClusterStatus {
                            ready_control_plane: Some(ready_cp),
                            ready_workers: Some(ready_workers),
                            ..current_status
                        };
                        if let Err(e) = ctx.kube.patch_status(&name, &updated_status).await {
                            warn!(error = %e, "Failed to update pivoted cluster status from heartbeat");
                        }
                    }
                }
            }
            Ok(Action::requeue(Duration::from_secs(60)))
        }
        ClusterPhase::Ready => handle_ready(&cluster, &ctx).await,
        ClusterPhase::Unpivoting => {
            // Unpivoting is handled by handle_deletion, just wait
            debug!("cluster is Unpivoting, waiting for completion");
            Ok(Action::requeue(Duration::from_secs(5)))
        }
        ClusterPhase::Deleting => {
            // Deleting is handled by handle_deletion, just wait
            debug!("cluster is Deleting, waiting for completion");
            Ok(Action::requeue(Duration::from_secs(5)))
        }
        ClusterPhase::Failed => {
            // Failed state requires manual intervention
            warn!("cluster is in Failed state, awaiting spec change");
            Ok(Action::await_change())
        }
    };

    // Record reconcile metrics and update phase gauge
    match &result {
        Ok(_) => {
            timer.success();
            ctx.error_counts.remove(&cluster.name_any());
            // Update cluster phase gauge with current phase
            let phase_label = match current_phase {
                ClusterPhase::Pending => metrics::ClusterPhase::Pending,
                ClusterPhase::Provisioning => metrics::ClusterPhase::Provisioning,
                ClusterPhase::Pivoting | ClusterPhase::Pivoted => metrics::ClusterPhase::Pivoting,
                ClusterPhase::Ready => metrics::ClusterPhase::Ready,
                ClusterPhase::Failed => metrics::ClusterPhase::Failed,
                ClusterPhase::Deleting | ClusterPhase::Unpivoting => {
                    metrics::ClusterPhase::Deleting
                }
            };
            metrics::set_cluster_phase_count(phase_label, 1);
        }
        Err(_) => timer.error("transient"),
    }

    result
}

/// Maximum backoff delay for retryable errors (5 minutes)
const MAX_ERROR_BACKOFF: Duration = Duration::from_secs(300);

/// Error policy for the controller
///
/// This function is called when reconciliation fails. It determines
/// the requeue strategy:
/// - Retryable errors: exponential backoff (5s, 10s, 20s, ... capped at 5m)
/// - Non-retryable errors: await spec change, don't retry
pub fn error_policy(cluster: Arc<LatticeCluster>, error: &Error, ctx: Arc<Context>) -> Action {
    let cluster_name = cluster.name_any();

    if error.is_retryable() {
        let count = ctx
            .error_counts
            .entry(cluster_name.clone())
            .and_modify(|c| *c = c.saturating_add(1))
            .or_insert(1);
        let backoff_secs = (5u64 << (*count - 1).min(6)).min(MAX_ERROR_BACKOFF.as_secs());

        error!(
            ?error,
            cluster = %cluster_name,
            retry_count = *count,
            backoff_secs,
            "reconciliation failed (retryable)"
        );
        Action::requeue(Duration::from_secs(backoff_secs))
    } else {
        error!(
            ?error,
            cluster = %cluster_name,
            "reconciliation failed (permanent)"
        );
        ctx.error_counts.remove(&cluster_name);
        Action::await_change()
    }
}

/// Real implementation of PivotOperations using AgentRegistry
pub struct PivotOperationsImpl {
    agent_registry: SharedAgentRegistry,
    client: Client,
    self_cluster_name: Option<String>,
}

impl PivotOperationsImpl {
    /// Create new pivot operations with the given agent registry
    pub fn new(
        agent_registry: SharedAgentRegistry,
        client: Client,
        self_cluster_name: Option<String>,
    ) -> Self {
        Self {
            agent_registry,
            client,
            self_cluster_name,
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
        // Check if agent is connected
        if self.agent_registry.get(cluster_name).is_none() {
            return Err(Error::pivot(format!(
                "agent not connected for cluster {}",
                cluster_name
            )));
        }

        // Mark pivot in progress to prevent duplicate triggers
        self.agent_registry
            .update_state(cluster_name, AgentState::Pivoting);

        // Fetch resources for distribution (CloudProviders, SecretProviders, CedarPolicies, OIDCProviders, and their secrets)
        let self_cluster_name = self.self_cluster_name.as_deref().unwrap_or("unknown");
        let resources = fetch_distributable_resources(&self.client, self_cluster_name)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "failed to fetch distributable resources, continuing without");
                DistributableResources::default()
            });

        // Configure the distributed move with resources
        // Note: Infrastructure manifests (network policies, etc.) are reconciled
        // continuously by the child cluster's controller after pivot
        let config = CellMoverConfig::new(source_namespace, target_namespace, cluster_name)
            .with_distributable_resources(&resources);

        // Create the gRPC command sender
        let sender = std::sync::Arc::new(lattice_cell::GrpcMoveCommandSender::new(
            self.agent_registry.clone(),
            cluster_name.to_string(),
        ));

        // Execute the distributed move
        // All resources and manifests are sent via MoveComplete which has an ack
        let mut mover = CellMover::new(self.client.clone(), config, sender);
        let result = mover.execute().await.map_err(|e| {
            // Reset state on failure
            self.agent_registry
                .update_state(cluster_name, AgentState::Provisioning);
            Error::pivot(format!("distributed move failed: {}", e))
        })?;

        info!(
            cluster = %cluster_name,
            objects_moved = result.objects_moved,
            objects_deleted = result.objects_deleted,
            "pivot completed via distributed move"
        );

        // Move completed successfully (MoveCompleteAck received) - mark state
        self.agent_registry
            .update_state(cluster_name, AgentState::Ready);
        self.agent_registry.set_pivot_complete(cluster_name, true);

        // Persist pivot_complete to CRD status
        let api: Api<LatticeCluster> = Api::all(self.client.clone());
        let patch = serde_json::json!({
            "status": {
                "pivotComplete": true
            }
        });
        if let Err(e) = api
            .patch_status(
                cluster_name,
                &PatchParams::apply("lattice-operator"),
                &Patch::Merge(&patch),
            )
            .await
        {
            warn!(cluster = %cluster_name, error = %e, "Failed to persist pivot_complete to status");
        }

        Ok(())
    }

    fn is_agent_ready(&self, cluster_name: &str) -> bool {
        self.agent_registry
            .get(cluster_name)
            .is_some_and(|a| a.is_ready_for_pivot())
    }

    fn is_pivot_complete(&self, cluster_name: &str) -> bool {
        self.agent_registry
            .get(cluster_name)
            .is_some_and(|a| a.pivot_complete)
    }
}

/// Check if a cluster has the finalizer
fn has_finalizer(cluster: &LatticeCluster) -> bool {
    cluster
        .metadata
        .finalizers
        .as_ref()
        .is_some_and(|f| f.contains(&CLUSTER_FINALIZER.to_string()))
}

/// Add the unpivot finalizer to a cluster
async fn add_finalizer(cluster: &LatticeCluster, ctx: &Context) -> Result<(), Error> {
    let name = cluster.name_any();
    ctx.kube
        .add_cluster_finalizer(&name, CLUSTER_FINALIZER)
        .await
}

/// Remove the unpivot finalizer from a cluster
async fn remove_finalizer(cluster: &LatticeCluster, ctx: &Context) -> Result<(), Error> {
    let name = cluster.name_any();
    ctx.kube
        .remove_cluster_finalizer(&name, CLUSTER_FINALIZER)
        .await
}

/// Handle cluster deletion with unpivot logic
///
/// For cell clusters (has parent_config): blocks deletion if child clusters exist.
/// This prevents orphaning clusters. Remove finalizer manually for break-glass.
///
/// For self clusters with a parent: unpivot CAPI resources back to parent.
///
/// For root clusters (no parent): just remove the finalizer.
///
/// For non-self clusters (child clusters being deleted from parent):
/// delete CAPI Cluster to trigger infrastructure cleanup.
async fn handle_deletion(
    cluster: &LatticeCluster,
    ctx: &Context,
    is_self: bool,
) -> Result<Action, Error> {
    let name = cluster.name_any();

    // If no finalizer, nothing to do
    if !has_finalizer(cluster) {
        debug!(cluster = %name, "No finalizer, allowing deletion");
        return Ok(Action::await_change());
    }

    // For non-self clusters (we're the parent), delete CAPI infrastructure
    if !is_self {
        let capi_namespace = capi_namespace(&name);

        // Set phase to Deleting if not already
        let current_phase = cluster.status.as_ref().map(|s| &s.phase);
        if current_phase != Some(&ClusterPhase::Deleting) {
            let status = cluster
                .status
                .clone()
                .unwrap_or_default()
                .phase(ClusterPhase::Deleting);
            ctx.kube.patch_status(&name, &status).await?;
        }

        // Check if CAPI Cluster still exists
        let capi_exists = match ctx.capi.capi_cluster_exists(&name, &capi_namespace).await {
            Ok(exists) => exists,
            Err(e) => {
                // Assume exists on error to avoid premature deletion
                warn!(cluster = %name, error = %e, "Failed to check CAPI cluster existence, assuming exists");
                true
            }
        };

        if capi_exists {
            // Wait for CAPI to be stable before deleting (prevents race with provisioning)
            let is_stable = match ctx.capi.is_cluster_stable(&name, &capi_namespace).await {
                Ok(stable) => stable,
                Err(e) => {
                    debug!(cluster = %name, error = %e, "Failed to check CAPI stability, assuming unstable");
                    false
                }
            };

            if !is_stable {
                info!(cluster = %name, "Waiting for CAPI to stabilize before deletion");
                let status = cluster
                    .status
                    .clone()
                    .unwrap_or_default()
                    .phase(ClusterPhase::Deleting)
                    .message("Waiting for CAPI to stabilize before cleanup");
                ctx.kube.patch_status(&name, &status).await?;
                return Ok(Action::requeue(Duration::from_secs(10)));
            }

            // Delete CAPI Cluster to trigger infrastructure cleanup
            info!(cluster = %name, "Deleting CAPI Cluster to trigger infrastructure cleanup");
            ctx.events
                .publish(
                    &cluster.object_ref(&()),
                    EventType::Normal,
                    reasons::DELETION_STARTED,
                    actions::DELETE,
                    Some("Deleting CAPI cluster".to_string()),
                )
                .await;
            if let Err(e) = ctx.capi.delete_capi_cluster(&name, &capi_namespace).await {
                warn!(cluster = %name, error = %e, "Failed to delete CAPI Cluster");
            }
            // Requeue to wait for deletion
            return Ok(Action::requeue(Duration::from_secs(10)));
        }

        // CAPI Cluster is gone, remove finalizer
        info!(cluster = %name, "Infrastructure cleanup complete, removing finalizer");
        remove_finalizer(cluster, ctx).await?;
        return Ok(Action::await_change());
    }

    // If this cluster is a cell (has parent_config), block deletion if children exist
    if cluster.spec.parent_config.is_some() {
        let child_names: Vec<String> = ctx
            .kube
            .list_clusters()
            .await?
            .into_iter()
            .filter(|c| c.name_any() != name)
            .map(|c| c.name_any())
            .collect();

        if !child_names.is_empty() {
            warn!(cluster = %name, ?child_names, "Cannot delete cell with active children");
            let status = cluster.status.clone().unwrap_or_default().message(format!(
                "Deletion blocked: {} child cluster(s) exist: {}. Delete children first or remove finalizer for break-glass.",
                child_names.len(),
                child_names.join(", ")
            ));
            ctx.kube.patch_status(&name, &status).await?;
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
    }

    // For self clusters, check if we have a parent to unpivot to
    let has_parent = ctx
        .kube
        .get_secret(PARENT_CONFIG_SECRET, LATTICE_SYSTEM_NAMESPACE)
        .await?
        .is_some();

    if !has_parent {
        // Root cluster - no unpivot needed, just remove finalizer
        info!(cluster = %name, "Root cluster deletion - no unpivot needed");
        remove_finalizer(cluster, ctx).await?;
        return Ok(Action::await_change());
    }

    // Wait for cluster to be stable before unpivoting (no scaling in progress)
    // Check 1: CAPI resources are stable (no machines provisioning/deleting)
    let capi_namespace = capi_namespace(&name);
    let capi_stable = match ctx.capi.is_cluster_stable(&name, &capi_namespace).await {
        Ok(stable) => stable,
        Err(e) => {
            debug!(cluster = %name, error = %e, "Failed to check CAPI stability, assuming unstable");
            false
        }
    };

    if !capi_stable {
        info!(cluster = %name, "Waiting for CAPI to stabilize before unpivoting");
        let status = cluster
            .status
            .clone()
            .unwrap_or_default()
            .message("Deletion pending: waiting for CAPI to stabilize");
        ctx.kube.patch_status(&name, &status).await?;
        return Ok(Action::requeue(Duration::from_secs(10)));
    }

    // Check 2: Actual node count matches LatticeCluster spec (prevents TOCTOU with scaling)
    let desired_workers: u32 = cluster
        .spec
        .nodes
        .worker_pools
        .values()
        .map(|p| p.replicas)
        .sum();
    let ready_workers = cluster
        .status
        .as_ref()
        .and_then(|s| s.ready_workers)
        .unwrap_or(0);

    if ready_workers < desired_workers {
        info!(
            cluster = %name,
            ready = ready_workers,
            desired = desired_workers,
            "Waiting for workers to match spec before unpivoting"
        );
        let status = cluster.status.clone().unwrap_or_default().message(format!(
            "Deletion pending: waiting for workers ({}/{})",
            ready_workers, desired_workers
        ));
        ctx.kube.patch_status(&name, &status).await?;
        return Ok(Action::requeue(Duration::from_secs(10)));
    }

    // Self cluster with parent - agent handles unpivot automatically
    // The agent detects deletion_timestamp on connect and starts an unpivot retry loop
    // that keeps sending ClusterDeleting to parent until parent's CAPI deletes us.
    // We just need to:
    // 1. Delete cell service (free up the LoadBalancer IP)
    // 2. Set phase to Unpivoting
    // 3. Wait - finalizer keeps the resource around until CAPI deletes the infrastructure

    let current_phase = cluster
        .status
        .as_ref()
        .map(|s| s.phase)
        .unwrap_or(ClusterPhase::Pending);

    if current_phase != ClusterPhase::Unpivoting {
        info!(cluster = %name, "Starting unpivot - agent will send manifests to parent");
        ctx.events
            .publish(
                &cluster.object_ref(&()),
                EventType::Normal,
                reasons::UNPIVOT_STARTED,
                actions::DELETE,
                Some("Starting unpivot to parent".to_string()),
            )
            .await;

        // Delete the cell LoadBalancer service to free the IP
        ctx.kube.delete_cell_service().await?;

        // Set phase to Unpivoting
        let status = cluster
            .status
            .clone()
            .unwrap_or_default()
            .phase(ClusterPhase::Unpivoting)
            .message("Agent sending CAPI resources to parent");
        ctx.kube.patch_status(&name, &status).await?;
    }

    // Keep waiting - agent is sending manifests, parent will delete us via CAPI
    // Finalizer never explicitly removed; CAPI deletes the entire infrastructure
    debug!(cluster = %name, "Unpivoting - waiting for parent to delete via CAPI");
    Ok(Action::requeue(Duration::from_secs(30)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phases::{generate_capi_manifests, update_status as update_cluster_status};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use lattice_capi::installer::CapiProviderConfig;
    use lattice_capi::provider::CAPIManifest;
    use lattice_common::crd::{
        BackupsConfig, BootstrapProvider, CloudProvider, Condition, ConditionStatus,
        ControlPlaneSpec, EndpointsSpec, KubernetesSpec, LatticeClusterSpec, MonitoringConfig,
        NodeSpec, ProviderConfig, ProviderSpec, ServiceSpec, WorkerPoolSpec,
    };
    use mockall::mock;

    // Local mocks for traits defined in other crates - the mockall-generated mocks
    // are only available within those crates' test configurations
    mock! {
        pub CapiInstaller {}

        #[async_trait::async_trait]
        impl CapiInstaller for CapiInstaller {
            async fn ensure(&self, config: &CapiProviderConfig) -> Result<(), Error>;
        }
    }

    mock! {
        pub CAPIClient {}

        #[async_trait::async_trait]
        impl CAPIClient for CAPIClient {
            async fn apply_manifests(&self, manifests: &[CAPIManifest], namespace: &str) -> Result<(), Error>;
            async fn is_infrastructure_ready(&self, cluster_name: &str, namespace: &str, bootstrap: BootstrapProvider) -> Result<bool, Error>;
            async fn get_pool_replicas(&self, cluster_name: &str, pool_id: &str, namespace: &str) -> Result<Option<u32>, Error>;
            async fn scale_pool(&self, cluster_name: &str, pool_id: &str, namespace: &str, replicas: u32) -> Result<(), Error>;
            async fn delete_capi_cluster(&self, cluster_name: &str, namespace: &str) -> Result<(), Error>;
            async fn capi_cluster_exists(&self, cluster_name: &str, namespace: &str) -> Result<bool, Error>;
            async fn is_cluster_stable(&self, cluster_name: &str, namespace: &str) -> Result<bool, Error>;
            fn kube_client(&self) -> Client;
        }
    }

    /// Create a sample LatticeCluster for testing
    /// Note: Includes finalizer by default since non-self clusters get one on first reconcile
    fn sample_cluster(name: &str) -> LatticeCluster {
        LatticeCluster {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                finalizers: Some(vec![CLUSTER_FINALIZER.to_string()]),
                ..Default::default()
            },
            spec: LatticeClusterSpec {
                provider_ref: "test-provider".to_string(),
                provider: ProviderSpec {
                    kubernetes: KubernetesSpec {
                        version: "1.32.0".to_string(),
                        cert_sans: None,
                        bootstrap: BootstrapProvider::default(),
                    },
                    config: ProviderConfig::docker(),
                    credentials_secret_ref: None,
                },
                nodes: NodeSpec {
                    control_plane: ControlPlaneSpec {
                        replicas: 1,
                        instance_type: None,
                        root_volume: None,
                    },
                    worker_pools: std::collections::BTreeMap::from([(
                        "default".to_string(),
                        WorkerPoolSpec {
                            replicas: 2,
                            ..Default::default()
                        },
                    )]),
                },
                networking: None,
                parent_config: None,
                services: true,
                gpu: false,
                monitoring: MonitoringConfig::default(),
                backups: BackupsConfig::default(),
            },
            status: None,
        }
    }

    /// Create a sample cell (management cluster) for testing
    fn sample_parent(name: &str) -> LatticeCluster {
        let mut cluster = sample_cluster(name);
        cluster.spec.parent_config = Some(EndpointsSpec {
            grpc_port: 50051,
            bootstrap_port: 8443,
            proxy_port: 8081,
            service: ServiceSpec {
                type_: "LoadBalancer".to_string(),
            },
        });
        cluster
    }

    /// Create a sample Docker CloudProvider for testing
    fn sample_docker_provider() -> CloudProvider {
        use lattice_common::crd::{CloudProviderSpec, CloudProviderType};

        CloudProvider::new(
            "test-provider",
            CloudProviderSpec {
                provider_type: CloudProviderType::Docker,
                region: None,
                credentials_secret_ref: None,
                credentials: None,
                credential_data: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        )
    }

    /// Create a cluster with a specific status phase
    fn cluster_with_phase(name: &str, phase: ClusterPhase) -> LatticeCluster {
        let mut cluster = sample_cluster(name);
        cluster.status = Some(LatticeClusterStatus::with_phase(phase));
        // Add finalizer - non-self clusters get this on first reconcile
        cluster.metadata.finalizers = Some(vec![CLUSTER_FINALIZER.to_string()]);
        cluster
    }

    /// Create a cluster with invalid spec (zero control plane nodes)
    fn invalid_cluster(name: &str) -> LatticeCluster {
        let mut cluster = sample_cluster(name);
        cluster.spec.nodes.control_plane.replicas = 0;
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
            assert!(cluster.spec.is_parent());
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
                self.updates
                    .lock()
                    .expect("mutex should not be poisoned")
                    .push(status);
            }

            fn last_phase(&self) -> Option<ClusterPhase> {
                self.updates
                    .lock()
                    .expect("mutex should not be poisoned")
                    .last()
                    .map(|s| s.phase)
            }

            fn was_updated(&self) -> bool {
                !self
                    .updates
                    .lock()
                    .expect("mutex should not be poisoned")
                    .is_empty()
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
            // Non-self clusters get a finalizer added on first reconcile
            mock.expect_add_cluster_finalizer().returning(|_, _| Ok(()));
            // Return a Docker CloudProvider (no credentials needed)
            mock.expect_get_cloud_provider()
                .returning(|_| Ok(Some(sample_docker_provider())));

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

        /// Creates a context for read-only scenarios (minimal status updates).
        fn mock_context_readonly() -> Arc<Context> {
            let mut mock = MockKubeClient::new();
            // Default expectations for node operations (Ready phase)
            // Return 2 workers to match sample_cluster spec (so we get 60s requeue)
            mock.expect_get_ready_node_counts().returning(|| {
                Ok(NodeCounts {
                    ready_control_plane: 1,
                    ready_workers: 2,
                })
            });
            // Non-self clusters get a finalizer added on first reconcile
            mock.expect_add_cluster_finalizer().returning(|_, _| Ok(()));
            // Ready phase updates worker pool status
            mock.expect_patch_status().returning(|_, _| Ok(()));
            // Return a Docker CloudProvider (no credentials needed)
            mock.expect_get_cloud_provider()
                .returning(|_| Ok(Some(sample_docker_provider())));

            let mut capi_mock = MockCAPIClient::new();
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _, _| Ok(false));
            // MachineDeployment has 2 replicas to match spec - no scaling needed
            capi_mock
                .expect_get_pool_replicas()
                .returning(|_, _, _| Ok(Some(2)));
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
            // Non-self clusters get a finalizer added on first reconcile
            mock.expect_add_cluster_finalizer().returning(|_, _| Ok(()));
            // Return a Docker CloudProvider (no credentials needed)
            mock.expect_get_cloud_provider()
                .returning(|_| Ok(Some(sample_docker_provider())));

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
        async fn new_cluster_starts_provisioning() {
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
        async fn pending_cluster_starts_provisioning() {
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
        async fn provisioning_cluster_waits_for_infrastructure() {
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
        async fn ready_infrastructure_triggers_pivot() {
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
        async fn ready_cluster_performs_drift_detection() {
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
        async fn failed_cluster_awaits_human_intervention() {
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
        async fn invalid_spec_immediately_fails() {
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
        async fn kube_api_errors_trigger_retry() {
            let cluster = Arc::new(sample_cluster("error-cluster"));

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status()
                .returning(|_, _| Err(Error::provider("connection refused".to_string())));
            mock.expect_ensure_namespace().returning(|_| Ok(()));
            mock.expect_get_cloud_provider()
                .returning(|_| Ok(Some(sample_docker_provider())));

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
        async fn capi_failures_trigger_retry() {
            let cluster = Arc::new(sample_cluster("capi-error-cluster"));

            let mut mock = MockKubeClient::new();
            mock.expect_ensure_namespace().returning(|_| Ok(()));
            mock.expect_get_cloud_provider()
                .returning(|_| Ok(Some(sample_docker_provider())));

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
        #[case::provider_error(Error::provider("test error".to_string()), true)]
        #[case::validation_error(Error::validation("invalid spec".to_string()), false)]
        #[case::pivot_error(Error::pivot("pivot failed".to_string()), true)]
        fn test_error_policy_requeue_behavior(#[case] error: Error, #[case] retryable: bool) {
            let cluster = Arc::new(sample_cluster("test-cluster"));
            let ctx = mock_context_no_updates();

            let action = error_policy(cluster, &error, ctx);

            if retryable {
                assert_eq!(action, Action::requeue(Duration::from_secs(5)));
            } else {
                assert_eq!(action, Action::await_change());
            }
        }
    }

    /// Tests for status update error handling
    ///
    /// Note: The actual status content (phase, message, conditions) is tested
    /// through the reconcile flow tests which verify the complete behavior.
    /// These tests focus on error propagation which is a separate concern.
    mod status_error_handling {
        use super::*;

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
    mod generate_manifests_tests {
        use super::*;

        fn cluster_with_docker_config(name: &str) -> LatticeCluster {
            LatticeCluster {
                metadata: ObjectMeta {
                    name: Some(name.to_string()),
                    ..Default::default()
                },
                spec: LatticeClusterSpec {
                    provider_ref: "test-provider".to_string(),
                    provider: ProviderSpec {
                        kubernetes: KubernetesSpec {
                            version: "1.32.0".to_string(),
                            cert_sans: None,
                            bootstrap: BootstrapProvider::default(),
                        },
                        config: ProviderConfig::docker(),
                        credentials_secret_ref: None,
                    },
                    nodes: NodeSpec {
                        control_plane: ControlPlaneSpec {
                            replicas: 1,
                            instance_type: None,
                            root_volume: None,
                        },
                        worker_pools: std::collections::BTreeMap::from([(
                            "default".to_string(),
                            WorkerPoolSpec {
                                replicas: 2,
                                ..Default::default()
                            },
                        )]),
                    },
                    networking: None,
                    parent_config: None,
                    services: true,
                    gpu: false,
                    monitoring: MonitoringConfig::default(),
                    backups: BackupsConfig::default(),
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
            let manifests = result.expect("manifest generation should succeed");
            // Docker provider should generate manifests
            assert!(!manifests.is_empty());
        }
    }

    /// Infrastructure Ready Detection Tests
    ///
    /// These tests verify the controller correctly detects when CAPI
    /// infrastructure is ready based on the Cluster resource status.
    mod infrastructure_ready_detection {
        use super::*;

        /// Story: When CAPI reports infrastructure NOT ready, the controller
        /// should continue polling with the Provisioning phase requeue interval.
        #[tokio::test]
        async fn not_ready_infrastructure_triggers_requeue() {
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
        async fn ready_infrastructure_triggers_phase_transition() {
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
                updates_clone
                    .lock()
                    .expect("mutex should not be poisoned")
                    .push(status.clone());
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
            let recorded = updates.lock().expect("mutex should not be poisoned");
            assert!(!recorded.is_empty());
            assert_eq!(
                recorded.last().expect("should have records").phase,
                ClusterPhase::Pivoting
            );
            assert_eq!(action, Action::requeue(Duration::from_secs(5)));
        }

        /// Story: When CAPI infrastructure check fails, error should propagate
        /// for retry with backoff.
        #[tokio::test]
        async fn infrastructure_check_failure_propagates_error() {
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
    /// CAPI ensure is always called (it's idempotent).
    mod capi_installation_flow {
        use super::*;

        use std::sync::{Arc as StdArc, Mutex};

        /// Story: Controller always calls CAPI ensure before provisioning
        /// (ensure is idempotent - handles upgrades and no-ops).
        #[tokio::test]
        async fn capi_init_called_before_provisioning() {
            let cluster = Arc::new(sample_cluster("ready-to-provision"));

            let updates: StdArc<Mutex<Vec<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(Vec::new()));
            let updates_clone = updates.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                updates_clone
                    .lock()
                    .expect("mutex should not be poisoned")
                    .push(status.clone());
                Ok(())
            });
            mock.expect_ensure_namespace().returning(|_| Ok(()));
            mock.expect_get_cloud_provider()
                .returning(|_| Ok(Some(sample_docker_provider())));

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
            let recorded = updates.lock().expect("mutex should not be poisoned");
            assert!(!recorded.is_empty());
        }

        /// Story: When CAPI installation fails, the error should propagate
        /// for retry with exponential backoff.
        #[tokio::test]
        async fn capi_installation_failure_propagates_error() {
            let cluster = Arc::new(sample_cluster("install-fails"));

            let mut mock = MockKubeClient::new();
            mock.expect_get_cloud_provider()
                .returning(|_| Ok(Some(sample_docker_provider())));
            let capi_mock = MockCAPIClient::new();

            let mut installer = MockCapiInstaller::new();
            // Installation fails
            installer.expect_ensure().returning(|_| {
                Err(Error::capi_installation(
                    "provider manifests not found".to_string(),
                ))
            });

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
                .contains("provider manifests"));
        }
    }

    /// Status Update Content Tests
    ///
    /// These tests verify that status updates contain the correct phase,
    /// message, and conditions as the cluster progresses through its lifecycle.
    mod status_update_content {
        use super::*;

        use std::sync::{Arc as StdArc, Mutex};

        /// Story: When transitioning to Provisioning, the status should include
        /// a clear message and Provisioning condition for observability.
        #[tokio::test]
        async fn provisioning_status_has_correct_content() {
            let cluster = sample_cluster("new-cluster");

            let captured_status: StdArc<Mutex<Option<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(None));
            let captured_clone = captured_status.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                *captured_clone.lock().expect("mutex should not be poisoned") =
                    Some(status.clone());
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
                .expect("update_cluster_status should succeed");

            let status = captured_status
                .lock()
                .expect("mutex should not be poisoned")
                .clone()
                .expect("status should be set");
            assert_eq!(status.phase, ClusterPhase::Provisioning);
            assert!(status
                .message
                .expect("message should be set")
                .contains("Provisioning"));
            assert!(!status.conditions.is_empty());

            let condition = &status.conditions[0];
            assert_eq!(condition.type_, "Provisioning");
            assert_eq!(condition.status, ConditionStatus::True);
        }

        /// Story: When transitioning to Pivoting, the status should indicate
        /// that the cluster is being transitioned to self-management.
        #[tokio::test]
        async fn pivoting_status_has_correct_content() {
            let cluster = sample_cluster("pivoting-cluster");

            let captured_status: StdArc<Mutex<Option<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(None));
            let captured_clone = captured_status.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                *captured_clone.lock().expect("mutex should not be poisoned") =
                    Some(status.clone());
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
                .expect("update_cluster_status should succeed");

            let status = captured_status
                .lock()
                .expect("mutex should not be poisoned")
                .clone()
                .expect("status should be set");
            assert_eq!(status.phase, ClusterPhase::Pivoting);
            assert!(status
                .message
                .expect("message should be set")
                .contains("Pivoting"));

            let condition = &status.conditions[0];
            assert_eq!(condition.type_, "Pivoting");
            assert_eq!(condition.reason, "StartingPivot");
        }

        /// Story: When a cluster fails validation, the status should clearly
        /// indicate the failure reason so users can fix the configuration.
        #[tokio::test]
        async fn failed_status_includes_error_message() {
            let cluster = sample_cluster("invalid-cluster");

            let captured_status: StdArc<Mutex<Option<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(None));
            let captured_clone = captured_status.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                *captured_clone.lock().expect("mutex should not be poisoned") =
                    Some(status.clone());
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
                .expect("update_cluster_status should succeed");

            let status = captured_status
                .lock()
                .expect("mutex should not be poisoned")
                .clone()
                .expect("status should be set");
            assert_eq!(status.phase, ClusterPhase::Failed);
            assert_eq!(
                status.message.as_ref().expect("message should be set"),
                error_msg
            );

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

        fn mock_context_minimal() -> Arc<Context> {
            Arc::new(Context::for_testing(
                Arc::new(MockKubeClient::new()),
                Arc::new(MockCAPIClient::new()),
                Arc::new(MockCapiInstaller::new()),
            ))
        }

        /// Story: Retryable errors requeue with exponential backoff,
        /// non-retryable errors await change.
        #[test]
        fn retryable_errors_requeue_nonretryable_await() {
            let cluster = Arc::new(sample_cluster("error-cluster"));

            // Retryable errors should requeue
            let retryable = vec![
                Error::provider("provider error".to_string()),
                Error::pivot("pivot error".to_string()),
                Error::capi_installation("capi error".to_string()),
            ];
            for error in retryable {
                let ctx = mock_context_minimal(); // Fresh context per error
                let action = error_policy(cluster.clone(), &error, ctx);
                assert_ne!(
                    action,
                    Action::await_change(),
                    "retryable error {:?} should requeue",
                    error
                );
            }

            // Non-retryable errors should await change
            let non_retryable = vec![
                Error::validation("validation error".to_string()),
                Error::serialization("serialization error".to_string()),
            ];
            for error in non_retryable {
                let ctx = mock_context_minimal();
                let action = error_policy(cluster.clone(), &error, ctx);
                assert_eq!(
                    action,
                    Action::await_change(),
                    "non-retryable error {:?} should await change",
                    error
                );
            }
        }

        /// Story: Error policy should work correctly with clusters in any phase.
        #[test]
        fn error_policy_works_for_all_phases() {
            let phases = vec![
                ClusterPhase::Pending,
                ClusterPhase::Provisioning,
                ClusterPhase::Pivoting,
                ClusterPhase::Pivoted,
                ClusterPhase::Ready,
                ClusterPhase::Deleting,
                ClusterPhase::Unpivoting,
                ClusterPhase::Failed,
            ];

            for phase in phases {
                let ctx = mock_context_minimal(); // Fresh context per phase
                let cluster = Arc::new(cluster_with_phase("test", phase));
                let error = Error::provider("test error".to_string());
                let action = error_policy(cluster, &error, ctx);

                assert_eq!(
                    action,
                    Action::requeue(Duration::from_secs(5)),
                    "phase {:?} should trigger requeue on first error",
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
        use lattice_cell::AgentRegistry;

        /// Get a K8s client for tests, or skip if not available
        async fn test_client() -> Option<Client> {
            lattice_common::fips::install_crypto_provider();
            Client::try_default().await.ok()
        }

        /// Story: Creating a new PivotOperationsImpl should work
        #[tokio::test]
        async fn create_pivot_operations() {
            let Some(client) = test_client().await else {
                eprintln!("Skipping test: no K8s cluster available");
                return;
            };
            let registry = Arc::new(AgentRegistry::new());
            let ops = PivotOperationsImpl::new(registry, client, None);
            // Just verify it can be created
            assert!(!ops.is_agent_ready("nonexistent-cluster"));
        }

        /// Story: Agent ready check should return false for unconnected cluster
        #[tokio::test]
        async fn agent_not_ready_when_not_connected() {
            let Some(client) = test_client().await else {
                eprintln!("Skipping test: no K8s cluster available");
                return;
            };
            let registry = Arc::new(AgentRegistry::new());
            let ops = PivotOperationsImpl::new(registry, client, None);

            assert!(!ops.is_agent_ready("test-cluster"));
        }

        /// Story: Pivot complete check should return false for unconnected cluster
        #[tokio::test]
        async fn pivot_not_complete_when_not_connected() {
            let Some(client) = test_client().await else {
                eprintln!("Skipping test: no K8s cluster available");
                return;
            };
            let registry = Arc::new(AgentRegistry::new());
            let ops = PivotOperationsImpl::new(registry, client, None);

            assert!(!ops.is_pivot_complete("test-cluster"));
        }

        /// Story: Trigger pivot should fail when agent is not connected
        #[tokio::test]
        async fn trigger_pivot_fails_when_no_agent() {
            let Some(client) = test_client().await else {
                eprintln!("Skipping test: no K8s cluster available");
                return;
            };
            let registry = Arc::new(AgentRegistry::new());
            let ops = PivotOperationsImpl::new(registry, client, None);

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

        // --- determine_pivot_action tests ---

        #[test]
        fn pivot_action_complete_when_pivot_done() {
            assert_eq!(determine_pivot_action(true, false), PivotAction::Complete);
        }

        #[test]
        fn pivot_action_trigger_pivot_when_agent_connected() {
            assert_eq!(
                determine_pivot_action(false, true),
                PivotAction::TriggerPivot
            );
        }

        #[test]
        fn pivot_action_wait_for_agent_when_nothing_ready() {
            assert_eq!(
                determine_pivot_action(false, false),
                PivotAction::WaitForAgent
            );
        }

        // --- determine_scaling_action tests ---

        fn pool_spec(replicas: u32, min: Option<u32>, max: Option<u32>) -> WorkerPoolSpec {
            WorkerPoolSpec {
                replicas,
                min,
                max,
                ..Default::default()
            }
        }

        #[test]
        fn scaling_action_static_uses_spec_replicas() {
            let spec = pool_spec(3, None, None);
            let action = determine_scaling_action(&spec, Some(2));

            assert_eq!(action.desired_replicas(), 3);
            assert!(!action.is_autoscaling());
            assert!(matches!(action, ScalingAction::Scale { target: 3, .. }));
        }

        #[test]
        fn scaling_action_noop_when_replicas_match() {
            let spec = pool_spec(3, None, None);
            let action = determine_scaling_action(&spec, Some(3));

            assert_eq!(action.desired_replicas(), 3);
            assert!(!action.is_autoscaling());
            assert!(matches!(action, ScalingAction::NoOp { .. }));
        }

        #[test]
        fn scaling_action_autoscaling_uses_current_when_available() {
            let spec = pool_spec(3, Some(1), Some(10));
            let action = determine_scaling_action(&spec, Some(7));

            assert_eq!(action.desired_replicas(), 7); // Uses current
            assert!(action.is_autoscaling());
            assert!(matches!(action, ScalingAction::NoOp { .. }));
        }

        #[test]
        fn scaling_action_autoscaling_falls_back_to_min() {
            let spec = pool_spec(3, Some(2), Some(10));
            let action = determine_scaling_action(&spec, None);

            assert_eq!(action.desired_replicas(), 2); // Falls back to min
            assert!(action.is_autoscaling());
        }

        #[test]
        fn scaling_action_scales_up() {
            let spec = pool_spec(5, None, None);
            let action = determine_scaling_action(&spec, Some(2));

            assert_eq!(
                action,
                ScalingAction::Scale {
                    current: 2,
                    target: 5
                }
            );
        }

        #[test]
        fn scaling_action_scales_down() {
            let spec = pool_spec(3, None, None);
            let action = determine_scaling_action(&spec, Some(10));

            assert_eq!(
                action,
                ScalingAction::Scale {
                    current: 10,
                    target: 3
                }
            );
        }

        #[test]
        fn scaling_action_waits_when_deployment_missing_and_replicas_wanted() {
            let spec = pool_spec(3, None, None);
            let action = determine_scaling_action(&spec, None);

            assert_eq!(action, ScalingAction::WaitForMachineDeployment);
        }

        #[test]
        fn scaling_action_noop_when_deployment_missing_and_zero_replicas() {
            let spec = pool_spec(0, None, None);
            let action = determine_scaling_action(&spec, None);

            assert!(matches!(action, ScalingAction::NoOp { .. }));
            assert_eq!(action.desired_replicas(), 0);
        }

        // --- autoscaling_warning tests ---

        #[test]
        fn autoscaling_warning_none_for_static_scaling() {
            let spec = pool_spec(5, None, None);
            assert!(autoscaling_warning(&spec).is_none());
        }

        #[test]
        fn autoscaling_warning_none_when_spec_in_bounds() {
            let spec = pool_spec(5, Some(1), Some(10));
            assert!(autoscaling_warning(&spec).is_none());
        }

        #[test]
        fn autoscaling_warning_when_spec_below_min() {
            let spec = pool_spec(1, Some(3), Some(10));
            let warning = autoscaling_warning(&spec);

            assert!(warning.is_some());
            assert!(warning.unwrap().contains("replicas (1) ignored"));
        }

        #[test]
        fn autoscaling_warning_when_spec_above_max() {
            let spec = pool_spec(15, Some(1), Some(10));
            let warning = autoscaling_warning(&spec);

            assert!(warning.is_some());
            assert!(warning.unwrap().contains("replicas (15) ignored"));
        }
    }
}
