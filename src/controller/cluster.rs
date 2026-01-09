//! LatticeCluster controller implementation
//!
//! This module implements the reconciliation logic for LatticeCluster resources.
//! It follows the Kubernetes controller pattern: observe current state, determine
//! desired state, calculate diff, and apply changes.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, error, info, instrument, warn};

#[cfg(test)]
use mockall::automock;

use crate::agent::connection::SharedAgentRegistry;
use crate::capi::{ensure_capi_installed_with, CapiDetector, CapiInstaller};
use crate::crd::{
    Condition, ClusterPhase, ConditionStatus, LatticeCluster, LatticeClusterStatus,
    ProviderType,
};
use crate::proto::{cell_command, AgentState, CellCommand, StartPivotCommand};
use crate::provider::{CAPIManifest, DockerProvider, Provider};
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
}

/// Trait for cluster bootstrap registration
///
/// This trait allows the controller to register clusters for bootstrap
/// and obtain tokens for kubeadm postKubeadmCommands.
#[cfg_attr(test, automock)]
pub trait ClusterBootstrap: Send + Sync {
    /// Register a cluster for bootstrap and return a one-time token
    ///
    /// # Arguments
    ///
    /// * `cluster_id` - Unique cluster identifier
    /// * `cell_endpoint` - gRPC endpoint for the parent cell
    /// * `ca_certificate` - CA certificate PEM for the parent cell
    ///
    /// # Returns
    ///
    /// A one-time bootstrap token
    fn register_cluster(
        &self,
        cluster_id: String,
        cell_endpoint: String,
        ca_certificate: String,
    ) -> String;

    /// Check if a cluster is already registered
    fn is_cluster_registered(&self, cluster_id: &str) -> bool;

    /// Get the cell gRPC endpoint for agents to connect to
    fn cell_endpoint(&self) -> &str;

    /// Get the bootstrap HTTP endpoint for kubeadm webhook
    fn bootstrap_endpoint(&self) -> &str;

    /// Get the CA certificate PEM
    fn ca_cert_pem(&self) -> &str;
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
    ///
    /// # Returns
    ///
    /// True if infrastructure is ready, false otherwise
    async fn is_infrastructure_ready(
        &self,
        cluster_name: &str,
        namespace: &str,
    ) -> Result<bool, Error>;
}

/// Real bootstrap implementation wrapping BootstrapState
pub struct ClusterBootstrapImpl<G: crate::bootstrap::ManifestGenerator> {
    state: Arc<crate::bootstrap::BootstrapState<G>>,
    cell_endpoint: String,
    bootstrap_endpoint: String,
}

impl<G: crate::bootstrap::ManifestGenerator> ClusterBootstrapImpl<G> {
    /// Create a new ClusterBootstrapImpl wrapping the given BootstrapState
    pub fn new(
        state: Arc<crate::bootstrap::BootstrapState<G>>,
        cell_endpoint: String,
        bootstrap_endpoint: String,
    ) -> Self {
        Self {
            state,
            cell_endpoint,
            bootstrap_endpoint,
        }
    }
}

impl<G: crate::bootstrap::ManifestGenerator + 'static> ClusterBootstrap
    for ClusterBootstrapImpl<G>
{
    fn register_cluster(
        &self,
        cluster_id: String,
        cell_endpoint: String,
        ca_certificate: String,
    ) -> String {
        let token = self
            .state
            .register_cluster(cluster_id, cell_endpoint, ca_certificate);
        token.as_str().to_string()
    }

    fn is_cluster_registered(&self, cluster_id: &str) -> bool {
        self.state.is_cluster_registered(cluster_id)
    }

    fn cell_endpoint(&self) -> &str {
        &self.cell_endpoint
    }

    fn bootstrap_endpoint(&self) -> &str {
        &self.bootstrap_endpoint
    }

    fn ca_cert_pem(&self) -> &str {
        self.state.ca_cert_pem()
    }
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
            .filter(|node| {
                // Check if it's NOT a control plane node
                let labels = node.metadata.labels.as_ref();
                let is_control_plane = labels
                    .map(|l| l.contains_key("node-role.kubernetes.io/control-plane"))
                    .unwrap_or(false);

                if is_control_plane {
                    return false;
                }

                // Check if node is Ready
                let conditions = node.status.as_ref().and_then(|s| s.conditions.as_ref());
                conditions
                    .map(|conds| {
                        conds
                            .iter()
                            .any(|c| c.type_ == "Ready" && c.status == "True")
                    })
                    .unwrap_or(false)
            })
            .count() as u32;

        Ok(ready_workers)
    }

    async fn are_control_plane_nodes_tainted(&self) -> Result<bool, Error> {
        use k8s_openapi::api::core::v1::Node;

        let api: Api<Node> = Api::all(self.client.clone());
        let nodes = api.list(&Default::default()).await?;

        // Check all control plane nodes have the NoSchedule taint
        for node in nodes.items.iter() {
            let labels = node.metadata.labels.as_ref();
            let is_control_plane = labels
                .map(|l| l.contains_key("node-role.kubernetes.io/control-plane"))
                .unwrap_or(false);

            if !is_control_plane {
                continue;
            }

            // Check for NoSchedule taint
            let taints = node.spec.as_ref().and_then(|s| s.taints.as_ref());
            let has_no_schedule = taints
                .map(|t| {
                    t.iter().any(|taint| {
                        taint.key == "node-role.kubernetes.io/control-plane"
                            && taint.effect == "NoSchedule"
                    })
                })
                .unwrap_or(false);

            if !has_no_schedule {
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
            let labels = node.metadata.labels.as_ref();
            let is_control_plane = labels
                .map(|l| l.contains_key("node-role.kubernetes.io/control-plane"))
                .unwrap_or(false);

            if !is_control_plane {
                continue;
            }

            let node_name = node
                .metadata
                .name
                .as_ref()
                .ok_or_else(|| Error::provider("node has no name".to_string()))?;

            // Check if already tainted
            let taints = node.spec.as_ref().and_then(|s| s.taints.as_ref());
            let has_no_schedule = taints
                .map(|t| {
                    t.iter().any(|taint| {
                        taint.key == "node-role.kubernetes.io/control-plane"
                            && taint.effect == "NoSchedule"
                    })
                })
                .unwrap_or(false);

            if has_no_schedule {
                debug!(node = %node_name, "control plane node already tainted");
                continue;
            }

            // Add the taint
            info!(node = %node_name, "applying NoSchedule taint to control plane node");

            let patch = serde_json::json!({
                "spec": {
                    "taints": [
                        {
                            "key": "node-role.kubernetes.io/control-plane",
                            "effect": "NoSchedule"
                        }
                    ]
                }
            });

            api.patch(
                node_name,
                &PatchParams::apply("lattice-controller"),
                &Patch::Strategic(&patch),
            )
            .await?;

            info!(node = %node_name, "control plane node tainted");
        }

        Ok(())
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
            let obj: DynamicObject = serde_json::from_value(serde_json::json!({
                "apiVersion": manifest.api_version,
                "kind": manifest.kind,
                "metadata": {
                    "name": manifest.metadata.name,
                    "namespace": namespace,
                    "labels": manifest.metadata.labels,
                },
                "spec": manifest.spec,
            }))
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
    ) -> Result<bool, Error> {
        use kube::api::DynamicObject;
        use kube::discovery::ApiResource;

        // Check if the CAPI Cluster resource has Ready condition
        let ar = ApiResource {
            group: "cluster.x-k8s.io".to_string(),
            version: "v1beta1".to_string(),
            api_version: "cluster.x-k8s.io/v1beta1".to_string(),
            kind: "Cluster".to_string(),
            plural: "clusters".to_string(),
        };

        let api: Api<DynamicObject> = Api::namespaced_with(self.client.clone(), namespace, &ar);

        match api.get(cluster_name).await {
            Ok(cluster) => {
                // Check status.phase == "Provisioned" or status.conditions contains Ready=True
                if let Some(status) = cluster.data.get("status") {
                    if let Some(phase) = status.get("phase").and_then(|p| p.as_str()) {
                        if phase == "Provisioned" {
                            return Ok(true);
                        }
                    }
                    // Also check conditions
                    if let Some(conditions) = status.get("conditions").and_then(|c| c.as_array()) {
                        for condition in conditions {
                            if condition.get("type").and_then(|t| t.as_str()) == Some("Ready")
                                && condition.get("status").and_then(|s| s.as_str()) == Some("True")
                            {
                                return Ok(true);
                            }
                        }
                    }
                }
                Ok(false)
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                // Cluster doesn't exist yet
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
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
    ("kubeadmcontrolplanetemplate", "kubeadmcontrolplanetemplates"),
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

/// Trait abstracting pivot operations for testability
#[cfg_attr(test, automock)]
#[async_trait]
pub trait PivotOperations: Send + Sync {
    /// Trigger pivot for a cluster
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

    /// Check if pivot is complete (agent reports Ready state)
    fn is_pivot_complete(&self, cluster_name: &str) -> bool;

    /// Store post-pivot manifests to send after PivotComplete
    ///
    /// These manifests (LatticeCluster CRD + resource) will be sent
    /// to the agent via BootstrapCommand after pivot succeeds.
    fn store_post_pivot_manifests(
        &self,
        cluster_name: &str,
        crd_yaml: Option<String>,
        cluster_yaml: Option<String>,
    );
}

/// Cell-specific capabilities for provisioning workload clusters
///
/// These components are only needed when running as a cell (management cluster).
/// Bundling them together makes it clear they go together and reduces
/// the number of optional fields in Context.
pub struct CellCapabilities {
    /// Bootstrap registration for workload clusters
    pub bootstrap: Arc<dyn ClusterBootstrap>,
    /// Agent registry for connected agents
    pub agent_registry: SharedAgentRegistry,
    /// Pivot operations for orchestrating cluster pivots
    pub pivot_ops: Arc<dyn PivotOperations>,
}

impl CellCapabilities {
    /// Create new cell capabilities
    pub fn new(
        bootstrap: Arc<dyn ClusterBootstrap>,
        agent_registry: SharedAgentRegistry,
        pivot_ops: Arc<dyn PivotOperations>,
    ) -> Self {
        Self {
            bootstrap,
            agent_registry,
            pivot_ops,
        }
    }
}

/// Controller context containing shared state and clients
///
/// The context is shared across all reconciliation calls and holds
/// resources that are expensive to create (like Kubernetes clients).
///
/// Use [`ContextBuilder`] to construct instances:
///
/// ```ignore
/// let ctx = Context::builder(client)
///     .namespace("capi-system")
///     .cell_capabilities(cell_caps)
///     .build();
/// ```
pub struct Context {
    /// Kubernetes client for API operations (trait object for testability)
    pub kube: Arc<dyn KubeClient>,
    /// CAPI client for applying manifests
    pub capi: Arc<dyn CAPIClient>,
    /// CAPI detector for checking installation status
    pub capi_detector: Arc<dyn CapiDetector>,
    /// CAPI installer for installing CAPI and providers
    pub capi_installer: Arc<dyn CapiInstaller>,
    /// Default namespace for CAPI resources
    pub capi_namespace: String,
    /// Cell capabilities (present only when running as a cell)
    pub cell: Option<CellCapabilities>,
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

    /// Access bootstrap registration (convenience accessor)
    pub fn bootstrap(&self) -> Option<&Arc<dyn ClusterBootstrap>> {
        self.cell.as_ref().map(|c| &c.bootstrap)
    }

    /// Access agent registry (convenience accessor)
    pub fn agent_registry(&self) -> Option<&SharedAgentRegistry> {
        self.cell.as_ref().map(|c| &c.agent_registry)
    }

    /// Access pivot operations (convenience accessor)
    pub fn pivot_ops(&self) -> Option<&Arc<dyn PivotOperations>> {
        self.cell.as_ref().map(|c| &c.pivot_ops)
    }

    /// Check if this context has cell capabilities
    pub fn is_cell(&self) -> bool {
        self.cell.is_some()
    }

    /// Create a context for testing with custom mock clients
    ///
    /// This method is primarily for unit tests where a real Kubernetes
    /// client is not available. For production code, use [`Context::builder`].
    #[cfg(test)]
    pub fn for_testing(
        kube: Arc<dyn KubeClient>,
        capi: Arc<dyn CAPIClient>,
        capi_detector: Arc<dyn CapiDetector>,
        capi_installer: Arc<dyn CapiInstaller>,
        namespace: &str,
    ) -> Self {
        Self {
            kube,
            capi,
            capi_detector,
            capi_installer,
            capi_namespace: namespace.to_string(),
            cell: None,
        }
    }

    /// Create a context for testing with cell capabilities
    ///
    /// This method is primarily for unit tests where a real Kubernetes
    /// client is not available but cell capabilities are needed.
    #[cfg(test)]
    pub fn for_testing_with_cell(
        kube: Arc<dyn KubeClient>,
        capi: Arc<dyn CAPIClient>,
        capi_detector: Arc<dyn CapiDetector>,
        capi_installer: Arc<dyn CapiInstaller>,
        namespace: &str,
        cell: CellCapabilities,
    ) -> Self {
        Self {
            kube,
            capi,
            capi_detector,
            capi_installer,
            capi_namespace: namespace.to_string(),
            cell: Some(cell),
        }
    }
}

/// Builder for constructing [`Context`] instances
///
/// # Examples
///
/// Basic context for agent mode:
/// ```ignore
/// let ctx = Context::builder(client).build();
/// ```
///
/// Context with custom namespace:
/// ```ignore
/// let ctx = Context::builder(client)
///     .namespace("capi-system")
///     .build();
/// ```
///
/// Full cell context:
/// ```ignore
/// let ctx = Context::builder(client)
///     .namespace("capi-system")
///     .cell_capabilities(CellCapabilities::new(bootstrap, registry, pivot_ops))
///     .build();
/// ```
///
/// Testing with mock clients:
/// ```ignore
/// let ctx = Context::builder(client)
///     .kube_client(mock_kube)
///     .capi_client(mock_capi)
///     .build();
/// ```
pub struct ContextBuilder {
    client: Client,
    kube: Option<Arc<dyn KubeClient>>,
    capi: Option<Arc<dyn CAPIClient>>,
    capi_detector: Option<Arc<dyn CapiDetector>>,
    capi_installer: Option<Arc<dyn CapiInstaller>>,
    capi_namespace: String,
    cell: Option<CellCapabilities>,
}

impl ContextBuilder {
    /// Create a new builder with the given Kubernetes client
    fn new(client: Client) -> Self {
        Self {
            client,
            kube: None,
            capi: None,
            capi_detector: None,
            capi_installer: None,
            capi_namespace: "default".to_string(),
            cell: None,
        }
    }

    /// Set the CAPI namespace
    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.capi_namespace = namespace.into();
        self
    }

    /// Set cell capabilities for running as a management cluster
    pub fn cell_capabilities(mut self, cell: CellCapabilities) -> Self {
        self.cell = Some(cell);
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

    /// Override the CAPI detector (primarily for testing)
    pub fn capi_detector(mut self, detector: Arc<dyn CapiDetector>) -> Self {
        self.capi_detector = Some(detector);
        self
    }

    /// Override the CAPI installer (primarily for testing)
    pub fn capi_installer(mut self, installer: Arc<dyn CapiInstaller>) -> Self {
        self.capi_installer = Some(installer);
        self
    }

    /// Build the Context
    pub fn build(self) -> Context {
        use crate::capi::{ClusterctlInstaller, KubeCapiDetector};

        Context {
            kube: self
                .kube
                .unwrap_or_else(|| Arc::new(KubeClientImpl::new(self.client.clone()))),
            capi: self
                .capi
                .unwrap_or_else(|| Arc::new(CAPIClientImpl::new(self.client.clone()))),
            capi_detector: self
                .capi_detector
                .unwrap_or_else(|| Arc::new(KubeCapiDetector::new(self.client.clone()))),
            capi_installer: self
                .capi_installer
                .unwrap_or_else(|| Arc::new(ClusterctlInstaller::new())),
            capi_namespace: self.capi_namespace,
            cell: self.cell,
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
        update_status_failed(&cluster, &ctx, &e.to_string()).await?;
        // Don't requeue for validation errors - they require spec changes
        return Ok(Action::await_change());
    }

    // Get current status, defaulting to Pending if not set
    let current_phase = cluster
        .status
        .as_ref()
        .map(|s| s.phase.clone())
        .unwrap_or(ClusterPhase::Pending);

    debug!(?current_phase, "current cluster phase");

    // State machine: transition based on current phase
    match current_phase {
        ClusterPhase::Pending => {
            // Ensure CAPI is installed before provisioning
            info!("ensuring CAPI is installed for provider");
            ensure_capi_installed_with(
                ctx.capi_detector.as_ref(),
                ctx.capi_installer.as_ref(),
                &cluster.spec.provider.type_,
            )
            .await?;

            // Generate and apply CAPI manifests, then transition to Provisioning
            info!("generating CAPI manifests for cluster");

            // Get the appropriate provider based on cluster spec
            let manifests = generate_capi_manifests(&cluster, &ctx).await?;

            // Apply CAPI manifests
            info!(count = manifests.len(), "applying CAPI manifests");
            ctx.capi
                .apply_manifests(&manifests, &ctx.capi_namespace)
                .await?;

            // Update status to Provisioning
            info!("transitioning to Provisioning phase");
            update_status_provisioning(&cluster, &ctx).await?;
            Ok(Action::requeue(Duration::from_secs(5)))
        }
        ClusterPhase::Provisioning => {
            // Check if CAPI infrastructure is ready
            debug!("checking infrastructure status");

            let is_ready = ctx
                .capi
                .is_infrastructure_ready(&name, &ctx.capi_namespace)
                .await?;

            if is_ready {
                // Infrastructure is ready, transition to Pivoting
                info!("infrastructure ready, transitioning to Pivoting phase");
                update_status_pivoting(&cluster, &ctx).await?;
                Ok(Action::requeue(Duration::from_secs(5)))
            } else {
                // Still provisioning, requeue
                debug!("infrastructure not ready yet");
                Ok(Action::requeue(Duration::from_secs(30)))
            }
        }
        ClusterPhase::Pivoting => {
            // Check if we have pivot operations configured (cell mode)
            if let Some(pivot_ops) = ctx.pivot_ops() {
                // Check if pivot is already complete
                if pivot_ops.is_pivot_complete(&name) {
                    info!("pivot complete, transitioning to Ready phase");
                    update_status_ready(&cluster, &ctx).await?;
                    return Ok(Action::requeue(Duration::from_secs(60)));
                }

                // Check if agent is connected and ready for pivot
                if pivot_ops.is_agent_ready(&name) {
                    // Store post-pivot manifests before triggering pivot
                    // These will be sent to the agent after PivotComplete
                    use kube::CustomResourceExt;
                    let crd_yaml = serde_yaml::to_string(&LatticeCluster::crd())
                        .map_err(|e| Error::serialization(e.to_string()))?;
                    let cluster_yaml = serde_yaml::to_string(cluster.as_ref())
                        .map_err(|e| Error::serialization(e.to_string()))?;

                    pivot_ops.store_post_pivot_manifests(&name, Some(crd_yaml), Some(cluster_yaml));

                    // Agent is ready, trigger pivot if not already in progress
                    // The pivot_ops checks internally if pivot is already running
                    info!("agent ready, triggering pivot");
                    match pivot_ops
                        .trigger_pivot(&name, &ctx.capi_namespace, "default")
                        .await
                    {
                        Ok(()) => {
                            debug!("pivot triggered successfully, waiting for completion");
                        }
                        Err(e) => {
                            warn!(error = %e, "pivot trigger failed, will retry");
                        }
                    }
                } else {
                    debug!("waiting for agent to connect and be ready for pivot");
                }

                // Requeue to check pivot progress
                Ok(Action::requeue(Duration::from_secs(10)))
            } else {
                // No pivot operations - this is a non-cell mode
                // Just transition to Ready since pivot is not applicable
                debug!("no pivot operations configured, transitioning to Ready");
                update_status_ready(&cluster, &ctx).await?;
                Ok(Action::requeue(Duration::from_secs(60)))
            }
        }
        ClusterPhase::Ready => {
            // Cluster is ready, check for drift and ensure control plane is properly tainted
            debug!("cluster is ready, checking worker status and control plane taints");

            // Get desired worker count from spec
            let desired_workers = cluster.spec.nodes.workers;

            // Get current ready worker count
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
            }

            Ok(Action::requeue(Duration::from_secs(60)))
        }
        ClusterPhase::Failed => {
            // Failed state requires manual intervention
            warn!("cluster is in Failed state, awaiting spec change");
            Ok(Action::await_change())
        }
    }
}

/// Generate CAPI manifests for a cluster based on its provider type
async fn generate_capi_manifests(
    cluster: &LatticeCluster,
    ctx: &Context,
) -> Result<Vec<CAPIManifest>, Error> {
    use crate::provider::BootstrapInfo;

    // Build bootstrap info from context if this is a workload cluster
    let bootstrap = if let Some(bootstrap_ctx) = ctx.bootstrap() {
        let name = cluster.metadata.name.as_deref().unwrap_or("unknown");
        let ca_cert = bootstrap_ctx.ca_cert_pem().to_string();
        let cell_endpoint = bootstrap_ctx.cell_endpoint().to_string();
        let bootstrap_endpoint = bootstrap_ctx.bootstrap_endpoint().to_string();

        // Register cluster and get token
        let token = bootstrap_ctx.register_cluster(
            name.to_string(),
            cell_endpoint.clone(),
            ca_cert.clone(),
        );

        BootstrapInfo::new(bootstrap_endpoint, token, cell_endpoint, ca_cert)
    } else {
        // No bootstrap context - this is likely a management cluster
        BootstrapInfo::default()
    };

    match cluster.spec.provider.type_ {
        ProviderType::Docker => {
            let provider = DockerProvider::new();
            provider.generate_capi_manifests(cluster, &bootstrap).await
        }
        ProviderType::Aws => {
            // TODO: Implement AWS provider
            Err(Error::provider(
                "AWS provider not yet implemented".to_string(),
            ))
        }
        ProviderType::Gcp => {
            // TODO: Implement GCP provider
            Err(Error::provider(
                "GCP provider not yet implemented".to_string(),
            ))
        }
        ProviderType::Azure => {
            // TODO: Implement Azure provider
            Err(Error::provider(
                "Azure provider not yet implemented".to_string(),
            ))
        }
    }
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

/// Update cluster status to Provisioning phase
async fn update_status_provisioning(cluster: &LatticeCluster, ctx: &Context) -> Result<(), Error> {
    let name = cluster.name_any();

    let condition = Condition::new(
        "Provisioning",
        ConditionStatus::True,
        "StartingProvisioning",
        "Cluster provisioning has started",
    );

    let status = LatticeClusterStatus::with_phase(ClusterPhase::Provisioning)
        .message("Provisioning cluster infrastructure")
        .condition(condition);

    ctx.kube.patch_status(&name, &status).await?;

    info!("updated status to Provisioning");
    Ok(())
}

/// Update cluster status to Pivoting phase
async fn update_status_pivoting(cluster: &LatticeCluster, ctx: &Context) -> Result<(), Error> {
    let name = cluster.name_any();

    let condition = Condition::new(
        "Pivoting",
        ConditionStatus::True,
        "StartingPivot",
        "Cluster pivot has started",
    );

    let status = LatticeClusterStatus::with_phase(ClusterPhase::Pivoting)
        .message("Pivoting cluster to self-managed")
        .condition(condition);

    ctx.kube.patch_status(&name, &status).await?;

    info!("updated status to Pivoting");
    Ok(())
}

/// Update cluster status to Ready phase
async fn update_status_ready(cluster: &LatticeCluster, ctx: &Context) -> Result<(), Error> {
    let name = cluster.name_any();

    let condition = Condition::new(
        "Ready",
        ConditionStatus::True,
        "ClusterReady",
        "Cluster is self-managed and ready",
    );

    let status = LatticeClusterStatus::with_phase(ClusterPhase::Ready)
        .message("Cluster is self-managed and ready")
        .condition(condition);

    ctx.kube.patch_status(&name, &status).await?;

    info!("updated status to Ready");
    Ok(())
}

/// Update cluster status to Failed phase
async fn update_status_failed(
    cluster: &LatticeCluster,
    ctx: &Context,
    message: &str,
) -> Result<(), Error> {
    let name = cluster.name_any();

    let condition =
        Condition::new("Ready", ConditionStatus::False, "ValidationFailed", message);

    let status = LatticeClusterStatus::with_phase(ClusterPhase::Failed)
        .message(message.to_string())
        .condition(condition);

    ctx.kube.patch_status(&name, &status).await?;

    warn!(message, "updated status to Failed");
    Ok(())
}

/// Real implementation of PivotOperations using AgentRegistry and PivotOrchestrator
pub struct PivotOperationsImpl {
    /// Agent registry for sending commands
    agent_registry: SharedAgentRegistry,
    /// Set of clusters where pivot has been triggered (to avoid double-triggering)
    pivot_in_progress: dashmap::DashSet<String>,
}

impl PivotOperationsImpl {
    /// Create a new PivotOperationsImpl
    pub fn new(agent_registry: SharedAgentRegistry) -> Self {
        Self {
            agent_registry,
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
        if let Some(agent) = self.agent_registry.get(cluster_name) {
            agent.is_ready_for_pivot()
        } else {
            false
        }
    }

    fn is_pivot_complete(&self, cluster_name: &str) -> bool {
        if let Some(agent) = self.agent_registry.get(cluster_name) {
            matches!(agent.state, AgentState::Ready)
        } else {
            false
        }
    }

    fn store_post_pivot_manifests(
        &self,
        cluster_name: &str,
        crd_yaml: Option<String>,
        cluster_yaml: Option<String>,
    ) {
        use crate::agent::connection::PostPivotManifests;

        let manifests = PostPivotManifests {
            crd_yaml,
            cluster_yaml,
        };
        self.agent_registry
            .set_post_pivot_manifests(cluster_name, manifests);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        CellSpec, KubernetesSpec, LatticeClusterSpec, NodeSpec, ProviderSpec, ProviderType,
        ServiceSpec,
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
                    type_: ProviderType::Docker,
                    kubernetes: KubernetesSpec {
                        version: "1.31.0".to_string(),
                        cert_sans: None,
                    },
                },
                nodes: NodeSpec {
                    control_plane: 1,
                    workers: 2,
                },
                networking: None,
                cell: None,
                cell_ref: None,
                environment: None,
                region: None,
                workload: None,
            },
            status: None,
        }
    }

    /// Create a sample cell (management cluster) for testing
    fn sample_cell(name: &str) -> LatticeCluster {
        let mut cluster = sample_cluster(name);
        cluster.spec.cell = Some(CellSpec {
            host: "172.18.255.1".to_string(),
            service: ServiceSpec {
                type_: "LoadBalancer".to_string(),
            },
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
            let cluster = sample_cell("mgmt");
            assert!(cluster.spec.validate().is_ok());
            assert!(cluster.spec.is_cell());
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
        use crate::capi::{MockCapiDetector, MockCapiInstaller};
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

        /// Creates mocks where CAPI is already installed (no installation needed)
        fn mock_capi_already_installed() -> (Arc<MockCapiDetector>, Arc<MockCapiInstaller>) {
            let mut detector = MockCapiDetector::new();
            // CAPI is already installed
            detector.expect_crd_exists().returning(|_, _| Ok(true));
            let installer = MockCapiInstaller::new();
            (Arc::new(detector), Arc::new(installer))
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

            let mut capi_mock = MockCAPIClient::new();
            capi_mock.expect_apply_manifests().returning(|_, _| Ok(()));

            let (detector, installer) = mock_capi_already_installed();

            (
                Arc::new(Context::for_testing(
                    Arc::new(mock),
                    Arc::new(capi_mock),
                    detector,
                    installer,
                    "default",
                )),
                capture,
            )
        }

        /// Creates a context for read-only scenarios where no status updates happen.
        fn mock_context_readonly() -> Arc<Context> {
            let mut mock = MockKubeClient::new();
            // Default expectations for node operations (Ready phase)
            mock.expect_get_ready_worker_count().returning(|| Ok(0));
            mock.expect_are_control_plane_nodes_tainted()
                .returning(|| Ok(true));
            mock.expect_taint_control_plane_nodes().returning(|| Ok(()));

            let mut capi_mock = MockCAPIClient::new();
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _| Ok(false));
            let (detector, installer) = mock_capi_already_installed();
            Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                detector,
                installer,
                "default",
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
                .returning(|_, _| Ok(true));

            let (detector, installer) = mock_capi_already_installed();

            (
                Arc::new(Context::for_testing(
                    Arc::new(mock),
                    Arc::new(capi_mock),
                    detector,
                    installer,
                    "default",
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

            let mut capi_mock = MockCAPIClient::new();
            capi_mock.expect_apply_manifests().returning(|_, _| Ok(()));

            let (detector, installer) = mock_capi_already_installed();

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                detector,
                installer,
                "default",
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

            let mock = MockKubeClient::new();
            let mut capi_mock = MockCAPIClient::new();
            capi_mock
                .expect_apply_manifests()
                .returning(|_, _| Err(Error::provider("CAPI apply failed".to_string())));

            let (detector, installer) = mock_capi_already_installed();

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                detector,
                installer,
                "default",
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
        use crate::capi::{MockCapiDetector, MockCapiInstaller};
        use rstest::rstest;

        fn mock_context_no_updates() -> Arc<Context> {
            let mock = MockKubeClient::new();
            let capi_mock = MockCAPIClient::new();
            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();
            Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
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
        use crate::capi::{MockCapiDetector, MockCapiInstaller};

        /// Story: When the Kubernetes API fails during status update, the error
        /// should propagate up so the controller can retry the reconciliation.
        #[tokio::test]
        async fn test_kube_api_failure_propagates_error() {
            let cluster = sample_cluster("test-cluster");

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status()
                .returning(|_, _| Err(Error::provider("connection failed".to_string())));

            let capi_mock = MockCAPIClient::new();
            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();
            let ctx = Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
            );

            let result = update_status_provisioning(&cluster, &ctx).await;

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
        use crate::capi::{MockCapiDetector, MockCapiInstaller};

        fn cluster_with_provider(name: &str, provider_type: ProviderType) -> LatticeCluster {
            LatticeCluster {
                metadata: ObjectMeta {
                    name: Some(name.to_string()),
                    ..Default::default()
                },
                spec: LatticeClusterSpec {
                    provider: ProviderSpec {
                        type_: provider_type,
                        kubernetes: KubernetesSpec {
                            version: "1.31.0".to_string(),
                            cert_sans: None,
                        },
                    },
                    nodes: NodeSpec {
                        control_plane: 1,
                        workers: 2,
                    },
                    networking: None,
                    cell: None,
                    cell_ref: None,
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
            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();
            Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
            ))
        }

        #[tokio::test]
        async fn test_generate_capi_manifests_docker_provider() {
            let cluster = cluster_with_provider("docker-cluster", ProviderType::Docker);
            let ctx = mock_context();
            let result = generate_capi_manifests(&cluster, &ctx).await;

            assert!(result.is_ok());
            let manifests = result.unwrap();
            // Docker provider should generate manifests
            assert!(!manifests.is_empty());
        }

        #[tokio::test]
        async fn test_generate_capi_manifests_aws_provider_not_implemented() {
            let cluster = cluster_with_provider("aws-cluster", ProviderType::Aws);
            let ctx = mock_context();
            let result = generate_capi_manifests(&cluster, &ctx).await;

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("AWS provider not yet implemented"));
        }

        #[tokio::test]
        async fn test_generate_capi_manifests_gcp_provider_not_implemented() {
            let cluster = cluster_with_provider("gcp-cluster", ProviderType::Gcp);
            let ctx = mock_context();
            let result = generate_capi_manifests(&cluster, &ctx).await;

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("GCP provider not yet implemented"));
        }

        #[tokio::test]
        async fn test_generate_capi_manifests_azure_provider_not_implemented() {
            let cluster = cluster_with_provider("azure-cluster", ProviderType::Azure);
            let ctx = mock_context();
            let result = generate_capi_manifests(&cluster, &ctx).await;

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err
                .to_string()
                .contains("Azure provider not yet implemented"));
        }
    }

    /// Workload Cluster Bootstrap Flow Tests
    ///
    /// These tests verify that when a workload cluster is provisioned with
    /// bootstrap context (parent cell information), the manifest generation
    /// correctly registers the cluster and includes bootstrap information
    /// in the generated CAPI manifests.
    mod workload_cluster_bootstrap_flow {
        use super::*;
        use crate::capi::{MockCapiDetector, MockCapiInstaller};

        /// A simple test implementation of ClusterBootstrap that doesn't use mockall
        /// because ClusterBootstrap returns &str which is tricky with mockall.
        struct TestClusterBootstrap {
            cell_endpoint: String,
            bootstrap_endpoint: String,
            ca_cert: String,
            registered_clusters: std::sync::Mutex<Vec<String>>,
        }

        impl TestClusterBootstrap {
            fn new(cell_endpoint: &str, ca_cert: &str) -> Self {
                Self {
                    cell_endpoint: cell_endpoint.to_string(),
                    // Derive bootstrap endpoint from cell endpoint
                    bootstrap_endpoint: format!(
                        "https://{}:8080",
                        cell_endpoint.split(':').next().unwrap_or("localhost")
                    ),
                    ca_cert: ca_cert.to_string(),
                    registered_clusters: std::sync::Mutex::new(Vec::new()),
                }
            }

            fn was_cluster_registered(&self, cluster_id: &str) -> bool {
                self.registered_clusters
                    .lock()
                    .unwrap()
                    .contains(&cluster_id.to_string())
            }
        }

        impl ClusterBootstrap for TestClusterBootstrap {
            fn register_cluster(
                &self,
                cluster_id: String,
                _cell_endpoint: String,
                _ca_certificate: String,
            ) -> String {
                self.registered_clusters
                    .lock()
                    .unwrap()
                    .push(cluster_id.clone());
                format!("bootstrap-token-for-{}", cluster_id)
            }

            fn is_cluster_registered(&self, cluster_id: &str) -> bool {
                self.registered_clusters
                    .lock()
                    .unwrap()
                    .contains(&cluster_id.to_string())
            }

            fn cell_endpoint(&self) -> &str {
                &self.cell_endpoint
            }

            fn bootstrap_endpoint(&self) -> &str {
                &self.bootstrap_endpoint
            }

            fn ca_cert_pem(&self) -> &str {
                &self.ca_cert
            }
        }

        /// Creates a cell context for testing with full cell capabilities.
        /// This represents a real cell configuration with bootstrap, agent registry, and pivot ops.
        fn cell_context_for_testing(
            bootstrap: Arc<TestClusterBootstrap>,
            namespace: &str,
        ) -> Context {
            use crate::agent::connection::AgentRegistry;

            let mock = MockKubeClient::new();
            let capi_mock = MockCAPIClient::new();
            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();

            // Create mock pivot operations (no-op for bootstrap tests)
            let pivot_ops: Arc<dyn PivotOperations> = Arc::new(MockPivotOperations::new());
            let agent_registry = Arc::new(AgentRegistry::new());
            let cell = CellCapabilities::new(bootstrap, agent_registry, pivot_ops);

            Context::for_testing_with_cell(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                namespace,
                cell,
            )
        }

        /// Story: When provisioning a workload cluster, the controller should
        /// register the cluster with the bootstrap service and include the
        /// bootstrap token in the generated CAPI manifests so kubeadm can
        /// call back to get the agent and CNI manifests.
        #[tokio::test]
        async fn story_workload_cluster_registers_for_bootstrap() {
            let cluster = sample_cluster("workload-prod-001");

            // Create a test bootstrap service
            let bootstrap = Arc::new(TestClusterBootstrap::new(
                "cell.example.com:443",
                "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
            ));

            let ctx = cell_context_for_testing(bootstrap.clone(), "default");

            // Generate manifests - this should trigger registration
            let result = generate_capi_manifests(&cluster, &ctx).await;

            assert!(result.is_ok());
            let manifests = result.unwrap();
            assert!(!manifests.is_empty());

            // Verify the cluster was registered
            assert!(bootstrap.was_cluster_registered("workload-prod-001"));
        }

        /// Story: The bootstrap context provides the parent cell's endpoint
        /// so workload clusters know where to connect after provisioning.
        #[tokio::test]
        async fn story_bootstrap_context_provides_cell_endpoint() {
            let bootstrap = Arc::new(TestClusterBootstrap::new(
                "mgmt.lattice.io:443",
                "FAKE_CA_CERT",
            ));

            let ctx = cell_context_for_testing(bootstrap, "capi-system");

            // Verify bootstrap is present in context
            assert!(ctx.bootstrap().is_some());
            let bootstrap_ctx = ctx.bootstrap().unwrap();
            assert_eq!(bootstrap_ctx.cell_endpoint(), "mgmt.lattice.io:443");
        }

        /// Story: The CA certificate is included so workload clusters can
        /// verify the parent cell's TLS certificate during bootstrap.
        #[tokio::test]
        async fn story_bootstrap_includes_ca_certificate() {
            let bootstrap = Arc::new(TestClusterBootstrap::new(
                "cell:443",
                "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
            ));

            let ctx = cell_context_for_testing(bootstrap, "default");

            let bootstrap_ctx = ctx.bootstrap().unwrap();
            assert!(bootstrap_ctx.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        }

        /// Story: The bootstrap token returned by register_cluster is included
        /// in the generated CAPI manifests for kubeadm postKubeadmCommands.
        #[tokio::test]
        async fn story_bootstrap_token_included_in_manifests() {
            let cluster = sample_cluster("workload-with-token");

            let bootstrap = Arc::new(TestClusterBootstrap::new(
                "cell.example.com:443",
                "-----BEGIN CERTIFICATE-----\nCA_CERT\n-----END CERTIFICATE-----",
            ));

            let ctx = cell_context_for_testing(bootstrap, "default");

            let result = generate_capi_manifests(&cluster, &ctx).await;
            assert!(result.is_ok());

            let manifests = result.unwrap();
            // Find the KubeadmControlPlane manifest
            let kcp = manifests
                .iter()
                .find(|m| m.kind == "KubeadmControlPlane")
                .expect("Should have KubeadmControlPlane manifest");

            // The spec should contain postKubeadmCommands with the bootstrap token
            let spec = kcp
                .spec
                .as_ref()
                .expect("KubeadmControlPlane should have spec");
            let kubeadm_config = spec
                .get("kubeadmConfigSpec")
                .expect("Should have kubeadmConfigSpec");
            let post_commands = kubeadm_config.get("postKubeadmCommands");

            assert!(post_commands.is_some(), "Should have postKubeadmCommands");
            let commands_str = serde_json::to_string(post_commands.unwrap()).unwrap();
            assert!(commands_str.contains("bootstrap-token-for-workload-with-token"));
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
        use crate::capi::{MockCapiDetector, MockCapiInstaller};

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
                .returning(|_, _| Ok(false));

            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
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
                .returning(|_, _| Ok(true));

            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
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
                .returning(|_, _| Err(Error::provider("CAPI API unavailable".to_string())));

            let detector = MockCapiDetector::new();
            let installer = MockCapiInstaller::new();

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
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
    /// These tests verify the controller correctly handles CAPI installation
    /// before attempting to provision a cluster.
    mod capi_installation_flow {
        use super::*;
        use crate::capi::{MockCapiDetector, MockCapiInstaller};
        use std::sync::{Arc as StdArc, Mutex};

        /// Story: When CAPI is already installed, the controller proceeds
        /// directly to manifest generation without installing.
        #[tokio::test]
        async fn story_capi_already_installed_skips_installation() {
            let cluster = Arc::new(sample_cluster("ready-to-provision"));

            let updates: StdArc<Mutex<Vec<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(Vec::new()));
            let updates_clone = updates.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                updates_clone.lock().unwrap().push(status.clone());
                Ok(())
            });

            let mut capi_mock = MockCAPIClient::new();
            capi_mock.expect_apply_manifests().returning(|_, _| Ok(()));

            let mut detector = MockCapiDetector::new();
            // CAPI is already installed
            detector.expect_crd_exists().returning(|_, _| Ok(true));

            // Installer should NOT be called
            let installer = MockCapiInstaller::new();

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
            ));

            let result = reconcile(cluster, ctx).await;

            assert!(result.is_ok());
            // Should have transitioned to Provisioning
            let recorded = updates.lock().unwrap();
            assert!(!recorded.is_empty());
        }

        /// Story: When CAPI is not installed, the controller should install it
        /// before attempting to provision.
        #[tokio::test]
        async fn story_capi_not_installed_triggers_installation() {
            let cluster = Arc::new(sample_cluster("needs-capi"));

            let updates: StdArc<Mutex<Vec<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(Vec::new()));
            let updates_clone = updates.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                updates_clone.lock().unwrap().push(status.clone());
                Ok(())
            });

            let mut capi_mock = MockCAPIClient::new();
            capi_mock.expect_apply_manifests().returning(|_, _| Ok(()));

            let mut detector = MockCapiDetector::new();
            // CAPI is NOT installed initially
            detector.expect_crd_exists().returning(|_, _| Ok(false));

            let mut installer = MockCapiInstaller::new();
            // Installer should be called
            installer.expect_install().times(1).returning(|_| Ok(()));

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
            ));

            let result = reconcile(cluster, ctx).await;

            assert!(result.is_ok());
        }

        /// Story: When CAPI installation fails, the error should propagate
        /// for retry with exponential backoff.
        #[tokio::test]
        async fn story_capi_installation_failure_propagates_error() {
            let cluster = Arc::new(sample_cluster("install-fails"));

            let mock = MockKubeClient::new();
            let capi_mock = MockCAPIClient::new();

            let mut detector = MockCapiDetector::new();
            // CAPI is NOT installed
            detector.expect_crd_exists().returning(|_, _| Ok(false));

            let mut installer = MockCapiInstaller::new();
            // Installation fails
            installer
                .expect_install()
                .returning(|_| Err(Error::capi_installation("clusterctl not found".to_string())));

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
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
        use crate::capi::{MockCapiDetector, MockCapiInstaller};
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

            let ctx = Context::for_testing(
                Arc::new(mock),
                Arc::new(MockCAPIClient::new()),
                Arc::new(MockCapiDetector::new()),
                Arc::new(MockCapiInstaller::new()),
                "default",
            );

            update_status_provisioning(&cluster, &ctx).await.unwrap();

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

            let ctx = Context::for_testing(
                Arc::new(mock),
                Arc::new(MockCAPIClient::new()),
                Arc::new(MockCapiDetector::new()),
                Arc::new(MockCapiInstaller::new()),
                "default",
            );

            update_status_pivoting(&cluster, &ctx).await.unwrap();

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

            let ctx = Context::for_testing(
                Arc::new(mock),
                Arc::new(MockCAPIClient::new()),
                Arc::new(MockCapiDetector::new()),
                Arc::new(MockCapiInstaller::new()),
                "default",
            );

            let error_msg = "control plane count must be at least 1";
            update_status_failed(&cluster, &ctx, error_msg)
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
        use crate::capi::{MockCapiDetector, MockCapiInstaller};

        fn mock_context_minimal() -> Arc<Context> {
            Arc::new(Context::for_testing(
                Arc::new(MockKubeClient::new()),
                Arc::new(MockCAPIClient::new()),
                Arc::new(MockCapiDetector::new()),
                Arc::new(MockCapiInstaller::new()),
                "default",
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

    /// Pivoting Phase Orchestration Tests
    ///
    /// These tests verify the reconcile behavior during the Pivoting phase
    /// when pivot_ops is configured. This covers the agent readiness checks,
    /// pivot triggering, and post-pivot manifest storage.
    mod pivoting_phase_orchestration {
        use super::*;
        use crate::capi::{MockCapiDetector, MockCapiInstaller};
        use std::sync::{Arc as StdArc, Mutex};

        /// Simple stub bootstrap for pivot tests (doesn't need full functionality)
        struct StubClusterBootstrap;

        impl ClusterBootstrap for StubClusterBootstrap {
            fn register_cluster(&self, _: String, _: String, _: String) -> String {
                "stub-token".to_string()
            }
            fn is_cluster_registered(&self, _: &str) -> bool {
                false
            }
            fn cell_endpoint(&self) -> &str {
                "cell:443"
            }
            fn bootstrap_endpoint(&self) -> &str {
                "https://cell:8080"
            }
            fn ca_cert_pem(&self) -> &str {
                "STUB_CA"
            }
        }

        /// Test implementation of PivotOperations for controlled testing
        struct TestPivotOps {
            agent_ready: bool,
            pivot_complete: bool,
            trigger_should_fail: bool,
            stored_manifests: StdArc<Mutex<Option<(String, Option<String>, Option<String>)>>>,
        }

        impl TestPivotOps {
            fn agent_ready() -> Self {
                Self {
                    agent_ready: true,
                    pivot_complete: false,
                    trigger_should_fail: false,
                    stored_manifests: StdArc::new(Mutex::new(None)),
                }
            }

            fn agent_not_ready() -> Self {
                Self {
                    agent_ready: false,
                    pivot_complete: false,
                    trigger_should_fail: false,
                    stored_manifests: StdArc::new(Mutex::new(None)),
                }
            }

            fn pivot_already_complete() -> Self {
                Self {
                    agent_ready: true,
                    pivot_complete: true,
                    trigger_should_fail: false,
                    stored_manifests: StdArc::new(Mutex::new(None)),
                }
            }

            fn pivot_trigger_fails() -> Self {
                Self {
                    agent_ready: true,
                    pivot_complete: false,
                    trigger_should_fail: true,
                    stored_manifests: StdArc::new(Mutex::new(None)),
                }
            }

            fn manifests_were_stored(&self) -> bool {
                self.stored_manifests.lock().unwrap().is_some()
            }
        }

        #[async_trait]
        impl PivotOperations for TestPivotOps {
            async fn trigger_pivot(
                &self,
                _cluster_name: &str,
                _source_namespace: &str,
                _target_namespace: &str,
            ) -> Result<(), Error> {
                if self.trigger_should_fail {
                    Err(Error::pivot("trigger failed".to_string()))
                } else {
                    Ok(())
                }
            }

            fn is_agent_ready(&self, _cluster_name: &str) -> bool {
                self.agent_ready
            }

            fn is_pivot_complete(&self, _cluster_name: &str) -> bool {
                self.pivot_complete
            }

            fn store_post_pivot_manifests(
                &self,
                cluster_name: &str,
                crd_yaml: Option<String>,
                cluster_yaml: Option<String>,
            ) {
                *self.stored_manifests.lock().unwrap() =
                    Some((cluster_name.to_string(), crd_yaml, cluster_yaml));
            }
        }

        /// Captured status for verification
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
        }

        fn mock_context_with_pivot_ops(
            pivot_ops: Arc<dyn PivotOperations>,
        ) -> (Arc<Context>, StatusCapture) {
            use crate::agent::connection::AgentRegistry;

            let capture = StatusCapture::new();
            let capture_clone = capture.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                capture_clone.record(status.clone());
                Ok(())
            });

            let capi_mock = MockCAPIClient::new();

            let mut detector = MockCapiDetector::new();
            detector.expect_crd_exists().returning(|_, _| Ok(true));
            let installer = MockCapiInstaller::new();

            // Create full cell capabilities - this is a real cell configuration
            let bootstrap: Arc<dyn ClusterBootstrap> = Arc::new(StubClusterBootstrap);
            let agent_registry = Arc::new(AgentRegistry::new());
            let cell = CellCapabilities::new(bootstrap, agent_registry, pivot_ops);

            let ctx = Context::for_testing_with_cell(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
                cell,
            );

            (Arc::new(ctx), capture)
        }

        /// Story: When pivot is already complete (agent in Ready state),
        /// the controller should transition to Ready phase.
        #[tokio::test]
        async fn story_pivot_complete_transitions_to_ready() {
            let cluster = Arc::new(cluster_with_phase("pivot-done", ClusterPhase::Pivoting));
            let pivot_ops = Arc::new(TestPivotOps::pivot_already_complete());
            let (ctx, capture) = mock_context_with_pivot_ops(pivot_ops);

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Should transition to Ready
            assert_eq!(capture.last_phase(), Some(ClusterPhase::Ready));
            assert_eq!(action, Action::requeue(Duration::from_secs(60)));
        }

        /// Story: When agent is ready for pivot, controller should store
        /// post-pivot manifests and trigger the pivot operation.
        #[tokio::test]
        async fn story_agent_ready_triggers_pivot() {
            let cluster = Arc::new(cluster_with_phase("pivot-ready", ClusterPhase::Pivoting));
            let pivot_ops = Arc::new(TestPivotOps::agent_ready());
            let (ctx, _capture) = mock_context_with_pivot_ops(pivot_ops.clone());

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Manifests should be stored before pivot
            assert!(pivot_ops.manifests_were_stored());
            // Should requeue to check pivot progress
            assert_eq!(action, Action::requeue(Duration::from_secs(10)));
        }

        /// Story: When agent is not yet connected, controller should wait
        /// and requeue without triggering pivot.
        #[tokio::test]
        async fn story_agent_not_ready_waits() {
            let cluster = Arc::new(cluster_with_phase("waiting-agent", ClusterPhase::Pivoting));
            let pivot_ops = Arc::new(TestPivotOps::agent_not_ready());
            let (ctx, _capture) = mock_context_with_pivot_ops(pivot_ops.clone());

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Manifests should NOT be stored (agent not ready)
            assert!(!pivot_ops.manifests_were_stored());
            // Should requeue to check again
            assert_eq!(action, Action::requeue(Duration::from_secs(10)));
        }

        /// Story: When pivot trigger fails, controller should continue and retry
        /// (error is logged but doesn't fail reconcile).
        #[tokio::test]
        async fn story_pivot_trigger_failure_continues() {
            let cluster = Arc::new(cluster_with_phase("trigger-fail", ClusterPhase::Pivoting));
            let pivot_ops = Arc::new(TestPivotOps::pivot_trigger_fails());
            let (ctx, _capture) = mock_context_with_pivot_ops(pivot_ops);

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Should still requeue to retry
            assert_eq!(action, Action::requeue(Duration::from_secs(10)));
        }

        /// Story: When no pivot_ops is configured (non-cell mode),
        /// Pivoting phase should immediately transition to Ready.
        #[tokio::test]
        async fn story_no_pivot_ops_skips_to_ready() {
            let cluster = Arc::new(cluster_with_phase("non-cell", ClusterPhase::Pivoting));

            let capture = StatusCapture::new();
            let capture_clone = capture.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                capture_clone.record(status.clone());
                Ok(())
            });

            let capi_mock = MockCAPIClient::new();
            let mut detector = MockCapiDetector::new();
            detector.expect_crd_exists().returning(|_, _| Ok(true));
            let installer = MockCapiInstaller::new();

            // Context WITHOUT pivot_ops
            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(detector),
                Arc::new(installer),
                "default",
            ));

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Should transition directly to Ready
            assert_eq!(capture.last_phase(), Some(ClusterPhase::Ready));
            assert_eq!(action, Action::requeue(Duration::from_secs(60)));
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
            let ops = PivotOperationsImpl::new(registry);
            // Just verify it can be created
            assert!(!ops.is_agent_ready("nonexistent-cluster"));
        }

        /// Story: Agent ready check should return false for unconnected cluster
        #[test]
        fn story_agent_not_ready_when_not_connected() {
            let registry = Arc::new(AgentRegistry::new());
            let ops = PivotOperationsImpl::new(registry);

            assert!(!ops.is_agent_ready("test-cluster"));
        }

        /// Story: Pivot complete check should return false for unconnected cluster
        #[test]
        fn story_pivot_not_complete_when_not_connected() {
            let registry = Arc::new(AgentRegistry::new());
            let ops = PivotOperationsImpl::new(registry);

            assert!(!ops.is_pivot_complete("test-cluster"));
        }

        /// Story: Trigger pivot should fail when agent is not connected
        #[tokio::test]
        async fn story_trigger_pivot_fails_when_no_agent() {
            let registry = Arc::new(AgentRegistry::new());
            let ops = PivotOperationsImpl::new(registry);

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
            let ops = PivotOperationsImpl::new(registry);

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
}
