//! LatticeCluster Custom Resource Definition
//!
//! The LatticeCluster CRD represents a Kubernetes cluster managed by Lattice.
//! It supports both parent clusters (can have children) and leaf clusters.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::issuer::DnsConfig;
use super::topology::NetworkTopologyConfig;
use super::types::{
    ClusterPhase, Condition, EndpointsSpec, NodeSpec, ProviderSpec, RegistryMirror,
};

/// Monitoring infrastructure configuration.
///
/// Controls VictoriaMetrics deployment and HA mode.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct MonitoringConfig {
    /// Enable monitoring infrastructure (VictoriaMetrics + KEDA).
    #[serde(default = "super::default_true")]
    pub enabled: bool,
    /// Deploy VictoriaMetrics in HA cluster mode (2 replicas each).
    /// When false, deploys a single-node VMSingle instance.
    #[serde(default = "super::default_true")]
    pub ha: bool,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ha: true,
        }
    }
}

/// Backup infrastructure configuration.
///
/// Controls Velero deployment.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct BackupsConfig {
    /// Enable backup infrastructure (Velero).
    #[serde(default = "super::default_true")]
    pub enabled: bool,
}

impl Default for BackupsConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Specification for a LatticeCluster
///
/// A LatticeCluster can be either:
/// - A parent cluster with the `parent` field set (can provision children)
/// - A leaf cluster (without `parent` field)
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeCluster",
    plural = "latticeclusters",
    shortname = "lc",
    status = "LatticeClusterStatus",
    namespaced = false,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Provider","type":"string","jsonPath":".spec.provider.type"}"#,
    printcolumn = r#"{"name":"K8s","type":"string","jsonPath":".spec.provider.kubernetes.version"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#,
    printcolumn = r#"{"name":"Image","type":"string","jsonPath":".status.latticeImage","priority":1}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeClusterSpec {
    /// Reference to a InfraProvider for credentials and account-level config
    ///
    /// The cluster uses the referenced InfraProvider's credentials.
    /// The provider field still contains cluster-specific config (k8s version, instance types).
    pub provider_ref: String,

    /// Infrastructure provider configuration
    pub provider: ProviderSpec,

    /// Node topology (control plane and worker counts)
    pub nodes: NodeSpec,

    /// Parent configuration - if present, this cluster can accept child connections
    ///
    /// When set, the cluster acts as a parent (cell) that can provision and manage
    /// child clusters. Contains the host and ports for child agent connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_config: Option<EndpointsSpec>,

    /// Enable LatticeService support (Istio ambient mesh + bilateral agreements).
    /// Defaults to true for backwards compatibility.
    #[serde(default = "super::default_true")]
    pub services: bool,

    /// Enable GPU infrastructure (NFD + NVIDIA device plugin).
    /// GPUs are discovered automatically by NFD from instance types.
    #[serde(default)]
    pub gpu: bool,

    /// Monitoring infrastructure configuration (VictoriaMetrics + KEDA for autoscaling).
    #[serde(default)]
    pub monitoring: MonitoringConfig,

    /// Backup infrastructure configuration (Velero).
    #[serde(default)]
    pub backups: BackupsConfig,

    /// Network topology configuration for topology-aware scheduling.
    /// Enables Volcano HyperNode discovery for workload co-placement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_topology: Option<NetworkTopologyConfig>,

    /// Registry mirrors for redirecting container image pulls through private mirrors.
    /// Each entry maps an upstream registry to a mirror endpoint with optional credentials.
    /// Use `upstream: "@infra"` to cover all build-time infrastructure registries.
    /// Use `upstream: "*"` as a catch-all for any registry (air-gapped environments).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_mirrors: Option<Vec<RegistryMirror>>,

    /// DNS provider configuration for external-dns and ACME DNS-01 challenges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,

    /// Named cert-manager issuer references.
    /// Keys are logical names (e.g., "public", "internal"), values are
    /// names of CertIssuer CRD resources. Each referenced CertIssuer generates
    /// a cert-manager ClusterIssuer named `lattice-{key}`.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub issuers: std::collections::BTreeMap<String, String>,

    /// Container image for the Lattice operator on this cluster.
    pub lattice_image: String,

    /// When true, this cluster pushes its latticeImage to children via K8s API proxy.
    #[serde(default)]
    pub cascade_upgrade: bool,
}

impl LatticeClusterSpec {
    /// Returns true if this cluster can have children (has parent config)
    pub fn is_parent(&self) -> bool {
        self.parent_config.is_some()
    }

    /// Validate the cluster specification
    pub fn validate(&self) -> Result<(), crate::Error> {
        // provider_ref must not be empty
        if self.provider_ref.is_empty() {
            return Err(crate::Error::validation("provider_ref cannot be empty"));
        }

        // Validate node spec
        self.nodes.validate()?;

        // Validate parent config if present
        if let Some(ref pc) = self.parent_config {
            pc.validate()?;
        }

        // Validate DNS config
        if let Some(ref dns) = self.dns {
            dns.validate().map_err(crate::Error::validation)?;
        }

        // Validate issuer references
        for (key, cert_issuer_ref) in &self.issuers {
            crate::crd::validate_dns_label(key, "issuer key").map_err(crate::Error::validation)?;
            if cert_issuer_ref.is_empty() {
                return Err(crate::Error::validation(format!(
                    "issuers['{key}']: CertIssuer reference cannot be empty"
                )));
            }
        }

        Ok(())
    }
}

/// Resource capacity for a single worker pool.
///
/// Each pool has homogeneous nodes (same instance type). Reports both
/// the per-node resource shape and aggregate allocation across the pool,
/// giving the scheduler enough to determine workload schedulability.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PoolResourceSummary {
    /// Pool name (matches lattice.dev/pool label on nodes)
    pub pool_name: String,
    /// Number of ready nodes in this pool
    pub ready_nodes: u32,
    /// Total number of nodes in this pool
    pub total_nodes: u32,
    /// Allocatable CPU per node (millicores)
    pub node_cpu_millis: i64,
    /// Allocatable memory per node (bytes)
    pub node_memory_bytes: i64,
    /// GPU devices per node (0 if no GPUs)
    pub node_gpu_count: u32,
    /// GPU type from NFD label (e.g. "NVIDIA-H100"), empty if no GPUs
    pub gpu_type: String,
    /// Sum of pod CPU requests across pool (millicores)
    pub allocated_cpu_millis: i64,
    /// Sum of pod memory requests across pool (bytes)
    pub allocated_memory_bytes: i64,
    /// Sum of pod GPU requests across pool
    pub allocated_gpu_count: u32,
}

/// Health of a child cluster connected via agent
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChildClusterHealth {
    /// Child cluster name
    pub name: String,
    /// Number of ready nodes
    #[serde(default)]
    pub ready_nodes: u32,
    /// Total number of nodes
    #[serde(default)]
    pub total_nodes: u32,
    /// Number of ready control plane nodes
    #[serde(default)]
    pub ready_control_plane: u32,
    /// Total number of control plane nodes
    #[serde(default)]
    pub total_control_plane: u32,
    /// Current agent state (e.g., "Ready", "Provisioning")
    #[serde(default)]
    pub agent_state: String,
    /// Last heartbeat timestamp (ISO 8601)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_heartbeat: Option<String>,
    /// Per-worker-pool resource capacity (CPU, memory, GPU)
    #[serde(default)]
    pub pool_resources: Vec<PoolResourceSummary>,

    /// Operator image running on this child cluster
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lattice_image: Option<String>,

    /// Kubernetes version running on this child cluster (e.g. "v1.32")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_version: Option<String>,
}

/// Status for a worker pool
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkerPoolStatus {
    /// Desired number of replicas (from MachineDeployment, not spec when autoscaling)
    #[serde(default)]
    pub desired_replicas: u32,

    /// Current number of replicas (MachineDeployment spec.replicas)
    #[serde(default)]
    pub current_replicas: u32,

    /// Number of ready nodes in this pool
    #[serde(default)]
    pub ready_replicas: u32,

    /// Whether cluster autoscaler manages this pool
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub autoscaling_enabled: bool,

    /// Human-readable message about pool state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Phase of an infrastructure component upgrade.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum InfraComponentPhase {
    /// Version matches desired — no work needed.
    #[default]
    UpToDate,
    /// Manifests applied, waiting for health gate.
    Upgrading,
    /// Health gate failed or component is unhealthy after upgrade.
    Degraded,
}

impl std::fmt::Display for InfraComponentPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UpToDate => write!(f, "UpToDate"),
            Self::Upgrading => write!(f, "Upgrading"),
            Self::Degraded => write!(f, "Degraded"),
        }
    }
}

/// Status of a single infrastructure component (Istio, Cilium, etc.).
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InfraComponentStatus {
    /// Component name (e.g., "istio", "cilium", "cert-manager").
    pub name: String,
    /// Version embedded in the operator binary.
    pub desired_version: String,
    /// Version last successfully applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<String>,
    /// Current upgrade phase.
    #[serde(default)]
    pub phase: InfraComponentPhase,
}

/// Status for a LatticeCluster
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeClusterStatus {
    /// The generation of the spec that was last processed by the controller.
    ///
    /// Consumers can compare this to `metadata.generation` to determine if the
    /// controller has processed the most recent spec changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Current phase of the cluster lifecycle
    #[serde(default)]
    pub phase: ClusterPhase,

    /// Human-readable message about current state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Conditions representing the cluster state
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    /// Number of ready control plane nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready_control_plane: Option<u32>,

    /// Number of ready worker nodes (sum across all pools)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready_workers: Option<u32>,

    /// Status of individual worker pools
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub worker_pools: std::collections::BTreeMap<String, WorkerPoolStatus>,

    /// Kubernetes API server endpoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// Whether pivot has completed successfully
    ///
    /// This is set to true when the agent confirms MoveCompleteAck with success=true.
    /// It's the authoritative source of truth for pivot completion, persisted in
    /// the cluster status to survive controller restarts.
    #[serde(default, skip_serializing_if = "is_false")]
    pub pivot_complete: bool,

    /// Whether bootstrap has completed (manifests fetched from parent)
    ///
    /// This is set to true when the bootstrap webhook is called and manifests are
    /// returned. It persists across operator restarts, allowing CSR signing to work
    /// for clusters that completed bootstrap before the restart.
    #[serde(default, skip_serializing_if = "is_false")]
    pub bootstrap_complete: bool,

    /// Whether CAPI import is complete for unpivot (crash-safe marker)
    ///
    /// Set to true AFTER successfully importing CAPI objects from child and unpausing,
    /// but BEFORE initiating LatticeCluster deletion. This prevents re-importing on
    /// crash recovery which could cause ownership/UID conflicts.
    ///
    /// Flow: import -> unpause -> set this true -> delete LatticeCluster
    #[serde(default, skip_serializing_if = "is_false")]
    pub unpivot_import_complete: bool,

    /// Bootstrap token for authenticating with the parent cell during bootstrap
    ///
    /// Generated once when the cluster is first provisioned and stored here
    /// as the single source of truth. Used by the bootstrap webhook to validate
    /// requests from new clusters. Moves with the LatticeCluster during pivot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_token: Option<String>,

    /// SHA-256 hash of the one-time CSR token (generated when bootstrap is consumed)
    ///
    /// Persisted to CRD status so CSR signing survives operator restarts.
    /// The raw CSR token is never persisted — only sent once in the bootstrap response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csr_token_hash: Option<String>,

    /// Health of child clusters connected via agent
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children_health: Vec<ChildClusterHealth>,

    /// Last heartbeat timestamp from agent (if this cluster has a parent)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_heartbeat: Option<String>,

    /// Last Kubernetes version successfully reconciled to all CAPI resources (CP + workers).
    ///
    /// Set only AFTER all control plane and worker pool versions match the desired version.
    /// When `status.version == format_capi_version(spec.provider.kubernetes.version)`,
    /// the version reconciliation loop is skipped entirely (zero CAPI API calls).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Per-component infrastructure upgrade status.
    ///
    /// Populated by the operator during phased infrastructure installation.
    /// Each entry tracks the desired vs current version and upgrade phase
    /// for a single component (Istio, Cilium, cert-manager, etc.).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub infrastructure: Vec<InfraComponentStatus>,

    /// Per-worker-pool resource capacity (CPU, memory, GPU)
    #[serde(default)]
    pub pool_resources: Vec<PoolResourceSummary>,

    /// The operator image currently running on this cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lattice_image: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl LatticeClusterStatus {
    /// Create a new status with the given phase
    pub fn with_phase(phase: ClusterPhase) -> Self {
        Self {
            phase,
            ..Default::default()
        }
    }

    /// Set the phase and return self for chaining
    pub fn phase(mut self, phase: ClusterPhase) -> Self {
        self.phase = phase;
        self
    }

    /// Set the message and return self for chaining
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    /// Add a condition and return self for chaining
    pub fn condition(mut self, condition: Condition) -> Self {
        // Remove existing condition of the same type
        self.conditions.retain(|c| c.type_ != condition.type_);
        self.conditions.push(condition);
        self
    }

    /// Mark unpivot import as complete and return self for chaining
    pub fn unpivot_import_complete(mut self, complete: bool) -> Self {
        self.unpivot_import_complete = complete;
        self
    }
}

impl LatticeCluster {
    /// Create a copy suitable for export to another cluster.
    ///
    /// Strips server-managed metadata fields (managedFields, resourceVersion, uid, etc.)
    /// that would cause server-side apply to fail on the target cluster.
    /// Status is removed entirely since it should be managed by the target cluster's
    /// controller, not inherited from the source.
    pub fn for_export(&self) -> Self {
        let mut exported = self.clone();
        crate::kube_utils::strip_export_metadata(&mut exported.metadata);
        // Remove status entirely - the target cluster's controller will manage status.
        exported.status = None;
        exported
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::types::{
        BootstrapProvider, ControlPlaneSpec, KubernetesSpec, ProviderConfig, ServiceSpec,
        WorkerPoolSpec,
    };

    // =========================================================================
    // Test Fixtures
    // =========================================================================

    fn sample_provider_spec() -> ProviderSpec {
        ProviderSpec {
            kubernetes: KubernetesSpec {
                version: "1.32.0".to_string(),
                cert_sans: Some(vec!["127.0.0.1".to_string(), "localhost".to_string()]),
                bootstrap: BootstrapProvider::default(),
            },
            config: ProviderConfig::docker(),
            credentials_secret_ref: None,
        }
    }

    fn sample_node_spec() -> NodeSpec {
        NodeSpec {
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
        }
    }

    fn endpoints_spec() -> EndpointsSpec {
        EndpointsSpec {
            grpc_port: 50051,
            bootstrap_port: 8443,
            proxy_port: 8081,
            service: ServiceSpec {
                type_: "LoadBalancer".to_string(),
            },
            cert_policy: None,
        }
    }

    // =========================================================================
    // Cluster Type Identification Stories
    // =========================================================================
    //
    // Lattice supports two cluster configurations:
    // - Parent clusters: Can provision and manage child clusters (have `parent` field)
    // - Leaf clusters: Run user applications, cannot provision children

    /// Story: A cluster with parent configuration can have children
    ///
    /// Parent clusters can provision and manage child clusters. They have the
    /// parent config (host, service) for child clusters to connect back to.
    #[test]
    fn cluster_with_parent_config_can_have_children() {
        let spec = LatticeClusterSpec {
            provider_ref: "test-provider".to_string(),
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),

            parent_config: Some(endpoints_spec()),
            services: true,
            gpu: false,
            monitoring: MonitoringConfig::default(),
            backups: BackupsConfig::default(),
            network_topology: None,
            registry_mirrors: None,
            dns: None,
            issuers: std::collections::BTreeMap::new(),
            lattice_image: "ghcr.io/evan-hines-js/lattice:latest".to_string(),
            cascade_upgrade: false,
        };

        assert!(spec.is_parent(), "Should be recognized as a parent");
    }

    /// Story: A cluster without parent configuration is a leaf cluster
    ///
    /// Leaf clusters run user workloads and connect outbound to their
    /// parent for management and monitoring.
    #[test]
    fn cluster_without_parent_is_leaf() {
        let spec = LatticeClusterSpec {
            provider_ref: "test-provider".to_string(),
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),

            parent_config: None,
            services: true,
            gpu: false,
            monitoring: MonitoringConfig::default(),
            backups: BackupsConfig::default(),
            network_topology: None,
            registry_mirrors: None,
            dns: None,
            issuers: std::collections::BTreeMap::new(),
            lattice_image: "ghcr.io/evan-hines-js/lattice:latest".to_string(),
            cascade_upgrade: false,
        };

        assert!(!spec.is_parent(), "Leaf cluster cannot have children");
    }

    // =========================================================================
    // Validation Stories
    // =========================================================================
    //
    // These tests ensure cluster specs are validated before provisioning.

    /// Story: Valid parent cluster configuration passes validation
    ///
    /// A parent cluster needs parent config and valid node topology.
    #[test]
    fn valid_parent_passes_validation() {
        let spec = LatticeClusterSpec {
            provider_ref: "test-provider".to_string(),
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),

            parent_config: Some(endpoints_spec()),
            services: true,
            gpu: false,
            monitoring: MonitoringConfig::default(),
            backups: BackupsConfig::default(),
            network_topology: None,
            registry_mirrors: None,
            dns: None,
            issuers: std::collections::BTreeMap::new(),
            lattice_image: "ghcr.io/evan-hines-js/lattice:latest".to_string(),
            cascade_upgrade: false,
        };

        assert!(
            spec.validate().is_ok(),
            "Valid parent spec should pass validation"
        );
    }

    /// Story: Valid workload cluster configuration passes validation
    ///
    /// A workload cluster needs valid node topology.
    #[test]
    fn valid_workload_cluster_passes_validation() {
        let spec = LatticeClusterSpec {
            provider_ref: "test-provider".to_string(),
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),

            parent_config: None,
            services: true,
            gpu: false,
            monitoring: MonitoringConfig::default(),
            backups: BackupsConfig::default(),
            network_topology: None,
            registry_mirrors: None,
            dns: None,
            issuers: std::collections::BTreeMap::new(),
            lattice_image: "ghcr.io/evan-hines-js/lattice:latest".to_string(),
            cascade_upgrade: false,
        };

        assert!(
            spec.validate().is_ok(),
            "Valid workload spec should pass validation"
        );
    }

    /// Story: Cluster with zero control plane nodes fails validation
    ///
    /// Every Kubernetes cluster needs at least one control plane node.
    #[test]
    fn zero_control_plane_nodes_fails_validation() {
        let spec = LatticeClusterSpec {
            provider_ref: "test-provider".to_string(),
            provider: sample_provider_spec(),
            nodes: NodeSpec {
                control_plane: ControlPlaneSpec {
                    replicas: 0,
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

            parent_config: None,
            services: true,
            gpu: false,
            monitoring: MonitoringConfig::default(),
            backups: BackupsConfig::default(),
            network_topology: None,
            registry_mirrors: None,
            dns: None,
            issuers: std::collections::BTreeMap::new(),
            lattice_image: "ghcr.io/evan-hines-js/lattice:latest".to_string(),
            cascade_upgrade: false,
        };

        assert!(
            spec.validate().is_err(),
            "Zero control plane nodes should fail"
        );
    }

    /// Story: Empty provider_ref fails validation
    ///
    /// Every cluster must reference a InfraProvider for credentials.
    #[test]
    fn empty_provider_ref_fails_validation() {
        let spec = LatticeClusterSpec {
            provider_ref: "".to_string(),
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),

            parent_config: None,
            services: true,
            gpu: false,
            monitoring: MonitoringConfig::default(),
            backups: BackupsConfig::default(),
            network_topology: None,
            registry_mirrors: None,
            dns: None,
            issuers: std::collections::BTreeMap::new(),
            lattice_image: "ghcr.io/evan-hines-js/lattice:latest".to_string(),
            cascade_upgrade: false,
        };

        assert!(
            spec.validate().is_err(),
            "Empty provider_ref should fail validation"
        );
    }

    // =========================================================================
    // Status Builder Stories
    // =========================================================================
    //
    // The status builder pattern allows fluent construction of cluster status.

    /// Story: Controller builds complete status during reconciliation
    ///
    /// The controller uses the builder pattern to construct status updates
    /// with phase, message, and conditions in a single fluent chain.
    #[test]
    fn controller_builds_complete_status_fluently() {
        use crate::crd::types::ConditionStatus;

        let condition = Condition::new(
            "Ready",
            ConditionStatus::False,
            "Provisioning",
            "Cluster is being provisioned",
        );

        let status = LatticeClusterStatus::default()
            .phase(ClusterPhase::Provisioning)
            .message("Creating infrastructure")
            .condition(condition);

        assert_eq!(status.phase, ClusterPhase::Provisioning);
        assert_eq!(status.message.as_deref(), Some("Creating infrastructure"));
        assert_eq!(status.conditions.len(), 1);
    }

    /// Story: Adding condition with same type replaces the old one
    ///
    /// When cluster state changes (e.g., Ready: False -> Ready: True),
    /// the new condition replaces the old one rather than accumulating.
    #[test]
    fn new_condition_replaces_old_condition_of_same_type() {
        use crate::crd::types::ConditionStatus;

        let provisioning = Condition::new(
            "Ready",
            ConditionStatus::False,
            "Provisioning",
            "Cluster is being provisioned",
        );
        let ready = Condition::new(
            "Ready",
            ConditionStatus::True,
            "ClusterReady",
            "Cluster is ready",
        );

        let status = LatticeClusterStatus::default()
            .condition(provisioning)
            .condition(ready);

        assert_eq!(
            status.conditions.len(),
            1,
            "Should only have one Ready condition"
        );
        assert_eq!(
            status.conditions[0].status,
            ConditionStatus::True,
            "Should have the latest status"
        );
        assert_eq!(
            status.conditions[0].reason, "ClusterReady",
            "Should have the latest reason"
        );
    }

    // =========================================================================
    // YAML Serialization Stories
    // =========================================================================
    //
    // LatticeCluster specs are defined in YAML manifests. These tests ensure
    // serialization matches the expected format.

    /// Story: User defines management cluster in YAML manifest
    ///
    /// Platform operators define management clusters in YAML files that
    /// are applied to set up the Lattice control plane.
    #[test]
    fn yaml_manifest_defines_management_cluster() {
        let yaml = r#"
providerRef: aws-prod
provider:
  kubernetes:
    version: "1.35.0"
    certSANs:
      - "127.0.0.1"
      - "localhost"
  config:
    docker:
      lbCidr: "172.18.255.1/32"
nodes:
  controlPlane:
    replicas: 1
  workerPools:
    default:
      replicas: 2
parentConfig:
  service:
    type: LoadBalancer
latticeImage: "ghcr.io/evan-hines-js/lattice:v1.0.0"
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("should parse YAML");
        let spec: LatticeClusterSpec =
            serde_json::from_value(value).expect("parent cluster YAML should parse successfully");

        assert!(spec.is_parent(), "Should be a parent cluster");
        assert_eq!(spec.nodes.control_plane.replicas, 1);
        assert_eq!(spec.nodes.total_workers(), 2);
        assert_eq!(spec.provider.kubernetes.version, "1.35.0");
        assert_eq!(
            spec.provider.config.lb_cidr(),
            Some("172.18.255.1/32"),
            "lb_cidr should be extracted from docker config"
        );
        assert_eq!(
            spec.parent_config
                .as_ref()
                .expect("parent_config should be present")
                .service
                .type_,
            "LoadBalancer"
        );
    }

    /// Story: User defines leaf cluster in YAML manifest
    ///
    /// Application teams define leaf clusters for running workloads.
    /// Environment/region metadata belongs in metadata.labels, not in the spec.
    #[test]
    fn yaml_manifest_defines_leaf_cluster() {
        let yaml = r#"
providerRef: aws-prod
provider:
  kubernetes:
    version: "1.32.0"
    certSANs:
      - "127.0.0.1"
  config:
    docker: {}
nodes:
  controlPlane:
    replicas: 1
  workerPools:
    general:
      replicas: 3
latticeImage: "ghcr.io/evan-hines-js/lattice:v1.0.0"
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("should parse YAML");
        let spec: LatticeClusterSpec =
            serde_json::from_value(value).expect("leaf cluster YAML should parse successfully");

        assert!(!spec.is_parent(), "Should be leaf cluster");
        assert_eq!(spec.nodes.total_workers(), 3);
    }

    /// Story: Spec survives serialization roundtrip
    ///
    /// When specs are serialized and deserialized (e.g., stored in etcd),
    /// all data must be preserved.
    #[test]
    fn spec_survives_json_roundtrip() {
        let spec = LatticeClusterSpec {
            provider_ref: "test-provider".to_string(),
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),

            parent_config: None,
            services: true,
            gpu: false,
            monitoring: MonitoringConfig::default(),
            backups: BackupsConfig::default(),
            network_topology: None,
            registry_mirrors: None,
            dns: None,
            issuers: std::collections::BTreeMap::new(),
            lattice_image: "ghcr.io/evan-hines-js/lattice:latest".to_string(),
            cascade_upgrade: false,
        };

        let json =
            serde_json::to_string(&spec).expect("LatticeClusterSpec serialization should succeed");
        let parsed: LatticeClusterSpec =
            serde_json::from_str(&json).expect("LatticeClusterSpec deserialization should succeed");

        assert_eq!(spec, parsed, "Spec should survive roundtrip");
    }

    // =========================================================================
    // PoolResourceSummary Serialization Tests
    // =========================================================================

    /// Story: PoolResourceSummary survives JSON serialization roundtrip
    ///
    /// Pool resource summaries are stored in LatticeClusterStatus and transmitted
    /// via heartbeats. All fields must survive serialization to/from JSON.
    #[test]
    fn pool_resource_summary_survives_json_roundtrip() {
        let summary = PoolResourceSummary {
            pool_name: "gpu-pool".to_string(),
            ready_nodes: 3,
            total_nodes: 4,
            node_cpu_millis: 16000,
            node_memory_bytes: 68_719_476_736, // 64 GiB
            node_gpu_count: 8,
            gpu_type: "NVIDIA-H100".to_string(),
            allocated_cpu_millis: 12000,
            allocated_memory_bytes: 51_539_607_552, // 48 GiB
            allocated_gpu_count: 6,
        };

        let json = serde_json::to_string(&summary)
            .expect("PoolResourceSummary serialization should succeed");
        let parsed: PoolResourceSummary = serde_json::from_str(&json)
            .expect("PoolResourceSummary deserialization should succeed");

        assert_eq!(
            summary, parsed,
            "PoolResourceSummary should survive roundtrip"
        );
    }

    /// Story: Default PoolResourceSummary roundtrips cleanly
    ///
    /// A default (zeroed) summary should also serialize and deserialize without loss.
    #[test]
    fn pool_resource_summary_default_roundtrip() {
        let summary = PoolResourceSummary::default();

        let json = serde_json::to_string(&summary)
            .expect("default PoolResourceSummary serialization should succeed");
        let parsed: PoolResourceSummary = serde_json::from_str(&json)
            .expect("default PoolResourceSummary deserialization should succeed");

        assert_eq!(
            summary, parsed,
            "Default PoolResourceSummary should survive roundtrip"
        );
    }

    /// Story: PoolResourceSummary uses camelCase in JSON (Kubernetes convention)
    ///
    /// The struct uses `#[serde(rename_all = "camelCase")]`, so JSON keys must be
    /// camelCase to match Kubernetes CRD conventions.
    #[test]
    fn pool_resource_summary_uses_camel_case_keys() {
        let summary = PoolResourceSummary {
            pool_name: "default".to_string(),
            ready_nodes: 2,
            total_nodes: 2,
            node_cpu_millis: 4000,
            node_memory_bytes: 8_589_934_592,
            node_gpu_count: 0,
            gpu_type: String::new(),
            allocated_cpu_millis: 1000,
            allocated_memory_bytes: 2_147_483_648,
            allocated_gpu_count: 0,
        };

        let json_value = serde_json::to_value(&summary).expect("serialization should succeed");
        let obj = json_value.as_object().expect("should be a JSON object");

        assert!(
            obj.contains_key("poolName"),
            "should have camelCase key 'poolName'"
        );
        assert!(
            obj.contains_key("readyNodes"),
            "should have camelCase key 'readyNodes'"
        );
        assert!(
            obj.contains_key("nodeCpuMillis"),
            "should have camelCase key 'nodeCpuMillis'"
        );
        assert!(
            obj.contains_key("nodeMemoryBytes"),
            "should have camelCase key 'nodeMemoryBytes'"
        );
        assert!(
            obj.contains_key("nodeGpuCount"),
            "should have camelCase key 'nodeGpuCount'"
        );
        assert!(
            obj.contains_key("gpuType"),
            "should have camelCase key 'gpuType'"
        );
        assert!(
            obj.contains_key("allocatedCpuMillis"),
            "should have camelCase key 'allocatedCpuMillis'"
        );
        assert!(
            obj.contains_key("allocatedMemoryBytes"),
            "should have camelCase key 'allocatedMemoryBytes'"
        );
        assert!(
            obj.contains_key("allocatedGpuCount"),
            "should have camelCase key 'allocatedGpuCount'"
        );

        // Verify snake_case keys are NOT present
        assert!(
            !obj.contains_key("pool_name"),
            "should not have snake_case keys"
        );
        assert!(
            !obj.contains_key("ready_nodes"),
            "should not have snake_case keys"
        );
    }

    // =========================================================================
    // Export Tests
    // =========================================================================

    #[test]
    fn for_export_strips_status() {
        let cluster = LatticeCluster {
            metadata: kube::api::ObjectMeta {
                name: Some("test-cluster".to_string()),
                namespace: Some("default".to_string()),
                uid: Some("abc-123".to_string()),
                resource_version: Some("12345".to_string()),
                ..Default::default()
            },
            spec: LatticeClusterSpec {
                provider_ref: "test".to_string(),
                provider: sample_provider_spec(),
                nodes: sample_node_spec(),

                parent_config: None,
                services: true,
                gpu: false,
                monitoring: MonitoringConfig::default(),
                backups: BackupsConfig::default(),
                network_topology: None,
                registry_mirrors: None,
                dns: None,
                issuers: std::collections::BTreeMap::new(),
                lattice_image: "ghcr.io/evan-hines-js/lattice:latest".to_string(),
                cascade_upgrade: false,
            },
            status: Some(LatticeClusterStatus::default().phase(ClusterPhase::Ready)),
        };

        let exported = cluster.for_export();

        // Status should be removed
        assert!(exported.status.is_none());
        // Name should be preserved
        assert_eq!(exported.metadata.name, Some("test-cluster".to_string()));
        // Server-managed fields should be stripped
        assert!(exported.metadata.uid.is_none());
        assert!(exported.metadata.resource_version.is_none());
    }
}
