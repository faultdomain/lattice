//! LatticeCluster Custom Resource Definition
//!
//! The LatticeCluster CRD represents a Kubernetes cluster managed by Lattice.
//! It supports both parent clusters (can have children) and leaf clusters.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::{
    ClusterPhase, Condition, EndpointsSpec, NetworkingSpec, NodeSpec, ProviderSpec,
};

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
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeClusterSpec {
    /// Reference to a CloudProvider for credentials and account-level config
    ///
    /// The cluster uses the referenced CloudProvider's credentials.
    /// The provider field still contains cluster-specific config (k8s version, instance types).
    pub provider_ref: String,

    /// Infrastructure provider configuration
    pub provider: ProviderSpec,

    /// Node topology (control plane and worker counts)
    pub nodes: NodeSpec,

    /// Network configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub networking: Option<NetworkingSpec>,

    /// Parent configuration - if present, this cluster can accept child connections
    ///
    /// When set, the cluster acts as a parent (cell) that can provision and manage
    /// child clusters. Contains the host and ports for child agent connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_config: Option<EndpointsSpec>,

    /// Enable LatticeService support (Istio ambient mesh + bilateral agreements).
    /// Defaults to true for backwards compatibility.
    #[serde(default = "default_true")]
    pub services_enabled: bool,
}

fn default_true() -> bool {
    true
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

        Ok(())
    }
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
        BootstrapProvider, KubernetesSpec, ProviderConfig, ServiceSpec, WorkerPoolSpec,
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
            control_plane: 1,
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
            host: Some("172.18.255.1".to_string()),
            grpc_port: 50051,
            bootstrap_port: 8443,
            proxy_port: 8081,
            service: ServiceSpec {
                type_: "LoadBalancer".to_string(),
            },
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
    fn story_cluster_with_parent_config_can_have_children() {
        let spec = LatticeClusterSpec {
            provider_ref: "test-provider".to_string(),
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),
            networking: None,
            parent_config: Some(endpoints_spec()),
            services_enabled: true,
        };

        assert!(spec.is_parent(), "Should be recognized as a parent");
    }

    /// Story: A cluster without parent configuration is a leaf cluster
    ///
    /// Leaf clusters run user workloads and connect outbound to their
    /// parent for management and monitoring.
    #[test]
    fn story_cluster_without_parent_is_leaf() {
        let spec = LatticeClusterSpec {
            provider_ref: "test-provider".to_string(),
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),
            networking: None,
            parent_config: None,
            services_enabled: true,
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
    fn story_valid_parent_passes_validation() {
        let spec = LatticeClusterSpec {
            provider_ref: "test-provider".to_string(),
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),
            networking: None,
            parent_config: Some(endpoints_spec()),
            services_enabled: true,
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
    fn story_valid_workload_cluster_passes_validation() {
        let spec = LatticeClusterSpec {
            provider_ref: "test-provider".to_string(),
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),
            networking: None,
            parent_config: None,
            services_enabled: true,
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
    fn story_zero_control_plane_nodes_fails_validation() {
        let spec = LatticeClusterSpec {
            provider_ref: "test-provider".to_string(),
            provider: sample_provider_spec(),
            nodes: NodeSpec {
                control_plane: 0,
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
            services_enabled: true,
        };

        assert!(
            spec.validate().is_err(),
            "Zero control plane nodes should fail"
        );
    }

    /// Story: Empty provider_ref fails validation
    ///
    /// Every cluster must reference a CloudProvider for credentials.
    #[test]
    fn story_empty_provider_ref_fails_validation() {
        let spec = LatticeClusterSpec {
            provider_ref: "".to_string(),
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),
            networking: None,
            parent_config: None,
            services_enabled: true,
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
    fn story_controller_builds_complete_status_fluently() {
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
    fn story_new_condition_replaces_old_condition_of_same_type() {
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
    fn story_yaml_manifest_defines_management_cluster() {
        let yaml = r#"
providerRef: aws-prod
provider:
  kubernetes:
    version: "1.35.0"
    certSANs:
      - "127.0.0.1"
      - "localhost"
  config:
    docker: {}
nodes:
  controlPlane: 1
  workerPools:
    default:
      replicas: 2
networking:
  default:
    cidr: "172.18.255.1/32"
parentConfig:
  host: "172.18.255.1"
  service:
    type: LoadBalancer
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("should parse YAML");
        let spec: LatticeClusterSpec =
            serde_json::from_value(value).expect("parent cluster YAML should parse successfully");

        assert!(spec.is_parent(), "Should be a parent cluster");
        assert_eq!(spec.nodes.control_plane, 1);
        assert_eq!(spec.nodes.total_workers(), 2);
        assert_eq!(spec.provider.kubernetes.version, "1.35.0");
        assert_eq!(
            spec.parent_config
                .as_ref()
                .expect("parent_config should be present")
                .host,
            Some("172.18.255.1".to_string())
        );
    }

    /// Story: User defines leaf cluster in YAML manifest
    ///
    /// Application teams define leaf clusters for running workloads.
    /// Environment/region metadata belongs in metadata.labels, not in the spec.
    #[test]
    fn story_yaml_manifest_defines_leaf_cluster() {
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
  controlPlane: 1
  workerPools:
    general:
      replicas: 3
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
    fn story_spec_survives_json_roundtrip() {
        let spec = LatticeClusterSpec {
            provider_ref: "test-provider".to_string(),
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),
            networking: None,
            parent_config: None,
            services_enabled: true,
        };

        let json =
            serde_json::to_string(&spec).expect("LatticeClusterSpec serialization should succeed");
        let parsed: LatticeClusterSpec =
            serde_json::from_str(&json).expect("LatticeClusterSpec deserialization should succeed");

        assert_eq!(spec, parsed, "Spec should survive roundtrip");
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
                networking: None,
                parent_config: None,
                services_enabled: true,
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
