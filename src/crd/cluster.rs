//! LatticeCluster Custom Resource Definition
//!
//! The LatticeCluster CRD represents a Kubernetes cluster managed by Lattice.
//! It supports both management clusters (cells) and workload clusters.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::{
    CellSpec, Condition, ClusterPhase, NetworkingSpec, NodeSpec, ProviderSpec, WorkloadSpec,
};

/// Specification for a LatticeCluster
///
/// A LatticeCluster can be either:
/// - A management cluster (cell) with the `cell` field set
/// - A workload cluster with `cell_ref` pointing to its parent cell
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
    /// Infrastructure provider configuration
    pub provider: ProviderSpec,

    /// Node topology (control plane and worker counts)
    pub nodes: NodeSpec,

    /// Network configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub networking: Option<NetworkingSpec>,

    /// Cell configuration - if present, this cluster is a management cluster
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell: Option<CellSpec>,

    /// Reference to parent cell - for workload clusters
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_ref: Option<String>,

    /// Environment identifier (e.g., prod, staging, dev)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,

    /// Region identifier
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// Workload configuration - services to deploy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<WorkloadSpec>,
}

impl LatticeClusterSpec {
    /// Returns true if this cluster is a cell (management cluster)
    pub fn is_cell(&self) -> bool {
        self.cell.is_some()
    }

    /// Returns true if this is a workload cluster (has a cell reference)
    pub fn is_workload_cluster(&self) -> bool {
        self.cell_ref.is_some()
    }

    /// Validate the cluster specification
    pub fn validate(&self) -> Result<(), crate::Error> {
        // Validate node spec
        self.nodes.validate()?;

        // A cluster can't be both a cell and reference another cell
        if self.cell.is_some() && self.cell_ref.is_some() {
            return Err(crate::Error::validation(
                "cluster cannot have both 'cell' and 'cellRef' - it's either a management cluster or a workload cluster",
            ));
        }

        Ok(())
    }
}

/// Status for a LatticeCluster
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeClusterStatus {
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

    /// Number of ready worker nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready_workers: Option<u32>,

    /// Kubernetes API server endpoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::types::{KubernetesSpec, ProviderType, ServiceSpec};

    // =========================================================================
    // Test Fixtures
    // =========================================================================

    fn sample_provider_spec() -> ProviderSpec {
        ProviderSpec {
            type_: ProviderType::Docker,
            kubernetes: KubernetesSpec {
                version: "1.31.0".to_string(),
                cert_sans: Some(vec!["127.0.0.1".to_string(), "localhost".to_string()]),
            },
        }
    }

    fn sample_node_spec() -> NodeSpec {
        NodeSpec {
            control_plane: 1,
            workers: 2,
        }
    }

    fn cell_spec() -> CellSpec {
        CellSpec {
            host: "172.18.255.1".to_string(),
            service: ServiceSpec {
                type_: "LoadBalancer".to_string(),
            },
        }
    }

    // =========================================================================
    // Cluster Type Identification Stories
    // =========================================================================
    //
    // Lattice supports two cluster types:
    // - Cells: Management clusters that provision and monitor workload clusters
    // - Workloads: Clusters that run user applications and reference a parent cell

    /// Story: A cluster with cell configuration is recognized as a management cluster
    ///
    /// Cells are the management plane of Lattice. They have the cell config
    /// (host, service) which enables them to accept connections from child clusters.
    #[test]
    fn story_cluster_with_cell_config_is_management_cluster() {
        let spec = LatticeClusterSpec {
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),
            networking: None,
            cell: Some(cell_spec()),
            cell_ref: None,
            environment: None,
            region: None,
            workload: None,
        };

        assert!(spec.is_cell(), "Should be recognized as a cell");
        assert!(
            !spec.is_workload_cluster(),
            "Cell is not a workload cluster"
        );
    }

    /// Story: A cluster with cellRef is recognized as a workload cluster
    ///
    /// Workload clusters reference their parent cell. They run user workloads
    /// and connect outbound to the cell for management and monitoring.
    #[test]
    fn story_cluster_with_cell_ref_is_workload_cluster() {
        let spec = LatticeClusterSpec {
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),
            networking: None,
            cell: None,
            cell_ref: Some("mgmt".to_string()),
            environment: Some("prod".to_string()),
            region: Some("us-west".to_string()),
            workload: None,
        };

        assert!(
            spec.is_workload_cluster(),
            "Should be recognized as workload cluster"
        );
        assert!(!spec.is_cell(), "Workload cluster is not a cell");
    }

    // =========================================================================
    // Validation Stories
    // =========================================================================
    //
    // These tests ensure cluster specs are validated before provisioning.

    /// Story: Valid cell configuration passes validation
    ///
    /// A management cluster needs cell config and valid node topology.
    #[test]
    fn story_valid_cell_passes_validation() {
        let spec = LatticeClusterSpec {
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),
            networking: None,
            cell: Some(cell_spec()),
            cell_ref: None,
            environment: None,
            region: None,
            workload: None,
        };

        assert!(
            spec.validate().is_ok(),
            "Valid cell spec should pass validation"
        );
    }

    /// Story: Valid workload cluster configuration passes validation
    ///
    /// A workload cluster needs a cellRef and valid node topology.
    #[test]
    fn story_valid_workload_cluster_passes_validation() {
        let spec = LatticeClusterSpec {
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),
            networking: None,
            cell: None,
            cell_ref: Some("mgmt".to_string()),
            environment: None,
            region: None,
            workload: None,
        };

        assert!(
            spec.validate().is_ok(),
            "Valid workload spec should pass validation"
        );
    }

    /// Story: Cluster cannot be both a cell AND reference another cell
    ///
    /// A cluster must be either a cell OR a workload cluster, never both.
    /// This prevents confusing hierarchies where a cluster manages itself.
    #[test]
    fn story_conflicting_cell_config_fails_validation() {
        let spec = LatticeClusterSpec {
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),
            networking: None,
            cell: Some(cell_spec()),
            cell_ref: Some("other-cell".to_string()),
            environment: None,
            region: None,
            workload: None,
        };

        let result = spec.validate();
        assert!(result.is_err(), "Conflicting config should fail validation");
        assert!(
            result.unwrap_err().to_string().contains("cannot have both"),
            "Error message should explain the conflict"
        );
    }

    /// Story: Cluster with zero control plane nodes fails validation
    ///
    /// Every Kubernetes cluster needs at least one control plane node.
    #[test]
    fn story_zero_control_plane_nodes_fails_validation() {
        let spec = LatticeClusterSpec {
            provider: sample_provider_spec(),
            nodes: NodeSpec {
                control_plane: 0,
                workers: 2,
            },
            networking: None,
            cell: None,
            cell_ref: None,
            environment: None,
            region: None,
            workload: None,
        };

        assert!(
            spec.validate().is_err(),
            "Zero control plane nodes should fail"
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
provider:
  type: docker
  kubernetes:
    version: "1.35.0"
    certSANs:
      - "127.0.0.1"
      - "localhost"
nodes:
  controlPlane: 1
  workers: 2
networking:
  default:
    cidr: "172.18.255.1/32"
cell:
  host: "172.18.255.1"
  service:
    type: LoadBalancer
"#;
        let spec: LatticeClusterSpec = serde_yaml::from_str(yaml).unwrap();

        assert!(spec.is_cell(), "Should be a cell");
        assert_eq!(spec.nodes.control_plane, 1);
        assert_eq!(spec.nodes.workers, 2);
        assert_eq!(spec.provider.kubernetes.version, "1.35.0");
        assert_eq!(spec.cell.as_ref().unwrap().host, "172.18.255.1");
    }

    /// Story: User defines production workload cluster in YAML manifest
    ///
    /// Application teams define workload clusters with environment metadata
    /// and service deployments.
    #[test]
    fn story_yaml_manifest_defines_production_workload_cluster() {
        let yaml = r#"
environment: prod
region: us-west
cellRef: mgmt
provider:
  type: docker
  kubernetes:
    version: "1.31.0"
    certSANs:
      - "127.0.0.1"
nodes:
  controlPlane: 1
  workers: 3
workload:
  services:
    - name: curl-tester
    - name: simple-nginx
"#;
        let spec: LatticeClusterSpec = serde_yaml::from_str(yaml).unwrap();

        assert!(spec.is_workload_cluster(), "Should be workload cluster");
        assert_eq!(spec.cell_ref.as_deref(), Some("mgmt"));
        assert_eq!(spec.environment.as_deref(), Some("prod"));
        assert_eq!(spec.region.as_deref(), Some("us-west"));

        let workload = spec.workload.unwrap();
        assert_eq!(workload.services.len(), 2);
        assert_eq!(workload.services[0].name, "curl-tester");
        assert_eq!(workload.services[1].name, "simple-nginx");
    }

    /// Story: Spec survives serialization roundtrip
    ///
    /// When specs are serialized and deserialized (e.g., stored in etcd),
    /// all data must be preserved.
    #[test]
    fn story_spec_survives_yaml_roundtrip() {
        let spec = LatticeClusterSpec {
            provider: sample_provider_spec(),
            nodes: sample_node_spec(),
            networking: None,
            cell: None,
            cell_ref: Some("mgmt".to_string()),
            environment: Some("staging".to_string()),
            region: None,
            workload: None,
        };

        let yaml = serde_yaml::to_string(&spec).unwrap();
        let parsed: LatticeClusterSpec = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(spec, parsed, "Spec should survive roundtrip");
    }
}
