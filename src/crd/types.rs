//! Supporting types for LatticeCluster CRD

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Supported infrastructure provider types
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ProviderType {
    /// Docker/Kind provider for local development
    #[default]
    Docker,
    /// Amazon Web Services
    Aws,
    /// Google Cloud Platform
    Gcp,
    /// Microsoft Azure
    Azure,
}

impl ProviderType {
    /// Returns true if this is a valid provider type string
    pub fn is_valid(s: &str) -> bool {
        matches!(
            s.to_lowercase().as_str(),
            "docker" | "aws" | "gcp" | "azure"
        )
    }
}

impl std::str::FromStr for ProviderType {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "docker" => Ok(Self::Docker),
            "aws" => Ok(Self::Aws),
            "gcp" => Ok(Self::Gcp),
            "azure" => Ok(Self::Azure),
            _ => Err(crate::Error::validation(format!(
                "invalid provider type: {s}, expected one of: docker, aws, gcp, azure"
            ))),
        }
    }
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Docker => write!(f, "docker"),
            Self::Aws => write!(f, "aws"),
            Self::Gcp => write!(f, "gcp"),
            Self::Azure => write!(f, "azure"),
        }
    }
}

/// Infrastructure provider specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ProviderSpec {
    /// The type of infrastructure provider
    #[serde(rename = "type")]
    pub type_: ProviderType,

    /// Kubernetes configuration
    pub kubernetes: KubernetesSpec,
}

/// Kubernetes version and configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct KubernetesSpec {
    /// Kubernetes version to deploy
    pub version: String,

    /// Additional Subject Alternative Names for the API server certificate
    #[serde(rename = "certSANs", default, skip_serializing_if = "Option::is_none")]
    pub cert_sans: Option<Vec<String>>,
}

/// Node topology specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct NodeSpec {
    /// Number of control plane nodes (must be positive odd number for HA)
    #[serde(rename = "controlPlane")]
    pub control_plane: u32,

    /// Number of worker nodes
    pub workers: u32,
}

impl NodeSpec {
    /// Returns the total number of nodes
    pub fn total_nodes(&self) -> u32 {
        self.control_plane + self.workers
    }

    /// Validates the node specification
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.control_plane == 0 {
            return Err(crate::Error::validation(
                "control plane count must be at least 1",
            ));
        }
        // For HA, control plane should be odd (1, 3, 5)
        if self.control_plane > 1 && self.control_plane.is_multiple_of(2) {
            return Err(crate::Error::validation(
                "control plane count must be odd for HA (1, 3, 5, ...)",
            ));
        }
        Ok(())
    }
}

/// Network configuration specification
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct NetworkingSpec {
    /// Default network pool configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<NetworkPool>,
}

/// Network pool for Cilium LB-IPAM
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct NetworkPool {
    /// CIDR block for the network pool (e.g., "172.18.255.1/32" for single IP)
    pub cidr: String,
}

/// Cell (management cluster) specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct CellSpec {
    /// Host address for agent connections
    pub host: String,

    /// gRPC port for agent connections (default: 50051)
    #[serde(default = "default_grpc_port", rename = "grpcPort")]
    pub grpc_port: u16,

    /// Bootstrap HTTPS port for kubeadm webhook (default: 443)
    #[serde(default = "default_bootstrap_port", rename = "bootstrapPort")]
    pub bootstrap_port: u16,

    /// Service exposure configuration
    pub service: ServiceSpec,
}

fn default_grpc_port() -> u16 {
    crate::DEFAULT_GRPC_PORT
}

fn default_bootstrap_port() -> u16 {
    crate::DEFAULT_BOOTSTRAP_PORT
}

impl CellSpec {
    /// Get the combined cell endpoint in format "host:http_port:grpc_port"
    ///
    /// This format is used by bootstrap to pass all connection info in a single string.
    pub fn cell_endpoint(&self) -> String {
        format!("{}:{}:{}", self.host, self.bootstrap_port, self.grpc_port)
    }

    /// Get the gRPC endpoint URL for agent connections
    pub fn grpc_endpoint(&self) -> String {
        format!("https://{}:{}", self.host, self.grpc_port)
    }

    /// Get the bootstrap endpoint URL for kubeadm webhook
    pub fn bootstrap_endpoint(&self) -> String {
        format!("https://{}:{}", self.host, self.bootstrap_port)
    }
}

/// Service exposure specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ServiceSpec {
    /// Service type (LoadBalancer, NodePort, ClusterIP)
    #[serde(rename = "type")]
    pub type_: String,
}

/// Workload specification for clusters
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct WorkloadSpec {
    /// Services to deploy on this cluster
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<ServiceRef>,
}

/// Reference to a service to deploy
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ServiceRef {
    /// Name of the service
    pub name: String,
}

/// Cluster lifecycle phase
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClusterPhase {
    /// Cluster is waiting to be provisioned
    #[default]
    Pending,
    /// Cluster infrastructure is being created
    Provisioning,
    /// CAPI resources are being pivoted to the cluster
    Pivoting,
    /// Cluster is fully operational and self-managing
    Ready,
    /// Cluster has encountered an error
    Failed,
}

impl std::fmt::Display for ClusterPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Provisioning => write!(f, "Provisioning"),
            Self::Pivoting => write!(f, "Pivoting"),
            Self::Ready => write!(f, "Ready"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Condition status following Kubernetes conventions
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum ConditionStatus {
    /// Condition is true
    True,
    /// Condition is false
    False,
    /// Condition status is unknown
    #[default]
    Unknown,
}

impl std::fmt::Display for ConditionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::True => write!(f, "True"),
            Self::False => write!(f, "False"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Kubernetes-style condition for status reporting
///
/// This type follows Kubernetes API conventions and can be used
/// for any resource status (clusters, services, etc.)
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct Condition {
    /// Type of condition (e.g., Ready, Provisioning)
    #[serde(rename = "type")]
    pub type_: String,

    /// Status of the condition (True, False, Unknown)
    pub status: ConditionStatus,

    /// Machine-readable reason for the condition
    pub reason: String,

    /// Human-readable message
    pub message: String,

    /// Last time the condition transitioned
    #[serde(rename = "lastTransitionTime")]
    pub last_transition_time: DateTime<Utc>,
}

impl Condition {
    /// Create a new condition with the current timestamp
    pub fn new(
        type_: impl Into<String>,
        status: ConditionStatus,
        reason: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            type_: type_.into(),
            status,
            reason: reason.into(),
            message: message.into(),
            last_transition_time: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod provider_type {
        use super::*;

        #[test]
        fn test_from_str_valid() {
            assert_eq!(
                "docker".parse::<ProviderType>().unwrap(),
                ProviderType::Docker
            );
            assert_eq!("aws".parse::<ProviderType>().unwrap(), ProviderType::Aws);
            assert_eq!("gcp".parse::<ProviderType>().unwrap(), ProviderType::Gcp);
            assert_eq!(
                "azure".parse::<ProviderType>().unwrap(),
                ProviderType::Azure
            );
        }

        #[test]
        fn test_from_str_case_insensitive() {
            assert_eq!(
                "DOCKER".parse::<ProviderType>().unwrap(),
                ProviderType::Docker
            );
            assert_eq!(
                "Docker".parse::<ProviderType>().unwrap(),
                ProviderType::Docker
            );
            assert_eq!("AWS".parse::<ProviderType>().unwrap(), ProviderType::Aws);
        }

        #[test]
        fn test_from_str_invalid() {
            let result = "invalid".parse::<ProviderType>();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("invalid provider type"));
        }

        #[test]
        fn test_display() {
            assert_eq!(ProviderType::Docker.to_string(), "docker");
            assert_eq!(ProviderType::Aws.to_string(), "aws");
            assert_eq!(ProviderType::Gcp.to_string(), "gcp");
            assert_eq!(ProviderType::Azure.to_string(), "azure");
        }

        #[test]
        fn test_is_valid() {
            assert!(ProviderType::is_valid("docker"));
            assert!(ProviderType::is_valid("aws"));
            assert!(ProviderType::is_valid("gcp"));
            assert!(ProviderType::is_valid("azure"));
            assert!(ProviderType::is_valid("DOCKER"));
            assert!(!ProviderType::is_valid("invalid"));
            assert!(!ProviderType::is_valid(""));
        }
    }

    mod node_spec {
        use super::*;

        #[test]
        fn test_total_nodes() {
            let spec = NodeSpec {
                control_plane: 1,
                workers: 2,
            };
            assert_eq!(spec.total_nodes(), 3);
        }

        #[test]
        fn test_validate_single_control_plane() {
            let spec = NodeSpec {
                control_plane: 1,
                workers: 0,
            };
            assert!(spec.validate().is_ok());
        }

        #[test]
        fn test_validate_ha_control_plane() {
            let spec = NodeSpec {
                control_plane: 3,
                workers: 2,
            };
            assert!(spec.validate().is_ok());

            let spec = NodeSpec {
                control_plane: 5,
                workers: 2,
            };
            assert!(spec.validate().is_ok());
        }

        #[test]
        fn test_validate_zero_control_plane_fails() {
            let spec = NodeSpec {
                control_plane: 0,
                workers: 2,
            };
            let result = spec.validate();
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("at least 1"));
        }

        #[test]
        fn test_validate_even_control_plane_fails() {
            let spec = NodeSpec {
                control_plane: 2,
                workers: 2,
            };
            let result = spec.validate();
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("odd"));
        }
    }

    mod cluster_condition {
        use super::*;

        #[test]
        fn test_new_sets_timestamp() {
            let before = Utc::now();
            let condition = Condition::new(
                "Ready",
                ConditionStatus::True,
                "ClusterReady",
                "Cluster is ready",
            );
            let after = Utc::now();

            assert_eq!(condition.type_, "Ready");
            assert_eq!(condition.status, ConditionStatus::True);
            assert_eq!(condition.reason, "ClusterReady");
            assert_eq!(condition.message, "Cluster is ready");
            assert!(condition.last_transition_time >= before);
            assert!(condition.last_transition_time <= after);
        }
    }

    // ==========================================================================
    // Story Tests: Cluster State Machine
    // ==========================================================================
    //
    // Clusters transition through phases during their lifecycle:
    // Pending -> Provisioning -> Pivoting -> Ready
    // Any phase can transition to Failed on error.

    mod cluster_lifecycle {
        use super::*;

        /// Story: New cluster starts in Pending phase
        ///
        /// When a user creates a LatticeCluster CRD, it starts in Pending
        /// phase waiting for the operator to begin provisioning.
        #[test]
        fn story_new_cluster_starts_pending() {
            let phase = ClusterPhase::default();
            assert_eq!(phase, ClusterPhase::Pending);
            assert_eq!(phase.to_string(), "Pending");
        }

        /// Story: Complete successful cluster lifecycle
        ///
        /// A cluster transitions through all phases during normal provisioning:
        /// Pending -> Provisioning -> Pivoting -> Ready
        #[test]
        fn story_successful_cluster_lifecycle() {
            // User creates LatticeCluster - starts Pending
            let mut phase = ClusterPhase::Pending;
            assert_eq!(phase.to_string(), "Pending");

            // Operator picks up CRD and starts CAPI provisioning
            phase = ClusterPhase::Provisioning;
            assert_eq!(phase.to_string(), "Provisioning");

            // CAPI completes, agent connects, pivot begins
            phase = ClusterPhase::Pivoting;
            assert_eq!(phase.to_string(), "Pivoting");

            // CAPI resources imported, cluster is self-managing
            phase = ClusterPhase::Ready;
            assert_eq!(phase.to_string(), "Ready");
        }

        /// Story: Cluster failure during provisioning
        ///
        /// If CAPI provisioning fails (e.g., quota exceeded),
        /// the cluster transitions to Failed state.
        #[test]
        fn story_provisioning_failure() {
            // CAPI reports infrastructure failure - cluster goes to Failed
            let phase = ClusterPhase::Failed;
            assert_eq!(phase.to_string(), "Failed");
        }

        /// Story: Cluster failure during pivot
        ///
        /// If pivot fails (e.g., agent disconnects), the cluster
        /// may need manual intervention.
        #[test]
        fn story_pivot_failure() {
            // Agent connection lost during pivot - cluster goes to Failed
            let phase = ClusterPhase::Failed;
            assert_eq!(phase.to_string(), "Failed");
        }

        /// Story: Phase values are serializable for status updates
        ///
        /// Phases must serialize correctly for Kubernetes status subresource.
        #[test]
        fn story_phase_serialization_for_kubernetes() {
            let phases = [
                ClusterPhase::Pending,
                ClusterPhase::Provisioning,
                ClusterPhase::Pivoting,
                ClusterPhase::Ready,
                ClusterPhase::Failed,
            ];

            for phase in phases {
                let json = serde_json::to_string(&phase).unwrap();
                let parsed: ClusterPhase = serde_json::from_str(&json).unwrap();
                assert_eq!(phase, parsed);
            }
        }
    }

    mod cluster_conditions {
        use super::*;

        /// Story: Conditions track cluster health with Kubernetes conventions
        ///
        /// Conditions follow Kubernetes API conventions with type, status,
        /// reason, and message fields plus a timestamp.
        #[test]
        fn story_conditions_follow_kubernetes_conventions() {
            let before = Utc::now();

            // Create a "Ready" condition
            let condition = Condition::new(
                "Ready",
                ConditionStatus::True,
                "ClusterReady",
                "All components are healthy",
            );

            let after = Utc::now();

            // Follows Kubernetes condition structure
            assert_eq!(condition.type_, "Ready");
            assert_eq!(condition.status, ConditionStatus::True);
            assert_eq!(condition.reason, "ClusterReady"); // Machine-readable
            assert_eq!(condition.message, "All components are healthy"); // Human-readable

            // Timestamp is set automatically
            assert!(condition.last_transition_time >= before);
            assert!(condition.last_transition_time <= after);
        }

        /// Story: Condition status reflects actual state
        ///
        /// ConditionStatus::True means the condition is met,
        /// False means it's not met, Unknown means we can't determine.
        #[test]
        fn story_condition_status_meanings() {
            // True = condition is definitely met
            let ready = Condition::new(
                "Ready",
                ConditionStatus::True,
                "AllHealthy",
                "Cluster is fully operational",
            );
            assert_eq!(ready.status.to_string(), "True");

            // False = condition is definitely NOT met
            let not_ready = Condition::new(
                "Ready",
                ConditionStatus::False,
                "ComponentsFailed",
                "Control plane nodes not reachable",
            );
            assert_eq!(not_ready.status.to_string(), "False");

            // Unknown = can't determine (e.g., during startup)
            let unknown = Condition::new(
                "Ready",
                ConditionStatus::Unknown,
                "Checking",
                "Health check in progress",
            );
            assert_eq!(unknown.status.to_string(), "Unknown");
        }

        /// Story: Default condition status is Unknown (safe default)
        #[test]
        fn story_default_condition_status_is_safe() {
            // When we don't know the state, Unknown is the safe default
            let status = ConditionStatus::default();
            assert_eq!(status, ConditionStatus::Unknown);
        }

        /// Story: Conditions are serializable for status updates
        #[test]
        fn story_condition_serialization() {
            let statuses = [
                ConditionStatus::True,
                ConditionStatus::False,
                ConditionStatus::Unknown,
            ];

            for status in statuses {
                let json = serde_json::to_string(&status).unwrap();
                let parsed: ConditionStatus = serde_json::from_str(&json).unwrap();
                assert_eq!(status, parsed);
            }
        }
    }

    mod serde_tests {
        use super::*;

        #[test]
        fn test_provider_spec_roundtrip() {
            let spec = ProviderSpec {
                type_: ProviderType::Docker,
                kubernetes: KubernetesSpec {
                    version: "1.29.0".to_string(),
                    cert_sans: Some(vec!["10.0.0.1".to_string()]),
                },
            };
            let json = serde_json::to_string(&spec).unwrap();
            let parsed: ProviderSpec = serde_json::from_str(&json).unwrap();
            assert_eq!(spec, parsed);
        }

        #[test]
        fn test_kubernetes_spec_without_cert_sans() {
            let spec = KubernetesSpec {
                version: "1.29.0".to_string(),
                cert_sans: None,
            };
            let json = serde_json::to_string(&spec).unwrap();
            assert!(!json.contains("certSANs"));
            let parsed: KubernetesSpec = serde_json::from_str(&json).unwrap();
            assert_eq!(spec, parsed);
        }

        #[test]
        fn test_networking_spec_default() {
            let spec = NetworkingSpec::default();
            assert!(spec.default.is_none());
        }

        #[test]
        fn test_network_pool_roundtrip() {
            let pool = NetworkPool {
                cidr: "10.0.0.0/24".to_string(),
            };
            let json = serde_json::to_string(&pool).unwrap();
            let parsed: NetworkPool = serde_json::from_str(&json).unwrap();
            assert_eq!(pool, parsed);
        }

        #[test]
        fn test_cell_spec_roundtrip() {
            let spec = CellSpec {
                host: "cell.example.com".to_string(),
                grpc_port: 50051,
                bootstrap_port: 8443,
                service: ServiceSpec {
                    type_: "LoadBalancer".to_string(),
                },
            };
            let json = serde_json::to_string(&spec).unwrap();
            let parsed: CellSpec = serde_json::from_str(&json).unwrap();
            assert_eq!(spec, parsed);
        }

        #[test]
        fn test_cell_spec_endpoints() {
            let spec = CellSpec {
                host: "172.18.255.1".to_string(),
                grpc_port: 50051,
                bootstrap_port: 8443,
                service: ServiceSpec {
                    type_: "LoadBalancer".to_string(),
                },
            };
            assert_eq!(spec.grpc_endpoint(), "https://172.18.255.1:50051");
            assert_eq!(spec.bootstrap_endpoint(), "https://172.18.255.1:8443");
        }

        #[test]
        fn test_cell_spec_default_ports() {
            // Ports should default when not specified in JSON
            let json = r#"{"host":"example.com","service":{"type":"LoadBalancer"}}"#;
            let spec: CellSpec = serde_json::from_str(json).unwrap();
            assert_eq!(spec.grpc_port, 50051);
            assert_eq!(spec.bootstrap_port, 8443);
        }

        #[test]
        fn test_workload_spec_default() {
            let spec = WorkloadSpec::default();
            assert!(spec.services.is_empty());
        }

        #[test]
        fn test_workload_spec_with_services() {
            let spec = WorkloadSpec {
                services: vec![
                    ServiceRef {
                        name: "nginx".to_string(),
                    },
                    ServiceRef {
                        name: "redis".to_string(),
                    },
                ],
            };
            let json = serde_json::to_string(&spec).unwrap();
            let parsed: WorkloadSpec = serde_json::from_str(&json).unwrap();
            assert_eq!(spec, parsed);
            assert_eq!(spec.services.len(), 2);
        }

        #[test]
        fn test_service_ref_roundtrip() {
            let service = ServiceRef {
                name: "my-service".to_string(),
            };
            let json = serde_json::to_string(&service).unwrap();
            let parsed: ServiceRef = serde_json::from_str(&json).unwrap();
            assert_eq!(service, parsed);
        }

        #[test]
        fn test_cluster_phase_serde() {
            let phases = vec![
                ClusterPhase::Pending,
                ClusterPhase::Provisioning,
                ClusterPhase::Pivoting,
                ClusterPhase::Ready,
                ClusterPhase::Failed,
            ];
            for phase in phases {
                let json = serde_json::to_string(&phase).unwrap();
                let parsed: ClusterPhase = serde_json::from_str(&json).unwrap();
                assert_eq!(phase, parsed);
            }
        }

        #[test]
        fn test_condition_status_serde() {
            let statuses = vec![
                ConditionStatus::True,
                ConditionStatus::False,
                ConditionStatus::Unknown,
            ];
            for status in statuses {
                let json = serde_json::to_string(&status).unwrap();
                let parsed: ConditionStatus = serde_json::from_str(&json).unwrap();
                assert_eq!(status, parsed);
            }
        }

        #[test]
        fn test_provider_type_default() {
            assert_eq!(ProviderType::default(), ProviderType::Docker);
        }
    }
}
