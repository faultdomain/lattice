//! Supporting types for LatticeCluster CRD

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Supported infrastructure provider types
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    /// Docker/Kind provider for local development
    #[default]
    Docker,
    /// Proxmox VE - on-premises virtualization
    Proxmox,
    /// OpenStack - private cloud
    OpenStack,
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
            "docker" | "proxmox" | "openstack" | "aws" | "gcp" | "azure"
        )
    }

    /// Returns true if this provider is for on-premises infrastructure
    pub fn is_on_prem(&self) -> bool {
        matches!(self, Self::Docker | Self::Proxmox | Self::OpenStack)
    }

    /// Returns true if this provider is for public cloud
    pub fn is_cloud(&self) -> bool {
        matches!(self, Self::Aws | Self::Gcp | Self::Azure)
    }
}

impl std::str::FromStr for ProviderType {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "docker" => Ok(Self::Docker),
            "proxmox" => Ok(Self::Proxmox),
            "openstack" => Ok(Self::OpenStack),
            "aws" => Ok(Self::Aws),
            "gcp" => Ok(Self::Gcp),
            "azure" => Ok(Self::Azure),
            _ => Err(crate::Error::validation(format!(
                "invalid provider type: {s}, expected one of: docker, proxmox, openstack, aws, gcp, azure"
            ))),
        }
    }
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Docker => write!(f, "docker"),
            Self::Proxmox => write!(f, "proxmox"),
            Self::OpenStack => write!(f, "openstack"),
            Self::Aws => write!(f, "aws"),
            Self::Gcp => write!(f, "gcp"),
            Self::Azure => write!(f, "azure"),
        }
    }
}

/// Bootstrap provider for cluster node initialization
///
/// Determines how nodes are bootstrapped during cluster provisioning.
/// - Kubeadm: Standard Kubernetes bootstrap (requires FIPS relaxation for non-FIPS clusters)
/// - Rke2: RKE2 bootstrap (FIPS-compliant out of the box)
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]

pub enum BootstrapProvider {
    /// Standard kubeadm bootstrap (default)
    /// Note: May require FIPS relaxation when communicating with non-FIPS clusters
    #[default]
    Kubeadm,
    /// RKE2 bootstrap (FIPS-compliant)
    Rke2,
}

impl BootstrapProvider {
    /// Returns true if this bootstrap provider is FIPS-compliant out of the box
    pub fn is_fips_native(&self) -> bool {
        matches!(self, Self::Rke2)
    }

    /// Returns true if this bootstrap provider may need FIPS relaxation
    /// when bootstrapping clusters to non-FIPS API servers
    pub fn needs_fips_relax(&self) -> bool {
        matches!(self, Self::Kubeadm)
    }
}

impl std::fmt::Display for BootstrapProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kubeadm => write!(f, "kubeadm"),
            Self::Rke2 => write!(f, "rke2"),
        }
    }
}

/// Infrastructure provider specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderSpec {
    /// Kubernetes configuration
    pub kubernetes: KubernetesSpec,

    /// Provider-specific configuration (determines provider type)
    pub config: ProviderConfig,
}

impl ProviderSpec {
    /// Get the provider type from the config
    pub fn provider_type(&self) -> ProviderType {
        self.config.provider_type()
    }
}

/// Provider-specific configuration
///
/// Exactly one provider must be specified. Uses `config.docker: {}` format.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderConfig {
    /// Docker/Kind for local development
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docker: Option<DockerConfig>,
    /// Proxmox VE on-premises virtualization
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox: Option<ProxmoxConfig>,
}

impl ProviderConfig {
    /// Create a Docker provider config
    pub fn docker() -> Self {
        Self {
            docker: Some(DockerConfig::default()),
            proxmox: None,
        }
    }

    /// Create a Proxmox provider config
    pub fn proxmox(config: ProxmoxConfig) -> Self {
        Self {
            docker: None,
            proxmox: Some(config),
        }
    }

    /// Get the provider type
    pub fn provider_type(&self) -> ProviderType {
        if self.docker.is_some() {
            ProviderType::Docker
        } else if self.proxmox.is_some() {
            ProviderType::Proxmox
        } else {
            // Default to Docker if nothing specified
            ProviderType::Docker
        }
    }

    /// Validate that exactly one provider is configured
    pub fn validate(&self) -> Result<(), crate::Error> {
        let count = [self.docker.is_some(), self.proxmox.is_some()]
            .iter()
            .filter(|&&x| x)
            .count();

        if count == 0 {
            return Err(crate::Error::validation(
                "provider config must specify exactly one provider (docker or proxmox)",
            ));
        }
        if count > 1 {
            return Err(crate::Error::validation(
                "provider config must specify exactly one provider, not multiple",
            ));
        }
        Ok(())
    }
}

/// Docker/Kind provider configuration
///
/// Docker provider uses sensible defaults and requires no configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DockerConfig {
    // No fields - Docker uses sensible defaults
}

/// Kubernetes version and configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct KubernetesSpec {
    /// Kubernetes version to deploy
    pub version: String,

    /// Additional Subject Alternative Names for the API server certificate
    #[serde(rename = "certSANs", default, skip_serializing_if = "Option::is_none")]
    pub cert_sans: Option<Vec<String>>,

    /// Bootstrap provider (kubeadm or rke2)
    /// Defaults to kubeadm for backwards compatibility
    #[serde(default, skip_serializing_if = "is_default_bootstrap")]
    pub bootstrap: BootstrapProvider,
}

fn is_default_bootstrap(b: &BootstrapProvider) -> bool {
    *b == BootstrapProvider::Kubeadm
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

/// Parent cluster configuration
///
/// When present, this cluster can have children (provision and manage other clusters).
/// Contains the endpoint configuration for child clusters to connect back.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct EndpointsSpec {
    /// Host address for child agent connections
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

impl EndpointsSpec {
    /// Get the combined parent endpoint in format "host:http_port:grpc_port"
    ///
    /// This format is used by bootstrap to pass all connection info in a single string.
    pub fn endpoint(&self) -> String {
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

// =============================================================================
// Provider-Specific Configuration
// =============================================================================

/// Proxmox VE provider configuration (CAPMOX)
///
/// Configuration for provisioning clusters on Proxmox Virtual Environment.
/// All fields are optional with sensible defaults.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxConfig {
    /// Proxmox node to clone VMs from
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_node: Option<String>,

    /// VM template ID to clone from
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<u32>,

    /// Storage backend (e.g., "local-lvm", "ceph")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,

    /// Network bridge (e.g., "vmbr0")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<String>,

    /// Allowed Proxmox nodes for VM placement
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_nodes: Option<Vec<String>>,

    /// DNS servers for cluster nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_servers: Option<Vec<String>>,

    /// IPv4 address pool for nodes (CIDR ranges)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4_addresses: Option<Vec<String>>,

    /// IPv4 network prefix length (default: 24)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4_prefix: Option<u8>,

    /// IPv4 gateway address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4_gateway: Option<String>,

    // Control plane VM sizing
    /// CPU sockets for control plane nodes (default: 1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_sockets: Option<u32>,

    /// CPU cores for control plane nodes (default: 4)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_cores: Option<u32>,

    /// Memory in MiB for control plane nodes (default: 8192)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_memory_mib: Option<u32>,

    /// Disk size in GB for control plane nodes (default: 50)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_disk_size_gb: Option<u32>,

    // Worker VM sizing
    /// CPU sockets for worker nodes (default: 1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_sockets: Option<u32>,

    /// CPU cores for worker nodes (default: 4)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_cores: Option<u32>,

    /// Memory in MiB for worker nodes (default: 8192)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_memory_mib: Option<u32>,

    /// Disk size in GB for worker nodes (default: 100)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_disk_size_gb: Option<u32>,
}

/// Cluster lifecycle phase
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]

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
                kubernetes: KubernetesSpec {
                    version: "1.29.0".to_string(),
                    cert_sans: Some(vec!["10.0.0.1".to_string()]),
                    bootstrap: BootstrapProvider::default(),
                },
                config: ProviderConfig::docker(),
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
                bootstrap: BootstrapProvider::default(),
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
            let spec = EndpointsSpec {
                host: "cell.example.com".to_string(),
                grpc_port: 50051,
                bootstrap_port: 8443,
                service: ServiceSpec {
                    type_: "LoadBalancer".to_string(),
                },
            };
            let json = serde_json::to_string(&spec).unwrap();
            let parsed: EndpointsSpec = serde_json::from_str(&json).unwrap();
            assert_eq!(spec, parsed);
        }

        #[test]
        fn test_cell_spec_endpoints() {
            let spec = EndpointsSpec {
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
            let spec: EndpointsSpec = serde_json::from_str(json).unwrap();
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

        #[test]
        fn test_bootstrap_provider_default() {
            assert_eq!(BootstrapProvider::default(), BootstrapProvider::Kubeadm);
        }

        #[test]
        fn test_bootstrap_provider_serde() {
            let providers = vec![BootstrapProvider::Kubeadm, BootstrapProvider::Rke2];
            for provider in providers {
                let json = serde_json::to_string(&provider).unwrap();
                let parsed: BootstrapProvider = serde_json::from_str(&json).unwrap();
                assert_eq!(provider, parsed);
            }
        }

        #[test]
        fn test_bootstrap_provider_display() {
            assert_eq!(BootstrapProvider::Kubeadm.to_string(), "kubeadm");
            assert_eq!(BootstrapProvider::Rke2.to_string(), "rke2");
        }

        #[test]
        fn test_bootstrap_provider_fips_native() {
            assert!(!BootstrapProvider::Kubeadm.is_fips_native());
            assert!(BootstrapProvider::Rke2.is_fips_native());
        }

        #[test]
        fn test_bootstrap_provider_needs_fips_relax() {
            assert!(BootstrapProvider::Kubeadm.needs_fips_relax());
            assert!(!BootstrapProvider::Rke2.needs_fips_relax());
        }

        #[test]
        fn test_kubernetes_spec_with_bootstrap_provider() {
            let spec = KubernetesSpec {
                version: "1.35.0".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Rke2,
            };
            let json = serde_json::to_string(&spec).unwrap();
            assert!(json.contains("rke2")); // RKE2 should be serialized
            let parsed: KubernetesSpec = serde_json::from_str(&json).unwrap();
            assert_eq!(spec.bootstrap, parsed.bootstrap);
        }

        #[test]
        fn test_kubernetes_spec_default_bootstrap_not_serialized() {
            let spec = KubernetesSpec {
                version: "1.35.0".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::Kubeadm, // Default
            };
            let json = serde_json::to_string(&spec).unwrap();
            // Default should not be serialized (skip_serializing_if)
            assert!(!json.contains("bootstrap"));
        }
    }
}
