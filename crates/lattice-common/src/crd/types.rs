//! Supporting types for LatticeCluster CRD

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// Re-export provider configs from the providers module
pub use super::providers::{
    AwsConfig, DockerConfig, Ipv4PoolConfig, Ipv6PoolConfig, OpenStackConfig, ProxmoxConfig,
};

// =============================================================================
// Provider Types
// =============================================================================

/// Supported infrastructure provider types
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
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
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BootstrapProvider {
    /// Standard kubeadm bootstrap (default)
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

// =============================================================================
// Provider Specification
// =============================================================================

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
    /// AWS public cloud
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws: Option<AwsConfig>,
    /// Docker/Kind for local development
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docker: Option<DockerConfig>,
    /// OpenStack private/public cloud
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openstack: Option<OpenStackConfig>,
    /// Proxmox VE on-premises virtualization
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox: Option<ProxmoxConfig>,
}

impl ProviderConfig {
    /// Create an AWS provider config
    pub fn aws(config: AwsConfig) -> Self {
        Self {
            aws: Some(config),
            docker: None,
            openstack: None,
            proxmox: None,
        }
    }

    /// Create a Docker provider config
    pub fn docker() -> Self {
        Self {
            aws: None,
            docker: Some(DockerConfig::default()),
            openstack: None,
            proxmox: None,
        }
    }

    /// Create an OpenStack provider config
    pub fn openstack(config: OpenStackConfig) -> Self {
        Self {
            aws: None,
            docker: None,
            openstack: Some(config),
            proxmox: None,
        }
    }

    /// Create a Proxmox provider config
    pub fn proxmox(config: ProxmoxConfig) -> Self {
        Self {
            aws: None,
            docker: None,
            openstack: None,
            proxmox: Some(config),
        }
    }

    /// Get the provider type
    pub fn provider_type(&self) -> ProviderType {
        if self.aws.is_some() {
            ProviderType::Aws
        } else if self.docker.is_some() {
            ProviderType::Docker
        } else if self.openstack.is_some() {
            ProviderType::OpenStack
        } else if self.proxmox.is_some() {
            ProviderType::Proxmox
        } else {
            ProviderType::Docker
        }
    }

    /// Validate that exactly one provider is configured
    pub fn validate(&self) -> Result<(), crate::Error> {
        let count = [
            self.aws.is_some(),
            self.docker.is_some(),
            self.openstack.is_some(),
            self.proxmox.is_some(),
        ]
        .iter()
        .filter(|&&x| x)
        .count();

        if count == 0 {
            return Err(crate::Error::validation(
                "provider config must specify exactly one provider (aws, docker, openstack, or proxmox)",
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

// =============================================================================
// Kubernetes Configuration
// =============================================================================

/// Kubernetes version and configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct KubernetesSpec {
    /// Kubernetes version to deploy
    pub version: String,

    /// Additional Subject Alternative Names for the API server certificate
    #[serde(rename = "certSANs", default, skip_serializing_if = "Option::is_none")]
    pub cert_sans: Option<Vec<String>>,

    /// Bootstrap provider (kubeadm or rke2)
    #[serde(default, skip_serializing_if = "is_default_bootstrap")]
    pub bootstrap: BootstrapProvider,
}

fn is_default_bootstrap(b: &BootstrapProvider) -> bool {
    *b == BootstrapProvider::Kubeadm
}

// =============================================================================
// Node Configuration
// =============================================================================

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
        if self.control_plane > 1 && self.control_plane.is_multiple_of(2) {
            return Err(crate::Error::validation(
                "control plane count must be odd for HA (1, 3, 5, ...)",
            ));
        }
        Ok(())
    }
}

// =============================================================================
// Network Configuration
// =============================================================================

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

// =============================================================================
// Secret Reference
// =============================================================================

/// Reference to a Kubernetes Secret
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretRef {
    /// Name of the Secret
    pub name: String,
    /// Namespace of the Secret (default: "lattice-system")
    #[serde(default = "default_lattice_namespace")]
    pub namespace: String,
}

fn default_lattice_namespace() -> String {
    "lattice-system".to_string()
}

// =============================================================================
// Endpoints Configuration
// =============================================================================

/// Parent cluster endpoint configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EndpointsSpec {
    /// Host address for child agent connections.
    /// Optional for cloud providers with LBs - will be auto-discovered from LB status.
    /// Required for on-premises providers (Proxmox, Docker).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// gRPC port for agent connections (default: 50051)
    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,

    /// Bootstrap HTTPS port for kubeadm webhook (default: 443)
    #[serde(default = "default_bootstrap_port")]
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
    /// Returns None if host is not set (pending auto-discovery from cloud LB)
    pub fn endpoint(&self) -> Option<String> {
        self.host
            .as_ref()
            .map(|h| format!("{}:{}:{}", h, self.bootstrap_port, self.grpc_port))
    }

    /// Get the gRPC endpoint URL for agent connections
    /// Returns None if host is not set
    pub fn grpc_endpoint(&self) -> Option<String> {
        self.host
            .as_ref()
            .map(|h| format!("https://{}:{}", h, self.grpc_port))
    }

    /// Get the bootstrap endpoint URL for kubeadm webhook
    /// Returns None if host is not set
    pub fn bootstrap_endpoint(&self) -> Option<String> {
        self.host
            .as_ref()
            .map(|h| format!("https://{}:{}", h, self.bootstrap_port))
    }
}

/// Service exposure specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ServiceSpec {
    /// Service type (LoadBalancer, NodePort, ClusterIP)
    #[serde(rename = "type")]
    pub type_: String,
}

// =============================================================================
// Workload Configuration
// =============================================================================

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
// Cluster Status Types
// =============================================================================

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
    /// Cluster is being deleted and unpivoting CAPI resources to parent
    Unpivoting,
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
            Self::Unpivoting => write!(f, "Unpivoting"),
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

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    mod provider_type {
        use super::*;

        #[test]
        fn test_from_str_valid() {
            assert_eq!(
                "docker"
                    .parse::<ProviderType>()
                    .expect("docker should be a valid provider type"),
                ProviderType::Docker
            );
            assert_eq!(
                "aws"
                    .parse::<ProviderType>()
                    .expect("aws should be a valid provider type"),
                ProviderType::Aws
            );
            assert_eq!(
                "gcp"
                    .parse::<ProviderType>()
                    .expect("gcp should be a valid provider type"),
                ProviderType::Gcp
            );
            assert_eq!(
                "azure"
                    .parse::<ProviderType>()
                    .expect("azure should be a valid provider type"),
                ProviderType::Azure
            );
        }

        #[test]
        fn test_from_str_case_insensitive() {
            assert_eq!(
                "DOCKER"
                    .parse::<ProviderType>()
                    .expect("DOCKER should be a valid provider type"),
                ProviderType::Docker
            );
            assert_eq!(
                "Docker"
                    .parse::<ProviderType>()
                    .expect("Docker should be a valid provider type"),
                ProviderType::Docker
            );
            assert_eq!(
                "AWS"
                    .parse::<ProviderType>()
                    .expect("AWS should be a valid provider type"),
                ProviderType::Aws
            );
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

    mod cluster_phase {
        use super::*;

        #[test]
        fn test_default_is_pending() {
            assert_eq!(ClusterPhase::default(), ClusterPhase::Pending);
        }

        #[test]
        fn test_display() {
            assert_eq!(ClusterPhase::Pending.to_string(), "Pending");
            assert_eq!(ClusterPhase::Provisioning.to_string(), "Provisioning");
            assert_eq!(ClusterPhase::Pivoting.to_string(), "Pivoting");
            assert_eq!(ClusterPhase::Ready.to_string(), "Ready");
            assert_eq!(ClusterPhase::Failed.to_string(), "Failed");
        }

        #[test]
        fn test_serde_roundtrip() {
            let phases = [
                ClusterPhase::Pending,
                ClusterPhase::Provisioning,
                ClusterPhase::Pivoting,
                ClusterPhase::Ready,
                ClusterPhase::Failed,
            ];
            for phase in phases {
                let json = serde_json::to_string(&phase)
                    .expect("ClusterPhase serialization should succeed");
                let parsed: ClusterPhase = serde_json::from_str(&json)
                    .expect("ClusterPhase deserialization should succeed");
                assert_eq!(phase, parsed);
            }
        }
    }

    mod condition {
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

        #[test]
        fn test_condition_status_display() {
            assert_eq!(ConditionStatus::True.to_string(), "True");
            assert_eq!(ConditionStatus::False.to_string(), "False");
            assert_eq!(ConditionStatus::Unknown.to_string(), "Unknown");
        }

        #[test]
        fn test_default_status_is_unknown() {
            assert_eq!(ConditionStatus::default(), ConditionStatus::Unknown);
        }
    }

    mod bootstrap_provider {
        use super::*;

        #[test]
        fn test_default_is_kubeadm() {
            assert_eq!(BootstrapProvider::default(), BootstrapProvider::Kubeadm);
        }

        #[test]
        fn test_display() {
            assert_eq!(BootstrapProvider::Kubeadm.to_string(), "kubeadm");
            assert_eq!(BootstrapProvider::Rke2.to_string(), "rke2");
        }

        #[test]
        fn test_fips_native() {
            assert!(!BootstrapProvider::Kubeadm.is_fips_native());
            assert!(BootstrapProvider::Rke2.is_fips_native());
        }

        #[test]
        fn test_needs_fips_relax() {
            assert!(BootstrapProvider::Kubeadm.needs_fips_relax());
            assert!(!BootstrapProvider::Rke2.needs_fips_relax());
        }

        #[test]
        fn test_serde_roundtrip() {
            let providers = [BootstrapProvider::Kubeadm, BootstrapProvider::Rke2];
            for provider in providers {
                let json = serde_json::to_string(&provider)
                    .expect("BootstrapProvider serialization should succeed");
                let parsed: BootstrapProvider = serde_json::from_str(&json)
                    .expect("BootstrapProvider deserialization should succeed");
                assert_eq!(provider, parsed);
            }
        }
    }

    mod provider_config {
        use super::*;

        #[test]
        fn test_docker_config() {
            let config = ProviderConfig::docker();
            assert!(config.docker.is_some());
            assert_eq!(config.provider_type(), ProviderType::Docker);
            assert!(config.validate().is_ok());
        }

        #[test]
        fn test_proxmox_config() {
            let proxmox = ProxmoxConfig {
                control_plane_endpoint: "10.0.0.100".to_string(),
                ipv4_pool: Ipv4PoolConfig {
                    range: "10.0.0.101-120/24".to_string(),
                    gateway: "10.0.0.1".to_string(),
                },
                cp_cores: 4,
                cp_memory_mib: 8192,
                cp_disk_size_gb: 50,
                worker_cores: 4,
                worker_memory_mib: 8192,
                worker_disk_size_gb: 100,
                source_node: None,
                template_id: None,
                template_tags: None,
                snap_name: None,
                target_node: None,
                pool: None,
                description: None,
                tags: None,
                allowed_nodes: None,
                dns_servers: None,
                ssh_authorized_keys: None,
                virtual_ip_network_interface: None,
                kube_vip_image: None,
                secret_ref: None,
                ipv6_pool: None,
                bridge: None,
                vlan: None,
                network_model: None,
                memory_adjustment: None,
                vmid_min: None,
                vmid_max: None,
                skip_cloud_init_status: None,
                skip_qemu_guest_agent: None,
                cp_sockets: None,
                worker_sockets: None,
            };
            let config = ProviderConfig::proxmox(proxmox);
            assert!(config.proxmox.is_some());
            assert_eq!(config.provider_type(), ProviderType::Proxmox);
            assert!(config.validate().is_ok());
        }

        #[test]
        fn test_aws_config() {
            let aws = AwsConfig {
                region: "us-west-2".to_string(),
                cp_instance_type: "m5.xlarge".to_string(),
                worker_instance_type: "m5.large".to_string(),
                ssh_key_name: "lattice-key".to_string(),
                ..Default::default()
            };
            let config = ProviderConfig::aws(aws);
            assert!(config.aws.is_some());
            assert_eq!(config.provider_type(), ProviderType::Aws);
            assert!(config.validate().is_ok());
        }

        #[test]
        fn test_openstack_config() {
            let openstack = OpenStackConfig {
                external_network_id: "ext-net".to_string(),
                cp_flavor: "m1.large".to_string(),
                worker_flavor: "m1.medium".to_string(),
                image_name: "Ubuntu 22.04".to_string(),
                ssh_key_name: "lattice-key".to_string(),
                ..Default::default()
            };
            let config = ProviderConfig::openstack(openstack);
            assert!(config.openstack.is_some());
            assert_eq!(config.provider_type(), ProviderType::OpenStack);
            assert!(config.validate().is_ok());
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
            let json =
                serde_json::to_string(&spec).expect("ProviderSpec serialization should succeed");
            let parsed: ProviderSpec =
                serde_json::from_str(&json).expect("ProviderSpec deserialization should succeed");
            assert_eq!(spec, parsed);
        }

        #[test]
        fn test_kubernetes_spec_without_cert_sans() {
            let spec = KubernetesSpec {
                version: "1.29.0".to_string(),
                cert_sans: None,
                bootstrap: BootstrapProvider::default(),
            };
            let json =
                serde_json::to_string(&spec).expect("KubernetesSpec serialization should succeed");
            assert!(!json.contains("certSANs"));
            let parsed: KubernetesSpec =
                serde_json::from_str(&json).expect("KubernetesSpec deserialization should succeed");
            assert_eq!(spec, parsed);
        }

        #[test]
        fn test_endpoints_spec_default_ports() {
            let json = r#"{"host":"example.com","service":{"type":"LoadBalancer"}}"#;
            let spec: EndpointsSpec =
                serde_json::from_str(json).expect("EndpointsSpec deserialization should succeed");
            assert_eq!(spec.grpc_port, 50051);
            assert_eq!(spec.bootstrap_port, 8443);
        }

        #[test]
        fn test_endpoints_spec_urls() {
            let spec = EndpointsSpec {
                host: Some("172.18.255.1".to_string()),
                grpc_port: 50051,
                bootstrap_port: 8443,
                service: ServiceSpec {
                    type_: "LoadBalancer".to_string(),
                },
            };
            assert_eq!(
                spec.grpc_endpoint(),
                Some("https://172.18.255.1:50051".to_string())
            );
            assert_eq!(
                spec.bootstrap_endpoint(),
                Some("https://172.18.255.1:8443".to_string())
            );
            assert_eq!(spec.endpoint(), Some("172.18.255.1:8443:50051".to_string()));
        }

        #[test]
        fn test_endpoints_spec_no_host() {
            let spec = EndpointsSpec {
                host: None,
                grpc_port: 50051,
                bootstrap_port: 8443,
                service: ServiceSpec {
                    type_: "LoadBalancer".to_string(),
                },
            };
            assert_eq!(spec.grpc_endpoint(), None);
            assert_eq!(spec.bootstrap_endpoint(), None);
            assert_eq!(spec.endpoint(), None);
        }
    }
}
