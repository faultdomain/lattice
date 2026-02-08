//! Supporting types for LatticeCluster CRD

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::LATTICE_SYSTEM_NAMESPACE;

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
    /// Returns true if this provider is for on-premises infrastructure
    pub fn is_on_prem(&self) -> bool {
        matches!(self, Self::Docker | Self::Proxmox | Self::OpenStack)
    }

    /// Returns true if this provider is for public cloud
    pub fn is_cloud(&self) -> bool {
        matches!(self, Self::Aws | Self::Gcp | Self::Azure)
    }

    /// Returns LoadBalancer Service annotations for this provider
    pub fn load_balancer_annotations(&self) -> std::collections::BTreeMap<String, String> {
        let mut annotations = std::collections::BTreeMap::new();
        match self {
            Self::Aws => {
                // NLB works reliably with CAPA security groups (Classic ELB doesn't)
                annotations.insert(
                    "service.beta.kubernetes.io/aws-load-balancer-type".to_string(),
                    "nlb".to_string(),
                );
                // Enable cross-zone load balancing so all NLB IPs route to the single pod
                // Without this, only the NLB IP in the pod's AZ works
                annotations.insert(
                    "service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled".to_string(),
                    "true".to_string(),
                );
            }
            Self::Gcp => {
                // GCP uses regional external LB by default, no special annotations needed
            }
            Self::Azure => {
                // Azure uses Standard LB by default, no special annotations needed
            }
            Self::Docker | Self::Proxmox | Self::OpenStack => {
                // On-prem uses Cilium L2 announcements, no cloud LB annotations
            }
        }
        annotations
    }

    /// Returns the Kubernetes topology key for pod spread constraints.
    ///
    /// Cloud providers automatically set `topology.kubernetes.io/zone` on nodes.
    /// On-prem providers (Docker, Proxmox) don't have zones, so we spread by hostname.
    /// OpenStack supports availability zones like cloud providers.
    pub fn topology_spread_key(&self) -> &'static str {
        match self {
            Self::Docker | Self::Proxmox => "kubernetes.io/hostname",
            Self::Aws | Self::Gcp | Self::Azure | Self::OpenStack => "topology.kubernetes.io/zone",
        }
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

    /// Reference to a Secret containing provider credentials
    ///
    /// The secret must have the label `lattice.dev/credential-type: provider`
    /// and contain the appropriate credential fields for the provider type.
    /// This allows multiple credential sets for the same provider (e.g., multiple AWS accounts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_secret_ref: Option<SecretRef>,
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

/// Taint effect for node taints
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum TaintEffect {
    /// Do not schedule new pods on this node
    NoSchedule,
    /// Prefer not to schedule new pods on this node
    PreferNoSchedule,
    /// Evict existing pods and do not schedule new ones
    NoExecute,
}

impl std::fmt::Display for TaintEffect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSchedule => write!(f, "NoSchedule"),
            Self::PreferNoSchedule => write!(f, "PreferNoSchedule"),
            Self::NoExecute => write!(f, "NoExecute"),
        }
    }
}

/// Node taint specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct NodeTaint {
    /// Taint key
    pub key: String,

    /// Taint value (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,

    /// Taint effect
    pub effect: TaintEffect,
}

// =============================================================================
// Instance Type / Sizing Configuration
// =============================================================================

/// Explicit resource specification for providers without named instance types (e.g., Proxmox)
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NodeResourceSpec {
    /// Number of CPU cores
    pub cores: u32,

    /// Memory in GiB
    pub memory_gib: u32,

    /// Disk size in GiB
    pub disk_gib: u32,

    /// Number of CPU sockets (default: 1)
    #[serde(
        default = "default_sockets",
        skip_serializing_if = "is_default_sockets"
    )]
    pub sockets: u32,
}

fn default_sockets() -> u32 {
    1
}

fn is_default_sockets(v: &u32) -> bool {
    *v == 1
}

/// Instance type specification — either a named type (AWS/OpenStack) or explicit resources (Proxmox)
///
/// YAML examples:
/// - `instanceType: { name: m5.xlarge }` → named cloud instance
/// - `instanceType: { cores: 16, memoryGib: 32, diskGib: 50 }` → explicit resources
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InstanceType {
    /// Named instance type (e.g., "m5.xlarge", "b2-30") for cloud providers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Number of CPU cores (for explicit resource specification, e.g. Proxmox)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cores: Option<u32>,

    /// Memory in GiB
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_gib: Option<u32>,

    /// Disk size in GiB
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_gib: Option<u32>,

    /// Number of CPU sockets (default: 1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sockets: Option<u32>,
}

impl InstanceType {
    /// Create a named instance type (e.g., "m5.xlarge")
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..Default::default()
        }
    }

    /// Create an explicit resource specification
    pub fn resources(spec: NodeResourceSpec) -> Self {
        Self {
            cores: Some(spec.cores),
            memory_gib: Some(spec.memory_gib),
            disk_gib: Some(spec.disk_gib),
            sockets: Some(spec.sockets),
            ..Default::default()
        }
    }

    /// Get the named instance type string
    pub fn as_named(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the resource specification, if resource fields are set
    pub fn as_resources(&self) -> Option<NodeResourceSpec> {
        match (self.cores, self.memory_gib, self.disk_gib) {
            (Some(cores), Some(memory_gib), Some(disk_gib)) => Some(NodeResourceSpec {
                cores,
                memory_gib,
                disk_gib,
                sockets: self.sockets.unwrap_or(1),
            }),
            _ => None,
        }
    }
}

/// Root volume configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RootVolume {
    /// Volume size in GB
    pub size_gb: u32,

    /// Volume type (provider-interpreted, e.g., "gp3", "io1", "high-speed")
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// Control plane specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ControlPlaneSpec {
    /// Number of control plane nodes (must be positive odd number for HA)
    pub replicas: u32,

    /// Instance type for control plane nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_type: Option<InstanceType>,

    /// Root volume configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_volume: Option<RootVolume>,
}

/// Worker pool specification for named worker pools
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkerPoolSpec {
    /// Human-readable display name for the pool
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Number of worker nodes in this pool (ignored when autoscaling is enabled)
    pub replicas: u32,

    /// Instance type for nodes in this pool
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_type: Option<InstanceType>,

    /// Root volume configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_volume: Option<RootVolume>,

    /// Labels to apply to nodes in this pool
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub labels: std::collections::BTreeMap<String, String>,

    /// Taints to apply to nodes in this pool
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taints: Vec<NodeTaint>,

    /// Minimum number of nodes for cluster autoscaler.
    /// When both min and max are set, the cluster autoscaler manages this pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u32>,

    /// Maximum number of nodes for cluster autoscaler.
    /// When both min and max are set, the cluster autoscaler manages this pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,
}

impl WorkerPoolSpec {
    /// Returns true if autoscaling is enabled for this pool (both min and max are set)
    pub fn is_autoscaling_enabled(&self) -> bool {
        self.min.is_some() && self.max.is_some()
    }

    /// Validate autoscaling configuration
    pub fn validate(&self) -> Result<(), String> {
        match (self.min, self.max) {
            (Some(min), Some(max)) => {
                if min > max {
                    return Err(format!("min ({}) cannot exceed max ({})", min, max));
                }
                if min == 0 {
                    return Err("scale-from-zero not supported (min must be >= 1)".into());
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err("min and max must both be set or both unset".into());
            }
            (None, None) => {}
        }
        Ok(())
    }
}

/// Node topology specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NodeSpec {
    /// Control plane configuration (replicas, instance type, root volume)
    #[serde(rename = "controlPlane")]
    pub control_plane: ControlPlaneSpec,

    /// Named worker pools with independent scaling
    ///
    /// Keys are pool identifiers (e.g., "general", "gpu", "high-memory").
    /// Each pool can have different sizes, labels, and taints.
    #[serde(default)]
    pub worker_pools: std::collections::BTreeMap<String, WorkerPoolSpec>,
}

impl NodeSpec {
    /// Returns the total number of worker nodes across all pools
    pub fn total_workers(&self) -> u32 {
        self.worker_pools.values().map(|p| p.replicas).sum()
    }

    /// Returns the total number of nodes (control plane + all workers)
    pub fn total_nodes(&self) -> u32 {
        self.control_plane.replicas + self.total_workers()
    }

    /// Validates the node specification
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.control_plane.replicas == 0 {
            return Err(crate::Error::validation(
                "control plane count must be at least 1",
            ));
        }
        if self.control_plane.replicas > 1 && self.control_plane.replicas.is_multiple_of(2) {
            return Err(crate::Error::validation(
                "control plane count must be odd for HA (1, 3, 5, ...)",
            ));
        }

        // Validate pool identifiers and autoscaling config
        for (pool_id, pool_spec) in &self.worker_pools {
            if !is_valid_pool_id(pool_id) {
                return Err(crate::Error::validation(format!(
                    "invalid worker pool id '{}': must be lowercase alphanumeric with hyphens, starting with a letter",
                    pool_id
                )));
            }
            if let Err(e) = pool_spec.validate() {
                return Err(crate::Error::validation(format!(
                    "worker pool '{}': {}",
                    pool_id, e
                )));
            }
        }

        Ok(())
    }
}

/// Check if a pool ID is valid (lowercase alphanumeric + hyphens, starts with letter)
fn is_valid_pool_id(id: &str) -> bool {
    super::validate_dns_identifier(id, false).is_ok()
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
    /// Namespace of the Secret (default: LATTICE_SYSTEM_NAMESPACE)
    #[serde(default = "default_lattice_namespace")]
    pub namespace: String,
}

fn default_lattice_namespace() -> String {
    LATTICE_SYSTEM_NAMESPACE.to_string()
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

    /// Bootstrap HTTPS port for kubeadm webhook (default: 8443)
    #[serde(default = "default_bootstrap_port")]
    pub bootstrap_port: u16,

    /// K8s API proxy port for CAPI controller access to children (default: 8081)
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,

    /// Service exposure configuration
    pub service: ServiceSpec,
}

fn default_grpc_port() -> u16 {
    crate::DEFAULT_GRPC_PORT
}

fn default_bootstrap_port() -> u16 {
    crate::DEFAULT_BOOTSTRAP_PORT
}

fn default_proxy_port() -> u16 {
    crate::DEFAULT_PROXY_PORT
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

    /// Get the K8s API proxy endpoint URL for CAPI controller access
    /// Returns None if host is not set
    pub fn proxy_endpoint(&self) -> Option<String> {
        self.host
            .as_ref()
            .map(|h| format!("https://{}:{}", h, self.proxy_port))
    }

    /// Get the authenticated proxy endpoint URL for user/service access (Cedar-authorized)
    /// Returns None if host is not set
    pub fn auth_proxy_endpoint(&self) -> Option<String> {
        self.host
            .as_ref()
            .map(|h| format!("https://{}:{}", h, crate::DEFAULT_AUTH_PROXY_PORT))
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
// Service Reference
// =============================================================================

/// Reference to a service with optional namespace qualification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct ServiceRef {
    /// Name of the service
    pub name: String,
    /// Namespace of the service (defaults to same namespace if omitted)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

impl ServiceRef {
    /// Create a new ServiceRef with explicit namespace
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            namespace: Some(namespace.into()),
            name: name.into(),
        }
    }

    /// Create a ServiceRef that inherits namespace from context
    pub fn local(name: impl Into<String>) -> Self {
        Self {
            namespace: None,
            name: name.into(),
        }
    }

    /// Resolve the namespace, using the provided default if not specified
    pub fn resolve_namespace<'a>(&'a self, default_namespace: &'a str) -> &'a str {
        self.namespace.as_deref().unwrap_or(default_namespace)
    }
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
    /// Pivot complete - cluster is self-managing (parent's view of child cluster)
    Pivoted,
    /// Cluster is fully operational and self-managing
    Ready,
    /// Cluster is being deleted (infrastructure teardown in progress)
    Deleting,
    /// Cluster is being deleted and unpivoting CAPI resources to parent (self cluster only)
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
            Self::Pivoted => write!(f, "Pivoted"),
            Self::Ready => write!(f, "Ready"),
            Self::Deleting => write!(f, "Deleting"),
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
        fn test_topology_spread_key() {
            // On-prem providers use hostname (no zones)
            assert_eq!(
                ProviderType::Docker.topology_spread_key(),
                "kubernetes.io/hostname"
            );
            assert_eq!(
                ProviderType::Proxmox.topology_spread_key(),
                "kubernetes.io/hostname"
            );

            // Cloud providers use zones
            assert_eq!(
                ProviderType::Aws.topology_spread_key(),
                "topology.kubernetes.io/zone"
            );
            assert_eq!(
                ProviderType::Gcp.topology_spread_key(),
                "topology.kubernetes.io/zone"
            );
            assert_eq!(
                ProviderType::Azure.topology_spread_key(),
                "topology.kubernetes.io/zone"
            );
            assert_eq!(
                ProviderType::OpenStack.topology_spread_key(),
                "topology.kubernetes.io/zone"
            );
        }

        #[test]
        fn test_is_on_prem() {
            // On-prem providers
            assert!(ProviderType::Docker.is_on_prem());
            assert!(ProviderType::Proxmox.is_on_prem());
            assert!(ProviderType::OpenStack.is_on_prem());

            // Cloud providers are NOT on-prem
            assert!(!ProviderType::Aws.is_on_prem());
            assert!(!ProviderType::Gcp.is_on_prem());
            assert!(!ProviderType::Azure.is_on_prem());
        }

        #[test]
        fn test_is_cloud() {
            // Cloud providers
            assert!(ProviderType::Aws.is_cloud());
            assert!(ProviderType::Gcp.is_cloud());
            assert!(ProviderType::Azure.is_cloud());

            // On-prem providers are NOT cloud
            assert!(!ProviderType::Docker.is_cloud());
            assert!(!ProviderType::Proxmox.is_cloud());
            assert!(!ProviderType::OpenStack.is_cloud());
        }

        #[test]
        fn test_load_balancer_annotations_aws() {
            let annotations = ProviderType::Aws.load_balancer_annotations();
            assert_eq!(annotations.len(), 2);
            assert_eq!(
                annotations.get("service.beta.kubernetes.io/aws-load-balancer-type"),
                Some(&"nlb".to_string())
            );
            // Cross-zone LB ensures all NLB IPs route to single pod
            assert_eq!(
                annotations.get("service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled"),
                Some(&"true".to_string())
            );
        }

        #[test]
        fn test_load_balancer_annotations_gcp_azure() {
            // GCP and Azure don't need special annotations
            assert!(ProviderType::Gcp.load_balancer_annotations().is_empty());
            assert!(ProviderType::Azure.load_balancer_annotations().is_empty());
        }

        #[test]
        fn test_load_balancer_annotations_on_prem() {
            // On-prem providers use Cilium L2, no cloud LB annotations
            assert!(ProviderType::Docker.load_balancer_annotations().is_empty());
            assert!(ProviderType::Proxmox.load_balancer_annotations().is_empty());
            assert!(ProviderType::OpenStack
                .load_balancer_annotations()
                .is_empty());
        }
    }

    mod node_spec {
        use super::*;

        fn cp(replicas: u32) -> ControlPlaneSpec {
            ControlPlaneSpec {
                replicas,
                instance_type: None,
                root_volume: None,
            }
        }

        fn pool(replicas: u32) -> WorkerPoolSpec {
            WorkerPoolSpec {
                replicas,
                ..Default::default()
            }
        }

        #[test]
        fn test_total_nodes_single_pool() {
            let spec = NodeSpec {
                control_plane: cp(1),
                worker_pools: std::collections::BTreeMap::from([("default".to_string(), pool(2))]),
            };
            assert_eq!(spec.total_workers(), 2);
            assert_eq!(spec.total_nodes(), 3);
        }

        #[test]
        fn test_total_nodes_multiple_pools() {
            let spec = NodeSpec {
                control_plane: cp(1),
                worker_pools: std::collections::BTreeMap::from([
                    ("general".to_string(), pool(3)),
                    ("gpu".to_string(), pool(2)),
                ]),
            };
            assert_eq!(spec.total_workers(), 5);
            assert_eq!(spec.total_nodes(), 6);
        }

        #[test]
        fn test_total_nodes_no_pools() {
            let spec = NodeSpec {
                control_plane: cp(3),
                worker_pools: std::collections::BTreeMap::new(),
            };
            assert_eq!(spec.total_workers(), 0);
            assert_eq!(spec.total_nodes(), 3);
        }

        #[test]
        fn test_validate_single_control_plane() {
            let spec = NodeSpec {
                control_plane: cp(1),
                worker_pools: std::collections::BTreeMap::new(),
            };
            assert!(spec.validate().is_ok());
        }

        #[test]
        fn test_validate_ha_control_plane() {
            let spec = NodeSpec {
                control_plane: cp(3),
                worker_pools: std::collections::BTreeMap::from([("default".to_string(), pool(2))]),
            };
            assert!(spec.validate().is_ok());

            let spec = NodeSpec {
                control_plane: cp(5),
                worker_pools: std::collections::BTreeMap::from([("default".to_string(), pool(2))]),
            };
            assert!(spec.validate().is_ok());
        }

        #[test]
        fn test_validate_zero_control_plane_fails() {
            let spec = NodeSpec {
                control_plane: cp(0),
                worker_pools: std::collections::BTreeMap::from([("default".to_string(), pool(2))]),
            };
            let result = spec.validate();
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("at least 1"));
        }

        #[test]
        fn test_validate_even_control_plane_fails() {
            let spec = NodeSpec {
                control_plane: cp(2),
                worker_pools: std::collections::BTreeMap::from([("default".to_string(), pool(2))]),
            };
            let result = spec.validate();
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("odd"));
        }

        #[test]
        fn test_validate_pool_id_valid() {
            let spec = NodeSpec {
                control_plane: cp(1),
                worker_pools: std::collections::BTreeMap::from([
                    ("general-purpose-pool".to_string(), pool(2)),
                    ("gpu2".to_string(), pool(1)),
                ]),
            };
            assert!(spec.validate().is_ok());
        }

        #[test]
        fn test_validate_pool_id_invalid_uppercase() {
            let spec = NodeSpec {
                control_plane: cp(1),
                worker_pools: std::collections::BTreeMap::from([("GPU".to_string(), pool(2))]),
            };
            let result = spec.validate();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("invalid worker pool id"));
        }

        #[test]
        fn test_validate_pool_id_invalid_starts_with_number() {
            let spec = NodeSpec {
                control_plane: cp(1),
                worker_pools: std::collections::BTreeMap::from([("2gpu".to_string(), pool(2))]),
            };
            let result = spec.validate();
            assert!(result.is_err());
        }

        #[test]
        fn test_instance_type_named_serde() {
            let it = InstanceType::named("m5.xlarge");
            let json = serde_json::to_string(&it).unwrap();
            let parsed: InstanceType = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.as_named(), Some("m5.xlarge"));
            assert!(parsed.as_resources().is_none());
        }

        #[test]
        fn test_instance_type_resources_serde() {
            let it = InstanceType::resources(NodeResourceSpec {
                cores: 16,
                memory_gib: 32,
                disk_gib: 50,
                sockets: 1,
            });
            let json = serde_json::to_string(&it).unwrap();
            let parsed: InstanceType = serde_json::from_str(&json).unwrap();
            assert!(parsed.as_named().is_none());
            let res = parsed.as_resources().unwrap();
            assert_eq!(res.cores, 16);
            assert_eq!(res.memory_gib, 32);
            assert_eq!(res.disk_gib, 50);
            assert_eq!(res.sockets, 1);
        }

        #[test]
        fn test_control_plane_spec_serde() {
            let spec = ControlPlaneSpec {
                replicas: 3,
                instance_type: Some(InstanceType::named("m5.xlarge")),
                root_volume: Some(RootVolume {
                    size_gb: 50,
                    type_: Some("gp3".to_string()),
                }),
            };
            let json = serde_json::to_string(&spec).unwrap();
            let parsed: ControlPlaneSpec = serde_json::from_str(&json).unwrap();
            assert_eq!(spec, parsed);
        }

        #[test]
        fn test_root_volume_serde() {
            let vol = RootVolume {
                size_gb: 100,
                type_: None,
            };
            let json = serde_json::to_string(&vol).unwrap();
            assert!(!json.contains("type"));
            let parsed: RootVolume = serde_json::from_str(&json).unwrap();
            assert_eq!(vol, parsed);
        }
    }

    mod worker_pool_spec {
        use super::*;

        #[test]
        fn test_default() {
            let pool = WorkerPoolSpec::default();
            assert_eq!(pool.replicas, 0);
            assert!(pool.display_name.is_none());
            assert!(pool.instance_type.is_none());
            assert!(pool.root_volume.is_none());
            assert!(pool.labels.is_empty());
            assert!(pool.taints.is_empty());
        }

        #[test]
        fn test_serde_roundtrip() {
            let pool = WorkerPoolSpec {
                display_name: Some("GPU Workers".to_string()),
                replicas: 3,
                instance_type: Some(InstanceType::named("gpu-large")),
                root_volume: None,
                labels: std::collections::BTreeMap::from([(
                    "nvidia.com/gpu".to_string(),
                    "true".to_string(),
                )]),
                taints: vec![NodeTaint {
                    key: "nvidia.com/gpu".to_string(),
                    value: None,
                    effect: TaintEffect::NoSchedule,
                }],
                min: Some(1),
                max: Some(10),
            };
            let json =
                serde_json::to_string(&pool).expect("WorkerPoolSpec serialization should succeed");
            let parsed: WorkerPoolSpec =
                serde_json::from_str(&json).expect("WorkerPoolSpec deserialization should succeed");
            assert_eq!(pool, parsed);
        }

        #[test]
        fn test_autoscaling_enabled() {
            let pool = WorkerPoolSpec {
                replicas: 3,
                min: Some(1),
                max: Some(10),
                ..Default::default()
            };
            assert!(pool.is_autoscaling_enabled());
        }

        #[test]
        fn test_autoscaling_disabled_without_min_max() {
            let pool = WorkerPoolSpec {
                replicas: 3,
                ..Default::default()
            };
            assert!(!pool.is_autoscaling_enabled());
        }

        #[test]
        fn test_autoscaling_disabled_with_only_min() {
            let pool = WorkerPoolSpec {
                replicas: 3,
                min: Some(1),
                ..Default::default()
            };
            assert!(!pool.is_autoscaling_enabled());
        }

        #[test]
        fn test_validate_min_greater_than_max() {
            let pool = WorkerPoolSpec {
                replicas: 3,
                min: Some(10),
                max: Some(5),
                ..Default::default()
            };
            let result = pool.validate();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("cannot exceed"));
        }

        #[test]
        fn test_validate_min_zero() {
            let pool = WorkerPoolSpec {
                replicas: 3,
                min: Some(0),
                max: Some(10),
                ..Default::default()
            };
            let result = pool.validate();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("scale-from-zero"));
        }

        #[test]
        fn test_validate_only_min_set() {
            let pool = WorkerPoolSpec {
                replicas: 3,
                min: Some(1),
                ..Default::default()
            };
            let result = pool.validate();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("both be set"));
        }

        #[test]
        fn test_validate_valid_autoscaling() {
            let pool = WorkerPoolSpec {
                replicas: 3,
                min: Some(1),
                max: Some(10),
                ..Default::default()
            };
            assert!(pool.validate().is_ok());
        }

        #[test]
        fn test_validate_static_scaling() {
            let pool = WorkerPoolSpec {
                replicas: 3,
                ..Default::default()
            };
            assert!(pool.validate().is_ok());
        }
    }

    mod taint_effect {
        use super::*;

        #[test]
        fn test_display() {
            assert_eq!(TaintEffect::NoSchedule.to_string(), "NoSchedule");
            assert_eq!(
                TaintEffect::PreferNoSchedule.to_string(),
                "PreferNoSchedule"
            );
            assert_eq!(TaintEffect::NoExecute.to_string(), "NoExecute");
        }

        #[test]
        fn test_serde_roundtrip() {
            let effects = [
                TaintEffect::NoSchedule,
                TaintEffect::PreferNoSchedule,
                TaintEffect::NoExecute,
            ];
            for effect in effects {
                let json = serde_json::to_string(&effect)
                    .expect("TaintEffect serialization should succeed");
                let parsed: TaintEffect = serde_json::from_str(&json)
                    .expect("TaintEffect deserialization should succeed");
                assert_eq!(effect, parsed);
            }
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
            assert_eq!(ClusterPhase::Pivoted.to_string(), "Pivoted");
            assert_eq!(ClusterPhase::Ready.to_string(), "Ready");
            assert_eq!(ClusterPhase::Deleting.to_string(), "Deleting");
            assert_eq!(ClusterPhase::Unpivoting.to_string(), "Unpivoting");
            assert_eq!(ClusterPhase::Failed.to_string(), "Failed");
        }

        #[test]
        fn test_serde_roundtrip() {
            let phases = [
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
                ipv6_pool: None,
                bridge: None,
                vlan: None,
                network_model: None,
                memory_adjustment: None,
                vmid_min: None,
                vmid_max: None,
                skip_cloud_init_status: None,
                skip_qemu_guest_agent: None,
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
                external_network: "ext-net".to_string(),
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

    mod pool_id_validation {
        use super::*;

        #[test]
        fn test_valid_simple() {
            assert!(is_valid_pool_id("default"));
            assert!(is_valid_pool_id("general"));
            assert!(is_valid_pool_id("gpu"));
        }

        #[test]
        fn test_valid_with_numbers() {
            assert!(is_valid_pool_id("gpu1"));
            assert!(is_valid_pool_id("pool123"));
            assert!(is_valid_pool_id("a1b2c3"));
        }

        #[test]
        fn test_valid_with_hyphens() {
            assert!(is_valid_pool_id("high-memory"));
            assert!(is_valid_pool_id("general-purpose"));
            assert!(is_valid_pool_id("gpu-large-v2"));
        }

        #[test]
        fn test_invalid_empty() {
            assert!(!is_valid_pool_id(""));
        }

        #[test]
        fn test_invalid_starts_with_number() {
            assert!(!is_valid_pool_id("1pool"));
            assert!(!is_valid_pool_id("2gpu"));
        }

        #[test]
        fn test_invalid_starts_with_hyphen() {
            assert!(!is_valid_pool_id("-pool"));
        }

        #[test]
        fn test_invalid_ends_with_hyphen() {
            assert!(!is_valid_pool_id("pool-"));
            assert!(!is_valid_pool_id("general-"));
        }

        #[test]
        fn test_invalid_uppercase() {
            assert!(!is_valid_pool_id("GPU"));
            assert!(!is_valid_pool_id("Pool"));
            assert!(!is_valid_pool_id("highMemory"));
        }

        #[test]
        fn test_invalid_special_chars() {
            assert!(!is_valid_pool_id("pool_name"));
            assert!(!is_valid_pool_id("pool.name"));
            assert!(!is_valid_pool_id("pool@name"));
        }
    }

    mod provider_config_validation {
        use super::*;

        #[test]
        fn test_validate_no_provider() {
            let config = ProviderConfig {
                aws: None,
                docker: None,
                openstack: None,
                proxmox: None,
            };
            let result = config.validate();
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("exactly one provider"));
        }

        #[test]
        fn test_validate_multiple_providers() {
            let config = ProviderConfig {
                aws: Some(AwsConfig {
                    region: "us-west-2".to_string(),
                    ssh_key_name: "key".to_string(),
                    ..Default::default()
                }),
                docker: Some(DockerConfig::default()),
                openstack: None,
                proxmox: None,
            };
            let result = config.validate();
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("not multiple"));
        }

        #[test]
        fn test_provider_type_defaults_to_docker() {
            let config = ProviderConfig {
                aws: None,
                docker: None,
                openstack: None,
                proxmox: None,
            };
            // Even when no provider is set, provider_type returns Docker as default
            assert_eq!(config.provider_type(), ProviderType::Docker);
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
                credentials_secret_ref: None,
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
                proxy_port: 8081,
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
            assert_eq!(
                spec.proxy_endpoint(),
                Some("https://172.18.255.1:8081".to_string())
            );
            assert_eq!(spec.endpoint(), Some("172.18.255.1:8443:50051".to_string()));
        }

        #[test]
        fn test_endpoints_spec_no_host() {
            let spec = EndpointsSpec {
                host: None,
                grpc_port: 50051,
                bootstrap_port: 8443,
                proxy_port: 8081,
                service: ServiceSpec {
                    type_: "LoadBalancer".to_string(),
                },
            };
            assert_eq!(spec.grpc_endpoint(), None);
            assert_eq!(spec.bootstrap_endpoint(), None);
            assert_eq!(spec.proxy_endpoint(), None);
            assert_eq!(spec.endpoint(), None);
        }
    }
}
