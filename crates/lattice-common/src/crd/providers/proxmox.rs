//! Proxmox VE provider configuration (CAPMOX)
//!
//! This provider generates Cluster API manifests for provisioning Kubernetes
//! clusters on Proxmox Virtual Environment using the CAPMOX provider.
//!
//! Reference: <https://github.com/ionos-cloud/cluster-api-provider-proxmox>

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::super::types::SecretRef;

/// IPv4 pool configuration for CAPI IPAM
///
/// Defines a range of IPv4 addresses for automatic allocation to cluster nodes.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Ipv4PoolConfig {
    /// Start of IP range (e.g., "10.0.0.101")
    pub start: String,

    /// End of IP range (e.g., "10.0.0.120")
    pub end: String,

    /// Network prefix length (default: 24)
    #[serde(default = "default_ipv4_prefix")]
    pub prefix: u8,

    /// Gateway address (e.g., "10.0.0.1")
    pub gateway: String,
}

fn default_ipv4_prefix() -> u8 {
    24
}

/// IPv6 pool configuration for CAPI IPAM
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Ipv6PoolConfig {
    /// Start of IP range
    pub start: String,

    /// End of IP range
    pub end: String,

    /// Network prefix length (default: 64)
    #[serde(default = "default_ipv6_prefix")]
    pub prefix: u8,

    /// Gateway address
    pub gateway: String,
}

fn default_ipv6_prefix() -> u8 {
    64
}

/// Proxmox VE provider configuration (CAPMOX)
///
/// Configuration for provisioning clusters on Proxmox Virtual Environment.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxConfig {
    // ==========================================================================
    // Required Fields
    // ==========================================================================

    /// Control plane endpoint IP or FQDN
    /// This is the VIP that kube-vip will manage for API server access
    pub control_plane_endpoint: String,

    /// IPv4 address pool for automatic node IP allocation via CAPI IPAM
    pub ipv4_pool: Ipv4PoolConfig,

    /// CPU cores for control plane nodes
    pub cp_cores: u32,

    /// Memory in MiB for control plane nodes
    pub cp_memory_mib: u32,

    /// Disk size in GB for control plane nodes
    pub cp_disk_size_gb: u32,

    /// CPU cores for worker nodes
    pub worker_cores: u32,

    /// Memory in MiB for worker nodes
    pub worker_memory_mib: u32,

    /// Disk size in GB for worker nodes
    pub worker_disk_size_gb: u32,

    // ==========================================================================
    // Template Source Configuration (Optional)
    // ==========================================================================

    /// Proxmox node where the template VM is located
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_node: Option<String>,

    /// VM template ID to clone from (default: 9000)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<u32>,

    /// Template selector for dynamic template lookup by tags
    /// If set, templateId is ignored and template is selected by matching tags
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_tags: Option<Vec<String>>,

    /// Snapshot name to clone from (if not set, clones current state)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snap_name: Option<String>,

    // ==========================================================================
    // VM Placement (Optional)
    // ==========================================================================

    /// Target node for cloning (overrides automatic placement)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_node: Option<String>,

    /// Proxmox resource pool for new VMs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<String>,

    /// Description for new VMs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Tags to apply to VMs (for organization and filtering)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    // ==========================================================================
    // Cluster-Level Configuration (Optional)
    // ==========================================================================

    /// Allowed Proxmox nodes for VM placement
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_nodes: Option<Vec<String>>,

    /// DNS servers for cluster nodes (default: ["8.8.8.8", "8.8.4.4"])
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_servers: Option<Vec<String>>,

    /// SSH authorized keys to deploy to VMs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_authorized_keys: Option<Vec<String>>,

    /// Network interface where kube-vip binds for virtual IP (default: "ens18")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_ip_network_interface: Option<String>,

    /// kube-vip image (default: ghcr.io/kube-vip/kube-vip:v0.8.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kube_vip_image: Option<String>,

    // ==========================================================================
    // Credentials (Optional)
    // ==========================================================================

    /// Reference to Secret containing Proxmox API credentials
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<SecretRef>,

    // ==========================================================================
    // IPv6 Configuration (Optional)
    // ==========================================================================

    /// IPv6 address pool for automatic node IP allocation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_pool: Option<Ipv6PoolConfig>,

    // ==========================================================================
    // Network Configuration (Optional)
    // ==========================================================================

    /// Network bridge (default: "vmbr0")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<String>,

    /// VLAN tag for network isolation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,

    /// Network model (default: "virtio")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_model: Option<String>,

    // ==========================================================================
    // Scheduler Hints (Optional)
    // ==========================================================================

    /// Memory adjustment percentage for scheduling
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_adjustment: Option<u64>,

    // ==========================================================================
    // VM ID Range (Optional)
    // ==========================================================================

    /// Minimum VMID for created VMs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmid_min: Option<u32>,

    /// Maximum VMID for created VMs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmid_max: Option<u32>,

    // ==========================================================================
    // Health Checks (Optional)
    // ==========================================================================

    /// Skip cloud-init status check (required for Flatcar Linux)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_cloud_init_status: Option<bool>,

    /// Skip QEMU guest agent check
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_qemu_guest_agent: Option<bool>,

    // ==========================================================================
    // VM Sizing - Optional Overrides
    // ==========================================================================

    /// CPU sockets for control plane nodes (default: 1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_sockets: Option<u32>,

    /// CPU sockets for worker nodes (default: 1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_sockets: Option<u32>,
}
