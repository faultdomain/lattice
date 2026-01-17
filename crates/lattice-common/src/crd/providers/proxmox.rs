//! Proxmox VE provider configuration (CAPMOX)
//!
//! This provider generates Cluster API manifests for provisioning Kubernetes
//! clusters on Proxmox Virtual Environment using the CAPMOX provider.
//!
//! Reference: <https://github.com/ionos-cloud/cluster-api-provider-proxmox>

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::super::types::SecretRef;

/// Proxmox VE provider configuration (CAPMOX)
///
/// Configuration for provisioning clusters on Proxmox Virtual Environment.
/// All fields are optional with sensible defaults.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxConfig {
    // ==========================================================================
    // Template Source Configuration
    // ==========================================================================

    /// Proxmox node where the template VM is located
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_node: Option<String>,

    /// VM template ID to clone from
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
    // Clone Configuration
    // ==========================================================================

    /// Storage backend for full clone (e.g., "local-lvm", "ceph", "local-zfs")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,

    /// Disk format for cloned VMs (qcow2, raw, vmdk)
    /// Only applies when full clone is enabled
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// Use full clone instead of linked clone (default: true)
    /// Full clones are independent but use more storage
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_clone: Option<bool>,

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
    // Cluster-Level Configuration
    // ==========================================================================

    /// Control plane endpoint IP or FQDN (required for workload clusters)
    /// This is the VIP that kube-vip will manage for API server access
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_plane_endpoint: Option<String>,

    /// Allowed Proxmox nodes for VM placement
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_nodes: Option<Vec<String>>,

    /// DNS servers for cluster nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_servers: Option<Vec<String>>,

    /// SSH authorized keys to deploy to VMs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_authorized_keys: Option<Vec<String>>,

    /// Network interface where kube-vip binds for virtual IP
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_ip_network_interface: Option<String>,

    /// kube-vip image (default: ghcr.io/kube-vip/kube-vip:v0.8.0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kube_vip_image: Option<String>,

    // ==========================================================================
    // Credentials
    // ==========================================================================

    /// Reference to Secret containing Proxmox API credentials
    /// The secret should contain: url, token, secret
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<SecretRef>,

    // ==========================================================================
    // IPv4 Configuration
    // ==========================================================================

    /// IPv4 address pool for nodes (individual IPs or CIDR ranges)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4_addresses: Option<Vec<String>>,

    /// IPv4 network prefix length (default: 24)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4_prefix: Option<u8>,

    /// IPv4 gateway address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4_gateway: Option<String>,

    /// IPv4 route metric (priority) for default gateway
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4_metric: Option<u32>,

    // ==========================================================================
    // IPv6 Configuration
    // ==========================================================================

    /// IPv6 address pool for nodes (individual IPs or CIDR ranges)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_addresses: Option<Vec<String>>,

    /// IPv6 network prefix length (default: 64)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_prefix: Option<u8>,

    /// IPv6 gateway address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_gateway: Option<String>,

    /// IPv6 route metric (priority) for default gateway
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_metric: Option<u32>,

    // ==========================================================================
    // Network Configuration
    // ==========================================================================

    /// Network bridge (e.g., "vmbr0")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<String>,

    /// VLAN tag for network isolation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,

    /// Network model (virtio, e1000, rtl8139) - default: virtio
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_model: Option<String>,

    // ==========================================================================
    // Scheduler Hints
    // ==========================================================================

    /// Memory adjustment percentage for scheduling (0=disabled, 100=default, >100=overprovisioning)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_adjustment: Option<u64>,

    // ==========================================================================
    // VM ID Range
    // ==========================================================================

    /// Minimum VMID for created VMs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmid_min: Option<u32>,

    /// Maximum VMID for created VMs
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmid_max: Option<u32>,

    // ==========================================================================
    // Health Checks
    // ==========================================================================

    /// Skip cloud-init status check (required for Flatcar Linux)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_cloud_init_status: Option<bool>,

    /// Skip QEMU guest agent check
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_qemu_guest_agent: Option<bool>,

    // ==========================================================================
    // Control Plane VM Sizing
    // ==========================================================================

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

    // ==========================================================================
    // Worker VM Sizing
    // ==========================================================================

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
