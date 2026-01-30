//! Proxmox VE provider configuration (CAPMOX)
//!
//! This provider generates Cluster API manifests for provisioning Kubernetes
//! clusters on Proxmox Virtual Environment using the CAPMOX provider.
//!
//! Reference: <https://github.com/ionos-cloud/cluster-api-provider-proxmox>

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// IPv4 pool configuration for CAPI IPAM
///
/// Defines a range of IPv4 addresses for automatic allocation to cluster nodes.
///
/// # Range Format
///
/// The range field uses a compact CIDR notation: `"START-END_SUFFIX/PREFIX"`
///
/// Examples:
/// - `"10.0.0.101-102/24"` → IPs 10.0.0.101 to 10.0.0.102 with /24 prefix
/// - `"10.0.0.101-10.0.0.120/24"` → Full IP notation also supported
/// - `"192.168.1.50-100/24"` → IPs 192.168.1.50 to 192.168.1.100
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Ipv4PoolConfig {
    /// IP range in compact CIDR notation (e.g., "10.0.0.101-102/24")
    pub range: String,

    /// Gateway address (e.g., "10.0.0.1")
    pub gateway: String,
}

impl Ipv4PoolConfig {
    /// Parse the range field into start IP, end IP, and prefix length
    ///
    /// Supports two formats:
    /// - Compact: "10.0.0.101-102/24" (end is just the last octet)
    /// - Full: "10.0.0.101-10.0.0.120/24" (full end IP)
    ///
    /// Returns (start_ip, end_ip, prefix) or None if parsing fails
    pub fn parse_range(&self) -> Option<(String, String, u8)> {
        // Split off the CIDR prefix
        let (range_part, prefix_str) = self.range.rsplit_once('/')?;
        let prefix: u8 = prefix_str.parse().ok()?;

        // Split start and end
        let (start, end_part) = range_part.split_once('-')?;

        // Validate start IP
        let start_parts: Vec<&str> = start.split('.').collect();
        if start_parts.len() != 4 {
            return None;
        }
        for part in &start_parts {
            part.parse::<u8>().ok()?;
        }

        // Check if end is full IP or just last octet(s)
        let end = if end_part.contains('.') {
            // Full IP format: "10.0.0.101-10.0.0.120/24"
            let end_parts: Vec<&str> = end_part.split('.').collect();
            if end_parts.len() != 4 {
                return None;
            }
            for part in &end_parts {
                part.parse::<u8>().ok()?;
            }
            end_part.to_string()
        } else {
            // Compact format: "10.0.0.101-120/24" (last octet only)
            end_part.parse::<u8>().ok()?;
            format!(
                "{}.{}.{}.{}",
                start_parts[0], start_parts[1], start_parts[2], end_part
            )
        };

        Some((start.to_string(), end, prefix))
    }

    /// Get the start IP address
    pub fn start(&self) -> Option<String> {
        self.parse_range().map(|(start, _, _)| start)
    }

    /// Get the end IP address
    pub fn end(&self) -> Option<String> {
        self.parse_range().map(|(_, end, _)| end)
    }

    /// Get the prefix length
    pub fn prefix(&self) -> Option<u8> {
        self.parse_range().map(|(_, _, prefix)| prefix)
    }

    /// Get the IP range as "start-end" format for CAPI
    pub fn address_range(&self) -> Option<String> {
        let (start, end, _) = self.parse_range()?;
        Some(format!("{}-{}", start, end))
    }
}

/// IPv6 pool configuration for CAPI IPAM
///
/// # Range Format
///
/// The range field uses a compact CIDR notation similar to IPv4.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Ipv6PoolConfig {
    /// IP range in CIDR notation (e.g., "2001:db8::101-120/64")
    pub range: String,

    /// Gateway address
    pub gateway: String,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_compact_range() {
        let pool = Ipv4PoolConfig {
            range: "10.0.0.101-102/24".to_string(),
            gateway: "10.0.0.1".to_string(),
        };

        let (start, end, prefix) = pool
            .parse_range()
            .expect("compact IP range should parse successfully");
        assert_eq!(start, "10.0.0.101");
        assert_eq!(end, "10.0.0.102");
        assert_eq!(prefix, 24);
    }

    #[test]
    fn parse_full_range() {
        let pool = Ipv4PoolConfig {
            range: "10.0.0.101-10.0.0.120/24".to_string(),
            gateway: "10.0.0.1".to_string(),
        };

        let (start, end, prefix) = pool
            .parse_range()
            .expect("full IP range should parse successfully");
        assert_eq!(start, "10.0.0.101");
        assert_eq!(end, "10.0.0.120");
        assert_eq!(prefix, 24);
    }

    #[test]
    fn parse_range_different_prefix() {
        let pool = Ipv4PoolConfig {
            range: "192.168.1.50-100/16".to_string(),
            gateway: "192.168.0.1".to_string(),
        };

        let (start, end, prefix) = pool
            .parse_range()
            .expect("IP range with different prefix should parse successfully");
        assert_eq!(start, "192.168.1.50");
        assert_eq!(end, "192.168.1.100");
        assert_eq!(prefix, 16);
    }

    #[test]
    fn address_range_format() {
        let pool = Ipv4PoolConfig {
            range: "10.0.0.101-107/24".to_string(),
            gateway: "10.0.0.1".to_string(),
        };

        assert_eq!(
            pool.address_range(),
            Some("10.0.0.101-10.0.0.107".to_string())
        );
    }

    #[test]
    fn accessors() {
        let pool = Ipv4PoolConfig {
            range: "10.0.0.101-105/24".to_string(),
            gateway: "10.0.0.1".to_string(),
        };

        assert_eq!(pool.start(), Some("10.0.0.101".to_string()));
        assert_eq!(pool.end(), Some("10.0.0.105".to_string()));
        assert_eq!(pool.prefix(), Some(24));
    }

    #[test]
    fn invalid_range_returns_none() {
        let invalid_cases = [
            "invalid",
            "10.0.0.1",
            "10.0.0.1-",
            "-10/24",
            "10.0.0.1-10/",
            "10.0.0.1-10.0.0/24",
        ];

        for range in invalid_cases {
            let pool = Ipv4PoolConfig {
                range: range.to_string(),
                gateway: "10.0.0.1".to_string(),
            };
            assert!(pool.parse_range().is_none(), "expected None for: {}", range);
        }
    }

}
