//! Cilium LB-IPAM resource generation
//!
//! Generates CiliumLoadBalancerIPPool and CiliumL2AnnouncementPolicy resources
//! from LatticeCluster networking configuration.
//!
//! For Proxmox clusters without explicit networking config, LB pools are
//! auto-derived from the ipv4_pool configuration using the .200-.250 range.

use serde::{Deserialize, Serialize};

use lattice_common::crd::{Ipv4PoolConfig, NetworkingSpec};

/// Generate Cilium LB-IPAM resources from networking spec
///
/// Returns YAML strings for:
/// - CiliumLoadBalancerIPPool (one per pool in networking spec)
/// - CiliumL2AnnouncementPolicy (enables L2 announcements)
pub fn generate_lb_resources(networking: &NetworkingSpec) -> Vec<String> {
    let mut resources = Vec::new();

    // Generate IP pool for default network if configured
    if let Some(ref pool) = networking.default {
        resources.push(generate_ip_pool("default", &pool.cidr));
    }

    // Always generate L2 announcement policy if we have any pools
    if !resources.is_empty() {
        resources.push(generate_l2_policy());
    }

    resources
}

/// Generate Cilium LB-IPAM resources auto-derived from Proxmox ipv4_pool
///
/// Uses the .200-.250 range from the same subnet as the node IP pool.
/// For example, if ipv4_pool uses 10.0.0.101-120 with gateway 10.0.0.1/24,
/// this generates a LoadBalancer pool using 10.0.0.200/27 (200-231).
///
/// Returns YAML strings for:
/// - CiliumLoadBalancerIPPool (derived from ipv4_pool subnet)
/// - CiliumL2AnnouncementPolicy (enables L2 announcements)
pub fn generate_lb_resources_from_proxmox(ipv4_pool: &Ipv4PoolConfig) -> Vec<String> {
    let mut resources = Vec::new();

    // Derive LB CIDR from the same subnet as ipv4_pool
    // Use .200/27 range (200-231) which doesn't overlap with typical node ranges
    if let Some(cidr) = derive_lb_cidr_from_pool(ipv4_pool) {
        resources.push(generate_ip_pool("default", &cidr));
        resources.push(generate_l2_policy());
    }

    resources
}

/// Derive a LoadBalancer CIDR from the Proxmox ipv4_pool gateway
///
/// Takes the network base from the gateway (e.g., 10.0.0.1 → 10.0.0.0)
/// and creates a /27 range starting at .200 (10.0.0.200/27 = 200-231)
fn derive_lb_cidr_from_pool(pool: &Ipv4PoolConfig) -> Option<String> {
    // Parse gateway to get the network base
    let parts: Vec<&str> = pool.gateway.split('.').collect();
    if parts.len() != 4 {
        return None;
    }

    // Build the .200/27 CIDR in the same /24 network
    // This gives us IPs .200-.231 for LoadBalancer services
    Some(format!("{}.{}.{}.200/27", parts[0], parts[1], parts[2]))
}

/// Generate a CiliumLoadBalancerIPPool resource
fn generate_ip_pool(name: &str, cidr: &str) -> String {
    let pool = CiliumLoadBalancerIPPool {
        api_version: "cilium.io/v2alpha1".to_string(),
        kind: "CiliumLoadBalancerIPPool".to_string(),
        metadata: Metadata {
            name: name.to_string(),
            labels: Some(managed_by_labels()),
        },
        spec: IPPoolSpec {
            blocks: vec![IPBlock {
                cidr: cidr.to_string(),
            }],
        },
    };

    serde_json::to_string(&pool).expect("CiliumLoadBalancerIPPool serialization")
}

/// Generate CiliumL2AnnouncementPolicy resource
fn generate_l2_policy() -> String {
    let policy = CiliumL2AnnouncementPolicy {
        api_version: "cilium.io/v2alpha1".to_string(),
        kind: "CiliumL2AnnouncementPolicy".to_string(),
        metadata: Metadata {
            name: "default".to_string(),
            labels: Some(managed_by_labels()),
        },
        spec: L2PolicySpec {
            load_balancer_ips: true,
            interfaces: vec!["^.*$".to_string()], // Match all interfaces
        },
    };

    serde_json::to_string(&policy).expect("CiliumL2AnnouncementPolicy serialization")
}

fn managed_by_labels() -> std::collections::BTreeMap<String, String> {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "lattice".to_string(),
    );
    labels
}

// =============================================================================
// Cilium CRD Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CiliumLoadBalancerIPPool {
    api_version: String,
    kind: String,
    metadata: Metadata,
    spec: IPPoolSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IPPoolSpec {
    blocks: Vec<IPBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IPBlock {
    cidr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CiliumL2AnnouncementPolicy {
    api_version: String,
    kind: String,
    metadata: Metadata,
    spec: L2PolicySpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct L2PolicySpec {
    #[serde(rename = "loadBalancerIPs")]
    load_balancer_ips: bool,
    interfaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Metadata {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<std::collections::BTreeMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::NetworkPool;

    #[test]
    fn test_generate_ip_pool() {
        let yaml = generate_ip_pool("default", "172.18.255.1/32");

        assert!(yaml.contains("apiVersion: cilium.io/v2alpha1"));
        assert!(yaml.contains("kind: CiliumLoadBalancerIPPool"));
        assert!(yaml.contains("name: default"));
        assert!(yaml.contains("cidr: 172.18.255.1/32"));
        assert!(yaml.contains("app.kubernetes.io/managed-by: lattice"));
    }

    #[test]
    fn test_generate_l2_policy() {
        let yaml = generate_l2_policy();

        assert!(yaml.contains("apiVersion: cilium.io/v2alpha1"));
        assert!(yaml.contains("kind: CiliumL2AnnouncementPolicy"));
        assert!(yaml.contains("loadBalancerIPs: true"));
        assert!(yaml.contains("- ^.*$")); // Match all interfaces
    }

    #[test]
    fn test_generate_lb_resources_with_networking() {
        let networking = NetworkingSpec {
            default: Some(NetworkPool {
                cidr: "10.0.100.0/24".to_string(),
            }),
        };

        let resources = generate_lb_resources(&networking);

        assert_eq!(resources.len(), 2); // IP pool + L2 policy
        assert!(resources[0].contains("CiliumLoadBalancerIPPool"));
        assert!(resources[0].contains("10.0.100.0/24"));
        assert!(resources[1].contains("CiliumL2AnnouncementPolicy"));
    }

    #[test]
    fn test_generate_lb_resources_empty_networking() {
        let networking = NetworkingSpec::default();

        let resources = generate_lb_resources(&networking);

        assert!(resources.is_empty());
    }

    #[test]
    fn test_single_ip_cidr() {
        // Single IP for cell LoadBalancer
        let yaml = generate_ip_pool("cell", "172.18.255.1/32");

        assert!(yaml.contains("cidr: 172.18.255.1/32"));
    }

    #[test]
    fn test_derive_lb_cidr_from_pool() {
        let pool = Ipv4PoolConfig {
            range: "10.0.0.101-120/24".to_string(),
            gateway: "10.0.0.1".to_string(),
        };

        let cidr = derive_lb_cidr_from_pool(&pool);

        assert_eq!(cidr, Some("10.0.0.200/27".to_string()));
    }

    #[test]
    fn test_derive_lb_cidr_different_subnet() {
        let pool = Ipv4PoolConfig {
            range: "192.168.1.50-100/24".to_string(),
            gateway: "192.168.1.1".to_string(),
        };

        let cidr = derive_lb_cidr_from_pool(&pool);

        assert_eq!(cidr, Some("192.168.1.200/27".to_string()));
    }

    #[test]
    fn test_generate_lb_resources_from_proxmox() {
        let pool = Ipv4PoolConfig {
            range: "10.0.0.101-120/24".to_string(),
            gateway: "10.0.0.1".to_string(),
        };

        let resources = generate_lb_resources_from_proxmox(&pool);

        assert_eq!(resources.len(), 2); // IP pool + L2 policy
        assert!(resources[0].contains("CiliumLoadBalancerIPPool"));
        assert!(resources[0].contains("10.0.0.200/27"));
        assert!(resources[1].contains("CiliumL2AnnouncementPolicy"));
    }
}
