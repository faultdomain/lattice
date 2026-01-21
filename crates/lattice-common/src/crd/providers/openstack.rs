//! OpenStack provider configuration (CAPO)
//!
//! This provider generates Cluster API manifests for provisioning Kubernetes
//! clusters on OpenStack using the CAPO provider.
//!
//! Reference: <https://github.com/kubernetes-sigs/cluster-api-provider-openstack>

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::super::types::SecretRef;

/// OpenStack provider configuration (CAPO)
///
/// Configuration for provisioning clusters on OpenStack.
/// Supports OVH, Vexxhost, and other OpenStack-based clouds.
/// Requires Octavia for API server load balancing.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OpenStackConfig {
    // ==========================================================================
    // Required Fields
    // ==========================================================================
    /// External network ID for floating IPs and API server load balancer
    pub external_network_id: String,

    /// OpenStack flavor for control plane nodes (e.g., "b2-30")
    pub cp_flavor: String,

    /// OpenStack flavor for worker nodes (e.g., "b2-15")
    pub worker_flavor: String,

    /// Image name or ID for node VMs (e.g., "Ubuntu 22.04")
    pub image_name: String,

    /// SSH key name registered in OpenStack for node access
    pub ssh_key_name: String,

    // ==========================================================================
    // Cloud Configuration (Optional)
    // ==========================================================================
    /// Cloud name from clouds.yaml (default: "openstack")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_name: Option<String>,

    /// Reference to Secret containing clouds.yaml
    /// Secret must have key "clouds.yaml" with OpenStack credentials
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<SecretRef>,

    // ==========================================================================
    // Network Configuration (Optional)
    // ==========================================================================
    /// DNS nameservers for cluster nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_nameservers: Option<Vec<String>>,

    /// CIDR for managed subnet (default: "10.6.0.0/24")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_cidr: Option<String>,

    // ==========================================================================
    // API Server Load Balancer (Optional)
    // ==========================================================================
    /// Flavor for Octavia load balancer (provider-specific)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_server_load_balancer_flavor: Option<String>,

    // ==========================================================================
    // Security Groups (Optional)
    // ==========================================================================
    /// Enable managed security groups (default: true)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_security_groups: Option<bool>,

    /// Allow all traffic in default security group (for development)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_all_in_cluster_traffic: Option<bool>,

    // ==========================================================================
    // Availability Zones (Optional)
    // ==========================================================================
    /// Availability zone for control plane nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_availability_zone: Option<String>,

    /// Availability zone for worker nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_availability_zone: Option<String>,

    // ==========================================================================
    // Root Volume (Optional)
    // ==========================================================================
    /// Root volume size in GB for control plane (default: use flavor disk)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_root_volume_size_gb: Option<u32>,

    /// Root volume type for control plane (e.g., "high-speed")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_root_volume_type: Option<String>,

    /// Root volume size in GB for workers (default: use flavor disk)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_root_volume_size_gb: Option<u32>,

    /// Root volume type for workers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_root_volume_type: Option<String>,

    // ==========================================================================
    // SSH Access (Optional)
    // ==========================================================================
    /// Additional SSH authorized keys for node access
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_authorized_keys: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_yaml_roundtrip() {
        let config = OpenStackConfig {
            external_network_id: "ext-net-123".to_string(),
            cp_flavor: "b2-30".to_string(),
            worker_flavor: "b2-15".to_string(),
            image_name: "Ubuntu 22.04".to_string(),
            ssh_key_name: "my-key".to_string(),
            cloud_name: Some("ovh".to_string()),
            dns_nameservers: Some(vec!["8.8.8.8".to_string()]),
            ..Default::default()
        };

        let yaml =
            serde_yaml::to_string(&config).expect("OpenStackConfig serialization should succeed");
        assert!(yaml.contains("externalNetworkId: ext-net-123"));
        assert!(yaml.contains("cpFlavor: b2-30"));

        let parsed: OpenStackConfig =
            serde_yaml::from_str(&yaml).expect("OpenStackConfig deserialization should succeed");
        assert_eq!(parsed, config);
    }

    #[test]
    fn minimal_config() {
        let yaml = r#"
externalNetworkId: ext-net
cpFlavor: m1.large
workerFlavor: m1.medium
imageName: ubuntu-22.04
sshKeyName: default
"#;
        let config: OpenStackConfig = serde_yaml::from_str(yaml)
            .expect("minimal OpenStackConfig deserialization should succeed");
        assert_eq!(config.external_network_id, "ext-net");
        assert_eq!(config.cp_flavor, "m1.large");
        assert!(config.cloud_name.is_none());
    }

    #[test]
    fn full_config_with_options() {
        let yaml = r#"
externalNetworkId: Ext-Net
cpFlavor: b2-30
workerFlavor: b2-15
imageName: Ubuntu 22.04
sshKeyName: lattice-key
cloudName: ovh
dnsNameservers:
  - 8.8.8.8
  - 8.8.4.4
nodeCidr: 10.6.0.0/24
cpRootVolumeSizeGb: 50
cpRootVolumeType: high-speed
workerRootVolumeSizeGb: 100
cpAvailabilityZone: nova
"#;
        let config: OpenStackConfig = serde_yaml::from_str(yaml)
            .expect("full OpenStackConfig deserialization should succeed");
        assert_eq!(config.cp_root_volume_size_gb, Some(50));
        assert_eq!(config.cp_availability_zone, Some("nova".to_string()));
    }
}
