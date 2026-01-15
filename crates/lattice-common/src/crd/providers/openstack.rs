//! OpenStack provider configuration (CAPO)
//!
//! This provider generates Cluster API manifests for provisioning Kubernetes
//! clusters on OpenStack using the CAPO provider. Works with any OpenStack
//! cloud including OVH Public Cloud.
//!
//! Reference: <https://cluster-api-openstack.sigs.k8s.io/clusteropenstack/configuration.html>

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// OpenStack provider configuration (CAPO)
///
/// Configuration for provisioning clusters on OpenStack (including OVH Public Cloud).
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OpenstackConfig {
    // ==========================================================================
    // Identity and Cloud Configuration
    // ==========================================================================

    /// Name of the cloud in clouds.yaml (default: "openstack")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_name: Option<String>,

    // ==========================================================================
    // Network Configuration
    // ==========================================================================

    /// External network name or ID for floating IPs (e.g., "Ext-Net" on OVH)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_network: Option<String>,

    /// Existing network ID to use (creates new network if not specified)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,

    /// Existing subnet ID to use
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet_id: Option<String>,

    /// CIDR for managed subnet if creating new network (default: "10.6.0.0/24")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_subnet_cidr: Option<String>,

    /// DNS nameservers for cluster nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_nameservers: Option<Vec<String>>,

    /// Use a pre-existing router instead of creating a new one
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_id: Option<String>,

    // ==========================================================================
    // Floating IP Configuration
    // ==========================================================================

    /// Use floating IPs for nodes (default: true for external access)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_floating_ip: Option<bool>,

    /// Explicitly specify the floating IP for API server access
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_server_floating_ip: Option<String>,

    /// Disable floating IP for API server (provision cluster without external IP)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_api_server_floating_ip: Option<bool>,

    // ==========================================================================
    // Load Balancer Configuration
    // ==========================================================================

    /// Enable API server load balancer (default: true)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_server_lb_enabled: Option<bool>,

    /// Restrict network access to Kubernetes API using CIDR ranges
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_server_lb_allowed_cidrs: Option<Vec<String>>,

    // ==========================================================================
    // Security Groups
    // ==========================================================================

    /// Create managed security groups for control plane and worker nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_security_groups: Option<bool>,

    /// Allow all traffic between cluster nodes on all ports (when using managed security groups)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_all_in_cluster_traffic: Option<bool>,

    /// Pre-existing security groups to attach to instances
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_groups: Option<Vec<String>>,

    // ==========================================================================
    // Bastion Host Configuration
    // ==========================================================================

    /// Enable SSH bastion host creation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bastion_enabled: Option<bool>,

    /// Bastion host machine flavor
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bastion_flavor: Option<String>,

    /// Bastion host operating system image
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bastion_image: Option<String>,

    /// SSH key for bastion host (uses ssh_key_name if not specified)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bastion_ssh_key_name: Option<String>,

    /// Explicitly assign floating IP to bastion
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bastion_floating_ip: Option<String>,

    // ==========================================================================
    // Instance Configuration
    // ==========================================================================

    /// SSH key name registered in OpenStack
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key_name: Option<String>,

    /// Image name for cluster nodes (e.g., "Ubuntu 22.04")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_name: Option<String>,

    /// Image ID for cluster nodes (alternative to image_name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_id: Option<String>,

    /// Availability zone for instances
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability_zone: Option<String>,

    /// Server group for anti-affinity placement
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_group_id: Option<String>,

    /// Custom metadata key-value pairs to add to instances
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_metadata: Option<BTreeMap<String, String>>,

    /// Tags to add to all resources
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    // ==========================================================================
    // Control Plane Instance Configuration
    // ==========================================================================

    /// Flavor (instance type) for control plane nodes (e.g., "b2-30" on OVH)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_flavor: Option<String>,

    /// Root volume size in GB for control plane nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_root_volume_size: Option<u32>,

    /// Cinder volume type for control plane root volumes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_root_volume_type: Option<String>,

    /// Availability zone for control plane root volumes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_root_volume_az: Option<String>,

    // ==========================================================================
    // Worker Instance Configuration
    // ==========================================================================

    /// Flavor (instance type) for worker nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_flavor: Option<String>,

    /// Root volume size in GB for worker nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_root_volume_size: Option<u32>,

    /// Cinder volume type for worker root volumes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_root_volume_type: Option<String>,

    /// Availability zone for worker root volumes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_root_volume_az: Option<String>,
}
