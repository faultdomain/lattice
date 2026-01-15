//! AWS provider configuration (CAPA)
//!
//! This provider generates Cluster API manifests for provisioning Kubernetes
//! clusters on Amazon Web Services using the CAPA provider.
//!
//! Reference: <https://cluster-api-aws.sigs.k8s.io/crd/>

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// AWS provider configuration (CAPA)
///
/// Configuration for provisioning clusters on Amazon Web Services.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AwsConfig {
    // ==========================================================================
    // Region and Identity
    // ==========================================================================

    /// AWS region (e.g., "us-west-2")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// AWS security partition (default: "aws", also "aws-cn", "aws-us-gov")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition: Option<String>,

    // ==========================================================================
    // Network Configuration
    // ==========================================================================

    /// VPC ID to use (creates new VPC if not specified)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpc_id: Option<String>,

    /// Subnet IDs for cluster nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet_ids: Option<Vec<String>>,

    /// IPv4 CIDR blocks for node port security group rules (default: 0.0.0.0/0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_port_ingress_cidrs: Option<Vec<String>>,

    // ==========================================================================
    // Load Balancer Configuration
    // ==========================================================================

    /// Load balancer scheme: "internet-facing" or "internal" (default: internet-facing)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lb_scheme: Option<String>,

    /// Load balancer type: "classic", "nlb", "alb" (default: classic)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lb_type: Option<String>,

    /// Use existing load balancer by name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lb_name: Option<String>,

    /// Additional security groups for control plane load balancer
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lb_additional_security_groups: Option<Vec<String>>,

    /// Subnets for the load balancer
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lb_subnets: Option<Vec<String>>,

    // ==========================================================================
    // Security Groups
    // ==========================================================================

    /// Override default security groups (bastion, controlplane, apiserver-lb, node, lb)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_group_overrides: Option<BTreeMap<String, String>>,

    /// Additional security groups to apply to instances
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_security_groups: Option<Vec<String>>,

    // ==========================================================================
    // Bastion Host Configuration
    // ==========================================================================

    /// Enable bastion host for SSH access
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bastion_enabled: Option<bool>,

    /// EC2 instance type for bastion host
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bastion_instance_type: Option<String>,

    /// AMI ID for bastion host
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bastion_ami_id: Option<String>,

    // ==========================================================================
    // AMI Configuration
    // ==========================================================================

    /// AMI ID for cluster nodes (uses CAPA default if not specified)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ami_id: Option<String>,

    /// AMI naming format to look up machine images
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_lookup_format: Option<String>,

    /// AWS Organization ID to look up machine images
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_lookup_org: Option<String>,

    /// Base operating system for image lookup (e.g., "ubuntu-20.04")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_lookup_base_os: Option<String>,

    // ==========================================================================
    // SSH Configuration
    // ==========================================================================

    /// SSH key name for EC2 instances
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key_name: Option<String>,

    // ==========================================================================
    // Tags
    // ==========================================================================

    /// Additional tags to add to AWS resources
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_tags: Option<BTreeMap<String, String>>,

    // ==========================================================================
    // Instance Metadata Service (IMDS)
    // ==========================================================================

    /// HTTP endpoint for IMDS: "enabled" or "disabled"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imds_http_endpoint: Option<String>,

    /// HTTP tokens for IMDS: "optional" or "required" (IMDSv2)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imds_http_tokens: Option<String>,

    /// Put response hop limit for IMDS (1-64, default: 1)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imds_http_put_response_hop_limit: Option<u32>,

    // ==========================================================================
    // Placement Configuration
    // ==========================================================================

    /// Placement group name for instances
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_group_name: Option<String>,

    /// Partition number within placement group
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_group_partition: Option<i64>,

    /// Instance tenancy: "default", "dedicated", or "host"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenancy: Option<String>,

    /// Capacity Reservation ID for on-demand instances
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity_reservation_id: Option<String>,

    // ==========================================================================
    // Spot and Market Options
    // ==========================================================================

    /// Market type: "on-demand", "spot", or "capacity-block"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub market_type: Option<String>,

    /// Maximum spot price (only for spot instances)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spot_max_price: Option<String>,

    // ==========================================================================
    // Control Plane Instance Configuration
    // ==========================================================================

    /// EC2 instance type for control plane nodes (default: "t3.large")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_instance_type: Option<String>,

    /// IAM instance profile for control plane nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_iam_instance_profile: Option<String>,

    /// Root volume size in GB for control plane nodes (default: 80)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_root_volume_size: Option<u32>,

    /// Root volume type for control plane nodes (gp2, gp3, io1, io2)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_root_volume_type: Option<String>,

    /// Root volume IOPS for control plane nodes (for io1, io2, gp3)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_root_volume_iops: Option<u32>,

    /// Root volume throughput for control plane nodes (for gp3, in MiB/s)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_root_volume_throughput: Option<u32>,

    /// Encrypt root volume for control plane nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_root_volume_encrypted: Option<bool>,

    /// Subnet ID specifically for control plane nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_subnet_id: Option<String>,

    // ==========================================================================
    // Worker Instance Configuration
    // ==========================================================================

    /// EC2 instance type for worker nodes (default: "t3.large")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_instance_type: Option<String>,

    /// IAM instance profile for worker nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_iam_instance_profile: Option<String>,

    /// Root volume size in GB for worker nodes (default: 80)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_root_volume_size: Option<u32>,

    /// Root volume type for worker nodes (gp2, gp3, io1, io2)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_root_volume_type: Option<String>,

    /// Root volume IOPS for worker nodes (for io1, io2, gp3)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_root_volume_iops: Option<u32>,

    /// Root volume throughput for worker nodes (for gp3, in MiB/s)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_root_volume_throughput: Option<u32>,

    /// Encrypt root volume for worker nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_root_volume_encrypted: Option<bool>,

    /// Subnet ID specifically for worker nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_subnet_id: Option<String>,

    // ==========================================================================
    // Network
    // ==========================================================================

    /// Enable public IP for nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<bool>,
}
