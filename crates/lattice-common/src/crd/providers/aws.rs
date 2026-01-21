//! AWS provider configuration (CAPA)
//!
//! This provider generates Cluster API manifests for provisioning Kubernetes
//! clusters on AWS using the CAPA provider.
//!
//! Reference: <https://github.com/kubernetes-sigs/cluster-api-provider-aws>

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// AWS provider configuration (CAPA)
///
/// Configuration for provisioning clusters on AWS.
/// Uses NLB for API server load balancing.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AwsConfig {
    // ==========================================================================
    // Required Fields
    // ==========================================================================
    /// AWS region (e.g., "us-west-2", "eu-west-1")
    pub region: String,

    /// EC2 instance type for control plane nodes (e.g., "m5.xlarge")
    pub cp_instance_type: String,

    /// EC2 instance type for worker nodes (e.g., "m5.large")
    pub worker_instance_type: String,

    /// SSH key name registered in AWS for node access
    pub ssh_key_name: String,

    // ==========================================================================
    // IAM Configuration (Optional - uses CAPA defaults)
    // ==========================================================================
    /// IAM instance profile for control plane nodes
    /// Default: "control-plane.cluster-api-provider-aws.sigs.k8s.io"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_iam_instance_profile: Option<String>,

    /// IAM instance profile for worker nodes
    /// Default: "nodes.cluster-api-provider-aws.sigs.k8s.io"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_iam_instance_profile: Option<String>,

    // ==========================================================================
    // VPC Configuration (Optional - CAPA creates default VPC)
    // ==========================================================================
    /// Existing VPC ID to use (CAPA creates a new VPC if not specified)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpc_id: Option<String>,

    /// Subnet IDs for control plane (required if vpc_id is set)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_subnet_ids: Option<Vec<String>>,

    /// Subnet IDs for workers (required if vpc_id is set)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_subnet_ids: Option<Vec<String>>,

    // ==========================================================================
    // Load Balancer Configuration (Optional)
    // ==========================================================================
    /// Load balancer type for API server: "nlb" (default) or "classic"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_balancer_type: Option<String>,

    // ==========================================================================
    // Root Volume (Optional)
    // ==========================================================================
    /// Root volume size in GB for control plane (default: 80)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_root_volume_size_gb: Option<u32>,

    /// Root volume type for control plane (e.g., "gp3", "io1")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_root_volume_type: Option<String>,

    /// Root volume size in GB for workers (default: 80)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_root_volume_size_gb: Option<u32>,

    /// Root volume type for workers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_root_volume_type: Option<String>,

    // ==========================================================================
    // AMI Configuration (Optional - uses CAPA default)
    // ==========================================================================
    /// AMI ID for nodes (CAPA uses latest Ubuntu if not specified)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ami_id: Option<String>,

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
        let config = AwsConfig {
            region: "us-west-2".to_string(),
            cp_instance_type: "m5.xlarge".to_string(),
            worker_instance_type: "m5.large".to_string(),
            ssh_key_name: "my-key".to_string(),
            ..Default::default()
        };

        let yaml = serde_yaml::to_string(&config).expect("AwsConfig serialization should succeed");
        assert!(yaml.contains("region: us-west-2"));
        assert!(yaml.contains("cpInstanceType: m5.xlarge"));

        let parsed: AwsConfig =
            serde_yaml::from_str(&yaml).expect("AwsConfig deserialization should succeed");
        assert_eq!(parsed, config);
    }

    #[test]
    fn minimal_config() {
        let yaml = r#"
region: us-east-1
cpInstanceType: m5.xlarge
workerInstanceType: m5.large
sshKeyName: default
"#;
        let config: AwsConfig =
            serde_yaml::from_str(yaml).expect("minimal AwsConfig deserialization should succeed");
        assert_eq!(config.region, "us-east-1");
        assert_eq!(config.cp_instance_type, "m5.xlarge");
        assert!(config.vpc_id.is_none());
    }

    #[test]
    fn full_config_with_vpc() {
        let yaml = r#"
region: eu-west-1
cpInstanceType: m5.2xlarge
workerInstanceType: m5.xlarge
sshKeyName: lattice-key
vpcId: vpc-12345
cpSubnetIds:
  - subnet-cp-1
  - subnet-cp-2
workerSubnetIds:
  - subnet-worker-1
loadBalancerType: nlb
cpRootVolumeSizeGb: 100
cpRootVolumeType: gp3
workerRootVolumeSizeGb: 200
"#;
        let config: AwsConfig =
            serde_yaml::from_str(yaml).expect("full AwsConfig deserialization should succeed");
        assert_eq!(config.vpc_id, Some("vpc-12345".to_string()));
        assert_eq!(config.cp_root_volume_size_gb, Some(100));
        assert_eq!(config.load_balancer_type, Some("nlb".to_string()));
    }
}
