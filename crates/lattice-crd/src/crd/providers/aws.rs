//! AWS provider configuration (CAPA)
//!
//! Reference: <https://github.com/kubernetes-sigs/cluster-api-provider-aws>
//! BYOI: <https://cluster-api-aws.sigs.k8s.io/topics/bring-your-own-aws-infrastructure>

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// AWS provider configuration (CAPA)
///
/// Supports both managed infrastructure (CAPA creates VPC/subnets) and
/// BYOI (Bring Your Own Infrastructure) where you provide existing resources.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AwsConfig {
    /// AWS region (e.g., "us-west-2")
    pub region: String,

    /// SSH key name registered in AWS for node access
    pub ssh_key_name: String,

    /// IAM instance profile for control plane nodes
    /// Default: "control-plane.cluster-api-provider-aws.sigs.k8s.io"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cp_iam_instance_profile: Option<String>,

    /// IAM instance profile for worker nodes
    /// Default: "nodes.cluster-api-provider-aws.sigs.k8s.io"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_iam_instance_profile: Option<String>,

    /// Existing VPC ID for BYOI. CAPA reuses this VPC instead of creating one.
    /// Requires subnet_ids to also be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpc_id: Option<String>,

    /// Existing subnet IDs for BYOI. CAPA auto-discovers AZ and public/private.
    /// Required when vpc_id is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet_ids: Option<Vec<String>>,

    /// Load balancer type for API server: "nlb" (default) or "classic"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_balancer_type: Option<String>,

    /// Use internal (private) load balancer for API server.
    /// When true, the API server is only accessible from within the VPC.
    /// Default: false (public load balancer)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal_load_balancer: Option<bool>,

    /// AMI ID for nodes (CAPA uses latest Ubuntu if not specified)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ami_id: Option<String>,

    /// Additional SSH authorized keys for node access
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_authorized_keys: Option<Vec<String>>,
}

impl AwsConfig {
    /// Check if this is a BYOI configuration
    pub fn is_byoi(&self) -> bool {
        self.vpc_id.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config() {
        let yaml = r#"
region: us-east-1
sshKeyName: default
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let config: AwsConfig = serde_json::from_value(value).expect("deserialization");
        assert_eq!(config.region, "us-east-1");
        assert!(!config.is_byoi());
    }

    #[test]
    fn byoi_config() {
        let yaml = r#"
region: us-west-2
sshKeyName: lattice-key
vpcId: vpc-0425c335226437144
subnetIds:
  - subnet-0261219d564bb0dc5
  - subnet-0fdcccba78668e013
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let config: AwsConfig = serde_json::from_value(value).expect("deserialization");
        assert!(config.is_byoi());
        assert_eq!(config.vpc_id, Some("vpc-0425c335226437144".to_string()));
        assert_eq!(config.subnet_ids.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn full_managed_config() {
        let yaml = r#"
region: eu-west-1
sshKeyName: lattice-key
loadBalancerType: nlb
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let config: AwsConfig = serde_json::from_value(value).expect("deserialization");
        assert!(!config.is_byoi());
        assert_eq!(config.load_balancer_type, Some("nlb".to_string()));
    }

    #[test]
    fn private_cluster_config() {
        let yaml = r#"
region: us-west-2
sshKeyName: lattice-key
internalLoadBalancer: true
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let config: AwsConfig = serde_json::from_value(value).expect("deserialization");
        assert_eq!(config.internal_load_balancer, Some(true));
    }
}
