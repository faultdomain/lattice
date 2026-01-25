//! CloudProvider CRD for registering cloud accounts/credentials
//!
//! A CloudProvider represents a named cloud account that clusters can reference.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::types::SecretRef;

/// CloudProvider defines a cloud account/region that clusters can be deployed to.
///
/// Example:
/// ```yaml
/// apiVersion: lattice.dev/v1alpha1
/// kind: CloudProvider
/// metadata:
///   name: aws-prod
/// spec:
///   type: AWS
///   region: us-east-1
///   credentialsSecretRef:
///     name: aws-prod-creds
///   aws:
///     vpcId: vpc-xxx
///     subnetIds: [subnet-a, subnet-b]
/// ```
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "CloudProvider",
    namespaced,
    status = "CloudProviderStatus",
    printcolumn = r#"{"name":"Type","type":"string","jsonPath":".spec.type"}"#,
    printcolumn = r#"{"name":"Region","type":"string","jsonPath":".spec.region"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct CloudProviderSpec {
    /// Cloud provider type
    #[serde(rename = "type")]
    pub provider_type: CloudProviderType,

    /// Region/location for this provider
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// Reference to secret containing provider credentials
    /// Optional for Docker provider, required for cloud providers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_secret_ref: Option<SecretRef>,

    /// AWS-specific configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws: Option<AwsProviderConfig>,

    /// Proxmox-specific configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxmox: Option<ProxmoxProviderConfig>,

    /// OpenStack-specific configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openstack: Option<OpenStackProviderConfig>,

    /// Labels for cluster selector matching
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// Supported cloud provider types
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CloudProviderType {
    /// Amazon Web Services
    AWS,
    /// Proxmox VE (on-premises)
    Proxmox,
    /// OpenStack (private cloud)
    OpenStack,
    /// Docker/Kind (local development)
    Docker,
}

/// AWS-specific provider configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AwsProviderConfig {
    /// Existing VPC ID (BYOI)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpc_id: Option<String>,

    /// Existing subnet IDs (BYOI)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet_ids: Option<Vec<String>>,

    /// SSH key name for node access
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key_name: Option<String>,

    /// IAM role ARN for CAPA to assume
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_arn: Option<String>,
}

/// Proxmox-specific provider configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxProviderConfig {
    /// Proxmox server URL
    pub server_url: String,

    /// Proxmox node name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,

    /// Storage pool for VM disks
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
}

/// OpenStack-specific provider configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OpenStackProviderConfig {
    /// OpenStack auth URL
    pub auth_url: String,

    /// Existing network ID (BYOI)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,

    /// Floating IP pool for external access
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floating_ip_pool: Option<String>,
}

/// CloudProvider status
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CloudProviderStatus {
    /// Current phase
    #[serde(default)]
    pub phase: CloudProviderPhase,

    /// Human-readable message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Last time credentials were validated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_validated: Option<String>,

    /// Number of clusters using this provider
    #[serde(default)]
    pub cluster_count: u32,
}

/// CloudProvider phase
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum CloudProviderPhase {
    /// Provider is being validated
    #[default]
    Pending,
    /// Credentials validated, ready for use
    Ready,
    /// Credential validation failed
    Failed,
}

impl CloudProvider {
    /// Get the provider type
    pub fn provider_type(&self) -> CloudProviderType {
        self.spec.provider_type
    }

    /// Get the region
    pub fn region(&self) -> Option<&str> {
        self.spec.region.as_deref()
    }

    /// Get the credentials secret reference
    pub fn credentials_secret_ref(&self) -> Option<&SecretRef> {
        self.spec.credentials_secret_ref.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: CloudProvider
metadata:
  name: aws-prod
spec:
  type: aws
  region: us-east-1
  credentialsSecretRef:
    name: aws-prod-creds
  aws:
    vpcId: vpc-xxx
    subnetIds:
      - subnet-a
      - subnet-b
"#;
        let provider: CloudProvider = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(provider.spec.provider_type, CloudProviderType::AWS);
        assert_eq!(provider.spec.region, Some("us-east-1".to_string()));
    }

    #[test]
    fn proxmox_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: CloudProvider
metadata:
  name: proxmox-lab
spec:
  type: proxmox
  credentialsSecretRef:
    name: proxmox-creds
  proxmox:
    serverUrl: https://pve.local:8006
    node: pve1
    storage: local-lvm
"#;
        let provider: CloudProvider = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(provider.spec.provider_type, CloudProviderType::Proxmox);
    }
}
