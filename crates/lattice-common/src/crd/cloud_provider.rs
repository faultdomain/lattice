//! CloudProvider CRD for registering cloud accounts/credentials
//!
//! A CloudProvider represents a named cloud account that clusters can reference.

use kube::{CustomResource, ResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::types::SecretRef;
use super::workload::resources::ResourceSpec;
use crate::LATTICE_SYSTEM_NAMESPACE;

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

    /// Reference to secret containing provider credentials.
    /// Manual mode: operator creates a K8s Secret and references it here.
    /// Mutually exclusive with `credentials`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_secret_ref: Option<SecretRef>,

    /// ESO-managed credential source. Same ResourceSpec as LatticeService secrets.
    /// The controller creates an ExternalSecret that syncs credentials from a
    /// ClusterSecretStore. Mutually exclusive with `credentialsSecretRef`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<ResourceSpec>,

    /// Template data for shaping credentials using `${secret.*}` syntax.
    /// Each key becomes a key in the resulting K8s Secret.
    /// Values can use `${secret.credentials.KEY}` to inject secret values.
    /// Only valid when `credentials` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_data: Option<BTreeMap<String, String>>,

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

    /// Generation of the spec that was last reconciled
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
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
    /// Resolve the K8s Secret that contains provider credentials.
    ///
    /// - ESO mode (`credentials` set): returns a synthetic ref pointing to the
    ///   ESO-synced secret `{name}-credentials` in `lattice-system`.
    /// - Manual mode (`credentialsSecretRef` set): returns the user-provided ref.
    /// - Neither set: returns `None`.
    pub fn k8s_secret_ref(&self) -> Option<SecretRef> {
        if self.spec.credentials.is_some() {
            Some(SecretRef {
                name: format!("{}-credentials", self.name_any()),
                namespace: LATTICE_SYSTEM_NAMESPACE.to_string(),
            })
        } else {
            self.spec.credentials_secret_ref.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::ResourceType;

    fn make_provider(name: &str, spec: CloudProviderSpec) -> CloudProvider {
        CloudProvider::new(name, spec)
    }

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
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: CloudProvider = serde_json::from_value(value).expect("parse");
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
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: CloudProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type, CloudProviderType::Proxmox);
    }

    // =========================================================================
    // k8s_secret_ref() Tests
    // =========================================================================

    #[test]
    fn k8s_secret_ref_manual_mode() {
        let cp = make_provider(
            "aws-prod",
            CloudProviderSpec {
                provider_type: CloudProviderType::AWS,
                region: None,
                credentials_secret_ref: Some(SecretRef {
                    name: "my-manual-secret".to_string(),
                    namespace: "lattice-system".to_string(),
                }),
                credentials: None,
                credential_data: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        );

        let secret_ref = cp.k8s_secret_ref().expect("should have secret ref");
        assert_eq!(secret_ref.name, "my-manual-secret");
        assert_eq!(secret_ref.namespace, "lattice-system");
    }

    #[test]
    fn k8s_secret_ref_eso_mode() {
        let mut params = BTreeMap::new();
        params.insert("provider".to_string(), serde_json::json!("vault-prod"));

        let cp = make_provider(
            "aws-prod",
            CloudProviderSpec {
                provider_type: CloudProviderType::AWS,
                region: None,
                credentials_secret_ref: None,
                credentials: Some(ResourceSpec {
                    type_: ResourceType::Secret,
                    id: Some("infrastructure/aws/prod".to_string()),
                    params: Some(params),
                    ..Default::default()
                }),
                credential_data: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        );

        let secret_ref = cp.k8s_secret_ref().expect("should have secret ref");
        assert_eq!(secret_ref.name, "aws-prod-credentials");
        assert_eq!(secret_ref.namespace, LATTICE_SYSTEM_NAMESPACE);
    }

    #[test]
    fn k8s_secret_ref_none() {
        let cp = make_provider(
            "docker",
            CloudProviderSpec {
                provider_type: CloudProviderType::Docker,
                region: None,
                credentials_secret_ref: None,
                credentials: None,
                credential_data: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        );

        assert!(cp.k8s_secret_ref().is_none());
    }

    #[test]
    fn credential_data_yaml_parsing() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: CloudProvider
metadata:
  name: openstack-prod
spec:
  type: openstack
  credentials:
    type: secret
    id: infrastructure/openstack/credentials
    params:
      provider: vault-prod
      keys:
        - username
        - password
        - auth_url
  credentialData:
    clouds.yaml: |
      clouds:
        openstack:
          auth:
            username: "${secret.credentials.username}"
            password: "${secret.credentials.password}"
            auth_url: "${secret.credentials.auth_url}"
  openstack:
    authUrl: https://openstack.example.com:5000/v3
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: CloudProvider = serde_json::from_value(value).expect("parse");

        assert_eq!(provider.spec.provider_type, CloudProviderType::OpenStack);
        assert!(provider.spec.credentials.is_some());
        assert!(provider.spec.credential_data.is_some());

        let creds = provider.spec.credentials.as_ref().unwrap();
        assert!(creds.type_.is_secret());
        assert_eq!(
            creds.id,
            Some("infrastructure/openstack/credentials".to_string())
        );

        let data = provider.spec.credential_data.as_ref().unwrap();
        assert!(data.contains_key("clouds.yaml"));
        assert!(data["clouds.yaml"].contains("${secret.credentials.username}"));

        // ESO mode should generate synthetic ref
        let secret_ref = provider.k8s_secret_ref().expect("should have secret ref");
        assert_eq!(secret_ref.name, "openstack-prod-credentials");
    }

    #[test]
    fn eso_credentials_take_priority_over_manual() {
        let mut params = BTreeMap::new();
        params.insert("provider".to_string(), serde_json::json!("vault"));

        let cp = make_provider(
            "test",
            CloudProviderSpec {
                provider_type: CloudProviderType::AWS,
                region: None,
                credentials_secret_ref: Some(SecretRef {
                    name: "manual".to_string(),
                    namespace: "default".to_string(),
                }),
                credentials: Some(ResourceSpec {
                    type_: ResourceType::Secret,
                    id: Some("path".to_string()),
                    params: Some(params),
                    ..Default::default()
                }),
                credential_data: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        );

        // ESO mode takes priority
        let secret_ref = cp.k8s_secret_ref().unwrap();
        assert_eq!(secret_ref.name, "test-credentials");
    }
}
