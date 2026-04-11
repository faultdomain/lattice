//! InfraProvider CRD for registering cloud accounts/credentials
//!
//! A InfraProvider represents a named cloud account that clusters can reference.

use kube::{CustomResource, ResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::types::credential_secret_name;

/// InfraProvider defines a cloud account/region that clusters can be deployed to.
///
/// Example:
/// ```yaml
/// apiVersion: lattice.dev/v1alpha1
/// kind: InfraProvider
/// metadata:
///   name: aws-prod
/// spec:
///   type: AWS
///   region: us-east-1
///   credentials:
///     id: infrastructure/aws/prod
///     provider: lattice-local
///     keys: [AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY]
///   aws:
///     vpcId: vpc-xxx
///     subnetIds: [subnet-a, subnet-b]
/// ```
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "InfraProvider",
    namespaced,
    status = "InfraProviderStatus",
    printcolumn = r#"{"name":"Type","type":"string","jsonPath":".spec.type"}"#,
    printcolumn = r#"{"name":"Region","type":"string","jsonPath":".spec.region"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct InfraProviderSpec {
    /// Cloud provider type
    #[serde(rename = "type")]
    pub provider_type: InfraProviderType,

    /// Region/location for this provider
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// ESO-managed credential source. The controller creates an ExternalSecret
    /// that syncs credentials from a ClusterSecretStore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<super::types::CredentialSpec>,

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
#[non_exhaustive]
pub enum InfraProviderType {
    /// Amazon Web Services
    AWS,
    /// Proxmox VE (on-premises)
    Proxmox,
    /// OpenStack (private cloud)
    OpenStack,
    /// Docker/Kind (local development)
    Docker,
}

impl std::fmt::Display for InfraProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AWS => write!(f, "AWS"),
            Self::Proxmox => write!(f, "Proxmox"),
            Self::OpenStack => write!(f, "OpenStack"),
            Self::Docker => write!(f, "Docker"),
        }
    }
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

/// InfraProvider status
///
/// All optional fields serialize as `null` (no `skip_serializing_if`) so that
/// merge-patch status updates correctly clear stale values.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InfraProviderStatus {
    /// Current phase
    #[serde(default)]
    pub phase: InfraProviderPhase,

    /// Human-readable message
    #[serde(default)]
    pub message: Option<String>,

    /// Last time credentials were validated
    #[serde(default)]
    pub last_validated: Option<String>,

    /// Number of clusters using this provider
    #[serde(default)]
    pub cluster_count: u32,

    /// Generation of the spec that was last reconciled
    #[serde(default)]
    pub observed_generation: Option<i64>,
}

/// InfraProvider phase
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum InfraProviderPhase {
    /// Provider is being validated
    #[default]
    Pending,
    /// Credentials validated, ready for use
    Ready,
    /// Credential validation failed
    Failed,
}

impl std::fmt::Display for InfraProviderPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Ready => write!(f, "Ready"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

impl InfraProviderSpec {
    /// Validate the spec. Returns an error if invalid.
    pub fn validate(&self) -> Result<(), crate::ValidationError> {
        // Validate credentials if present
        if let Some(ref credentials) = self.credentials {
            credentials.validate()?;
        }

        // credentialData requires credentials
        if self.credential_data.is_some() && self.credentials.is_none() {
            return Err(crate::ValidationError::new(
                "credentialData requires credentials to be set",
            ));
        }

        // Provider-type-specific config validation
        match self.provider_type {
            InfraProviderType::AWS => {
                // AWS provider doesn't strictly require aws config (it's optional BYOI),
                // but does require credentials
                if self.credentials.is_none() {
                    return Err(crate::ValidationError::new(
                        "AWS provider requires credentials",
                    ));
                }
            }
            InfraProviderType::Proxmox => {
                if self.credentials.is_none() {
                    return Err(crate::ValidationError::new(
                        "Proxmox provider requires credentials",
                    ));
                }
                let proxmox = self.proxmox.as_ref().ok_or_else(|| {
                    crate::ValidationError::new("proxmox config required when type is proxmox")
                })?;
                if proxmox.server_url.is_empty() {
                    return Err(crate::ValidationError::new(
                        "proxmox.serverUrl cannot be empty",
                    ));
                }
            }
            InfraProviderType::OpenStack => {
                if self.credentials.is_none() {
                    return Err(crate::ValidationError::new(
                        "OpenStack provider requires credentials",
                    ));
                }
                let openstack = self.openstack.as_ref().ok_or_else(|| {
                    crate::ValidationError::new("openstack config required when type is openstack")
                })?;
                if openstack.auth_url.is_empty() {
                    return Err(crate::ValidationError::new(
                        "openstack.authUrl cannot be empty",
                    ));
                }
            }
            InfraProviderType::Docker => {
                // Docker providers require no credentials or provider-specific config
            }
        }

        Ok(())
    }
}

impl InfraProvider {
    /// Returns the ESO-synced credential secret name (`{name}-credentials`).
    /// `None` if no credentials are configured (e.g., Docker provider).
    /// Callers create ExternalSecrets in whichever namespace they need.
    pub fn credential_secret_name(&self) -> Option<String> {
        self.spec
            .credentials
            .as_ref()
            .map(|_| credential_secret_name(&self.name_any()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::CredentialSpec;

    #[test]
    fn aws_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: aws-prod
spec:
  type: aws
  region: us-east-1
  credentials:
    id: infra/aws/prod
    provider: lattice-local
  aws:
    vpcId: vpc-xxx
    subnetIds:
      - subnet-a
      - subnet-b
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: InfraProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type, InfraProviderType::AWS);
        assert_eq!(provider.spec.region, Some("us-east-1".to_string()));
        assert!(provider.spec.credentials.is_some());
    }

    #[test]
    fn proxmox_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: proxmox-lab
spec:
  type: proxmox
  credentials:
    id: proxmox-creds
    provider: lattice-local
  proxmox:
    serverUrl: https://pve.local:8006
    node: pve1
    storage: local-lvm
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: InfraProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type, InfraProviderType::Proxmox);
        assert!(provider.spec.credentials.is_some());
    }

    #[test]
    fn k8s_secret_ref_with_credentials() {
        let cp = InfraProvider::new(
            "aws-prod",
            InfraProviderSpec {
                provider_type: InfraProviderType::AWS,
                region: None,
                credentials: Some(CredentialSpec::test("infra/aws/prod", "vault-prod")),
                credential_data: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        );

        let name = cp.credential_secret_name().unwrap();
        assert_eq!(name, "aws-prod-credentials");
    }

    #[test]
    fn credential_secret_name_without_credentials() {
        let cp = InfraProvider::new(
            "docker",
            InfraProviderSpec {
                provider_type: InfraProviderType::Docker,
                region: None,
                credentials: None,
                credential_data: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        );

        assert!(cp.credential_secret_name().is_none());
    }

    #[test]
    fn credential_data_yaml_parsing() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: InfraProvider
metadata:
  name: openstack-prod
spec:
  type: openstack
  credentials:
    id: infrastructure/openstack/credentials
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
        let provider: InfraProvider = serde_json::from_value(value).expect("parse");

        assert_eq!(provider.spec.provider_type, InfraProviderType::OpenStack);
        assert!(provider.spec.credentials.is_some());
        assert!(provider.spec.credential_data.is_some());

        assert!(provider.spec.credentials.is_some());
        let data = provider.spec.credential_data.as_ref().unwrap();
        assert!(data.contains_key("clouds.yaml"));
        assert!(data["clouds.yaml"].contains("${secret.credentials.username}"));

        let name = provider.credential_secret_name().unwrap();
        assert_eq!(name, "openstack-prod-credentials");
    }
}
