//! ImageProvider CRD for container image registry credentials
//!
//! An ImageProvider represents a named container registry account. The operator
//! compiles it into a `kubernetes.io/dockerconfigjson` Secret that can be
//! referenced as `imagePullSecrets` by operator deployments and workload pods.
//!
//! Distributed to child clusters via the resource sync, replacing the legacy
//! `lattice-registry` Secret approach.

use std::collections::BTreeMap;

use kube::{CustomResource, ResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::SecretRef;

/// ImageProvider defines credentials for a container image registry.
///
/// Shared across clusters — distributed via resource sync to all children.
/// The operator compiles each ImageProvider into a `kubernetes.io/dockerconfigjson`
/// Secret in `lattice-system` that the operator deployment and workload pods
/// can reference in `imagePullSecrets`.
///
/// Example (GHCR with Vault credentials):
/// ```yaml
/// apiVersion: lattice.dev/v1alpha1
/// kind: ImageProvider
/// metadata:
///   name: ghcr
/// spec:
///   type: ghcr
///   registry: ghcr.io
///   credentials:
///     id: ci/ghcr-token
///     provider: vault-prod
///     keys: [username, token]
///   credentialData:
///     .dockerconfigjson: |
///       {"auths":{"ghcr.io":{"auth":"${secret.credentials.username}:${secret.credentials.token}"}}}
/// ```
///
/// Example (ECR with IAM role — no credentials needed):
/// ```yaml
/// apiVersion: lattice.dev/v1alpha1
/// kind: ImageProvider
/// metadata:
///   name: ecr-prod
/// spec:
///   type: ecr
///   registry: 123456789.dkr.ecr.us-east-1.amazonaws.com
///   ecr:
///     region: us-east-1
///     accountId: "123456789"
/// ```
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "ImageProvider",
    namespaced,
    status = "ImageProviderStatus",
    printcolumn = r#"{"name":"Type","type":"string","jsonPath":".spec.type"}"#,
    printcolumn = r#"{"name":"Registry","type":"string","jsonPath":".spec.registry"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ImageProviderSpec {
    /// Registry type
    #[serde(rename = "type")]
    pub provider_type: ImageProviderType,

    /// Registry hostname (e.g., "ghcr.io", "docker.io", "123456789.dkr.ecr.us-east-1.amazonaws.com")
    pub registry: String,

    /// ESO-managed credential source. The controller creates an ExternalSecret
    /// that syncs credentials from a ClusterSecretStore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<super::types::CredentialSpec>,

    /// Template data for shaping credentials using `${secret.*}` syntax.
    /// Must produce a `.dockerconfigjson` key with valid Docker config JSON.
    /// Only valid when `credentials` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_data: Option<BTreeMap<String, String>>,

    /// ECR-specific configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecr: Option<EcrConfig>,
}

/// Supported image registry types
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ImageProviderType {
    /// GitHub Container Registry
    Ghcr,
    /// Docker Hub
    Dockerhub,
    /// AWS Elastic Container Registry
    Ecr,
    /// Google Artifact Registry / GCR
    Gar,
    /// Azure Container Registry
    Acr,
    /// Harbor
    Harbor,
    /// Generic OCI-compatible registry
    Generic,
}

impl std::fmt::Display for ImageProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ghcr => write!(f, "GHCR"),
            Self::Dockerhub => write!(f, "Docker Hub"),
            Self::Ecr => write!(f, "ECR"),
            Self::Gar => write!(f, "GAR"),
            Self::Acr => write!(f, "ACR"),
            Self::Harbor => write!(f, "Harbor"),
            Self::Generic => write!(f, "Generic"),
        }
    }
}

/// ECR-specific configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EcrConfig {
    /// AWS region
    pub region: String,

    /// AWS account ID
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
}

/// ImageProvider status
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ImageProviderStatus {
    /// Current phase
    #[serde(default)]
    pub phase: ImageProviderPhase,

    /// Human-readable message
    #[serde(default)]
    pub message: Option<String>,

    /// Generation of the spec that was last reconciled
    #[serde(default)]
    pub observed_generation: Option<i64>,
}

/// ImageProvider phase
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImageProviderPhase {
    /// Provider is being validated
    #[default]
    Pending,
    /// Credentials synced, ready for use
    Ready,
    /// Credential sync failed
    Failed,
}

impl std::fmt::Display for ImageProviderPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Ready => write!(f, "Ready"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

impl ImageProviderSpec {
    /// Validate the spec. Returns an error if invalid.
    pub fn validate(&self) -> Result<(), crate::ValidationError> {
        if self.registry.is_empty() {
            return Err(crate::ValidationError::new("registry cannot be empty"));
        }

        if let Some(ref credentials) = self.credentials {
            credentials.validate()?;
        }

        if self.credential_data.is_some() && self.credentials.is_none() {
            return Err(crate::ValidationError::new(
                "credentialData requires credentials to be set",
            ));
        }

        if self.provider_type == ImageProviderType::Ecr {
            let ecr = self
                .ecr
                .as_ref()
                .ok_or_else(|| crate::ValidationError::new("ecr config required when type is ecr"))?;
            if ecr.region.is_empty() {
                return Err(crate::ValidationError::new("ecr.region cannot be empty"));
            }
        }

        Ok(())
    }

    /// Create a minimal spec.
    pub fn new(provider_type: ImageProviderType, registry: &str) -> Self {
        Self {
            provider_type,
            registry: registry.to_string(),
            credentials: None,
            credential_data: None,
            ecr: None,
        }
    }
}

impl ImageProvider {
    /// Resolve the K8s Secret that contains registry credentials.
    ///
    /// Returns a synthetic ref pointing to the ESO-synced secret
    /// `{name}-credentials` in `lattice-system` namespace.
    /// Returns `None` if no credentials are configured.
    pub fn k8s_secret_ref(&self) -> Option<SecretRef> {
        self.spec
            .credentials
            .as_ref()
            .map(|_| SecretRef::for_credentials(&self.name_any(), crate::LATTICE_SYSTEM_NAMESPACE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::CredentialSpec;

    #[test]
    fn ghcr_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: ImageProvider
metadata:
  name: ghcr
spec:
  type: ghcr
  registry: ghcr.io
  credentials:
    id: ci/ghcr-token
    provider: vault-prod
    keys: [username, token]
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: ImageProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type, ImageProviderType::Ghcr);
        assert_eq!(provider.spec.registry, "ghcr.io");
        assert!(provider.spec.credentials.is_some());
        assert!(provider.spec.validate().is_ok());
    }

    #[test]
    fn ecr_requires_config() {
        let spec = ImageProviderSpec::new(
            ImageProviderType::Ecr,
            "123456789.dkr.ecr.us-east-1.amazonaws.com",
        );
        assert!(spec.validate().is_err());
    }

    #[test]
    fn ecr_with_config_valid() {
        let spec = ImageProviderSpec {
            ecr: Some(EcrConfig {
                region: "us-east-1".to_string(),
                account_id: Some("123456789".to_string()),
            }),
            ..ImageProviderSpec::new(
                ImageProviderType::Ecr,
                "123456789.dkr.ecr.us-east-1.amazonaws.com",
            )
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn empty_registry_fails_validation() {
        let spec = ImageProviderSpec::new(ImageProviderType::Ghcr, "");
        assert!(spec.validate().is_err());
    }

    #[test]
    fn generic_provider_valid() {
        let spec = ImageProviderSpec::new(ImageProviderType::Generic, "registry.example.com");
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn k8s_secret_ref_with_credentials() {
        let provider = ImageProvider::new(
            "ghcr",
            ImageProviderSpec {
                credentials: Some(CredentialSpec::test_with_keys(
                    "ci/ghcr",
                    "vault-prod",
                    &["token"],
                )),
                ..ImageProviderSpec::new(ImageProviderType::Ghcr, "ghcr.io")
            },
        );
        let secret_ref = provider.k8s_secret_ref().unwrap();
        assert_eq!(secret_ref.name, "ghcr-credentials");
        assert_eq!(secret_ref.namespace, crate::LATTICE_SYSTEM_NAMESPACE);
    }

    #[test]
    fn k8s_secret_ref_without_credentials() {
        let provider = ImageProvider::new(
            "ecr",
            ImageProviderSpec {
                ecr: Some(EcrConfig {
                    region: "us-east-1".to_string(),
                    account_id: None,
                }),
                ..ImageProviderSpec::new(
                    ImageProviderType::Ecr,
                    "123456789.dkr.ecr.us-east-1.amazonaws.com",
                )
            },
        );
        assert!(provider.k8s_secret_ref().is_none());
    }

    #[test]
    fn provider_type_display() {
        assert_eq!(ImageProviderType::Ghcr.to_string(), "GHCR");
        assert_eq!(ImageProviderType::Dockerhub.to_string(), "Docker Hub");
        assert_eq!(ImageProviderType::Ecr.to_string(), "ECR");
        assert_eq!(ImageProviderType::Generic.to_string(), "Generic");
    }

    #[test]
    fn phase_display() {
        assert_eq!(ImageProviderPhase::Pending.to_string(), "Pending");
        assert_eq!(ImageProviderPhase::Ready.to_string(), "Ready");
        assert_eq!(ImageProviderPhase::Failed.to_string(), "Failed");
    }

    #[test]
    fn credential_data_yaml_parsing() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: ImageProvider
metadata:
  name: harbor-prod
spec:
  type: harbor
  registry: harbor.internal.com
  credentials:
    id: ci/harbor
    provider: vault-prod
    keys: [username, password]
  credentialData:
    .dockerconfigjson: |
      {"auths":{"harbor.internal.com":{"auth":"${secret.credentials.username}:${secret.credentials.password}"}}}
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: ImageProvider = serde_json::from_value(value).expect("parse");
        assert!(provider.spec.credentials.is_some());
        assert!(provider.spec.credential_data.is_some());
        let data = provider.spec.credential_data.as_ref().unwrap();
        assert!(data.contains_key(".dockerconfigjson"));
    }
}
