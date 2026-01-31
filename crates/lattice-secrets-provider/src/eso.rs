//! External Secrets Operator (ESO) types
//!
//! Typed structs for ESO ClusterSecretStore resources. These implement
//! `HasApiResource` for consistent API version handling.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use lattice_common::kube_utils::HasApiResource;

// =============================================================================
// ClusterSecretStore
// =============================================================================

/// ESO ClusterSecretStore resource
///
/// A cluster-scoped SecretStore that can be referenced by ExternalSecrets
/// across all namespaces.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClusterSecretStore {
    /// API version
    #[serde(default = "ClusterSecretStore::default_api_version")]
    pub api_version: String,
    /// Resource kind
    #[serde(default = "ClusterSecretStore::default_kind")]
    pub kind: String,
    /// Resource metadata
    pub metadata: ClusterSecretStoreMetadata,
    /// Store specification
    pub spec: ClusterSecretStoreSpec,
}

impl HasApiResource for ClusterSecretStore {
    const API_VERSION: &'static str = "external-secrets.io/v1beta1";
    const KIND: &'static str = "ClusterSecretStore";
}

impl ClusterSecretStore {
    fn default_api_version() -> String {
        <Self as HasApiResource>::API_VERSION.to_string()
    }
    fn default_kind() -> String {
        <Self as HasApiResource>::KIND.to_string()
    }

    /// Create a new ClusterSecretStore
    pub fn new(name: impl Into<String>, spec: ClusterSecretStoreSpec) -> Self {
        Self {
            api_version: Self::default_api_version(),
            kind: Self::default_kind(),
            metadata: ClusterSecretStoreMetadata::new(name),
            spec,
        }
    }
}

/// Metadata for ClusterSecretStore (cluster-scoped, no namespace)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ClusterSecretStoreMetadata {
    /// Resource name
    pub name: String,
    /// Labels
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

impl ClusterSecretStoreMetadata {
    /// Create new metadata with standard Lattice labels
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        let mut labels = BTreeMap::new();
        labels.insert(
            lattice_common::LABEL_MANAGED_BY.to_string(),
            lattice_common::LABEL_MANAGED_BY_LATTICE.to_string(),
        );
        labels.insert("lattice.dev/secrets-provider".to_string(), name.clone());
        Self { name, labels }
    }
}

/// ClusterSecretStore spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ClusterSecretStoreSpec {
    /// Provider configuration
    pub provider: ProviderSpec,
}

/// Provider specification (currently only Vault is supported)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProviderSpec {
    /// Vault provider configuration
    pub vault: VaultProvider,
}

/// Vault provider configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VaultProvider {
    /// Vault server URL
    pub server: String,
    /// Path to secrets (e.g., "secret")
    pub path: String,
    /// Vault KV version
    pub version: String,
    /// Vault namespace (optional, for enterprise)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// CA bundle for TLS verification
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle: Option<String>,
    /// Authentication configuration
    pub auth: VaultAuth,
}

/// Vault authentication configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VaultAuth {
    /// Token authentication
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_secret_ref: Option<SecretKeyRef>,
    /// Kubernetes authentication
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<KubernetesAuth>,
    /// AppRole authentication
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_role: Option<AppRoleAuth>,
}

/// Reference to a secret key
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SecretKeyRef {
    /// Secret name
    pub name: String,
    /// Secret namespace
    pub namespace: String,
    /// Key within the secret
    pub key: String,
}

/// Kubernetes auth configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KubernetesAuth {
    /// Mount path in Vault
    pub mount_path: String,
    /// Role name
    pub role: String,
    /// Service account reference
    pub service_account_ref: ServiceAccountRef,
}

/// Reference to a service account
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceAccountRef {
    /// Service account name
    pub name: String,
    /// Service account namespace
    pub namespace: String,
}

/// AppRole auth configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppRoleAuth {
    /// Mount path in Vault
    pub path: String,
    /// Reference to role_id secret key
    pub role_ref: SecretKeyRef,
    /// Reference to secret_id secret key
    pub secret_ref: SecretKeyRef,
}
