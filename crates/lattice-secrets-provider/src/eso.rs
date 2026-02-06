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
    const API_VERSION: &'static str = "external-secrets.io/v1";
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

// =============================================================================
// ExternalSecret
// =============================================================================

/// ESO ExternalSecret resource
///
/// A namespace-scoped resource that syncs secrets from an external provider
/// (via ClusterSecretStore) into a Kubernetes Secret.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSecret {
    /// API version
    #[serde(default = "ExternalSecret::default_api_version")]
    pub api_version: String,
    /// Resource kind
    #[serde(default = "ExternalSecret::default_kind")]
    pub kind: String,
    /// Resource metadata
    pub metadata: ExternalSecretMetadata,
    /// ExternalSecret specification
    pub spec: ExternalSecretSpec,
}

impl HasApiResource for ExternalSecret {
    const API_VERSION: &'static str = "external-secrets.io/v1";
    const KIND: &'static str = "ExternalSecret";
}

impl ExternalSecret {
    fn default_api_version() -> String {
        <Self as HasApiResource>::API_VERSION.to_string()
    }
    fn default_kind() -> String {
        <Self as HasApiResource>::KIND.to_string()
    }

    /// Create a new ExternalSecret
    pub fn new(
        name: impl Into<String>,
        namespace: impl Into<String>,
        spec: ExternalSecretSpec,
    ) -> Self {
        Self {
            api_version: Self::default_api_version(),
            kind: Self::default_kind(),
            metadata: ExternalSecretMetadata::new(name, namespace),
            spec,
        }
    }
}

/// Metadata for ExternalSecret (namespace-scoped)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ExternalSecretMetadata {
    /// Resource name
    pub name: String,
    /// Resource namespace
    pub namespace: String,
    /// Labels
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

impl ExternalSecretMetadata {
    /// Create new metadata with standard Lattice labels
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        let name = name.into();
        let mut labels = BTreeMap::new();
        labels.insert(
            lattice_common::LABEL_MANAGED_BY.to_string(),
            lattice_common::LABEL_MANAGED_BY_LATTICE.to_string(),
        );
        Self {
            name,
            namespace: namespace.into(),
            labels,
        }
    }

    /// Add a label
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }
}

/// ExternalSecret spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSecretSpec {
    /// Reference to the secret store
    pub secret_store_ref: SecretStoreRef,
    /// Target Kubernetes Secret configuration
    pub target: ExternalSecretTarget,
    /// Key mappings from external secret to K8s secret
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data: Vec<ExternalSecretData>,
    /// Alternative: fetch all keys matching a path pattern
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_from: Option<Vec<ExternalSecretDataFrom>>,
    /// Refresh interval for syncing (e.g., "1h", "30m")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_interval: Option<String>,
}

/// Reference to a SecretStore or ClusterSecretStore
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretStoreRef {
    /// Name of the SecretStore/ClusterSecretStore
    pub name: String,
    /// Kind: "SecretStore" or "ClusterSecretStore"
    #[serde(default = "SecretStoreRef::default_kind")]
    pub kind: String,
}

impl SecretStoreRef {
    fn default_kind() -> String {
        "ClusterSecretStore".to_string()
    }

    /// Create a reference to a ClusterSecretStore
    pub fn cluster_secret_store(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: "ClusterSecretStore".to_string(),
        }
    }
}

/// Target Kubernetes Secret configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSecretTarget {
    /// Name of the Kubernetes Secret to create
    pub name: String,
    /// Creation policy: Owner, Orphan, Merge, None
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_policy: Option<String>,
    /// Deletion policy: Retain, Delete, Merge
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion_policy: Option<String>,
}

impl ExternalSecretTarget {
    /// Create a new target with just the name
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            creation_policy: None,
            deletion_policy: None,
        }
    }
}

/// Individual key mapping from external secret to K8s secret
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSecretData {
    /// Key in the resulting Kubernetes Secret
    pub secret_key: String,
    /// Reference to the external secret
    pub remote_ref: RemoteRef,
}

impl ExternalSecretData {
    /// Create a new data mapping
    pub fn new(secret_key: impl Into<String>, remote_ref: RemoteRef) -> Self {
        Self {
            secret_key: secret_key.into(),
            remote_ref,
        }
    }
}

/// Reference to a key in the external secret store
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RemoteRef {
    /// Path/key in the external secret store (e.g., Vault path)
    pub key: String,
    /// Specific property within the secret (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
}

impl RemoteRef {
    /// Create a reference to a full secret path
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            property: None,
        }
    }

    /// Create a reference to a specific property within a secret
    pub fn with_property(key: impl Into<String>, property: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            property: Some(property.into()),
        }
    }
}

/// Fetch all keys from a path (alternative to explicit data mappings)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSecretDataFrom {
    /// Extract from a specific path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extract: Option<ExternalSecretExtract>,
}

/// Extract configuration for dataFrom
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSecretExtract {
    /// Path to extract from
    pub key: String,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_secret_serialization() {
        let secret = ExternalSecret::new(
            "my-api-db-creds",
            "default",
            ExternalSecretSpec {
                secret_store_ref: SecretStoreRef::cluster_secret_store("vault-prod"),
                target: ExternalSecretTarget::new("my-api-db-creds"),
                data: vec![
                    ExternalSecretData::new(
                        "username",
                        RemoteRef::with_property("database/prod/credentials", "username"),
                    ),
                    ExternalSecretData::new(
                        "password",
                        RemoteRef::with_property("database/prod/credentials", "password"),
                    ),
                ],
                data_from: None,
                refresh_interval: Some("1h".to_string()),
            },
        );

        let json = serde_json::to_string_pretty(&secret).unwrap();
        assert!(json.contains("external-secrets.io/v1"));
        assert!(json.contains("ExternalSecret"));
        assert!(json.contains("vault-prod"));
        assert!(json.contains("ClusterSecretStore"));
        assert!(json.contains("database/prod/credentials"));

        // Verify round-trip
        let parsed: ExternalSecret = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, secret);
    }

    #[test]
    fn test_external_secret_data_from() {
        let secret = ExternalSecret::new(
            "all-secrets",
            "default",
            ExternalSecretSpec {
                secret_store_ref: SecretStoreRef::cluster_secret_store("vault"),
                target: ExternalSecretTarget::new("all-secrets"),
                data: vec![],
                data_from: Some(vec![ExternalSecretDataFrom {
                    extract: Some(ExternalSecretExtract {
                        key: "path/to/secrets".to_string(),
                    }),
                }]),
                refresh_interval: None,
            },
        );

        let json = serde_json::to_string_pretty(&secret).unwrap();
        assert!(json.contains("dataFrom"));
        assert!(json.contains("extract"));
        assert!(json.contains("path/to/secrets"));
    }

    #[test]
    fn test_secret_store_ref_default_kind() {
        let store_ref = SecretStoreRef::cluster_secret_store("my-store");
        assert_eq!(store_ref.kind, "ClusterSecretStore");
    }
}
