//! SecretsProvider CRD for Vault integration
//!
//! A SecretsProvider represents a connection to HashiCorp Vault that can be
//! distributed to child clusters, creating ESO ClusterSecretStore automatically.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::SecretRef;

/// SecretsProvider defines a Vault connection for ESO integration.
///
/// When distributed to child clusters, this creates the corresponding ESO
/// ClusterSecretStore automatically.
///
/// Example:
/// ```yaml
/// apiVersion: lattice.dev/v1alpha1
/// kind: SecretsProvider
/// metadata:
///   name: vault-prod
/// spec:
///   server: https://vault.example.com
///   path: secret/data/lattice
///   authMethod: kubernetes
///   kubernetesRole: lattice
///   credentialsSecretRef:
///     name: vault-token
/// ```
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "SecretsProvider",
    namespaced,
    status = "SecretsProviderStatus",
    printcolumn = r#"{"name":"Server","type":"string","jsonPath":".spec.server"}"#,
    printcolumn = r#"{"name":"Auth","type":"string","jsonPath":".spec.authMethod"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct SecretsProviderSpec {
    /// Vault server URL
    pub server: String,

    /// Path prefix for secrets (e.g., "secret/data/lattice")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Authentication method
    #[serde(default)]
    pub auth_method: VaultAuthMethod,

    /// Reference to secret containing Vault credentials
    /// Required for token auth (contains VAULT_TOKEN)
    /// Optional for kubernetes auth (uses ServiceAccount)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_secret_ref: Option<SecretRef>,

    /// Kubernetes auth mount path (default: "kubernetes")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_mount_path: Option<String>,

    /// Kubernetes auth role
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes_role: Option<String>,

    /// Vault namespace (enterprise feature)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// CA certificate for TLS verification (PEM format)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle: Option<String>,
}

/// Vault authentication methods
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum VaultAuthMethod {
    /// Token-based auth (credentialsSecretRef contains VAULT_TOKEN)
    #[default]
    Token,
    /// Kubernetes ServiceAccount auth
    Kubernetes,
    /// AppRole auth (credentialsSecretRef contains role_id and secret_id)
    AppRole,
}

/// SecretsProvider status
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretsProviderStatus {
    /// Current phase
    #[serde(default)]
    pub phase: SecretsProviderPhase,

    /// Human-readable message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Last time connection was validated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_validated: Option<String>,
}

/// SecretsProvider phase
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum SecretsProviderPhase {
    /// Provider is being validated
    #[default]
    Pending,
    /// Connection validated, ready for use
    Ready,
    /// Connection validation failed
    Failed,
}

impl SecretsProvider {
    /// Get the credentials secret reference
    pub fn credentials_secret_ref(&self) -> Option<&SecretRef> {
        self.spec.credentials_secret_ref.as_ref()
    }

    /// Get the ESO ClusterSecretStore name (same as SecretsProvider name)
    pub fn secret_store_name(&self) -> &str {
        self.metadata.name.as_deref().unwrap_or("default")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_token_auth_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: SecretsProvider
metadata:
  name: vault-prod
spec:
  server: https://vault.example.com
  path: secret/data/lattice
  authMethod: token
  credentialsSecretRef:
    name: vault-token
"#;
        let provider: SecretsProvider = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(provider.spec.server, "https://vault.example.com");
        assert_eq!(provider.spec.auth_method, VaultAuthMethod::Token);
    }

    #[test]
    fn vault_kubernetes_auth_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: SecretsProvider
metadata:
  name: vault-k8s
spec:
  server: https://vault.example.com
  authMethod: kubernetes
  kubernetesRole: lattice
  kubernetesMountPath: kubernetes
"#;
        let provider: SecretsProvider = serde_yaml::from_str(yaml).expect("parse");
        assert_eq!(provider.spec.auth_method, VaultAuthMethod::Kubernetes);
        assert_eq!(provider.spec.kubernetes_role, Some("lattice".to_string()));
    }
}
