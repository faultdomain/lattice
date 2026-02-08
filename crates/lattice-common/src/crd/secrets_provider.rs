//! SecretsProvider CRD for ESO integration
//!
//! A SecretsProvider wraps an ESO `ClusterSecretStore.spec.provider` configuration.
//! The `spec.provider` field is passed through verbatim — users write native ESO
//! provider YAML and Lattice manages the ClusterSecretStore lifecycle.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// SecretsProvider defines an ESO provider configuration.
///
/// When created, the controller creates a corresponding ESO ClusterSecretStore
/// whose `spec.provider` is populated verbatim from `spec.provider`.
///
/// Example (AWS Secrets Manager):
/// ```yaml
/// apiVersion: lattice.dev/v1alpha1
/// kind: SecretsProvider
/// metadata:
///   name: team-b-store
/// spec:
///   provider:
///     aws:
///       service: SecretsManager
///       region: eu-central-1
///       auth:
///         secretRef:
///           accessKeyIDSecretRef:
///             name: awssm-secret
///             key: access-key
///           secretAccessKeySecretRef:
///             name: awssm-secret
///             key: secret-access-key
/// ```
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "SecretsProvider",
    namespaced,
    status = "SecretsProviderStatus",
    printcolumn = r#"{"name":"Provider","type":"string","jsonPath":".status.providerType"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct SecretsProviderSpec {
    /// ESO provider configuration.
    ///
    /// Exactly one top-level key (the provider type) must be present.
    /// This becomes `spec.provider` of the ClusterSecretStore verbatim.
    pub provider: serde_json::Map<String, serde_json::Value>,
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

    /// Detected provider type (first key of spec.provider, e.g. "vault", "aws")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_type: Option<String>,
}

/// SecretsProvider phase
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum SecretsProviderPhase {
    /// Provider is being validated
    #[default]
    Pending,
    /// ClusterSecretStore applied, ready for use
    Ready,
    /// ClusterSecretStore creation failed
    Failed,
}

impl SecretsProviderSpec {
    /// Returns the provider type name (first key of the provider map).
    ///
    /// E.g. `"vault"`, `"aws"`, `"webhook"`.
    pub fn provider_type_name(&self) -> Option<&str> {
        self.provider.keys().next().map(|s| s.as_str())
    }

    /// Validate the spec. Returns an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.provider.is_empty() {
            return Err("spec.provider must contain exactly one provider key".to_string());
        }
        if self.provider.len() > 1 {
            let keys: Vec<&String> = self.provider.keys().collect();
            return Err(format!(
                "spec.provider must contain exactly one provider key, found {}: {:?}",
                self.provider.len(),
                keys
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_secrets_manager_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: SecretsProvider
metadata:
  name: team-b-store
spec:
  provider:
    aws:
      service: SecretsManager
      region: eu-central-1
      auth:
        secretRef:
          accessKeyIDSecretRef:
            name: awssm-secret
            key: access-key
          secretAccessKeySecretRef:
            name: awssm-secret
            key: secret-access-key
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: SecretsProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type_name(), Some("aws"));
        assert!(provider.spec.validate().is_ok());

        let aws = &provider.spec.provider["aws"];
        assert_eq!(aws["service"], "SecretsManager");
        assert_eq!(aws["region"], "eu-central-1");
    }

    #[test]
    fn vault_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: SecretsProvider
metadata:
  name: vault-prod
spec:
  provider:
    vault:
      server: https://vault.example.com
      path: secret
      version: v2
      auth:
        tokenSecretRef:
          name: vault-token
          namespace: lattice-system
          key: token
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: SecretsProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type_name(), Some("vault"));
        assert!(provider.spec.validate().is_ok());

        let vault = &provider.spec.provider["vault"];
        assert_eq!(vault["server"], "https://vault.example.com");
    }

    #[test]
    fn webhook_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: SecretsProvider
metadata:
  name: webhook-test
spec:
  provider:
    webhook:
      url: "http://example.com/secret/{{ .remoteRef.key }}"
      method: GET
      result:
        jsonPath: "$"
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: SecretsProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type_name(), Some("webhook"));
        assert!(provider.spec.validate().is_ok());
    }

    #[test]
    fn barbican_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: SecretsProvider
metadata:
  name: barbican-store
spec:
  provider:
    barbican:
      url: https://barbican.example.com
      auth:
        secretRef:
          name: os-creds
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: SecretsProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type_name(), Some("barbican"));
        assert!(provider.spec.validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_provider() {
        let spec = SecretsProviderSpec {
            provider: serde_json::Map::new(),
        };
        let err = spec.validate().unwrap_err();
        assert!(err.contains("exactly one provider key"));
    }

    #[test]
    fn validate_rejects_multi_key_provider() {
        let mut provider = serde_json::Map::new();
        provider.insert("vault".to_string(), serde_json::json!({}));
        provider.insert("aws".to_string(), serde_json::json!({}));
        let spec = SecretsProviderSpec { provider };
        let err = spec.validate().unwrap_err();
        assert!(err.contains("exactly one provider key"));
        assert!(err.contains("found 2"));
    }

    #[test]
    fn provider_type_name_returns_first_key() {
        let mut provider = serde_json::Map::new();
        provider.insert(
            "aws".to_string(),
            serde_json::json!({"region": "us-east-1"}),
        );
        let spec = SecretsProviderSpec { provider };
        assert_eq!(spec.provider_type_name(), Some("aws"));
    }

    #[test]
    fn provider_type_name_returns_none_for_empty() {
        let spec = SecretsProviderSpec {
            provider: serde_json::Map::new(),
        };
        assert_eq!(spec.provider_type_name(), None);
    }
}
