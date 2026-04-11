//! SecretProvider CRD for ESO integration
//!
//! A SecretProvider wraps an ESO `ClusterSecretStore.spec.provider` configuration.
//! The `spec.provider` field is passed through verbatim — users write native ESO
//! provider YAML and Lattice manages the ClusterSecretStore lifecycle.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// SecretProvider defines an ESO provider configuration.
///
/// When created, the controller creates a corresponding ESO ClusterSecretStore
/// whose `spec.provider` is populated verbatim from `spec.provider`.
///
/// Example (AWS Secrets Manager):
/// ```yaml
/// apiVersion: lattice.dev/v1alpha1
/// kind: SecretProvider
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
    kind = "SecretProvider",
    namespaced,
    status = "SecretProviderStatus",
    printcolumn = r#"{"name":"Provider","type":"string","jsonPath":".status.providerType"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct SecretProviderSpec {
    /// ESO provider configuration.
    ///
    /// Exactly one top-level key (the provider type) must be present.
    /// This becomes `spec.provider` of the ClusterSecretStore verbatim.
    ///
    /// Uses `x-kubernetes-preserve-unknown-fields` so Kubernetes won't prune
    /// the arbitrary ESO provider fields (url, auth, region, etc.).
    #[schemars(schema_with = "crate::crd::preserve_unknown_fields")]
    pub provider: serde_json::Map<String, serde_json::Value>,
}

/// SecretProvider status
///
/// All optional fields serialize as `null` (no `skip_serializing_if`) so that
/// merge-patch status updates correctly clear stale values.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretProviderStatus {
    /// Current phase
    #[serde(default)]
    pub phase: SecretProviderPhase,

    /// Human-readable message
    #[serde(default)]
    pub message: Option<String>,

    /// Last time connection was validated
    #[serde(default)]
    pub last_validated: Option<String>,

    /// Detected provider type (first key of spec.provider, e.g. "vault", "aws")
    #[serde(default)]
    pub provider_type: Option<String>,

    /// Generation of the spec that was last reconciled
    #[serde(default)]
    pub observed_generation: Option<i64>,
}

/// SecretProvider phase
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretProviderPhase {
    /// Provider is being validated
    #[default]
    Pending,
    /// ClusterSecretStore applied, ready for use
    Ready,
    /// ClusterSecretStore creation failed
    Failed,
}

impl std::fmt::Display for SecretProviderPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Ready => write!(f, "Ready"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

impl SecretProviderSpec {
    /// Returns the provider type name (first key of the provider map).
    ///
    /// E.g. `"vault"`, `"aws"`, `"webhook"`.
    pub fn provider_type_name(&self) -> Option<&str> {
        self.provider.keys().next().map(|s| s.as_str())
    }

    /// Extract external (non-cluster-local) endpoints from the provider configuration.
    ///
    /// Inspects known provider types for URL fields:
    /// - `vault` → `server`
    /// - `webhook` → `url`
    /// - `barbican` → `url`
    ///
    /// Returns parsed endpoints that are NOT cluster-local (i.e., need external egress).
    pub fn external_endpoints(&self) -> Vec<super::ParsedEndpoint> {
        let urls: Vec<&str> = self
            .provider
            .iter()
            .flat_map(|(provider_type, config)| {
                let field = match provider_type.as_str() {
                    "vault" => "server",
                    "webhook" | "barbican" => "url",
                    _ => return vec![],
                };
                config
                    .get(field)
                    .and_then(|v| v.as_str())
                    .into_iter()
                    .collect::<Vec<_>>()
            })
            .collect();

        urls.into_iter()
            .filter_map(super::ParsedEndpoint::parse)
            .filter(|ep| !ep.is_cluster_local())
            .collect()
    }

    /// Validate the spec. Returns an error if invalid.
    pub fn validate(&self) -> Result<(), crate::ValidationError> {
        if self.provider.is_empty() {
            return Err(crate::ValidationError::new(
                "spec.provider must contain exactly one provider key",
            ));
        }
        if self.provider.len() > 1 {
            let keys: Vec<&String> = self.provider.keys().collect();
            return Err(crate::ValidationError::new(format!(
                "spec.provider must contain exactly one provider key, found {}: {:?}",
                self.provider.len(),
                keys
            )));
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
kind: SecretProvider
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
        let provider: SecretProvider = serde_json::from_value(value).expect("parse");
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
kind: SecretProvider
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
        let provider: SecretProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type_name(), Some("vault"));
        assert!(provider.spec.validate().is_ok());

        let vault = &provider.spec.provider["vault"];
        assert_eq!(vault["server"], "https://vault.example.com");
    }

    #[test]
    fn webhook_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: SecretProvider
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
        let provider: SecretProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type_name(), Some("webhook"));
        assert!(provider.spec.validate().is_ok());
    }

    #[test]
    fn barbican_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: SecretProvider
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
        let provider: SecretProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type_name(), Some("barbican"));
        assert!(provider.spec.validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_provider() {
        let spec = SecretProviderSpec {
            provider: serde_json::Map::new(),
        };
        let err = spec.validate().unwrap_err().to_string();
        assert!(err.contains("exactly one provider key"));
    }

    #[test]
    fn validate_rejects_multi_key_provider() {
        let mut provider = serde_json::Map::new();
        provider.insert("vault".to_string(), serde_json::json!({}));
        provider.insert("aws".to_string(), serde_json::json!({}));
        let spec = SecretProviderSpec { provider };
        let err = spec.validate().unwrap_err().to_string();
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
        let spec = SecretProviderSpec { provider };
        assert_eq!(spec.provider_type_name(), Some("aws"));
    }

    #[test]
    fn provider_type_name_returns_none_for_empty() {
        let spec = SecretProviderSpec {
            provider: serde_json::Map::new(),
        };
        assert_eq!(spec.provider_type_name(), None);
    }

    // =========================================================================
    // external_endpoints() tests
    // =========================================================================

    #[test]
    fn external_endpoints_vault_server() {
        let mut provider = serde_json::Map::new();
        provider.insert(
            "vault".to_string(),
            serde_json::json!({"server": "https://vault.example.com:8200", "path": "secret"}),
        );
        let spec = SecretProviderSpec { provider };
        let eps = spec.external_endpoints();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].host, "vault.example.com");
        assert_eq!(eps[0].port, 8200);
    }

    #[test]
    fn external_endpoints_vault_default_port() {
        let mut provider = serde_json::Map::new();
        provider.insert(
            "vault".to_string(),
            serde_json::json!({"server": "https://vault.example.com"}),
        );
        let spec = SecretProviderSpec { provider };
        let eps = spec.external_endpoints();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].host, "vault.example.com");
        assert_eq!(eps[0].port, 443);
    }

    #[test]
    fn external_endpoints_webhook_url() {
        let mut provider = serde_json::Map::new();
        provider.insert(
            "webhook".to_string(),
            serde_json::json!({"url": "http://webhook.example.com:9090/path"}),
        );
        let spec = SecretProviderSpec { provider };
        let eps = spec.external_endpoints();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].host, "webhook.example.com");
        assert_eq!(eps[0].port, 9090);
    }

    #[test]
    fn external_endpoints_barbican_url() {
        let mut provider = serde_json::Map::new();
        provider.insert(
            "barbican".to_string(),
            serde_json::json!({"url": "https://barbican.example.com"}),
        );
        let spec = SecretProviderSpec { provider };
        let eps = spec.external_endpoints();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].host, "barbican.example.com");
        assert_eq!(eps[0].port, 443);
    }

    #[test]
    fn external_endpoints_cluster_local_filtered() {
        let mut provider = serde_json::Map::new();
        provider.insert(
            "webhook".to_string(),
            serde_json::json!({"url": "http://my-webhook.lattice-system.svc:8787/secret"}),
        );
        let spec = SecretProviderSpec { provider };
        let eps = spec.external_endpoints();
        assert!(
            eps.is_empty(),
            "cluster-local endpoints should be filtered out"
        );
    }

    #[test]
    fn external_endpoints_unknown_provider() {
        let mut provider = serde_json::Map::new();
        provider.insert(
            "aws".to_string(),
            serde_json::json!({"service": "SecretsManager", "region": "us-east-1"}),
        );
        let spec = SecretProviderSpec { provider };
        assert!(spec.external_endpoints().is_empty());
    }

    #[test]
    fn external_endpoints_empty_provider() {
        let spec = SecretProviderSpec {
            provider: serde_json::Map::new(),
        };
        assert!(spec.external_endpoints().is_empty());
    }
}
