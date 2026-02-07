//! OIDCProvider CRD for authentication configuration
//!
//! An OIDCProvider defines an OIDC identity provider configuration used by
//! the Lattice auth proxy to validate user tokens.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::default_true;
use super::types::SecretRef;

/// OIDCProvider defines an OIDC identity provider for the auth proxy.
///
/// The auth proxy uses this configuration to validate JWT tokens from users.
///
/// Example:
/// ```yaml
/// apiVersion: lattice.dev/v1alpha1
/// kind: OIDCProvider
/// metadata:
///   name: corporate-idp
///   namespace: lattice-system
/// spec:
///   issuerUrl: https://idp.example.com
///   clientId: lattice-proxy
///   usernameClaim: email
///   groupsClaim: groups
///   audiences:
///     - lattice-proxy
/// ```
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "OIDCProvider",
    namespaced,
    status = "OIDCProviderStatus",
    printcolumn = r#"{"name":"Issuer","type":"string","jsonPath":".spec.issuerUrl"}"#,
    printcolumn = r#"{"name":"ClientID","type":"string","jsonPath":".spec.clientId"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct OIDCProviderSpec {
    /// OIDC issuer URL (e.g., https://idp.example.com)
    /// Must serve .well-known/openid-configuration
    pub issuer_url: String,

    /// OIDC client ID
    pub client_id: String,

    /// Optional: Client secret for token introspection
    /// If provided, enables token introspection endpoint validation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<SecretRef>,

    /// JWT claim to use as username (default: "sub")
    #[serde(default = "default_username_claim")]
    pub username_claim: String,

    /// JWT claim to use as groups (default: "groups")
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,

    /// Optional: Prefix to add to usernames (e.g., "oidc:")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username_prefix: Option<String>,

    /// Optional: Prefix to add to groups (e.g., "oidc:")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups_prefix: Option<String>,

    /// Allowed audiences for token validation
    /// If empty, only the clientId is accepted
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audiences: Vec<String>,

    /// Required claims that must be present in the token
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_claims: Vec<RequiredClaim>,

    /// CA certificate for TLS verification (PEM format)
    /// Use for self-signed IdP certificates
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle: Option<String>,

    /// JWKS refresh interval in seconds (default: 3600)
    #[serde(default = "default_jwks_refresh_interval")]
    pub jwks_refresh_interval_seconds: u32,

    /// Whether to propagate this provider to child clusters
    /// When true, provider is distributed down the hierarchy
    #[serde(default = "default_true")]
    pub propagate: bool,

    /// Whether child clusters can define their own OIDC provider
    /// When false (default), children must use inherited provider
    #[serde(default)]
    pub allow_child_override: bool,
}

fn default_username_claim() -> String {
    "sub".to_string()
}

fn default_groups_claim() -> String {
    "groups".to_string()
}

fn default_jwks_refresh_interval() -> u32 {
    3600
}

/// A required claim that must be present in the token
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RequiredClaim {
    /// Claim name
    pub name: String,

    /// Required value (if specified, claim must match this value)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// OIDCProvider status
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OIDCProviderStatus {
    /// Current phase
    #[serde(default)]
    pub phase: OIDCProviderPhase,

    /// Human-readable message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Last time JWKS was fetched
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_jwks_fetch: Option<String>,

    /// JWKS endpoint URL (from discovery)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
}

/// OIDCProvider phase
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum OIDCProviderPhase {
    /// Provider is being validated
    #[default]
    Pending,
    /// Discovery and JWKS fetch successful
    Ready,
    /// Validation failed
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_oidc_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: OIDCProvider
metadata:
  name: corporate-idp
spec:
  issuerUrl: https://idp.example.com
  clientId: lattice-proxy
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: OIDCProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.issuer_url, "https://idp.example.com");
        assert_eq!(provider.spec.client_id, "lattice-proxy");
        assert_eq!(provider.spec.username_claim, "sub");
        assert_eq!(provider.spec.groups_claim, "groups");
    }

    #[test]
    fn full_oidc_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: OIDCProvider
metadata:
  name: okta-prod
spec:
  issuerUrl: https://company.okta.com
  clientId: lattice
  usernameClaim: email
  groupsClaim: groups
  usernamePrefix: "okta:"
  groupsPrefix: "okta:"
  audiences:
    - lattice
    - kubernetes
  requiredClaims:
    - name: email_verified
      value: "true"
  jwksRefreshIntervalSeconds: 1800
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: OIDCProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.issuer_url, "https://company.okta.com");
        assert_eq!(provider.spec.username_claim, "email");
        assert_eq!(provider.spec.username_prefix, Some("okta:".to_string()));
        assert_eq!(provider.spec.audiences.len(), 2);
        assert_eq!(provider.spec.required_claims.len(), 1);
        assert_eq!(provider.spec.jwks_refresh_interval_seconds, 1800);
    }

    #[test]
    fn oidc_provider_with_client_secret() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: OIDCProvider
metadata:
  name: with-secret
spec:
  issuerUrl: https://idp.example.com
  clientId: lattice
  clientSecret:
    name: oidc-client-secret
    namespace: lattice-system
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: OIDCProvider = serde_json::from_value(value).expect("parse");
        assert!(provider.spec.client_secret.is_some());
        let secret_ref = provider.spec.client_secret.unwrap();
        assert_eq!(secret_ref.name, "oidc-client-secret");
    }

    #[test]
    fn oidc_provider_propagate_defaults_to_true() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: OIDCProvider
metadata:
  name: corporate-idp
spec:
  issuerUrl: https://idp.example.com
  clientId: lattice
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: OIDCProvider = serde_json::from_value(value).expect("parse");
        // propagate should default to true
        assert!(provider.spec.propagate);
        // allow_child_override should default to false
        assert!(!provider.spec.allow_child_override);
    }

    #[test]
    fn oidc_provider_propagate_false() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: OIDCProvider
metadata:
  name: local-idp
spec:
  issuerUrl: https://local-idp.example.com
  clientId: local-lattice
  propagate: false
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: OIDCProvider = serde_json::from_value(value).expect("parse");
        assert!(!provider.spec.propagate);
    }

    #[test]
    fn oidc_provider_allow_child_override() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: OIDCProvider
metadata:
  name: corporate-idp
spec:
  issuerUrl: https://idp.example.com
  clientId: lattice
  allowChildOverride: true
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: OIDCProvider = serde_json::from_value(value).expect("parse");
        assert!(provider.spec.propagate); // still defaults to true
        assert!(provider.spec.allow_child_override);
    }
}
