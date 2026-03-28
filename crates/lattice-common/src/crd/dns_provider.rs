//! DNSProvider CRD for DNS management credentials
//!
//! A DNSProvider represents a named DNS provider account that clusters can reference
//! for external-dns record management and cert-manager ACME DNS-01 challenges.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::SecretRef;

/// DNSProvider defines a DNS provider configuration for managing DNS records.
///
/// Shared across clusters — multiple LatticeCluster resources can reference the
/// same DNSProvider. Supports split DNS/infra configurations where DNS credentials
/// differ from the InfraProvider.
///
/// Example (Route53):
/// ```yaml
/// apiVersion: lattice.dev/v1alpha1
/// kind: DNSProvider
/// metadata:
///   name: route53-prod
/// spec:
///   type: route53
///   zone: example.com
///   credentialsSecretRef:
///     name: aws-dns-creds
///   route53:
///     region: us-east-1
///     hostedZoneId: Z1234567890
/// ```
///
/// Example (Cloudflare):
/// ```yaml
/// apiVersion: lattice.dev/v1alpha1
/// kind: DNSProvider
/// metadata:
///   name: cloudflare-prod
/// spec:
///   type: cloudflare
///   zone: example.com
///   credentialsSecretRef:
///     name: cf-api-token
/// ```
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "DNSProvider",
    namespaced,
    status = "DNSProviderStatus",
    printcolumn = r#"{"name":"Type","type":"string","jsonPath":".spec.type"}"#,
    printcolumn = r#"{"name":"Zone","type":"string","jsonPath":".spec.zone"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct DNSProviderSpec {
    /// DNS provider type
    #[serde(rename = "type")]
    pub provider_type: DNSProviderType,

    /// DNS zone to manage (e.g., "example.com")
    pub zone: String,

    /// DNS resolver address for private zone forwarding (e.g., "10.0.0.53:53").
    /// When set, the operator adds a CoreDNS forward block so pods can resolve
    /// names in this zone. Omit for public zones (Route53, Cloudflare, etc.)
    /// where resolution works via the public DNS hierarchy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver: Option<String>,

    /// Reference to secret containing provider credentials
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_secret_ref: Option<SecretRef>,

    /// Pi-hole-specific configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pihole: Option<PiholeConfig>,

    /// Route53-specific configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route53: Option<Route53Config>,

    /// Cloudflare-specific configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloudflare: Option<CloudflareConfig>,

    /// Google Cloud DNS-specific configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub google: Option<GoogleDnsConfig>,

    /// Azure DNS-specific configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure: Option<AzureDnsConfig>,

    /// OpenStack Designate-specific configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub designate: Option<DesignateConfig>,
}

/// Supported DNS provider types
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum DNSProviderType {
    /// Pi-hole local DNS
    Pihole,
    /// AWS Route53
    Route53,
    /// Cloudflare
    Cloudflare,
    /// Google Cloud DNS
    Google,
    /// Azure DNS
    Azure,
    /// OpenStack Designate DNS-as-a-Service
    Designate,
}

impl std::fmt::Display for DNSProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pihole => write!(f, "Pi-hole"),
            Self::Route53 => write!(f, "Route53"),
            Self::Cloudflare => write!(f, "Cloudflare"),
            Self::Google => write!(f, "Google"),
            Self::Azure => write!(f, "Azure"),
            Self::Designate => write!(f, "Designate"),
        }
    }
}

/// Pi-hole-specific configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PiholeConfig {
    /// Pi-hole server URL (e.g., "http://pihole.local")
    pub url: String,
}

/// Route53-specific configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Route53Config {
    /// AWS region for Route53 API calls
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// Hosted zone ID (if not provided, looked up by zone name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosted_zone_id: Option<String>,
}

/// Cloudflare-specific configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CloudflareConfig {
    /// Whether to use Cloudflare proxy (orange cloud) on created records
    #[serde(default)]
    pub proxied: bool,
}

/// Google Cloud DNS-specific configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GoogleDnsConfig {
    /// GCP project ID
    pub project: String,
}

/// Azure DNS-specific configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AzureDnsConfig {
    /// Azure subscription ID
    pub subscription_id: String,

    /// Azure resource group containing the DNS zone
    pub resource_group: String,
}

/// OpenStack Designate-specific configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DesignateConfig {
    /// Designate zone ID (if not provided, looked up by zone name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,

    /// OpenStack region
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// DNSProvider status
///
/// All optional fields serialize as `null` (no `skip_serializing_if`) so that
/// merge-patch status updates correctly clear stale values.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DNSProviderStatus {
    /// Current phase
    #[serde(default)]
    pub phase: DNSProviderPhase,

    /// Human-readable message
    #[serde(default)]
    pub message: Option<String>,

    /// Number of clusters referencing this provider
    #[serde(default)]
    pub cluster_count: u32,

    /// Generation of the spec that was last reconciled
    #[serde(default)]
    pub observed_generation: Option<i64>,
}

/// DNSProvider phase
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum DNSProviderPhase {
    /// Provider is being validated
    #[default]
    Pending,
    /// Credentials validated, ready for use
    Ready,
    /// Credential validation failed
    Failed,
}

impl std::fmt::Display for DNSProviderPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Ready => write!(f, "Ready"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

impl DNSProviderSpec {
    /// Validate the spec. Returns an error if invalid.
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.zone.is_empty() {
            return Err(crate::Error::validation("zone cannot be empty"));
        }

        // Validate provider-specific config matches type
        match self.provider_type {
            DNSProviderType::Pihole => {
                let pihole = self.pihole.as_ref().ok_or_else(|| {
                    crate::Error::validation("pihole config required when type is pihole")
                })?;
                if pihole.url.is_empty() {
                    return Err(crate::Error::validation("pihole.url cannot be empty"));
                }
            }
            DNSProviderType::Google => {
                if self.google.is_none() {
                    return Err(crate::Error::validation(
                        "google config required when type is google",
                    ));
                }
            }
            DNSProviderType::Azure => {
                if self.azure.is_none() {
                    return Err(crate::Error::validation(
                        "azure config required when type is azure",
                    ));
                }
            }
            DNSProviderType::Designate => {
                if self.designate.is_none() {
                    return Err(crate::Error::validation(
                        "designate config required when type is designate",
                    ));
                }
            }
            // Route53 and Cloudflare provider-specific configs are optional
            DNSProviderType::Route53 | DNSProviderType::Cloudflare => {}
        }

        Ok(())
    }
}

impl DNSProviderSpec {
    /// Create a minimal spec with only provider type and zone.
    pub fn new(provider_type: DNSProviderType, zone: &str) -> Self {
        Self {
            provider_type,
            zone: zone.to_string(),
            resolver: None,
            credentials_secret_ref: None,
            pihole: None,
            route53: None,
            cloudflare: None,
            google: None,
            azure: None,
            designate: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pihole_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: DNSProvider
metadata:
  name: pihole-local
spec:
  type: pihole
  zone: home.local
  credentialsSecretRef:
    name: pihole-api-key
  pihole:
    url: http://pihole.local
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: DNSProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type, DNSProviderType::Pihole);
        assert_eq!(provider.spec.zone, "home.local");
        assert_eq!(
            provider.spec.pihole.as_ref().unwrap().url,
            "http://pihole.local"
        );
        assert!(provider.spec.validate().is_ok());
    }

    #[test]
    fn pihole_requires_config() {
        let spec = DNSProviderSpec::new(DNSProviderType::Pihole, "home.local");
        assert!(spec.validate().is_err());
    }

    #[test]
    fn pihole_empty_url_fails() {
        let spec = DNSProviderSpec {
            pihole: Some(PiholeConfig {
                url: String::new(),
            }),
            ..DNSProviderSpec::new(DNSProviderType::Pihole, "home.local")
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn route53_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: DNSProvider
metadata:
  name: route53-prod
spec:
  type: route53
  zone: example.com
  credentialsSecretRef:
    name: aws-dns-creds
  route53:
    region: us-east-1
    hostedZoneId: Z1234567890
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: DNSProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type, DNSProviderType::Route53);
        assert_eq!(provider.spec.zone, "example.com");
        assert!(provider.spec.validate().is_ok());
    }

    #[test]
    fn cloudflare_provider_yaml() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: DNSProvider
metadata:
  name: cloudflare-prod
spec:
  type: cloudflare
  zone: example.com
  credentialsSecretRef:
    name: cf-api-token
  cloudflare:
    proxied: true
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let provider: DNSProvider = serde_json::from_value(value).expect("parse");
        assert_eq!(provider.spec.provider_type, DNSProviderType::Cloudflare);
        assert!(provider.spec.cloudflare.as_ref().unwrap().proxied);
        assert!(provider.spec.validate().is_ok());
    }

    #[test]
    fn google_provider_requires_config() {
        let spec = DNSProviderSpec::new(DNSProviderType::Google, "example.com");
        assert!(spec.validate().is_err());
    }

    #[test]
    fn azure_provider_requires_config() {
        let spec = DNSProviderSpec::new(DNSProviderType::Azure, "example.com");
        assert!(spec.validate().is_err());
    }

    #[test]
    fn empty_zone_fails_validation() {
        let spec = DNSProviderSpec::new(DNSProviderType::Route53, "");
        assert!(spec.validate().is_err());
    }

    #[test]
    fn route53_minimal_valid() {
        let spec = DNSProviderSpec {
            credentials_secret_ref: Some(SecretRef {
                name: "aws-creds".to_string(),
                namespace: "lattice-system".to_string(),
            }),
            ..DNSProviderSpec::new(DNSProviderType::Route53, "example.com")
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn google_with_config_valid() {
        let spec = DNSProviderSpec {
            google: Some(GoogleDnsConfig {
                project: "my-project".to_string(),
            }),
            ..DNSProviderSpec::new(DNSProviderType::Google, "example.com")
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn azure_with_config_valid() {
        let spec = DNSProviderSpec {
            azure: Some(AzureDnsConfig {
                subscription_id: "sub-123".to_string(),
                resource_group: "rg-dns".to_string(),
            }),
            ..DNSProviderSpec::new(DNSProviderType::Azure, "example.com")
        };
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn provider_type_display() {
        assert_eq!(DNSProviderType::Pihole.to_string(), "Pi-hole");
        assert_eq!(DNSProviderType::Route53.to_string(), "Route53");
        assert_eq!(DNSProviderType::Cloudflare.to_string(), "Cloudflare");
        assert_eq!(DNSProviderType::Google.to_string(), "Google");
        assert_eq!(DNSProviderType::Azure.to_string(), "Azure");
    }

    #[test]
    fn phase_display() {
        assert_eq!(DNSProviderPhase::Pending.to_string(), "Pending");
        assert_eq!(DNSProviderPhase::Ready.to_string(), "Ready");
        assert_eq!(DNSProviderPhase::Failed.to_string(), "Failed");
    }

    #[test]
    fn designate_requires_config() {
        let spec = DNSProviderSpec {
            resolver: Some("10.0.0.53:53".to_string()),
            ..DNSProviderSpec::new(DNSProviderType::Designate, "internal.cloud")
        };
        assert!(spec.validate().is_err());
    }

    #[test]
    fn designate_with_config_valid() {
        let spec = DNSProviderSpec {
            resolver: Some("10.0.0.53:53".to_string()),
            designate: Some(DesignateConfig {
                zone_id: Some("zone-123".to_string()),
                region: Some("RegionOne".to_string()),
            }),
            ..DNSProviderSpec::new(DNSProviderType::Designate, "internal.cloud")
        };
        assert!(spec.validate().is_ok());
    }
}
