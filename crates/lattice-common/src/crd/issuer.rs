//! Certificate issuer types for LatticeCluster
//!
//! Named issuer configurations that the operator reconciles into cert-manager
//! ClusterIssuer resources. Supports ACME, CA, self-signed, and Vault PKI.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::SecretRef;

/// A named certificate issuer configuration.
///
/// Each entry in `LatticeClusterSpec.issuers` generates a cert-manager
/// ClusterIssuer named `lattice-{key}`. Services reference these issuers
/// via `IngressTls.issuerRef`.
///
/// Example YAML:
/// ```yaml
/// issuers:
///   public:
///     type: acme
///     acme:
///       email: ops@example.com
///       server: https://acme-v2.api.letsencrypt.org/directory
///       dnsProviderRef: public
///   internal:
///     type: ca
///     ca:
///       secretRef:
///         name: internal-ca
///   dev:
///     type: selfSigned
/// ```
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSpec {
    /// Issuer type
    #[serde(rename = "type")]
    pub type_: IssuerType,

    /// ACME configuration (required when type = acme)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme: Option<AcmeIssuerSpec>,

    /// CA configuration (required when type = ca)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<CaIssuerSpec>,

    /// Vault PKI configuration (required when type = vault)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<VaultIssuerSpec>,
    // selfSigned needs no extra config
}

/// Supported cert-manager issuer types
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum IssuerType {
    /// ACME (e.g., Let's Encrypt)
    Acme,
    /// CA issuer from a secret containing a CA cert+key pair
    Ca,
    /// Self-signed certificates
    SelfSigned,
    /// HashiCorp Vault PKI backend
    Vault,
}

impl std::fmt::Display for IssuerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Acme => write!(f, "ACME"),
            Self::Ca => write!(f, "CA"),
            Self::SelfSigned => write!(f, "SelfSigned"),
            Self::Vault => write!(f, "Vault"),
        }
    }
}

/// ACME issuer configuration (Let's Encrypt, ZeroSSL, etc.)
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AcmeIssuerSpec {
    /// Email address for ACME registration
    pub email: String,

    /// ACME server URL (e.g., "https://acme-v2.api.letsencrypt.org/directory")
    pub server: String,

    /// Reference to a key in `dns.providers` for DNS-01 challenges.
    /// When set, generates a DNS-01 solver using the referenced DNSProvider's
    /// credentials. When absent, generates an HTTP-01 solver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_provider_ref: Option<String>,
}

/// CA issuer configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CaIssuerSpec {
    /// Reference to a secret containing the CA certificate and private key.
    /// The secret must contain `tls.crt` and `tls.key` entries.
    pub secret_ref: SecretRef,
}

/// Vault PKI issuer configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VaultIssuerSpec {
    /// Vault server URL
    pub server: String,

    /// PKI mount path (e.g., "pki")
    pub path: String,

    /// Reference to a secret containing Vault authentication credentials
    pub auth_secret_ref: SecretRef,
}

/// DNS configuration for a cluster.
///
/// Maps named keys to DNSProvider CRD references. Each key can be referenced
/// by ACME issuers via `dnsProviderRef`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DnsConfig {
    /// Named DNS provider references.
    /// Keys are logical names (e.g., "public", "internal"), values are
    /// names of DNSProvider CRD resources.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub providers: std::collections::BTreeMap<String, String>,
}

impl IssuerSpec {
    /// Validate the issuer spec.
    pub fn validate(
        &self,
        name: &str,
        dns_providers: &std::collections::BTreeMap<String, String>,
    ) -> Result<(), String> {
        crate::crd::validate_dns_label(name, "issuer name")?;

        match self.type_ {
            IssuerType::Acme => {
                let acme = self.acme.as_ref().ok_or_else(|| {
                    format!("issuer '{name}': acme config required when type is acme")
                })?;
                if acme.email.is_empty() {
                    return Err(format!("issuer '{name}': acme.email cannot be empty"));
                }
                if acme.server.is_empty() {
                    return Err(format!("issuer '{name}': acme.server cannot be empty"));
                }
                if let Some(ref dns_ref) = acme.dns_provider_ref {
                    if !dns_providers.contains_key(dns_ref) {
                        return Err(format!(
                            "issuer '{name}': dnsProviderRef '{dns_ref}' not found in dns.providers (available: {:?})",
                            dns_providers.keys().collect::<Vec<_>>()
                        ));
                    }
                }
            }
            IssuerType::Ca => {
                if self.ca.is_none() {
                    return Err(format!(
                        "issuer '{name}': ca config required when type is ca"
                    ));
                }
            }
            IssuerType::Vault => {
                let vault = self.vault.as_ref().ok_or_else(|| {
                    format!("issuer '{name}': vault config required when type is vault")
                })?;
                if vault.server.is_empty() {
                    return Err(format!("issuer '{name}': vault.server cannot be empty"));
                }
                if vault.path.is_empty() {
                    return Err(format!("issuer '{name}': vault.path cannot be empty"));
                }
            }
            IssuerType::SelfSigned => {
                // No config needed — but reject extraneous fields
                if self.acme.is_some() || self.ca.is_some() || self.vault.is_some() {
                    return Err(format!(
                        "issuer '{name}': selfSigned type must not have acme, ca, or vault config"
                    ));
                }
            }
        }

        Ok(())
    }
}

impl DnsConfig {
    /// Validate the DNS config.
    pub fn validate(&self) -> Result<(), String> {
        for key in self.providers.keys() {
            crate::crd::validate_dns_label(key, "dns provider key")?;
        }
        for (key, value) in &self.providers {
            if value.is_empty() {
                return Err(format!(
                    "dns.providers['{key}']: DNSProvider reference cannot be empty"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn empty_providers() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    fn with_provider(key: &str, value: &str) -> BTreeMap<String, String> {
        BTreeMap::from([(key.to_string(), value.to_string())])
    }

    // =========================================================================
    // ACME Issuer Tests
    // =========================================================================

    #[test]
    fn acme_valid() {
        let spec = IssuerSpec {
            type_: IssuerType::Acme,
            acme: Some(AcmeIssuerSpec {
                email: "ops@example.com".to_string(),
                server: "https://acme-v2.api.letsencrypt.org/directory".to_string(),
                dns_provider_ref: None,
            }),
            ca: None,
            vault: None,
        };
        assert!(spec.validate("public", &empty_providers()).is_ok());
    }

    #[test]
    fn acme_with_dns_provider_ref_valid() {
        let spec = IssuerSpec {
            type_: IssuerType::Acme,
            acme: Some(AcmeIssuerSpec {
                email: "ops@example.com".to_string(),
                server: "https://acme-v2.api.letsencrypt.org/directory".to_string(),
                dns_provider_ref: Some("public".to_string()),
            }),
            ca: None,
            vault: None,
        };
        assert!(spec
            .validate("public", &with_provider("public", "route53-prod"))
            .is_ok());
    }

    #[test]
    fn acme_missing_dns_provider_ref_fails() {
        let spec = IssuerSpec {
            type_: IssuerType::Acme,
            acme: Some(AcmeIssuerSpec {
                email: "ops@example.com".to_string(),
                server: "https://acme-v2.api.letsencrypt.org/directory".to_string(),
                dns_provider_ref: Some("nonexistent".to_string()),
            }),
            ca: None,
            vault: None,
        };
        let err = spec.validate("public", &empty_providers()).unwrap_err();
        assert!(err.contains("not found in dns.providers"));
    }

    #[test]
    fn acme_missing_config_fails() {
        let spec = IssuerSpec {
            type_: IssuerType::Acme,
            acme: None,
            ca: None,
            vault: None,
        };
        assert!(spec.validate("public", &empty_providers()).is_err());
    }

    #[test]
    fn acme_empty_email_fails() {
        let spec = IssuerSpec {
            type_: IssuerType::Acme,
            acme: Some(AcmeIssuerSpec {
                email: String::new(),
                server: "https://acme-v2.api.letsencrypt.org/directory".to_string(),
                dns_provider_ref: None,
            }),
            ca: None,
            vault: None,
        };
        assert!(spec.validate("public", &empty_providers()).is_err());
    }

    #[test]
    fn acme_empty_server_fails() {
        let spec = IssuerSpec {
            type_: IssuerType::Acme,
            acme: Some(AcmeIssuerSpec {
                email: "ops@example.com".to_string(),
                server: String::new(),
                dns_provider_ref: None,
            }),
            ca: None,
            vault: None,
        };
        assert!(spec.validate("public", &empty_providers()).is_err());
    }

    // =========================================================================
    // CA Issuer Tests
    // =========================================================================

    #[test]
    fn ca_valid() {
        let spec = IssuerSpec {
            type_: IssuerType::Ca,
            acme: None,
            ca: Some(CaIssuerSpec {
                secret_ref: SecretRef {
                    name: "internal-ca".to_string(),
                    namespace: "lattice-system".to_string(),
                },
            }),
            vault: None,
        };
        assert!(spec.validate("internal", &empty_providers()).is_ok());
    }

    #[test]
    fn ca_missing_config_fails() {
        let spec = IssuerSpec {
            type_: IssuerType::Ca,
            acme: None,
            ca: None,
            vault: None,
        };
        assert!(spec.validate("internal", &empty_providers()).is_err());
    }

    // =========================================================================
    // Self-Signed Issuer Tests
    // =========================================================================

    #[test]
    fn self_signed_valid() {
        let spec = IssuerSpec {
            type_: IssuerType::SelfSigned,
            acme: None,
            ca: None,
            vault: None,
        };
        assert!(spec.validate("dev", &empty_providers()).is_ok());
    }

    #[test]
    fn self_signed_with_acme_config_fails() {
        let spec = IssuerSpec {
            type_: IssuerType::SelfSigned,
            acme: Some(AcmeIssuerSpec {
                email: "ops@example.com".to_string(),
                server: "https://acme.example.com".to_string(),
                dns_provider_ref: None,
            }),
            ca: None,
            vault: None,
        };
        let err = spec.validate("dev", &empty_providers()).unwrap_err();
        assert!(err.contains("must not have"));
    }

    // =========================================================================
    // Vault Issuer Tests
    // =========================================================================

    #[test]
    fn vault_valid() {
        let spec = IssuerSpec {
            type_: IssuerType::Vault,
            acme: None,
            ca: None,
            vault: Some(VaultIssuerSpec {
                server: "https://vault.example.com".to_string(),
                path: "pki".to_string(),
                auth_secret_ref: SecretRef {
                    name: "vault-auth".to_string(),
                    namespace: "lattice-system".to_string(),
                },
            }),
        };
        assert!(spec.validate("vault-pki", &empty_providers()).is_ok());
    }

    #[test]
    fn vault_missing_config_fails() {
        let spec = IssuerSpec {
            type_: IssuerType::Vault,
            acme: None,
            ca: None,
            vault: None,
        };
        assert!(spec.validate("vault-pki", &empty_providers()).is_err());
    }

    #[test]
    fn vault_empty_server_fails() {
        let spec = IssuerSpec {
            type_: IssuerType::Vault,
            acme: None,
            ca: None,
            vault: Some(VaultIssuerSpec {
                server: String::new(),
                path: "pki".to_string(),
                auth_secret_ref: SecretRef {
                    name: "vault-auth".to_string(),
                    namespace: "lattice-system".to_string(),
                },
            }),
        };
        assert!(spec.validate("vault-pki", &empty_providers()).is_err());
    }

    #[test]
    fn vault_empty_path_fails() {
        let spec = IssuerSpec {
            type_: IssuerType::Vault,
            acme: None,
            ca: None,
            vault: Some(VaultIssuerSpec {
                server: "https://vault.example.com".to_string(),
                path: String::new(),
                auth_secret_ref: SecretRef {
                    name: "vault-auth".to_string(),
                    namespace: "lattice-system".to_string(),
                },
            }),
        };
        assert!(spec.validate("vault-pki", &empty_providers()).is_err());
    }

    // =========================================================================
    // Issuer Name Validation
    // =========================================================================

    #[test]
    fn invalid_issuer_name_fails() {
        let spec = IssuerSpec {
            type_: IssuerType::SelfSigned,
            acme: None,
            ca: None,
            vault: None,
        };
        let err = spec.validate("My_Issuer", &empty_providers()).unwrap_err();
        assert!(err.contains("issuer name"));
    }

    // =========================================================================
    // DnsConfig Validation
    // =========================================================================

    #[test]
    fn dns_config_valid() {
        let config = DnsConfig {
            providers: with_provider("public", "route53-prod"),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn dns_config_empty_ref_fails() {
        let config = DnsConfig {
            providers: with_provider("public", ""),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn dns_config_invalid_key_fails() {
        let config = DnsConfig {
            providers: BTreeMap::from([("My_Provider".to_string(), "route53-prod".to_string())]),
        };
        assert!(config.validate().is_err());
    }

    // =========================================================================
    // IssuerType Display
    // =========================================================================

    #[test]
    fn issuer_type_display() {
        assert_eq!(IssuerType::Acme.to_string(), "ACME");
        assert_eq!(IssuerType::Ca.to_string(), "CA");
        assert_eq!(IssuerType::SelfSigned.to_string(), "SelfSigned");
        assert_eq!(IssuerType::Vault.to_string(), "Vault");
    }

    // =========================================================================
    // YAML Roundtrip
    // =========================================================================

    #[test]
    fn issuer_spec_json_roundtrip() {
        let spec = IssuerSpec {
            type_: IssuerType::Acme,
            acme: Some(AcmeIssuerSpec {
                email: "ops@example.com".to_string(),
                server: "https://acme-v2.api.letsencrypt.org/directory".to_string(),
                dns_provider_ref: Some("public".to_string()),
            }),
            ca: None,
            vault: None,
        };
        let json = serde_json::to_string(&spec).expect("serialize");
        let parsed: IssuerSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(spec, parsed);
    }

    #[test]
    fn dns_config_json_roundtrip() {
        let config = DnsConfig {
            providers: BTreeMap::from([
                ("public".to_string(), "route53-prod".to_string()),
                ("internal".to_string(), "cloudflare-internal".to_string()),
            ]),
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let parsed: DnsConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, parsed);
    }
}
