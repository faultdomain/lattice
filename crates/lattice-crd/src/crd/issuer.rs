//! CertIssuer CRD for certificate issuer management
//!
//! A CertIssuer represents a named certificate issuer configuration that the
//! operator reconciles into cert-manager ClusterIssuer resources. Supports
//! ACME, CA, self-signed, and Vault PKI.

use kube::{CustomResource, ResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::SecretRef;

use crate::LATTICE_SYSTEM_NAMESPACE;

/// CertIssuer defines a certificate issuer configuration.
///
/// Each CertIssuer generates a cert-manager ClusterIssuer named
/// `lattice-{metadata.name}`. Services reference these issuers via
/// `IngressTls.issuerRef`.
///
/// Example YAML:
/// ```yaml
/// apiVersion: lattice.dev/v1alpha1
/// kind: CertIssuer
/// metadata:
///   name: public
/// spec:
///   type: acme
///   acme:
///     email: ops@example.com
///     server: https://acme-v2.api.letsencrypt.org/directory
///     dnsProviderRef: public
/// ```
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "CertIssuer",
    namespaced,
    status = "CertIssuerStatus",
    printcolumn = r#"{"name":"Type","type":"string","jsonPath":".spec.type"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct CertIssuerSpec {
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

    /// Reference to a DNSProvider CRD for DNS-01 challenges.
    /// When set, generates a DNS-01 solver using the referenced DNSProvider's
    /// credentials. When absent, generates an HTTP-01 solver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_provider_ref: Option<String>,
}

/// CA issuer configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CaIssuerSpec {
    /// ESO-managed credential source for the CA certificate and private key.
    pub credentials: super::types::CredentialSpec,
}

/// Vault PKI issuer configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VaultIssuerSpec {
    /// Vault server URL
    pub server: String,

    /// PKI mount path (e.g., "pki")
    pub path: String,

    /// ESO-managed credential source for Vault authentication
    pub auth_credentials: super::types::CredentialSpec,
}

/// CertIssuer status
///
/// All optional fields serialize as `null` (no `skip_serializing_if`) so that
/// merge-patch status updates correctly clear stale values.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertIssuerStatus {
    /// Current phase
    #[serde(default)]
    pub phase: CertIssuerPhase,

    /// Human-readable message
    #[serde(default)]
    pub message: Option<String>,

    /// Generation of the spec that was last reconciled
    #[serde(default)]
    pub observed_generation: Option<i64>,
}

/// CertIssuer phase
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertIssuerPhase {
    /// Issuer is being validated
    #[default]
    Pending,
    /// Issuer validated, ready for use
    Ready,
    /// Issuer validation failed
    Failed,
}

impl std::fmt::Display for CertIssuerPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Ready => write!(f, "Ready"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

impl CertIssuer {
    /// Resolve the K8s Secret for this issuer's credentials.
    ///
    /// Returns a synthetic ref pointing to the ESO-synced secret
    /// `{name}-credentials` in `lattice-system`. Returns `None` for
    /// types that don't need credentials (SelfSigned, ACME HTTP-01).
    pub fn k8s_secret_ref(&self) -> Option<SecretRef> {
        match self.spec.type_ {
            IssuerType::Ca | IssuerType::Vault => Some(SecretRef::for_credentials(
                &self.name_any(),
                LATTICE_SYSTEM_NAMESPACE,
            )),
            _ => None,
        }
    }
}

impl CertIssuerSpec {
    /// Validate the issuer spec. Returns an error if invalid.
    pub fn validate(&self) -> Result<(), crate::ValidationError> {
        match self.type_ {
            IssuerType::Acme => {
                let acme = self.acme.as_ref().ok_or_else(|| {
                    crate::ValidationError::new("acme config required when type is acme")
                })?;
                if acme.email.is_empty() {
                    return Err(crate::ValidationError::new("acme.email cannot be empty"));
                }
                if acme.server.is_empty() {
                    return Err(crate::ValidationError::new("acme.server cannot be empty"));
                }
                if let Some(ref dns_ref) = acme.dns_provider_ref {
                    if dns_ref.is_empty() {
                        return Err(crate::ValidationError::new(
                            "acme.dnsProviderRef cannot be empty when specified",
                        ));
                    }
                }
            }
            IssuerType::Ca => {
                let ca = self.ca.as_ref().ok_or_else(|| {
                    crate::ValidationError::new("ca config required when type is ca")
                })?;
                ca.credentials.validate()?;
            }
            IssuerType::Vault => {
                let vault = self.vault.as_ref().ok_or_else(|| {
                    crate::ValidationError::new("vault config required when type is vault")
                })?;
                if vault.server.is_empty() {
                    return Err(crate::ValidationError::new("vault.server cannot be empty"));
                }
                if vault.path.is_empty() {
                    return Err(crate::ValidationError::new("vault.path cannot be empty"));
                }
                vault.auth_credentials.validate()?;
            }
            IssuerType::SelfSigned => {
                // No config needed — but reject extraneous fields
                if self.acme.is_some() || self.ca.is_some() || self.vault.is_some() {
                    return Err(crate::ValidationError::new(
                        "selfSigned type must not have acme, ca, or vault config",
                    ));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::CredentialSpec;
    use std::collections::BTreeMap;

    fn make_issuer(name: &str, spec: CertIssuerSpec) -> CertIssuer {
        CertIssuer::new(name, spec)
    }

    // =========================================================================
    // ACME Issuer Tests
    // =========================================================================

    #[test]
    fn acme_valid() {
        let issuer = make_issuer(
            "public",
            CertIssuerSpec {
                type_: IssuerType::Acme,
                acme: Some(AcmeIssuerSpec {
                    email: "ops@example.com".to_string(),
                    server: "https://acme-v2.api.letsencrypt.org/directory".to_string(),
                    dns_provider_ref: None,
                }),
                ca: None,
                vault: None,
            },
        );
        assert!(issuer.spec.validate().is_ok());
    }

    #[test]
    fn acme_with_dns_provider_ref_valid() {
        let issuer = make_issuer(
            "public",
            CertIssuerSpec {
                type_: IssuerType::Acme,
                acme: Some(AcmeIssuerSpec {
                    email: "ops@example.com".to_string(),
                    server: "https://acme-v2.api.letsencrypt.org/directory".to_string(),
                    dns_provider_ref: Some("public".to_string()),
                }),
                ca: None,
                vault: None,
            },
        );
        assert!(issuer.spec.validate().is_ok());
    }

    #[test]
    fn acme_empty_dns_provider_ref_fails() {
        let issuer = make_issuer(
            "public",
            CertIssuerSpec {
                type_: IssuerType::Acme,
                acme: Some(AcmeIssuerSpec {
                    email: "ops@example.com".to_string(),
                    server: "https://acme-v2.api.letsencrypt.org/directory".to_string(),
                    dns_provider_ref: Some(String::new()),
                }),
                ca: None,
                vault: None,
            },
        );
        assert!(issuer.spec.validate().is_err());
    }

    #[test]
    fn acme_missing_config_fails() {
        let issuer = make_issuer(
            "public",
            CertIssuerSpec {
                type_: IssuerType::Acme,
                acme: None,
                ca: None,
                vault: None,
            },
        );
        assert!(issuer.spec.validate().is_err());
    }

    #[test]
    fn acme_empty_email_fails() {
        let issuer = make_issuer(
            "public",
            CertIssuerSpec {
                type_: IssuerType::Acme,
                acme: Some(AcmeIssuerSpec {
                    email: String::new(),
                    server: "https://acme-v2.api.letsencrypt.org/directory".to_string(),
                    dns_provider_ref: None,
                }),
                ca: None,
                vault: None,
            },
        );
        assert!(issuer.spec.validate().is_err());
    }

    #[test]
    fn acme_empty_server_fails() {
        let issuer = make_issuer(
            "public",
            CertIssuerSpec {
                type_: IssuerType::Acme,
                acme: Some(AcmeIssuerSpec {
                    email: "ops@example.com".to_string(),
                    server: String::new(),
                    dns_provider_ref: None,
                }),
                ca: None,
                vault: None,
            },
        );
        assert!(issuer.spec.validate().is_err());
    }

    // =========================================================================
    // CA Issuer Tests
    // =========================================================================

    #[test]
    fn ca_valid() {
        let issuer = make_issuer(
            "internal",
            CertIssuerSpec {
                type_: IssuerType::Ca,
                acme: None,
                ca: Some(CaIssuerSpec {
                    credentials: CredentialSpec::test("pki/internal-ca", "lattice-local"),
                }),
                vault: None,
            },
        );
        assert!(issuer.spec.validate().is_ok());
    }

    #[test]
    fn ca_missing_config_fails() {
        let issuer = make_issuer(
            "internal",
            CertIssuerSpec {
                type_: IssuerType::Ca,
                acme: None,
                ca: None,
                vault: None,
            },
        );
        assert!(issuer.spec.validate().is_err());
    }

    // =========================================================================
    // Self-Signed Issuer Tests
    // =========================================================================

    #[test]
    fn self_signed_valid() {
        let issuer = make_issuer(
            "dev",
            CertIssuerSpec {
                type_: IssuerType::SelfSigned,
                acme: None,
                ca: None,
                vault: None,
            },
        );
        assert!(issuer.spec.validate().is_ok());
    }

    #[test]
    fn self_signed_with_acme_config_fails() {
        let issuer = make_issuer(
            "dev",
            CertIssuerSpec {
                type_: IssuerType::SelfSigned,
                acme: Some(AcmeIssuerSpec {
                    email: "ops@example.com".to_string(),
                    server: "https://acme.example.com".to_string(),
                    dns_provider_ref: None,
                }),
                ca: None,
                vault: None,
            },
        );
        let err = issuer.spec.validate().unwrap_err();
        assert!(err.to_string().contains("must not have"));
    }

    // =========================================================================
    // Vault Issuer Tests
    // =========================================================================

    #[test]
    fn vault_valid() {
        let issuer = make_issuer(
            "vault-pki",
            CertIssuerSpec {
                type_: IssuerType::Vault,
                acme: None,
                ca: None,
                vault: Some(VaultIssuerSpec {
                    server: "https://vault.example.com".to_string(),
                    path: "pki".to_string(),
                    auth_credentials: CredentialSpec::test("vault/auth", "lattice-local"),
                }),
            },
        );
        assert!(issuer.spec.validate().is_ok());
    }

    #[test]
    fn vault_missing_config_fails() {
        let issuer = make_issuer(
            "vault-pki",
            CertIssuerSpec {
                type_: IssuerType::Vault,
                acme: None,
                ca: None,
                vault: None,
            },
        );
        assert!(issuer.spec.validate().is_err());
    }

    #[test]
    fn vault_empty_server_fails() {
        let issuer = make_issuer(
            "vault-pki",
            CertIssuerSpec {
                type_: IssuerType::Vault,
                acme: None,
                ca: None,
                vault: Some(VaultIssuerSpec {
                    server: String::new(),
                    path: "pki".to_string(),
                    auth_credentials: CredentialSpec::test("vault/auth", "lattice-local"),
                }),
            },
        );
        assert!(issuer.spec.validate().is_err());
    }

    #[test]
    fn vault_empty_path_fails() {
        let issuer = make_issuer(
            "vault-pki",
            CertIssuerSpec {
                type_: IssuerType::Vault,
                acme: None,
                ca: None,
                vault: Some(VaultIssuerSpec {
                    server: "https://vault.example.com".to_string(),
                    path: String::new(),
                    auth_credentials: CredentialSpec::test("vault/auth", "lattice-local"),
                }),
            },
        );
        assert!(issuer.spec.validate().is_err());
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
    // CertIssuerPhase Display
    // =========================================================================

    #[test]
    fn cert_issuer_phase_display() {
        assert_eq!(CertIssuerPhase::Pending.to_string(), "Pending");
        assert_eq!(CertIssuerPhase::Ready.to_string(), "Ready");
        assert_eq!(CertIssuerPhase::Failed.to_string(), "Failed");
    }

    // =========================================================================
    // YAML Roundtrip
    // =========================================================================

    #[test]
    fn cert_issuer_spec_json_roundtrip() {
        let spec = CertIssuerSpec {
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
        let parsed: CertIssuerSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(spec, parsed);
    }

    // =========================================================================
    // DnsConfig Validation (unchanged)
    // =========================================================================

    fn with_provider(key: &str, value: &str) -> BTreeMap<String, String> {
        BTreeMap::from([(key.to_string(), value.to_string())])
    }

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
