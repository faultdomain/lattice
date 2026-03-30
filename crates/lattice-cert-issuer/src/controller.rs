//! CertIssuer reconciliation controller
//!
//! Watches CertIssuer CRDs and validates configuration and dependencies.
//!
//! Validation varies by issuer type:
//! - **ACME with dns_provider_ref**: Fetches the referenced DNSProvider CRD and verifies it's Ready
//! - **CA**: Verifies the referenced CA secret exists
//! - **Vault**: Verifies the auth secret exists
//! - **SelfSigned**: No extra validation needed

use std::sync::Arc;
use std::time::Duration;

use kube::api::Api;
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{
    CertIssuer, CertIssuerPhase, CertIssuerStatus, DNSProvider, DNSProviderPhase, IssuerType,
};
use lattice_common::status_check;
use lattice_common::{
    ControllerContext, ReconcileError, LATTICE_SYSTEM_NAMESPACE, REQUEUE_ERROR_SECS,
    REQUEUE_SUCCESS_SECS,
};
use lattice_secret_provider::credentials::{
    reconcile_credentials as reconcile_eso_credentials, ProviderCredentialConfig,
};

const FIELD_MANAGER: &str = "lattice-cert-issuer-controller";

/// Reconcile a CertIssuer
///
/// Validates spec and dependencies (secrets, DNSProvider refs), then updates status.
/// Skips work when the spec hasn't changed (generation matches) and already Ready.
pub async fn reconcile(
    issuer: Arc<CertIssuer>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = issuer.name_any();
    let client = &ctx.client;
    let generation = issuer.metadata.generation.unwrap_or(0);

    // Skip work if spec unchanged and already Ready
    if status_check::is_status_unchanged(
        issuer.status.as_ref(),
        &CertIssuerPhase::Ready,
        None,
        Some(generation),
    ) {
        return Ok(Action::requeue(Duration::from_secs(300)));
    }

    info!(cert_issuer = %name, issuer_type = ?issuer.spec.type_, "Reconciling CertIssuer");

    match validate_issuer(client, &issuer).await {
        Ok(()) => {
            info!(cert_issuer = %name, "CertIssuer validated successfully");

            update_status(
                client,
                &issuer,
                CertIssuerPhase::Ready,
                Some("Validated successfully".to_string()),
                Some(generation),
            )
            .await?;

            Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
        }
        Err(e) => {
            warn!(
                cert_issuer = %name,
                error = %e,
                "CertIssuer validation failed"
            );

            update_status(
                client,
                &issuer,
                CertIssuerPhase::Failed,
                Some(e.to_string()),
                Some(generation),
            )
            .await?;

            Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)))
        }
    }
}

/// Validate a CertIssuer's spec and dependencies.
async fn validate_issuer(client: &Client, issuer: &CertIssuer) -> Result<(), ReconcileError> {
    // Validate the spec itself
    issuer
        .spec
        .validate()
        .map_err(|e| ReconcileError::Validation(e.to_string()))?;

    let ns = issuer
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

    match issuer.spec.type_ {
        IssuerType::Acme => {
            // If ACME has a dns_provider_ref, verify the DNSProvider exists and is Ready
            if let Some(ref acme) = issuer.spec.acme {
                if let Some(ref dns_ref) = acme.dns_provider_ref {
                    let dns_api: Api<DNSProvider> = Api::namespaced(client.clone(), &ns);
                    let dns_provider = dns_api.get(dns_ref).await.map_err(ReconcileError::Kube)?;

                    let dns_phase = dns_provider
                        .status
                        .as_ref()
                        .map(|s| &s.phase)
                        .unwrap_or(&DNSProviderPhase::Pending);

                    if *dns_phase != DNSProviderPhase::Ready {
                        return Err(ReconcileError::Validation(format!(
                            "referenced DNSProvider '{}' is not Ready (current phase: {})",
                            dns_ref, dns_phase,
                        )));
                    }

                    debug!(
                        cert_issuer = %issuer.name_any(),
                        dns_provider = %dns_ref,
                        "Referenced DNSProvider is Ready"
                    );
                }
            }
            Ok(())
        }
        IssuerType::Ca => {
            let ca = issuer.spec.ca.as_ref().ok_or_else(|| {
                ReconcileError::Validation("ca config required when type is ca".into())
            })?;

            reconcile_eso_credentials(
                client,
                &ProviderCredentialConfig {
                    provider_name: &issuer.name_any(),
                    credentials: &ca.credentials,
                    credential_data: None,
                    target_namespace: LATTICE_SYSTEM_NAMESPACE,
                    field_manager: FIELD_MANAGER,
                },
            )
            .await?;

            debug!(cert_issuer = %issuer.name_any(), "CA credentials reconciled via ESO");
            Ok(())
        }
        IssuerType::Vault => {
            let vault = issuer.spec.vault.as_ref().ok_or_else(|| {
                ReconcileError::Validation("vault config required when type is vault".into())
            })?;

            reconcile_eso_credentials(
                client,
                &ProviderCredentialConfig {
                    provider_name: &issuer.name_any(),
                    credentials: &vault.auth_credentials,
                    credential_data: None,
                    target_namespace: LATTICE_SYSTEM_NAMESPACE,
                    field_manager: FIELD_MANAGER,
                },
            )
            .await?;

            debug!(cert_issuer = %issuer.name_any(), "Vault auth credentials reconciled via ESO");
            Ok(())
        }
        IssuerType::SelfSigned => {
            debug!(cert_issuer = %issuer.name_any(), "SelfSigned issuer requires no extra validation");
            Ok(())
        }
        _ => Err(ReconcileError::Validation(format!(
            "unsupported issuer type: {}",
            issuer.spec.type_
        ))),
    }
}

/// Update CertIssuer status
async fn update_status(
    client: &Client,
    issuer: &CertIssuer,
    phase: CertIssuerPhase,
    message: Option<String>,
    observed_generation: Option<i64>,
) -> Result<(), ReconcileError> {
    if status_check::is_status_unchanged(
        issuer.status.as_ref(),
        &phase,
        message.as_deref(),
        observed_generation,
    ) {
        debug!(cert_issuer = %issuer.name_any(), "Status unchanged, skipping update");
        return Ok(());
    }

    let name = issuer.name_any();
    let namespace = issuer
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

    let status = CertIssuerStatus {
        phase,
        message,
        observed_generation,
    };

    lattice_common::kube_utils::patch_resource_status::<CertIssuer>(
        client,
        &name,
        &namespace,
        &status,
        FIELD_MANAGER,
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{
        AcmeIssuerSpec, CaIssuerSpec, CertIssuerSpec, ResourceParams, ResourceType, SecretParams,
        VaultIssuerSpec,
    };
    use lattice_common::crd::workload::resources::ResourceSpec;

    // =========================================================================
    // Test Helpers
    // =========================================================================

    fn sample_acme_issuer() -> CertIssuer {
        CertIssuer::new(
            "public",
            CertIssuerSpec {
                type_: IssuerType::Acme,
                acme: Some(AcmeIssuerSpec {
                    email: "ops@example.com".to_string(),
                    server: "https://acme-v2.api.letsencrypt.org/directory".to_string(),
                    dns_provider_ref: Some("route53-prod".to_string()),
                }),
                ca: None,
                vault: None,
            },
        )
    }

    fn sample_ca_issuer() -> CertIssuer {
        CertIssuer::new(
            "internal",
            CertIssuerSpec {
                type_: IssuerType::Ca,
                acme: None,
                ca: Some(CaIssuerSpec {
                    credentials: ResourceSpec::test_secret("pki/internal-ca", "lattice-local"),
                }),
                vault: None,
            },
        )
    }

    fn sample_vault_issuer() -> CertIssuer {
        CertIssuer::new(
            "vault-pki",
            CertIssuerSpec {
                type_: IssuerType::Vault,
                acme: None,
                ca: None,
                vault: Some(VaultIssuerSpec {
                    server: "https://vault.example.com".to_string(),
                    path: "pki".to_string(),
                    auth_credentials: ResourceSpec::test_secret("vault/auth", "lattice-local"),
                }),
            },
        )
    }

    fn sample_self_signed_issuer() -> CertIssuer {
        CertIssuer::new(
            "dev",
            CertIssuerSpec {
                type_: IssuerType::SelfSigned,
                acme: None,
                ca: None,
                vault: None,
            },
        )
    }

    // =========================================================================
    // Spec Validation Tests
    // =========================================================================

    #[tokio::test]
    async fn acme_spec_validates() {
        let issuer = sample_acme_issuer();
        assert!(issuer.spec.validate().is_ok());
    }

    #[tokio::test]
    async fn ca_spec_validates() {
        let issuer = sample_ca_issuer();
        assert!(issuer.spec.validate().is_ok());
    }

    #[tokio::test]
    async fn vault_spec_validates() {
        let issuer = sample_vault_issuer();
        assert!(issuer.spec.validate().is_ok());
    }

    #[tokio::test]
    async fn self_signed_spec_validates() {
        let issuer = sample_self_signed_issuer();
        assert!(issuer.spec.validate().is_ok());
    }

    #[tokio::test]
    async fn acme_missing_config_fails() {
        let issuer = CertIssuer::new(
            "bad-acme",
            CertIssuerSpec {
                type_: IssuerType::Acme,
                acme: None,
                ca: None,
                vault: None,
            },
        );
        assert!(issuer.spec.validate().is_err());
    }

    #[tokio::test]
    async fn acme_empty_email_fails() {
        let issuer = CertIssuer::new(
            "bad-acme",
            CertIssuerSpec {
                type_: IssuerType::Acme,
                acme: Some(AcmeIssuerSpec {
                    email: String::new(),
                    server: "https://acme.example.com".to_string(),
                    dns_provider_ref: None,
                }),
                ca: None,
                vault: None,
            },
        );
        assert!(issuer.spec.validate().is_err());
    }

    #[tokio::test]
    async fn acme_empty_server_fails() {
        let issuer = CertIssuer::new(
            "bad-acme",
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

    #[tokio::test]
    async fn ca_missing_config_fails() {
        let issuer = CertIssuer::new(
            "bad-ca",
            CertIssuerSpec {
                type_: IssuerType::Ca,
                acme: None,
                ca: None,
                vault: None,
            },
        );
        assert!(issuer.spec.validate().is_err());
    }

    #[tokio::test]
    async fn vault_missing_config_fails() {
        let issuer = CertIssuer::new(
            "bad-vault",
            CertIssuerSpec {
                type_: IssuerType::Vault,
                acme: None,
                ca: None,
                vault: None,
            },
        );
        assert!(issuer.spec.validate().is_err());
    }

    #[tokio::test]
    async fn vault_empty_server_fails() {
        let issuer = CertIssuer::new(
            "bad-vault",
            CertIssuerSpec {
                type_: IssuerType::Vault,
                acme: None,
                ca: None,
                vault: Some(VaultIssuerSpec {
                    server: String::new(),
                    path: "pki".to_string(),
                    auth_credentials: ResourceSpec::test_secret("vault/auth", "lattice-local"),
                }),
            },
        );
        assert!(issuer.spec.validate().is_err());
    }

    #[tokio::test]
    async fn vault_empty_path_fails() {
        let issuer = CertIssuer::new(
            "bad-vault",
            CertIssuerSpec {
                type_: IssuerType::Vault,
                acme: None,
                ca: None,
                vault: Some(VaultIssuerSpec {
                    server: "https://vault.example.com".to_string(),
                    path: String::new(),
                    auth_credentials: ResourceSpec::test_secret("vault/auth", "lattice-local"),
                }),
            },
        );
        assert!(issuer.spec.validate().is_err());
    }

    #[tokio::test]
    async fn self_signed_with_extra_config_fails() {
        let issuer = CertIssuer::new(
            "bad-self-signed",
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
        assert!(issuer.spec.validate().is_err());
    }

    // =========================================================================
    // Status Tests
    // =========================================================================

    #[tokio::test]
    async fn status_unchanged_skips_update() {
        let mut issuer = sample_acme_issuer();
        issuer.status = Some(CertIssuerStatus {
            phase: CertIssuerPhase::Ready,
            message: None,
            observed_generation: Some(1),
        });

        assert!(status_check::is_status_unchanged(
            issuer.status.as_ref(),
            &CertIssuerPhase::Ready,
            None,
            Some(1),
        ));
        assert!(!status_check::is_status_unchanged(
            issuer.status.as_ref(),
            &CertIssuerPhase::Failed,
            None,
            Some(1),
        ));
        assert!(!status_check::is_status_unchanged(
            issuer.status.as_ref(),
            &CertIssuerPhase::Ready,
            None,
            Some(2),
        ));
    }

    #[tokio::test]
    async fn status_fields() {
        let status = CertIssuerStatus {
            phase: CertIssuerPhase::Failed,
            message: Some("secret not found".to_string()),
            observed_generation: Some(2),
        };

        assert_eq!(status.phase, CertIssuerPhase::Failed);
        assert!(status.message.is_some());
        assert_eq!(status.observed_generation, Some(2));
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[tokio::test]
    async fn issuer_with_namespace_uses_it() {
        let mut issuer = sample_acme_issuer();
        issuer.metadata.namespace = Some("custom-namespace".to_string());
        assert_eq!(issuer.namespace(), Some("custom-namespace".to_string()));
    }

    #[tokio::test]
    async fn issuer_without_namespace_uses_default() {
        let issuer = sample_acme_issuer();
        let namespace = issuer
            .namespace()
            .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());
        assert_eq!(namespace, LATTICE_SYSTEM_NAMESPACE);
    }

    #[tokio::test]
    async fn all_issuer_types_covered() {
        let types = [
            IssuerType::Acme,
            IssuerType::Ca,
            IssuerType::SelfSigned,
            IssuerType::Vault,
        ];

        for t in types {
            let display = t.to_string();
            assert!(!display.is_empty());
        }
    }

    #[tokio::test]
    async fn acme_without_dns_ref_validates() {
        let issuer = CertIssuer::new(
            "http-only",
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
}
