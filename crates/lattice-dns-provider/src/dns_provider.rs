//! DNSProvider reconciliation controller
//!
//! Watches DNSProvider CRDs and validates configuration and credentials.
//!
//! For cloud DNS providers (Route53, Cloudflare, Google, Azure), the controller
//! verifies that the referenced credentials Secret exists. For Pi-hole, only
//! spec validation is performed (URL must be present).

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::core::v1::Secret;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{
    DNSProvider, DNSProviderPhase, DNSProviderStatus, DNSProviderType,
};
use lattice_common::status_check;
use lattice_common::{
    ControllerContext, ReconcileError, LATTICE_SYSTEM_NAMESPACE, REQUEUE_ERROR_SECS,
    REQUEUE_SUCCESS_SECS,
};

const FIELD_MANAGER: &str = "lattice-dns-provider-controller";

/// Reconcile a DNSProvider
///
/// Validates spec and credentials, then updates status.
/// Skips work when the spec hasn't changed (generation matches) and already Ready.
pub async fn reconcile(
    provider: Arc<DNSProvider>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = provider.name_any();
    let client = &ctx.client;
    let generation = provider.metadata.generation.unwrap_or(0);

    // Skip work if spec unchanged and already Ready
    if status_check::is_status_unchanged(
        provider.status.as_ref(),
        &DNSProviderPhase::Ready,
        None,
        Some(generation),
    ) {
        return Ok(Action::requeue(Duration::from_secs(300)));
    }

    info!(dns_provider = %name, provider_type = ?provider.spec.provider_type, "Reconciling DNSProvider");

    match validate_provider(client, &provider).await {
        Ok(()) => {
            info!(dns_provider = %name, "DNSProvider validated successfully");

            update_status(
                client,
                &provider,
                DNSProviderPhase::Ready,
                Some("Validated successfully".to_string()),
                Some(generation),
            )
            .await?;

            Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
        }
        Err(e) => {
            warn!(
                dns_provider = %name,
                error = %e,
                "DNSProvider validation failed"
            );

            update_status(
                client,
                &provider,
                DNSProviderPhase::Failed,
                Some(e.to_string()),
                Some(generation),
            )
            .await?;

            Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)))
        }
    }
}

/// Validate a DNSProvider's spec and credentials.
async fn validate_provider(client: &Client, provider: &DNSProvider) -> Result<(), ReconcileError> {
    // Validate the spec itself (zone, provider-specific config)
    provider
        .spec
        .validate()
        .map_err(|e| ReconcileError::Validation(e.to_string()))?;

    match provider.spec.provider_type {
        DNSProviderType::Pihole => {
            // Pi-hole only needs spec validation (URL presence), no secret check
            debug!(dns_provider = %provider.name_any(), "Pi-hole provider requires no credentials secret");
            Ok(())
        }
        _ => {
            // All other providers require credentials
            let secret_ref = provider.spec.credentials_secret_ref.as_ref().ok_or_else(|| {
                ReconcileError::Validation(format!(
                    "{} provider requires credentialsSecretRef",
                    provider.spec.provider_type
                ))
            })?;

            let ns = &secret_ref.namespace;
            let secret_name = &secret_ref.name;

            let secrets: Api<Secret> = Api::namespaced(client.clone(), ns);
            secrets
                .get(secret_name)
                .await
                .map_err(ReconcileError::Kube)?;

            debug!(
                dns_provider = %provider.name_any(),
                secret = %secret_name,
                namespace = %ns,
                "Credentials secret verified"
            );

            Ok(())
        }
    }
}

/// Update DNSProvider status
async fn update_status(
    client: &Client,
    provider: &DNSProvider,
    phase: DNSProviderPhase,
    message: Option<String>,
    observed_generation: Option<i64>,
) -> Result<(), ReconcileError> {
    if status_check::is_status_unchanged(
        provider.status.as_ref(),
        &phase,
        message.as_deref(),
        observed_generation,
    ) {
        debug!(dns_provider = %provider.name_any(), "Status unchanged, skipping update");
        return Ok(());
    }

    let name = provider.name_any();
    let namespace = provider
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

    let status = DNSProviderStatus {
        phase,
        message,
        last_validated: Some(chrono::Utc::now().to_rfc3339()),
        cluster_count: 0,
        observed_generation,
    };

    lattice_common::kube_utils::patch_resource_status::<DNSProvider>(
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
        AzureDnsConfig, CloudflareConfig, GoogleDnsConfig, PiholeConfig, Route53Config, SecretRef,
    };

    // =========================================================================
    // Test Helpers
    // =========================================================================

    fn sample_pihole_provider() -> DNSProvider {
        DNSProvider::new(
            "pihole-local",
            lattice_common::crd::DNSProviderSpec {
                provider_type: DNSProviderType::Pihole,
                zone: "home.local".to_string(),
                credentials_secret_ref: Some(SecretRef {
                    name: "pihole-api-key".to_string(),
                    namespace: "lattice-system".to_string(),
                }),
                pihole: Some(PiholeConfig {
                    url: "http://pihole.local".to_string(),
                }),
                route53: None,
                cloudflare: None,
                google: None,
                azure: None,
                designate: None,
                resolver: None,
            },
        )
    }

    fn sample_route53_provider() -> DNSProvider {
        DNSProvider::new(
            "route53-prod",
            lattice_common::crd::DNSProviderSpec {
                provider_type: DNSProviderType::Route53,
                zone: "example.com".to_string(),
                credentials_secret_ref: Some(SecretRef {
                    name: "aws-dns-creds".to_string(),
                    namespace: "lattice-system".to_string(),
                }),
                pihole: None,
                route53: Some(Route53Config {
                    region: Some("us-east-1".to_string()),
                    hosted_zone_id: Some("Z1234567890".to_string()),
                }),
                cloudflare: None,
                google: None,
                azure: None,
                designate: None,
                resolver: None,
            },
        )
    }

    fn sample_cloudflare_provider() -> DNSProvider {
        DNSProvider::new(
            "cloudflare-prod",
            lattice_common::crd::DNSProviderSpec {
                provider_type: DNSProviderType::Cloudflare,
                zone: "example.com".to_string(),
                credentials_secret_ref: Some(SecretRef {
                    name: "cf-api-token".to_string(),
                    namespace: "lattice-system".to_string(),
                }),
                pihole: None,
                route53: None,
                cloudflare: Some(CloudflareConfig { proxied: true }),
                google: None,
                azure: None,
                designate: None,
                resolver: None,
            },
        )
    }

    // =========================================================================
    // Spec Validation Tests
    // =========================================================================

    #[tokio::test]
    async fn pihole_spec_validates() {
        let provider = sample_pihole_provider();
        assert!(provider.spec.validate().is_ok());
    }

    #[tokio::test]
    async fn route53_spec_validates() {
        let provider = sample_route53_provider();
        assert!(provider.spec.validate().is_ok());
    }

    #[tokio::test]
    async fn cloudflare_spec_validates() {
        let provider = sample_cloudflare_provider();
        assert!(provider.spec.validate().is_ok());
    }

    #[tokio::test]
    async fn empty_zone_fails() {
        let provider = DNSProvider::new(
            "bad",
            lattice_common::crd::DNSProviderSpec {
                provider_type: DNSProviderType::Route53,
                zone: String::new(),
                credentials_secret_ref: None,
                pihole: None,
                route53: None,
                cloudflare: None,
                google: None,
                azure: None,
                designate: None,
                resolver: None,
            },
        );
        assert!(provider.spec.validate().is_err());
    }

    #[tokio::test]
    async fn pihole_missing_config_fails() {
        let provider = DNSProvider::new(
            "bad-pihole",
            lattice_common::crd::DNSProviderSpec {
                provider_type: DNSProviderType::Pihole,
                zone: "home.local".to_string(),
                credentials_secret_ref: None,
                pihole: None,
                route53: None,
                cloudflare: None,
                google: None,
                azure: None,
                designate: None,
                resolver: None,
            },
        );
        assert!(provider.spec.validate().is_err());
    }

    #[tokio::test]
    async fn pihole_empty_url_fails() {
        let provider = DNSProvider::new(
            "bad-pihole",
            lattice_common::crd::DNSProviderSpec {
                provider_type: DNSProviderType::Pihole,
                zone: "home.local".to_string(),
                credentials_secret_ref: None,
                pihole: Some(PiholeConfig {
                    url: String::new(),
                }),
                route53: None,
                cloudflare: None,
                google: None,
                azure: None,
                designate: None,
                resolver: None,
            },
        );
        assert!(provider.spec.validate().is_err());
    }

    #[tokio::test]
    async fn google_missing_config_fails() {
        let provider = DNSProvider::new(
            "bad-google",
            lattice_common::crd::DNSProviderSpec {
                provider_type: DNSProviderType::Google,
                zone: "example.com".to_string(),
                credentials_secret_ref: None,
                pihole: None,
                route53: None,
                cloudflare: None,
                google: None,
                azure: None,
                designate: None,
                resolver: None,
            },
        );
        assert!(provider.spec.validate().is_err());
    }

    #[tokio::test]
    async fn azure_missing_config_fails() {
        let provider = DNSProvider::new(
            "bad-azure",
            lattice_common::crd::DNSProviderSpec {
                provider_type: DNSProviderType::Azure,
                zone: "example.com".to_string(),
                credentials_secret_ref: None,
                pihole: None,
                route53: None,
                cloudflare: None,
                google: None,
                azure: None,
                designate: None,
                resolver: None,
            },
        );
        assert!(provider.spec.validate().is_err());
    }

    // =========================================================================
    // Credential Requirement Tests
    // =========================================================================

    #[tokio::test]
    async fn pihole_does_not_require_credentials() {
        let provider = sample_pihole_provider();
        // Pi-hole should not require credentialsSecretRef
        assert_eq!(provider.spec.provider_type, DNSProviderType::Pihole);
        // Pihole validation should pass without checking secret existence
    }

    #[tokio::test]
    async fn route53_requires_credentials_secret_ref() {
        let provider = DNSProvider::new(
            "route53-no-creds",
            lattice_common::crd::DNSProviderSpec {
                provider_type: DNSProviderType::Route53,
                zone: "example.com".to_string(),
                credentials_secret_ref: None,
                pihole: None,
                route53: None,
                cloudflare: None,
                google: None,
                azure: None,
                designate: None,
                resolver: None,
            },
        );
        // Spec validation passes (credentialsSecretRef is not checked there)
        assert!(provider.spec.validate().is_ok());
        // But the provider has no credentials_secret_ref, so the controller would reject it
        assert!(provider.spec.credentials_secret_ref.is_none());
    }

    #[tokio::test]
    async fn cloudflare_has_credentials() {
        let provider = sample_cloudflare_provider();
        assert!(provider.spec.credentials_secret_ref.is_some());
        let secret_ref = provider.spec.credentials_secret_ref.as_ref().unwrap();
        assert_eq!(secret_ref.name, "cf-api-token");
    }

    // =========================================================================
    // Status Tests
    // =========================================================================

    #[tokio::test]
    async fn status_unchanged_skips_update() {
        let mut provider = sample_route53_provider();
        provider.status = Some(DNSProviderStatus {
            phase: DNSProviderPhase::Ready,
            message: None,
            last_validated: Some("2024-01-01T00:00:00Z".to_string()),
            cluster_count: 0,
            observed_generation: Some(1),
        });

        assert!(status_check::is_status_unchanged(
            provider.status.as_ref(),
            &DNSProviderPhase::Ready,
            None,
            Some(1),
        ));
        assert!(!status_check::is_status_unchanged(
            provider.status.as_ref(),
            &DNSProviderPhase::Failed,
            None,
            Some(1),
        ));
        assert!(!status_check::is_status_unchanged(
            provider.status.as_ref(),
            &DNSProviderPhase::Ready,
            None,
            Some(2),
        ));
    }

    #[tokio::test]
    async fn status_fields() {
        let status = DNSProviderStatus {
            phase: DNSProviderPhase::Failed,
            message: Some("credentials not found".to_string()),
            last_validated: Some(chrono::Utc::now().to_rfc3339()),
            cluster_count: 3,
            observed_generation: Some(2),
        };

        assert_eq!(status.phase, DNSProviderPhase::Failed);
        assert!(status.message.is_some());
        assert!(status.last_validated.is_some());
        assert_eq!(status.cluster_count, 3);
        assert_eq!(status.observed_generation, Some(2));
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[tokio::test]
    async fn provider_with_namespace_uses_it() {
        let mut provider = sample_pihole_provider();
        provider.metadata.namespace = Some("custom-namespace".to_string());
        assert_eq!(provider.namespace(), Some("custom-namespace".to_string()));
    }

    #[tokio::test]
    async fn provider_without_namespace_uses_default() {
        let provider = sample_pihole_provider();
        let namespace = provider
            .namespace()
            .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());
        assert_eq!(namespace, LATTICE_SYSTEM_NAMESPACE);
    }

    #[tokio::test]
    async fn all_provider_types_covered() {
        let types = [
            DNSProviderType::Pihole,
            DNSProviderType::Route53,
            DNSProviderType::Cloudflare,
            DNSProviderType::Google,
            DNSProviderType::Azure,
        ];

        for t in types {
            let display = t.to_string();
            assert!(!display.is_empty());
        }
    }

    #[tokio::test]
    async fn google_with_config_valid() {
        let provider = DNSProvider::new(
            "google-prod",
            lattice_common::crd::DNSProviderSpec {
                provider_type: DNSProviderType::Google,
                zone: "example.com".to_string(),
                credentials_secret_ref: Some(SecretRef {
                    name: "gcp-dns-creds".to_string(),
                    namespace: "lattice-system".to_string(),
                }),
                pihole: None,
                route53: None,
                cloudflare: None,
                google: Some(GoogleDnsConfig {
                    project: "my-project".to_string(),
                }),
                azure: None,
                designate: None,
                resolver: None,
            },
        );
        assert!(provider.spec.validate().is_ok());
    }

    #[tokio::test]
    async fn azure_with_config_valid() {
        let provider = DNSProvider::new(
            "azure-prod",
            lattice_common::crd::DNSProviderSpec {
                provider_type: DNSProviderType::Azure,
                zone: "example.com".to_string(),
                credentials_secret_ref: Some(SecretRef {
                    name: "azure-dns-creds".to_string(),
                    namespace: "lattice-system".to_string(),
                }),
                pihole: None,
                route53: None,
                cloudflare: None,
                google: None,
                azure: Some(AzureDnsConfig {
                    subscription_id: "sub-123".to_string(),
                    resource_group: "rg-dns".to_string(),
                }),
                designate: None,
                resolver: None,
            },
        );
        assert!(provider.spec.validate().is_ok());
    }
}
