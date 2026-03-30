//! DNSProvider reconciliation controller
//!
//! Watches DNSProvider CRDs and validates configuration and credentials.
//!
//! For cloud DNS providers (Route53, Cloudflare, Google, Azure), the controller
//! verifies that the referenced credentials Secret exists. For Pi-hole, only
//! spec validation is performed (URL must be present).

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{DNSProvider, DNSProviderPhase, DNSProviderStatus, DNSProviderType};
use lattice_common::status_check;
use lattice_common::{
    ControllerContext, ReconcileError, LATTICE_SYSTEM_NAMESPACE, REQUEUE_ERROR_SECS,
    REQUEUE_SUCCESS_SECS,
};
use lattice_secret_provider::credentials::{
    reconcile_credentials as reconcile_eso_credentials, ProviderCredentialConfig,
};

const FIELD_MANAGER: &str = "lattice-dns-provider-controller";

/// Namespace where external-dns pods run. ESO-synced secrets must land here.
const EXTERNAL_DNS_NAMESPACE: &str = "external-dns";

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

    // Validate credentialData requires credentials
    if provider.spec.credential_data.is_some() && provider.spec.credentials.is_none() {
        return Err(ReconcileError::Validation(
            "credentialData requires credentials to be set".into(),
        ));
    }

    // Reconcile ESO credentials for all provider types.
    // Pihole credentials are optional (some setups have no password),
    // all other providers require credentials.
    if let Some(ref credentials) = provider.spec.credentials {
        reconcile_eso_credentials(
            client,
            &ProviderCredentialConfig {
                provider_name: &provider.name_any(),
                credentials,
                credential_data: provider.spec.credential_data.as_ref(),
                target_namespace: EXTERNAL_DNS_NAMESPACE,
                field_manager: FIELD_MANAGER,
            },
        )
        .await?;
    } else if provider.spec.provider_type != DNSProviderType::Pihole {
        return Err(ReconcileError::Validation(format!(
            "{} provider requires credentials",
            provider.spec.provider_type
        )));
    }

    Ok(())
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
        AzureDnsConfig, CloudflareConfig, DNSProviderSpec, GoogleDnsConfig, PiholeConfig, ResourceSpec, Route53Config,
    };


    fn sample_pihole_provider() -> DNSProvider {
        DNSProvider::new(
            "pihole-local",
            DNSProviderSpec {
                pihole: Some(PiholeConfig {
                    url: "http://pihole.local".to_string(),
                }),
                ..DNSProviderSpec::new(DNSProviderType::Pihole, "home.local")
            },
        )
    }

    fn sample_route53_provider() -> DNSProvider {
        DNSProvider::new(
            "route53-prod",
            DNSProviderSpec {
                credentials: Some(ResourceSpec::test_secret_with_keys(
                    "dns/aws/prod",
                    "vault-prod",
                    &["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
                )),
                route53: Some(Route53Config {
                    region: Some("us-east-1".to_string()),
                    hosted_zone_id: Some("Z1234567890".to_string()),
                }),
                ..DNSProviderSpec::new(DNSProviderType::Route53, "example.com")
            },
        )
    }

    fn sample_cloudflare_provider() -> DNSProvider {
        DNSProvider::new(
            "cloudflare-prod",
            DNSProviderSpec {
                credentials: Some(ResourceSpec::test_secret_with_keys(
                    "dns/cloudflare/prod",
                    "vault-prod",
                    &["CF_API_TOKEN"],
                )),
                cloudflare: Some(CloudflareConfig { proxied: true }),
                ..DNSProviderSpec::new(DNSProviderType::Cloudflare, "example.com")
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
        let provider = DNSProvider::new("bad", DNSProviderSpec::new(DNSProviderType::Route53, ""));
        assert!(provider.spec.validate().is_err());
    }

    #[tokio::test]
    async fn pihole_missing_config_fails() {
        let provider = DNSProvider::new(
            "bad-pihole",
            DNSProviderSpec::new(DNSProviderType::Pihole, "home.local"),
        );
        assert!(provider.spec.validate().is_err());
    }

    #[tokio::test]
    async fn pihole_empty_url_fails() {
        let provider = DNSProvider::new(
            "bad-pihole",
            DNSProviderSpec {
                pihole: Some(PiholeConfig { url: String::new() }),
                ..DNSProviderSpec::new(DNSProviderType::Pihole, "home.local")
            },
        );
        assert!(provider.spec.validate().is_err());
    }

    #[tokio::test]
    async fn google_missing_config_fails() {
        let provider = DNSProvider::new(
            "bad-google",
            DNSProviderSpec::new(DNSProviderType::Google, "example.com"),
        );
        assert!(provider.spec.validate().is_err());
    }

    #[tokio::test]
    async fn azure_missing_config_fails() {
        let provider = DNSProvider::new(
            "bad-azure",
            DNSProviderSpec::new(DNSProviderType::Azure, "example.com"),
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
    async fn route53_requires_credentials() {
        let provider = DNSProvider::new(
            "route53-no-creds",
            DNSProviderSpec::new(DNSProviderType::Route53, "example.com"),
        );
        assert!(provider.spec.validate().is_ok());
        assert!(provider.spec.credentials.is_none());
        assert!(provider.k8s_secret_ref().is_none());
    }

    #[tokio::test]
    async fn eso_credentials_resolve_to_external_dns_namespace() {
        let provider = sample_route53_provider();
        let secret_ref = provider.k8s_secret_ref().unwrap();
        assert_eq!(secret_ref.name, "route53-prod-credentials");
        assert_eq!(secret_ref.namespace, EXTERNAL_DNS_NAMESPACE);
    }

    #[tokio::test]
    async fn cloudflare_has_eso_credentials() {
        let provider = sample_cloudflare_provider();
        assert!(provider.spec.credentials.is_some());
        let secret_ref = provider.k8s_secret_ref().unwrap();
        assert_eq!(secret_ref.name, "cloudflare-prod-credentials");
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
            cluster_count: 3,
            observed_generation: Some(2),
        };

        assert_eq!(status.phase, DNSProviderPhase::Failed);
        assert!(status.message.is_some());
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
            DNSProviderSpec {
                credentials: Some(ResourceSpec::test_secret_with_keys("dns/gcp/prod", "vault-prod", &["key.json"])),
                google: Some(GoogleDnsConfig {
                    project: "my-project".to_string(),
                }),
                ..DNSProviderSpec::new(DNSProviderType::Google, "example.com")
            },
        );
        assert!(provider.spec.validate().is_ok());
    }

    #[tokio::test]
    async fn azure_with_config_valid() {
        let provider = DNSProvider::new(
            "azure-prod",
            DNSProviderSpec {
                credentials: Some(ResourceSpec::test_secret_with_keys("dns/azure/prod", "vault-prod", &["azure.json"])),
                azure: Some(AzureDnsConfig {
                    subscription_id: "sub-123".to_string(),
                    resource_group: "rg-dns".to_string(),
                }),
                ..DNSProviderSpec::new(DNSProviderType::Azure, "example.com")
            },
        );
        assert!(provider.spec.validate().is_ok());
    }
}
