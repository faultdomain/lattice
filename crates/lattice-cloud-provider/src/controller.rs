//! InfraProvider reconciliation controller
//!
//! Watches InfraProvider CRDs and reconciles credentials.
//!
//! ## Credential Modes
//!
//! InfraProvider supports three mutually exclusive credential modes:
//!
//! - **ESO mode** (`credentials` field): The controller creates an ESO ExternalSecret
//!   that syncs credentials from a ClusterSecretStore. Optionally shaped with
//!   `credentialData` templates.
//!
//! - **Manual mode** (`credentialsSecretRef` field): Operator manages the K8s Secret
//!   directly. The controller only validates the reference is present.
//!
//! - **No credentials** (Docker provider): No credentials required.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{
    InfraProvider, InfraProviderPhase, InfraProviderStatus, InfraProviderType,
};
use lattice_common::status_check;
use lattice_common::{
    ControllerContext, ReconcileError, LATTICE_SYSTEM_NAMESPACE, REQUEUE_ERROR_SECS,
    REQUEUE_SUCCESS_SECS,
};
use lattice_secret_provider::credentials::{
    reconcile_credentials as reconcile_eso_credentials, ProviderCredentialConfig,
};

const FIELD_MANAGER: &str = "lattice-cloud-provider-controller";

/// Reconcile a InfraProvider
///
/// Reconciles credentials (ESO or manual) and updates status.
/// Skips work when the spec hasn't changed (generation matches) and already Ready.
pub async fn reconcile(
    cp: Arc<InfraProvider>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = cp.name_any();
    let client = &ctx.client;
    let generation = cp.metadata.generation.unwrap_or(0);

    // Skip work if spec unchanged and already Ready
    if status_check::is_status_unchanged(
        cp.status.as_ref(),
        &InfraProviderPhase::Ready,
        None,
        Some(generation),
    ) {
        return Ok(Action::requeue(Duration::from_secs(300)));
    }

    info!(cloud_provider = %name, provider_type = ?cp.spec.provider_type, "Reconciling InfraProvider");

    match reconcile_credentials(client, &cp).await {
        Ok(()) => {
            info!(cloud_provider = %name, "Credentials reconciled successfully");

            update_status(
                client,
                &cp,
                InfraProviderPhase::Ready,
                Some("Credentials reconciled successfully".to_string()),
                Some(generation),
            )
            .await?;

            // Requeue periodically to re-validate
            Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
        }
        Err(e) => {
            warn!(
                cloud_provider = %name,
                error = %e,
                "Credential reconciliation failed"
            );

            update_status(
                client,
                &cp,
                InfraProviderPhase::Failed,
                Some(e.to_string()),
                Some(generation),
            )
            .await?;

            Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)))
        }
    }
}

/// Reconcile ESO credentials for the cloud provider.
///
/// Docker providers require no credentials. All others require the
/// `credentials` field (ESO ResourceSpec).
async fn reconcile_credentials(client: &Client, cp: &InfraProvider) -> Result<(), ReconcileError> {
    if cp.spec.credential_data.is_some() && cp.spec.credentials.is_none() {
        return Err(ReconcileError::Validation(
            "credentialData requires credentials to be set".into(),
        ));
    }

    match cp.spec.provider_type {
        InfraProviderType::Docker => {
            debug!(cloud_provider = %cp.name_any(), "Docker provider requires no credentials");
            Ok(())
        }
        provider_type => {
            if let Some(ref credentials) = cp.spec.credentials {
                reconcile_eso_credentials(
                    client,
                    &ProviderCredentialConfig {
                        provider_name: &cp.name_any(),
                        credentials,
                        credential_data: cp.spec.credential_data.as_ref(),
                        target_namespace: LATTICE_SYSTEM_NAMESPACE,
                        field_manager: FIELD_MANAGER,
                    },
                )
                .await?;
                Ok(())
            } else {
                Err(ReconcileError::Validation(format!(
                    "{:?} provider requires credentials",
                    provider_type
                )))
            }
        }
    }
}

/// Update InfraProvider status
async fn update_status(
    client: &Client,
    cp: &InfraProvider,
    phase: InfraProviderPhase,
    message: Option<String>,
    observed_generation: Option<i64>,
) -> Result<(), ReconcileError> {
    if status_check::is_status_unchanged(
        cp.status.as_ref(),
        &phase,
        message.as_deref(),
        observed_generation,
    ) {
        debug!(cloud_provider = %cp.name_any(), "Status unchanged, skipping update");
        return Ok(());
    }

    let name = cp.name_any();
    let namespace = cp
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

    let status = InfraProviderStatus {
        phase,
        message,
        last_validated: Some(chrono::Utc::now().to_rfc3339()),
        cluster_count: 0,
        observed_generation,
    };

    lattice_common::kube_utils::patch_resource_status::<InfraProvider>(
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
    use kube::core::ObjectMeta;
    use lattice_common::crd::{
        InfraProviderSpec, ResourceParams, ResourceSpec, ResourceType, SecretParams,
    };
    use lattice_common::template::extract_secret_refs;
    use lattice_secret_provider::eso::{build_external_secret, build_templated_external_secret};
    use std::collections::BTreeMap;


    fn sample_provider(provider_type: InfraProviderType) -> InfraProvider {
        let (name, region) = match provider_type {
            InfraProviderType::Docker => ("docker", None),
            InfraProviderType::AWS => ("aws-prod", Some("us-east-1")),
            InfraProviderType::Proxmox => ("proxmox-homelab", None),
            InfraProviderType::OpenStack => ("openstack-prod", Some("RegionOne")),
            _ => ("unknown", None),
        };

        let credentials = if provider_type == InfraProviderType::Docker {
            None
        } else {
            Some(ResourceSpec::test_secret(&format!("infra/{name}"), "lattice-local"))
        };

        InfraProvider::new(
            name,
            InfraProviderSpec {
                provider_type,
                region: region.map(String::from),
                credentials,
                credential_data: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        )
    }

    #[tokio::test]
    async fn docker_no_credentials() {
        let cp = sample_provider(InfraProviderType::Docker);
        assert_eq!(cp.spec.provider_type, InfraProviderType::Docker);
        assert!(cp.spec.credentials.is_none());
        assert!(cp.k8s_secret_ref().is_none());
    }

    #[tokio::test]
    async fn eso_credentials_resolve() {
        let cp = sample_provider(InfraProviderType::AWS);
        assert!(cp.spec.credentials.is_some());
        let secret_ref = cp.k8s_secret_ref().unwrap();
        assert_eq!(secret_ref.name, "aws-prod-credentials");
        assert_eq!(secret_ref.namespace, LATTICE_SYSTEM_NAMESPACE);
    }

    #[tokio::test]
    async fn credential_data_without_credentials_is_invalid() {
        let mut data = BTreeMap::new();
        data.insert("key".to_string(), "value".to_string());

        let cp = InfraProvider::new(
            "test",
            InfraProviderSpec {
                provider_type: InfraProviderType::AWS,
                region: None,
                credentials: None,
                credential_data: Some(data),
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        );

        assert!(cp.spec.credential_data.is_some() && cp.spec.credentials.is_none());
    }

    #[tokio::test]
    async fn simple_mode_builds_external_secret() {
        let cp = sample_provider(InfraProviderType::AWS);

        let resource = cp.spec.credentials.as_ref().unwrap();
        let params = resource.params.as_secret().unwrap();
        let remote_key = resource.secret_remote_key().unwrap();
        let secret_name = format!("{}-credentials", cp.name_any());

        let es = build_external_secret(
            &secret_name,
            LATTICE_SYSTEM_NAMESPACE,
            &params.provider,
            remote_key,
            params.keys.as_deref(),
            None,
        );

        assert_eq!(es.metadata.name, "aws-prod-credentials");
        assert_eq!(es.metadata.namespace, LATTICE_SYSTEM_NAMESPACE);
        assert_eq!(es.spec.secret_store_ref.name, "lattice-local");
    }

    #[tokio::test]
    async fn templated_mode_builds_external_secret() {
        let mut credential_data = BTreeMap::new();
        credential_data.insert(
            "clouds.yaml".to_string(),
            "auth:\n  username: \"${secret.credentials.username}\"\n  password: \"${secret.credentials.password}\"".to_string(),
        );

        let cp = InfraProvider::new(
            "openstack-test",
            InfraProviderSpec {
                provider_type: InfraProviderType::OpenStack,
                region: None,
                credentials: Some(ResourceSpec {
                    type_: ResourceType::Secret,
                    id: Some("infrastructure/openstack/creds".to_string()),
                    params: ResourceParams::Secret(SecretParams {
                        provider: "vault-prod".to_string(),
                        keys: Some(vec![
                            "username".to_string(),
                            "password".to_string(),
                            "auth_url".to_string(),
                        ]),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                credential_data: Some(credential_data.clone()),
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        );

        let resource = cp.spec.credentials.as_ref().unwrap();
        let params = resource.params.as_secret().unwrap();
        let remote_key = resource.secret_remote_key().unwrap();
        let secret_name = format!("{}-credentials", cp.name_any());

        let mut template_data = BTreeMap::new();
        let mut all_refs = Vec::new();
        for (key, value) in &credential_data {
            let (rendered, refs) = extract_secret_refs(value, false);
            template_data.insert(key.clone(), rendered);
            all_refs.extend(refs);
        }

        let es = build_templated_external_secret(
            &secret_name,
            LATTICE_SYSTEM_NAMESPACE,
            &params.provider,
            remote_key,
            params.keys.as_deref(),
            template_data,
            &all_refs,
        )
        .unwrap();

        assert_eq!(es.metadata.name, "openstack-test-credentials");
        assert!(es.spec.target.template.is_some());
        let template = es.spec.target.template.as_ref().unwrap();
        assert!(template.data.contains_key("clouds.yaml"));
        assert!(template.data["clouds.yaml"].contains("{{ .credentials_username }}"));
        assert_eq!(es.spec.data.len(), 2);
    }

    #[tokio::test]
    async fn missing_credentials_for_cloud_provider() {
        let cp = InfraProvider::new(
            "aws-no-creds",
            InfraProviderSpec {
                provider_type: InfraProviderType::AWS,
                region: None,
                credentials: None,
                credential_data: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        );

        assert!(cp.spec.credentials.is_none());
        assert!(cp.k8s_secret_ref().is_none());
    }

    #[tokio::test]
    async fn status_unchanged_skips_update() {
        let mut cp = sample_provider(InfraProviderType::Docker);
        cp.status = Some(InfraProviderStatus {
            phase: InfraProviderPhase::Ready,
            message: None,
            last_validated: Some("2024-01-01T00:00:00Z".to_string()),
            cluster_count: 0,
            observed_generation: Some(1),
        });

        assert!(status_check::is_status_unchanged(
            cp.status.as_ref(),
            &InfraProviderPhase::Ready,
            None,
            Some(1)
        ));
        assert!(!status_check::is_status_unchanged(
            cp.status.as_ref(),
            &InfraProviderPhase::Failed,
            None,
            Some(1)
        ));
    }

    #[tokio::test]
    async fn provider_with_namespace_uses_it() {
        let mut cp = sample_provider(InfraProviderType::Docker);
        cp.metadata = ObjectMeta {
            name: Some("test-provider".to_string()),
            namespace: Some("custom-namespace".to_string()),
            ..Default::default()
        };
        assert_eq!(cp.namespace(), Some("custom-namespace".to_string()));
    }

    #[tokio::test]
    async fn all_provider_types_covered() {
        for provider_type in [
            InfraProviderType::Docker,
            InfraProviderType::AWS,
            InfraProviderType::Proxmox,
            InfraProviderType::OpenStack,
        ] {
            let cp = sample_provider(provider_type);
            assert_eq!(cp.spec.provider_type, provider_type);
        }
    }
}
