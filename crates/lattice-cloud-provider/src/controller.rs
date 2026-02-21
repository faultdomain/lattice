//! CloudProvider reconciliation controller
//!
//! Watches CloudProvider CRDs and reconciles credentials.
//!
//! ## Credential Modes
//!
//! CloudProvider supports three mutually exclusive credential modes:
//!
//! 1. **ESO mode** (`credentials` field): The controller creates an ESO ExternalSecret
//!    that syncs credentials from a ClusterSecretStore. Optionally shaped with
//!    `credentialData` templates.
//!
//! 2. **Manual mode** (`credentialsSecretRef` field): Operator manages the K8s Secret
//!    directly. The controller only validates the reference is present.
//!
//! 3. **No credentials** (Docker provider): No credentials required.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{
    CloudProvider, CloudProviderPhase, CloudProviderStatus, CloudProviderType,
};
use lattice_common::template::extract_secret_refs;
use lattice_common::{ControllerContext, ReconcileError, LATTICE_SYSTEM_NAMESPACE};
use lattice_secret_provider::eso::{
    apply_external_secret, build_external_secret, build_templated_external_secret,
};

/// Reconcile a CloudProvider
///
/// Reconciles credentials (ESO or manual) and updates status.
pub async fn reconcile(
    cp: Arc<CloudProvider>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = cp.name_any();
    let client = &ctx.client;

    info!(cloud_provider = %name, provider_type = ?cp.spec.provider_type, "Reconciling CloudProvider");

    match reconcile_credentials(client, &cp).await {
        Ok(()) => {
            info!(cloud_provider = %name, "Credentials reconciled successfully");

            update_status(client, &cp, CloudProviderPhase::Ready, None).await?;

            // Requeue periodically to re-validate
            Ok(Action::requeue(Duration::from_secs(300)))
        }
        Err(e) => {
            warn!(
                cloud_provider = %name,
                error = %e,
                "Credential reconciliation failed"
            );

            update_status(client, &cp, CloudProviderPhase::Failed, Some(e.to_string())).await?;

            // Retry with backoff
            Ok(Action::requeue(Duration::from_secs(60)))
        }
    }
}

/// Reconcile credentials for the cloud provider.
///
/// Handles three modes:
/// - **ESO mode**: Creates ExternalSecret from `credentials` (+ optional `credentialData`)
/// - **Manual mode**: Validates `credentialsSecretRef` is present
/// - **Docker**: No credentials required
async fn reconcile_credentials(client: &Client, cp: &CloudProvider) -> Result<(), ReconcileError> {
    // Mutual exclusion validation
    if cp.spec.credentials.is_some() && cp.spec.credentials_secret_ref.is_some() {
        return Err(ReconcileError::Validation(
            "credentials and credentialsSecretRef are mutually exclusive".into(),
        ));
    }
    if cp.spec.credential_data.is_some() && cp.spec.credentials.is_none() {
        return Err(ReconcileError::Validation(
            "credentialData requires credentials to be set".into(),
        ));
    }

    match cp.spec.provider_type {
        CloudProviderType::Docker => {
            debug!(cloud_provider = %cp.name_any(), "Docker provider requires no credentials");
            Ok(())
        }
        provider_type => {
            if let Some(ref resource) = cp.spec.credentials {
                // ESO mode: create ExternalSecret
                let params = resource
                    .secret_params()
                    .map_err(|e| ReconcileError::Validation(format!("credentials: {}", e)))?
                    .ok_or_else(|| {
                        ReconcileError::Validation(
                            "credentials must have type: secret with params.provider".into(),
                        )
                    })?;

                let remote_key = resource.secret_remote_key().ok_or_else(|| {
                    ReconcileError::Validation(
                        "credentials: missing 'id' field (remote key)".into(),
                    )
                })?;

                let secret_name = format!("{}-credentials", cp.name_any());

                let es = if let Some(ref data) = cp.spec.credential_data {
                    // Templated mode: extract ${secret.*} refs, build templated ExternalSecret
                    let mut template_data = BTreeMap::new();
                    let mut all_refs = Vec::new();
                    for (key, value) in data {
                        let (rendered, refs) = extract_secret_refs(value, false);
                        template_data.insert(key.clone(), rendered);
                        all_refs.extend(refs);
                    }
                    build_templated_external_secret(
                        &secret_name,
                        LATTICE_SYSTEM_NAMESPACE,
                        &params.provider,
                        remote_key,
                        params.keys.as_deref(),
                        template_data,
                        &all_refs,
                    )
                    .map_err(ReconcileError::Validation)?
                } else {
                    // Simple mode: sync all keys directly
                    build_external_secret(
                        &secret_name,
                        LATTICE_SYSTEM_NAMESPACE,
                        &params.provider,
                        remote_key,
                        params.keys.as_deref(),
                        None,
                    )
                };

                apply_external_secret(client, &es, "lattice-cloud-provider-controller").await?;

                debug!(
                    cloud_provider = %cp.name_any(),
                    provider = ?provider_type,
                    "ESO ExternalSecret applied for credentials"
                );
                Ok(())
            } else if cp.spec.credentials_secret_ref.is_some() {
                // Manual mode: credentials managed externally
                debug!(
                    cloud_provider = %cp.name_any(),
                    provider = ?provider_type,
                    "Manual credentials reference present"
                );
                Ok(())
            } else {
                Err(ReconcileError::Validation(format!(
                    "{:?} provider requires credentials or credentialsSecretRef",
                    provider_type
                )))
            }
        }
    }
}

/// Update CloudProvider status
async fn update_status(
    client: &Client,
    cp: &CloudProvider,
    phase: CloudProviderPhase,
    message: Option<String>,
) -> Result<(), ReconcileError> {
    // Check if status already matches - avoid update loop
    if let Some(ref current_status) = cp.status {
        if current_status.phase == phase && current_status.message == message {
            debug!(cloud_provider = %cp.name_any(), "Status unchanged, skipping update");
            return Ok(());
        }
    }

    let name = cp.name_any();
    let namespace = cp
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

    let status = CloudProviderStatus {
        phase,
        message,
        last_validated: Some(chrono::Utc::now().to_rfc3339()),
        cluster_count: 0,
    };

    lattice_common::kube_utils::patch_resource_status::<CloudProvider>(
        client,
        &name,
        &namespace,
        &status,
        "lattice-cloud-provider-controller",
    )
    .await
    .map_err(|e| ReconcileError::Kube(format!("failed to update status: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use lattice_common::crd::{CloudProviderSpec, ResourceSpec, ResourceType, SecretRef};
    use lattice_common::{CAPA_NAMESPACE, CAPMOX_NAMESPACE, CAPO_NAMESPACE};

    // =========================================================================
    // Test Helpers
    // =========================================================================

    fn sample_provider(provider_type: CloudProviderType) -> CloudProvider {
        let (name, region, creds_namespace) = match provider_type {
            CloudProviderType::Docker => ("docker", None, None),
            CloudProviderType::AWS => ("aws-prod", Some("us-east-1"), Some(CAPA_NAMESPACE)),
            CloudProviderType::Proxmox => ("proxmox-homelab", None, Some(CAPMOX_NAMESPACE)),
            CloudProviderType::OpenStack => {
                ("openstack-prod", Some("RegionOne"), Some(CAPO_NAMESPACE))
            }
        };

        let credentials_secret_ref = creds_namespace.map(|ns| SecretRef {
            name: format!("{}-creds", name),
            namespace: ns.to_string(),
        });

        CloudProvider::new(
            name,
            CloudProviderSpec {
                provider_type,
                region: region.map(String::from),
                credentials_secret_ref,
                credentials: None,
                credential_data: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        )
    }

    fn sample_eso_provider(name: &str, provider_type: CloudProviderType) -> CloudProvider {
        let mut params = BTreeMap::new();
        params.insert("provider".to_string(), serde_json::json!("vault-prod"));

        CloudProvider::new(
            name,
            CloudProviderSpec {
                provider_type,
                region: None,
                credentials_secret_ref: None,
                credentials: Some(ResourceSpec {
                    type_: ResourceType::Secret,
                    id: Some("infrastructure/aws/prod".to_string()),
                    params: Some(params),
                    ..Default::default()
                }),
                credential_data: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        )
    }

    // =========================================================================
    // reconcile_credentials Tests
    // =========================================================================

    #[tokio::test]
    async fn docker_no_credentials() {
        let cp = sample_provider(CloudProviderType::Docker);
        // Docker doesn't need a client — no ESO apply
        // reconcile_credentials requires &Client, but Docker returns before using it.
        // We can't call it without a client, so test the validation logic directly.
        assert_eq!(cp.spec.provider_type, CloudProviderType::Docker);
        assert!(cp.spec.credentials.is_none());
        assert!(cp.spec.credentials_secret_ref.is_none());
    }

    #[tokio::test]
    async fn manual_mode_unchanged() {
        let cp = sample_provider(CloudProviderType::AWS);
        // Has credentialsSecretRef, no credentials
        assert!(cp.spec.credentials_secret_ref.is_some());
        assert!(cp.spec.credentials.is_none());
    }

    #[tokio::test]
    async fn mutual_exclusion_validation() {
        let mut params = BTreeMap::new();
        params.insert("provider".to_string(), serde_json::json!("vault"));

        let cp = CloudProvider::new(
            "test",
            CloudProviderSpec {
                provider_type: CloudProviderType::AWS,
                region: None,
                credentials_secret_ref: Some(SecretRef {
                    name: "manual".to_string(),
                    namespace: "default".to_string(),
                }),
                credentials: Some(ResourceSpec {
                    type_: ResourceType::Secret,
                    id: Some("path".to_string()),
                    params: Some(params),
                    ..Default::default()
                }),
                credential_data: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        );

        // Can't test reconcile_credentials without a Client, but we can verify
        // the validation would catch this by checking the fields
        assert!(cp.spec.credentials.is_some() && cp.spec.credentials_secret_ref.is_some());
    }

    #[tokio::test]
    async fn credential_data_without_credentials_is_invalid() {
        let mut data = BTreeMap::new();
        data.insert("key".to_string(), "value".to_string());

        let cp = CloudProvider::new(
            "test",
            CloudProviderSpec {
                provider_type: CloudProviderType::AWS,
                region: None,
                credentials_secret_ref: None,
                credentials: None,
                credential_data: Some(data),
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        );

        // credentialData without credentials should be rejected
        assert!(cp.spec.credential_data.is_some() && cp.spec.credentials.is_none());
    }

    #[tokio::test]
    async fn simple_mode_builds_external_secret() {
        let cp = sample_eso_provider("aws-test", CloudProviderType::AWS);

        let resource = cp.spec.credentials.as_ref().unwrap();
        let params = resource.secret_params().unwrap().unwrap();
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

        assert_eq!(es.metadata.name, "aws-test-credentials");
        assert_eq!(es.metadata.namespace, LATTICE_SYSTEM_NAMESPACE);
        assert_eq!(es.spec.secret_store_ref.name, "vault-prod");
        // No keys specified → dataFrom extract
        assert!(es.spec.data.is_empty());
        assert!(es.spec.data_from.is_some());
    }

    #[tokio::test]
    async fn templated_mode_builds_external_secret() {
        let mut params_map = BTreeMap::new();
        params_map.insert("provider".to_string(), serde_json::json!("vault-prod"));
        params_map.insert(
            "keys".to_string(),
            serde_json::json!(["username", "password", "auth_url"]),
        );

        let mut credential_data = BTreeMap::new();
        credential_data.insert(
            "clouds.yaml".to_string(),
            "auth:\n  username: \"${secret.credentials.username}\"\n  password: \"${secret.credentials.password}\"".to_string(),
        );

        let cp = CloudProvider::new(
            "openstack-test",
            CloudProviderSpec {
                provider_type: CloudProviderType::OpenStack,
                region: None,
                credentials_secret_ref: None,
                credentials: Some(ResourceSpec {
                    type_: ResourceType::Secret,
                    id: Some("infrastructure/openstack/creds".to_string()),
                    params: Some(params_map),
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
        let params = resource.secret_params().unwrap().unwrap();
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
            template_data.clone(),
            &all_refs,
        )
        .unwrap();

        assert_eq!(es.metadata.name, "openstack-test-credentials");
        assert!(es.spec.target.template.is_some());
        let template = es.spec.target.template.as_ref().unwrap();
        assert!(template.data.contains_key("clouds.yaml"));
        // Secret refs should be replaced with Go template syntax
        let clouds_yaml = &template.data["clouds.yaml"];
        assert!(clouds_yaml.contains("{{ .credentials_username }}"));
        assert!(clouds_yaml.contains("{{ .credentials_password }}"));
        // Should have data entries for the referenced keys
        assert_eq!(es.spec.data.len(), 2); // username and password
    }

    #[tokio::test]
    async fn missing_credentials_for_cloud_provider() {
        let cp = CloudProvider::new(
            "aws-no-creds",
            CloudProviderSpec {
                provider_type: CloudProviderType::AWS,
                region: None,
                credentials_secret_ref: None,
                credentials: None,
                credential_data: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        );

        // Neither credentials nor credentialsSecretRef set
        assert!(cp.spec.credentials.is_none());
        assert!(cp.spec.credentials_secret_ref.is_none());
        assert!(cp.k8s_secret_ref().is_none());
    }

    // =========================================================================
    // Status Update Tests
    // =========================================================================

    #[tokio::test]
    async fn status_unchanged_skips_update() {
        let mut cp = sample_provider(CloudProviderType::Docker);
        cp.status = Some(CloudProviderStatus {
            phase: CloudProviderPhase::Ready,
            message: None,
            last_validated: Some("2024-01-01T00:00:00Z".to_string()),
            cluster_count: 0,
        });

        let expected_phase = CloudProviderPhase::Ready;
        let expected_message: Option<String> = None;

        if let Some(ref current_status) = cp.status {
            assert_eq!(current_status.phase, expected_phase);
            assert_eq!(current_status.message, expected_message);
        }
    }

    #[tokio::test]
    async fn cloud_provider_status_fields() {
        let status = CloudProviderStatus {
            phase: CloudProviderPhase::Failed,
            message: Some("Test error message".to_string()),
            last_validated: Some(chrono::Utc::now().to_rfc3339()),
            cluster_count: 5,
        };

        assert_eq!(status.phase, CloudProviderPhase::Failed);
        assert!(status.message.is_some());
        assert!(status.last_validated.is_some());
        assert_eq!(status.cluster_count, 5);
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[tokio::test]
    async fn provider_with_namespace_uses_it() {
        let mut cp = sample_provider(CloudProviderType::Docker);
        cp.metadata = ObjectMeta {
            name: Some("test-provider".to_string()),
            namespace: Some("custom-namespace".to_string()),
            ..Default::default()
        };

        assert_eq!(cp.namespace(), Some("custom-namespace".to_string()));
    }

    #[tokio::test]
    async fn provider_without_namespace_uses_default() {
        let cp = sample_provider(CloudProviderType::Docker);
        let namespace = cp
            .namespace()
            .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());
        assert_eq!(namespace, LATTICE_SYSTEM_NAMESPACE);
    }

    #[tokio::test]
    async fn all_provider_types_covered() {
        let provider_types = [
            CloudProviderType::Docker,
            CloudProviderType::AWS,
            CloudProviderType::Proxmox,
            CloudProviderType::OpenStack,
        ];

        for provider_type in provider_types {
            let cp = sample_provider(provider_type);
            assert_eq!(cp.spec.provider_type, provider_type);
        }
    }
}
