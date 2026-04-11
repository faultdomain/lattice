//! ImageProvider reconciliation controller
//!
//! Watches ImageProvider CRDs and creates ESO ExternalSecrets that produce
//! `kubernetes.io/dockerconfigjson` Secrets for image pull authentication.
//!
//! Uses the same `ensure_credentials` path as InfraProvider and DNSProvider.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{ImageProvider, ImageProviderPhase, ImageProviderStatus};
use lattice_common::status_check;
use lattice_common::{ControllerContext, ReconcileError, REQUEUE_ERROR_SECS, REQUEUE_SUCCESS_SECS};
use lattice_core::LATTICE_SYSTEM_NAMESPACE;

const FIELD_MANAGER: &str = "lattice-image-provider-controller";

/// Reconcile an ImageProvider
///
/// Validates the spec and syncs credentials via ESO. The resulting Secret
/// is a `kubernetes.io/dockerconfigjson` type that kubelet uses for image pulls.
pub async fn reconcile(
    ip: Arc<ImageProvider>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = ip.name_any();
    let client = &ctx.client;
    let generation = ip.metadata.generation.ok_or_else(|| {
        ReconcileError::Validation("ImageProvider missing metadata.generation".into())
    })?;

    if status_check::is_status_unchanged(
        ip.status.as_ref(),
        &ImageProviderPhase::Ready,
        None,
        Some(generation),
    ) {
        return Ok(Action::requeue(Duration::from_secs(300)));
    }

    info!(image_provider = %name, provider_type = ?ip.spec.provider_type, "Reconciling ImageProvider");

    if let Err(e) = ip.spec.validate() {
        let msg = e.to_string();
        warn!(image_provider = %name, error = %msg, "Validation failed");
        update_status(
            client,
            &ip,
            ImageProviderPhase::Failed,
            Some(msg),
            Some(generation),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
    }

    if let Some(ref credentials) = ip.spec.credentials {
        // Force dockerconfigjson type so kubelet recognizes the Secret
        let mut creds = credentials.clone();
        if creds.secret_type.is_none() {
            creds.secret_type = Some(lattice_core::SECRET_TYPE_DOCKERCONFIG.to_string());
        }

        // Interpolate ${registry} in credentialData if provided
        let interpolated;
        let credential_data = match ip.spec.credential_data.as_ref() {
            Some(data) => {
                interpolated = interpolate_registry(data, &ip.spec.registry)
                    .map_err(ReconcileError::Validation)?;
                Some(&interpolated)
            }
            None => None,
        };

        if let Err(e) = lattice_secret_provider::credentials::reconcile_credentials(
            client,
            &lattice_secret_provider::credentials::ProviderCredentialConfig {
                provider_name: &name,
                credentials: &creds,
                credential_data,
                target_namespace: LATTICE_SYSTEM_NAMESPACE,
                field_manager: FIELD_MANAGER,
            },
        )
        .await
        {
            let msg = format!("Failed to create ExternalSecret: {e}");
            warn!(image_provider = %name, error = %msg);
            update_status(
                client,
                &ip,
                ImageProviderPhase::Failed,
                Some(msg),
                Some(generation),
            )
            .await?;
            return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
        }
    }

    let status_msg = if ip.spec.credentials.is_some() {
        "Credentials synced"
    } else {
        "Ready (no credentials configured)"
    };
    info!(image_provider = %name, "{status_msg}");
    update_status(
        client,
        &ip,
        ImageProviderPhase::Ready,
        Some(status_msg.to_string()),
        Some(generation),
    )
    .await?;

    Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
}

/// Interpolate `${registry}` in credentialData values with the actual registry hostname.
///
/// Returns an error if the registry value contains Go template syntax (`{{`/`}}`),
/// which could be used to inject into ESO's Go template engine and exfiltrate
/// other secret values.
fn interpolate_registry(
    data: &std::collections::BTreeMap<String, String>,
    registry: &str,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    if registry.contains("{{") || registry.contains("}}") {
        return Err(format!(
            "registry '{}' contains Go template syntax, which is not allowed",
            registry
        ));
    }
    Ok(data
        .iter()
        .map(|(k, v)| (k.clone(), v.replace("${registry}", registry)))
        .collect())
}

async fn update_status(
    client: &Client,
    ip: &ImageProvider,
    phase: ImageProviderPhase,
    message: Option<String>,
    observed_generation: Option<i64>,
) -> Result<(), ReconcileError> {
    if status_check::is_status_unchanged(
        ip.status.as_ref(),
        &phase,
        message.as_deref(),
        observed_generation,
    ) {
        debug!(image_provider = %ip.name_any(), "Status unchanged, skipping update");
        return Ok(());
    }

    let name = ip.name_any();
    let namespace = ip.namespace().ok_or_else(|| {
        ReconcileError::Validation("ImageProvider missing metadata.namespace".into())
    })?;

    let status = ImageProviderStatus {
        phase,
        message,
        observed_generation,
    };

    lattice_common::kube_utils::patch_resource_status::<ImageProvider>(
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
    use lattice_common::crd::{ImageProviderSpec, ImageProviderType};

    fn sample_provider(provider_type: ImageProviderType, registry: &str) -> ImageProvider {
        ImageProvider::new("test", ImageProviderSpec::new(provider_type, registry))
    }

    #[test]
    fn generic_provider_validates() {
        let ip = sample_provider(ImageProviderType::Generic, "registry.example.com");
        assert!(ip.spec.validate().is_ok());
    }

    #[test]
    fn empty_registry_fails() {
        let ip = sample_provider(ImageProviderType::Ghcr, "");
        assert!(ip.spec.validate().is_err());
    }

    #[test]
    fn status_unchanged_skips() {
        let mut ip = sample_provider(ImageProviderType::Ghcr, "ghcr.io");
        ip.status = Some(ImageProviderStatus {
            phase: ImageProviderPhase::Ready,
            message: None,
            observed_generation: Some(1),
        });

        assert!(status_check::is_status_unchanged(
            ip.status.as_ref(),
            &ImageProviderPhase::Ready,
            None,
            Some(1)
        ));
    }
}
