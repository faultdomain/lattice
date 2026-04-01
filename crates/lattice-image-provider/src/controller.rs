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
use lattice_common::{
    ControllerContext, ReconcileError, LATTICE_SYSTEM_NAMESPACE, REQUEUE_ERROR_SECS,
    REQUEUE_SUCCESS_SECS,
};

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
    let generation = ip.metadata.generation.unwrap_or(0);

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
        update_status(client, &ip, ImageProviderPhase::Failed, Some(msg), Some(generation)).await?;
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
    }

    // Sync credentials via ESO if configured
    if let Some(ref credentials) = ip.spec.credentials {
        if let Err(e) = lattice_secret_provider::credentials::ensure_credentials(
            client,
            &name,
            credentials,
            ip.spec.credential_data.as_ref(),
            LATTICE_SYSTEM_NAMESPACE,
            FIELD_MANAGER,
        )
        .await
        {
            let msg = format!("Failed to sync credentials: {e}");
            warn!(image_provider = %name, error = %msg);
            update_status(client, &ip, ImageProviderPhase::Failed, Some(msg), Some(generation))
                .await?;
            return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
        }
    }

    info!(image_provider = %name, "Credentials synced");
    update_status(
        client,
        &ip,
        ImageProviderPhase::Ready,
        Some("Credentials synced".to_string()),
        Some(generation),
    )
    .await?;

    Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
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
    let namespace = ip
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

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
        ImageProvider::new(
            "test",
            ImageProviderSpec::new(provider_type, registry),
        )
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
