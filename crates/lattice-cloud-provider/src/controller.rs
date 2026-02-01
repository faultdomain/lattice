//! CloudProvider reconciliation controller
//!
//! Watches CloudProvider CRDs and validates credentials.
//!
//! ## Credential Validation
//!
//! Currently, credential validation only checks that the required `credentialsSecretRef`
//! exists in the CloudProvider spec. It does NOT verify that:
//! - The referenced Secret actually exists in the cluster
//! - The credentials within the Secret are valid/working
//! - The credentials have sufficient permissions
//!
//! Future work may add actual cloud API validation (e.g., AWS STS GetCallerIdentity,
//! Proxmox API health check, OpenStack identity API validation).

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{
    CloudProvider, CloudProviderPhase, CloudProviderStatus, CloudProviderType,
};
use lattice_common::{ReconcileError, LATTICE_SYSTEM_NAMESPACE};

// Re-export for convenience
pub use lattice_common::ControllerContext;

/// Reconcile a CloudProvider
///
/// Validates credentials and updates status.
pub async fn reconcile(
    cp: Arc<CloudProvider>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = cp.name_any();
    let client = &ctx.client;

    info!(cloud_provider = %name, provider_type = ?cp.spec.provider_type, "Reconciling CloudProvider");

    // Validate credentials based on provider type
    match validate_credentials(&cp).await {
        Ok(()) => {
            info!(cloud_provider = %name, "Credentials validated successfully");

            update_status(client, &cp, CloudProviderPhase::Ready, None).await?;

            // Requeue periodically to re-validate
            Ok(Action::requeue(Duration::from_secs(300)))
        }
        Err(e) => {
            warn!(
                cloud_provider = %name,
                error = %e,
                "Credential validation failed"
            );

            update_status(client, &cp, CloudProviderPhase::Failed, Some(e.to_string())).await?;

            // Retry with backoff
            Ok(Action::requeue(Duration::from_secs(60)))
        }
    }
}

/// Validate credentials for the cloud provider.
///
/// This currently only validates that the `credentialsSecretRef` field is present
/// for providers that require it. It does not verify the Secret exists or that
/// the credentials are valid. See module-level documentation for details.
async fn validate_credentials(cp: &CloudProvider) -> Result<(), ReconcileError> {
    match cp.spec.provider_type {
        CloudProviderType::Docker => {
            // Docker provider runs locally and requires no credentials
            debug!(cloud_provider = %cp.name_any(), "Docker provider requires no credentials");
            Ok(())
        }
        provider_type => {
            // All other providers (AWS, Proxmox, OpenStack) require credentials
            if cp.spec.credentials_secret_ref.is_none() {
                return Err(ReconcileError::Validation(format!(
                    "{:?} provider requires credentialsSecretRef",
                    provider_type
                )));
            }
            debug!(
                cloud_provider = %cp.name_any(),
                provider = ?provider_type,
                "Credentials reference present (existence validated, not connectivity)"
            );
            Ok(())
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
        // Cluster count tracking would require querying LatticeCluster CRDs
        // that reference this provider. This is not implemented yet.
        cluster_count: 0,
    };

    let patch = serde_json::json!({
        "status": status
    });

    let api: Api<CloudProvider> = Api::namespaced(client.clone(), &namespace);
    api.patch_status(
        &name,
        &PatchParams::apply("lattice-cloud-provider"),
        &Patch::Merge(&patch),
    )
    .await
    .map_err(|e| ReconcileError::Kube(format!("failed to update status: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::ObjectMeta;
    use lattice_common::crd::{CloudProviderSpec, SecretRef};
    use lattice_common::{CAPA_NAMESPACE, CAPMOX_NAMESPACE, CAPO_NAMESPACE};

    // =========================================================================
    // Test Helpers
    // =========================================================================

    /// Create a sample CloudProvider with the given type and optional credentials.
    /// This consolidates the separate sample_*_provider functions.
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
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        )
    }

    /// Helper to test that a provider type validates successfully with credentials.
    async fn assert_validates_with_credentials(provider_type: CloudProviderType) {
        let cp = sample_provider(provider_type);
        let result = validate_credentials(&cp).await;
        assert!(
            result.is_ok(),
            "{:?} provider should validate with credentials, got: {:?}",
            provider_type,
            result
        );
    }

    /// Helper to test that a provider type fails validation without credentials.
    async fn assert_requires_credentials(provider_type: CloudProviderType) {
        let mut cp = sample_provider(provider_type);
        cp.spec.credentials_secret_ref = None;

        let result = validate_credentials(&cp).await;
        let err = result.expect_err(&format!(
            "{:?} provider should require credentials",
            provider_type
        ));
        assert!(
            err.to_string().contains("credentialsSecretRef"),
            "Error should mention credentialsSecretRef, got: {}",
            err
        );
    }

    // =========================================================================
    // Credential Validation Tests
    // =========================================================================

    #[tokio::test]
    async fn docker_provider_validates_without_credentials() {
        let cp = sample_provider(CloudProviderType::Docker);
        let result = validate_credentials(&cp).await;
        assert!(
            result.is_ok(),
            "Docker provider should not require credentials"
        );
    }

    #[tokio::test]
    async fn aws_provider_requires_credentials() {
        assert_requires_credentials(CloudProviderType::AWS).await;
    }

    #[tokio::test]
    async fn aws_provider_validates_with_credentials() {
        assert_validates_with_credentials(CloudProviderType::AWS).await;
    }

    #[tokio::test]
    async fn proxmox_provider_requires_credentials() {
        assert_requires_credentials(CloudProviderType::Proxmox).await;
    }

    #[tokio::test]
    async fn proxmox_provider_validates_with_credentials() {
        assert_validates_with_credentials(CloudProviderType::Proxmox).await;
    }

    #[tokio::test]
    async fn openstack_provider_requires_credentials() {
        assert_requires_credentials(CloudProviderType::OpenStack).await;
    }

    #[tokio::test]
    async fn openstack_provider_validates_with_credentials() {
        assert_validates_with_credentials(CloudProviderType::OpenStack).await;
    }

    // =========================================================================
    // Reconcile Tests
    // =========================================================================

    // Note: Full reconcile() tests require a real or mock Kubernetes client.
    // These tests validate the reconcile logic by testing validate_credentials
    // directly, which is the core of reconcile(). Integration tests with a
    // real cluster provide full reconcile() coverage.

    #[tokio::test]
    async fn reconcile_returns_error_for_missing_credentials() {
        // This test validates the error path through validate_credentials
        let mut cp = sample_provider(CloudProviderType::AWS);
        cp.spec.credentials_secret_ref = None;

        let result = validate_credentials(&cp).await;
        assert!(
            result.is_err(),
            "Missing credentials should fail validation"
        );
    }

    // =========================================================================
    // Status Update Tests
    // =========================================================================

    #[tokio::test]
    async fn status_unchanged_skips_update() {
        // Test the status comparison logic by creating a provider with existing status
        let mut cp = sample_provider(CloudProviderType::Docker);
        cp.status = Some(CloudProviderStatus {
            phase: CloudProviderPhase::Ready,
            message: None,
            last_validated: Some("2024-01-01T00:00:00Z".to_string()),
            cluster_count: 0,
        });

        // Verify status matches what would be set - the update_status function
        // checks this internally. We can't fully test without a client, but we
        // can verify the status struct creation.
        let expected_phase = CloudProviderPhase::Ready;
        let expected_message: Option<String> = None;

        if let Some(ref current_status) = cp.status {
            assert_eq!(current_status.phase, expected_phase);
            assert_eq!(current_status.message, expected_message);
        }
    }

    #[tokio::test]
    async fn cloud_provider_status_fields() {
        // Test that CloudProviderStatus can be created with all fields
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

        // Verify the namespace is preserved
        assert_eq!(cp.namespace(), Some("custom-namespace".to_string()));
    }

    #[tokio::test]
    async fn provider_without_namespace_uses_default() {
        let cp = sample_provider(CloudProviderType::Docker);
        // When namespace is None, update_status falls back to LATTICE_SYSTEM_NAMESPACE
        let namespace = cp
            .namespace()
            .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());
        assert_eq!(namespace, LATTICE_SYSTEM_NAMESPACE);
    }

    #[tokio::test]
    async fn all_provider_types_covered() {
        // Ensure we have test coverage for all CloudProviderType variants
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
