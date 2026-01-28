//! CloudProvider reconciliation controller
//!
//! Watches CloudProvider CRDs and validates credentials.

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{
    CloudProvider, CloudProviderPhase, CloudProviderStatus, CloudProviderType,
};

/// Controller context
pub struct Context {
    /// Kubernetes client
    pub client: Client,
}

impl Context {
    /// Create a new context
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

/// Reconcile a CloudProvider
///
/// Validates credentials and updates status.
pub async fn reconcile(
    cp: Arc<CloudProvider>,
    ctx: Arc<Context>,
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

/// Error policy - always requeue on error
pub fn error_policy(_cp: Arc<CloudProvider>, error: &ReconcileError, _ctx: Arc<Context>) -> Action {
    warn!(error = %error, "Reconcile error, will retry");
    Action::requeue(Duration::from_secs(30))
}

/// Validate credentials for the cloud provider
async fn validate_credentials(cp: &CloudProvider) -> Result<(), ReconcileError> {
    match cp.spec.provider_type {
        CloudProviderType::Docker => {
            // Docker doesn't need credentials validation
            debug!(cloud_provider = %cp.name_any(), "Docker provider - no credentials to validate");
            Ok(())
        }
        CloudProviderType::AWS => {
            // For now, just check that credentials secret ref exists
            if cp.spec.credentials_secret_ref.is_none() {
                return Err(ReconcileError::Validation(
                    "AWS provider requires credentialsSecretRef".to_string(),
                ));
            }
            // TODO: Actually validate AWS credentials by calling STS GetCallerIdentity
            debug!(cloud_provider = %cp.name_any(), "AWS credentials reference present");
            Ok(())
        }
        CloudProviderType::Proxmox => {
            if cp.spec.credentials_secret_ref.is_none() {
                return Err(ReconcileError::Validation(
                    "Proxmox provider requires credentialsSecretRef".to_string(),
                ));
            }
            // TODO: Validate Proxmox credentials by calling API
            debug!(cloud_provider = %cp.name_any(), "Proxmox credentials reference present");
            Ok(())
        }
        CloudProviderType::OpenStack => {
            if cp.spec.credentials_secret_ref.is_none() {
                return Err(ReconcileError::Validation(
                    "OpenStack provider requires credentialsSecretRef".to_string(),
                ));
            }
            // TODO: Validate OpenStack credentials by calling identity API
            debug!(cloud_provider = %cp.name_any(), "OpenStack credentials reference present");
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
        .unwrap_or_else(|| "lattice-system".to_string());

    let status = CloudProviderStatus {
        phase,
        message,
        last_validated: Some(chrono::Utc::now().to_rfc3339()),
        cluster_count: 0, // TODO: Count clusters using this provider
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

/// Reconcile errors
#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    /// Kubernetes API error
    #[error("kubernetes error: {0}")]
    Kube(String),

    /// Validation error
    #[error("validation error: {0}")]
    Validation(String),

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{CloudProviderSpec, SecretRef};

    fn sample_aws_provider() -> CloudProvider {
        CloudProvider::new(
            "aws-prod",
            CloudProviderSpec {
                provider_type: CloudProviderType::AWS,
                region: Some("us-east-1".to_string()),
                credentials_secret_ref: Some(SecretRef {
                    name: "aws-creds".to_string(),
                    namespace: "capa-system".to_string(),
                }),
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        )
    }

    fn sample_docker_provider() -> CloudProvider {
        CloudProvider::new(
            "docker",
            CloudProviderSpec {
                provider_type: CloudProviderType::Docker,
                region: None,
                credentials_secret_ref: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        )
    }

    #[tokio::test]
    async fn docker_provider_validates_without_credentials() {
        let cp = sample_docker_provider();
        let result = validate_credentials(&cp).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn aws_provider_requires_credentials() {
        let mut cp = sample_aws_provider();
        cp.spec.credentials_secret_ref = None;

        let result = validate_credentials(&cp).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("credentialsSecretRef"));
    }

    #[tokio::test]
    async fn aws_provider_validates_with_credentials() {
        let cp = sample_aws_provider();
        let result = validate_credentials(&cp).await;
        assert!(result.is_ok());
    }

    // =========================================================================
    // Proxmox Provider Tests
    // =========================================================================

    fn sample_proxmox_provider() -> CloudProvider {
        CloudProvider::new(
            "proxmox-homelab",
            CloudProviderSpec {
                provider_type: CloudProviderType::Proxmox,
                region: None,
                credentials_secret_ref: Some(SecretRef {
                    name: "proxmox-creds".to_string(),
                    namespace: "capmox-system".to_string(),
                }),
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        )
    }

    #[tokio::test]
    async fn proxmox_provider_requires_credentials() {
        let mut cp = sample_proxmox_provider();
        cp.spec.credentials_secret_ref = None;

        let result = validate_credentials(&cp).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("credentialsSecretRef"));
    }

    #[tokio::test]
    async fn proxmox_provider_validates_with_credentials() {
        let cp = sample_proxmox_provider();
        let result = validate_credentials(&cp).await;
        assert!(result.is_ok());
    }

    // =========================================================================
    // OpenStack Provider Tests
    // =========================================================================

    fn sample_openstack_provider() -> CloudProvider {
        CloudProvider::new(
            "openstack-prod",
            CloudProviderSpec {
                provider_type: CloudProviderType::OpenStack,
                region: Some("RegionOne".to_string()),
                credentials_secret_ref: Some(SecretRef {
                    name: "openstack-creds".to_string(),
                    namespace: "capo-system".to_string(),
                }),
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        )
    }

    #[tokio::test]
    async fn openstack_provider_requires_credentials() {
        let mut cp = sample_openstack_provider();
        cp.spec.credentials_secret_ref = None;

        let result = validate_credentials(&cp).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("credentialsSecretRef"));
    }

    #[tokio::test]
    async fn openstack_provider_validates_with_credentials() {
        let cp = sample_openstack_provider();
        let result = validate_credentials(&cp).await;
        assert!(result.is_ok());
    }

}
