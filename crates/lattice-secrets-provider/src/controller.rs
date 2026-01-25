//! SecretsProvider reconciliation controller
//!
//! Watches SecretsProvider CRDs and ensures ESO ClusterSecretStore exists.

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, DynamicObject, Patch, PatchParams};
use kube::discovery::ApiResource;
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{
    SecretsProvider, SecretsProviderPhase, SecretsProviderStatus, VaultAuthMethod,
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

/// Reconcile a SecretsProvider
///
/// Ensures the corresponding ESO ClusterSecretStore exists.
/// If ESO is not installed, requeues to retry later.
pub async fn reconcile(
    sp: Arc<SecretsProvider>,
    ctx: Arc<Context>,
) -> Result<Action, ReconcileError> {
    let name = sp.name_any();
    let client = &ctx.client;

    info!(secrets_provider = %name, "Reconciling SecretsProvider");

    // Try to create/update the ClusterSecretStore
    match ensure_cluster_secret_store(client, &sp).await {
        Ok(()) => {
            info!(secrets_provider = %name, "ClusterSecretStore is up to date");

            // Update status to Ready
            update_status(client, &sp, SecretsProviderPhase::Ready, None).await?;

            // Requeue periodically to handle drift
            Ok(Action::requeue(Duration::from_secs(300)))
        }
        Err(e) if is_crd_not_found(&e) => {
            // ESO not installed yet - requeue to try again
            warn!(
                secrets_provider = %name,
                "ESO ClusterSecretStore CRD not found - ESO may not be installed, will retry"
            );

            update_status(
                client,
                &sp,
                SecretsProviderPhase::Pending,
                Some("Waiting for ESO to be installed".to_string()),
            )
            .await?;

            // Retry more frequently when waiting for ESO
            Ok(Action::requeue(Duration::from_secs(30)))
        }
        Err(e) => {
            warn!(
                secrets_provider = %name,
                error = %e,
                "Failed to ensure ClusterSecretStore"
            );

            update_status(
                client,
                &sp,
                SecretsProviderPhase::Failed,
                Some(e.to_string()),
            )
            .await?;

            // Retry with backoff on other errors
            Ok(Action::requeue(Duration::from_secs(60)))
        }
    }
}

/// Error policy - always requeue on error
pub fn error_policy(
    _sp: Arc<SecretsProvider>,
    error: &ReconcileError,
    _ctx: Arc<Context>,
) -> Action {
    warn!(error = %error, "Reconcile error, will retry");
    Action::requeue(Duration::from_secs(30))
}

/// Check if error is due to CRD not found (ESO not installed)
fn is_crd_not_found(error: &ReconcileError) -> bool {
    error.to_string().contains("404")
        || error.to_string().contains("not found")
        || error
            .to_string()
            .contains("the server could not find the requested resource")
}

/// Ensure ClusterSecretStore exists for the SecretsProvider
async fn ensure_cluster_secret_store(
    client: &Client,
    sp: &SecretsProvider,
) -> Result<(), ReconcileError> {
    let name = sp.name_any();

    // Build the ClusterSecretStore spec based on auth method
    let provider_spec = build_vault_provider_spec(sp)?;

    let cluster_secret_store = serde_json::json!({
        "apiVersion": "external-secrets.io/v1beta1",
        "kind": "ClusterSecretStore",
        "metadata": {
            "name": name,
            "labels": {
                "app.kubernetes.io/managed-by": "lattice",
                "lattice.dev/secrets-provider": name
            }
        },
        "spec": {
            "provider": provider_spec
        }
    });

    // Use dynamic API to apply ClusterSecretStore
    let api_resource = ApiResource::from_gvk(&kube::api::GroupVersionKind {
        group: "external-secrets.io".to_string(),
        version: "v1beta1".to_string(),
        kind: "ClusterSecretStore".to_string(),
    });

    let css_api: Api<DynamicObject> = Api::all_with(client.clone(), &api_resource);
    let css: DynamicObject = serde_json::from_value(cluster_secret_store).map_err(|e| {
        ReconcileError::Internal(format!("failed to build ClusterSecretStore: {}", e))
    })?;

    let params = PatchParams::apply("lattice-secrets-provider").force();
    css_api
        .patch(&name, &params, &Patch::Apply(&css))
        .await
        .map_err(|e| ReconcileError::Kube(e.to_string()))?;

    debug!(secrets_provider = %name, "Applied ClusterSecretStore");
    Ok(())
}

/// Build Vault provider spec for ClusterSecretStore
fn build_vault_provider_spec(sp: &SecretsProvider) -> Result<serde_json::Value, ReconcileError> {
    match sp.spec.auth_method {
        VaultAuthMethod::Token => {
            let secret_ref = sp.spec.credentials_secret_ref.as_ref().ok_or_else(|| {
                ReconcileError::Validation("Token auth requires credentialsSecretRef".to_string())
            })?;
            Ok(serde_json::json!({
                "vault": {
                    "server": sp.spec.server,
                    "path": sp.spec.path.as_deref().unwrap_or("secret"),
                    "version": "v2",
                    "namespace": sp.spec.namespace,
                    "caBundle": sp.spec.ca_bundle,
                    "auth": {
                        "tokenSecretRef": {
                            "name": secret_ref.name,
                            "namespace": &secret_ref.namespace,
                            "key": "token"
                        }
                    }
                }
            }))
        }
        VaultAuthMethod::Kubernetes => {
            let mount_path = sp
                .spec
                .kubernetes_mount_path
                .as_deref()
                .unwrap_or("kubernetes");
            let role = sp
                .spec
                .kubernetes_role
                .as_deref()
                .unwrap_or("external-secrets");
            Ok(serde_json::json!({
                "vault": {
                    "server": sp.spec.server,
                    "path": sp.spec.path.as_deref().unwrap_or("secret"),
                    "version": "v2",
                    "namespace": sp.spec.namespace,
                    "caBundle": sp.spec.ca_bundle,
                    "auth": {
                        "kubernetes": {
                            "mountPath": mount_path,
                            "role": role,
                            "serviceAccountRef": {
                                "name": "external-secrets",
                                "namespace": "external-secrets"
                            }
                        }
                    }
                }
            }))
        }
        VaultAuthMethod::AppRole => {
            let secret_ref = sp.spec.credentials_secret_ref.as_ref().ok_or_else(|| {
                ReconcileError::Validation("AppRole auth requires credentialsSecretRef".to_string())
            })?;
            Ok(serde_json::json!({
                "vault": {
                    "server": sp.spec.server,
                    "path": sp.spec.path.as_deref().unwrap_or("secret"),
                    "version": "v2",
                    "namespace": sp.spec.namespace,
                    "caBundle": sp.spec.ca_bundle,
                    "auth": {
                        "appRole": {
                            "path": "approle",
                            "roleRef": {
                                "name": secret_ref.name,
                                "namespace": &secret_ref.namespace,
                                "key": "role_id"
                            },
                            "secretRef": {
                                "name": secret_ref.name,
                                "namespace": &secret_ref.namespace,
                                "key": "secret_id"
                            }
                        }
                    }
                }
            }))
        }
    }
}

/// Update SecretsProvider status
async fn update_status(
    client: &Client,
    sp: &SecretsProvider,
    phase: SecretsProviderPhase,
    message: Option<String>,
) -> Result<(), ReconcileError> {
    // Check if status already matches - avoid update loop
    if let Some(ref current_status) = sp.status {
        if current_status.phase == phase && current_status.message == message {
            debug!(secrets_provider = %sp.name_any(), "Status unchanged, skipping update");
            return Ok(());
        }
    }

    let name = sp.name_any();
    let namespace = sp
        .namespace()
        .unwrap_or_else(|| "lattice-system".to_string());

    let status = SecretsProviderStatus {
        phase,
        message,
        last_validated: Some(chrono::Utc::now().to_rfc3339()),
    };

    let patch = serde_json::json!({
        "status": status
    });

    let api: Api<SecretsProvider> = Api::namespaced(client.clone(), &namespace);
    api.patch_status(
        &name,
        &PatchParams::apply("lattice-secrets-provider"),
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
    use lattice_common::crd::{SecretRef, SecretsProviderSpec};

    fn sample_token_provider() -> SecretsProvider {
        SecretsProvider::new(
            "vault-prod",
            SecretsProviderSpec {
                server: "https://vault.example.com".to_string(),
                path: Some("secret/data/myapp".to_string()),
                auth_method: VaultAuthMethod::Token,
                credentials_secret_ref: Some(SecretRef {
                    name: "vault-token".to_string(),
                    namespace: "lattice-system".to_string(),
                }),
                kubernetes_mount_path: None,
                kubernetes_role: None,
                namespace: None,
                ca_bundle: None,
            },
        )
    }

    fn sample_k8s_auth_provider() -> SecretsProvider {
        SecretsProvider::new(
            "vault-k8s",
            SecretsProviderSpec {
                server: "https://vault.example.com".to_string(),
                path: Some("secret".to_string()),
                auth_method: VaultAuthMethod::Kubernetes,
                credentials_secret_ref: None,
                kubernetes_mount_path: Some("kubernetes".to_string()),
                kubernetes_role: Some("my-role".to_string()),
                namespace: None,
                ca_bundle: None,
            },
        )
    }

    #[test]
    fn token_auth_builds_correct_spec() {
        let sp = sample_token_provider();
        let spec = build_vault_provider_spec(&sp).expect("should build spec");

        let vault = spec.get("vault").expect("should have vault");
        assert_eq!(vault.get("server").unwrap(), "https://vault.example.com");

        let auth = vault.get("auth").expect("should have auth");
        assert!(auth.get("tokenSecretRef").is_some());
    }

    #[test]
    fn kubernetes_auth_builds_correct_spec() {
        let sp = sample_k8s_auth_provider();
        let spec = build_vault_provider_spec(&sp).expect("should build spec");

        let vault = spec.get("vault").expect("should have vault");
        let auth = vault.get("auth").expect("should have auth");
        let k8s = auth.get("kubernetes").expect("should have kubernetes auth");

        assert_eq!(k8s.get("role").unwrap(), "my-role");
        assert_eq!(k8s.get("mountPath").unwrap(), "kubernetes");
    }

    #[test]
    fn token_auth_requires_credentials_ref() {
        let mut sp = sample_token_provider();
        sp.spec.credentials_secret_ref = None;

        let result = build_vault_provider_spec(&sp);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("credentialsSecretRef"));
    }
}
