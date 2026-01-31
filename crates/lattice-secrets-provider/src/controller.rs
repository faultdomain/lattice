//! SecretsProvider reconciliation controller
//!
//! Watches SecretsProvider CRDs and ensures ESO ClusterSecretStore exists.

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, DynamicObject, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{
    SecretsProvider, SecretsProviderPhase, SecretsProviderStatus, VaultAuthMethod,
};
use lattice_common::kube_utils::HasApiResource;
use lattice_common::{ReconcileError, LATTICE_SYSTEM_NAMESPACE};

use crate::eso::{
    AppRoleAuth, ClusterSecretStore, ClusterSecretStoreSpec, KubernetesAuth, ProviderSpec,
    SecretKeyRef, ServiceAccountRef, VaultAuth, VaultProvider,
};

// Re-export for convenience
pub use lattice_common::{default_error_policy, ControllerContext};

/// Reconcile a SecretsProvider
///
/// Ensures the corresponding ESO ClusterSecretStore exists.
/// If ESO is not installed, requeues to retry later.
pub async fn reconcile(
    sp: Arc<SecretsProvider>,
    ctx: Arc<ControllerContext>,
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

    // Build the ClusterSecretStore using typed structs
    let vault_provider = build_vault_provider(sp)?;
    let css = ClusterSecretStore::new(
        &name,
        ClusterSecretStoreSpec {
            provider: ProviderSpec {
                vault: vault_provider,
            },
        },
    );

    // Serialize to JSON for dynamic API
    let css_json = serde_json::to_value(&css).map_err(|e| {
        ReconcileError::Internal(format!("failed to serialize ClusterSecretStore: {}", e))
    })?;

    // Use dynamic API to apply ClusterSecretStore
    let api_resource = ClusterSecretStore::api_resource();
    let css_api: Api<DynamicObject> = Api::all_with(client.clone(), &api_resource);
    let css_obj: DynamicObject = serde_json::from_value(css_json).map_err(|e| {
        ReconcileError::Internal(format!("failed to build ClusterSecretStore: {}", e))
    })?;

    let params = PatchParams::apply("lattice-secrets-provider").force();
    css_api
        .patch(&name, &params, &Patch::Apply(&css_obj))
        .await
        .map_err(|e| ReconcileError::Kube(e.to_string()))?;

    debug!(secrets_provider = %name, "Applied ClusterSecretStore");
    Ok(())
}

/// Build VaultProvider from SecretsProvider spec
fn build_vault_provider(sp: &SecretsProvider) -> Result<VaultProvider, ReconcileError> {
    let auth = build_vault_auth(sp)?;

    Ok(VaultProvider {
        server: sp.spec.server.clone(),
        path: sp.spec.path.clone().unwrap_or_else(|| "secret".to_string()),
        version: "v2".to_string(),
        namespace: sp.spec.namespace.clone(),
        ca_bundle: sp.spec.ca_bundle.clone(),
        auth,
    })
}

/// Build Vault auth configuration based on auth method
fn build_vault_auth(sp: &SecretsProvider) -> Result<VaultAuth, ReconcileError> {
    match sp.spec.auth_method {
        VaultAuthMethod::Token => {
            let secret_ref = sp.spec.credentials_secret_ref.as_ref().ok_or_else(|| {
                ReconcileError::Validation("Token auth requires credentialsSecretRef".to_string())
            })?;
            Ok(VaultAuth {
                token_secret_ref: Some(SecretKeyRef {
                    name: secret_ref.name.clone(),
                    namespace: secret_ref.namespace.clone(),
                    key: "token".to_string(),
                }),
                kubernetes: None,
                app_role: None,
            })
        }
        VaultAuthMethod::Kubernetes => {
            let mount_path = sp
                .spec
                .kubernetes_mount_path
                .clone()
                .unwrap_or_else(|| "kubernetes".to_string());
            let role = sp
                .spec
                .kubernetes_role
                .clone()
                .unwrap_or_else(|| "external-secrets".to_string());
            Ok(VaultAuth {
                token_secret_ref: None,
                kubernetes: Some(KubernetesAuth {
                    mount_path,
                    role,
                    service_account_ref: ServiceAccountRef {
                        name: "external-secrets".to_string(),
                        namespace: "external-secrets".to_string(),
                    },
                }),
                app_role: None,
            })
        }
        VaultAuthMethod::AppRole => {
            let secret_ref = sp.spec.credentials_secret_ref.as_ref().ok_or_else(|| {
                ReconcileError::Validation("AppRole auth requires credentialsSecretRef".to_string())
            })?;
            let mount_path = sp
                .spec
                .approle_mount_path
                .clone()
                .unwrap_or_else(|| "approle".to_string());
            Ok(VaultAuth {
                token_secret_ref: None,
                kubernetes: None,
                app_role: Some(AppRoleAuth {
                    path: mount_path,
                    role_ref: SecretKeyRef {
                        name: secret_ref.name.clone(),
                        namespace: secret_ref.namespace.clone(),
                        key: "role_id".to_string(),
                    },
                    secret_ref: SecretKeyRef {
                        name: secret_ref.name.clone(),
                        namespace: secret_ref.namespace.clone(),
                        key: "secret_id".to_string(),
                    },
                }),
            })
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
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

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
                    namespace: LATTICE_SYSTEM_NAMESPACE.to_string(),
                }),
                kubernetes_mount_path: None,
                kubernetes_role: None,
                approle_mount_path: None,
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
                approle_mount_path: None,
                namespace: None,
                ca_bundle: None,
            },
        )
    }

    #[test]
    fn token_auth_builds_correct_provider() {
        let sp = sample_token_provider();
        let provider = build_vault_provider(&sp).expect("should build provider");

        assert_eq!(provider.server, "https://vault.example.com");
        assert!(provider.auth.token_secret_ref.is_some());
        assert!(provider.auth.kubernetes.is_none());
        assert!(provider.auth.app_role.is_none());

        let token_ref = provider.auth.token_secret_ref.unwrap();
        assert_eq!(token_ref.key, "token");
    }

    #[test]
    fn kubernetes_auth_builds_correct_provider() {
        let sp = sample_k8s_auth_provider();
        let provider = build_vault_provider(&sp).expect("should build provider");

        assert!(provider.auth.kubernetes.is_some());
        let k8s = provider.auth.kubernetes.unwrap();
        assert_eq!(k8s.role, "my-role");
        assert_eq!(k8s.mount_path, "kubernetes");
    }

    #[test]
    fn token_auth_requires_credentials_ref() {
        let mut sp = sample_token_provider();
        sp.spec.credentials_secret_ref = None;

        let result = build_vault_provider(&sp);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("credentialsSecretRef"));
    }

    // =========================================================================
    // AppRole Auth Tests
    // =========================================================================

    fn sample_approle_provider() -> SecretsProvider {
        SecretsProvider::new(
            "vault-approle",
            SecretsProviderSpec {
                server: "https://vault.example.com".to_string(),
                path: Some("secret/data/myapp".to_string()),
                auth_method: VaultAuthMethod::AppRole,
                credentials_secret_ref: Some(SecretRef {
                    name: "vault-approle".to_string(),
                    namespace: LATTICE_SYSTEM_NAMESPACE.to_string(),
                }),
                kubernetes_mount_path: None,
                kubernetes_role: None,
                approle_mount_path: None,
                namespace: Some("my-vault-namespace".to_string()),
                ca_bundle: Some("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t".to_string()),
            },
        )
    }

    #[test]
    fn approle_auth_builds_correct_provider() {
        let sp = sample_approle_provider();
        let provider = build_vault_provider(&sp).expect("should build provider");

        assert_eq!(provider.server, "https://vault.example.com");
        assert_eq!(provider.namespace, Some("my-vault-namespace".to_string()));
        assert_eq!(
            provider.ca_bundle,
            Some("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t".to_string())
        );

        assert!(provider.auth.app_role.is_some());
        let approle = provider.auth.app_role.unwrap();
        assert_eq!(approle.path, "approle");
        assert_eq!(approle.role_ref.name, "vault-approle");
        assert_eq!(approle.role_ref.key, "role_id");
        assert_eq!(approle.secret_ref.name, "vault-approle");
        assert_eq!(approle.secret_ref.key, "secret_id");
    }

    #[test]
    fn approle_auth_requires_credentials_ref() {
        let mut sp = sample_approle_provider();
        sp.spec.credentials_secret_ref = None;

        let result = build_vault_provider(&sp);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("credentialsSecretRef"));
    }

    #[test]
    fn approle_auth_uses_custom_mount_path() {
        let mut sp = sample_approle_provider();
        sp.spec.approle_mount_path = Some("custom-approle".to_string());

        let provider = build_vault_provider(&sp).expect("should build provider");
        let approle = provider.auth.app_role.expect("should have appRole");
        assert_eq!(approle.path, "custom-approle");
    }

    // =========================================================================
    // Kubernetes Auth Default Tests
    // =========================================================================

    #[test]
    fn kubernetes_auth_uses_defaults() {
        let sp = SecretsProvider::new(
            "vault-k8s-default",
            SecretsProviderSpec {
                server: "https://vault.example.com".to_string(),
                path: None, // Should default to "secret"
                auth_method: VaultAuthMethod::Kubernetes,
                credentials_secret_ref: None,
                kubernetes_mount_path: None, // Should default to "kubernetes"
                kubernetes_role: None,       // Should default to "external-secrets"
                approle_mount_path: None,
                namespace: None,
                ca_bundle: None,
            },
        );
        let provider = build_vault_provider(&sp).expect("should build provider");

        assert_eq!(provider.path, "secret");

        let k8s = provider
            .auth
            .kubernetes
            .expect("should have kubernetes auth");
        assert_eq!(k8s.mount_path, "kubernetes");
        assert_eq!(k8s.role, "external-secrets");
    }

    // =========================================================================
    // Error Detection Tests
    // =========================================================================

    #[test]
    fn is_crd_not_found_detects_404() {
        let err = ReconcileError::Kube("404 Not Found".to_string());
        assert!(is_crd_not_found(&err));
    }

    #[test]
    fn is_crd_not_found_detects_not_found() {
        let err = ReconcileError::Kube("resource not found".to_string());
        assert!(is_crd_not_found(&err));
    }

    #[test]
    fn is_crd_not_found_detects_server_message() {
        let err =
            ReconcileError::Kube("the server could not find the requested resource".to_string());
        assert!(is_crd_not_found(&err));
    }

    #[test]
    fn is_crd_not_found_returns_false_for_other_errors() {
        let err = ReconcileError::Kube("connection refused".to_string());
        assert!(!is_crd_not_found(&err));

        let err = ReconcileError::Validation("invalid spec".to_string());
        assert!(!is_crd_not_found(&err));
    }

    // =========================================================================
    // Spec Building Edge Cases
    // =========================================================================

    #[test]
    fn token_auth_uses_default_path() {
        let sp = SecretsProvider::new(
            "vault-token-default",
            SecretsProviderSpec {
                server: "https://vault.example.com".to_string(),
                path: None, // Should default to "secret"
                auth_method: VaultAuthMethod::Token,
                credentials_secret_ref: Some(SecretRef {
                    name: "token".to_string(),
                    namespace: "default".to_string(),
                }),
                kubernetes_mount_path: None,
                kubernetes_role: None,
                approle_mount_path: None,
                namespace: None,
                ca_bundle: None,
            },
        );
        let provider = build_vault_provider(&sp).expect("should build provider");

        assert_eq!(provider.path, "secret");
    }
}
