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
    SecretsBackend, SecretsProvider, SecretsProviderPhase, SecretsProviderStatus, VaultAuthMethod,
};
use lattice_common::kube_utils::HasApiResource;
use lattice_common::{
    ControllerContext, ReconcileError, LATTICE_SYSTEM_NAMESPACE, LOCAL_SECRETS_NAMESPACE,
    LOCAL_SECRETS_PORT,
};

use crate::eso::{
    AppRoleAuth, ClusterSecretStore, ClusterSecretStoreSpec, KubernetesAuth, ProviderSpec,
    SecretKeyRef, ServiceAccountRef, VaultAuth, VaultProvider, WebhookProvider, WebhookResult,
};

/// Default Vault secret path
const DEFAULT_PATH: &str = "secret";
/// Default Vault KV version
const DEFAULT_VAULT_VERSION: &str = "v2";
/// Default Kubernetes auth mount path in Vault
const DEFAULT_MOUNT_PATH: &str = "kubernetes";
/// Default Kubernetes auth role name
const DEFAULT_ROLE: &str = "external-secrets";
/// Default AppRole auth mount path in Vault
const DEFAULT_APPROLE_PATH: &str = "approle";
/// Default ESO namespace
const ESO_NAMESPACE: &str = "external-secrets";
/// Default ESO service account name
const ESO_SERVICE_ACCOUNT: &str = "external-secrets";

/// Service name for the local secrets webhook
const LOCAL_SECRETS_SERVICE: &str = "lattice-local-secrets";

/// Requeue interval for successful reconciliation (handles drift detection)
const REQUEUE_SUCCESS_SECS: u64 = 300;
/// Requeue interval when CRD is not found (waiting for ESO installation)
const REQUEUE_CRD_NOT_FOUND_SECS: u64 = 30;
/// Requeue interval on other errors (with backoff)
const REQUEUE_ERROR_SECS: u64 = 60;

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
            Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
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
            Ok(Action::requeue(Duration::from_secs(
                REQUEUE_CRD_NOT_FOUND_SECS,
            )))
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
            Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)))
        }
    }
}

/// Check if error is due to CRD not found (ESO not installed)
fn is_crd_not_found(error: &ReconcileError) -> bool {
    let err_str = error.to_string();
    err_str.contains("404")
        || err_str.contains("not found")
        || err_str.contains("the server could not find the requested resource")
}

/// Ensure ClusterSecretStore exists for the SecretsProvider
async fn ensure_cluster_secret_store(
    client: &Client,
    sp: &SecretsProvider,
) -> Result<(), ReconcileError> {
    let name = sp.name_any();

    // Build the provider spec based on backend type
    let provider_spec = match sp.spec.backend {
        SecretsBackend::Vault => {
            let vault_provider = build_vault_provider(sp)?;
            ProviderSpec {
                vault: Some(vault_provider),
                webhook: None,
            }
        }
        SecretsBackend::Local => {
            ensure_local_secrets_namespace(client).await?;
            ensure_webhook_service(client).await?;
            ProviderSpec {
                vault: None,
                webhook: Some(build_webhook_provider()),
            }
        }
    };

    let css = ClusterSecretStore::new(
        &name,
        ClusterSecretStoreSpec {
            provider: provider_spec,
        },
    );

    // Serialize to JSON for dynamic API
    let css_json = serde_json::to_value(&css).map_err(|e| {
        ReconcileError::Internal(format!("failed to serialize ClusterSecretStore: {e}"))
    })?;

    // Use dynamic API to apply ClusterSecretStore
    let api_resource = ClusterSecretStore::api_resource();
    let css_api: Api<DynamicObject> = Api::all_with(client.clone(), &api_resource);
    let css_obj: DynamicObject = serde_json::from_value(css_json).map_err(|e| {
        ReconcileError::Internal(format!("failed to build ClusterSecretStore: {e}"))
    })?;

    let params = PatchParams::apply("lattice-secrets-provider").force();
    css_api
        .patch(&name, &params, &Patch::Apply(&css_obj))
        .await
        .map_err(|e| ReconcileError::Kube(format!("failed to apply ClusterSecretStore: {e}")))?;

    debug!(secrets_provider = %name, "Applied ClusterSecretStore");
    Ok(())
}

/// Build webhook provider configuration for local backend
fn build_webhook_provider() -> WebhookProvider {
    // Go template placeholder for ESO — kept as a const to avoid fragile `{{{{`
    // escaping that `format!` would require for literal double-braces.
    const ESO_REMOTE_REF_KEY: &str = "{{ .remoteRef.key }}";

    let base = format!(
        "http://{}.{}.svc:{}/secret/",
        LOCAL_SECRETS_SERVICE, LATTICE_SYSTEM_NAMESPACE, LOCAL_SECRETS_PORT
    );
    let url = format!("{}{}", base, ESO_REMOTE_REF_KEY);
    WebhookProvider {
        url,
        method: "GET".to_string(),
        result: WebhookResult {
            json_path: "$".to_string(),
        },
    }
}

/// Ensure the `lattice-secrets` namespace exists for local secret sources
async fn ensure_local_secrets_namespace(client: &Client) -> Result<(), ReconcileError> {
    use k8s_openapi::api::core::v1::Namespace;

    let ns_api: Api<Namespace> = Api::all(client.clone());
    let ns = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": LOCAL_SECRETS_NAMESPACE,
            "labels": {
                "app.kubernetes.io/managed-by": "lattice"
            }
        }
    });

    let params = PatchParams::apply("lattice-secrets-provider").force();
    ns_api
        .patch(LOCAL_SECRETS_NAMESPACE, &params, &Patch::Apply(&ns))
        .await
        .map_err(|e| {
            ReconcileError::Kube(format!(
                "failed to ensure namespace {LOCAL_SECRETS_NAMESPACE}: {e}"
            ))
        })?;

    debug!("Ensured namespace {}", LOCAL_SECRETS_NAMESPACE);
    Ok(())
}

/// Ensure the webhook K8s Service exists pointing at operator pods
async fn ensure_webhook_service(client: &Client) -> Result<(), ReconcileError> {
    use k8s_openapi::api::core::v1::Service;

    let svc = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": LOCAL_SECRETS_SERVICE,
            "namespace": LATTICE_SYSTEM_NAMESPACE,
            "labels": {
                "app.kubernetes.io/managed-by": "lattice"
            }
        },
        "spec": {
            "selector": {
                "app": "lattice-operator"
            },
            "ports": [{
                "name": "webhook",
                "port": LOCAL_SECRETS_PORT,
                "targetPort": LOCAL_SECRETS_PORT,
                "protocol": "TCP"
            }]
        }
    });

    let svc_api: Api<Service> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let params = PatchParams::apply("lattice-secrets-provider").force();
    svc_api
        .patch(LOCAL_SECRETS_SERVICE, &params, &Patch::Apply(&svc))
        .await
        .map_err(|e| {
            ReconcileError::Kube(format!(
                "failed to ensure webhook service {LOCAL_SECRETS_SERVICE}: {e}"
            ))
        })?;

    debug!("Ensured webhook service {}", LOCAL_SECRETS_SERVICE);
    Ok(())
}

/// Build VaultProvider from SecretsProvider spec
fn build_vault_provider(sp: &SecretsProvider) -> Result<VaultProvider, ReconcileError> {
    let auth = build_vault_auth(sp)?;

    Ok(VaultProvider {
        server: sp.spec.server.clone(),
        path: sp
            .spec
            .path
            .clone()
            .unwrap_or_else(|| DEFAULT_PATH.to_string()),
        version: DEFAULT_VAULT_VERSION.to_string(),
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
                .unwrap_or_else(|| DEFAULT_MOUNT_PATH.to_string());
            let role = sp
                .spec
                .kubernetes_role
                .clone()
                .unwrap_or_else(|| DEFAULT_ROLE.to_string());
            Ok(VaultAuth {
                token_secret_ref: None,
                kubernetes: Some(KubernetesAuth {
                    mount_path,
                    role,
                    service_account_ref: ServiceAccountRef {
                        name: ESO_SERVICE_ACCOUNT.to_string(),
                        namespace: ESO_NAMESPACE.to_string(),
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
                .unwrap_or_else(|| DEFAULT_APPROLE_PATH.to_string());
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
    .map_err(|e| ReconcileError::Kube(format!("failed to update status: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{SecretRef, SecretsProviderSpec};

    /// Helper to assert that a provider requires credentials_secret_ref
    fn assert_requires_credentials<F>(mut provider_fn: F)
    where
        F: FnMut() -> SecretsProvider,
    {
        let mut sp = provider_fn();
        sp.spec.credentials_secret_ref = None;
        let result = build_vault_provider(&sp);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("credentialsSecretRef"));
    }

    fn sample_token_provider() -> SecretsProvider {
        SecretsProvider::new(
            "vault-prod",
            SecretsProviderSpec {
                backend: SecretsBackend::default(),
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
                backend: SecretsBackend::default(),
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
        assert_requires_credentials(sample_token_provider);
    }

    // =========================================================================
    // AppRole Auth Tests
    // =========================================================================

    fn sample_approle_provider() -> SecretsProvider {
        SecretsProvider::new(
            "vault-approle",
            SecretsProviderSpec {
                backend: SecretsBackend::default(),
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
        assert_requires_credentials(sample_approle_provider);
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
                backend: SecretsBackend::default(),
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
                backend: SecretsBackend::default(),
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

    // =========================================================================
    // Reconcile Action Tests
    // =========================================================================

    /// Test helper to compute the expected Action for a given reconcile result.
    /// This mirrors the logic in reconcile() without requiring a Kubernetes client.
    fn compute_expected_action(result: Result<(), ReconcileError>) -> Action {
        match result {
            Ok(()) => Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)),
            Err(e) if is_crd_not_found(&e) => {
                Action::requeue(Duration::from_secs(REQUEUE_CRD_NOT_FOUND_SECS))
            }
            Err(_) => Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)),
        }
    }

    #[test]
    fn reconcile_success_requeues_with_300s() {
        let action = compute_expected_action(Ok(()));
        assert_eq!(action, Action::requeue(Duration::from_secs(300)));
    }

    #[test]
    fn reconcile_crd_not_found_requeues_with_30s() {
        let action =
            compute_expected_action(Err(ReconcileError::Kube("404 Not Found".to_string())));
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    #[test]
    fn reconcile_crd_not_found_message_requeues_with_30s() {
        let action = compute_expected_action(Err(ReconcileError::Kube(
            "the server could not find the requested resource".to_string(),
        )));
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    #[test]
    fn reconcile_other_error_requeues_with_60s() {
        let action =
            compute_expected_action(Err(ReconcileError::Kube("connection refused".to_string())));
        assert_eq!(action, Action::requeue(Duration::from_secs(60)));
    }

    #[test]
    fn reconcile_validation_error_requeues_with_60s() {
        let action =
            compute_expected_action(Err(ReconcileError::Validation("invalid spec".to_string())));
        assert_eq!(action, Action::requeue(Duration::from_secs(60)));
    }

    // =========================================================================
    // Requeue Constants Tests
    // =========================================================================

    #[test]
    fn requeue_constants_have_expected_values() {
        // Success path: 5 minutes for drift detection
        assert_eq!(REQUEUE_SUCCESS_SECS, 300);
        // CRD not found: 30 seconds for faster ESO installation detection
        assert_eq!(REQUEUE_CRD_NOT_FOUND_SECS, 30);
        // Error path: 1 minute for backoff
        assert_eq!(REQUEUE_ERROR_SECS, 60);
    }

    // =========================================================================
    // Webhook Provider Tests
    // =========================================================================

    #[test]
    fn build_webhook_provider_produces_correct_url() {
        let provider = build_webhook_provider();
        assert!(
            provider
                .url
                .contains("lattice-local-secrets.lattice-system.svc:8787"),
            "URL should target the webhook service: {}",
            provider.url
        );
        assert!(
            provider.url.contains("{{ .remoteRef.key }}"),
            "URL should contain Go template placeholder: {}",
            provider.url
        );
        assert_eq!(provider.method, "GET");
        assert_eq!(provider.result.json_path, "$");
    }

    #[test]
    fn local_secrets_constants_are_expected() {
        assert_eq!(LOCAL_SECRETS_SERVICE, "lattice-local-secrets");
        assert_eq!(LOCAL_SECRETS_PORT, 8787);
        assert_eq!(LOCAL_SECRETS_NAMESPACE, "lattice-secrets");
    }
}
