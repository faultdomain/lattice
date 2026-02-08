//! SecretProvider reconciliation controller
//!
//! Watches SecretProvider CRDs and ensures ESO ClusterSecretStore exists.
//! The provider configuration is passed through verbatim from
//! `SecretProvider.spec.provider` to `ClusterSecretStore.spec.provider`.

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, DynamicObject, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::crd::{SecretProvider, SecretProviderPhase};
use lattice_common::kube_utils::HasApiResource;
use lattice_common::{
    ControllerContext, ReconcileError, LABEL_MANAGED_BY, LABEL_MANAGED_BY_LATTICE,
    LATTICE_SYSTEM_NAMESPACE, LOCAL_SECRETS_NAMESPACE, LOCAL_SECRETS_PORT,
};

use crate::eso::{
    ClusterSecretStore, ClusterSecretStoreSpec, ProviderSpec, WebhookProvider, WebhookResult,
};

/// Well-known name for the local webhook ClusterSecretStore
pub(crate) const LOCAL_WEBHOOK_STORE_NAME: &str = "lattice-local";

/// Service name for the local secrets webhook
const LOCAL_SECRETS_SERVICE: &str = "lattice-local-secrets";

/// Requeue interval for successful reconciliation (handles drift detection)
const REQUEUE_SUCCESS_SECS: u64 = 300;
/// Requeue interval when CRD is not found (waiting for ESO installation)
const REQUEUE_CRD_NOT_FOUND_SECS: u64 = 30;
/// Requeue interval on other errors (with backoff)
const REQUEUE_ERROR_SECS: u64 = 60;
/// Requeue interval when waiting for ClusterSecretStore to become Ready
const REQUEUE_WAITING_SECS: u64 = 10;

/// Ensure the local webhook infrastructure exists.
///
/// Called once on controller startup (not per-reconcile). Creates:
/// - `lattice-secrets` namespace for local secret sources
/// - `lattice-local-secrets` Service pointing at operator pods
/// - `lattice-local` ClusterSecretStore backed by the webhook
pub async fn ensure_local_webhook_infrastructure(client: &Client) -> Result<(), ReconcileError> {
    ensure_local_secrets_namespace(client).await?;
    ensure_webhook_service(client).await?;

    let css = ClusterSecretStore::new(
        LOCAL_WEBHOOK_STORE_NAME,
        ClusterSecretStoreSpec {
            provider: ProviderSpec {
                webhook: Some(build_webhook_provider()),
            },
        },
    );

    let css_json = serde_json::to_value(&css).map_err(|e| {
        ReconcileError::Internal(format!("failed to serialize local ClusterSecretStore: {e}"))
    })?;

    let api_resource = ClusterSecretStore::api_resource();
    let css_api: Api<DynamicObject> = Api::all_with(client.clone(), &api_resource);
    let css_obj: DynamicObject = serde_json::from_value(css_json).map_err(|e| {
        ReconcileError::Internal(format!("failed to build local ClusterSecretStore: {e}"))
    })?;

    let params = PatchParams::apply("lattice-secrets-provider").force();
    css_api
        .patch(LOCAL_WEBHOOK_STORE_NAME, &params, &Patch::Apply(&css_obj))
        .await
        .map_err(|e| {
            ReconcileError::Kube(format!("failed to apply local ClusterSecretStore: {e}"))
        })?;

    info!(
        "Local webhook ClusterSecretStore '{}' ensured",
        LOCAL_WEBHOOK_STORE_NAME
    );
    Ok(())
}

/// Reconcile a SecretProvider
///
/// Ensures the corresponding ESO ClusterSecretStore exists with the
/// provider configuration passed through verbatim.
pub async fn reconcile(
    sp: Arc<SecretProvider>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = sp.name_any();
    let client = &ctx.client;

    info!(secrets_provider = %name, "Reconciling SecretProvider");

    // Validate spec before attempting to create the ClusterSecretStore
    if let Err(msg) = sp.spec.validate() {
        warn!(secrets_provider = %name, error = %msg, "Invalid SecretProvider spec");
        update_status(client, &sp, SecretProviderPhase::Failed, Some(msg), None).await?;
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
    }

    let provider_type = sp.spec.provider_type_name().map(|s| s.to_string());

    // Try to create/update the ClusterSecretStore
    match ensure_cluster_secret_store(client, &sp).await {
        Ok(()) => {
            // Check if ESO has validated the ClusterSecretStore
            match check_cluster_secret_store_ready(client, &name).await {
                Ok(Some((true, _))) => {
                    info!(secrets_provider = %name, "ClusterSecretStore is Ready");
                    update_status(
                        client,
                        &sp,
                        SecretProviderPhase::Ready,
                        None,
                        provider_type,
                    )
                    .await?;
                    Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
                }
                Ok(Some((false, msg))) => {
                    info!(secrets_provider = %name, reason = %msg, "ClusterSecretStore not ready yet");
                    update_status(
                        client,
                        &sp,
                        SecretProviderPhase::Pending,
                        Some(format!("ClusterSecretStore not ready: {msg}")),
                        provider_type,
                    )
                    .await?;
                    Ok(Action::requeue(Duration::from_secs(REQUEUE_WAITING_SECS)))
                }
                Ok(None) => {
                    // No Ready condition yet — ESO hasn't reconciled
                    info!(secrets_provider = %name, "Waiting for ESO to validate ClusterSecretStore");
                    update_status(
                        client,
                        &sp,
                        SecretProviderPhase::Pending,
                        Some("Waiting for ESO to validate ClusterSecretStore".to_string()),
                        provider_type,
                    )
                    .await?;
                    Ok(Action::requeue(Duration::from_secs(REQUEUE_WAITING_SECS)))
                }
                Err(e) => {
                    warn!(secrets_provider = %name, error = %e, "Failed to check ClusterSecretStore status");
                    // CSS was applied successfully, just can't read status — requeue
                    Ok(Action::requeue(Duration::from_secs(REQUEUE_WAITING_SECS)))
                }
            }
        }
        Err(e) if is_crd_not_found(&e) => {
            warn!(
                secrets_provider = %name,
                "ESO ClusterSecretStore CRD not found - ESO may not be installed, will retry"
            );

            update_status(
                client,
                &sp,
                SecretProviderPhase::Pending,
                Some("Waiting for ESO to be installed".to_string()),
                provider_type,
            )
            .await?;

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
                SecretProviderPhase::Failed,
                Some(e.to_string()),
                provider_type,
            )
            .await?;

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

/// Ensure ClusterSecretStore exists for the SecretProvider.
///
/// Passes `sp.spec.provider` through verbatim as the CSS `spec.provider`.
async fn ensure_cluster_secret_store(
    client: &Client,
    sp: &SecretProvider,
) -> Result<(), ReconcileError> {
    let name = sp.name_any();

    let provider_value = serde_json::Value::Object(sp.spec.provider.clone());
    let css_json = serde_json::json!({
        "apiVersion": "external-secrets.io/v1",
        "kind": "ClusterSecretStore",
        "metadata": {
            "name": name,
            "labels": {
                LABEL_MANAGED_BY: LABEL_MANAGED_BY_LATTICE,
                "lattice.dev/secrets-provider": name,
            }
        },
        "spec": {
            "provider": provider_value
        }
    });

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

/// Check if a ClusterSecretStore has been validated by ESO.
///
/// Returns `Ok(Some((ready, message)))` if a Ready condition exists,
/// `Ok(None)` if ESO hasn't set a condition yet.
async fn check_cluster_secret_store_ready(
    client: &Client,
    name: &str,
) -> Result<Option<(bool, String)>, ReconcileError> {
    let api_resource = ClusterSecretStore::api_resource();
    let css_api: Api<DynamicObject> = Api::all_with(client.clone(), &api_resource);

    let css = css_api.get(name).await.map_err(|e| {
        ReconcileError::Kube(format!("failed to get ClusterSecretStore '{name}': {e}"))
    })?;

    let conditions = css
        .data
        .get("status")
        .and_then(|s| s.get("conditions"))
        .and_then(|c| c.as_array());

    if let Some(conditions) = conditions {
        for condition in conditions {
            if condition.get("type").and_then(|t| t.as_str()) == Some("Ready") {
                let is_ready =
                    condition.get("status").and_then(|s| s.as_str()) == Some("True");
                let message = condition
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string();
                return Ok(Some((is_ready, message)));
            }
        }
    }

    Ok(None)
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

/// Update SecretProvider status
async fn update_status(
    client: &Client,
    sp: &SecretProvider,
    phase: SecretProviderPhase,
    message: Option<String>,
    provider_type: Option<String>,
) -> Result<(), ReconcileError> {
    // Check if status already matches - avoid update loop
    if let Some(ref current_status) = sp.status {
        if current_status.phase == phase
            && current_status.message == message
            && current_status.provider_type == provider_type
        {
            debug!(secrets_provider = %sp.name_any(), "Status unchanged, skipping update");
            return Ok(());
        }
    }

    let name = sp.name_any();
    let namespace = sp
        .namespace()
        .unwrap_or(LATTICE_SYSTEM_NAMESPACE.to_string());

    // Build the patch manually instead of serializing SecretProviderStatus,
    // because Merge patches need explicit `null` to clear fields — serde's
    // `skip_serializing_if = "Option::is_none"` omits them entirely, which
    // leaves stale values in place and causes a reconcile loop.
    let patch = serde_json::json!({
        "status": {
            "phase": phase,
            "message": message,
            "lastValidated": chrono::Utc::now().to_rfc3339(),
            "providerType": provider_type,
        }
    });

    let api: Api<SecretProvider> = Api::namespaced(client.clone(), &namespace);
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
    // Reconcile Action Tests
    // =========================================================================

    /// Test helper to compute the expected Action for a given reconcile result.
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
        assert_eq!(REQUEUE_SUCCESS_SECS, 300);
        assert_eq!(REQUEUE_CRD_NOT_FOUND_SECS, 30);
        assert_eq!(REQUEUE_ERROR_SECS, 60);
        assert_eq!(REQUEUE_WAITING_SECS, 10);
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
