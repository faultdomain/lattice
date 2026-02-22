//! SecretProvider reconciliation controller
//!
//! Watches SecretProvider CRDs and ensures ESO ClusterSecretStore exists.
//! The provider configuration is passed through verbatim from
//! `SecretProvider.spec.provider` to `ClusterSecretStore.spec.provider`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, DynamicObject, ListParams, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use rand::Rng;
use tracing::{debug, info, warn};

use lattice_common::crd::{SecretProvider, SecretProviderPhase};
use lattice_common::kube_utils::HasApiResource;
use lattice_common::{
    ControllerContext, ReconcileError, LABEL_MANAGED_BY, LABEL_MANAGED_BY_LATTICE,
    LATTICE_SYSTEM_NAMESPACE, LOCAL_SECRETS_NAMESPACE, LOCAL_SECRETS_PORT,
    LOCAL_WEBHOOK_AUTH_SECRET, LOCAL_WEBHOOK_STORE_NAME, REQUEUE_CRD_NOT_FOUND_SECS,
    REQUEUE_ERROR_SECS, REQUEUE_SUCCESS_SECS,
};

use crate::eso::{
    ClusterSecretStore, ClusterSecretStoreSpec, ExternalSecret, ProviderSpec, WebhookProvider,
    WebhookResult, WebhookSecret, WebhookSecretRef,
};
use crate::webhook::WebhookCredentials;

const FIELD_MANAGER: &str = "lattice-secret-provider-controller";

/// Service name for the local secrets webhook
const LOCAL_SECRETS_SERVICE: &str = "lattice-local-secrets";

/// Requeue interval when waiting for ClusterSecretStore to become Ready
const REQUEUE_WAITING_SECS: u64 = 10;

/// Ensure webhook auth credentials exist, creating them if needed.
///
/// On first run, generates a random username and password, stores them in a
/// K8s Secret in `lattice-system`. On subsequent runs, loads the existing
/// credentials. Returns the credentials for the webhook server to use.
pub async fn ensure_webhook_credentials(
    client: &Client,
) -> Result<WebhookCredentials, ReconcileError> {
    let api: Api<k8s_openapi::api::core::v1::Secret> =
        Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

    // Try to load existing credentials
    if let Ok(secret) = api.get(LOCAL_WEBHOOK_AUTH_SECRET).await {
        if let Some(data) = secret.data {
            let username = data
                .get("username")
                .and_then(|v| String::from_utf8(v.0.clone()).ok());
            let password = data
                .get("password")
                .and_then(|v| String::from_utf8(v.0.clone()).ok());

            if let (Some(username), Some(password)) = (username, password) {
                info!("Loaded existing webhook auth credentials");
                return Ok(WebhookCredentials {
                    username,
                    password: zeroize::Zeroizing::new(password),
                });
            }
            warn!("Webhook auth secret exists but has missing/invalid fields, regenerating");
        }
    }

    // Generate new random credentials
    let mut rng = rand::thread_rng();
    let username = format!("lattice-webhook-{:08x}", rng.gen::<u32>());
    let password: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..62);
            match idx {
                0..=9 => (b'0' + idx) as char,
                10..=35 => (b'a' + idx - 10) as char,
                _ => (b'A' + idx - 36) as char,
            }
        })
        .collect();

    let secret_json = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": LOCAL_WEBHOOK_AUTH_SECRET,
            "namespace": LATTICE_SYSTEM_NAMESPACE,
            "labels": {
                LABEL_MANAGED_BY: LABEL_MANAGED_BY_LATTICE,
                "external-secrets.io/type": "webhook"
            }
        },
        "type": "Opaque",
        "stringData": {
            "username": &username,
            "password": &password
        }
    });

    let params = PatchParams::apply(FIELD_MANAGER).force();
    api.patch(
        LOCAL_WEBHOOK_AUTH_SECRET,
        &params,
        &Patch::Apply(&secret_json),
    )
    .await
    .map_err(|e| ReconcileError::kube("failed to create webhook auth secret", e))?;

    info!("Generated new webhook auth credentials");
    Ok(WebhookCredentials {
        username,
        password: zeroize::Zeroizing::new(password),
    })
}

/// Ensure the local webhook infrastructure exists.
///
/// Called once on controller startup (not per-reconcile). Creates:
/// - `lattice-secrets` namespace for local secret sources
/// - `lattice-local-secrets` Service pointing at operator pods
/// - `lattice-local` ClusterSecretStore backed by the webhook (with auth)
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

    let params = PatchParams::apply(FIELD_MANAGER).force();
    css_api
        .patch(LOCAL_WEBHOOK_STORE_NAME, &params, &Patch::Apply(&css_obj))
        .await
        .map_err(|e| ReconcileError::kube("failed to apply local ClusterSecretStore", e))?;

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
                    // Detect transition from not-ready to ready and force-refresh
                    // any failed ExternalSecrets so they don't wait for refreshInterval
                    let was_pending = sp
                        .status
                        .as_ref()
                        .map(|s| s.phase != SecretProviderPhase::Ready)
                        .unwrap_or(true);
                    if was_pending {
                        info!(secrets_provider = %name, "ClusterSecretStore transitioned to Ready, force-refreshing failed ExternalSecrets");
                        if let Err(e) = force_refresh_failed_external_secrets(client, &name).await {
                            warn!(secrets_provider = %name, error = %e, "Failed to force-refresh ExternalSecrets (non-fatal)");
                        }
                    }

                    info!(secrets_provider = %name, "ClusterSecretStore is Ready");
                    update_status(client, &sp, SecretProviderPhase::Ready, None, provider_type)
                        .await?;
                    Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)))
                }
                Ok(Some((false, msg))) => {
                    info!(secrets_provider = %name, reason = %msg, "ClusterSecretStore not ready yet, re-applying to trigger ESO revalidation");
                    // Re-apply the CSS spec to force ESO to re-run provider validation.
                    // Without this, ESO keeps the store in InvalidProviderConfig even after
                    // the underlying issue (e.g., webhook pod not running) resolves.
                    if let Err(e) = ensure_cluster_secret_store(client, &sp).await {
                        warn!(secrets_provider = %name, error = %e, "Failed to re-apply ClusterSecretStore for revalidation");
                    }
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
        Err(e) if e.is_crd_not_found() => {
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

    let params = PatchParams::apply(FIELD_MANAGER).force();
    css_api
        .patch(&name, &params, &Patch::Apply(&css_obj))
        .await
        .map_err(|e| ReconcileError::kube("failed to apply ClusterSecretStore", e))?;

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

    let css = css_api
        .get(name)
        .await
        .map_err(|e| ReconcileError::kube(format!("failed to get ClusterSecretStore '{name}'"), e))?;

    let conditions = css
        .data
        .get("status")
        .and_then(|s| s.get("conditions"))
        .and_then(|c| c.as_array());

    if let Some(conditions) = conditions {
        for condition in conditions {
            if condition.get("type").and_then(|t| t.as_str()) == Some("Ready") {
                let is_ready = condition.get("status").and_then(|s| s.as_str()) == Some("True");
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

/// Force-refresh failed ExternalSecrets that reference a given ClusterSecretStore.
///
/// When a ClusterSecretStore transitions from unhealthy to healthy, ExternalSecrets
/// that failed due to the store being unavailable won't retry until their
/// `refreshInterval` (typically 1h). This function annotates them with
/// `force-sync=<timestamp>` to trigger immediate resync.
async fn force_refresh_failed_external_secrets(
    client: &Client,
    store_name: &str,
) -> Result<(), ReconcileError> {
    let api_resource = ExternalSecret::api_resource();
    let es_api: Api<DynamicObject> = Api::all_with(client.clone(), &api_resource);

    let es_list = es_api
        .list(&ListParams::default())
        .await
        .map_err(|e| ReconcileError::kube("failed to list ExternalSecrets", e))?;

    let timestamp = chrono::Utc::now().timestamp().to_string();
    let mut refreshed = 0u32;

    for es in &es_list {
        // Check if this ExternalSecret references the given store
        let refs_store = es
            .data
            .get("spec")
            .and_then(|s| s.get("secretStoreRef"))
            .map(|r| {
                let name_match = r.get("name").and_then(|n| n.as_str()) == Some(store_name);
                let kind_match = r
                    .get("kind")
                    .and_then(|k| k.as_str())
                    .map(|k| k == "ClusterSecretStore")
                    .unwrap_or(true); // default kind is ClusterSecretStore
                name_match && kind_match
            })
            .unwrap_or(false);

        if !refs_store {
            continue;
        }

        // Check if this ExternalSecret is in a failed state (Ready=False)
        let is_failed = es
            .data
            .get("status")
            .and_then(|s| s.get("conditions"))
            .and_then(|c| c.as_array())
            .map(|conditions| {
                conditions.iter().any(|c| {
                    c.get("type").and_then(|t| t.as_str()) == Some("Ready")
                        && c.get("status").and_then(|s| s.as_str()) == Some("False")
                })
            })
            .unwrap_or(false);

        if !is_failed {
            continue;
        }

        let es_name = es.metadata.name.as_deref().unwrap_or("unknown");
        let es_namespace = es.metadata.namespace.as_deref().unwrap_or("default");

        // Annotate with force-sync to trigger immediate resync
        let patch = serde_json::json!({
            "metadata": {
                "annotations": {
                    "force-sync": &timestamp
                }
            }
        });

        let ns_api: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), es_namespace, &api_resource);
        if let Err(e) = ns_api
            .patch(
                es_name,
                &PatchParams::apply(FIELD_MANAGER).force(),
                &Patch::Merge(&patch),
            )
            .await
        {
            warn!(
                external_secret = %es_name,
                namespace = %es_namespace,
                error = %e,
                "Failed to force-refresh ExternalSecret"
            );
        } else {
            info!(
                external_secret = %es_name,
                namespace = %es_namespace,
                "Force-refreshed failed ExternalSecret after store recovery"
            );
            refreshed += 1;
        }
    }

    if refreshed > 0 {
        info!(
            store = %store_name,
            count = refreshed,
            "Force-refreshed failed ExternalSecrets after ClusterSecretStore recovery"
        );
    }

    Ok(())
}

/// Build webhook provider configuration for local backend
fn build_webhook_provider() -> WebhookProvider {
    // Go template placeholders for ESO — kept as consts to avoid fragile `{{{{`
    // escaping that `format!` would require for literal double-braces.
    const ESO_REMOTE_REF_KEY: &str = "{{ .remoteRef.key }}";
    // Conditional property suffix: appends `/{property}` only when remoteRef.property
    // is non-empty. This handles both ESO paths:
    //   - spec.data entries (property set)  → /secret/foo/password  → single value
    //   - dataFrom.extract (property empty) → /secret/foo           → full JSON map
    const ESO_PROPERTY_SUFFIX: &str =
        "{{ if .remoteRef.property }}/{{ .remoteRef.property }}{{ end }}";

    let base = format!(
        "http://{}.{}.svc:{}/secret/",
        LOCAL_SECRETS_SERVICE, LATTICE_SYSTEM_NAMESPACE, LOCAL_SECRETS_PORT
    );
    let url = format!("{}{}{}", base, ESO_REMOTE_REF_KEY, ESO_PROPERTY_SUFFIX);

    // ESO renders the Go template: reads .auth.username and .auth.password from
    // the referenced K8s Secret, base64-encodes "user:pass", and sends as Basic auth.
    let mut headers = BTreeMap::new();
    headers.insert(
        "Authorization".to_string(),
        r#"Basic {{ print .auth.username ":" .auth.password | b64enc }}"#.to_string(),
    );

    let secrets = vec![WebhookSecret {
        name: "auth".to_string(),
        secret_ref: WebhookSecretRef {
            namespace: LATTICE_SYSTEM_NAMESPACE.to_string(),
            name: LOCAL_WEBHOOK_AUTH_SECRET.to_string(),
        },
    }];

    WebhookProvider {
        url,
        method: "GET".to_string(),
        headers,
        secrets,
        result: WebhookResult {
            json_path: "$".to_string(),
        },
    }
}

/// Ensure the `lattice-secrets` namespace exists for local secret sources
async fn ensure_local_secrets_namespace(client: &Client) -> Result<(), ReconcileError> {
    let ns_api: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());
    let ns = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": LOCAL_SECRETS_NAMESPACE,
            "labels": {
                "app.kubernetes.io/managed-by": lattice_common::LABEL_MANAGED_BY_LATTICE
            }
        }
    });

    let params = PatchParams::apply(FIELD_MANAGER).force();
    ns_api
        .patch(LOCAL_SECRETS_NAMESPACE, &params, &Patch::Apply(&ns))
        .await
        .map_err(|e| {
            ReconcileError::kube(
                format!("failed to ensure namespace {LOCAL_SECRETS_NAMESPACE}"),
                e,
            )
        })?;

    debug!("Ensured namespace {}", LOCAL_SECRETS_NAMESPACE);
    Ok(())
}

/// Ensure the webhook K8s Service exists pointing at operator pods
async fn ensure_webhook_service(client: &Client) -> Result<(), ReconcileError> {
    let svc = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": LOCAL_SECRETS_SERVICE,
            "namespace": LATTICE_SYSTEM_NAMESPACE,
            "labels": {
                "app.kubernetes.io/managed-by": lattice_common::LABEL_MANAGED_BY_LATTICE
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

    let svc_api: Api<k8s_openapi::api::core::v1::Service> =
        Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let params = PatchParams::apply(FIELD_MANAGER).force();
    svc_api
        .patch(LOCAL_SECRETS_SERVICE, &params, &Patch::Apply(&svc))
        .await
        .map_err(|e| {
            ReconcileError::kube(
                format!("failed to ensure webhook service {LOCAL_SECRETS_SERVICE}"),
                e,
            )
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
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

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
        &PatchParams::apply(FIELD_MANAGER),
        &Patch::Merge(&patch),
    )
    .await
    .map_err(|e| ReconcileError::kube("failed to update status", e))?;

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
        assert!(err.is_crd_not_found());
    }

    #[test]
    fn is_crd_not_found_detects_not_found() {
        let err = ReconcileError::Kube("resource not found".to_string());
        assert!(err.is_crd_not_found());
    }

    #[test]
    fn is_crd_not_found_detects_server_message() {
        let err =
            ReconcileError::Kube("the server could not find the requested resource".to_string());
        assert!(err.is_crd_not_found());
    }

    #[test]
    fn is_crd_not_found_returns_false_for_other_errors() {
        let err = ReconcileError::Kube("connection refused".to_string());
        assert!(!err.is_crd_not_found());

        let err = ReconcileError::Validation("invalid spec".to_string());
        assert!(!err.is_crd_not_found());
    }

    // =========================================================================
    // Reconcile Action Tests
    // =========================================================================

    /// Test helper to compute the expected Action for a given reconcile result.
    fn compute_expected_action(result: Result<(), ReconcileError>) -> Action {
        match result {
            Ok(()) => Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)),
            Err(e) if e.is_crd_not_found() => {
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
            "URL should contain key placeholder: {}",
            provider.url
        );
        assert!(
            provider
                .url
                .contains("{{ if .remoteRef.property }}/{{ .remoteRef.property }}{{ end }}"),
            "URL should conditionally append property: {}",
            provider.url
        );
        assert_eq!(provider.method, "GET");
        assert_eq!(
            provider.result.json_path, "$",
            "jsonPath should be $ (property extraction is server-side)"
        );

        // Verify auth header template
        assert_eq!(
            provider.headers.get("Authorization").unwrap(),
            r#"Basic {{ print .auth.username ":" .auth.password | b64enc }}"#,
            "Authorization header should use ESO Go template for Basic auth"
        );

        // Verify secret reference
        assert_eq!(provider.secrets.len(), 1);
        assert_eq!(provider.secrets[0].name, "auth");
        assert_eq!(
            provider.secrets[0].secret_ref.name,
            LOCAL_WEBHOOK_AUTH_SECRET
        );
        assert_eq!(
            provider.secrets[0].secret_ref.namespace,
            LATTICE_SYSTEM_NAMESPACE
        );
    }

    #[test]
    fn local_secrets_constants_are_expected() {
        assert_eq!(LOCAL_SECRETS_SERVICE, "lattice-local-secrets");
        assert_eq!(LOCAL_SECRETS_PORT, 8787);
        assert_eq!(LOCAL_SECRETS_NAMESPACE, "lattice-secrets");
        assert_eq!(LOCAL_WEBHOOK_AUTH_SECRET, "lattice-webhook-auth");
    }
}
