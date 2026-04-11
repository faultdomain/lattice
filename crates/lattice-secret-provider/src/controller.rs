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
use tracing::{debug, info, warn};

use lattice_common::kube_utils::HasApiResource;
use lattice_common::status_check;
use lattice_common::{
    ControllerContext, ReconcileError, LABEL_MANAGED_BY, LABEL_MANAGED_BY_LATTICE, LABEL_NAME,
    LOCAL_SECRETS_NAMESPACE, LOCAL_SECRETS_PORT, LOCAL_WEBHOOK_AUTH_SECRET,
    LOCAL_WEBHOOK_STORE_NAME, OPERATOR_NAME, REQUEUE_CRD_NOT_FOUND_SECS, REQUEUE_ERROR_SECS,
    REQUEUE_SUCCESS_SECS,
};
use lattice_core::LATTICE_SYSTEM_NAMESPACE;
use lattice_crd::crd::{
    EgressRule, EgressTarget, LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberTarget,
    SecretProvider, SecretProviderPhase,
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

    // Generate new random credentials using FIPS-validated RNG
    let mut id_bytes = [0u8; 4];
    aws_lc_rs::rand::fill(&mut id_bytes).map_err(|_| {
        ReconcileError::Internal("FIPS RNG failure generating webhook credentials".into())
    })?;
    let username = format!("lattice-webhook-{:08x}", u32::from_be_bytes(id_bytes));

    let mut pwd_bytes = [0u8; 32];
    aws_lc_rs::rand::fill(&mut pwd_bytes).map_err(|_| {
        ReconcileError::Internal("FIPS RNG failure generating webhook credentials".into())
    })?;
    let password: String = pwd_bytes
        .iter()
        .map(|b| {
            let idx = (*b as usize) % 62;
            match idx {
                0..=9 => (b'0' + idx as u8) as char,
                10..=35 => (b'a' + (idx - 10) as u8) as char,
                _ => (b'A' + (idx - 36) as u8) as char,
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
    .await?;

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
        .await?;

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
/// Skips work when the spec hasn't changed (generation matches) and already Ready.
pub async fn reconcile(
    sp: Arc<SecretProvider>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = sp.name_any();
    let client = &ctx.client;
    let generation = sp.metadata.generation.unwrap_or(0);

    // Validate spec on every run (cheap, catches edge cases)
    if let Err(e) = sp.spec.validate() {
        let msg = e.to_string();
        warn!(secrets_provider = %name, error = %msg, "Invalid SecretProvider spec");
        update_status(
            client,
            &sp,
            SecretProviderPhase::Failed,
            Some(msg),
            None,
            Some(generation),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
    }

    let provider_type = sp.spec.provider_type_name().map(|s| s.to_string());

    // Skip full reconcile if spec unchanged and already Ready
    if status_check::is_status_unchanged(
        sp.status.as_ref(),
        &SecretProviderPhase::Ready,
        None,
        Some(generation),
    ) {
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)));
    }

    info!(secrets_provider = %name, "Reconciling SecretProvider");

    // Try to create/update the ClusterSecretStore
    match ensure_cluster_secret_store(client, &sp).await {
        Ok(()) => {
            // Ensure egress policies so ESO can reach external provider endpoints
            ensure_external_egress_lmm(client, &sp).await?;

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
                    update_status(
                        client,
                        &sp,
                        SecretProviderPhase::Ready,
                        None,
                        provider_type,
                        Some(generation),
                    )
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
                        Some(generation),
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
                        Some(generation),
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
                Some(generation),
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
                Some(generation),
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
        .await?;

    debug!(secrets_provider = %name, "Applied ClusterSecretStore");
    Ok(())
}

/// Namespace where ESO is deployed
const ESO_NAMESPACE: &str = "external-secrets";

/// Ensure an egress LMM exists for external SecretProvider endpoints.
///
/// When a SecretProvider points to an external host (e.g., Vault at 172.18.0.9:8200),
/// ESO pods need mesh egress policies to reach it. This creates a lightweight
/// egress-only LatticeMeshMember targeting ESO pods with FQDN egress rules.
///
/// If the provider has no external endpoints (e.g., cluster-local webhook), any
/// existing egress LMM for this provider is deleted.
async fn ensure_external_egress_lmm(
    client: &Client,
    sp: &SecretProvider,
) -> Result<(), ReconcileError> {
    let sp_name = sp.name_any();
    let lmm_name = format!("egress-sp-{}", sp_name);
    let endpoints = sp.spec.external_endpoints();

    let api: Api<LatticeMeshMember> = Api::namespaced(client.clone(), ESO_NAMESPACE);

    if endpoints.is_empty() {
        // No external endpoints — delete any existing egress LMM
        match api.delete(&lmm_name, &Default::default()).await {
            Ok(_) => {
                debug!(secrets_provider = %sp_name, "Deleted egress LMM (no external endpoints)");
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {}
            Err(e) => {
                warn!(secrets_provider = %sp_name, error = %e, "Failed to delete egress LMM");
            }
        }
        return Ok(());
    }

    let egress_rules: Vec<EgressRule> = endpoints
        .iter()
        .map(|ep| EgressRule::tcp(EgressTarget::for_host(&ep.host), vec![ep.port]))
        .collect();

    let mut lmm = LatticeMeshMember::new(
        &lmm_name,
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                LABEL_NAME.to_string(),
                "external-secrets".to_string(),
            )])),
            ports: vec![],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: egress_rules,
            allow_peer_traffic: false,
            depends_all: false,
            ingress: None,
            service_account: Some("external-secrets".to_string()),
            ambient: true, advertise: None,
        },
    );
    lmm.metadata.namespace = Some(ESO_NAMESPACE.to_string());
    lmm.metadata.labels = Some(BTreeMap::from([
        (
            LABEL_MANAGED_BY.to_string(),
            "secret-provider-controller".to_string(),
        ),
        ("lattice.dev/secrets-provider".to_string(), sp_name.clone()),
    ]));

    let params = PatchParams::apply(FIELD_MANAGER).force();
    api.patch(&lmm_name, &params, &Patch::Apply(&lmm)).await?;

    info!(
        secrets_provider = %sp_name,
        lmm = %lmm_name,
        endpoints = endpoints.len(),
        "Ensured egress LMM for external SecretProvider endpoints"
    );
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

    let css = css_api.get(name).await?;

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
/// Page size for paginated ExternalSecret listing.
/// Keeps per-page memory bounded while minimizing API round-trips.
const ES_LIST_PAGE_SIZE: u32 = 100;

async fn force_refresh_failed_external_secrets(
    client: &Client,
    store_name: &str,
) -> Result<(), ReconcileError> {
    let api_resource = ExternalSecret::api_resource();
    let es_api: Api<DynamicObject> = Api::all_with(client.clone(), &api_resource);

    let timestamp = chrono::Utc::now().timestamp().to_string();
    let mut refreshed = 0u32;

    // Paginate to avoid loading all ExternalSecrets into memory at once
    let mut lp = ListParams::default().limit(ES_LIST_PAGE_SIZE);
    loop {
        let es_list = es_api.list(&lp).await?;

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

        // Continue to next page or break
        match es_list.metadata.continue_ {
            Some(ref token) if !token.is_empty() => {
                lp = lp.continue_token(token);
            }
            _ => break,
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
                (LABEL_MANAGED_BY): LABEL_MANAGED_BY_LATTICE
            }
        }
    });

    let params = PatchParams::apply(FIELD_MANAGER).force();
    ns_api
        .patch(LOCAL_SECRETS_NAMESPACE, &params, &Patch::Apply(&ns))
        .await?;

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
                (LABEL_MANAGED_BY): LABEL_MANAGED_BY_LATTICE
            }
        },
        "spec": {
            "selector": {
                "app": OPERATOR_NAME
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
        .await?;

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
    observed_generation: Option<i64>,
) -> Result<(), ReconcileError> {
    if status_check::is_status_unchanged(
        sp.status.as_ref(),
        &phase,
        message.as_deref(),
        observed_generation,
    ) {
        debug!(secrets_provider = %sp.name_any(), "Status unchanged, skipping update");
        return Ok(());
    }

    let name = sp.name_any();
    let namespace = sp
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

    let status = lattice_crd::crd::SecretProviderStatus {
        phase,
        message,
        last_validated: Some(chrono::Utc::now().to_rfc3339()),
        provider_type,
        observed_generation,
    };

    lattice_common::kube_utils::patch_resource_status::<SecretProvider>(
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

    // =========================================================================
    // Error Detection Tests
    // =========================================================================

    fn kube_api_error(code: u16, message: &str) -> ReconcileError {
        ReconcileError::Kube(kube::Error::Api(Box::new(kube::core::Status {
            message: message.to_string(),
            reason: "".to_string(),
            code,
            ..Default::default()
        })))
    }

    #[test]
    fn is_crd_not_found_detects_404() {
        let err = kube_api_error(404, "404 Not Found");
        assert!(err.is_crd_not_found());
    }

    #[test]
    fn is_crd_not_found_detects_not_found() {
        let err = kube_api_error(404, "resource not found");
        assert!(err.is_crd_not_found());
    }

    #[test]
    fn is_crd_not_found_detects_server_message() {
        let err = kube_api_error(404, "the server could not find the requested resource");
        assert!(err.is_crd_not_found());
    }

    #[test]
    fn is_crd_not_found_returns_false_for_other_errors() {
        let err = kube_api_error(503, "connection refused");
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
        let action = compute_expected_action(Err(kube_api_error(404, "404 Not Found")));
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    #[test]
    fn reconcile_crd_not_found_message_requeues_with_30s() {
        let action = compute_expected_action(Err(kube_api_error(
            404,
            "the server could not find the requested resource",
        )));
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    #[test]
    fn reconcile_other_error_requeues_with_60s() {
        let action = compute_expected_action(Err(kube_api_error(503, "connection refused")));
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

    // =========================================================================
    // Egress LMM Construction Tests
    // =========================================================================

    #[test]
    fn eso_namespace_constant() {
        assert_eq!(ESO_NAMESPACE, "external-secrets");
    }

    /// Build a vault SecretProvider with a given server URL for testing.
    fn vault_secret_provider(name: &str, server: &str) -> SecretProvider {
        use lattice_crd::crd::SecretProviderSpec;

        let mut provider = serde_json::Map::new();
        provider.insert(
            "vault".to_string(),
            serde_json::json!({"server": server, "path": "secret"}),
        );
        let spec = SecretProviderSpec { provider };
        let mut sp = SecretProvider::new(name, spec);
        sp.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
        sp
    }

    #[test]
    fn egress_lmm_constructed_for_external_vault() {
        let sp = vault_secret_provider("vault-prod", "https://vault.example.com:8200");
        let endpoints = sp.spec.external_endpoints();

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].host, "vault.example.com");
        assert_eq!(endpoints[0].port, 8200);

        // Verify the LMM spec fields match what ensure_external_egress_lmm would build
        let lmm_name = format!("egress-sp-{}", sp.name_any());
        assert_eq!(lmm_name, "egress-sp-vault-prod");

        let egress_rules: Vec<EgressRule> = endpoints
            .iter()
            .map(|ep| EgressRule {
                target: EgressTarget::Fqdn(ep.host.clone()),
                ports: vec![ep.port],
                protocol: Default::default(),
            })
            .collect();

        assert_eq!(egress_rules.len(), 1);
        assert_eq!(
            egress_rules[0].target,
            EgressTarget::Fqdn("vault.example.com".to_string())
        );
        assert_eq!(egress_rules[0].ports, vec![8200]);
    }

    #[test]
    fn egress_lmm_not_needed_for_cluster_local_webhook() {
        use lattice_crd::crd::SecretProviderSpec;

        let mut provider = serde_json::Map::new();
        provider.insert(
            "webhook".to_string(),
            serde_json::json!({"url": "http://lattice-local-secrets.lattice-system.svc:8787/secret/{{ .remoteRef.key }}"}),
        );
        let spec = SecretProviderSpec { provider };
        assert!(spec.external_endpoints().is_empty());
    }
}
