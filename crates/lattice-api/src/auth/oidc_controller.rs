//! OIDCProvider validation controller
//!
//! Watches OIDCProvider CRDs and validates their OIDC discovery endpoint,
//! updating status fields (phase, jwks_uri, last_jwks_fetch, message).

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::ResourceExt;
use tracing::{debug, info, warn};

use lattice_common::crd::{OIDCProvider, OIDCProviderPhase, OIDCProviderStatus};
use lattice_common::{ControllerContext, ReconcileError, LATTICE_SYSTEM_NAMESPACE};

/// Requeue interval for successful reconciliation
const REQUEUE_SUCCESS_SECS: u64 = 300;
/// Requeue interval on error
const REQUEUE_ERROR_SECS: u64 = 60;

/// OIDC discovery document (subset of fields we need)
#[derive(Debug, serde::Deserialize)]
struct OidcDiscovery {
    issuer: String,
    jwks_uri: String,
}

/// JWKS document
#[derive(Debug, serde::Deserialize)]
struct JwksDocument {
    keys: Vec<serde_json::Value>,
}

/// Reconcile an OIDCProvider — validate connectivity and update status
pub async fn reconcile(
    provider: Arc<OIDCProvider>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = provider.name_any();
    let client = &ctx.client;

    info!(oidc_provider = %name, "Reconciling OIDCProvider");

    let new_status = validate_provider(&provider).await;

    // Check if status already matches — avoid update loop
    if let Some(ref current_status) = provider.status {
        if current_status.phase == new_status.phase
            && current_status.jwks_uri == new_status.jwks_uri
            && current_status.message == new_status.message
        {
            debug!(oidc_provider = %name, "Status unchanged, skipping update");
            return Ok(Action::requeue(Duration::from_secs(REQUEUE_SUCCESS_SECS)));
        }
    }

    // Update status
    let namespace = provider
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

    let patch = serde_json::json!({
        "status": new_status
    });

    let api: Api<OIDCProvider> = Api::namespaced(client.clone(), &namespace);
    api.patch_status(
        &name,
        &PatchParams::apply("lattice-oidc-validation"),
        &Patch::Merge(&patch),
    )
    .await
    .map_err(|e| ReconcileError::Kube(format!("failed to update OIDCProvider status: {e}")))?;

    let requeue = if new_status.phase == OIDCProviderPhase::Ready {
        REQUEUE_SUCCESS_SECS
    } else {
        REQUEUE_ERROR_SECS
    };

    info!(
        oidc_provider = %name,
        phase = ?new_status.phase,
        jwks_uri = ?new_status.jwks_uri,
        "OIDCProvider status updated"
    );

    Ok(Action::requeue(Duration::from_secs(requeue)))
}

/// Validate an OIDCProvider by fetching discovery document and JWKS
async fn validate_provider(provider: &OIDCProvider) -> OIDCProviderStatus {
    match try_validate_provider(provider).await {
        Ok(status) => status,
        Err(message) => OIDCProviderStatus {
            phase: OIDCProviderPhase::Failed,
            message: Some(message),
            last_jwks_fetch: None,
            jwks_uri: None,
        },
    }
}

/// Inner validation that uses Result for clean error propagation
async fn try_validate_provider(provider: &OIDCProvider) -> Result<OIDCProviderStatus, String> {
    let now = chrono::Utc::now().to_rfc3339();
    let issuer_url = &provider.spec.issuer_url;

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // Fetch OIDC discovery document
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/')
    );

    let discovery: OidcDiscovery = http_client
        .get(&discovery_url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch discovery: {}", e))?
        .json()
        .await
        .map_err(|e| format!("Invalid discovery response: {}", e))?;

    // Verify issuer matches
    if discovery.issuer != *issuer_url {
        return Err(format!(
            "Issuer mismatch: expected {}, got {}",
            issuer_url, discovery.issuer
        ));
    }

    // Fetch JWKS
    let jwks: JwksDocument = http_client
        .get(&discovery.jwks_uri)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch JWKS: {}", e))?
        .json()
        .await
        .map_err(|e| format!("Invalid JWKS response: {}", e))?;

    let key_count = jwks.keys.len();
    if key_count == 0 {
        warn!(issuer = %issuer_url, "JWKS contains no keys");
    }

    Ok(OIDCProviderStatus {
        phase: OIDCProviderPhase::Ready,
        message: Some(format!("Discovery OK, {} key(s) in JWKS", key_count)),
        last_jwks_fetch: Some(now),
        jwks_uri: Some(discovery.jwks_uri),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requeue_constants() {
        assert_eq!(REQUEUE_SUCCESS_SECS, 300);
        assert_eq!(REQUEUE_ERROR_SECS, 60);
    }
}
