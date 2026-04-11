//! OIDCProvider validation controller
//!
//! Watches OIDCProvider CRDs and validates their OIDC discovery endpoint,
//! updating status fields (phase, jwks_uri, last_jwks_fetch, message).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, info, warn};

use lattice_common::{
    ControllerContext, ReconcileError, LABEL_MANAGED_BY, OPERATOR_NAME, REQUEUE_SUCCESS_SECS,
};
use lattice_core::LATTICE_SYSTEM_NAMESPACE;
use lattice_crd::crd::{
    EgressRule, EgressTarget, LatticeMeshMember, LatticeMeshMemberSpec, MeshMemberTarget,
    OIDCProvider, OIDCProviderPhase, OIDCProviderStatus, ParsedEndpoint,
};

/// Shorter retry interval for OIDC validation failures. The global REQUEUE_ERROR_SECS (60s) is
/// too slow here — validation typically fails on the first attempt because the egress mesh policy
/// hasn't propagated yet (takes ~5-15s). A 15s retry gives ~18 attempts within the 300s test
/// timeout instead of ~4.
const OIDC_REQUEUE_ERROR_SECS: u64 = 15;

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

fn requeue_for_phase(phase: &OIDCProviderPhase) -> Duration {
    let secs = if *phase == OIDCProviderPhase::Ready {
        REQUEUE_SUCCESS_SECS
    } else {
        OIDC_REQUEUE_ERROR_SECS
    };
    Duration::from_secs(secs)
}

/// Reconcile an OIDCProvider — validate connectivity and update status
pub async fn reconcile(
    provider: Arc<OIDCProvider>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ReconcileError> {
    let name = provider.name_any();
    let client = &ctx.client;

    info!(oidc_provider = %name, "Reconciling OIDCProvider");

    // Ensure egress policies BEFORE validation so the operator can reach the external issuer
    ensure_oidc_egress_lmm(client, &provider).await?;

    let new_status = validate_provider(&provider).await;

    // Check if status already matches — avoid update loop
    if let Some(ref current_status) = provider.status {
        if current_status.phase == new_status.phase
            && current_status.jwks_uri == new_status.jwks_uri
            && current_status.message == new_status.message
        {
            debug!(oidc_provider = %name, "Status unchanged, skipping update");
            return Ok(Action::requeue(requeue_for_phase(&new_status.phase)));
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
    .await?;

    info!(
        oidc_provider = %name,
        phase = ?new_status.phase,
        jwks_uri = ?new_status.jwks_uri,
        "OIDCProvider status updated"
    );

    Ok(Action::requeue(requeue_for_phase(&new_status.phase)))
}

const FIELD_MANAGER: &str = "lattice-oidc-provider-controller";

/// Ensure an egress LMM exists for an external OIDCProvider issuer URL.
///
/// When an OIDCProvider points to an external IdP (e.g., Keycloak at 172.18.0.11:8080),
/// the operator pods need mesh egress policies to reach it for discovery and JWKS fetch.
/// This creates a lightweight egress-only LatticeMeshMember targeting operator pods.
///
/// If the issuer is cluster-local, any existing egress LMM is deleted.
async fn ensure_oidc_egress_lmm(
    client: &Client,
    provider: &OIDCProvider,
) -> Result<(), ReconcileError> {
    let provider_name = provider.name_any();
    let lmm_name = format!("egress-oidc-{}", provider_name);

    let api: Api<LatticeMeshMember> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

    let endpoint =
        ParsedEndpoint::parse(&provider.spec.issuer_url).filter(|ep| !ep.is_cluster_local());

    let Some(ep) = endpoint else {
        // Cluster-local or unparseable — delete any existing LMM
        match api.delete(&lmm_name, &Default::default()).await {
            Ok(_) => {
                debug!(oidc_provider = %provider_name, "Deleted egress LMM (cluster-local issuer)");
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {}
            Err(e) => {
                warn!(oidc_provider = %provider_name, error = %e, "Failed to delete egress LMM");
            }
        }
        return Ok(());
    };

    let mut lmm = LatticeMeshMember::new(
        &lmm_name,
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                "app".to_string(),
                OPERATOR_NAME.to_string(),
            )])),
            ports: vec![],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![EgressRule::tcp(
                EgressTarget::for_host(&ep.host),
                vec![ep.port],
            )],
            allow_peer_traffic: false,
            depends_all: false,
            ingress: None,
            service_account: Some(OPERATOR_NAME.to_string()),
            ambient: true, advertise: None,
        },
    );
    lmm.metadata.namespace = Some(LATTICE_SYSTEM_NAMESPACE.to_string());
    lmm.metadata.labels = Some(BTreeMap::from([(
        LABEL_MANAGED_BY.to_string(),
        "oidc-provider-controller".to_string(),
    )]));

    let params = PatchParams::apply(FIELD_MANAGER).force();
    api.patch(&lmm_name, &params, &Patch::Apply(&lmm)).await?;

    info!(
        oidc_provider = %provider_name,
        lmm = %lmm_name,
        host = %ep.host,
        port = ep.port,
        "Ensured egress LMM for external OIDCProvider issuer"
    );
    Ok(())
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
    fn external_issuer_parsed_correctly() {
        let ep = ParsedEndpoint::parse("https://keycloak.example.com:8080").expect("should parse");
        assert_eq!(ep.host, "keycloak.example.com");
        assert_eq!(ep.port, 8080);
        assert!(!ep.is_cluster_local());
    }

    #[test]
    fn cluster_local_issuer_filtered() {
        let ep =
            ParsedEndpoint::parse("https://keycloak.auth-system.svc:8443").expect("should parse");
        assert!(ep.is_cluster_local());
    }
}
