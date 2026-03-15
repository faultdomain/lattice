//! Remote secret reconciler for Istio multi-cluster discovery.
//!
//! Creates Istio remote secrets that tell istiod to discover services on remote
//! clusters via the K8s API proxy. Each `LatticeClusterRoutes` CRD (one per
//! source cluster) gets a corresponding `istio-remote-secret-{cluster}` Secret
//! in `istio-system`.
//!
//! Tokens are requested per-reconcile via the TokenRequest API against a
//! dedicated `lattice-istiod-proxy` ServiceAccount with read-only RBAC.
//! Tokens expire after 1 hour; reconcile requeues at half that interval
//! to keep them fresh.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, info};

use lattice_common::crd::{validate_dns_label, LatticeClusterRoutes};
use lattice_common::Error;

const FIELD_MANAGER: &str = "lattice-remote-secret";
const ISTIO_MULTICLUSTER_LABEL: &str = "istio/multiCluster";
const MANAGED_LABEL: &str = "lattice.dev/remote-secret-managed";

/// ServiceAccount dedicated to istiod proxy access (read-only, scoped).
pub const PROXY_SA_NAME: &str = "lattice-istiod-proxy";
pub const PROXY_SA_NAMESPACE: &str = "istio-system";
const TOKEN_EXPIRATION_SECS: i64 = 3600;

/// Context for the remote secret reconciler.
pub struct RemoteSecretContext {
    pub client: Client,
    pub proxy_base_url: String,
    pub ca_cert_pem: String,
}

pub async fn reconcile(
    routes: Arc<LatticeClusterRoutes>,
    ctx: Arc<RemoteSecretContext>,
) -> Result<Action, Error> {
    let source_cluster = routes.name_any();
    debug!(source = %source_cluster, "reconciling remote secret");

    validate_dns_label(&source_cluster, "cluster name")
        .map_err(|e| Error::validation(format!("invalid LatticeClusterRoutes name: {e}")))?;

    if routes.spec.routes.is_empty() {
        cleanup_remote_secret(&ctx.client, &source_cluster).await;
        return Ok(Action::requeue(Duration::from_secs(300)));
    }

    let token = request_proxy_token(&ctx.client).await.map_err(|e| {
        Error::internal(format!("failed to request proxy token: {e}"))
    })?;

    let secret_name = format!("istio-remote-secret-{}", source_cluster);
    let kubeconfig = build_remote_kubeconfig(
        &source_cluster,
        &ctx.proxy_base_url,
        &ctx.ca_cert_pem,
        &token,
    );

    let mut labels = BTreeMap::new();
    labels.insert(ISTIO_MULTICLUSTER_LABEL.to_string(), "true".to_string());
    labels.insert(MANAGED_LABEL.to_string(), source_cluster.clone());

    let mut annotations = BTreeMap::new();
    annotations.insert(
        "networking.istio.io/cluster".to_string(),
        source_cluster.clone(),
    );

    let secret = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": secret_name,
            "namespace": "istio-system",
            "labels": labels,
            "annotations": annotations
        },
        "data": {
            source_cluster.clone(): base64_encode(&kubeconfig)
        }
    });

    let api: Api<Secret> = Api::namespaced(ctx.client.clone(), "istio-system");
    let params = PatchParams::apply(FIELD_MANAGER).force();
    api.patch(&secret_name, &params, &Patch::Apply(&secret))
        .await
        .map_err(|e| Error::internal(format!("failed to apply remote secret: {e}")))?;

    info!(
        secret = %secret_name,
        source_cluster = %source_cluster,
        routes = routes.spec.routes.len(),
        "ensured remote secret"
    );

    // Requeue at half the token lifetime to refresh before expiry
    Ok(Action::requeue(Duration::from_secs(TOKEN_EXPIRATION_SECS as u64 / 2)))
}

async fn request_proxy_token(client: &Client) -> Result<String, kube::Error> {
    use k8s_openapi::api::authentication::v1::TokenRequest;
    use k8s_openapi::api::core::v1::ServiceAccount;
    use kube::api::PostParams;

    let sa_api: Api<ServiceAccount> = Api::namespaced(client.clone(), PROXY_SA_NAMESPACE);

    let token_request = TokenRequest {
        spec: k8s_openapi::api::authentication::v1::TokenRequestSpec {
            // No custom audience — the proxy's SaValidator uses the default
            // API server audience for TokenReview validation.
            audiences: vec![],
            expiration_seconds: Some(TOKEN_EXPIRATION_SECS),
            ..Default::default()
        },
        ..Default::default()
    };

    let response = sa_api
        .create_token_request(PROXY_SA_NAME, &PostParams::default(), &token_request)
        .await?;

    let status = response.status.ok_or_else(|| {
        kube::Error::Api(kube::error::ErrorResponse {
            status: "Failure".to_string(),
            message: "TokenRequest response missing status".to_string(),
            reason: "MissingStatus".to_string(),
            code: 500,
        })
    })?;
    Ok(status.token)
}

/// Build kubeconfig as JSON (not string interpolation) to prevent injection.
fn build_remote_kubeconfig(
    cluster_name: &str,
    proxy_base_url: &str,
    ca_cert_pem: &str,
    token: &str,
) -> String {
    let ca_b64 = base64_encode(ca_cert_pem);
    let server = format!("{}/clusters/{}", proxy_base_url, cluster_name);

    serde_json::to_string(&serde_json::json!({
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": cluster_name, "cluster": {
            "server": server,
            "certificate-authority-data": ca_b64
        }}],
        "users": [{"name": cluster_name, "user": {"token": token}}],
        "contexts": [{"name": cluster_name, "context": {
            "cluster": cluster_name, "user": cluster_name
        }}],
        "current-context": cluster_name
    }))
    .expect("serialize kubeconfig")
}

async fn cleanup_remote_secret(client: &Client, source_cluster: &str) {
    let secret_name = format!("istio-remote-secret-{}", source_cluster);
    let api: Api<Secret> = Api::namespaced(client.clone(), "istio-system");
    match api.delete(&secret_name, &Default::default()).await {
        Ok(_) => info!(secret = %secret_name, "deleted remote secret"),
        Err(kube::Error::Api(e)) if e.code == 404 => {}
        Err(e) => tracing::warn!(secret = %secret_name, error = %e, "failed to delete remote secret"),
    }
}

fn base64_encode(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kubeconfig_is_safe_json() {
        let kc = build_remote_kubeconfig("workload-1", "https://x:8082", "cert", "tok");
        let parsed: serde_json::Value = serde_json::from_str(&kc).unwrap();
        assert_eq!(
            parsed["clusters"][0]["cluster"]["server"],
            "https://x:8082/clusters/workload-1"
        );
        assert_eq!(parsed["users"][0]["user"]["token"], "tok");
        assert_eq!(parsed["current-context"], "workload-1");
    }

    #[test]
    fn yaml_injection_rejected_by_dns_validation() {
        assert!(validate_dns_label("evil\"\nusers:", "test").is_err());
    }
}
