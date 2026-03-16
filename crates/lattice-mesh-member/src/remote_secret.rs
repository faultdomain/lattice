//! Remote secret reconciler for Istio multi-cluster discovery.
//!
//! Creates Istio remote secrets that tell istiod to discover services on remote
//! clusters via the K8s API proxy. Each `LatticeClusterRoutes` CRD (one per
//! source cluster) gets a corresponding `istio-remote-secret-{cluster}` Secret
//! in `istio-system`.
//!
//! Also creates headless Service stubs on the local cluster for each advertised
//! route so CoreDNS can resolve the remote service's DNS name. Istiod matches
//! these stubs to remote endpoints discovered via the remote secret.
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
use tracing::{debug, info, warn};

use lattice_common::crd::{validate_dns_label, ClusterRoute, LatticeClusterRoutes};
use lattice_common::Error;

const FIELD_MANAGER: &str = "lattice-remote-secret";
const ISTIO_MULTICLUSTER_LABEL: &str = "istio/multiCluster";
const MANAGED_LABEL: &str = "lattice.dev/remote-secret-managed";

/// Label on Service stubs so we can track and clean them up.
const SERVICE_STUB_LABEL: &str = "lattice.dev/service-stub";

/// ServiceAccount dedicated to istiod proxy access (read-only, scoped).
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
        cleanup_service_stubs(&ctx.client, &source_cluster).await;
        return Ok(Action::requeue(Duration::from_secs(300)));
    }

    // Determine proxy credentials: peer routes (from parent) use parent's proxy,
    // local child routes use this cluster's own proxy.
    let is_peer = routes
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(lattice_common::PEER_ROUTES_LABEL))
        .is_some_and(|v| v == "true");

    let (proxy_url, ca_cert, token) = if is_peer {
        load_peer_proxy_credentials(&ctx.client).await?
    } else {
        let token = request_proxy_token(&ctx.client)
            .await
            .map_err(|e| Error::internal(format!("failed to request proxy token: {e}")))?;
        (ctx.proxy_base_url.clone(), ctx.ca_cert_pem.clone(), token)
    };

    // 1. Ensure remote secret for istiod endpoint discovery
    let secret_name = format!("istio-remote-secret-{}", source_cluster);
    let kubeconfig = build_remote_kubeconfig(&source_cluster, &proxy_url, &ca_cert, &token);

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

    // 2. Ensure Service stubs for DNS resolution on this cluster
    ensure_service_stubs(&ctx.client, &source_cluster, &routes.spec.routes).await;

    info!(
        secret = %secret_name,
        source_cluster = %source_cluster,
        routes = routes.spec.routes.len(),
        "ensured remote secret and service stubs"
    );

    // Requeue at half the token lifetime to refresh before expiry
    Ok(Action::requeue(Duration::from_secs(
        TOKEN_EXPIRATION_SECS as u64 / 2,
    )))
}

/// Create headless Service stubs so CoreDNS resolves remote service names.
///
/// For each advertised route, creates the target namespace (if needed) and a
/// headless Service (ClusterIP: None, no selector) so that
/// `{name}.{namespace}.svc.cluster.local` resolves. Istiod matches the Service
/// to remote endpoints discovered via the remote secret.
async fn ensure_service_stubs(client: &Client, source_cluster: &str, routes: &[ClusterRoute]) {
    let params = PatchParams::apply(FIELD_MANAGER).force();

    for route in routes {
        // Ensure namespace exists
        let ns = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": route.service_namespace,
                "labels": {
                    "app.kubernetes.io/managed-by": "lattice"
                }
            }
        });
        let ns_api = Api::<k8s_openapi::api::core::v1::Namespace>::all(client.clone());
        if let Err(e) = ns_api
            .patch(&route.service_namespace, &params, &Patch::Apply(&ns))
            .await
        {
            warn!(
                namespace = %route.service_namespace,
                error = %e,
                "failed to ensure namespace for service stub"
            );
            continue;
        }

        // Create Service stub (no selector, no endpoints) with a ClusterIP
        // so DNS resolves the service name. Headless services (clusterIP: None)
        // don't get DNS A records, which breaks cross-cluster routing.
        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": route.service_name,
                "namespace": route.service_namespace,
                "labels": {
                    SERVICE_STUB_LABEL: source_cluster,
                    "app.kubernetes.io/managed-by": "lattice"
                }
            },
            "spec": {
                "ports": [{
                    "port": route.port,
                    "protocol": "TCP",
                    "name": "tcp"
                }]
            }
        });

        let svc_api = Api::<k8s_openapi::api::core::v1::Service>::namespaced(
            client.clone(),
            &route.service_namespace,
        );
        if let Err(e) = svc_api
            .patch(&route.service_name, &params, &Patch::Apply(&svc))
            .await
        {
            warn!(
                service = %route.service_name,
                namespace = %route.service_namespace,
                error = %e,
                "failed to ensure service stub"
            );
        } else {
            debug!(
                service = %route.service_name,
                namespace = %route.service_namespace,
                source = %source_cluster,
                "ensured service stub for cross-cluster DNS"
            );
        }
    }
}

/// Clean up Service stubs for a cluster that no longer has routes.
async fn cleanup_service_stubs(client: &Client, source_cluster: &str) {
    let label_selector = format!("{}={}", SERVICE_STUB_LABEL, source_cluster);
    let svc_api = Api::<k8s_openapi::api::core::v1::Service>::all(client.clone());
    let list = match svc_api
        .list(&kube::api::ListParams::default().labels(&label_selector))
        .await
    {
        Ok(list) => list,
        Err(e) => {
            warn!(error = %e, "failed to list service stubs for cleanup");
            return;
        }
    };

    for svc in list {
        let name = svc.metadata.name.as_deref().unwrap_or_default();
        let ns = svc.metadata.namespace.as_deref().unwrap_or_default();
        let ns_api = Api::<k8s_openapi::api::core::v1::Service>::namespaced(client.clone(), ns);
        match ns_api.delete(name, &Default::default()).await {
            Ok(_) => info!(service = %name, namespace = %ns, "deleted service stub"),
            Err(kube::Error::Api(e)) if e.code == 404 => {}
            Err(e) => warn!(service = %name, error = %e, "failed to delete service stub"),
        }
    }
}

async fn request_proxy_token(client: &Client) -> Result<String, kube::Error> {
    lattice_common::kube_utils::request_istiod_proxy_token(client).await
}

/// Load peer proxy credentials stored by the agent's PeerRouteSync handler.
///
/// Returns (proxy_url, ca_cert_pem, proxy_token) from the Secret written by
/// the agent when it receives peer routes from the parent.
async fn load_peer_proxy_credentials(client: &Client) -> Result<(String, String, String), Error> {
    use lattice_common::LATTICE_SYSTEM_NAMESPACE;

    let secrets: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let secret = secrets
        .get("lattice-peer-proxy-credentials")
        .await
        .map_err(|e| {
            Error::internal(format!(
                "peer proxy credentials not found (parent may not have sent PeerRouteSync yet): {e}"
            ))
        })?;

    let data = secret
        .data
        .ok_or_else(|| Error::internal("peer proxy credentials secret has no data".to_string()))?;

    let get_field = |key: &str| -> Result<String, Error> {
        let bytes = data
            .get(key)
            .ok_or_else(|| Error::internal(format!("missing '{key}' in peer proxy credentials")))?;
        String::from_utf8(bytes.0.clone())
            .map_err(|e| Error::internal(format!("invalid UTF-8 in '{key}': {e}")))
    };

    Ok((
        get_field("proxy_url")?,
        get_field("ca_cert_pem")?,
        get_field("proxy_token")?,
    ))
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
        Err(e) => {
            warn!(secret = %secret_name, error = %e, "failed to delete remote secret")
        }
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
