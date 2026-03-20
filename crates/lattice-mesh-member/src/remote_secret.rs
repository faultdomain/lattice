//! Remote secret reconciler for Istio multi-cluster discovery.
//!
//! Creates Istio remote secrets so istiod can discover services on remote
//! clusters. Local child clusters use a direct API server kubeconfig (copied
//! pre-pivot). Peer clusters (from parent) use the parent's auth proxy.
//!
//! Also creates headless Service stubs on the local cluster for each advertised
//! route so CoreDNS can resolve the remote service's DNS name. Istiod matches
//! these stubs to remote endpoints discovered via the remote secret.
//!
//! Updates the `meshNetworks` field in the `istio` ConfigMap so istiod knows
//! how to reach endpoints on each remote network via the east-west gateway.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use tracing::{debug, error, info, warn};

use lattice_common::crd::{validate_dns_label, ClusterRoute, LatticeClusterRoutes};
use lattice_common::Error;

const FIELD_MANAGER: &str = "lattice-remote-secret";
const ISTIO_MULTICLUSTER_LABEL: &str = "istio/multiCluster";
const MANAGED_LABEL: &str = "lattice.dev/remote-secret-managed";

/// Label on Service stubs so we can track and clean them up.
const SERVICE_STUB_LABEL: &str = "lattice.dev/service-stub";

/// Context for the remote secret reconciler.
pub struct RemoteSecretContext {
    pub client: Client,
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
        cleanup_mesh_network(&ctx.client, &source_cluster).await;
        return Ok(Action::requeue(Duration::from_secs(300)));
    }

    // Determine kubeconfig source: peer routes (from parent) use parent's proxy,
    // local child routes use the direct API server kubeconfig copied pre-pivot.
    let is_peer = routes
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(lattice_common::PEER_ROUTES_LABEL))
        .is_some_and(|v| v == "true");

    let secret_name = format!("istio-remote-secret-{}", source_cluster);
    let kubeconfig = if is_peer {
        let (proxy_url, ca_cert, token) = load_peer_proxy_credentials(&ctx.client).await?;
        build_remote_kubeconfig(&source_cluster, &proxy_url, &ca_cert, &token)
    } else {
        load_direct_kubeconfig(&ctx.client, &source_cluster).await?
    };

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

    // Update meshNetworks so istiod knows how to route to this remote network
    ensure_mesh_network(&ctx.client, &source_cluster).await;

    // Ensure Service stubs for DNS resolution on this cluster
    ensure_service_stubs(&ctx.client, &source_cluster, &routes.spec.routes).await;

    info!(
        secret = %secret_name,
        source_cluster = %source_cluster,
        routes = routes.spec.routes.len(),
        "ensured remote secret, mesh network, and service stubs"
    );

    // Requeue periodically to recreate any deleted service stubs and
    // refresh peer proxy tokens (24h lifetime).
    Ok(Action::requeue(Duration::from_secs(3600)))
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
                    "app.kubernetes.io/managed-by": "lattice",
                    "istio.io/dataplane-mode": "ambient"
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
        // Build port list from service_ports if available, otherwise fall
        // back to the gateway port. Istiod requires stub ports to match the
        // real service ports for endpoint merging.
        let ports: Vec<serde_json::Value> = if route.service_ports.is_empty() {
            vec![serde_json::json!({"port": route.port, "protocol": "TCP", "name": "tcp"})]
        } else {
            route.service_ports.iter().map(|(name, &port)| {
                serde_json::json!({"port": port, "protocol": "TCP", "name": name})
            }).collect()
        };

        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "name": route.service_name,
                "namespace": route.service_namespace,
                "labels": {
                    SERVICE_STUB_LABEL: source_cluster,
                    "app.kubernetes.io/managed-by": "lattice",
                    "istio.io/global": "true"
                }
            },
            "spec": {
                "ports": ports
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

/// Load the direct API server kubeconfig for a child cluster.
///
/// Reads the `istiod-direct-kubeconfig-{cluster}` secret from istio-system,
/// copied from the CAPI kubeconfig pre-pivot by the cluster controller.
async fn load_direct_kubeconfig(client: &Client, cluster_name: &str) -> Result<String, Error> {
    let secret_name = format!("istiod-direct-kubeconfig-{}", cluster_name);
    let api: Api<Secret> = Api::namespaced(client.clone(), "istio-system");

    let secret = api.get(&secret_name).await.map_err(|e| {
        Error::internal(format!(
            "direct kubeconfig secret '{}' not found in istio-system \
             (copied pre-pivot by cluster controller): {e}",
            secret_name
        ))
    })?;

    let data = secret.data.as_ref().ok_or_else(|| {
        Error::internal(format!(
            "direct kubeconfig secret '{}' has no data",
            secret_name
        ))
    })?;

    let kc_bytes = data.get("kubeconfig").ok_or_else(|| {
        Error::internal(format!(
            "direct kubeconfig secret '{}' missing 'kubeconfig' key",
            secret_name
        ))
    })?;

    String::from_utf8(kc_bytes.0.clone())
        .map_err(|e| Error::internal(format!("direct kubeconfig is not valid UTF-8: {e}")))
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

/// Read-modify-write the `meshNetworks` field in the `istio` ConfigMap.
///
/// Uses optimistic concurrency (resourceVersion). On 409 Conflict,
/// the next reconcile will retry. The `modify` closure receives the
/// parsed networks document and returns whether a write is needed.
async fn update_mesh_networks(
    client: &Client,
    operation: &str,
    modify: impl FnOnce(&mut serde_json::Value) -> bool,
) {
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), "istio-system");

    let cm = match cm_api.get("istio").await {
        Ok(cm) => cm,
        Err(e) => {
            error!(error = %e, "failed to read istio ConfigMap for meshNetworks {}", operation);
            return;
        }
    };

    let resource_version = cm
        .metadata
        .resource_version
        .as_deref()
        .unwrap_or_default()
        .to_string();

    let data = cm.data.unwrap_or_default();
    let current_str = data
        .get("meshNetworks")
        .cloned()
        .unwrap_or_else(|| r#"{"networks":{}}"#.to_string());

    let mut doc: serde_json::Value =
        serde_json::from_str(&current_str).unwrap_or_else(|_| serde_json::json!({"networks": {}}));

    if !modify(&mut doc) {
        return; // no change needed
    }

    let updated_str = serde_json::to_string(&doc).expect("serialize meshNetworks");
    let mut updated_data = data.clone();
    updated_data.insert("meshNetworks".to_string(), updated_str);

    let patch = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "istio",
            "namespace": "istio-system",
            "resourceVersion": resource_version
        },
        "data": updated_data
    });

    match cm_api
        .replace(
            "istio",
            &Default::default(),
            &serde_json::from_value(patch).expect("valid ConfigMap"),
        )
        .await
    {
        Ok(_) => info!("meshNetworks {operation} succeeded"),
        Err(kube::Error::Api(e)) if e.code == 409 => {
            warn!("meshNetworks {operation} conflict, will retry on next reconcile");
        }
        Err(e) => error!(error = %e, "failed to {operation} meshNetworks"),
    }
}

/// Add a remote cluster's network entry to meshNetworks.
async fn ensure_mesh_network(client: &Client, source_cluster: &str) {
    let cluster = source_cluster.to_string();
    update_mesh_networks(client, &format!("add {cluster}"), |doc| {
        let entry = serde_json::json!({
            "endpoints": [{"fromRegistry": &cluster}],
            "gateways": [{
                "registryServiceName": "istio-eastwestgateway.istio-system",
                "port": 15008
            }]
        });
        if doc["networks"].get(&cluster) == Some(&entry) {
            return false; // already up to date
        }
        doc["networks"][&cluster] = entry;
        true
    })
    .await;
}

/// Remove a remote cluster's network entry from meshNetworks.
async fn cleanup_mesh_network(client: &Client, source_cluster: &str) {
    let cluster = source_cluster.to_string();
    update_mesh_networks(client, &format!("remove {cluster}"), |doc| {
        doc["networks"]
            .as_object_mut()
            .map(|obj| obj.remove(&cluster).is_some())
            .unwrap_or(false)
    })
    .await;
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
