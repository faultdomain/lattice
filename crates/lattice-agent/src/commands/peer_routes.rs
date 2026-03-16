//! PeerRouteSync command handler — creates LatticeClusterRoutes for sibling clusters
//!
//! When the parent pushes sibling routes, this handler:
//! 1. Stores the proxy credentials in a Secret (for the remote secret controller)
//! 2. Creates/updates LatticeClusterRoutes CRDs for each sibling cluster

use std::collections::HashMap;

use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use tracing::{debug, error, info};

use lattice_common::crd::{ClusterRoute, LatticeClusterRoutes};
use lattice_proto::PeerRouteSync;

use super::CommandContext;

/// Secret name for storing parent proxy credentials on the child
const PROXY_CREDENTIALS_SECRET: &str = "lattice-peer-proxy-credentials";
/// Namespace for proxy credentials
const CREDENTIALS_NAMESPACE: &str = "lattice-system";
use lattice_common::PEER_ROUTES_LABEL;

/// Handle a PeerRouteSync command from the parent.
pub async fn handle(sync: &PeerRouteSync, ctx: &CommandContext) {
    let client = match ctx.kube_provider.create().await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Failed to create K8s client for peer route sync");
            return;
        }
    };

    // Store proxy credentials for the remote secret controller
    if let Err(e) = store_proxy_credentials(
        &client,
        &sync.proxy_url,
        &sync.ca_cert_pem,
        &sync.proxy_token,
    )
    .await
    {
        error!(error = %e, "Failed to store peer proxy credentials");
        return;
    }

    // Group peer routes by source cluster
    let mut by_cluster: HashMap<String, Vec<ClusterRoute>> = HashMap::new();
    for svc in &sync.peer_routes {
        by_cluster
            .entry(svc.cluster.clone())
            .or_default()
            .push(ClusterRoute {
                service_name: svc.name.clone(),
                service_namespace: svc.namespace.clone(),
                hostname: svc.hostname.clone(),
                address: svc.address.clone(),
                port: svc.port as u16,
                protocol: svc.protocol.clone(),
                allowed_services: svc.allowed_services.clone(),
            });
    }

    info!(
        peer_clusters = by_cluster.len(),
        total_routes = sync.peer_routes.len(),
        "Processing peer route sync"
    );

    // Create/update LatticeClusterRoutes for each sibling
    let api: Api<LatticeClusterRoutes> = Api::all(client.clone());
    let params = PatchParams::apply("lattice-agent-peer").force();

    for (cluster_name, routes) in &by_cluster {
        let cr = serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeClusterRoutes",
            "metadata": {
                "name": cluster_name,
                "labels": {
                    PEER_ROUTES_LABEL: "true",
                    "app.kubernetes.io/managed-by": "lattice"
                }
            },
            "spec": {
                "clusterName": cluster_name,
                "routes": routes
            }
        });

        if let Err(e) = api.patch(cluster_name, &params, &Patch::Apply(&cr)).await {
            error!(
                cluster = %cluster_name,
                error = %e,
                "Failed to create LatticeClusterRoutes for sibling"
            );
        } else {
            debug!(
                cluster = %cluster_name,
                routes = routes.len(),
                "Created/updated peer LatticeClusterRoutes"
            );
        }
    }

    // If full sync, remove LatticeClusterRoutes for siblings no longer present
    if sync.is_full_sync {
        if let Ok(list) = api.list(&Default::default()).await {
            for cr in list.items {
                let name = cr.metadata.name.as_deref().unwrap_or_default();
                let is_peer = cr
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|l: &std::collections::BTreeMap<String, String>| {
                        l.get(PEER_ROUTES_LABEL)
                    })
                    .is_some_and(|v| v == "true");

                if is_peer && !by_cluster.contains_key(name) {
                    debug!(cluster = %name, "Removing stale peer LatticeClusterRoutes");
                    if let Err(e) = api.delete(name, &Default::default()).await {
                        error!(cluster = %name, error = %e, "Failed to delete stale peer routes");
                    }
                }
            }
        }
    }
}

/// Store the parent's proxy credentials in a Secret for the remote secret controller.
async fn store_proxy_credentials(
    client: &Client,
    proxy_url: &str,
    ca_cert_pem: &str,
    proxy_token: &str,
) -> Result<(), kube::Error> {
    use k8s_openapi::api::core::v1::Secret;

    let secrets: Api<Secret> = Api::namespaced(client.clone(), CREDENTIALS_NAMESPACE);
    let secret = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": PROXY_CREDENTIALS_SECRET,
            "namespace": CREDENTIALS_NAMESPACE,
            "labels": {
                "app.kubernetes.io/managed-by": "lattice"
            }
        },
        "stringData": {
            "proxy_url": proxy_url,
            "ca_cert_pem": ca_cert_pem,
            "proxy_token": proxy_token
        }
    });

    secrets
        .patch(
            PROXY_CREDENTIALS_SECRET,
            &PatchParams::apply("lattice-agent-peer").force(),
            &Patch::Apply(&secret),
        )
        .await?;

    debug!("Stored peer proxy credentials");
    Ok(())
}
