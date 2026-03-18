//! PeerRouteSync command handler — creates LatticeClusterRoutes for sibling clusters
//!
//! When the parent pushes sibling routes, this handler:
//! 1. Stores the proxy credentials in a Secret (for the remote secret controller)
//! 2. Creates/updates LatticeClusterRoutes CRDs for each sibling cluster

use std::collections::{BTreeMap, HashMap};

use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use tracing::{debug, error, info, warn};

use lattice_common::crd::{ClusterRoute, LatticeClusterRoutes};
use lattice_common::PEER_ROUTES_LABEL;
use lattice_proto::PeerRouteSync;

use super::CommandContext;

/// Secret name for storing parent proxy credentials on the child
const PROXY_CREDENTIALS_SECRET: &str = "lattice-peer-proxy-credentials";
/// Namespace for proxy credentials
const CREDENTIALS_NAMESPACE: &str = "lattice-system";

/// Compute a deterministic hash from the per-cluster route hashes.
///
/// The `BTreeMap` ensures consistent ordering. Each entry's key (cluster name)
/// and value (route content hash) are fed into SHA-256.
fn hash_peer_state(per_cluster: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut buf = Vec::new();
    for (name, route_hash) in per_cluster {
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(route_hash);
    }
    lattice_common::kube_utils::sha256(&buf)
}

/// Hash the content of a set of routes for one cluster.
fn hash_routes(routes: &[ClusterRoute]) -> Vec<u8> {
    let mut sorted: Vec<_> = routes.iter().collect();
    sorted.sort_by(|a, b| {
        (&a.service_namespace, &a.service_name).cmp(&(&b.service_namespace, &b.service_name))
    });
    let mut buf = Vec::new();
    for r in sorted {
        buf.extend_from_slice(r.service_name.as_bytes());
        buf.extend_from_slice(r.service_namespace.as_bytes());
        buf.extend_from_slice(r.hostname.as_bytes());
        buf.extend_from_slice(r.address.as_bytes());
        buf.extend_from_slice(&r.port.to_le_bytes());
        buf.extend_from_slice(r.protocol.as_bytes());
        for allowed in &r.allowed_services {
            buf.extend_from_slice(allowed.as_bytes());
        }
        // BTreeMap iteration is sorted by key
        for (name, port) in &r.service_ports {
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(&port.to_le_bytes());
        }
    }
    lattice_common::kube_utils::sha256(&buf)
}

/// Compute the initial peer routes hash from existing peer-labeled CRDs.
///
/// Called once at agent startup to seed the hash before any PeerRouteSync arrives.
pub async fn compute_initial_hash(client: &Client) -> Vec<u8> {
    let api: Api<LatticeClusterRoutes> = Api::all(client.clone());
    let list = match api.list(&Default::default()).await {
        Ok(l) => l,
        Err(_) => return vec![],
    };

    let mut per_cluster = BTreeMap::new();
    for cr in list.items {
        let is_peer = cr
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(PEER_ROUTES_LABEL))
            .is_some_and(|v| v == "true");
        if !is_peer {
            continue;
        }
        let name = cr.metadata.name.as_deref().unwrap_or_default().to_string();
        per_cluster.insert(name, hash_routes(&cr.spec.routes));
    }

    hash_peer_state(&per_cluster)
}

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

    // Group peer routes by source cluster, validating names to prevent injection
    let mut by_cluster: HashMap<String, Vec<ClusterRoute>> = HashMap::new();
    for svc in &sync.peer_routes {
        if let Err(e) = lattice_common::crd::validate_dns_label(&svc.cluster, "cluster") {
            warn!(error = %e, "Skipping peer route with invalid cluster name");
            continue;
        }
        if let Err(e) = lattice_common::crd::validate_dns_label(&svc.name, "service name") {
            warn!(error = %e, "Skipping peer route with invalid service name");
            continue;
        }
        // Namespace can contain dots (e.g., kube-system) but must be valid K8s name
        if svc.namespace.is_empty() || svc.namespace.len() > 253 {
            warn!(namespace = %svc.namespace, "Skipping peer route with invalid namespace");
            continue;
        }
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
                service_ports: svc.service_ports.iter()
                    .filter(|(_, &v)| v > 0 && v <= u16::MAX as u32)
                    .map(|(k, &v)| (k.clone(), v as u16))
                    .collect(),
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
                    .and_then(|l| l.get(PEER_ROUTES_LABEL))
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

    // Update the peer routes hash
    let mut per_cluster: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (name, routes) in &by_cluster {
        per_cluster.insert(name.clone(), hash_routes(routes));
    }
    let _ = ctx.peer_routes_hash_tx.send(hash_peer_state(&per_cluster));
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
