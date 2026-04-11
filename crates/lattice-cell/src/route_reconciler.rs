//! Cluster route reconciler — single writer for LatticeClusterRoutes CRDs
//!
//! Every cluster runs this reconciler. It merges two sources into a single
//! `LatticeClusterRoutes` CRD named after the cluster:
//!
//! - **Local services**: LatticeServices with `advertise: true` on ingress routes
//! - **Child routes**: received via channel from agent heartbeats (parent clusters only)
//!
//! The resulting CRD is the union of own + descendants. The agent reads this CRD
//! and heartbeats its contents to the parent, propagating routes up the hierarchy.

use std::collections::HashMap;

use futures::StreamExt;
use kube::api::{Api, DynamicObject, GroupVersionKind, Patch, PatchParams};
use kube::discovery::ApiResource;
use kube::runtime::watcher::{self, Event};
use kube::Client;
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use lattice_common::watcher::resilient_watcher;

use lattice_crd::crd::{
    ClusterRoute, LatticeClusterRoutes, LatticeClusterRoutesSpec, LatticeService,
};

/// A route update received from a child agent heartbeat
pub struct RouteUpdate {
    /// Child cluster name
    pub cluster_name: String,
    /// Routes advertised by the child (full replacement for that child)
    pub routes: Vec<ClusterRoute>,
}

/// Channel sender for child route updates
pub type RouteUpdateSender = mpsc::Sender<RouteUpdate>;

/// Configuration for the route reconciler
pub struct RouteReconcilerConfig {
    /// This cluster's name
    pub cluster_name: String,
    /// Kubernetes client
    pub client: Client,
    /// Channel for receiving child route updates (None on leaf clusters)
    pub child_routes_rx: mpsc::Receiver<RouteUpdate>,
    /// Watch sender for combined route state (local + children)
    pub all_routes_tx: AllRoutesSender,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayStatus {
    #[serde(default)]
    addresses: Vec<GatewayAddress>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayAddress {
    #[serde(default)]
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewaySpec {
    #[serde(default)]
    gateway_class_name: String,
    #[serde(default)]
    listeners: Vec<GatewayListener>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayListener {
    #[serde(default)]
    port: u16,
}

/// A route tagged with its source cluster name.
pub type TaggedRoute = (String, ClusterRoute);

/// Watch channel for the combined route state (local + all children).
/// Each route is tagged with the cluster name it belongs to.
/// Updated whenever any route changes. Read by the peer route broadcaster.
pub type AllRoutesSender = tokio::sync::watch::Sender<Vec<TaggedRoute>>;
pub type AllRoutesReceiver = tokio::sync::watch::Receiver<Vec<TaggedRoute>>;

/// Spawn the route reconciler task.
///
/// Returns (child_route_sender, all_routes_receiver).
/// The all_routes_receiver publishes the union of local + child routes
/// whenever either changes.
pub fn spawn_route_reconciler(
    cluster_name: String,
    client: Client,
) -> (RouteUpdateSender, AllRoutesReceiver) {
    let (tx, rx) = mpsc::channel::<RouteUpdate>(256);
    let (all_tx, all_rx) = tokio::sync::watch::channel(Vec::new());
    let config = RouteReconcilerConfig {
        cluster_name,
        client,
        child_routes_rx: rx,
        all_routes_tx: all_tx,
    };
    tokio::spawn(run_route_reconciler(config));
    (tx, all_rx)
}

/// Run the route reconciler loop.
///
/// Watches local LatticeServices for advertised routes and merges with
/// child routes from the channel. Writes the union to the local
/// `LatticeClusterRoutes` CRD.
async fn run_route_reconciler(config: RouteReconcilerConfig) {
    let cluster_name = config.cluster_name;
    let client = config.client;
    let mut child_rx = config.child_routes_rx;
    let all_routes_tx = config.all_routes_tx;

    let api: Api<LatticeClusterRoutes> = Api::all(client.clone());

    // Child routes keyed by child cluster name
    let mut child_routes: HashMap<String, Vec<ClusterRoute>> = HashMap::new();
    // Last written state to skip no-op writes
    let mut last_written_local: Vec<ClusterRoute> = Vec::new();
    let mut last_written_children: HashMap<String, Vec<ClusterRoute>> = HashMap::new();

    info!(cluster = %cluster_name, "Route reconciler started");

    // Seed local routes on startup so peer route sync has data immediately
    let mut local_routes = discover_local_routes(&client).await;
    if !local_routes.is_empty() {
        let tagged: Vec<TaggedRoute> = local_routes
            .iter()
            .map(|r| (cluster_name.clone(), r.clone()))
            .collect();
        let _ = all_routes_tx.send(tagged);
    }

    let svc_api: Api<LatticeService> = Api::all(client.clone());
    let mut svc_stream = std::pin::pin!(resilient_watcher(svc_api, watcher::Config::default()));

    loop {
        let mut should_reconcile = false;

        tokio::select! {
            Some(event) = svc_stream.next() => {
                if matches!(event, Event::Apply(_) | Event::Delete(_) | Event::InitDone) {
                    local_routes = discover_local_routes(&client).await;
                    should_reconcile = true;
                }
            }
            // Child route updates from heartbeats
            update = child_rx.recv() => {
                match update {
                    Some(update) => {
                        debug!(
                            cluster = %cluster_name,
                            child = %update.cluster_name,
                            routes = update.routes.len(),
                            "received child route update"
                        );
                        if update.routes.is_empty() {
                            // Ignore empty updates — the child's watcher may be
                            // restarting. Keep the last known good routes until
                            // the child sends real data again.
                            debug!(
                                child = %update.cluster_name,
                                "ignoring empty route update, keeping last known routes"
                            );
                        } else {
                            child_routes.insert(update.cluster_name, update.routes);
                            should_reconcile = true;
                        }
                    }
                    None => {
                        // Channel closed — no more child updates (leaf cluster or shutdown)
                        debug!(cluster = %cluster_name, "child route channel closed");
                        break;
                    }
                }
            }
        }

        if !should_reconcile {
            continue;
        }

        let mut any_changed = false;

        // Write local routes to self-named CRD only (no merging)
        if local_routes != last_written_local
            && write_cluster_routes(&api, &cluster_name, &local_routes)
                .await
                .is_ok()
        {
            last_written_local = local_routes.clone();
            any_changed = true;
        }

        // Write each child's routes to a per-child CRD
        for (child_name, routes) in &child_routes {
            let prev = last_written_children.get(child_name);
            if prev
                .map(|p: &Vec<ClusterRoute>| p == routes)
                .unwrap_or(false)
            {
                continue;
            }
            if write_cluster_routes(&api, child_name, routes).await.is_ok() {
                last_written_children.insert(child_name.clone(), routes.clone());
                any_changed = true;
            }
        }

        // Clean up CRDs for children that disconnected (empty routes removed them from map)
        let stale: Vec<String> = last_written_children
            .keys()
            .filter(|k| !child_routes.contains_key(*k))
            .cloned()
            .collect();
        for child_name in stale {
            if delete_cluster_routes(&api, &child_name).await.is_ok() {
                last_written_children.remove(&child_name);
                any_changed = true;
            }
        }

        // Publish combined route state tagged with source cluster names
        if any_changed {
            let mut all: Vec<TaggedRoute> = local_routes
                .iter()
                .map(|r| (cluster_name.clone(), r.clone()))
                .collect();
            for (child_name, routes) in &child_routes {
                for r in routes {
                    all.push((child_name.clone(), r.clone()));
                }
            }
            let _ = all_routes_tx.send(all);
        }
    }

    info!(cluster = %cluster_name, "Route reconciler stopped");
}

/// Discover local LatticeServices with `advertise: true` and resolve their Gateway addresses
async fn discover_local_routes(client: &Client) -> Vec<ClusterRoute> {
    let svc_api: Api<LatticeService> = Api::all(client.clone());
    let services = match svc_api.list(&Default::default()).await {
        Ok(list) => list.items,
        Err(e) => {
            warn!(error = %e, "failed to list LatticeService CRDs");
            return Vec::new();
        }
    };

    let gateways = list_gateways(client).await;
    let mut routes = Vec::new();

    for ls in &services {
        let svc_name = match ls.metadata.name.as_deref() {
            Some(n) => n,
            None => continue,
        };
        let svc_ns = ls.metadata.namespace.as_deref().unwrap_or("default");

        let ingress = match &ls.spec.ingress {
            Some(i) => i,
            None => continue,
        };

        for route in ingress.routes.values() {
            if route.advertise.is_none() {
                continue;
            }

            if route.hosts.is_empty() {
                warn!(
                    service = svc_name,
                    namespace = svc_ns,
                    "advertised route has no hostnames — cannot be discovered"
                );
                continue;
            }

            // Resolve the gateway address for routes with external access.
            // Advertise-only routes (no external gateway) don't need an address —
            // consumers reach the service via Istio multi-cluster using the
            // service FQDN, not a gateway IP.
            let (address, port) = if route.external_gateway {
                let result = resolve_gateway_address(svc_ns, &gateways);
                if result.0.is_empty() {
                    warn!(
                        service = svc_name,
                        namespace = svc_ns,
                        "advertised route has no Gateway address — route will not be discoverable until Gateway gets an IP"
                    );
                    continue;
                }
                result
            } else {
                (String::new(), 0)
            };

            let allowed_services = route
                .advertise
                .as_ref()
                .map(|a| a.allowed_services.clone())
                .unwrap_or_default();

            let protocol = match route.kind {
                lattice_crd::crd::RouteKind::HTTPRoute => {
                    if route.tls.is_some() {
                        "HTTPS"
                    } else {
                        "HTTP"
                    }
                }
                lattice_crd::crd::RouteKind::GRPCRoute => "GRPC",
                lattice_crd::crd::RouteKind::TCPRoute => "TCP",
                _ => "HTTP",
            };

            let service_ports: std::collections::BTreeMap<String, u16> = ls
                .spec
                .workload
                .service
                .as_ref()
                .map(|svc| {
                    svc.ports
                        .iter()
                        .map(|(name, ps)| (name.clone(), ps.port))
                        .collect()
                })
                .unwrap_or_default();

            for host in &route.hosts {
                let cr = ClusterRoute {
                    service_name: svc_name.to_string(),
                    service_namespace: svc_ns.to_string(),
                    hostname: host.clone(),
                    address: address.clone(),
                    port,
                    protocol: protocol.to_string(),
                    allowed_services: allowed_services.clone(),
                    service_ports: service_ports.clone(),
                };
                if let Err(reason) = cr.validate() {
                    warn!(
                        service = svc_name,
                        namespace = svc_ns,
                        reason = %reason,
                        "rejecting local route"
                    );
                    continue;
                }
                routes.push(cr);
            }
        }
    }

    routes
}

/// List all Gateway objects and key them by "namespace/name"
async fn list_gateways(client: &Client) -> HashMap<String, DynamicObject> {
    let gw_gvk = GroupVersionKind::gvk("gateway.networking.k8s.io", "v1", "Gateway");
    let gw_ar = ApiResource::from_gvk(&gw_gvk);
    let gw_api: Api<DynamicObject> = Api::all_with(client.clone(), &gw_ar);

    match gw_api.list(&Default::default()).await {
        Ok(list) => list
            .items
            .into_iter()
            .filter_map(|gw| {
                let ns = gw.metadata.namespace.as_deref().unwrap_or("default");
                let name = gw.metadata.name.as_deref()?;
                Some((format!("{ns}/{name}"), gw))
            })
            .collect(),
        Err(e) => {
            debug!(error = %e, "Gateway API not available");
            HashMap::new()
        }
    }
}

/// Resolve a Gateway LoadBalancer address in a namespace.
///
/// Only considers ingress gateways (gatewayClassName "istio"), not waypoint
/// gateways (gatewayClassName "istio-waypoint") which listen on HBONE port 15008.
fn resolve_gateway_address(
    namespace: &str,
    gateways: &HashMap<String, DynamicObject>,
) -> (String, u16) {
    for (key, gw) in gateways {
        if !key.starts_with(&format!("{namespace}/")) {
            continue;
        }

        let spec: Option<GatewaySpec> = gw
            .data
            .get("spec")
            .and_then(|s| serde_json::from_value(s.clone()).ok());

        // Skip waypoint gateways — they use HBONE (port 15008), not application traffic
        if let Some(ref s) = spec {
            if s.gateway_class_name == lattice_common::mesh::WAYPOINT_GATEWAY_CLASS {
                continue;
            }
        }

        let status: Option<GatewayStatus> = gw
            .data
            .get("status")
            .and_then(|s| serde_json::from_value(s.clone()).ok());

        let address = status
            .as_ref()
            .and_then(|s| s.addresses.first())
            .map(|a| a.value.clone())
            .unwrap_or_default();

        if address.is_empty() {
            continue;
        }

        let port = spec
            .and_then(|s| s.listeners.first().map(|l| l.port))
            .unwrap_or(443);

        return (address, port);
    }

    (String::new(), 0)
}

/// Write the merged route table to the LatticeClusterRoutes CRD.
///
/// Returns `Ok(())` on success so callers can decide whether to update their
/// cached state. A failed write returns `Err` and the caller should retry.
async fn write_cluster_routes(
    api: &Api<LatticeClusterRoutes>,
    cluster_name: &str,
    routes: &[ClusterRoute],
) -> Result<(), kube::Error> {
    let route_count = routes.len() as u32;

    let route_table = LatticeClusterRoutes::new(
        cluster_name,
        LatticeClusterRoutesSpec {
            routes: routes.to_vec(),
        },
    );

    let applied = api
        .patch(
            cluster_name,
            &PatchParams::apply("lattice-route-reconciler"),
            &Patch::Apply(route_table),
        )
        .await
        .map_err(|e| {
            error!(cluster = %cluster_name, error = %e, "failed to write LatticeClusterRoutes");
            e
        })?;

    let observed_generation = applied.metadata.generation;

    let status = serde_json::json!({
        "apiVersion": "lattice.dev/v1alpha1",
        "kind": "LatticeClusterRoutes",
        "metadata": { "name": cluster_name },
        "status": {
            "phase": "Ready",
            "routeCount": route_count,
            "lastUpdated": chrono::Utc::now().to_rfc3339(),
            "observedGeneration": observed_generation,
        }
    });

    if let Err(e) = api
        .patch_status(
            cluster_name,
            &PatchParams::apply("lattice-route-reconciler"),
            &Patch::Apply(status),
        )
        .await
    {
        warn!(cluster = %cluster_name, error = %e, "failed to patch LatticeClusterRoutes status");
    }

    info!(cluster = %cluster_name, routes = route_count, "reconciled LatticeClusterRoutes");
    Ok(())
}

/// Delete a LatticeClusterRoutes CRD (used when a child disconnects).
async fn delete_cluster_routes(
    api: &Api<LatticeClusterRoutes>,
    cluster_name: &str,
) -> Result<(), kube::Error> {
    match api.delete(cluster_name, &Default::default()).await {
        Ok(_) => {
            info!(cluster = %cluster_name, "deleted LatticeClusterRoutes for disconnected child");
            Ok(())
        }
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => {
            warn!(cluster = %cluster_name, error = %e, "failed to delete LatticeClusterRoutes");
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gateway_object(ns: &str, name: &str, address: &str, port: u16) -> DynamicObject {
        make_gateway_object_with_class(ns, name, address, port, "istio")
    }

    fn make_gateway_object_with_class(
        ns: &str,
        name: &str,
        address: &str,
        port: u16,
        gateway_class: &str,
    ) -> DynamicObject {
        let mut obj = DynamicObject::new(
            name,
            &ApiResource::from_gvk(&GroupVersionKind::gvk(
                "gateway.networking.k8s.io",
                "v1",
                "Gateway",
            )),
        );
        obj.metadata.namespace = Some(ns.to_string());
        obj.data = serde_json::json!({
            "spec": {
                "gatewayClassName": gateway_class,
                "listeners": [{ "port": port }]
            },
            "status": { "addresses": [{ "value": address }] }
        });
        obj
    }

    #[test]
    fn resolve_gateway_finds_address_in_namespace() {
        let mut gateways = HashMap::new();
        gateways.insert(
            "media/istio-gateway".to_string(),
            make_gateway_object("media", "istio-gateway", "10.0.0.217", 80),
        );

        let (addr, port) = resolve_gateway_address("media", &gateways);
        assert_eq!(addr, "10.0.0.217");
        assert_eq!(port, 80);
    }

    #[test]
    fn resolve_gateway_ignores_other_namespaces() {
        let mut gateways = HashMap::new();
        gateways.insert(
            "webapp/istio-gateway".to_string(),
            make_gateway_object("webapp", "istio-gateway", "10.0.0.218", 8080),
        );

        let (addr, port) = resolve_gateway_address("media", &gateways);
        assert_eq!(addr, "");
        assert_eq!(port, 0);
    }

    #[test]
    fn resolve_gateway_returns_empty_when_no_address() {
        let mut gateways = HashMap::new();
        let mut gw = make_gateway_object("media", "gw", "", 80);
        gw.data = serde_json::json!({
            "spec": { "gatewayClassName": "istio", "listeners": [{ "port": 80 }] },
            "status": { "addresses": [] }
        });
        gateways.insert("media/gw".to_string(), gw);

        let (addr, port) = resolve_gateway_address("media", &gateways);
        assert_eq!(addr, "");
        assert_eq!(port, 0);
    }

    #[test]
    fn resolve_gateway_defaults_port_to_443() {
        let mut gateways = HashMap::new();
        let mut gw = make_gateway_object("media", "gw", "10.0.0.1", 443);
        gw.data = serde_json::json!({
            "spec": { "gatewayClassName": "istio", "listeners": [] },
            "status": { "addresses": [{ "value": "10.0.0.1" }] }
        });
        gateways.insert("media/gw".to_string(), gw);

        let (addr, port) = resolve_gateway_address("media", &gateways);
        assert_eq!(addr, "10.0.0.1");
        assert_eq!(port, 443);
    }

    #[test]
    fn resolve_gateway_skips_waypoint_gateways() {
        let mut gateways = HashMap::new();
        // Waypoint gateway on HBONE port — should be skipped
        gateways.insert(
            "media/media-waypoint".to_string(),
            make_gateway_object_with_class(
                "media",
                "media-waypoint",
                "10.0.0.200",
                15008,
                "istio-waypoint",
            ),
        );
        // Ingress gateway on port 80 — should be selected
        gateways.insert(
            "media/istio-gateway".to_string(),
            make_gateway_object_with_class("media", "istio-gateway", "10.0.0.217", 80, "istio"),
        );

        let (addr, port) = resolve_gateway_address("media", &gateways);
        assert_eq!(addr, "10.0.0.217");
        assert_eq!(port, 80);
    }

    #[test]
    fn resolve_gateway_returns_empty_when_only_waypoint() {
        let mut gateways = HashMap::new();
        gateways.insert(
            "media/media-waypoint".to_string(),
            make_gateway_object_with_class(
                "media",
                "media-waypoint",
                "10.0.0.200",
                15008,
                "istio-waypoint",
            ),
        );

        let (addr, port) = resolve_gateway_address("media", &gateways);
        assert_eq!(addr, "");
        assert_eq!(port, 0);
    }
}
