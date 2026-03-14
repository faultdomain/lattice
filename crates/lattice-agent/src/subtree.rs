//! Subtree state management for agents
//!
//! Watches LatticeCluster CRDs and reports subtree state to the parent cell.
//! This enables the parent to know which clusters are in this agent's subtree
//! for routing and authorization purposes.

use std::collections::HashMap;

use futures::{StreamExt, TryStreamExt};
use kube::api::{DynamicObject, GroupVersionKind};
use kube::discovery::ApiResource;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use lattice_common::crd::{LatticeCluster, LatticeService};
use lattice_proto::{
    agent_message::Payload, AgentMessage, SubtreeCluster, SubtreeService, SubtreeState,
};

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
    listeners: Vec<GatewayListener>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GatewayListener {
    #[serde(default)]
    port: u16,
}

/// Builds and sends subtree state to the parent cell
pub struct SubtreeSender {
    /// This cluster's name
    cluster_name: String,
    /// Kubernetes client
    client: Client,
}

impl SubtreeSender {
    /// Create a new SubtreeSender
    pub fn new(cluster_name: String, client: Client) -> Self {
        Self {
            cluster_name,
            client,
        }
    }

    /// Build the full subtree state (used on connect)
    ///
    /// Includes self and all child LatticeCluster CRDs.
    pub async fn full_state(&self) -> SubtreeState {
        let mut clusters = vec![SubtreeCluster {
            name: self.cluster_name.clone(),
            parent: String::new(), // Agent doesn't know its parent name
            removed: false,
            phase: "Ready".to_string(),
            labels: HashMap::new(),
        }];

        // List child LatticeCluster CRDs
        let api: Api<LatticeCluster> = Api::all(self.client.clone());
        match api.list(&Default::default()).await {
            Ok(list) => {
                for lc in list.items {
                    if let Some(name) = lc.metadata.name.as_ref() {
                        let phase = lc
                            .status
                            .as_ref()
                            .map(|s| format!("{:?}", s.phase))
                            .unwrap_or_else(|| "Pending".to_string());

                        clusters.push(SubtreeCluster {
                            name: name.to_string(),
                            parent: self.cluster_name.clone(),
                            removed: false,
                            phase,
                            labels: lc
                                .metadata
                                .labels
                                .clone()
                                .unwrap_or_default()
                                .into_iter()
                                .collect(),
                        });
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to list LatticeCluster CRDs for subtree state");
            }
        }

        // Discover local services with ingress routes
        let services = self.discover_services().await;

        info!(
            cluster = %self.cluster_name,
            child_count = clusters.len() - 1,
            services = services.len(),
            "Built full subtree state"
        );

        SubtreeState {
            clusters,
            services,
            is_full_sync: true,
        }
    }

    /// Discover local LatticeService resources with ingress routes and resolve
    /// their Gateway addresses to build SubtreeService entries.
    async fn discover_services(&self) -> Vec<SubtreeService> {
        let mut services = Vec::new();

        // List LatticeService CRDs with ingress specs
        let svc_api: Api<LatticeService> = Api::all(self.client.clone());
        let lattice_services = match svc_api.list(&Default::default()).await {
            Ok(list) => list.items,
            Err(e) => {
                warn!(error = %e, "failed to list LatticeService CRDs for service discovery");
                return services;
            }
        };

        // List Gateway objects to resolve LB addresses
        let gw_gvk = GroupVersionKind::gvk("gateway.networking.k8s.io", "v1", "Gateway");
        let gw_ar = ApiResource::from_gvk(&gw_gvk);
        let gw_api: Api<DynamicObject> = Api::all_with(self.client.clone(), &gw_ar);
        let gateways: HashMap<String, DynamicObject> = match gw_api.list(&Default::default()).await
        {
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
                debug!(error = %e, "Gateway API not available, skipping service discovery");
                return services;
            }
        };

        for ls in &lattice_services {
            let svc_name = match ls.metadata.name.as_deref() {
                Some(n) => n,
                None => continue,
            };
            let svc_ns = ls.metadata.namespace.as_deref().unwrap_or("default");

            let ingress = match &ls.spec.ingress {
                Some(i) => i,
                None => continue,
            };

            let labels: HashMap<String, String> = ls
                .metadata
                .labels
                .clone()
                .unwrap_or_default()
                .into_iter()
                .collect();

            for route in ingress.routes.values() {
                if !route.advertise {
                    continue;
                }

                for host in &route.hosts {
                    // Resolve the Gateway address for this route's gateway class
                    let (address, port) =
                        resolve_gateway_address(svc_ns, &gateways);

                    if address.is_empty() {
                        debug!(
                            service = svc_name,
                            namespace = svc_ns,
                            host,
                            "no Gateway address found, skipping route"
                        );
                        continue;
                    }

                    services.push(SubtreeService {
                        name: svc_name.to_string(),
                        namespace: svc_ns.to_string(),
                        cluster: self.cluster_name.clone(),
                        removed: false,
                        hostname: host.clone(),
                        address: address.clone(),
                        port,
                        protocol: "HTTP".to_string(),
                        labels: labels.clone(),
                    });
                }
            }
        }

        services
    }

    /// Send full subtree state to parent
    pub async fn send_full_state(&self, message_tx: &mpsc::Sender<AgentMessage>) {
        let state = self.full_state().await;
        let msg = AgentMessage {
            cluster_name: self.cluster_name.clone(),
            payload: Some(Payload::SubtreeState(state)),
        };

        if let Err(e) = message_tx.send(msg).await {
            warn!(error = %e, "Failed to send subtree state to parent");
        }
    }

    /// Watch for LatticeCluster changes and send deltas to parent
    ///
    /// This spawns a task that watches for cluster changes and sends
    /// incremental updates. Returns the task handle for cleanup.
    pub fn spawn_watcher(
        self,
        message_tx: mpsc::Sender<AgentMessage>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.watch_and_send_deltas(message_tx).await;
        })
    }

    /// Watch for LatticeCluster and LatticeService changes and send deltas
    async fn watch_and_send_deltas(&self, message_tx: mpsc::Sender<AgentMessage>) {
        let cluster_api: Api<LatticeCluster> = Api::all(self.client.clone());
        let service_api: Api<LatticeService> = Api::all(self.client.clone());

        info!(cluster = %self.cluster_name, "Starting subtree watcher (clusters + services)");

        let mut cluster_stream =
            watcher::watcher(cluster_api, watcher::Config::default()).boxed();
        let mut service_stream =
            watcher::watcher(service_api, watcher::Config::default()).boxed();

        loop {
            tokio::select! {
                event = cluster_stream.try_next() => {
                    match event {
                        Ok(Some(event)) => {
                            if let Some(msg) = self.handle_cluster_event(event) {
                                if message_tx.send(msg).await.is_err() {
                                    debug!("Message channel closed, stopping subtree watcher");
                                    break;
                                }
                            }
                        }
                        Ok(None) => {
                            warn!("Cluster watcher stream ended");
                            break;
                        }
                        Err(e) => {
                            warn!(error = %e, "Cluster watcher error");
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        }
                    }
                }
                event = service_stream.try_next() => {
                    match event {
                        Ok(Some(event)) => {
                            // On any LatticeService change, re-discover all services
                            // and send a full service update (services only, not clusters)
                            if self.is_service_change(&event) {
                                let services = self.discover_services().await;
                                let delta = SubtreeState {
                                    clusters: vec![],
                                    services,
                                    is_full_sync: false,
                                };
                                let msg = AgentMessage {
                                    cluster_name: self.cluster_name.clone(),
                                    payload: Some(Payload::SubtreeState(delta)),
                                };
                                if message_tx.send(msg).await.is_err() {
                                    debug!("Message channel closed, stopping subtree watcher");
                                    break;
                                }
                            }
                        }
                        Ok(None) => {
                            warn!("Service watcher stream ended");
                            break;
                        }
                        Err(e) => {
                            warn!(error = %e, "Service watcher error");
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        }
                    }
                }
            }
        }

        info!(cluster = %self.cluster_name, "Subtree watcher stopped");
    }

    /// Handle a LatticeCluster watcher event, returning a delta message if applicable
    fn handle_cluster_event(&self, event: Event<LatticeCluster>) -> Option<AgentMessage> {
        match event {
            Event::Apply(lc) => {
                let name = lc.metadata.name.as_ref()?;
                debug!(cluster = %name, "LatticeCluster added/modified");

                let phase = lc
                    .status
                    .as_ref()
                    .map(|s| format!("{:?}", s.phase))
                    .unwrap_or_else(|| "Pending".to_string());

                let delta = SubtreeState {
                    clusters: vec![SubtreeCluster {
                        name: name.to_string(),
                        parent: self.cluster_name.clone(),
                        removed: false,
                        phase,
                        labels: lc
                            .metadata
                            .labels
                            .clone()
                            .unwrap_or_default()
                            .into_iter()
                            .collect(),
                    }],
                    services: vec![],
                    is_full_sync: false,
                };

                Some(AgentMessage {
                    cluster_name: self.cluster_name.clone(),
                    payload: Some(Payload::SubtreeState(delta)),
                })
            }
            Event::Delete(lc) => {
                let name = lc.metadata.name.as_ref()?;
                debug!(cluster = %name, "LatticeCluster deleted");

                let delta = SubtreeState {
                    clusters: vec![SubtreeCluster {
                        name: name.to_string(),
                        parent: self.cluster_name.clone(),
                        removed: true,
                        phase: String::new(),
                        labels: HashMap::new(),
                    }],
                    services: vec![],
                    is_full_sync: false,
                };

                Some(AgentMessage {
                    cluster_name: self.cluster_name.clone(),
                    payload: Some(Payload::SubtreeState(delta)),
                })
            }
            Event::Init | Event::InitApply(_) | Event::InitDone => None,
        }
    }

    /// Check if a LatticeService watcher event represents a meaningful change
    fn is_service_change(&self, event: &Event<LatticeService>) -> bool {
        matches!(event, Event::Apply(_) | Event::Delete(_) | Event::InitDone)
    }
}

/// Resolve a Gateway LoadBalancer address in a given namespace.
///
/// Looks for any Gateway in the namespace and returns its first assigned address
/// and listener port. Returns ("", 0) if no Gateway is found or has no address yet.
fn resolve_gateway_address(
    namespace: &str,
    gateways: &HashMap<String, DynamicObject>,
) -> (String, u32) {
    for (key, gw) in gateways {
        if !key.starts_with(&format!("{namespace}/")) {
            continue;
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

        let spec: Option<GatewaySpec> = gw
            .data
            .get("spec")
            .and_then(|s| serde_json::from_value(s.clone()).ok());

        let port = spec
            .and_then(|s| s.listeners.first().map(|l| l.port as u32))
            .unwrap_or(80);

        return (address, port);
    }

    (String::new(), 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subtree_cluster_creation() {
        let cluster = SubtreeCluster {
            name: "test-cluster".to_string(),
            parent: "parent-cluster".to_string(),
            removed: false,
            phase: "Ready".to_string(),
            labels: HashMap::new(),
        };

        assert_eq!(cluster.name, "test-cluster");
        assert_eq!(cluster.parent, "parent-cluster");
        assert!(!cluster.removed);
    }

    #[test]
    fn test_subtree_state_full_sync() {
        let state = SubtreeState {
            clusters: vec![SubtreeCluster {
                name: "root".to_string(),
                parent: String::new(),
                removed: false,
                phase: "Ready".to_string(),
                labels: HashMap::new(),
            }],
            services: vec![],
            is_full_sync: true,
        };

        assert!(state.is_full_sync);
        assert_eq!(state.clusters.len(), 1);
    }

    #[test]
    fn test_subtree_state_delta() {
        let state = SubtreeState {
            clusters: vec![SubtreeCluster {
                name: "child".to_string(),
                parent: "root".to_string(),
                removed: true,
                phase: String::new(),
                labels: HashMap::new(),
            }],
            services: vec![],
            is_full_sync: false,
        };

        assert!(!state.is_full_sync);
        assert!(state.clusters[0].removed);
    }
}
