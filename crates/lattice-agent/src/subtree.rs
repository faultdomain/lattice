//! Subtree state management for agents
//!
//! Watches LatticeCluster CRDs and reports subtree state to the parent cell.
//! This enables the parent to know which clusters are in this agent's subtree
//! for routing and authorization purposes.

use std::collections::HashMap;

use futures::{StreamExt, TryStreamExt};
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use lattice_common::crd::{LatticeCluster, LatticeClusterRoutes, LatticeService};
use lattice_proto::{
    agent_message::Payload, AgentMessage, SubtreeCluster, SubtreeService, SubtreeState,
};

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

        // Read services from the local LatticeClusterRoutes CRD
        // (written by the route reconciler, which merges own + children's routes)
        let services = self.read_cluster_routes().await;

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

    /// Read routes from the local `LatticeClusterRoutes` CRD and convert to `SubtreeService`
    async fn read_cluster_routes(&self) -> Vec<SubtreeService> {
        let api: Api<LatticeClusterRoutes> = Api::all(self.client.clone());

        let routes_crd = match api.get(&self.cluster_name).await {
            Ok(crd) => crd,
            Err(e) => {
                debug!(
                    cluster = %self.cluster_name,
                    error = %e,
                    "LatticeClusterRoutes not found, no routes to advertise"
                );
                return Vec::new();
            }
        };

        routes_crd
            .spec
            .routes
            .iter()
            .map(|r| SubtreeService {
                name: r.service_name.clone(),
                namespace: r.service_namespace.clone(),
                cluster: self.cluster_name.clone(),
                removed: false,
                hostname: r.hostname.clone(),
                address: r.address.clone(),
                port: r.port as u32,
                protocol: r.protocol.clone(),
                labels: HashMap::new(),
            })
            .collect()
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
                            // On any LatticeService change, re-read routes from the CRD
                            // (route reconciler updates it from LatticeService changes)
                            if self.is_service_change(&event) {
                                let services = self.read_cluster_routes().await;
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

    #[test]
    fn subtree_service_has_route_fields() {
        let svc = SubtreeService {
            name: "jellyfin".to_string(),
            namespace: "media".to_string(),
            cluster: "backend".to_string(),
            removed: false,
            hostname: "jellyfin.home.arpa".to_string(),
            address: "10.0.0.217".to_string(),
            port: 80,
            protocol: "HTTP".to_string(),
            labels: HashMap::from([
                ("lattice.dev/environment".to_string(), "homelab".to_string()),
            ]),
        };

        assert_eq!(svc.hostname, "jellyfin.home.arpa");
        assert_eq!(svc.address, "10.0.0.217");
        assert_eq!(svc.port, 80);
        assert_eq!(svc.protocol, "HTTP");
        assert!(!svc.removed);
    }
}
