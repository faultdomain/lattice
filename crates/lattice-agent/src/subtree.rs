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

use lattice_common::crd::LatticeCluster;
use lattice_proto::{agent_message::Payload, AgentMessage, SubtreeCluster, SubtreeState};

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

        info!(
            cluster = %self.cluster_name,
            child_count = clusters.len() - 1,
            "Built full subtree state"
        );

        SubtreeState {
            clusters,
            services: vec![], // Future: service mesh routing
            is_full_sync: true,
        }
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
    pub fn spawn_watcher(self, message_tx: mpsc::Sender<AgentMessage>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.watch_and_send_deltas(message_tx).await;
        })
    }

    /// Watch for LatticeCluster changes and send deltas
    async fn watch_and_send_deltas(&self, message_tx: mpsc::Sender<AgentMessage>) {
        let api: Api<LatticeCluster> = Api::all(self.client.clone());
        let config = watcher::Config::default();

        info!(cluster = %self.cluster_name, "Starting subtree watcher");

        // Use watcher to get events
        let mut stream = watcher::watcher(api, config).boxed();

        while let Ok(Some(event)) = stream.try_next().await {
            match event {
                Event::Apply(lc) => {
                    if let Some(name) = lc.metadata.name.as_ref() {
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
                Event::Delete(lc) => {
                    if let Some(name) = lc.metadata.name.as_ref() {
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
                Event::Init | Event::InitApply(_) | Event::InitDone => {
                    // Initial sync events - we already sent full state on connect
                }
            }
        }

        info!(cluster = %self.cluster_name, "Subtree watcher stopped");
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
}
