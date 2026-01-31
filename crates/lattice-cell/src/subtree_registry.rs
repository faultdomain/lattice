//! Subtree Registry - Tracks clusters in this cell's subtree
//!
//! Each cluster maintains awareness of its subtree (all descendants). This enables:
//! - **Routing**: Knowing which agent connection routes to which cluster
//! - **Kubeconfig**: Generating configs with all accessible clusters
//! - **Authorization**: Cedar policies can reference cluster hierarchy
//!
//! State bubbles up from children → parents:
//! - On connect: Agent sends full subtree state
//! - On change: Agent sends delta (add/remove)
//! - Parent aggregates and bubbles up to its own parent

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Information about a cluster in the subtree
#[derive(Clone, Debug, PartialEq)]
pub struct ClusterInfo {
    /// Cluster name (unique identifier)
    pub name: String,
    /// Immediate parent cluster name
    pub parent: String,
    /// Current phase (Pending, Provisioning, Ready, etc.)
    pub phase: String,
    /// Labels for policy matching
    pub labels: HashMap<String, String>,
}

/// Route information for reaching a cluster
#[derive(Clone, Debug)]
pub struct RouteInfo {
    /// Agent ID to route through (None if this is self)
    pub agent_id: Option<String>,
    /// Whether this cluster is the current cell itself
    pub is_self: bool,
    /// Cluster info
    pub cluster: ClusterInfo,
}

/// Registry of all clusters in this cell's subtree
///
/// Thread-safe via internal RwLock. Can be queried by the auth proxy
/// to determine routing and by kubeconfig endpoint to list clusters.
#[derive(Clone)]
pub struct SubtreeRegistry {
    /// Our own cluster name
    cluster_name: String,
    /// Map of cluster name → route info
    routes: Arc<RwLock<HashMap<String, RouteInfo>>>,
}

impl SubtreeRegistry {
    /// Create a new subtree registry
    ///
    /// # Arguments
    /// * `cluster_name` - Name of this cluster (self)
    pub fn new(cluster_name: String) -> Self {
        // Pre-populate with self
        let self_info = RouteInfo {
            agent_id: None,
            is_self: true,
            cluster: ClusterInfo {
                name: cluster_name.clone(),
                parent: String::new(),
                phase: "Ready".to_string(),
                labels: HashMap::new(),
            },
        };

        let mut initial_routes = HashMap::new();
        initial_routes.insert(cluster_name.clone(), self_info);

        Self {
            cluster_name,
            routes: Arc::new(RwLock::new(initial_routes)),
        }
    }

    /// Get this cell's cluster name
    pub fn cluster_name(&self) -> &str {
        &self.cluster_name
    }

    /// Get route info for a cluster
    ///
    /// Returns None if the cluster is not in our subtree.
    pub async fn get_route(&self, cluster_name: &str) -> Option<RouteInfo> {
        let routes = self.routes.read().await;
        routes.get(cluster_name).cloned()
    }

    /// Get all clusters in the subtree
    pub async fn all_clusters(&self) -> Vec<String> {
        let routes = self.routes.read().await;
        routes.keys().cloned().collect()
    }

    /// Get all clusters accessible via a specific agent
    pub async fn clusters_via_agent(&self, agent_id: &str) -> Vec<String> {
        let routes = self.routes.read().await;
        routes
            .iter()
            .filter_map(|(name, info)| {
                if info.agent_id.as_deref() == Some(agent_id) {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Handle full subtree state from an agent (replaces previous state)
    ///
    /// # Arguments
    /// * `agent_id` - ID of the agent sending this state
    /// * `clusters` - Full list of clusters in the agent's subtree
    pub async fn handle_full_sync(&self, agent_id: &str, clusters: Vec<ClusterInfo>) {
        let mut routes = self.routes.write().await;

        // Remove all clusters previously routed via this agent
        routes.retain(|_, info| info.agent_id.as_deref() != Some(agent_id));

        // Add new clusters
        for cluster in clusters {
            let route = RouteInfo {
                agent_id: Some(agent_id.to_string()),
                is_self: false,
                cluster,
            };
            routes.insert(route.cluster.name.clone(), route);
        }
    }

    /// Handle incremental subtree update from an agent
    ///
    /// # Arguments
    /// * `agent_id` - ID of the agent sending this update
    /// * `added` - Clusters to add
    /// * `removed` - Cluster names to remove
    pub async fn handle_delta(
        &self,
        agent_id: &str,
        added: Vec<ClusterInfo>,
        removed: Vec<String>,
    ) {
        let mut routes = self.routes.write().await;

        // Remove clusters
        for name in removed {
            // Only remove if it was routed via this agent
            if routes
                .get(&name)
                .map(|r| r.agent_id.as_deref() == Some(agent_id))
                .unwrap_or(false)
            {
                routes.remove(&name);
            }
        }

        // Add clusters
        for cluster in added {
            let route = RouteInfo {
                agent_id: Some(agent_id.to_string()),
                is_self: false,
                cluster,
            };
            routes.insert(route.cluster.name.clone(), route);
        }
    }

    /// Handle agent disconnect - remove all clusters routed via this agent
    pub async fn handle_agent_disconnect(&self, agent_id: &str) {
        let mut routes = self.routes.write().await;
        routes.retain(|_, info| info.agent_id.as_deref() != Some(agent_id));
    }

    /// Get count of clusters in subtree
    pub async fn cluster_count(&self) -> usize {
        self.routes.read().await.len()
    }

    /// Check if a cluster is in the subtree
    pub async fn contains(&self, cluster_name: &str) -> bool {
        self.routes.read().await.contains_key(cluster_name)
    }

    /// Get clusters by parent
    pub async fn children_of(&self, parent_name: &str) -> Vec<String> {
        let routes = self.routes.read().await;
        routes
            .iter()
            .filter_map(|(name, info)| {
                if info.cluster.parent == parent_name {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect()
    }
}

impl std::fmt::Debug for SubtreeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubtreeRegistry")
            .field("cluster_name", &self.cluster_name)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_new_registry_contains_self() {
        let registry = SubtreeRegistry::new("my-cluster".to_string());

        assert_eq!(registry.cluster_name(), "my-cluster");
        assert!(registry.contains("my-cluster").await);

        let route = registry.get_route("my-cluster").await.unwrap();
        assert!(route.is_self);
        assert!(route.agent_id.is_none());
    }

    #[tokio::test]
    async fn test_full_sync() {
        let registry = SubtreeRegistry::new("parent".to_string());

        let clusters = vec![
            ClusterInfo {
                name: "child-1".to_string(),
                parent: "parent".to_string(),
                phase: "Ready".to_string(),
                labels: HashMap::new(),
            },
            ClusterInfo {
                name: "grandchild-1".to_string(),
                parent: "child-1".to_string(),
                phase: "Ready".to_string(),
                labels: HashMap::new(),
            },
        ];

        registry.handle_full_sync("agent-1", clusters).await;

        assert_eq!(registry.cluster_count().await, 3); // parent + 2 children
        assert!(registry.contains("child-1").await);
        assert!(registry.contains("grandchild-1").await);

        let route = registry.get_route("child-1").await.unwrap();
        assert!(!route.is_self);
        assert_eq!(route.agent_id, Some("agent-1".to_string()));
    }

    #[tokio::test]
    async fn test_full_sync_replaces_previous() {
        let registry = SubtreeRegistry::new("parent".to_string());

        // First sync
        let clusters1 = vec![ClusterInfo {
            name: "old-cluster".to_string(),
            parent: "parent".to_string(),
            phase: "Ready".to_string(),
            labels: HashMap::new(),
        }];
        registry.handle_full_sync("agent-1", clusters1).await;
        assert!(registry.contains("old-cluster").await);

        // Second sync replaces
        let clusters2 = vec![ClusterInfo {
            name: "new-cluster".to_string(),
            parent: "parent".to_string(),
            phase: "Ready".to_string(),
            labels: HashMap::new(),
        }];
        registry.handle_full_sync("agent-1", clusters2).await;

        assert!(!registry.contains("old-cluster").await);
        assert!(registry.contains("new-cluster").await);
    }

    #[tokio::test]
    async fn test_delta_add_remove() {
        let registry = SubtreeRegistry::new("parent".to_string());

        // Add initial cluster
        let added = vec![ClusterInfo {
            name: "cluster-1".to_string(),
            parent: "parent".to_string(),
            phase: "Ready".to_string(),
            labels: HashMap::new(),
        }];
        registry.handle_delta("agent-1", added, vec![]).await;
        assert!(registry.contains("cluster-1").await);

        // Add another, remove first
        let added2 = vec![ClusterInfo {
            name: "cluster-2".to_string(),
            parent: "parent".to_string(),
            phase: "Ready".to_string(),
            labels: HashMap::new(),
        }];
        registry
            .handle_delta("agent-1", added2, vec!["cluster-1".to_string()])
            .await;

        assert!(!registry.contains("cluster-1").await);
        assert!(registry.contains("cluster-2").await);
    }

    #[tokio::test]
    async fn test_agent_disconnect() {
        let registry = SubtreeRegistry::new("parent".to_string());

        // Add clusters from two agents
        let clusters1 = vec![ClusterInfo {
            name: "from-agent-1".to_string(),
            parent: "parent".to_string(),
            phase: "Ready".to_string(),
            labels: HashMap::new(),
        }];
        let clusters2 = vec![ClusterInfo {
            name: "from-agent-2".to_string(),
            parent: "parent".to_string(),
            phase: "Ready".to_string(),
            labels: HashMap::new(),
        }];

        registry.handle_full_sync("agent-1", clusters1).await;
        registry.handle_full_sync("agent-2", clusters2).await;

        assert!(registry.contains("from-agent-1").await);
        assert!(registry.contains("from-agent-2").await);

        // Disconnect agent-1
        registry.handle_agent_disconnect("agent-1").await;

        assert!(!registry.contains("from-agent-1").await);
        assert!(registry.contains("from-agent-2").await);
        // Self is always preserved
        assert!(registry.contains("parent").await);
    }

    #[tokio::test]
    async fn test_clusters_via_agent() {
        let registry = SubtreeRegistry::new("parent".to_string());

        let clusters = vec![
            ClusterInfo {
                name: "child-1".to_string(),
                parent: "parent".to_string(),
                phase: "Ready".to_string(),
                labels: HashMap::new(),
            },
            ClusterInfo {
                name: "child-2".to_string(),
                parent: "parent".to_string(),
                phase: "Ready".to_string(),
                labels: HashMap::new(),
            },
        ];

        registry.handle_full_sync("agent-1", clusters).await;

        let via_agent = registry.clusters_via_agent("agent-1").await;
        assert_eq!(via_agent.len(), 2);
        assert!(via_agent.contains(&"child-1".to_string()));
        assert!(via_agent.contains(&"child-2".to_string()));
    }

    #[tokio::test]
    async fn test_children_of() {
        let registry = SubtreeRegistry::new("root".to_string());

        let clusters = vec![
            ClusterInfo {
                name: "child-1".to_string(),
                parent: "root".to_string(),
                phase: "Ready".to_string(),
                labels: HashMap::new(),
            },
            ClusterInfo {
                name: "grandchild-1".to_string(),
                parent: "child-1".to_string(),
                phase: "Ready".to_string(),
                labels: HashMap::new(),
            },
        ];

        registry.handle_full_sync("agent-1", clusters).await;

        let root_children = registry.children_of("root").await;
        assert_eq!(root_children.len(), 1);
        assert!(root_children.contains(&"child-1".to_string()));

        let child1_children = registry.children_of("child-1").await;
        assert_eq!(child1_children.len(), 1);
        assert!(child1_children.contains(&"grandchild-1".to_string()));
    }
}
