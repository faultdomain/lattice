//! Object graph building for CAPI resource discovery and ownership
//!
//! This module discovers CAPI resources and builds an ownership graph that determines
//! the order in which resources must be created on the target cluster.

use std::collections::{HashMap, HashSet};

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, DynamicObject, ListParams};
use kube::discovery::ApiResource;
use kube::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::error::MoveError;
use crate::{MOVE_HIERARCHY_LABEL, MOVE_LABEL};

/// Identity of a Kubernetes object
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectIdentity {
    /// API version (e.g., "cluster.x-k8s.io/v1beta1")
    pub api_version: String,
    /// Kind (e.g., "Cluster")
    pub kind: String,
    /// Namespace (empty for cluster-scoped)
    pub namespace: String,
    /// Name
    pub name: String,
    /// UID from source cluster
    pub uid: String,
}

impl ObjectIdentity {
    /// Create a new ObjectIdentity
    pub fn new(
        api_version: &str,
        kind: &str,
        namespace: &str,
        name: &str,
        uid: &str,
    ) -> Self {
        Self {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            namespace: namespace.to_string(),
            name: name.to_string(),
            uid: uid.to_string(),
        }
    }

    /// Get a display string for logging
    pub fn display(&self) -> String {
        if self.namespace.is_empty() {
            format!("{}/{}", self.kind, self.name)
        } else {
            format!("{}/{}/{}", self.kind, self.namespace, self.name)
        }
    }
}

/// A node in the object graph representing a single CAPI resource
#[derive(Debug, Clone)]
pub struct GraphNode {
    /// Identity of this object
    pub identity: ObjectIdentity,
    /// The full object data (JSON)
    pub object: serde_json::Value,
    /// UIDs of direct owners (from ownerReferences)
    pub owners: HashSet<String>,
    /// UIDs of soft owners (by naming convention)
    pub soft_owners: HashSet<String>,
    /// Whether this node should force-move its hierarchy
    pub force_move_hierarchy: bool,
    /// New UID after creation on target (filled in during import)
    pub new_uid: Option<String>,
}

impl GraphNode {
    /// Create a new GraphNode from a DynamicObject
    pub fn from_dynamic_object(obj: &DynamicObject, api_version: &str, kind: &str) -> Option<Self> {
        let uid = obj.metadata.uid.as_ref()?;
        let name = obj.metadata.name.as_ref()?;
        let namespace = obj.metadata.namespace.clone().unwrap_or_default();

        let identity = ObjectIdentity::new(api_version, kind, &namespace, name, uid);

        // Extract owner references
        let owners: HashSet<String> = obj
            .metadata
            .owner_references
            .as_ref()
            .map(|refs| refs.iter().map(|r| r.uid.clone()).collect())
            .unwrap_or_default();

        // Serialize the object to JSON for transmission
        // DynamicObject doesn't include apiVersion/kind in serialization, so we add them
        let mut object = serde_json::to_value(obj).ok()?;
        if let Some(obj_map) = object.as_object_mut() {
            obj_map.insert("apiVersion".to_string(), serde_json::Value::String(api_version.to_string()));
            obj_map.insert("kind".to_string(), serde_json::Value::String(kind.to_string()));
        }

        Some(Self {
            identity,
            object,
            owners,
            soft_owners: HashSet::new(),
            force_move_hierarchy: false,
            new_uid: None,
        })
    }

    /// Get the source UID
    pub fn uid(&self) -> &str {
        &self.identity.uid
    }

    /// Get all owners (both hard and soft)
    pub fn all_owners(&self) -> HashSet<String> {
        self.owners.union(&self.soft_owners).cloned().collect()
    }
}

/// Information about a discovered CRD type
#[derive(Debug, Clone)]
pub struct DiscoveredType {
    /// API resource for this type
    pub api_resource: ApiResource,
    /// Whether to force-move the hierarchy (from move-hierarchy label)
    pub move_hierarchy: bool,
}

/// The object graph containing all discovered CAPI resources and their relationships
#[derive(Debug)]
pub struct ObjectGraph {
    /// All nodes indexed by UID
    nodes: HashMap<String, GraphNode>,
    /// Discovered CRD types
    discovered_types: Vec<DiscoveredType>,
    /// Namespace being moved
    namespace: String,
}

impl ObjectGraph {
    /// Create a new empty ObjectGraph
    pub fn new(namespace: &str) -> Self {
        Self {
            nodes: HashMap::new(),
            discovered_types: Vec::new(),
            namespace: namespace.to_string(),
        }
    }

    /// Get the namespace
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Get all nodes
    pub fn nodes(&self) -> &HashMap<String, GraphNode> {
        &self.nodes
    }

    /// Get a node by UID
    pub fn get(&self, uid: &str) -> Option<&GraphNode> {
        self.nodes.get(uid)
    }

    /// Get all UIDs
    pub fn uids(&self) -> Vec<String> {
        self.nodes.keys().cloned().collect()
    }

    /// Get the number of nodes
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Check if the graph is empty
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Insert a node into the graph (for testing)
    #[cfg(test)]
    pub fn insert(&mut self, node: GraphNode) {
        let uid = node.uid().to_string();
        self.nodes.insert(uid, node);
    }

    /// Discover CRDs with move labels and populate the graph
    pub async fn discover(&mut self, client: &Client) -> Result<(), MoveError> {
        // Step 1: Discover all CRDs with move labels
        self.discover_types(client).await?;

        // Step 2: List all objects of discovered types in the namespace
        self.list_objects(client).await?;

        // Step 3: Process soft ownership relationships
        self.process_soft_ownership();

        // Step 4: Propagate force_move_hierarchy to descendants
        self.propagate_force_move_hierarchy();

        info!(
            namespace = %self.namespace,
            types = self.discovered_types.len(),
            objects = self.nodes.len(),
            "Object graph discovery complete"
        );

        Ok(())
    }

    /// Discover CRDs with clusterctl move labels
    async fn discover_types(&mut self, client: &Client) -> Result<(), MoveError> {
        let crd_api: Api<CustomResourceDefinition> = Api::all(client.clone());

        let crds = crd_api
            .list(&ListParams::default())
            .await
            .map_err(|e| MoveError::Discovery(format!("failed to list CRDs: {}", e)))?;

        for crd in crds.items {
            let name = match &crd.metadata.name {
                Some(n) => n,
                None => continue,
            };

            let labels = crd.metadata.labels.as_ref();

            // Check for move label or move-hierarchy label
            let has_move = labels.is_some_and(|l| l.contains_key(MOVE_LABEL));
            let has_move_hierarchy = labels.is_some_and(|l| l.contains_key(MOVE_HIERARCHY_LABEL));

            if !has_move && !has_move_hierarchy {
                continue;
            }

            // Extract API resource info from CRD spec
            let spec = &crd.spec;
            let group = &spec.group;
            let kind = &spec.names.kind;
            let plural = &spec.names.plural;

            // Use the first version that is served and stored
            let version = spec
                .versions
                .iter()
                .find(|v| v.served && v.storage)
                .map(|v| &v.name)
                .or_else(|| spec.versions.first().map(|v| &v.name));

            let version = match version {
                Some(v) => v.clone(),
                None => {
                    warn!(crd = %name, "CRD has no versions, skipping");
                    continue;
                }
            };

            let api_resource = ApiResource {
                group: group.clone(),
                version: version.clone(),
                kind: kind.clone(),
                api_version: format!("{}/{}", group, version),
                plural: plural.clone(),
            };

            debug!(
                crd = %name,
                kind = %kind,
                move_label = has_move,
                move_hierarchy = has_move_hierarchy,
                "Discovered CRD type"
            );

            self.discovered_types.push(DiscoveredType {
                api_resource,
                move_hierarchy: has_move_hierarchy,
            });
        }

        // Also add core types that are commonly moved (Secrets, ConfigMaps)
        self.add_core_types();

        info!(
            types = self.discovered_types.len(),
            "Discovered types for move"
        );

        Ok(())
    }

    /// Add core Kubernetes types that are commonly included in CAPI moves
    fn add_core_types(&mut self) {
        // Secrets are often referenced by CAPI resources
        self.discovered_types.push(DiscoveredType {
            api_resource: ApiResource {
                group: String::new(),
                version: "v1".to_string(),
                kind: "Secret".to_string(),
                api_version: "v1".to_string(),
                plural: "secrets".to_string(),
            },
            move_hierarchy: false,
        });

        // ConfigMaps may also be referenced
        self.discovered_types.push(DiscoveredType {
            api_resource: ApiResource {
                group: String::new(),
                version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
                api_version: "v1".to_string(),
                plural: "configmaps".to_string(),
            },
            move_hierarchy: false,
        });
    }

    /// List all objects of discovered types in the namespace
    async fn list_objects(&mut self, client: &Client) -> Result<(), MoveError> {
        for discovered_type in &self.discovered_types.clone() {
            let api: Api<DynamicObject> = Api::namespaced_with(
                client.clone(),
                &self.namespace,
                &discovered_type.api_resource,
            );

            let list = match api.list(&ListParams::default()).await {
                Ok(l) => l,
                Err(e) => {
                    // Not found is okay - type may not have any instances
                    if e.to_string().contains("404") || e.to_string().contains("not found") {
                        continue;
                    }
                    return Err(MoveError::Discovery(format!(
                        "failed to list {}: {}",
                        discovered_type.api_resource.kind, e
                    )));
                }
            };

            for obj in list.items {
                if let Some(mut node) = GraphNode::from_dynamic_object(
                    &obj,
                    &discovered_type.api_resource.api_version,
                    &discovered_type.api_resource.kind,
                ) {
                    // Mark if this type forces hierarchy move
                    node.force_move_hierarchy = discovered_type.move_hierarchy;

                    let uid = node.uid().to_string();
                    debug!(
                        kind = %node.identity.kind,
                        name = %node.identity.name,
                        uid = %uid,
                        owners = node.owners.len(),
                        "Added object to graph"
                    );
                    self.nodes.insert(uid, node);
                }
            }
        }

        Ok(())
    }

    /// Process soft ownership relationships
    ///
    /// Soft ownership is determined by naming conventions:
    /// - Secrets named `<cluster>-kubeconfig`, `<cluster>-ca`, etc.
    /// - Resources referencing Cluster by topology ref
    fn process_soft_ownership(&mut self) {
        // Collect cluster names first
        let cluster_names: Vec<(String, String)> = self
            .nodes
            .values()
            .filter(|n| n.identity.kind == "Cluster")
            .map(|n| (n.identity.name.clone(), n.uid().to_string()))
            .collect();

        // Find secrets that belong to clusters by naming convention
        let secret_owners: Vec<(String, String)> = self
            .nodes
            .values()
            .filter(|n| n.identity.kind == "Secret")
            .filter_map(|n| {
                let secret_name = &n.identity.name;
                // Check for common CAPI secret naming patterns
                for (cluster_name, cluster_uid) in &cluster_names {
                    if secret_name == &format!("{}-kubeconfig", cluster_name)
                        || secret_name == &format!("{}-ca", cluster_name)
                        || secret_name == &format!("{}-etcd", cluster_name)
                        || secret_name == &format!("{}-sa", cluster_name)
                        || secret_name.starts_with(&format!("{}-", cluster_name))
                    {
                        return Some((n.uid().to_string(), cluster_uid.clone()));
                    }
                }
                None
            })
            .collect();

        // Apply soft ownership
        for (secret_uid, cluster_uid) in secret_owners {
            if let Some(node) = self.nodes.get_mut(&secret_uid) {
                node.soft_owners.insert(cluster_uid.clone());
                debug!(
                    secret = %node.identity.name,
                    cluster_uid = %cluster_uid,
                    "Added soft ownership"
                );
            }
        }
    }

    /// Propagate force_move_hierarchy to all descendants
    fn propagate_force_move_hierarchy(&mut self) {
        // Build reverse ownership map (child -> parents)
        // and find all nodes with force_move_hierarchy
        let force_move_nodes: Vec<String> = self
            .nodes
            .values()
            .filter(|n| n.force_move_hierarchy)
            .map(|n| n.uid().to_string())
            .collect();

        // For each force_move node, mark all descendants
        for root_uid in force_move_nodes {
            self.mark_descendants_force_move(&root_uid);
        }
    }

    /// Mark all descendants of a node as force_move_hierarchy
    fn mark_descendants_force_move(&mut self, root_uid: &str) {
        // Find all nodes that have this root as an owner
        let children: Vec<String> = self
            .nodes
            .values()
            .filter(|n| n.all_owners().contains(root_uid))
            .map(|n| n.uid().to_string())
            .collect();

        for child_uid in children {
            if let Some(node) = self.nodes.get_mut(&child_uid) {
                if !node.force_move_hierarchy {
                    node.force_move_hierarchy = true;
                    // Recursively mark this node's descendants
                    self.mark_descendants_force_move(&child_uid);
                }
            }
        }
    }

    /// Filter the graph to only include objects related to a specific cluster
    pub fn filter_by_cluster(&mut self, cluster_name: &str) {
        // Find the cluster UID
        let cluster_uid = self
            .nodes
            .values()
            .find(|n| n.identity.kind == "Cluster" && n.identity.name == cluster_name)
            .map(|n| n.uid().to_string());

        let cluster_uid = match cluster_uid {
            Some(uid) => uid,
            None => {
                warn!(cluster = %cluster_name, "Cluster not found in graph");
                return;
            }
        };

        // Collect UIDs to keep (cluster and all descendants)
        let mut keep = HashSet::new();
        self.collect_descendants(&cluster_uid, &mut keep);

        // Also add any objects that are owners of kept objects
        let mut additional_keep = HashSet::new();
        for uid in &keep {
            if let Some(node) = self.nodes.get(uid) {
                additional_keep.extend(node.all_owners());
            }
        }
        keep.extend(additional_keep);

        // Remove nodes not in keep set
        self.nodes.retain(|uid, _| keep.contains(uid));

        debug!(
            cluster = %cluster_name,
            kept = keep.len(),
            "Filtered graph to cluster"
        );
    }

    /// Collect a node and all its descendants into a set
    fn collect_descendants(&self, uid: &str, collected: &mut HashSet<String>) {
        if collected.contains(uid) {
            return;
        }
        collected.insert(uid.to_string());

        // Find all nodes that have this node as an owner
        for node in self.nodes.values() {
            if node.all_owners().contains(uid) {
                self.collect_descendants(node.uid(), collected);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_node(uid: &str, kind: &str, name: &str, owners: Vec<&str>) -> GraphNode {
        GraphNode {
            identity: ObjectIdentity::new("test/v1", kind, "default", name, uid),
            object: serde_json::json!({"metadata": {"name": name, "uid": uid}}),
            owners: owners.into_iter().map(String::from).collect(),
            soft_owners: HashSet::new(),
            force_move_hierarchy: false,
            new_uid: None,
        }
    }

    #[test]
    fn test_object_identity_display() {
        let id = ObjectIdentity::new("v1", "Secret", "default", "my-secret", "uid-1");
        assert_eq!(id.display(), "Secret/default/my-secret");

        let cluster_id = ObjectIdentity::new("cluster.x-k8s.io/v1beta1", "Cluster", "", "my-cluster", "uid-2");
        assert_eq!(cluster_id.display(), "Cluster/my-cluster");
    }

    #[test]
    fn test_graph_node_all_owners() {
        let mut node = make_test_node("uid-1", "Machine", "machine-1", vec!["owner-1"]);
        node.soft_owners.insert("soft-owner-1".to_string());

        let all = node.all_owners();
        assert!(all.contains("owner-1"));
        assert!(all.contains("soft-owner-1"));
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_object_graph_basic_operations() {
        let mut graph = ObjectGraph::new("default");
        assert!(graph.is_empty());
        assert_eq!(graph.len(), 0);
        assert_eq!(graph.namespace(), "default");

        let node = make_test_node("uid-1", "Cluster", "test-cluster", vec![]);
        graph.insert(node);

        assert!(!graph.is_empty());
        assert_eq!(graph.len(), 1);
        assert!(graph.get("uid-1").is_some());
        assert!(graph.get("uid-2").is_none());
    }

    #[test]
    fn test_collect_descendants() {
        let mut graph = ObjectGraph::new("default");

        // Create a simple hierarchy: Cluster -> Machine -> DockerMachine
        let cluster = make_test_node("cluster-uid", "Cluster", "test-cluster", vec![]);
        let machine = make_test_node("machine-uid", "Machine", "test-machine", vec!["cluster-uid"]);
        let docker_machine = make_test_node(
            "docker-machine-uid",
            "DockerMachine",
            "test-docker-machine",
            vec!["machine-uid"],
        );

        graph.insert(cluster);
        graph.insert(machine);
        graph.insert(docker_machine);

        let mut collected = HashSet::new();
        graph.collect_descendants("cluster-uid", &mut collected);

        assert!(collected.contains("cluster-uid"));
        assert!(collected.contains("machine-uid"));
        assert!(collected.contains("docker-machine-uid"));
        assert_eq!(collected.len(), 3);
    }

    #[test]
    fn test_filter_by_cluster() {
        let mut graph = ObjectGraph::new("default");

        // Create two clusters with their own machines
        let cluster1 = make_test_node("cluster-1-uid", "Cluster", "cluster-1", vec![]);
        let machine1 = make_test_node("machine-1-uid", "Machine", "machine-1", vec!["cluster-1-uid"]);
        let cluster2 = make_test_node("cluster-2-uid", "Cluster", "cluster-2", vec![]);
        let machine2 = make_test_node("machine-2-uid", "Machine", "machine-2", vec!["cluster-2-uid"]);

        graph.insert(cluster1);
        graph.insert(machine1);
        graph.insert(cluster2);
        graph.insert(machine2);

        assert_eq!(graph.len(), 4);

        graph.filter_by_cluster("cluster-1");

        // Should only have cluster-1 and its machine
        assert_eq!(graph.len(), 2);
        assert!(graph.get("cluster-1-uid").is_some());
        assert!(graph.get("machine-1-uid").is_some());
        assert!(graph.get("cluster-2-uid").is_none());
        assert!(graph.get("machine-2-uid").is_none());
    }
}
