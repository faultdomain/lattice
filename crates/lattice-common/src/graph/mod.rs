//! Service Graph for Lattice
//!
//! This module implements a concurrent service dependency graph using DashMap.
//! It tracks services, their dependencies, and allowed callers for network
//! policy generation.
//!
//! The graph uses a multi-table adjacency list pattern similar to ETS in the Elixir POC:
//! - Vertices: Service nodes with metadata
//! - Edges Out: What services does this service call?
//! - Edges In: Who calls this service?
//! - Environment Index: Fast lookup of services by environment

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use dashmap::DashMap;

use crate::crd::{LatticeExternalServiceSpec, LatticeServiceSpec, ParsedEndpoint, Resolution};

/// Type of service node in the graph
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceType {
    /// Internal service managed by Lattice
    Local,
    /// External service defined via LatticeExternalService
    External,
    /// Placeholder for a service referenced but not yet defined
    Unknown,
}

/// A node in the service graph representing a service
#[derive(Clone, Debug)]
pub struct ServiceNode {
    /// Service name
    pub name: String,
    /// Type of service
    pub type_: ServiceType,
    /// Services this node depends on (outbound)
    pub dependencies: Vec<String>,
    /// Services allowed to call this node (inbound)
    pub allowed_callers: Vec<String>,
    /// Container image (for local services)
    pub image: Option<String>,
    /// Exposed ports: name -> port
    pub ports: BTreeMap<String, u16>,
    /// Parsed endpoints (for external services)
    pub endpoints: BTreeMap<String, ParsedEndpoint>,
    /// Resolution strategy (for external services)
    pub resolution: Option<Resolution>,
}

impl ServiceNode {
    /// Create a new local service node from a LatticeService spec
    pub fn from_service_spec(name: &str, spec: &LatticeServiceSpec) -> Self {
        Self {
            name: name.to_string(),
            type_: ServiceType::Local,
            dependencies: spec.dependencies().into_iter().map(String::from).collect(),
            allowed_callers: spec
                .allowed_callers()
                .into_iter()
                .map(String::from)
                .collect(),
            image: spec.primary_image().map(String::from),
            ports: spec
                .ports()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            endpoints: BTreeMap::new(),
            resolution: None,
        }
    }

    /// Create a new external service node from a LatticeExternalService spec
    pub fn from_external_spec(name: &str, spec: &LatticeExternalServiceSpec) -> Self {
        Self {
            name: name.to_string(),
            type_: ServiceType::External,
            dependencies: vec![],
            allowed_callers: spec.allowed_requesters.clone(),
            image: None,
            ports: BTreeMap::new(),
            endpoints: spec.valid_endpoints(),
            resolution: Some(spec.resolution.clone()),
        }
    }

    /// Create an unknown placeholder node
    pub fn unknown(name: &str) -> Self {
        Self {
            name: name.to_string(),
            type_: ServiceType::Unknown,
            dependencies: vec![],
            allowed_callers: vec![],
            image: None,
            ports: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            resolution: None,
        }
    }

    /// Check if this service allows a specific caller
    pub fn allows(&self, caller: &str) -> bool {
        self.allowed_callers.iter().any(|c| c == "*" || c == caller)
    }
}

/// An active edge in the service graph (bilateral agreement exists)
#[derive(Clone, Debug, PartialEq)]
pub struct ActiveEdge {
    /// Source service (caller)
    pub caller: String,
    /// Target service (callee)
    pub callee: String,
    /// Caller's ports
    pub caller_ports: BTreeMap<String, u16>,
    /// Callee's ports
    pub callee_ports: BTreeMap<String, u16>,
}

/// Composite key for graph lookups: (environment, service_name)
type GraphKey = (String, String);

/// Thread-safe service graph using DashMap
///
/// This implements the same patterns as the Elixir ETS-based Store:
/// - Separate maps for vertices, outgoing edges, and incoming edges
/// - O(1) lookups for dependencies and dependents
/// - Environment-scoped isolation
///
/// DashMap provides concurrent access without needing inner locks.
#[derive(Debug)]
pub struct ServiceGraph {
    /// Service nodes: (env, name) -> ServiceNode
    vertices: DashMap<GraphKey, ServiceNode>,

    /// Outgoing edges: (env, source) -> [targets]
    edges_out: DashMap<GraphKey, Vec<String>>,

    /// Incoming edges: (env, target) -> [sources]
    edges_in: DashMap<GraphKey, Vec<String>>,

    /// Environment index: env -> [service_names]
    env_index: DashMap<String, HashSet<String>>,
}

impl Default for ServiceGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceGraph {
    /// Create a new empty service graph
    pub fn new() -> Self {
        Self {
            vertices: DashMap::new(),
            edges_out: DashMap::new(),
            edges_in: DashMap::new(),
            env_index: DashMap::new(),
        }
    }

    /// Insert or update a local service in the graph
    pub fn put_service(&self, env: &str, name: &str, spec: &LatticeServiceSpec) {
        let node = ServiceNode::from_service_spec(name, spec);
        self.put_node(env, name, node);
    }

    /// Insert or update an external service in the graph
    pub fn put_external_service(&self, env: &str, name: &str, spec: &LatticeExternalServiceSpec) {
        let node = ServiceNode::from_external_spec(name, spec);
        self.put_node(env, name, node);
    }

    /// Internal: Insert a node and update all edge indices
    fn put_node(&self, env: &str, name: &str, node: ServiceNode) {
        let key = (env.to_string(), name.to_string());

        // Remove old edges if service existed
        self.remove_edges(env, name);

        // Store the node
        let dependencies = node.dependencies.clone();
        self.vertices.insert(key.clone(), node);

        // Update outgoing edges - use insert to avoid holding entry lock
        if !dependencies.is_empty() {
            self.edges_out.insert(key.clone(), dependencies.clone());

            // Update incoming edges for each dependency
            for dep in &dependencies {
                let dep_key = (env.to_string(), dep.clone());
                let name_clone = name.to_string();

                // Use alter for atomic update-or-insert
                self.edges_in
                    .entry(dep_key.clone())
                    .and_modify(|edges| edges.push(name_clone.clone()))
                    .or_insert_with(|| vec![name_clone]);

                // Create unknown stub if dependency doesn't exist
                if !self.vertices.contains_key(&dep_key) {
                    self.vertices.insert(dep_key, ServiceNode::unknown(dep));
                }
            }
        }

        // Update environment index - use entry for atomic update-or-insert
        let name_clone = name.to_string();
        self.env_index
            .entry(env.to_string())
            .and_modify(|index| {
                index.insert(name_clone.clone());
            })
            .or_insert_with(|| {
                let mut set = HashSet::new();
                set.insert(name_clone);
                set
            });
    }

    /// Remove a service from the graph
    pub fn delete_service(&self, env: &str, name: &str) {
        let key = (env.to_string(), name.to_string());

        // Remove outgoing edges (and clean up incoming refs in targets)
        self.remove_edges(env, name);

        // Remove incoming edges and clean up outgoing refs in sources
        if let Some((_, edges)) = self.edges_in.remove(&key) {
            for source in edges.iter() {
                let source_key = (env.to_string(), source.clone());
                if let Some(mut out_edges) = self.edges_out.get_mut(&source_key) {
                    out_edges.retain(|t| t != name);
                }
            }
        }

        // Remove vertex
        self.vertices.remove(&key);

        // Remove from environment index
        if let Some(mut index) = self.env_index.get_mut(env) {
            index.remove(name);
        }
    }

    /// Internal: Remove outgoing edges for a service (edges this service created)
    /// This does NOT remove incoming edges from other services - those are managed by those services.
    fn remove_edges(&self, env: &str, name: &str) {
        let key = (env.to_string(), name.to_string());

        // Remove outgoing edges and update incoming edges of targets
        if let Some((_, edges)) = self.edges_out.remove(&key) {
            for target in edges.iter() {
                let target_key = (env.to_string(), target.clone());
                if let Some(mut in_edges) = self.edges_in.get_mut(&target_key) {
                    in_edges.retain(|s| s != name);
                }
            }
        }
        // NOTE: We intentionally do NOT remove incoming edges here.
        // Those are managed by the services that created them.
    }

    /// Get a service node by environment and name
    pub fn get_service(&self, env: &str, name: &str) -> Option<ServiceNode> {
        let key = (env.to_string(), name.to_string());
        self.vertices.get(&key).map(|v| v.clone())
    }

    /// Get all services a service depends on (O(1))
    pub fn get_dependencies(&self, env: &str, name: &str) -> Vec<String> {
        let key = (env.to_string(), name.to_string());
        self.edges_out
            .get(&key)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Get all services that depend on this service (O(1))
    pub fn get_dependents(&self, env: &str, name: &str) -> Vec<String> {
        let key = (env.to_string(), name.to_string());
        self.edges_in
            .get(&key)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Get active inbound edges for a service (callers with bilateral agreement)
    pub fn get_active_inbound_edges(&self, env: &str, name: &str) -> Vec<ActiveEdge> {
        let Some(service) = self.get_service(env, name) else {
            return vec![];
        };

        self.get_dependents(env, name)
            .into_iter()
            .filter_map(|caller_name| {
                // Check if service allows this caller
                if !service.allows(&caller_name) {
                    return None;
                }

                // Get caller details
                let caller = self.get_service(env, &caller_name)?;
                if caller.type_ == ServiceType::Unknown {
                    return None;
                }

                Some(ActiveEdge {
                    caller: caller_name,
                    callee: name.to_string(),
                    caller_ports: caller.ports.clone(),
                    callee_ports: service.ports.clone(),
                })
            })
            .collect()
    }

    /// Get active outbound edges for a service (callees with bilateral agreement)
    pub fn get_active_outbound_edges(&self, env: &str, name: &str) -> Vec<ActiveEdge> {
        let Some(caller) = self.get_service(env, name) else {
            return vec![];
        };

        self.get_dependencies(env, name)
            .into_iter()
            .filter_map(|callee_name| {
                let callee = self.get_service(env, &callee_name)?;

                // For local services, check bilateral agreement
                if callee.type_ == ServiceType::Local && !callee.allows(name) {
                    return None;
                }

                // For external services, check if caller is allowed
                if callee.type_ == ServiceType::External && !callee.allows(name) {
                    return None;
                }

                // Skip unknown services
                if callee.type_ == ServiceType::Unknown {
                    return None;
                }

                Some(ActiveEdge {
                    caller: name.to_string(),
                    callee: callee_name,
                    caller_ports: caller.ports.clone(),
                    callee_ports: callee.ports.clone(),
                })
            })
            .collect()
    }

    /// Get all active edges in an environment (all bilateral agreements)
    ///
    /// This is optimized for performance by:
    /// 1. Iterating directly over edges_out instead of cloning all services
    /// 2. Avoiding redundant service lookups
    /// 3. Minimizing allocations
    pub fn list_active_edges(&self, env: &str) -> Vec<ActiveEdge> {
        // Pre-collect service names to avoid holding DashMap references during iteration
        let service_names: Vec<String> = self
            .env_index
            .get(env)
            .map(|index| index.iter().cloned().collect())
            .unwrap_or_default();

        let mut edges = Vec::new();

        for caller_name in service_names {
            let key = (env.to_string(), caller_name.clone());

            // Get caller node and its outbound edges in one lookup each
            let (caller_node, outbound) = match (self.vertices.get(&key), self.edges_out.get(&key))
            {
                (Some(node), Some(out)) => (node, out),
                _ => continue,
            };

            // Skip non-local services
            if caller_node.type_ != ServiceType::Local {
                continue;
            }

            // Cache caller ports for all edges from this caller
            let caller_ports = caller_node.ports.clone();

            for callee_name in outbound.iter() {
                let callee_key = (env.to_string(), callee_name.clone());
                let Some(callee) = self.vertices.get(&callee_key) else {
                    continue;
                };

                // Check bilateral agreement based on callee type
                let allowed = match callee.type_ {
                    ServiceType::Local | ServiceType::External => callee.allows(&caller_name),
                    ServiceType::Unknown => false,
                };

                if allowed {
                    edges.push(ActiveEdge {
                        caller: caller_name.clone(),
                        callee: callee_name.clone(),
                        caller_ports: caller_ports.clone(),
                        callee_ports: callee.ports.clone(),
                    });
                }
            }
        }

        edges
    }

    /// Get all services affected by a change to a service (transitive closure)
    pub fn get_affected_services(&self, env: &str, name: &str) -> HashSet<String> {
        let mut visited = HashSet::new();
        let mut stack = vec![name.to_string()];

        while let Some(current) = stack.pop() {
            if visited.insert(current.clone()) {
                for dependent in self.get_dependents(env, &current) {
                    stack.push(dependent);
                }
            }
        }

        visited
    }

    /// List all local services in an environment
    pub fn list_services(&self, env: &str) -> Vec<ServiceNode> {
        self.env_index
            .get(env)
            .map(|index| {
                index
                    .iter()
                    .filter_map(|name| {
                        let node = self.get_service(env, name)?;
                        if node.type_ == ServiceType::Local {
                            Some(node)
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// List all external services in an environment
    pub fn list_external_services(&self, env: &str) -> Vec<ServiceNode> {
        self.env_index
            .get(env)
            .map(|index| {
                index
                    .iter()
                    .filter_map(|name| {
                        let node = self.get_service(env, name)?;
                        if node.type_ == ServiceType::External {
                            Some(node)
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// List all environments with services
    pub fn list_environments(&self) -> Vec<String> {
        self.env_index
            .iter()
            .filter(|entry| !entry.value().is_empty())
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get count of services in an environment
    pub fn service_count(&self, env: &str) -> usize {
        self.env_index
            .get(env)
            .map(|index| index.len())
            .unwrap_or(0)
    }

    /// Clear all data from the graph
    pub fn clear(&self) {
        self.vertices.clear();
        self.edges_out.clear();
        self.edges_in.clear();
        self.env_index.clear();
    }
}

/// Thread-safe shared reference to a service graph
pub type SharedServiceGraph = Arc<ServiceGraph>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    // =========================================================================
    // Test Fixtures
    // =========================================================================

    fn make_service_spec(deps: Vec<&str>, callers: Vec<&str>) -> LatticeServiceSpec {
        use crate::crd::{
            ContainerSpec, DependencyDirection, DeploySpec, PortSpec, ReplicaSpec, ResourceSpec,
            ResourceType, ServicePortsSpec,
        };

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                command: None,
                args: None,
                variables: BTreeMap::new(),
                resources: None,
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
            },
        );

        let mut resources = BTreeMap::new();
        for dep in deps {
            resources.insert(
                dep.to_string(),
                ResourceSpec {
                    type_: ResourceType::Service,
                    direction: DependencyDirection::Outbound,
                    id: None,
                    class: None,
                    metadata: None,
                    params: None,
                },
            );
        }
        for caller in callers {
            resources.insert(
                caller.to_string(),
                ResourceSpec {
                    type_: ResourceType::Service,
                    direction: DependencyDirection::Inbound,
                    id: None,
                    class: None,
                    metadata: None,
                    params: None,
                },
            );
        }

        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 8080,
                target_port: None,
                protocol: None,
            },
        );

        LatticeServiceSpec {
            environment: "test".to_string(),
            containers,
            resources,
            service: Some(ServicePortsSpec { ports }),
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
        }
    }

    fn make_external_spec(allowed: Vec<&str>) -> LatticeExternalServiceSpec {
        use crate::crd::Resolution;

        LatticeExternalServiceSpec {
            environment: "test".to_string(),
            endpoints: BTreeMap::from([("api".to_string(), "https://api.example.com".to_string())]),
            allowed_requesters: allowed.into_iter().map(String::from).collect(),
            resolution: Resolution::Dns,
            description: None,
        }
    }

    // =========================================================================
    // Basic Operations Tests
    // =========================================================================

    #[test]
    fn test_put_and_get_service() {
        let graph = ServiceGraph::new();
        let spec = make_service_spec(vec![], vec![]);

        graph.put_service("prod", "api", &spec);

        let node = graph.get_service("prod", "api").unwrap();
        assert_eq!(node.name, "api");
        assert_eq!(node.type_, ServiceType::Local);
    }

    #[test]
    fn test_put_and_get_external_service() {
        let graph = ServiceGraph::new();
        let spec = make_external_spec(vec!["api"]);

        graph.put_external_service("prod", "google", &spec);

        let node = graph.get_service("prod", "google").unwrap();
        assert_eq!(node.name, "google");
        assert_eq!(node.type_, ServiceType::External);
        assert!(node.allows("api"));
    }

    #[test]
    fn test_delete_service() {
        let graph = ServiceGraph::new();
        let spec = make_service_spec(vec![], vec![]);

        graph.put_service("prod", "api", &spec);
        assert!(graph.get_service("prod", "api").is_some());

        graph.delete_service("prod", "api");
        assert!(graph.get_service("prod", "api").is_none());
    }

    // =========================================================================
    // Dependency Edge Tests
    // =========================================================================

    #[test]
    fn test_dependencies_and_dependents() {
        let graph = ServiceGraph::new();

        // api depends on cache
        let api_spec = make_service_spec(vec!["cache"], vec![]);
        graph.put_service("prod", "api", &api_spec);

        // cache allows api
        let cache_spec = make_service_spec(vec![], vec!["api"]);
        graph.put_service("prod", "cache", &cache_spec);

        // Check dependencies
        assert_eq!(graph.get_dependencies("prod", "api"), vec!["cache"]);
        assert!(graph.get_dependencies("prod", "cache").is_empty());

        // Check dependents
        assert!(graph.get_dependents("prod", "api").is_empty());
        assert_eq!(graph.get_dependents("prod", "cache"), vec!["api"]);
    }

    #[test]
    fn test_unknown_stub_creation() {
        let graph = ServiceGraph::new();

        // api depends on cache, but cache doesn't exist yet
        let api_spec = make_service_spec(vec!["cache"], vec![]);
        graph.put_service("prod", "api", &api_spec);

        // cache should exist as unknown stub
        let cache = graph.get_service("prod", "cache").unwrap();
        assert_eq!(cache.type_, ServiceType::Unknown);
    }

    // =========================================================================
    // Active Edge Tests (Bilateral Agreement)
    // =========================================================================

    #[test]
    fn test_active_inbound_edges() {
        let graph = ServiceGraph::new();

        // api allows caller
        let api_spec = make_service_spec(vec![], vec!["caller"]);
        graph.put_service("prod", "api", &api_spec);

        // caller depends on api
        let caller_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service("prod", "caller", &caller_spec);

        // Should have active inbound edge (bilateral agreement)
        let edges = graph.get_active_inbound_edges("prod", "api");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].caller, "caller");
        assert_eq!(edges[0].callee, "api");
    }

    #[test]
    fn test_no_active_edge_without_bilateral_agreement() {
        let graph = ServiceGraph::new();

        // api does NOT allow caller
        let api_spec = make_service_spec(vec![], vec![]);
        graph.put_service("prod", "api", &api_spec);

        // caller depends on api
        let caller_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service("prod", "caller", &caller_spec);

        // No active edge - api doesn't allow caller
        let edges = graph.get_active_inbound_edges("prod", "api");
        assert!(edges.is_empty());
    }

    #[test]
    fn test_active_outbound_edges() {
        let graph = ServiceGraph::new();

        // caller depends on api
        let caller_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service("prod", "caller", &caller_spec);

        // api allows caller
        let api_spec = make_service_spec(vec![], vec!["caller"]);
        graph.put_service("prod", "api", &api_spec);

        // Should have active outbound edge
        let edges = graph.get_active_outbound_edges("prod", "caller");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].caller, "caller");
        assert_eq!(edges[0].callee, "api");
    }

    #[test]
    fn test_external_service_active_edge() {
        let graph = ServiceGraph::new();

        // api depends on google
        let api_spec = make_service_spec(vec!["google"], vec![]);
        graph.put_service("prod", "api", &api_spec);

        // google allows api
        let google_spec = make_external_spec(vec!["api"]);
        graph.put_external_service("prod", "google", &google_spec);

        // Should have active outbound edge
        let edges = graph.get_active_outbound_edges("prod", "api");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].callee, "google");
    }

    // =========================================================================
    // Transitive Closure Tests
    // =========================================================================

    #[test]
    fn test_affected_services() {
        let graph = ServiceGraph::new();

        // frontend -> api -> cache
        let frontend_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service("prod", "frontend", &frontend_spec);

        let api_spec = make_service_spec(vec!["cache"], vec!["frontend"]);
        graph.put_service("prod", "api", &api_spec);

        let cache_spec = make_service_spec(vec![], vec!["api"]);
        graph.put_service("prod", "cache", &cache_spec);

        // Change to cache affects: cache, api, frontend
        let affected = graph.get_affected_services("prod", "cache");
        assert!(affected.contains("cache"));
        assert!(affected.contains("api"));
        assert!(affected.contains("frontend"));
        assert_eq!(affected.len(), 3);
    }

    // =========================================================================
    // List Operations Tests
    // =========================================================================

    #[test]
    fn test_list_services() {
        let graph = ServiceGraph::new();

        graph.put_service("prod", "api", &make_service_spec(vec![], vec![]));
        graph.put_service("prod", "worker", &make_service_spec(vec![], vec![]));
        graph.put_external_service("prod", "google", &make_external_spec(vec![]));

        let services = graph.list_services("prod");
        assert_eq!(services.len(), 2);

        let names: HashSet<_> = services.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains("api"));
        assert!(names.contains("worker"));
    }

    #[test]
    fn test_list_external_services() {
        let graph = ServiceGraph::new();

        graph.put_service("prod", "api", &make_service_spec(vec![], vec![]));
        graph.put_external_service("prod", "google", &make_external_spec(vec![]));
        graph.put_external_service("prod", "stripe", &make_external_spec(vec![]));

        let external = graph.list_external_services("prod");
        assert_eq!(external.len(), 2);

        let names: HashSet<_> = external.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains("google"));
        assert!(names.contains("stripe"));
    }

    #[test]
    fn test_list_environments() {
        let graph = ServiceGraph::new();

        graph.put_service("prod", "api", &make_service_spec(vec![], vec![]));
        graph.put_service("staging", "api", &make_service_spec(vec![], vec![]));

        let envs = graph.list_environments();
        assert!(envs.contains(&"prod".to_string()));
        assert!(envs.contains(&"staging".to_string()));
    }

    // =========================================================================
    // Environment Isolation Tests
    // =========================================================================

    #[test]
    fn test_environment_isolation() {
        let graph = ServiceGraph::new();

        // Same service name in different environments
        let spec = make_service_spec(vec![], vec![]);
        graph.put_service("prod", "api", &spec);
        graph.put_service("staging", "api", &spec);

        // Should be separate nodes
        assert!(graph.get_service("prod", "api").is_some());
        assert!(graph.get_service("staging", "api").is_some());

        // Deleting one doesn't affect the other
        graph.delete_service("prod", "api");
        assert!(graph.get_service("prod", "api").is_none());
        assert!(graph.get_service("staging", "api").is_some());
    }

    // =========================================================================
    // Edge Cleanup Tests
    // =========================================================================

    #[test]
    fn test_edges_cleaned_on_delete() {
        let graph = ServiceGraph::new();

        // api depends on cache
        let api_spec = make_service_spec(vec!["cache"], vec![]);
        graph.put_service("prod", "api", &api_spec);

        let cache_spec = make_service_spec(vec![], vec!["api"]);
        graph.put_service("prod", "cache", &cache_spec);

        assert_eq!(graph.get_dependents("prod", "cache"), vec!["api"]);

        // Delete api
        graph.delete_service("prod", "api");

        // cache should no longer have api as dependent
        assert!(graph.get_dependents("prod", "cache").is_empty());
    }

    #[test]
    fn test_edges_updated_on_service_update() {
        let graph = ServiceGraph::new();

        // api depends on cache
        let api_spec = make_service_spec(vec!["cache"], vec![]);
        graph.put_service("prod", "api", &api_spec);

        assert_eq!(graph.get_dependencies("prod", "api"), vec!["cache"]);

        // Update api to depend on redis instead
        let api_spec_v2 = make_service_spec(vec!["redis"], vec![]);
        graph.put_service("prod", "api", &api_spec_v2);

        assert_eq!(graph.get_dependencies("prod", "api"), vec!["redis"]);
        // cache should no longer have api as dependent
        assert!(graph.get_dependents("prod", "cache").is_empty());
    }

    // =========================================================================
    // Concurrency Tests
    // =========================================================================

    #[test]
    fn test_concurrent_access() {
        use std::thread;

        let graph = Arc::new(ServiceGraph::new());
        let mut handles = vec![];

        // Spawn multiple writers
        for i in 0..10 {
            let g = Arc::clone(&graph);
            handles.push(thread::spawn(move || {
                let spec = make_service_spec(vec![], vec![]);
                g.put_service("prod", &format!("service-{}", i), &spec);
            }));
        }

        // Spawn readers
        for _ in 0..10 {
            let g = Arc::clone(&graph);
            handles.push(thread::spawn(move || {
                let _ = g.list_services("prod");
                let _ = g.service_count("prod");
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(graph.service_count("prod"), 10);
    }

    // =========================================================================
    // Edge Case Tests
    // =========================================================================

    #[test]
    fn test_get_nonexistent_service() {
        let graph = ServiceGraph::new();
        assert!(graph.get_service("prod", "nonexistent").is_none());
    }

    #[test]
    fn test_get_dependencies_nonexistent_service() {
        let graph = ServiceGraph::new();
        assert!(graph.get_dependencies("prod", "nonexistent").is_empty());
    }

    #[test]
    fn test_get_dependents_nonexistent_service() {
        let graph = ServiceGraph::new();
        assert!(graph.get_dependents("prod", "nonexistent").is_empty());
    }

    #[test]
    fn test_delete_nonexistent_service() {
        let graph = ServiceGraph::new();
        // Should not panic
        graph.delete_service("prod", "nonexistent");
    }

    #[test]
    fn test_empty_graph_operations() {
        let graph = ServiceGraph::new();

        assert!(graph.list_services("prod").is_empty());
        assert!(graph.list_external_services("prod").is_empty());
        assert!(graph.list_environments().is_empty());
        assert_eq!(graph.service_count("prod"), 0);
        assert!(graph.get_active_inbound_edges("prod", "api").is_empty());
        assert!(graph.get_active_outbound_edges("prod", "api").is_empty());
        assert!(graph.list_active_edges("prod").is_empty());
    }

    #[test]
    fn test_clear_graph() {
        let graph = ServiceGraph::new();

        graph.put_service("prod", "api", &make_service_spec(vec!["cache"], vec![]));
        graph.put_service("prod", "cache", &make_service_spec(vec![], vec!["api"]));
        graph.put_external_service("prod", "google", &make_external_spec(vec!["api"]));

        assert_eq!(graph.service_count("prod"), 3);

        graph.clear();

        assert_eq!(graph.service_count("prod"), 0);
        assert!(graph.list_environments().is_empty());
        assert!(graph.get_service("prod", "api").is_none());
    }

    #[test]
    fn test_service_with_no_dependencies_or_callers() {
        let graph = ServiceGraph::new();
        let spec = make_service_spec(vec![], vec![]);

        graph.put_service("prod", "standalone", &spec);

        let node = graph.get_service("prod", "standalone").unwrap();
        assert!(node.dependencies.is_empty());
        assert!(node.allowed_callers.is_empty());
        assert!(graph.get_dependencies("prod", "standalone").is_empty());
        assert!(graph.get_dependents("prod", "standalone").is_empty());
    }

    // =========================================================================
    // Complex Graph Topology Tests
    // =========================================================================

    #[test]
    fn test_diamond_dependency_pattern() {
        let graph = ServiceGraph::new();

        // Diamond: frontend -> api, frontend -> worker -> api
        //             |                           |
        //             +-----------+---------------+
        //                         v
        //                       cache

        graph.put_service(
            "prod",
            "cache",
            &make_service_spec(vec![], vec!["api", "worker"]),
        );
        graph.put_service(
            "prod",
            "api",
            &make_service_spec(vec!["cache"], vec!["frontend"]),
        );
        graph.put_service(
            "prod",
            "worker",
            &make_service_spec(vec!["cache"], vec!["frontend"]),
        );
        graph.put_service(
            "prod",
            "frontend",
            &make_service_spec(vec!["api", "worker"], vec![]),
        );

        // Check diamond edges
        let frontend_deps = graph.get_dependencies("prod", "frontend");
        assert!(frontend_deps.contains(&"api".to_string()));
        assert!(frontend_deps.contains(&"worker".to_string()));

        let cache_dependents = graph.get_dependents("prod", "cache");
        assert!(cache_dependents.contains(&"api".to_string()));
        assert!(cache_dependents.contains(&"worker".to_string()));
    }

    #[test]
    fn test_circular_dependency() {
        let graph = ServiceGraph::new();

        // Circular: a -> b -> c -> a
        graph.put_service("prod", "a", &make_service_spec(vec!["b"], vec!["c"]));
        graph.put_service("prod", "b", &make_service_spec(vec!["c"], vec!["a"]));
        graph.put_service("prod", "c", &make_service_spec(vec!["a"], vec!["b"]));

        // All should have active edges in a cycle
        let edges_a = graph.get_active_outbound_edges("prod", "a");
        let edges_b = graph.get_active_outbound_edges("prod", "b");
        let edges_c = graph.get_active_outbound_edges("prod", "c");

        assert_eq!(edges_a.len(), 1);
        assert_eq!(edges_b.len(), 1);
        assert_eq!(edges_c.len(), 1);

        // Affected services for circular should include all
        let affected = graph.get_affected_services("prod", "a");
        assert!(affected.contains("a"));
        assert!(affected.contains("b"));
        assert!(affected.contains("c"));
    }

    #[test]
    fn test_many_to_one_dependency() {
        let graph = ServiceGraph::new();

        // Many services depend on one
        graph.put_service("prod", "shared", &make_service_spec(vec![], vec!["*"]));

        for i in 0..10 {
            let name = format!("client-{}", i);
            graph.put_service("prod", &name, &make_service_spec(vec!["shared"], vec![]));
        }

        // shared should have 10 dependents
        let dependents = graph.get_dependents("prod", "shared");
        assert_eq!(dependents.len(), 10);

        // All should have active edges due to wildcard
        let edges = graph.get_active_inbound_edges("prod", "shared");
        assert_eq!(edges.len(), 10);
    }

    #[test]
    fn test_one_to_many_dependency() {
        let graph = ServiceGraph::new();

        // One service depends on many
        let mut deps = vec![];
        for i in 0..10 {
            let name = format!("dep-{}", i);
            deps.push(name.clone());
            graph.put_service(
                "prod",
                &name,
                &make_service_spec(vec![], vec!["orchestrator"]),
            );
        }

        let dep_refs: Vec<&str> = deps.iter().map(|s| s.as_str()).collect();
        graph.put_service("prod", "orchestrator", &make_service_spec(dep_refs, vec![]));

        // orchestrator should have 10 dependencies
        let dependencies = graph.get_dependencies("prod", "orchestrator");
        assert_eq!(dependencies.len(), 10);

        // All should have active edges
        let edges = graph.get_active_outbound_edges("prod", "orchestrator");
        assert_eq!(edges.len(), 10);
    }

    // =========================================================================
    // Bilateral Agreement Edge Cases
    // =========================================================================

    #[test]
    fn test_wildcard_allows_all() {
        let graph = ServiceGraph::new();

        graph.put_service("prod", "public-api", &make_service_spec(vec![], vec!["*"]));
        graph.put_service(
            "prod",
            "random-service",
            &make_service_spec(vec!["public-api"], vec![]),
        );

        let edges = graph.get_active_outbound_edges("prod", "random-service");
        assert_eq!(edges.len(), 1);
    }

    #[test]
    fn test_specific_caller_only() {
        let graph = ServiceGraph::new();

        graph.put_service(
            "prod",
            "private-api",
            &make_service_spec(vec![], vec!["allowed-service"]),
        );
        graph.put_service(
            "prod",
            "allowed-service",
            &make_service_spec(vec!["private-api"], vec![]),
        );
        graph.put_service(
            "prod",
            "blocked-service",
            &make_service_spec(vec!["private-api"], vec![]),
        );

        // allowed-service should have access
        let allowed_edges = graph.get_active_outbound_edges("prod", "allowed-service");
        assert_eq!(allowed_edges.len(), 1);

        // blocked-service should NOT have access
        let blocked_edges = graph.get_active_outbound_edges("prod", "blocked-service");
        assert!(blocked_edges.is_empty());
    }

    #[test]
    fn test_external_service_access_control() {
        let graph = ServiceGraph::new();

        graph.put_external_service(
            "prod",
            "stripe",
            &make_external_spec(vec!["payment-service"]),
        );
        graph.put_service(
            "prod",
            "payment-service",
            &make_service_spec(vec!["stripe"], vec![]),
        );
        graph.put_service(
            "prod",
            "random-service",
            &make_service_spec(vec!["stripe"], vec![]),
        );

        // payment-service has access to stripe
        let payment_edges = graph.get_active_outbound_edges("prod", "payment-service");
        assert_eq!(payment_edges.len(), 1);

        // random-service does NOT have access
        let random_edges = graph.get_active_outbound_edges("prod", "random-service");
        assert!(random_edges.is_empty());
    }

    // =========================================================================
    // Service Update Tests
    // =========================================================================

    #[test]
    fn test_update_service_dependencies() {
        let graph = ServiceGraph::new();

        // Initial: api -> cache, redis
        graph.put_service(
            "prod",
            "api",
            &make_service_spec(vec!["cache", "redis"], vec![]),
        );

        assert_eq!(graph.get_dependencies("prod", "api").len(), 2);

        // Update: api -> cache only
        graph.put_service("prod", "api", &make_service_spec(vec!["cache"], vec![]));

        let deps = graph.get_dependencies("prod", "api");
        assert_eq!(deps.len(), 1);
        assert!(deps.contains(&"cache".to_string()));
        assert!(!deps.contains(&"redis".to_string()));
    }

    #[test]
    fn test_update_service_callers() {
        let graph = ServiceGraph::new();

        // Initial: api allows frontend, mobile
        graph.put_service(
            "prod",
            "api",
            &make_service_spec(vec![], vec!["frontend", "mobile"]),
        );

        // Update: api allows only frontend
        graph.put_service("prod", "api", &make_service_spec(vec![], vec!["frontend"]));

        let node = graph.get_service("prod", "api").unwrap();
        assert!(node.allows("frontend"));
        assert!(!node.allows("mobile"));
    }

    #[test]
    fn test_convert_local_to_external() {
        let graph = ServiceGraph::new();

        // Start as local service
        graph.put_service("prod", "service", &make_service_spec(vec![], vec![]));
        assert_eq!(
            graph.get_service("prod", "service").unwrap().type_,
            ServiceType::Local
        );

        // Convert to external
        graph.put_external_service("prod", "service", &make_external_spec(vec![]));
        assert_eq!(
            graph.get_service("prod", "service").unwrap().type_,
            ServiceType::External
        );
    }

    // =========================================================================
    // List Active Edges Tests
    // =========================================================================

    #[test]
    fn test_list_active_edges_empty() {
        let graph = ServiceGraph::new();

        // Services exist but no bilateral agreements
        graph.put_service("prod", "api", &make_service_spec(vec!["cache"], vec![]));
        graph.put_service("prod", "cache", &make_service_spec(vec![], vec![])); // doesn't allow api

        let edges = graph.list_active_edges("prod");
        assert!(edges.is_empty());
    }

    #[test]
    fn test_list_active_edges_with_agreements() {
        let graph = ServiceGraph::new();

        graph.put_service(
            "prod",
            "api",
            &make_service_spec(vec!["cache"], vec!["frontend"]),
        );
        graph.put_service("prod", "cache", &make_service_spec(vec![], vec!["api"]));
        graph.put_service("prod", "frontend", &make_service_spec(vec!["api"], vec![]));

        let edges = graph.list_active_edges("prod");
        assert_eq!(edges.len(), 2); // api->cache, frontend->api
    }

    // =========================================================================
    // ServiceNode Tests
    // =========================================================================

    #[test]
    fn test_service_node_allows_wildcard() {
        let node = ServiceNode {
            name: "test".to_string(),
            type_: ServiceType::Local,
            dependencies: vec![],
            allowed_callers: vec!["*".to_string()],
            image: None,
            ports: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            resolution: None,
        };

        assert!(node.allows("any-service"));
        assert!(node.allows("another-service"));
    }

    #[test]
    fn test_service_node_allows_specific() {
        let node = ServiceNode {
            name: "test".to_string(),
            type_: ServiceType::Local,
            dependencies: vec![],
            allowed_callers: vec!["allowed".to_string()],
            image: None,
            ports: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            resolution: None,
        };

        assert!(node.allows("allowed"));
        assert!(!node.allows("not-allowed"));
    }

    #[test]
    fn test_service_node_empty_callers_denies_all() {
        let node = ServiceNode {
            name: "test".to_string(),
            type_: ServiceType::Local,
            dependencies: vec![],
            allowed_callers: vec![],
            image: None,
            ports: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            resolution: None,
        };

        assert!(!node.allows("any-service"));
    }

    // =========================================================================
    // Stress Tests
    // =========================================================================

    #[test]
    fn test_large_graph() {
        let graph = ServiceGraph::new();

        // Create 100 services
        for i in 0..100 {
            let name = format!("service-{}", i);
            let deps: Vec<String> = if i > 0 {
                vec![format!("service-{}", i - 1)]
            } else {
                vec![]
            };
            let dep_refs: Vec<&str> = deps.iter().map(|s| s.as_str()).collect();
            graph.put_service("prod", &name, &make_service_spec(dep_refs, vec!["*"]));
        }

        assert_eq!(graph.service_count("prod"), 100);

        // Verify chain
        let deps = graph.get_dependencies("prod", "service-99");
        assert_eq!(deps, vec!["service-98"]);

        // Affected services for service-0 should include all 100
        let affected = graph.get_affected_services("prod", "service-0");
        assert_eq!(affected.len(), 100);
    }

    #[test]
    fn test_many_environments() {
        let graph = ServiceGraph::new();

        for env in 0..50 {
            let env_name = format!("env-{}", env);
            for svc in 0..10 {
                let svc_name = format!("service-{}", svc);
                graph.put_service(&env_name, &svc_name, &make_service_spec(vec![], vec![]));
            }
        }

        let envs = graph.list_environments();
        assert_eq!(envs.len(), 50);

        for env in 0..50 {
            let env_name = format!("env-{}", env);
            assert_eq!(graph.service_count(&env_name), 10);
        }
    }

    // =========================================================================
    // Concurrent Stress Tests
    // =========================================================================

    #[test]
    fn test_concurrent_writes_and_reads() {
        use std::thread;

        let graph = Arc::new(ServiceGraph::new());
        let mut handles = vec![];

        // Writers that add services
        for i in 0..20 {
            let g = Arc::clone(&graph);
            handles.push(thread::spawn(move || {
                for j in 0..50 {
                    let spec = make_service_spec(vec![], vec![]);
                    g.put_service("prod", &format!("svc-{}-{}", i, j), &spec);
                }
            }));
        }

        // Readers
        for _ in 0..10 {
            let g = Arc::clone(&graph);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = g.list_services("prod");
                    let _ = g.service_count("prod");
                    let _ = g.get_dependencies("prod", "svc-0-0");
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should have 20 * 50 = 1000 services
        assert_eq!(graph.service_count("prod"), 1000);
    }

    #[test]
    fn test_concurrent_delete_and_read() {
        use std::thread;

        let graph = Arc::new(ServiceGraph::new());

        // Add services first
        for i in 0..100 {
            graph.put_service(
                "prod",
                &format!("svc-{}", i),
                &make_service_spec(vec![], vec![]),
            );
        }

        let mut handles = vec![];

        // Deleters
        for i in 0..50 {
            let g = Arc::clone(&graph);
            handles.push(thread::spawn(move || {
                g.delete_service("prod", &format!("svc-{}", i));
            }));
        }

        // Readers (should not panic even if service is deleted mid-read)
        for _ in 0..50 {
            let g = Arc::clone(&graph);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    let _ = g.get_service("prod", &format!("svc-{}", i));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should have 50 services remaining
        assert_eq!(graph.service_count("prod"), 50);
    }

    // =========================================================================
    // Default Impl and Edge Case Tests
    // =========================================================================

    #[test]
    fn test_default_impl() {
        let graph: ServiceGraph = Default::default();
        assert_eq!(graph.service_count("any"), 0);
    }

    #[test]
    fn test_delete_service_cleans_incoming_edges() {
        let graph = ServiceGraph::new();

        // api -> cache (api depends on cache)
        // worker -> cache (worker also depends on cache)
        let api_spec = make_service_spec(vec!["cache"], vec![]);
        graph.put_service("prod", "api", &api_spec);

        let worker_spec = make_service_spec(vec!["cache"], vec![]);
        graph.put_service("prod", "worker", &worker_spec);

        let cache_spec = make_service_spec(vec![], vec!["api", "worker"]);
        graph.put_service("prod", "cache", &cache_spec);

        // cache has both api and worker as dependents
        let deps = graph.get_dependents("prod", "cache");
        assert_eq!(deps.len(), 2);

        // Delete cache - should clean up outgoing edges from api and worker
        graph.delete_service("prod", "cache");

        // api and worker should no longer list cache as dependency
        assert!(graph.get_dependencies("prod", "api").is_empty());
        assert!(graph.get_dependencies("prod", "worker").is_empty());
    }

    #[test]
    fn test_active_edges_skip_nonexistent_callee() {
        let graph = ServiceGraph::new();

        // api depends on cache, but cache doesn't exist
        let api_spec = make_service_spec(vec!["cache"], vec![]);
        graph.put_service("prod", "api", &api_spec);

        // Should return empty - callee doesn't exist
        let edges = graph.get_active_outbound_edges("prod", "api");
        assert!(edges.is_empty());
    }
}
