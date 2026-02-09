//! Service Graph for Lattice
//!
//! This module implements a concurrent service dependency graph using DashMap.
//! It tracks services, their dependencies, and allowed callers for network
//! policy generation.
//!
//! The graph supports cross-namespace dependencies where services in one namespace
//! can declare dependencies on services in other namespaces.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use dashmap::DashMap;
use tracing::warn;

use crate::crd::{LatticeExternalServiceSpec, LatticeServiceSpec, ParsedEndpoint, Resolution};

/// Fully qualified service reference: (namespace, name)
pub type QualifiedName = (String, String);

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
    /// Service namespace
    pub namespace: String,
    /// Service name
    pub name: String,
    /// Type of service
    pub type_: ServiceType,
    /// Services this node depends on (outbound) - fully qualified
    pub dependencies: Vec<QualifiedName>,
    /// Services allowed to call this node (inbound) - fully qualified
    pub allowed_callers: HashSet<QualifiedName>,
    /// Whether this service allows all callers (wildcard "*")
    pub allows_all: bool,
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
    pub fn from_service_spec(namespace: &str, name: &str, spec: &LatticeServiceSpec) -> Self {
        let caller_refs = spec.workload.allowed_callers(namespace);
        let allows_all = caller_refs.iter().any(|r| r.name == "*");

        // When allows_all is true, the explicit caller list is irrelevant
        let allowed_callers: HashSet<QualifiedName> = if allows_all {
            HashSet::new()
        } else {
            caller_refs
                .into_iter()
                .map(|r| (r.resolve_namespace(namespace).to_string(), r.name))
                .collect()
        };

        let dependencies: Vec<QualifiedName> = spec
            .workload
            .dependencies(namespace)
            .into_iter()
            .map(|r| (r.resolve_namespace(namespace).to_string(), r.name))
            .collect();

        Self {
            namespace: namespace.to_string(),
            name: name.to_string(),
            type_: ServiceType::Local,
            dependencies,
            allowed_callers,
            allows_all,
            image: spec.workload.primary_image().map(String::from),
            ports: spec
                .workload
                .ports()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            endpoints: BTreeMap::new(),
            resolution: None,
        }
    }

    /// Create a new external service node from a LatticeExternalService spec
    pub fn from_external_spec(
        namespace: &str,
        name: &str,
        spec: &LatticeExternalServiceSpec,
    ) -> Self {
        let allows_all = spec.allowed_requesters.iter().any(|c| c == "*");

        // When allows_all is true, the explicit caller list is irrelevant.
        // External services specify callers by name only - assumed same namespace.
        let allowed_callers: HashSet<QualifiedName> = if allows_all {
            HashSet::new()
        } else {
            spec.allowed_requesters
                .iter()
                .map(|caller| (namespace.to_string(), caller.clone()))
                .collect()
        };

        Self {
            namespace: namespace.to_string(),
            name: name.to_string(),
            type_: ServiceType::External,
            dependencies: vec![],
            allowed_callers,
            allows_all,
            image: None,
            ports: BTreeMap::new(),
            endpoints: spec.valid_endpoints(),
            resolution: Some(spec.resolution.clone()),
        }
    }

    /// Create an unknown placeholder node
    pub fn unknown(namespace: &str, name: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
            name: name.to_string(),
            type_: ServiceType::Unknown,
            dependencies: vec![],
            allowed_callers: HashSet::new(),
            allows_all: false,
            image: None,
            ports: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            resolution: None,
        }
    }

    /// Check if this service allows a specific caller (O(1) lookup)
    pub fn allows(&self, caller_namespace: &str, caller_name: &str) -> bool {
        self.allows_all
            || self
                .allowed_callers
                .contains(&(caller_namespace.to_string(), caller_name.to_string()))
    }
}

/// An active edge in the service graph (bilateral agreement exists)
#[derive(Clone, Debug, PartialEq)]
pub struct ActiveEdge {
    /// Source service namespace
    pub caller_namespace: String,
    /// Source service name
    pub caller_name: String,
    /// Target service namespace
    pub callee_namespace: String,
    /// Target service name
    pub callee_name: String,
    /// Caller's ports
    pub caller_ports: BTreeMap<String, u16>,
    /// Callee's ports
    pub callee_ports: BTreeMap<String, u16>,
}

/// Thread-safe service graph using DashMap
///
/// Supports cross-namespace dependencies where services can depend on
/// services in other namespaces.
#[derive(Debug)]
pub struct ServiceGraph {
    /// Service nodes: (namespace, name) -> ServiceNode
    vertices: DashMap<QualifiedName, ServiceNode>,

    /// Outgoing edges: (namespace, name) -> [(target_ns, target_name)]
    edges_out: DashMap<QualifiedName, Vec<QualifiedName>>,

    /// Incoming edges: (namespace, name) -> [(source_ns, source_name)]
    edges_in: DashMap<QualifiedName, Vec<QualifiedName>>,

    /// Namespace index: namespace -> [service_names]
    ns_index: DashMap<String, HashSet<String>>,
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
            ns_index: DashMap::new(),
        }
    }

    /// Insert or update a local service in the graph
    pub fn put_service(&self, namespace: &str, name: &str, spec: &LatticeServiceSpec) {
        let node = ServiceNode::from_service_spec(namespace, name, spec);
        self.put_node(node);
    }

    /// Insert or update an external service in the graph
    pub fn put_external_service(
        &self,
        namespace: &str,
        name: &str,
        spec: &LatticeExternalServiceSpec,
    ) {
        let node = ServiceNode::from_external_spec(namespace, name, spec);
        self.put_node(node);
    }

    /// Internal: Insert a node and update all edge indices
    fn put_node(&self, node: ServiceNode) {
        let key = (node.namespace.clone(), node.name.clone());

        // Remove old edges if service existed
        self.remove_edges(&node.namespace, &node.name);

        // Clone dependencies before moving node
        let dependencies = node.dependencies.clone();
        let namespace = node.namespace.clone();
        let name = node.name.clone();

        // Store the node
        self.vertices.insert(key.clone(), node);

        // Update outgoing edges
        if !dependencies.is_empty() {
            self.edges_out.insert(key.clone(), dependencies.clone());

            // Update incoming edges for each dependency
            for (dep_ns, dep_name) in &dependencies {
                let dep_key = (dep_ns.clone(), dep_name.clone());
                let source_key = (namespace.clone(), name.clone());

                self.edges_in
                    .entry(dep_key.clone())
                    .and_modify(|edges| {
                        if !edges.contains(&source_key) {
                            edges.push(source_key.clone());
                        }
                    })
                    .or_insert_with(|| vec![source_key]);

                // Create unknown stub if dependency doesn't exist
                if !self.vertices.contains_key(&dep_key) {
                    self.vertices
                        .insert(dep_key, ServiceNode::unknown(dep_ns, dep_name));
                }
            }
        }

        // Update namespace index
        self.ns_index
            .entry(namespace.clone())
            .and_modify(|index| {
                index.insert(name.clone());
            })
            .or_insert_with(|| {
                let mut set = HashSet::new();
                set.insert(name);
                set
            });
    }

    /// Remove a service from the graph
    pub fn delete_service(&self, namespace: &str, name: &str) {
        let key = (namespace.to_string(), name.to_string());

        // Remove outgoing edges (and clean up incoming refs in targets)
        self.remove_edges(namespace, name);

        // Remove incoming edges and clean up outgoing refs in sources
        if let Some((_, edges)) = self.edges_in.remove(&key) {
            for (source_ns, source_name) in edges.iter() {
                let source_key = (source_ns.clone(), source_name.clone());
                if let Some(mut out_edges) = self.edges_out.get_mut(&source_key) {
                    out_edges.retain(|(ns, n)| ns != namespace || n != name);
                }
            }
        }

        // Remove vertex
        self.vertices.remove(&key);

        // Remove from namespace index
        if let Some(mut index) = self.ns_index.get_mut(namespace) {
            index.remove(name);
        }
    }

    /// Internal: Remove outgoing edges for a service
    fn remove_edges(&self, namespace: &str, name: &str) {
        let key = (namespace.to_string(), name.to_string());

        // Remove outgoing edges and update incoming edges of targets
        if let Some((_, edges)) = self.edges_out.remove(&key) {
            for (target_ns, target_name) in edges.iter() {
                let target_key = (target_ns.clone(), target_name.clone());
                if let Some(mut in_edges) = self.edges_in.get_mut(&target_key) {
                    in_edges.retain(|(ns, n)| ns != namespace || n != name);
                }
            }
        }
    }

    /// Get a service node by namespace and name
    pub fn get_service(&self, namespace: &str, name: &str) -> Option<ServiceNode> {
        let key = (namespace.to_string(), name.to_string());
        self.vertices.get(&key).map(|v| v.clone())
    }

    /// Get all services this service depends on
    pub fn get_dependencies(&self, namespace: &str, name: &str) -> Vec<String> {
        let key = (namespace.to_string(), name.to_string());
        self.edges_out
            .get(&key)
            .map(|v| v.iter().map(|(_, n)| n.clone()).collect())
            .unwrap_or_default()
    }

    /// Get all services that depend on this service
    pub fn get_dependents(&self, namespace: &str, name: &str) -> Vec<String> {
        let key = (namespace.to_string(), name.to_string());
        self.edges_in
            .get(&key)
            .map(|v| v.iter().map(|(_, n)| n.clone()).collect())
            .unwrap_or_default()
    }

    /// Get active inbound edges for a service (callers with bilateral agreement)
    pub fn get_active_inbound_edges(&self, namespace: &str, name: &str) -> Vec<ActiveEdge> {
        let Some(service) = self.get_service(namespace, name) else {
            return vec![];
        };

        let key = (namespace.to_string(), name.to_string());
        let Some(incoming) = self.edges_in.get(&key) else {
            return vec![];
        };

        incoming
            .iter()
            .filter_map(|(caller_ns, caller_name)| {
                // Check if service allows this caller
                if !service.allows(caller_ns, caller_name) {
                    return None;
                }

                // Get caller details
                let caller = self.get_service(caller_ns, caller_name)?;
                if caller.type_ == ServiceType::Unknown {
                    warn!(
                        caller = %format!("{}/{}", caller_ns, caller_name),
                        callee = %format!("{}/{}", namespace, name),
                        "skipping inbound edge from unknown service (check dependency name)"
                    );
                    return None;
                }

                Some(ActiveEdge {
                    caller_namespace: caller_ns.clone(),
                    caller_name: caller_name.clone(),
                    callee_namespace: namespace.to_string(),
                    callee_name: name.to_string(),
                    caller_ports: caller.ports.clone(),
                    callee_ports: service.ports.clone(),
                })
            })
            .collect()
    }

    /// Get active outbound edges for a service (callees with bilateral agreement)
    pub fn get_active_outbound_edges(&self, namespace: &str, name: &str) -> Vec<ActiveEdge> {
        let Some(caller) = self.get_service(namespace, name) else {
            return vec![];
        };

        let key = (namespace.to_string(), name.to_string());
        let Some(outgoing) = self.edges_out.get(&key) else {
            return vec![];
        };

        outgoing
            .iter()
            .filter_map(|(callee_ns, callee_name)| {
                let callee = self.get_service(callee_ns, callee_name)?;

                // Check bilateral agreement
                let allowed = match callee.type_ {
                    ServiceType::Local | ServiceType::External => callee.allows(namespace, name),
                    ServiceType::Unknown => {
                        warn!(
                            caller = %format!("{}/{}", namespace, name),
                            callee = %format!("{}/{}", callee_ns, callee_name),
                            "skipping outbound edge to unknown service (check dependency name)"
                        );
                        false
                    }
                };

                if !allowed {
                    return None;
                }

                Some(ActiveEdge {
                    caller_namespace: namespace.to_string(),
                    caller_name: name.to_string(),
                    callee_namespace: callee_ns.clone(),
                    callee_name: callee_name.clone(),
                    caller_ports: caller.ports.clone(),
                    callee_ports: callee.ports.clone(),
                })
            })
            .collect()
    }

    /// List all local services in a namespace
    pub fn list_services(&self, namespace: &str) -> Vec<ServiceNode> {
        self.ns_index
            .get(namespace)
            .map(|index| {
                index
                    .iter()
                    .filter_map(|name| {
                        let node = self.get_service(namespace, name)?;
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

    /// List all external services in a namespace
    pub fn list_external_services(&self, namespace: &str) -> Vec<ServiceNode> {
        self.ns_index
            .get(namespace)
            .map(|index| {
                index
                    .iter()
                    .filter_map(|name| {
                        let node = self.get_service(namespace, name)?;
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

    /// List all namespaces with services
    pub fn list_namespaces(&self) -> Vec<String> {
        self.ns_index
            .iter()
            .filter(|entry| !entry.value().is_empty())
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get count of services in a namespace
    pub fn service_count(&self, namespace: &str) -> usize {
        self.ns_index
            .get(namespace)
            .map(|index| index.len())
            .unwrap_or(0)
    }

    /// Clear all data from the graph
    pub fn clear(&self) {
        self.vertices.clear();
        self.edges_out.clear();
        self.edges_in.clear();
        self.ns_index.clear();
    }
}

/// Thread-safe shared reference to a service graph
pub type SharedServiceGraph = Arc<ServiceGraph>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn make_service_spec(deps: Vec<&str>, callers: Vec<&str>) -> LatticeServiceSpec {
        use crate::crd::{
            ContainerSpec, DependencyDirection, PortSpec, ResourceSpec, ResourceType,
            ServicePortsSpec, WorkloadSpec,
        };

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                ..Default::default()
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
                    namespace: None,
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
                    namespace: None,
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
            workload: WorkloadSpec {
                containers,
                resources,
                service: Some(ServicePortsSpec { ports }),
            },
            ..Default::default()
        }
    }

    fn make_external_spec(allowed: Vec<&str>) -> LatticeExternalServiceSpec {
        LatticeExternalServiceSpec {
            endpoints: BTreeMap::from([("api".to_string(), "https://api.example.com".to_string())]),
            allowed_requesters: allowed.into_iter().map(String::from).collect(),
            resolution: Resolution::Dns,
            description: None,
        }
    }

    #[test]
    fn test_put_and_get_service() {
        let graph = ServiceGraph::new();
        let spec = make_service_spec(vec![], vec![]);

        graph.put_service("prod", "api", &spec);

        let node = graph
            .get_service("prod", "api")
            .expect("service should exist");
        assert_eq!(node.name, "api");
        assert_eq!(node.namespace, "prod");
        assert_eq!(node.type_, ServiceType::Local);
    }

    #[test]
    fn test_cross_namespace_dependency() {
        use crate::crd::{
            ContainerSpec, DependencyDirection, PortSpec, ResourceSpec, ResourceType,
            ServicePortsSpec, WorkloadSpec,
        };

        let graph = ServiceGraph::new();

        // Create a service in "frontend" namespace that depends on "backend/api"
        let mut resources = BTreeMap::new();
        resources.insert(
            "api".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                id: None,
                class: None,
                metadata: None,
                params: None,
                namespace: Some("backend".to_string()), // Cross-namespace!
            },
        );

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "web:latest".to_string(),
                ..Default::default()
            },
        );

        let frontend_spec = LatticeServiceSpec {
            workload: WorkloadSpec {
                containers,
                resources,
                service: Some(ServicePortsSpec {
                    ports: BTreeMap::from([(
                        "http".to_string(),
                        PortSpec {
                            port: 80,
                            target_port: None,
                            protocol: None,
                        },
                    )]),
                }),
            },
            ..Default::default()
        };

        graph.put_service("frontend", "web", &frontend_spec);

        // Check that the cross-namespace dependency was recorded
        let web = graph
            .get_service("frontend", "web")
            .expect("web should exist");
        assert_eq!(web.dependencies.len(), 1);
        assert_eq!(
            web.dependencies[0],
            ("backend".to_string(), "api".to_string())
        );

        // Check that an unknown stub was created in the backend namespace
        let api_stub = graph
            .get_service("backend", "api")
            .expect("api stub should exist");
        assert_eq!(api_stub.type_, ServiceType::Unknown);
    }

    #[test]
    fn test_bilateral_agreement_same_namespace() {
        let graph = ServiceGraph::new();

        // api allows gateway
        let api_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service("prod", "api", &api_spec);

        // gateway depends on api
        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service("prod", "gateway", &gateway_spec);

        // Should have active edge gateway -> api
        let edges = graph.get_active_outbound_edges("prod", "gateway");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].callee_name, "api");
        assert_eq!(edges[0].callee_namespace, "prod");
    }

    #[test]
    fn test_external_service() {
        let graph = ServiceGraph::new();

        // External service allowing api
        let ext_spec = make_external_spec(vec!["api"]);
        graph.put_external_service("prod", "stripe", &ext_spec);

        // api depends on stripe
        let api_spec = make_service_spec(vec!["stripe"], vec![]);
        graph.put_service("prod", "api", &api_spec);

        // Should have active edge api -> stripe
        let edges = graph.get_active_outbound_edges("prod", "api");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].callee_name, "stripe");
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
    // Wildcard "Allow All Inbound" Tests
    // =========================================================================

    #[test]
    fn test_wildcard_allows_all_sets_flag() {
        let graph = ServiceGraph::new();

        // Service with wildcard inbound (allows all callers)
        let api_spec = make_service_spec(vec![], vec!["*"]);
        graph.put_service("prod", "api", &api_spec);

        let node = graph
            .get_service("prod", "api")
            .expect("service should exist");
        assert!(node.allows_all, "allows_all should be true for wildcard");
    }

    #[test]
    fn test_wildcard_allows_any_caller() {
        let graph = ServiceGraph::new();

        // api allows all inbound via wildcard
        let api_spec = make_service_spec(vec![], vec!["*"]);
        graph.put_service("prod", "api", &api_spec);

        let node = graph.get_service("prod", "api").unwrap();

        // Should allow any caller
        assert!(node.allows("prod", "gateway"));
        assert!(node.allows("prod", "frontend"));
        assert!(node.allows("other-ns", "random-service"));
        assert!(node.allows("any", "thing"));
    }

    #[test]
    fn test_wildcard_bilateral_agreement_single_caller() {
        let graph = ServiceGraph::new();

        // api allows all inbound via wildcard
        let api_spec = make_service_spec(vec![], vec!["*"]);
        graph.put_service("prod", "api", &api_spec);

        // gateway depends on api (only needs outbound declaration)
        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service("prod", "gateway", &gateway_spec);

        // Should have active edge gateway -> api
        let outbound = graph.get_active_outbound_edges("prod", "gateway");
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].callee_name, "api");

        // api should see inbound from gateway
        let inbound = graph.get_active_inbound_edges("prod", "api");
        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0].caller_name, "gateway");
    }

    #[test]
    fn test_wildcard_bilateral_agreement_multiple_callers() {
        let graph = ServiceGraph::new();

        // api allows all inbound via wildcard
        let api_spec = make_service_spec(vec![], vec!["*"]);
        graph.put_service("prod", "api", &api_spec);

        // Multiple services depend on api
        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service("prod", "gateway", &gateway_spec);

        let frontend_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service("prod", "frontend", &frontend_spec);

        let worker_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service("prod", "worker", &worker_spec);

        // api should see inbound from all three
        let inbound = graph.get_active_inbound_edges("prod", "api");
        assert_eq!(inbound.len(), 3);

        let caller_names: Vec<_> = inbound.iter().map(|e| e.caller_name.as_str()).collect();
        assert!(caller_names.contains(&"gateway"));
        assert!(caller_names.contains(&"frontend"));
        assert!(caller_names.contains(&"worker"));
    }

    #[test]
    fn test_wildcard_cross_namespace() {
        use crate::crd::{
            ContainerSpec, DependencyDirection, PortSpec, ResourceSpec, ResourceType,
            ServicePortsSpec, WorkloadSpec,
        };

        let graph = ServiceGraph::new();

        // api in "backend" allows all inbound via wildcard
        let api_spec = make_service_spec(vec![], vec!["*"]);
        graph.put_service("backend", "api", &api_spec);

        // frontend in different namespace depends on backend/api
        let mut resources = BTreeMap::new();
        resources.insert(
            "api".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                id: None,
                class: None,
                metadata: None,
                params: None,
                namespace: Some("backend".to_string()),
            },
        );

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "web:latest".to_string(),
                ..Default::default()
            },
        );

        let frontend_spec = LatticeServiceSpec {
            workload: WorkloadSpec {
                containers,
                resources,
                service: Some(ServicePortsSpec {
                    ports: BTreeMap::from([(
                        "http".to_string(),
                        PortSpec {
                            port: 80,
                            target_port: None,
                            protocol: None,
                        },
                    )]),
                }),
            },
            ..Default::default()
        };

        graph.put_service("frontend", "web", &frontend_spec);

        // web should have active outbound to api (cross-namespace)
        let outbound = graph.get_active_outbound_edges("frontend", "web");
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].callee_namespace, "backend");
        assert_eq!(outbound[0].callee_name, "api");

        // api should see inbound from web (cross-namespace)
        let inbound = graph.get_active_inbound_edges("backend", "api");
        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0].caller_namespace, "frontend");
        assert_eq!(inbound[0].caller_name, "web");
    }

    #[test]
    fn test_no_wildcard_requires_explicit_allow() {
        let graph = ServiceGraph::new();

        // api allows only gateway explicitly (no wildcard)
        let api_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service("prod", "api", &api_spec);

        let node = graph.get_service("prod", "api").unwrap();
        assert!(
            !node.allows_all,
            "allows_all should be false without wildcard"
        );

        // gateway is allowed
        assert!(node.allows("prod", "gateway"));
        // frontend is NOT allowed
        assert!(!node.allows("prod", "frontend"));
    }

    #[test]
    fn test_wildcard_still_requires_outbound_declaration() {
        let graph = ServiceGraph::new();

        // api allows all inbound via wildcard
        let api_spec = make_service_spec(vec![], vec!["*"]);
        graph.put_service("prod", "api", &api_spec);

        // frontend exists but does NOT declare dependency on api
        let frontend_spec = make_service_spec(vec![], vec![]);
        graph.put_service("prod", "frontend", &frontend_spec);

        // No active edges - bilateral agreement requires outbound declaration
        let inbound = graph.get_active_inbound_edges("prod", "api");
        assert!(
            inbound.is_empty(),
            "should have no inbound without outbound declaration"
        );
    }

    #[test]
    fn test_external_service_wildcard() {
        let graph = ServiceGraph::new();

        // External service with wildcard
        let ext_spec = make_external_spec(vec!["*"]);
        graph.put_external_service("prod", "stripe", &ext_spec);

        let node = graph.get_service("prod", "stripe").unwrap();
        assert!(node.allows_all, "external service should have allows_all");

        // Any service declaring outbound should get through
        let api_spec = make_service_spec(vec!["stripe"], vec![]);
        graph.put_service("prod", "api", &api_spec);

        let worker_spec = make_service_spec(vec!["stripe"], vec![]);
        graph.put_service("prod", "worker", &worker_spec);

        let outbound_api = graph.get_active_outbound_edges("prod", "api");
        assert_eq!(outbound_api.len(), 1);
        assert_eq!(outbound_api[0].callee_name, "stripe");

        let outbound_worker = graph.get_active_outbound_edges("prod", "worker");
        assert_eq!(outbound_worker.len(), 1);
        assert_eq!(outbound_worker[0].callee_name, "stripe");
    }

    // =========================================================================
    // Listing and Query Tests
    // =========================================================================

    #[test]
    fn test_list_services_filters_local_only() {
        let graph = ServiceGraph::new();

        // Add local service
        let local_spec = make_service_spec(vec![], vec![]);
        graph.put_service("test-ns", "local-svc", &local_spec);

        // Add external service
        let ext_spec = make_external_spec(vec![]);
        graph.put_external_service("test-ns", "ext-svc", &ext_spec);

        let services = graph.list_services("test-ns");
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, "local-svc");
    }

    #[test]
    fn test_list_external_services_filters_external_only() {
        let graph = ServiceGraph::new();

        // Add local service
        let local_spec = make_service_spec(vec![], vec![]);
        graph.put_service("test-ns", "local-svc", &local_spec);

        // Add external service
        let ext_spec = make_external_spec(vec![]);
        graph.put_external_service("test-ns", "ext-svc", &ext_spec);

        let services = graph.list_external_services("test-ns");
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, "ext-svc");
    }

    #[test]
    fn test_list_services_empty_namespace() {
        let graph = ServiceGraph::new();
        let services = graph.list_services("nonexistent");
        assert!(services.is_empty());
    }

    #[test]
    fn test_list_external_services_empty_namespace() {
        let graph = ServiceGraph::new();
        let services = graph.list_external_services("nonexistent");
        assert!(services.is_empty());
    }

    #[test]
    fn test_list_namespaces() {
        let graph = ServiceGraph::new();

        let spec = make_service_spec(vec![], vec![]);
        graph.put_service("ns1", "svc1", &spec);
        graph.put_service("ns2", "svc2", &spec);
        graph.put_service("ns3", "svc3", &spec);

        let mut namespaces = graph.list_namespaces();
        namespaces.sort();
        assert_eq!(namespaces, vec!["ns1", "ns2", "ns3"]);
    }

    #[test]
    fn test_list_namespaces_excludes_empty() {
        let graph = ServiceGraph::new();

        let spec = make_service_spec(vec![], vec![]);
        graph.put_service("ns1", "svc1", &spec);
        graph.delete_service("ns1", "svc1");

        // ns1 should be excluded since it's now empty
        let namespaces = graph.list_namespaces();
        assert!(!namespaces.contains(&"ns1".to_string()));
    }

    #[test]
    fn test_service_count() {
        let graph = ServiceGraph::new();

        let spec = make_service_spec(vec![], vec![]);
        graph.put_service("ns1", "svc1", &spec);
        graph.put_service("ns1", "svc2", &spec);
        graph.put_service("ns2", "svc3", &spec);

        assert_eq!(graph.service_count("ns1"), 2);
        assert_eq!(graph.service_count("ns2"), 1);
        assert_eq!(graph.service_count("nonexistent"), 0);
    }
}
