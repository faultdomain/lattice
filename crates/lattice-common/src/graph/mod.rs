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

use dashmap::{DashMap, DashSet};
use tracing::warn;

use crate::crd::{
    EgressRule, IngressPolicySpec, LatticeExternalServiceSpec, LatticeMeshMemberSpec,
    LatticeServicePolicy, LatticeServiceSpec, MeshMemberTarget, ParsedEndpoint, PeerAuth,
    Resolution, ServiceBackupSpec, ServiceSelector, VolumeParams,
};

/// Fully qualified service reference: (namespace, name)
pub type QualifiedName = (String, String);

use crate::{MONITORING_NAMESPACE, VMAGENT_NODE_NAME};

/// Type of service node in the graph
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceType {
    /// Internal service managed by Lattice
    Local,
    /// External service defined via LatticeExternalService
    External,
    /// Pre-existing workload enrolled via LatticeMeshMember
    MeshMember,
    /// Placeholder for a service referenced but not yet defined
    Unknown,
}

/// K8s Service port mapping: service port -> container targetPort.
#[derive(Clone, Copy, Debug)]
pub struct PortMapping {
    /// Service port — what clients connect to (K8s Service `.spec.ports[].port`)
    pub service_port: u16,
    /// Container target port — what the pod listens on (K8s Service `.spec.ports[].targetPort`)
    pub target_port: u16,
    /// mTLS enforcement mode for this port
    pub peer_auth: PeerAuth,
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
    /// Whether this service depends on all services that allow it (wildcard outbound)
    pub depends_all: bool,
    /// Container image (for local services)
    pub image: Option<String>,
    /// Exposed ports: name -> port mapping
    pub ports: BTreeMap<String, PortMapping>,
    /// Parsed endpoints (for external services)
    pub endpoints: BTreeMap<String, ParsedEndpoint>,
    /// Resolution strategy (for external services)
    pub resolution: Option<Resolution>,
    /// Custom pod selector labels (for mesh members with non-LABEL_NAME selectors)
    pub selector: Option<BTreeMap<String, String>>,
    /// Target namespace (for namespace-scoped mesh members)
    pub target_namespace: Option<String>,
    /// Allow traffic between pods matching this member's own selector
    pub allow_peer_traffic: bool,
    /// Non-mesh egress rules (entity, CIDR, FQDN targets)
    pub egress_rules: Vec<EgressRule>,
    /// Override SA name for SPIFFE principal (None = use node name)
    pub service_account: Option<String>,
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
            depends_all: false,
            image: spec.workload.primary_image().map(String::from),
            ports: spec
                .workload
                .service
                .as_ref()
                .map(|svc| {
                    svc.ports
                        .iter()
                        .map(|(name, ps)| {
                            (
                                name.clone(),
                                PortMapping {
                                    service_port: ps.port,
                                    target_port: ps.target_port.unwrap_or(ps.port),
                                    peer_auth: PeerAuth::Strict,
                                },
                            )
                        })
                        .collect()
                })
                .unwrap_or_default(),
            endpoints: BTreeMap::new(),
            resolution: None,
            selector: None,
            target_namespace: None,
            allow_peer_traffic: false,
            egress_rules: vec![],
            service_account: None,
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
            depends_all: false,
            image: None,
            ports: BTreeMap::new(),
            endpoints: spec.valid_endpoints(),
            resolution: Some(spec.resolution.clone()),
            selector: None,
            target_namespace: None,
            allow_peer_traffic: false,
            egress_rules: vec![],
            service_account: None,
        }
    }

    /// Create a new mesh member node from a LatticeMeshMember spec
    pub fn from_mesh_member_spec(
        namespace: &str,
        name: &str,
        spec: &LatticeMeshMemberSpec,
    ) -> Self {
        let allows_all = spec.allowed_callers.iter().any(|c| c.name == "*");

        let allowed_callers: HashSet<QualifiedName> = if allows_all {
            HashSet::new()
        } else {
            spec.allowed_callers
                .iter()
                .map(|c| (c.resolve_namespace(namespace).to_string(), c.name.clone()))
                .collect()
        };

        let dependencies: Vec<QualifiedName> = spec
            .dependencies
            .iter()
            .map(|d| (d.resolve_namespace(namespace).to_string(), d.name.clone()))
            .collect();

        let ports: BTreeMap<String, PortMapping> = spec
            .ports
            .iter()
            .map(|p| {
                (
                    p.name.clone(),
                    PortMapping {
                        service_port: p.port,
                        target_port: p.port, // No K8s Service indirection
                        peer_auth: p.peer_auth,
                    },
                )
            })
            .collect();

        let selector = match &spec.target {
            MeshMemberTarget::Selector(labels) => Some(labels.clone()),
            MeshMemberTarget::Namespace(_) => None,
        };

        let target_namespace = match &spec.target {
            MeshMemberTarget::Namespace(ns) => Some(ns.clone()),
            MeshMemberTarget::Selector(_) => None,
        };

        Self {
            namespace: namespace.to_string(),
            name: name.to_string(),
            type_: ServiceType::MeshMember,
            dependencies,
            allowed_callers,
            allows_all,
            depends_all: spec.depends_all,
            image: None,
            ports,
            endpoints: BTreeMap::new(),
            resolution: None,
            selector,
            target_namespace,
            allow_peer_traffic: spec.allow_peer_traffic,
            egress_rules: spec.egress.clone(),
            service_account: spec.service_account.clone(),
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
            depends_all: false,
            image: None,
            ports: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            resolution: None,
            selector: None,
            target_namespace: None,
            allow_peer_traffic: false,
            egress_rules: vec![],
            service_account: None,
        }
    }

    /// Effective ServiceAccount name for SPIFFE principal generation.
    /// Returns the explicit `service_account` if set, otherwise falls back to the node name.
    pub fn sa_name(&self) -> &str {
        self.service_account.as_deref().unwrap_or(&self.name)
    }

    /// Return port numbers by peer auth mode.
    fn ports_with_auth(&self, mode: PeerAuth) -> Vec<u16> {
        self.ports
            .values()
            .filter(|pm| pm.peer_auth == mode)
            .map(|pm| pm.target_port)
            .collect()
    }

    /// Port numbers that accept plaintext from any source.
    pub fn permissive_port_numbers(&self) -> Vec<u16> {
        self.ports_with_auth(PeerAuth::Permissive)
    }

    /// Port numbers that accept plaintext from kube-apiserver only.
    pub fn webhook_port_numbers(&self) -> Vec<u16> {
        self.ports_with_auth(PeerAuth::Webhook)
    }

    /// All port numbers that need permissive mTLS (PeerAuthentication PERMISSIVE).
    pub fn all_non_strict_port_numbers(&self) -> Vec<u16> {
        self.ports
            .values()
            .filter(|pm| pm.peer_auth != PeerAuth::Strict)
            .map(|pm| pm.target_port)
            .collect()
    }

    /// Effective match labels for Istio policies (custom selector or fallback to LABEL_NAME).
    pub fn istio_match_labels(&self) -> BTreeMap<String, String> {
        self.selector
            .clone()
            .unwrap_or_else(|| BTreeMap::from([(crate::LABEL_NAME.to_string(), self.name.clone())]))
    }

    /// Effective match labels for Cilium policies (custom selector with k8s: prefix or CILIUM_LABEL_NAME).
    pub fn cilium_match_labels(&self) -> BTreeMap<String, String> {
        self.selector
            .as_ref()
            .map(|labels| {
                labels
                    .iter()
                    .map(|(k, v)| (format!("k8s:{}", k), v.clone()))
                    .collect()
            })
            .unwrap_or_else(|| {
                BTreeMap::from([(crate::CILIUM_LABEL_NAME.to_string(), self.name.clone())])
            })
    }

    /// Check if this service allows a specific caller (O(1) lookup)
    ///
    /// A service with a "metrics" port implicitly allows vmagent for scraping.
    pub fn allows(&self, caller_namespace: &str, caller_name: &str) -> bool {
        self.allows_all
            || self
                .allowed_callers
                .contains(&(caller_namespace.to_string(), caller_name.to_string()))
            || (self.ports.contains_key("metrics")
                && caller_name == VMAGENT_NODE_NAME
                && caller_namespace == MONITORING_NAMESPACE)
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
}

/// A cached policy node in the service graph
#[derive(Clone, Debug)]
pub struct PolicyNode {
    /// Policy name
    pub name: String,
    /// Policy namespace
    pub namespace: String,
    /// Selector for matching services
    pub selector: ServiceSelector,
    /// Priority (higher = evaluated first)
    pub priority: i32,
    /// Backup configuration
    pub backup: Option<ServiceBackupSpec>,
    /// Ingress defaults
    pub ingress: Option<IngressPolicySpec>,
}

impl From<&LatticeServicePolicy> for PolicyNode {
    fn from(policy: &LatticeServicePolicy) -> Self {
        Self {
            name: policy.metadata.name.clone().unwrap_or_default(),
            namespace: policy.metadata.namespace.clone().unwrap_or_default(),
            selector: policy.spec.selector.clone(),
            priority: policy.spec.priority,
            backup: policy.spec.backup.clone(),
            ingress: policy.spec.ingress.clone(),
        }
    }
}

/// Volume ownership record: who owns a shared volume and who may consume it
#[derive(Clone, Debug)]
pub struct VolumeOwnership {
    /// The service that owns (creates) this volume
    pub owner_name: String,
    /// The namespace of the owning service
    pub owner_namespace: String,
    /// Volume params (includes allowed_consumers, access_mode, size)
    pub params: VolumeParams,
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

    /// Cached LatticeServicePolicy nodes: (namespace, name) -> PolicyNode
    policies: DashMap<QualifiedName, PolicyNode>,

    /// Cached namespace labels: namespace -> labels
    ns_labels: DashMap<String, BTreeMap<String, String>>,

    /// Services with `depends_all: true` (wildcard outbound)
    depends_all_nodes: DashSet<QualifiedName>,

    /// Volume ownership index: (namespace, volume_id) -> VolumeOwnership
    ///
    /// Only shared volumes (those with both `id` and `size`) are indexed.
    /// Updated on put_service/delete_service.
    volume_owners: DashMap<(String, String), VolumeOwnership>,
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
            policies: DashMap::new(),
            ns_labels: DashMap::new(),
            depends_all_nodes: DashSet::new(),
            volume_owners: DashMap::new(),
        }
    }

    /// Insert or update a local service in the graph
    pub fn put_service(&self, namespace: &str, name: &str, spec: &LatticeServiceSpec) {
        let node = ServiceNode::from_service_spec(namespace, name, spec);
        self.put_node(node);
        self.update_volume_owners(namespace, name, spec);
    }

    /// Insert or update a mesh member in the graph
    pub fn put_mesh_member(&self, namespace: &str, name: &str, spec: &LatticeMeshMemberSpec) {
        let node = ServiceNode::from_mesh_member_spec(namespace, name, spec);
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
        let depends_all = node.depends_all;

        // Store the node
        self.vertices.insert(key.clone(), node);

        // Maintain depends_all index
        if depends_all {
            self.depends_all_nodes.insert(key.clone());
        } else {
            self.depends_all_nodes.remove(&key);
        }

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

        // Remove from depends_all index
        self.depends_all_nodes.remove(&key);

        // Remove from namespace index
        if let Some(mut index) = self.ns_index.get_mut(namespace) {
            index.remove(name);
        }

        // Remove volume ownership entries for this service
        self.volume_owners
            .retain(|_, v| !(v.owner_namespace == namespace && v.owner_name == name));
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

        let mut seen = HashSet::new();
        let mut edges = Vec::new();

        // Explicit incoming edges (from dependencies declarations)
        if let Some(incoming) = self.edges_in.get(&key) {
            for (caller_ns, caller_name) in incoming.iter() {
                if !service.allows(caller_ns, caller_name) {
                    continue;
                }

                let caller = match self.get_service(caller_ns, caller_name) {
                    Some(c) => c,
                    None => continue,
                };
                if caller.type_ == ServiceType::Unknown {
                    warn!(
                        caller = %format!("{}/{}", caller_ns, caller_name),
                        callee = %format!("{}/{}", namespace, name),
                        "skipping inbound edge from unknown service (check dependency name)"
                    );
                    continue;
                }

                let caller_key = (caller_ns.clone(), caller_name.clone());
                if seen.insert(caller_key) {
                    edges.push(ActiveEdge {
                        caller_namespace: caller_ns.clone(),
                        caller_name: caller_name.clone(),
                        callee_namespace: namespace.to_string(),
                        callee_name: name.to_string(),
                    });
                }
            }
        }

        // depends_all nodes: any service with depends_all that this service allows
        for entry in self.depends_all_nodes.iter() {
            let (da_ns, da_name) = entry.key();
            // Skip self
            if da_ns == namespace && da_name == name {
                continue;
            }
            let caller_key = (da_ns.clone(), da_name.clone());
            if seen.contains(&caller_key) {
                continue;
            }
            if !service.allows(da_ns, da_name) {
                continue;
            }
            match self.get_service(da_ns, da_name) {
                Some(c) if c.type_ != ServiceType::Unknown => {}
                _ => continue,
            }
            seen.insert(caller_key);
            edges.push(ActiveEdge {
                caller_namespace: da_ns.clone(),
                caller_name: da_name.clone(),
                callee_namespace: namespace.to_string(),
                callee_name: name.to_string(),
            });
        }

        edges
    }

    /// Get active outbound edges for a service (callees with bilateral agreement)
    pub fn get_active_outbound_edges(&self, namespace: &str, name: &str) -> Vec<ActiveEdge> {
        let service = match self.get_service(namespace, name) {
            Some(s) => s,
            None => return vec![],
        };

        let key = (namespace.to_string(), name.to_string());
        let mut seen = HashSet::new();
        let mut edges = Vec::new();

        // Explicit outgoing edges
        if let Some(outgoing) = self.edges_out.get(&key) {
            for (callee_ns, callee_name) in outgoing.iter() {
                let callee = match self.get_service(callee_ns, callee_name) {
                    Some(c) => c,
                    None => continue,
                };

                let allowed = match callee.type_ {
                    ServiceType::Local | ServiceType::External | ServiceType::MeshMember => {
                        callee.allows(namespace, name)
                    }
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
                    continue;
                }

                let callee_key = (callee_ns.clone(), callee_name.clone());
                if seen.insert(callee_key) {
                    edges.push(ActiveEdge {
                        caller_namespace: namespace.to_string(),
                        caller_name: name.to_string(),
                        callee_namespace: callee_ns.clone(),
                        callee_name: callee_name.clone(),
                    });
                }
            }
        }

        // depends_all: check all services that allow this caller
        if service.depends_all {
            for entry in self.vertices.iter() {
                let node = entry.value();
                let callee_key = (node.namespace.clone(), node.name.clone());
                if callee_key.0 == namespace && callee_key.1 == name {
                    continue;
                }
                if seen.contains(&callee_key) {
                    continue;
                }
                if node.type_ == ServiceType::Unknown {
                    continue;
                }
                if !node.allows(namespace, name) {
                    continue;
                }
                seen.insert(callee_key);
                edges.push(ActiveEdge {
                    caller_namespace: namespace.to_string(),
                    caller_name: name.to_string(),
                    callee_namespace: node.namespace.clone(),
                    callee_name: node.name.clone(),
                });
            }
        }

        edges
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

    /// List all mesh members in a namespace
    pub fn list_mesh_members(&self, namespace: &str) -> Vec<ServiceNode> {
        self.ns_index
            .get(namespace)
            .map(|index| {
                index
                    .iter()
                    .filter_map(|name| {
                        let node = self.get_service(namespace, name)?;
                        if node.type_ == ServiceType::MeshMember {
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

    /// Insert or update a policy in the graph
    pub fn put_policy(&self, node: PolicyNode) {
        let key = (node.namespace.clone(), node.name.clone());
        self.policies.insert(key, node);
    }

    /// Remove a policy from the graph
    pub fn delete_policy(&self, namespace: &str, name: &str) {
        let key = (namespace.to_string(), name.to_string());
        self.policies.remove(&key);
    }

    /// Cache namespace labels
    pub fn put_namespace_labels(&self, namespace: &str, labels: BTreeMap<String, String>) {
        self.ns_labels.insert(namespace.to_string(), labels);
    }

    /// Get cached namespace labels (returns None if not yet cached)
    pub fn get_namespace_labels(&self, namespace: &str) -> Option<BTreeMap<String, String>> {
        self.ns_labels.get(namespace).map(|v| v.clone())
    }

    /// Find policies matching a service, sorted by priority DESC then name ASC
    pub fn matching_policies(
        &self,
        service_labels: &BTreeMap<String, String>,
        service_namespace: &str,
    ) -> Vec<PolicyNode> {
        let ns_labels = self
            .ns_labels
            .get(service_namespace)
            .map(|v| v.clone())
            .unwrap_or_default();

        let mut matching: Vec<PolicyNode> = self
            .policies
            .iter()
            .filter(|entry| {
                let p = entry.value();
                p.selector
                    .matches(service_labels, &ns_labels, &p.namespace, service_namespace)
            })
            .map(|entry| entry.value().clone())
            .collect();

        matching.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.name.cmp(&b.name))
        });

        matching
    }

    /// Get the owner of a shared volume by namespace and volume ID.
    ///
    /// Returns `None` if no service owns a volume with this ID in this namespace.
    pub fn get_volume_owner(&self, namespace: &str, volume_id: &str) -> Option<VolumeOwnership> {
        let key = (namespace.to_string(), volume_id.to_string());
        self.volume_owners.get(&key).map(|v| v.clone())
    }

    /// Update the volume ownership index for a service.
    ///
    /// Removes all previous ownership entries for this service, then indexes
    /// any owned shared volumes (those with both `id` and `size`).
    fn update_volume_owners(&self, namespace: &str, name: &str, spec: &LatticeServiceSpec) {
        // Remove stale entries for this service
        self.volume_owners
            .retain(|_, v| !(v.owner_namespace == namespace && v.owner_name == name));

        // Index owned shared volumes
        for resource in spec.workload.resources.values() {
            if !resource.type_.is_volume() {
                continue;
            }
            let Some(ref volume_id) = resource.id else {
                continue;
            };
            let params = match resource.volume_params() {
                Ok(Some(p)) => p,
                _ => continue,
            };
            // Only index if this service owns the volume (has size)
            if params.size.is_none() {
                continue;
            }
            self.volume_owners.insert(
                (namespace.to_string(), volume_id.clone()),
                VolumeOwnership {
                    owner_name: name.to_string(),
                    owner_namespace: namespace.to_string(),
                    params,
                },
            );
        }
    }

    /// Clear all data from the graph
    pub fn clear(&self) {
        self.vertices.clear();
        self.edges_out.clear();
        self.edges_in.clear();
        self.ns_index.clear();
        self.policies.clear();
        self.ns_labels.clear();
        self.depends_all_nodes.clear();
        self.volume_owners.clear();
    }
}

/// Thread-safe shared reference to a service graph
pub type SharedServiceGraph = Arc<ServiceGraph>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VMAGENT_SA_NAME;
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

    // =========================================================================
    // MeshMember Tests
    // =========================================================================

    fn make_mesh_member_spec(
        labels: BTreeMap<String, String>,
        ports: Vec<(&str, u16)>,
        callers: Vec<&str>,
        deps: Vec<&str>,
    ) -> LatticeMeshMemberSpec {
        use crate::crd::{CallerRef, MeshMemberPort, PeerAuth, ServiceRef};

        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(labels),
            ports: ports
                .into_iter()
                .map(|(name, port)| MeshMemberPort {
                    port,
                    name: name.to_string(),
                    peer_auth: PeerAuth::Strict,
                })
                .collect(),
            allowed_callers: callers
                .into_iter()
                .map(|c| CallerRef {
                    name: c.to_string(),
                    namespace: None,
                })
                .collect(),
            dependencies: deps
                .into_iter()
                .map(|d| ServiceRef {
                    name: d.to_string(),
                    namespace: None,
                })
                .collect(),
            egress: vec![],
            allow_peer_traffic: false,
            depends_all: false,
            ingress: None,
            service_account: None,
        }
    }

    #[test]
    fn test_put_mesh_member() {
        let graph = ServiceGraph::new();
        let labels = BTreeMap::from([("app".to_string(), "prometheus".to_string())]);
        let spec = make_mesh_member_spec(labels.clone(), vec![("metrics", 9090)], vec![], vec![]);

        graph.put_mesh_member("monitoring", "prometheus", &spec);

        let node = graph.get_service("monitoring", "prometheus").unwrap();
        assert_eq!(node.type_, ServiceType::MeshMember);
        assert_eq!(node.selector, Some(labels));
        assert_eq!(node.ports.len(), 1);
        let port = node.ports.get("metrics").unwrap();
        assert_eq!(port.service_port, 9090);
        assert_eq!(port.target_port, 9090);
    }

    #[test]
    fn test_mesh_member_bilateral_with_service() {
        let graph = ServiceGraph::new();

        // MeshMember allows "api" caller
        let labels = BTreeMap::from([("app".to_string(), "prometheus".to_string())]);
        let mm_spec = make_mesh_member_spec(labels, vec![("metrics", 9090)], vec!["api"], vec![]);
        graph.put_mesh_member("monitoring", "prometheus", &mm_spec);

        // api depends on prometheus — need cross-namespace dep, build manually
        {
            use crate::crd::{
                ContainerSpec, DependencyDirection, PortSpec, ResourceSpec, ResourceType,
                ServicePortsSpec, WorkloadSpec,
            };

            let mut resources = BTreeMap::new();
            resources.insert(
                "prometheus".to_string(),
                ResourceSpec {
                    type_: ResourceType::Service,
                    direction: DependencyDirection::Outbound,
                    id: None,
                    class: None,
                    metadata: None,
                    params: None,
                    namespace: Some("monitoring".to_string()),
                },
            );

            let mut containers = BTreeMap::new();
            containers.insert(
                "main".to_string(),
                ContainerSpec {
                    image: "api:latest".to_string(),
                    ..Default::default()
                },
            );

            let spec = LatticeServiceSpec {
                workload: WorkloadSpec {
                    containers,
                    resources,
                    service: Some(ServicePortsSpec {
                        ports: BTreeMap::from([(
                            "http".to_string(),
                            PortSpec {
                                port: 8080,
                                target_port: None,
                                protocol: None,
                            },
                        )]),
                    }),
                },
                ..Default::default()
            };
            graph.put_service("monitoring", "api", &spec);
        }

        // Bilateral agreement: api -> prometheus
        let outbound = graph.get_active_outbound_edges("monitoring", "api");
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].callee_name, "prometheus");

        let inbound = graph.get_active_inbound_edges("monitoring", "prometheus");
        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0].caller_name, "api");
    }

    #[test]
    fn test_list_mesh_members() {
        let graph = ServiceGraph::new();

        // Add mesh member
        let labels = BTreeMap::from([("app".to_string(), "prometheus".to_string())]);
        let mm_spec = make_mesh_member_spec(labels, vec![("metrics", 9090)], vec![], vec![]);
        graph.put_mesh_member("monitoring", "prometheus", &mm_spec);

        // Add local service
        let svc_spec = make_service_spec(vec![], vec![]);
        graph.put_service("monitoring", "grafana", &svc_spec);

        let members = graph.list_mesh_members("monitoring");
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].name, "prometheus");

        // list_services should NOT include mesh members
        let services = graph.list_services("monitoring");
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, "grafana");
    }

    #[test]
    fn test_mesh_member_namespace_target() {
        let graph = ServiceGraph::new();

        let spec = LatticeMeshMemberSpec {
            target: MeshMemberTarget::Namespace("kube-system".to_string()),
            ports: vec![crate::crd::MeshMemberPort {
                port: 443,
                name: "https".to_string(),
                peer_auth: crate::crd::PeerAuth::Permissive,
            }],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![],
            allow_peer_traffic: false,
            depends_all: false,
            ingress: None,
            service_account: None,
        };

        graph.put_mesh_member("default", "kube-api-access", &spec);

        let node = graph.get_service("default", "kube-api-access").unwrap();
        assert_eq!(node.type_, ServiceType::MeshMember);
        assert_eq!(node.selector, None);
        assert_eq!(node.target_namespace, Some("kube-system".to_string()));
    }

    #[test]
    fn test_mesh_member_with_dependencies() {
        let graph = ServiceGraph::new();

        // MeshMember depends on a service
        let labels = BTreeMap::from([("app".to_string(), "webhook".to_string())]);
        let mm_spec = make_mesh_member_spec(labels, vec![("webhook", 9443)], vec![], vec!["api"]);
        graph.put_mesh_member("prod", "webhook-handler", &mm_spec);

        // api allows webhook-handler
        let api_spec = make_service_spec(vec![], vec!["webhook-handler"]);
        graph.put_service("prod", "api", &api_spec);

        // Bilateral agreement: webhook-handler -> api
        let outbound = graph.get_active_outbound_edges("prod", "webhook-handler");
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].callee_name, "api");
    }

    #[test]
    fn test_delete_mesh_member() {
        let graph = ServiceGraph::new();

        let labels = BTreeMap::from([("app".to_string(), "prometheus".to_string())]);
        let spec = make_mesh_member_spec(labels, vec![("metrics", 9090)], vec![], vec![]);
        graph.put_mesh_member("monitoring", "prometheus", &spec);

        assert!(graph.get_service("monitoring", "prometheus").is_some());
        graph.delete_service("monitoring", "prometheus");
        assert!(graph.get_service("monitoring", "prometheus").is_none());
    }

    // =========================================================================
    // Wildcard "Depends All" (Outbound) Tests
    // =========================================================================

    #[test]
    fn test_depends_all_sets_flag() {
        let graph = ServiceGraph::new();
        let labels = BTreeMap::from([("app".to_string(), "scraper".to_string())]);
        let mut spec = make_mesh_member_spec(labels, vec![("http", 8080)], vec![], vec![]);
        spec.depends_all = true;

        graph.put_mesh_member("monitoring", "scraper", &spec);

        let node = graph.get_service("monitoring", "scraper").unwrap();
        assert!(node.depends_all);
    }

    #[test]
    fn test_depends_all_outbound_edges() {
        let graph = ServiceGraph::new();

        // scraper has depends_all
        let labels = BTreeMap::from([("app".to_string(), "scraper".to_string())]);
        let mut spec = make_mesh_member_spec(labels, vec![("http", 8080)], vec![], vec![]);
        spec.depends_all = true;
        graph.put_mesh_member("prod", "scraper", &spec);

        // api allows scraper
        let api_spec = make_service_spec(vec![], vec!["scraper"]);
        graph.put_service("prod", "api", &api_spec);

        // worker does NOT allow scraper
        let worker_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service("prod", "worker", &worker_spec);

        // scraper should have outbound edge to api but not worker
        let outbound = graph.get_active_outbound_edges("prod", "scraper");
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].callee_name, "api");
    }

    #[test]
    fn test_depends_all_inbound_edges() {
        let graph = ServiceGraph::new();

        // scraper has depends_all
        let labels = BTreeMap::from([("app".to_string(), "scraper".to_string())]);
        let mut spec = make_mesh_member_spec(labels, vec![("http", 8080)], vec![], vec![]);
        spec.depends_all = true;
        graph.put_mesh_member("prod", "scraper", &spec);

        // api allows scraper
        let api_spec = make_service_spec(vec![], vec!["scraper"]);
        graph.put_service("prod", "api", &api_spec);

        // api should see inbound from scraper (even though scraper has no explicit dep on api)
        let inbound = graph.get_active_inbound_edges("prod", "api");
        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0].caller_name, "scraper");
    }

    #[test]
    fn test_depends_all_no_self_edge() {
        let graph = ServiceGraph::new();

        // Service allows all and depends on all
        let labels = BTreeMap::from([("app".to_string(), "svc".to_string())]);
        let mut spec = make_mesh_member_spec(labels, vec![("http", 8080)], vec!["*"], vec![]);
        spec.depends_all = true;
        graph.put_mesh_member("prod", "svc", &spec);

        let outbound = graph.get_active_outbound_edges("prod", "svc");
        assert!(outbound.is_empty(), "should not create self-edge");

        let inbound = graph.get_active_inbound_edges("prod", "svc");
        assert!(inbound.is_empty(), "should not create self-edge");
    }

    #[test]
    fn test_depends_all_cross_namespace() {
        let graph = ServiceGraph::new();

        // scraper in monitoring has depends_all
        let labels = BTreeMap::from([("app".to_string(), "scraper".to_string())]);
        let mut spec = make_mesh_member_spec(labels, vec![("http", 8080)], vec![], vec![]);
        spec.depends_all = true;
        graph.put_mesh_member("monitoring", "scraper", &spec);

        // api in prod allows scraper from monitoring
        use crate::crd::{
            ContainerSpec, DependencyDirection, PortSpec, ResourceSpec, ResourceType,
            ServicePortsSpec, WorkloadSpec,
        };
        let mut resources = BTreeMap::new();
        resources.insert(
            "scraper".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Inbound,
                id: None,
                class: None,
                metadata: None,
                params: None,
                namespace: Some("monitoring".to_string()),
            },
        );
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "api:latest".to_string(),
                ..Default::default()
            },
        );
        let api_spec = LatticeServiceSpec {
            workload: WorkloadSpec {
                containers,
                resources,
                service: Some(ServicePortsSpec {
                    ports: BTreeMap::from([(
                        "http".to_string(),
                        PortSpec {
                            port: 8080,
                            target_port: None,
                            protocol: None,
                        },
                    )]),
                }),
            },
            ..Default::default()
        };
        graph.put_service("prod", "api", &api_spec);

        // scraper should reach api cross-namespace
        let outbound = graph.get_active_outbound_edges("monitoring", "scraper");
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].callee_namespace, "prod");
        assert_eq!(outbound[0].callee_name, "api");
    }

    #[test]
    fn test_metrics_port_implicitly_allows_vmagent() {
        let graph = ServiceGraph::new();

        // Service with a "metrics" port but no explicit vmagent caller
        let labels = BTreeMap::from([("app".to_string(), "api".to_string())]);
        let spec = make_mesh_member_spec(labels, vec![("metrics", 9090)], vec![], vec![]);
        graph.put_mesh_member("prod", "api", &spec);

        let node = graph.get_service("prod", "api").unwrap();
        assert!(node.allows("monitoring", "vmagent"));
        assert!(!node.allows("monitoring", "other-service"));
        assert!(!node.allows("prod", "vmagent")); // wrong namespace
    }

    #[test]
    fn test_no_metrics_port_no_implicit_vmagent() {
        let graph = ServiceGraph::new();

        // Service without a "metrics" port
        let labels = BTreeMap::from([("app".to_string(), "api".to_string())]);
        let spec = make_mesh_member_spec(labels, vec![("http", 8080)], vec![], vec![]);
        graph.put_mesh_member("prod", "api", &spec);

        let node = graph.get_service("prod", "api").unwrap();
        assert!(!node.allows("monitoring", "vmagent"));
    }

    #[test]
    fn test_depends_all_vmagent_reaches_metrics_port() {
        let graph = ServiceGraph::new();

        // vmagent with depends_all
        let vmagent_labels = BTreeMap::from([("app".to_string(), "vmagent".to_string())]);
        let mut vmagent_spec =
            make_mesh_member_spec(vmagent_labels, vec![("http", 8429)], vec![], vec![]);
        vmagent_spec.depends_all = true;
        vmagent_spec.service_account = Some(VMAGENT_SA_NAME.to_string());
        graph.put_mesh_member("monitoring", VMAGENT_NODE_NAME, &vmagent_spec);

        // Service with metrics port (no explicit allowed_callers)
        let api_labels = BTreeMap::from([("app".to_string(), "api".to_string())]);
        let api_spec = make_mesh_member_spec(api_labels, vec![("metrics", 9090)], vec![], vec![]);
        graph.put_mesh_member("prod", "api", &api_spec);

        // vmagent should have outbound edge to api
        let outbound = graph.get_active_outbound_edges("monitoring", VMAGENT_NODE_NAME);
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].callee_name, "api");

        // api should see inbound from vmagent
        let inbound = graph.get_active_inbound_edges("prod", "api");
        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0].caller_name, VMAGENT_NODE_NAME);
    }

    #[test]
    fn test_depends_all_delete_cleans_index() {
        let graph = ServiceGraph::new();

        let labels = BTreeMap::from([("app".to_string(), "scraper".to_string())]);
        let mut spec = make_mesh_member_spec(labels, vec![("http", 8080)], vec![], vec![]);
        spec.depends_all = true;
        graph.put_mesh_member("prod", "scraper", &spec);

        // api allows scraper
        let api_spec = make_service_spec(vec![], vec!["scraper"]);
        graph.put_service("prod", "api", &api_spec);

        assert_eq!(graph.get_active_inbound_edges("prod", "api").len(), 1);

        // Delete scraper
        graph.delete_service("prod", "scraper");

        // api should no longer see inbound from scraper
        assert!(graph.get_active_inbound_edges("prod", "api").is_empty());
    }
}
