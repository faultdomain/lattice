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

use lattice_core::{MONITORING_NAMESPACE, VMAGENT_NODE_NAME};
use lattice_crd::crd::{
    EgressRule, LatticeMeshMemberSpec, LatticeServiceSpec, MeshMemberTarget, PeerAuth, ServiceRef,
    VolumeParams, WorkloadSpec,
};

/// Fully qualified service reference: (namespace, name)
pub type QualifiedName = (String, String);

/// Type of service node in the graph
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceType {
    /// Internal service managed by Lattice
    Local,
    /// Pre-existing workload enrolled via LatticeMeshMember
    MeshMember,
    /// Remote service discovered via LatticeClusterRoutes (cross-cluster)
    Remote {
        /// Source cluster name (from the LatticeClusterRoutes CRD name)
        source_cluster: String,
        /// Gateway address (LoadBalancer IP on the remote cluster)
        address: String,
        /// Gateway port
        port: u16,
        /// Hostname for the remote service
        hostname: String,
    },
    /// Placeholder for a service referenced but not yet defined
    Unknown,
}

impl ServiceType {
    /// Returns true if this is a local Lattice-managed service.
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local)
    }

    /// Returns true if this is a pre-existing workload enrolled via LatticeMeshMember.
    pub fn is_mesh_member(&self) -> bool {
        matches!(self, Self::MeshMember)
    }

    /// Returns true if this is a remote cross-cluster service.
    pub fn is_remote(&self) -> bool {
        matches!(self, Self::Remote { .. })
    }

    /// Returns true if this is a placeholder for an undefined service.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
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
    /// Whether this member participates in Istio ambient mesh (L7 enforcement).
    /// When `false`, only Cilium L4 policies are generated.
    pub ambient: bool,
    /// Cross-cluster advertisement config. When set, drives inbound
    /// AuthorizationPolicy for cross-cluster callers — open (any authenticated
    /// principal) or restricted (specific SPIFFE identities).
    pub advertise: Option<lattice_crd::crd::workload::ingress::AdvertiseConfig>,
}

/// Resolve a list of caller/service references into a (allows_all, callers) pair.
///
/// Filters out the wildcard entry ("*") from the callers set — it only drives
/// the `allows_all` flag. Non-wildcard entries (infrastructure identities like
/// gateway proxy SAs) are kept even when allows_all is true.
fn resolve_callers<'a>(
    refs: impl IntoIterator<Item = (&'a str, Option<&'a str>)>,
    default_namespace: &str,
) -> (bool, HashSet<QualifiedName>) {
    let mut allows_all = false;
    let mut callers = HashSet::new();
    for (name, ns) in refs {
        if name == "*" {
            allows_all = true;
            continue;
        }
        let resolved_ns = ns.unwrap_or(default_namespace).to_string();
        callers.insert((resolved_ns, name.to_string()));
    }
    (allows_all, callers)
}

impl ServiceNode {
    /// Create a new local service node from a LatticeService spec
    pub fn from_service_spec(namespace: &str, name: &str, spec: &LatticeServiceSpec) -> Self {
        let mut node = Self::from_workload_spec(namespace, name, &spec.workload);

        // If an explicit metrics port override is set and differs from "metrics",
        // inject vmagent as an allowed caller for that port too (from_workload_spec
        // already handles the default "metrics" port name).
        if let Some(explicit_port) = spec
            .observability
            .as_ref()
            .and_then(|o| o.metrics.as_ref())
            .and_then(|m| m.port.as_deref())
        {
            if explicit_port != "metrics" && node.ports.contains_key(explicit_port) {
                node.allowed_callers.insert((
                    MONITORING_NAMESPACE.to_string(),
                    VMAGENT_NODE_NAME.to_string(),
                ));
            }
        }

        node.advertise = spec.advertise.clone();

        node
    }

    /// Create a node from a raw WorkloadSpec (shared by LatticeService and LatticeJob tasks)
    pub fn from_workload_spec(namespace: &str, name: &str, workload: &WorkloadSpec) -> Self {
        let caller_refs = workload.allowed_callers(namespace);
        let (allows_all, mut allowed_callers) = resolve_callers(
            caller_refs
                .iter()
                .map(|r| (r.name.as_str(), r.namespace.as_deref())),
            namespace,
        );

        // Only include internal service dependencies as graph edges.
        // External-service egress is handled via LatticeMeshMember egress rules.
        let dependencies: Vec<QualifiedName> = workload
            .internal_dependencies(namespace)
            .into_iter()
            .map(|r| (r.resolve_namespace(namespace).to_string(), r.name))
            .collect();

        let ports: BTreeMap<String, PortMapping> = workload
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
            .unwrap_or_default();

        // Auto-inject vmagent as allowed caller when a "metrics" port exists
        if ports.contains_key("metrics") {
            allowed_callers.insert((
                MONITORING_NAMESPACE.to_string(),
                VMAGENT_NODE_NAME.to_string(),
            ));
        }

        Self {
            namespace: namespace.to_string(),
            name: name.to_string(),
            type_: ServiceType::Local,
            dependencies,
            allowed_callers,
            allows_all,
            depends_all: false,
            image: workload.primary_image().map(String::from),
            ports,
            selector: None,
            target_namespace: None,
            allow_peer_traffic: false,
            egress_rules: vec![],
            service_account: None,
            ambient: true,
            advertise: None,
        }
    }

    /// Create a new mesh member node from a LatticeMeshMember spec
    pub fn from_mesh_member_spec(
        namespace: &str,
        name: &str,
        spec: &LatticeMeshMemberSpec,
    ) -> Self {
        let (allows_all, mut allowed_callers) = resolve_callers(
            spec.allowed_callers
                .iter()
                .map(|c| (c.name.as_str(), c.namespace.as_deref())),
            namespace,
        );

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
                        service_port: p.service_port.unwrap_or(p.port),
                        target_port: p.port,
                        peer_auth: p.peer_auth,
                    },
                )
            })
            .collect();

        // Auto-inject vmagent as allowed caller when a "metrics" port exists
        if ports.contains_key("metrics") {
            allowed_callers.insert((
                MONITORING_NAMESPACE.to_string(),
                VMAGENT_NODE_NAME.to_string(),
            ));
        }

        let selector = match &spec.target {
            MeshMemberTarget::Selector(labels) => Some(labels.clone()),
            _ => None,
        };

        let target_namespace = match &spec.target {
            MeshMemberTarget::Namespace(ns) => Some(ns.clone()),
            _ => None,
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
            selector,
            target_namespace,
            allow_peer_traffic: spec.allow_peer_traffic,
            egress_rules: spec.egress.clone(),
            service_account: spec.service_account.clone(),
            ambient: spec.ambient,
            advertise: spec.advertise.clone(),
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
            selector: None,
            target_namespace: None,
            allow_peer_traffic: false,
            egress_rules: vec![],
            service_account: None,
            ambient: true,
            advertise: None,
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
        self.selector.clone().unwrap_or_else(|| {
            BTreeMap::from([(lattice_core::LABEL_NAME.to_string(), self.name.clone())])
        })
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
                BTreeMap::from([(
                    lattice_core::CILIUM_LABEL_NAME.to_string(),
                    self.name.clone(),
                )])
            })
    }

    /// Check if this service allows a specific caller (O(1) lookup)
    pub fn allows(&self, caller_namespace: &str, caller_name: &str) -> bool {
        self.allows_all
            || self
                .allowed_callers
                .contains(&(caller_namespace.to_string(), caller_name.to_string()))
    }
}

/// Typed node update that declares which controller is authoritative.
/// Used by `put_node` to determine field preservation during merge.
enum NodeUpdate {
    /// Local service controller (LatticeService, LatticeModel, LatticeJob).
    /// Authoritative on: allowed_callers, allows_all, dependencies, image, ports.
    Service(ServiceNode),
    /// MeshMember controller. Authoritative on: egress_rules, selector,
    /// target_namespace, allow_peer_traffic, depends_all, ambient,
    /// service_account, ports, type_.
    MeshMember(ServiceNode),
}

impl NodeUpdate {
    fn key(&self) -> QualifiedName {
        let node = self.inner();
        (node.namespace.clone(), node.name.clone())
    }

    fn inner(&self) -> &ServiceNode {
        match self {
            Self::Service(n) | Self::MeshMember(n) => n,
        }
    }

    fn into_inner(self) -> ServiceNode {
        match self {
            Self::Service(n) | Self::MeshMember(n) => n,
        }
    }

    /// Merge this update with an existing node (if any), respecting field ownership.
    fn into_merged(self, existing: Option<&ServiceNode>) -> ServiceNode {
        let existing = match existing {
            Some(e) => e,
            None => return self.into_inner(),
        };

        match self {
            Self::Service(node) => Self::preserve_mesh_member_fields(node, existing),
            Self::MeshMember(node) => Self::preserve_local_fields(node, existing),
        }
    }

    /// When a Local node replaces a MeshMember, preserve MeshMember-owned fields.
    fn preserve_mesh_member_fields(mut node: ServiceNode, existing: &ServiceNode) -> ServiceNode {
        if existing.type_ != ServiceType::MeshMember {
            return node;
        }

        if node.egress_rules.is_empty() {
            node.egress_rules = existing.egress_rules.clone();
        }
        if node.ports.is_empty() {
            node.ports = existing.ports.clone();
        }
        if node.selector.is_none() {
            node.selector = existing.selector.clone();
        }
        if node.target_namespace.is_none() {
            node.target_namespace = existing.target_namespace.clone();
        }
        if node.service_account.is_none() {
            node.service_account = existing.service_account.clone();
        }
        node.allow_peer_traffic = existing.allow_peer_traffic;
        node.depends_all = existing.depends_all;
        node.ambient = existing.ambient;
        node.type_ = existing.type_.clone();

        node
    }

    /// When a MeshMember node replaces a Local, preserve Local-owned fields.
    fn preserve_local_fields(mut node: ServiceNode, existing: &ServiceNode) -> ServiceNode {
        if existing.type_ == ServiceType::MeshMember {
            return node;
        }

        if node.allowed_callers.is_empty() && !node.allows_all {
            node.allowed_callers = existing.allowed_callers.clone();
            node.allows_all = existing.allows_all;
        }
        if node.dependencies.is_empty() {
            node.dependencies = existing.dependencies.clone();
        }

        node
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

/// Compute a stable hash of active edges plus policy epochs.
///
/// Sorts edges by namespace/name so the hash is stable regardless of graph
/// iteration order, appends policy and cedar epoch suffixes, then feeds the
/// result through `deterministic_hash`. The cedar epoch ensures that policy changes
/// trigger re-reconciliation even when graph topology is unchanged.
pub fn compute_edge_hash(
    inbound: &[ActiveEdge],
    outbound: &[ActiveEdge],
    cedar_epoch: u64,
) -> String {
    use std::fmt::Write;

    let mut sorted_in: Vec<_> = inbound
        .iter()
        .map(|e| (&e.caller_namespace, &e.caller_name))
        .collect();
    sorted_in.sort();

    let mut sorted_out: Vec<_> = outbound
        .iter()
        .map(|e| (&e.callee_namespace, &e.callee_name))
        .collect();
    sorted_out.sort();

    let mut input = String::new();
    for (ns, name) in &sorted_in {
        let _ = write!(input, "in:{ns}/{name}->");
    }
    for (ns, name) in &sorted_out {
        let _ = write!(input, "out:{ns}/{name}->");
    }
    let _ = write!(input, "cedar:{cedar_epoch}");
    lattice_core::deterministic_hash(&input)
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

    /// Services with `depends_all: true` (wildcard outbound)
    depends_all_nodes: DashSet<QualifiedName>,

    /// Volume ownership index: (namespace, volume_id) -> VolumeOwnership
    ///
    /// Only shared volumes (those with both `id` and `size`) are indexed.
    /// Updated on put_service/delete_service.
    volume_owners: DashMap<(String, String), VolumeOwnership>,

    /// This cluster's name. Used to filter `allowed_services` entries by cluster
    /// during `put_remote_service()` so that only entries matching the local cluster
    /// are admitted into `allowed_callers`. Without this, a remote service declaring
    /// `allowed_services: ["clusterA/ns/svc"]` would match `ns/svc` on ANY cluster.
    cluster_name: Option<String>,

    /// SPIFFE trust domain derived from the root CA fingerprint.
    /// Used by policy compilers to generate AuthorizationPolicy principals.
    /// All clusters sharing the same root CA have the same trust domain.
    trust_domain: String,
}

impl ServiceGraph {
    /// Dump the graph state as JSON for diagnostic purposes.
    ///
    /// Returns vertices (with node summaries), edges_out, edges_in, and
    /// depends_all_nodes. Skips internal bookkeeping (volume_owners).
    pub fn dump_json(&self) -> serde_json::Value {
        let mut vertices = serde_json::Map::new();
        for entry in self.vertices.iter() {
            let (ns, name) = entry.key();
            let node = entry.value();
            let key = format!("{}/{}", ns, name);

            let type_str = match &node.type_ {
                ServiceType::Local => "Local",
                ServiceType::MeshMember => "MeshMember",
                ServiceType::Remote { .. } => "Remote",
                ServiceType::Unknown => "Unknown",
            };

            let deps: Vec<String> = node
                .dependencies
                .iter()
                .map(|(dns, dn)| format!("{}/{}", dns, dn))
                .collect();

            let callers: Vec<String> = node
                .allowed_callers
                .iter()
                .map(|(cns, cn)| format!("{}/{}", cns, cn))
                .collect();

            let ports: serde_json::Map<String, serde_json::Value> = node
                .ports
                .iter()
                .map(|(pname, pm)| {
                    (
                        pname.clone(),
                        serde_json::json!({
                            "service_port": pm.service_port,
                            "target_port": pm.target_port,
                        }),
                    )
                })
                .collect();

            vertices.insert(
                key,
                serde_json::json!({
                    "type": type_str,
                    "dependencies": deps,
                    "allowed_callers": callers,
                    "allows_all": node.allows_all,
                    "depends_all": node.depends_all,
                    "ports": ports,
                    "ambient": node.ambient,
                }),
            );
        }

        let mut edges_out = serde_json::Map::new();
        for entry in self.edges_out.iter() {
            let (ns, name) = entry.key();
            let targets: Vec<String> = entry
                .value()
                .iter()
                .map(|(tns, tn)| format!("{}/{}", tns, tn))
                .collect();
            edges_out.insert(format!("{}/{}", ns, name), serde_json::json!(targets));
        }

        let mut edges_in = serde_json::Map::new();
        for entry in self.edges_in.iter() {
            let (ns, name) = entry.key();
            let sources: Vec<String> = entry
                .value()
                .iter()
                .map(|(sns, sn)| format!("{}/{}", sns, sn))
                .collect();
            edges_in.insert(format!("{}/{}", ns, name), serde_json::json!(sources));
        }

        let depends_all: Vec<String> = self
            .depends_all_nodes
            .iter()
            .map(|entry| {
                let (ns, name) = entry.key();
                format!("{}/{}", ns, name)
            })
            .collect();

        serde_json::json!({
            "vertices": vertices,
            "edges_out": edges_out,
            "edges_in": edges_in,
            "depends_all_nodes": depends_all,
        })
    }

    /// Create a new empty service graph
    pub fn new(trust_domain: impl Into<String>) -> Self {
        Self {
            vertices: DashMap::new(),
            edges_out: DashMap::new(),
            edges_in: DashMap::new(),
            ns_index: DashMap::new(),
            depends_all_nodes: DashSet::new(),
            volume_owners: DashMap::new(),
            cluster_name: None,
            trust_domain: trust_domain.into(),
        }
    }

    /// Set the local cluster name for cluster-scoped bilateral agreement filtering.
    pub fn with_cluster_name(mut self, name: impl Into<String>) -> Self {
        self.cluster_name = Some(name.into());
        self
    }

    /// Get the trust domain for SPIFFE principal generation.
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// Insert or update a local service in the graph
    pub fn put_service(&self, namespace: &str, name: &str, spec: &LatticeServiceSpec) {
        let node = ServiceNode::from_service_spec(namespace, name, spec);
        self.put_node(NodeUpdate::Service(node));
        self.update_volume_owners(namespace, name, &spec.workload);
    }

    /// Insert or update a workload in the graph (used by model/job controllers).
    ///
    /// Uses the same authoritative semantics as `put_service`: the caller list
    /// from the WorkloadSpec plus `extra_callers` is the source of truth.
    /// Model controllers pass infrastructure callers (kthena-router, etc.) via
    /// `extra_callers`; jobs pass `&[]`.
    pub fn put_workload(
        &self,
        namespace: &str,
        name: &str,
        workload: &WorkloadSpec,
        extra_callers: &[ServiceRef],
    ) {
        let mut node = ServiceNode::from_workload_spec(namespace, name, workload);
        for caller in extra_callers {
            let ns = caller.resolve_namespace(namespace).to_string();
            node.allowed_callers.insert((ns, caller.name.clone()));
        }
        self.put_node(NodeUpdate::Service(node));
        self.update_volume_owners(namespace, name, workload);
    }

    /// Insert or update a mesh member in the graph
    pub fn put_mesh_member(&self, namespace: &str, name: &str, spec: &LatticeMeshMemberSpec) {
        let node = ServiceNode::from_mesh_member_spec(namespace, name, spec);
        self.put_node(NodeUpdate::MeshMember(node));
    }

    /// Insert or update a remote service from a `ClusterRoute`.
    ///
    /// Remote services are registered with `allowed_callers` derived from the
    /// route's `allowed_services`. Empty list = fail-closed (nobody allowed).
    /// Must use `["*"]` explicitly to allow all callers.
    pub fn put_remote_service(&self, source_cluster: &str, route: &lattice_crd::crd::ClusterRoute) {
        let namespace = &route.service_namespace;
        let name = &route.service_name;

        // Don't overwrite local or mesh-member nodes — local takes precedence.
        // For Remote nodes from a different cluster with the same hostname,
        // use first-writer-wins to keep the existing working route stable.
        if let Some(existing) = self
            .vertices
            .get(&(namespace.to_string(), name.to_string()))
        {
            if existing.type_.is_local() || existing.type_.is_mesh_member() {
                return;
            }
            if let ServiceType::Remote {
                source_cluster: ref existing_source,
                hostname: ref existing_host,
                ..
            } = existing.type_
            {
                if existing_source != source_cluster && *existing_host == route.hostname {
                    warn!(
                        hostname = %route.hostname,
                        existing_cluster = %existing_source,
                        new_cluster = %source_cluster,
                        service = %format!("{}/{}", namespace, name),
                        "Route conflict: hostname advertised by multiple clusters, keeping existing route"
                    );
                    return;
                }
            }
        }

        // Parse allowed_services into (namespace, name) pairs for bilateral agreement.
        // Format: "cluster/namespace/name" or "*" for wildcard.
        // Empty list = fail-closed (advertised but nobody allowed).
        //
        // SECURITY: Only admit entries whose cluster component matches the local
        // cluster name. Without this filter, "clusterA/ns/svc" would match any
        // cluster that has a service "ns/svc", breaking cross-cluster isolation.
        let is_wildcard = route.allowed_services.iter().any(|s| s == "*");
        let mut callers = HashSet::new();
        let local_cluster = self.cluster_name.as_deref();
        for entry in &route.allowed_services {
            if entry == "*" {
                continue;
            }
            let parts: Vec<&str> = entry.splitn(3, '/').collect();
            if parts.len() == 3 {
                match local_cluster {
                    Some(lc) if parts[0] == lc => {
                        callers.insert((parts[1].to_string(), parts[2].to_string()));
                    }
                    Some(_) => {
                        // Entry targets a different cluster — not relevant here
                    }
                    None => {
                        warn!(
                            entry = %entry,
                            "cluster_name not set on ServiceGraph, cannot filter allowed_services — fail-closed"
                        );
                    }
                }
            }
        }

        let node = ServiceNode {
            namespace: namespace.to_string(),
            name: name.to_string(),
            type_: ServiceType::Remote {
                source_cluster: source_cluster.to_string(),
                address: route.address.clone(),
                port: route.port,
                hostname: route.hostname.clone(),
            },
            dependencies: vec![],
            allowed_callers: callers,
            allows_all: is_wildcard,
            depends_all: false,
            image: None,
            ports: BTreeMap::new(),
            selector: None,
            target_namespace: None,
            allow_peer_traffic: false,
            egress_rules: vec![],
            service_account: None,
            ambient: true,
            advertise: None,
        };
        self.put_node(NodeUpdate::Service(node));
    }

    /// Sync remote services for a specific source cluster.
    ///
    /// Removes all `Remote` nodes that were sourced from `source_cluster` and
    /// inserts the new routes. This is per-cluster, so updates from cluster A
    /// don't affect routes from cluster B (no flapping).
    pub fn sync_remote_services(
        &self,
        source_cluster: &str,
        routes: &[lattice_crd::crd::ClusterRoute],
    ) {
        // Remove existing remote nodes from this source cluster only
        let stale_keys: Vec<QualifiedName> = self
            .vertices
            .iter()
            .filter(|entry| {
                matches!(
                    &entry.value().type_,
                    ServiceType::Remote { source_cluster: ref sc, .. } if sc == source_cluster
                )
            })
            .map(|entry| entry.key().clone())
            .collect();

        for (ns, name) in &stale_keys {
            self.vertices.remove(&(ns.clone(), name.clone()));
            self.edges_out.remove(&(ns.clone(), name.clone()));
            self.edges_in.remove(&(ns.clone(), name.clone()));
            if let Some(mut ns_set) = self.ns_index.get_mut(ns) {
                ns_set.remove(name);
            }
        }

        // Insert new remote nodes
        for route in routes {
            self.put_remote_service(source_cluster, route);
        }
    }

    /// Internal: Insert a node and update all edge indices.
    ///
    /// The `NodeUpdate` variant determines which fields are preserved from
    /// any existing node. See `NodeUpdate::into_merged` for the merge rules.
    fn put_node(&self, update: NodeUpdate) {
        let key = update.key();

        // Merge with existing node, respecting field ownership per variant.
        // The block scope ensures the DashMap read-lock is dropped before insert.
        let node = {
            let existing = self.vertices.get(&key);
            update.into_merged(existing.as_deref())
        };

        // Clone dependencies before moving node
        let dependencies = node.dependencies.clone();
        let namespace = node.namespace.clone();
        let name = node.name.clone();
        let depends_all = node.depends_all;
        let source_key = (namespace.clone(), name.clone());

        // Snapshot old outbound targets for diff-based update
        let old_targets: HashSet<QualifiedName> = self
            .edges_out
            .get(&key)
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default();
        let new_targets: HashSet<QualifiedName> = dependencies.iter().cloned().collect();

        // Store the node
        self.vertices.insert(key.clone(), node);

        // Maintain depends_all index
        if depends_all {
            self.depends_all_nodes.insert(key.clone());
        } else {
            self.depends_all_nodes.remove(&key);
        }

        // Diff-based edge update: only touch edges that actually changed.
        // No remove-then-readd, so concurrent readers never see a stale empty state.
        let removed = old_targets.difference(&new_targets);
        let added = new_targets.difference(&old_targets);

        for target in removed {
            if let Some(mut in_edges) = self.edges_in.get_mut(target) {
                in_edges.retain(|e| e != &source_key);
            }
        }

        for target in added {
            self.edges_in
                .entry(target.clone())
                .and_modify(|edges| {
                    if !edges.contains(&source_key) {
                        edges.push(source_key.clone());
                    }
                })
                .or_insert_with(|| vec![source_key.clone()]);

            // Create unknown stub if dependency doesn't exist
            if !self.vertices.contains_key(target) {
                self.vertices
                    .insert(target.clone(), ServiceNode::unknown(&target.0, &target.1));
            }
        }

        // Update edges_out in one shot
        if new_targets.is_empty() {
            self.edges_out.remove(&key);
        } else {
            self.edges_out.insert(key.clone(), dependencies);
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
                if caller.type_.is_unknown() {
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

        // depends_all nodes: any local service with depends_all that this service allows.
        // Skip if the callee (this service) is remote — depends_all is local-only.
        if !service.type_.is_remote() {
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
                    Some(c) if !c.type_.is_unknown() => {}
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

                let allowed = if callee.type_.is_unknown() {
                    warn!(
                        caller = %format!("{}/{}", namespace, name),
                        callee = %format!("{}/{}", callee_ns, callee_name),
                        "skipping outbound edge to unknown service (check dependency name)"
                    );
                    false
                } else {
                    callee.allows(namespace, name)
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

        // depends_all: check all local services that allow this caller
        // Remote (cross-cluster) services are excluded — depends_all is for
        // local cluster dependencies only (e.g. metrics scraping, routing).
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
                if node.type_.is_unknown() || node.type_.is_remote() {
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
                        node.type_.is_local().then_some(node)
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
                        node.type_.is_mesh_member().then_some(node)
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

    /// All (namespace, name) pairs for nodes that could have a LatticeMeshMember.
    ///
    /// Includes both Local (LatticeService-created) and MeshMember nodes.
    /// Used by watch mappers to trigger MeshMember re-reconciliation.
    pub fn all_mesh_eligible(&self) -> Vec<(String, String)> {
        self.vertices
            .iter()
            .filter(|entry| entry.value().type_.is_local() || entry.value().type_.is_mesh_member())
            .map(|entry| {
                let (ns, name) = entry.key();
                (ns.clone(), name.clone())
            })
            .collect()
    }

    /// Get all node names in a namespace (all types, including Unknown).
    pub fn all_names_in_namespace(&self, namespace: &str) -> HashSet<String> {
        self.ns_index
            .get(namespace)
            .map(|index| index.clone())
            .unwrap_or_default()
    }

    /// Get count of services in a namespace
    pub fn service_count(&self, namespace: &str) -> usize {
        self.ns_index
            .get(namespace)
            .map(|index| index.len())
            .unwrap_or(0)
    }

    /// Get the owner of a shared volume by namespace and volume ID.
    ///
    /// Returns `None` if no service owns a volume with this ID in this namespace.
    pub fn get_volume_owner(&self, namespace: &str, volume_id: &str) -> Option<VolumeOwnership> {
        let key = (namespace.to_string(), volume_id.to_string());
        self.volume_owners.get(&key).map(|v| v.clone())
    }

    /// Update the volume ownership index for a workload.
    ///
    /// Removes all previous ownership entries for this workload, then indexes
    /// any owned shared volumes (those with both `id` and `size`).
    fn update_volume_owners(&self, namespace: &str, name: &str, workload: &WorkloadSpec) {
        // Remove stale entries for this workload
        self.volume_owners
            .retain(|_, v| !(v.owner_namespace == namespace && v.owner_name == name));

        // Index owned shared volumes
        for resource in workload.resources.values() {
            if !resource.type_.is_volume() {
                continue;
            }
            let Some(ref volume_id) = resource.id else {
                continue;
            };
            let params = match resource.params.as_volume() {
                Some(p) => p,
                None => continue,
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
                    params: params.clone(),
                },
            );
        }
    }

    /// Return all services with `depends_all: true`.
    ///
    /// These services have dynamic outbound edges that are computed on the fly
    /// rather than stored in edges_out, so they need explicit re-reconciliation
    /// triggers when any service in the graph changes.
    pub fn depends_all_services(&self) -> Vec<QualifiedName> {
        self.depends_all_nodes.iter().map(|e| e.clone()).collect()
    }
}

/// Thread-safe shared reference to a service graph
pub type SharedServiceGraph = Arc<ServiceGraph>;

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_core::VMAGENT_SA_NAME;
    use std::collections::BTreeMap;

    fn make_service_spec(deps: Vec<&str>, callers: Vec<&str>) -> LatticeServiceSpec {
        use lattice_crd::crd::{
            ContainerSpec, DependencyDirection, PortSpec, ResourceSpec, ServicePortsSpec,
            WorkloadSpec,
        };

        LatticeServiceSpec {
            workload: WorkloadSpec {
                containers: BTreeMap::from([(
                    "main".to_string(),
                    ContainerSpec {
                        image: "test:latest".to_string(),
                        ..Default::default()
                    },
                )]),
                resources: deps
                    .into_iter()
                    .map(|d| {
                        (
                            d.to_string(),
                            ResourceSpec {
                                direction: DependencyDirection::Outbound,
                                ..Default::default()
                            },
                        )
                    })
                    .chain(callers.into_iter().map(|c| {
                        (
                            c.to_string(),
                            ResourceSpec {
                                direction: DependencyDirection::Inbound,
                                ..Default::default()
                            },
                        )
                    }))
                    .collect(),
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
        }
    }

    #[test]
    fn test_put_and_get_service() {
        let graph = ServiceGraph::new("lattice.test");
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
        use lattice_crd::crd::{
            ContainerSpec, DependencyDirection, PortSpec, ResourceParams, ResourceSpec,
            ResourceType, ServicePortsSpec, WorkloadSpec,
        };

        let graph = ServiceGraph::new("lattice.test");

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
                params: ResourceParams::None,
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
        let graph = ServiceGraph::new("lattice.test");

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
    fn test_delete_service() {
        let graph = ServiceGraph::new("lattice.test");

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
        let graph = ServiceGraph::new("lattice.test");

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
        let graph = ServiceGraph::new("lattice.test");

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
        let graph = ServiceGraph::new("lattice.test");

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
        let graph = ServiceGraph::new("lattice.test");

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
        use lattice_crd::crd::{
            ContainerSpec, DependencyDirection, PortSpec, ResourceParams, ResourceSpec,
            ResourceType, ServicePortsSpec, WorkloadSpec,
        };

        let graph = ServiceGraph::new("lattice.test");

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
                params: ResourceParams::None,
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
        let graph = ServiceGraph::new("lattice.test");

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
        let graph = ServiceGraph::new("lattice.test");

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

    // =========================================================================
    // Listing and Query Tests
    // =========================================================================

    #[test]
    fn test_list_services_filters_local_only() {
        let graph = ServiceGraph::new("lattice.test");

        // Add local service
        let local_spec = make_service_spec(vec![], vec![]);
        graph.put_service("test-ns", "local-svc", &local_spec);

        // Add mesh member (non-local)
        let labels = BTreeMap::from([("app".to_string(), "ext".to_string())]);
        let mm_spec = make_mesh_member_spec(labels, vec![("http", 8080)], vec![], vec![]);
        graph.put_mesh_member("test-ns", "mm-svc", &mm_spec);

        let services = graph.list_services("test-ns");
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, "local-svc");
    }

    #[test]
    fn test_list_services_empty_namespace() {
        let graph = ServiceGraph::new("lattice.test");
        let services = graph.list_services("nonexistent");
        assert!(services.is_empty());
    }

    #[test]
    fn test_list_namespaces() {
        let graph = ServiceGraph::new("lattice.test");

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
        let graph = ServiceGraph::new("lattice.test");

        let spec = make_service_spec(vec![], vec![]);
        graph.put_service("ns1", "svc1", &spec);
        graph.delete_service("ns1", "svc1");

        // ns1 should be excluded since it's now empty
        let namespaces = graph.list_namespaces();
        assert!(!namespaces.contains(&"ns1".to_string()));
    }

    #[test]
    fn test_service_count() {
        let graph = ServiceGraph::new("lattice.test");

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
        use lattice_crd::crd::{MeshMemberPort, PeerAuth, ServiceRef};

        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(labels),
            ports: ports
                .into_iter()
                .map(|(name, port)| MeshMemberPort {
                    port,
                    service_port: None,
                    name: name.to_string(),
                    peer_auth: PeerAuth::Strict,
                })
                .collect(),
            allowed_callers: callers.into_iter().map(ServiceRef::local).collect(),
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
            ambient: true, advertise: None,
        }
    }

    #[test]
    fn test_put_mesh_member() {
        let graph = ServiceGraph::new("lattice.test");
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
        let graph = ServiceGraph::new("lattice.test");

        // MeshMember allows "api" caller
        let labels = BTreeMap::from([("app".to_string(), "prometheus".to_string())]);
        let mm_spec = make_mesh_member_spec(labels, vec![("metrics", 9090)], vec!["api"], vec![]);
        graph.put_mesh_member("monitoring", "prometheus", &mm_spec);

        // api depends on prometheus — need cross-namespace dep, build manually
        {
            use lattice_crd::crd::{
                ContainerSpec, DependencyDirection, PortSpec, ResourceParams, ResourceSpec,
                ResourceType, ServicePortsSpec, WorkloadSpec,
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
                    params: ResourceParams::None,
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
        let graph = ServiceGraph::new("lattice.test");

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
        let graph = ServiceGraph::new("lattice.test");

        let spec = LatticeMeshMemberSpec {
            target: MeshMemberTarget::Namespace("kube-system".to_string()),
            ports: vec![lattice_crd::crd::MeshMemberPort {
                port: 443,
                service_port: None,
                name: "https".to_string(),
                peer_auth: lattice_crd::crd::PeerAuth::Permissive,
            }],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![],
            allow_peer_traffic: false,
            depends_all: false,
            ingress: None,
            service_account: None,
            ambient: true, advertise: None,
        };

        graph.put_mesh_member("default", "kube-api-access", &spec);

        let node = graph.get_service("default", "kube-api-access").unwrap();
        assert_eq!(node.type_, ServiceType::MeshMember);
        assert_eq!(node.selector, None);
        assert_eq!(node.target_namespace, Some("kube-system".to_string()));
    }

    #[test]
    fn test_mesh_member_with_dependencies() {
        let graph = ServiceGraph::new("lattice.test");

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
        let graph = ServiceGraph::new("lattice.test");

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
        let graph = ServiceGraph::new("lattice.test");
        let labels = BTreeMap::from([("app".to_string(), "scraper".to_string())]);
        let mut spec = make_mesh_member_spec(labels, vec![("http", 8080)], vec![], vec![]);
        spec.depends_all = true;

        graph.put_mesh_member("monitoring", "scraper", &spec);

        let node = graph.get_service("monitoring", "scraper").unwrap();
        assert!(node.depends_all);
    }

    #[test]
    fn test_depends_all_outbound_edges() {
        let graph = ServiceGraph::new("lattice.test");

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
        let graph = ServiceGraph::new("lattice.test");

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
        let graph = ServiceGraph::new("lattice.test");

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
        let graph = ServiceGraph::new("lattice.test");

        // scraper in monitoring has depends_all
        let labels = BTreeMap::from([("app".to_string(), "scraper".to_string())]);
        let mut spec = make_mesh_member_spec(labels, vec![("http", 8080)], vec![], vec![]);
        spec.depends_all = true;
        graph.put_mesh_member("monitoring", "scraper", &spec);

        // api in prod allows scraper from monitoring
        use lattice_crd::crd::{
            ContainerSpec, DependencyDirection, PortSpec, ResourceParams, ResourceSpec,
            ResourceType, ServicePortsSpec, WorkloadSpec,
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
                params: ResourceParams::None,
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
        let graph = ServiceGraph::new("lattice.test");

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
        let graph = ServiceGraph::new("lattice.test");

        // Service without a "metrics" port
        let labels = BTreeMap::from([("app".to_string(), "api".to_string())]);
        let spec = make_mesh_member_spec(labels, vec![("http", 8080)], vec![], vec![]);
        graph.put_mesh_member("prod", "api", &spec);

        let node = graph.get_service("prod", "api").unwrap();
        assert!(!node.allows("monitoring", "vmagent"));
    }

    #[test]
    fn test_depends_all_vmagent_reaches_metrics_port() {
        let graph = ServiceGraph::new("lattice.test");

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
        let graph = ServiceGraph::new("lattice.test");

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

    #[test]
    fn test_depends_all_excludes_remote_services() {
        use lattice_crd::crd::ClusterRoute;

        let graph = ServiceGraph::new("lattice.test").with_cluster_name("mgmt");

        // scraper has depends_all
        let labels = BTreeMap::from([("app".to_string(), "scraper".to_string())]);
        let mut spec = make_mesh_member_spec(labels, vec![("http", 8080)], vec![], vec![]);
        spec.depends_all = true;
        graph.put_mesh_member("prod", "scraper", &spec);

        // local api allows scraper
        let api_spec = make_service_spec(vec![], vec!["scraper"]);
        graph.put_service("prod", "api", &api_spec);

        // remote service allows scraper (via wildcard)
        let route = ClusterRoute {
            service_name: "remote-svc".to_string(),
            service_namespace: "prod".to_string(),
            hostname: "remote-svc.example.local".to_string(),
            address: "10.0.0.100".to_string(),
            port: 80,
            protocol: "HTTP".to_string(),
            allowed_services: vec!["*".to_string()],
            service_ports: Default::default(),
        };
        graph.put_remote_service("child-cluster", &route);

        // scraper should have outbound edge to local api but NOT remote-svc
        let outbound = graph.get_active_outbound_edges("prod", "scraper");
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].callee_name, "api");

        // remote-svc should NOT have inbound from scraper via depends_all
        let remote_inbound = graph.get_active_inbound_edges("prod", "remote-svc");
        assert!(
            remote_inbound.is_empty(),
            "depends_all should not create edges to remote services"
        );
    }

    // =========================================================================
    #[test]
    fn put_service_preserves_mesh_member_egress_rules() {
        use lattice_crd::crd::{
            EgressRule, EgressTarget, LatticeMeshMemberSpec, MeshMemberTarget, PeerAuth,
        };

        let graph = ServiceGraph::new("lattice.test");

        // MeshMember controller writes node with egress rules
        let mm_spec = LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::new()),
            ports: vec![lattice_crd::crd::MeshMemberPort {
                port: 8080,
                service_port: None,
                name: "http".to_string(),
                peer_auth: PeerAuth::Strict,
            }],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![EgressRule::tcp(
                EgressTarget::Fqdn("example.com".to_string()),
                vec![443],
            )],
            allow_peer_traffic: false,
            depends_all: false,
            ingress: None,
            service_account: Some("custom-sa".to_string()),
            ambient: true, advertise: None,
        };
        graph.put_mesh_member("ns", "frontend", &mm_spec);

        let node = graph.get_service("ns", "frontend").unwrap();
        assert_eq!(node.egress_rules.len(), 1);
        assert_eq!(node.service_account, Some("custom-sa".to_string()));
        assert!(!node.ports.is_empty());

        // Service controller writes node (would previously clobber egress_rules)
        let svc_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service("ns", "frontend", &svc_spec);

        let node = graph.get_service("ns", "frontend").unwrap();
        assert_eq!(
            node.egress_rules.len(),
            1,
            "put_service must preserve MeshMember egress_rules"
        );
        assert_eq!(
            node.service_account,
            Some("custom-sa".to_string()),
            "put_service must preserve MeshMember service_account"
        );
        assert!(
            !node.ports.is_empty(),
            "put_service must preserve MeshMember ports"
        );
    }

    #[test]
    fn put_mesh_member_overwrites_service_egress_rules() {
        use lattice_crd::crd::{
            EgressRule, EgressTarget, LatticeMeshMemberSpec, MeshMemberTarget, PeerAuth,
        };

        let graph = ServiceGraph::new("lattice.test");

        // Service controller writes node first
        let svc_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service("ns", "frontend", &svc_spec);

        // MeshMember controller writes node with egress rules
        let mm_spec = LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::new()),
            ports: vec![lattice_crd::crd::MeshMemberPort {
                port: 8080,
                service_port: None,
                name: "http".to_string(),
                peer_auth: PeerAuth::Strict,
            }],
            allowed_callers: vec![],
            dependencies: vec![lattice_crd::crd::ServiceRef {
                name: "api".to_string(),
                namespace: None,
            }],
            egress: vec![EgressRule::tcp(
                EgressTarget::Fqdn("example.com".to_string()),
                vec![443],
            )],
            allow_peer_traffic: false,
            depends_all: false,
            ingress: None,
            service_account: None,
            ambient: true, advertise: None,
        };
        graph.put_mesh_member("ns", "frontend", &mm_spec);

        let node = graph.get_service("ns", "frontend").unwrap();
        assert_eq!(node.egress_rules.len(), 1);
        assert_eq!(node.type_, ServiceType::MeshMember);
    }

    /// put_workload is authoritative on callers: extra_callers are set, empty
    /// extra_callers means "no callers" (same as put_service).
    #[test]
    fn test_put_workload_extra_callers_are_authoritative() {
        use lattice_crd::crd::ServiceRef;

        let graph = ServiceGraph::new("lattice.test");

        // Mesh member controller sets allowed_callers
        let labels = BTreeMap::from([("app".to_string(), "serving".to_string())]);
        let mm_spec =
            make_mesh_member_spec(labels, vec![("inference", 8000)], vec!["router"], vec![]);
        graph.put_mesh_member("ns", "serving-prefill", &mm_spec);

        // Model controller overwrites with put_workload passing explicit callers
        let svc_spec = make_service_spec(vec![], vec![]);
        let callers = vec![ServiceRef::new("kthena-system", "kthena-router")];
        graph.put_workload("ns", "serving-prefill", &svc_spec.workload, &callers);

        let node = graph.get_service("ns", "serving-prefill").unwrap();
        assert!(
            node.allowed_callers
                .contains(&("kthena-system".to_string(), "kthena-router".to_string())),
            "extra_callers should be set on the node"
        );
    }

    /// Regression: put_service (LS controller) MUST be able to clear callers.
    /// This is the feedback loop fix — LS is authoritative on callers.
    #[test]
    fn test_put_service_clears_allowed_callers() {
        let graph = ServiceGraph::new("lattice.test");

        // Mesh member controller sets allowed_callers
        let labels = BTreeMap::from([("app".to_string(), "rm-internal".to_string())]);
        let mm_spec =
            make_mesh_member_spec(labels, vec![("http", 8080)], vec!["rm-client"], vec![]);
        graph.put_mesh_member("ns", "rm-internal", &mm_spec);

        // LS controller reconciles with no callers (rm-client removed from spec)
        let svc_spec = make_service_spec(vec![], vec![]);
        graph.put_service("ns", "rm-internal", &svc_spec);

        let node = graph.get_service("ns", "rm-internal").unwrap();
        assert!(
            node.allowed_callers.is_empty(),
            "put_service must clear allowed_callers when spec has none, got: {:?}",
            node.allowed_callers
        );
    }

    /// put_workload with empty extra_callers clears callers (authoritative).
    #[test]
    fn test_put_workload_empty_callers_clears() {
        let graph = ServiceGraph::new("lattice.test");

        // Mesh member with wildcard callers
        let labels = BTreeMap::from([("app".to_string(), "api".to_string())]);
        let mm_spec = make_mesh_member_spec(labels, vec![("http", 80)], vec!["*"], vec![]);
        graph.put_mesh_member("ns", "api", &mm_spec);

        // Model controller overwrites with put_workload (no extra callers)
        let svc_spec = make_service_spec(vec![], vec![]);
        graph.put_workload("ns", "api", &svc_spec.workload, &[]);

        let node = graph.get_service("ns", "api").unwrap();
        assert!(
            !node.allows_all,
            "put_workload with empty callers must not preserve allows_all"
        );
    }
}
