//! Network policy types and compilation for Lattice mesh members
//!
//! This module provides policy compilation logic implementing a defense-in-depth model:
//!
//! - **L7 (Istio AuthorizationPolicy)**: mTLS identity-based access control using SPIFFE principals
//! - **L4 (CiliumNetworkPolicy)**: eBPF-based network enforcement at the kernel level
//!
//! Policy compilation is split into provider-specific sub-modules:
//! - [`istio_ambient`]: L7 policies (AuthorizationPolicy, ServiceEntry, PeerAuthentication)
//! - [`cilium`]: L4 policies (CiliumNetworkPolicy)

pub(crate) mod cilium;
mod istio_ambient;

use lattice_common::crd::EgressTarget;
use lattice_common::graph::ServiceGraph;
use lattice_common::policy::cilium::CiliumNetworkPolicy;
use lattice_common::policy::istio::{AuthorizationPolicy, PeerAuthentication};
use lattice_common::policy::service_entry::ServiceEntry;

// =============================================================================
// Generated Policies Container
// =============================================================================

/// Collection of all policies generated for a mesh member
#[derive(Clone, Debug, Default)]
pub struct GeneratedPolicies {
    /// Istio AuthorizationPolicies
    pub authorization_policies: Vec<AuthorizationPolicy>,
    /// Cilium Network Policies
    pub cilium_policies: Vec<CiliumNetworkPolicy>,
    /// Istio ServiceEntries
    pub service_entries: Vec<ServiceEntry>,
    /// Istio PeerAuthentication (port-level mTLS overrides)
    pub peer_authentications: Vec<PeerAuthentication>,
}

impl GeneratedPolicies {
    /// Check if any policies were generated
    pub fn is_empty(&self) -> bool {
        self.authorization_policies.is_empty()
            && self.cilium_policies.is_empty()
            && self.service_entries.is_empty()
            && self.peer_authentications.is_empty()
    }

    /// Total count of all generated policies
    pub fn total_count(&self) -> usize {
        self.authorization_policies.len()
            + self.cilium_policies.len()
            + self.service_entries.len()
            + self.peer_authentications.len()
    }

    /// Clone with ServiceEntries removed (used when waypoint is not yet ready)
    pub fn without_service_entries(&self) -> Self {
        Self {
            authorization_policies: self.authorization_policies.clone(),
            cilium_policies: self.cilium_policies.clone(),
            service_entries: Vec::new(),
            peer_authentications: self.peer_authentications.clone(),
        }
    }
}

// =============================================================================
// Policy Compiler
// =============================================================================

/// Compiler for generating network policies from the service graph
///
/// This compiler implements defense-in-depth with:
/// - L7 (Istio AuthorizationPolicy): mTLS identity-based access control
/// - L4 (CiliumNetworkPolicy): eBPF-based network enforcement
///
/// Policies are only generated for edges that satisfy bilateral agreement:
/// caller declares dependency AND callee allows caller.
pub struct PolicyCompiler<'a> {
    graph: &'a ServiceGraph,
    cluster_name: String,
}

impl<'a> PolicyCompiler<'a> {
    /// Create a new policy compiler
    ///
    /// # Arguments
    /// * `graph` - The service graph for bilateral agreement checks
    /// * `cluster_name` - Cluster name used in trust domain (lattice.{cluster}.local)
    pub fn new(graph: &'a ServiceGraph, cluster_name: impl Into<String>) -> Self {
        Self {
            graph,
            cluster_name: cluster_name.into(),
        }
    }

    /// Compile all mesh policies for a member.
    ///
    /// This is the single entry point for all mesh policy generation.
    /// Uses the node's custom selector labels and supports permissive ports,
    /// peer traffic, non-mesh egress rules, and external dependencies.
    pub fn compile(&self, name: &str, namespace: &str) -> GeneratedPolicies {
        let Some(service_node) = self.graph.get_service(namespace, name) else {
            return GeneratedPolicies::default();
        };

        if service_node.type_.is_unknown() {
            return GeneratedPolicies::default();
        }

        let mut output = GeneratedPolicies::default();

        let inbound_edges = self.graph.get_active_inbound_edges(namespace, name);
        let outbound_edges = self.graph.get_active_outbound_edges(namespace, name);

        // Istio AuthorizationPolicy for inbound (ztunnel-enforced)
        if let Some(auth_policy) =
            self.compile_inbound_policy(&service_node, namespace, &inbound_edges)
        {
            output.authorization_policies.push(auth_policy);
        }

        // Cilium policy (handles inbound, outbound, DNS, FQDN egress, HBONE)
        output.cilium_policies.push(self.compile_cilium_policy(
            &service_node,
            namespace,
            &inbound_edges,
            &outbound_edges,
        ));

        // Permissive mTLS policies (PeerAuthentication + AuthorizationPolicy)
        let (peer_auths, auth_policies) =
            self.compile_permissive_policies(&service_node, namespace);
        output.peer_authentications.extend(peer_auths);
        output.authorization_policies.extend(auth_policies);

        // External egress: ServiceEntry + AuthorizationPolicy + waypoint
        // Handles inline external endpoints and FQDN egress rules.
        self.compile_egress(&service_node, namespace, &mut output);

        output
    }

    /// Compile external egress policies from FQDN egress rules.
    ///
    /// Generates Istio ServiceEntry + AuthorizationPolicy per FQDN target,
    /// plus a ztunnel waypoint allow policy if any ServiceEntries were generated.
    ///
    /// Cilium FQDN egress is handled separately in `compile_cilium_policy()`.
    fn compile_egress(
        &self,
        service_node: &lattice_common::graph::ServiceNode,
        namespace: &str,
        output: &mut GeneratedPolicies,
    ) {
        for rule in &service_node.egress_rules {
            if let EgressTarget::Fqdn(ref fqdn) = rule.target {
                output
                    .service_entries
                    .push(self.compile_fqdn_egress_service_entry(
                        &service_node.name,
                        namespace,
                        fqdn,
                        &rule.ports,
                    ));
                output
                    .authorization_policies
                    .push(self.compile_fqdn_egress_access_policy(
                        service_node,
                        namespace,
                        fqdn,
                        &rule.ports,
                    ));
            }
        }

        // Waypoint: if any ServiceEntries were generated, need ztunnel allow for waypoint→pod
        if !output.service_entries.is_empty() {
            if let Some(waypoint_policy) =
                self.compile_ztunnel_allow_policy(service_node, namespace)
            {
                output.authorization_policies.push(waypoint_policy);
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::PolicyCompiler;
    use lattice_common::crd::{
        ContainerSpec, DependencyDirection, EgressRule, EgressTarget, PortSpec, ResourceSpec,
        ServicePortsSpec, WorkloadSpec,
    };
    use lattice_common::graph::ServiceGraph;
    use lattice_common::mesh;
    use lattice_common::policy::cilium::{CiliumEgressRule, FqdnSelector};
    use std::collections::BTreeMap;

    pub(crate) fn make_service_spec(
        deps: Vec<&str>,
        callers: Vec<&str>,
    ) -> lattice_common::crd::LatticeServiceSpec {
        let mut resources = BTreeMap::new();
        for dep in deps {
            resources.insert(
                dep.to_string(),
                ResourceSpec {
                    direction: DependencyDirection::Outbound,
                    ..Default::default()
                },
            );
        }
        for caller in callers {
            resources.insert(
                caller.to_string(),
                ResourceSpec {
                    direction: DependencyDirection::Inbound,
                    ..Default::default()
                },
            );
        }

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                ..Default::default()
            },
        );

        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 8080,
                target_port: None,
                protocol: None,
            },
        );

        lattice_common::crd::LatticeServiceSpec {
            workload: WorkloadSpec {
                containers,
                resources,
                service: Some(ServicePortsSpec { ports }),
            },
            ..Default::default()
        }
    }

    #[test]
    fn bilateral_agreement_generates_policy() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let api_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service(ns, "api", &api_spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", "prod-ns");

        assert!(!output.authorization_policies.is_empty());
        let auth = &output.authorization_policies[0];
        // No external deps → ztunnel path (selector, no targetRefs)
        assert!(auth.spec.target_refs.is_empty());
        assert!(auth.spec.selector.is_some());
        assert!(auth.spec.rules[0].from[0]
            .source
            .principals
            .iter()
            .any(|p| p.contains("gateway")));
    }

    #[test]
    fn no_policy_without_bilateral_agreement() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let api_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service(ns, "api", &api_spec);

        let gateway_spec = make_service_spec(vec![], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", "prod-ns");

        assert!(output.authorization_policies.is_empty());
    }

    #[test]
    fn no_policies_when_not_in_graph() {
        let graph = ServiceGraph::new();
        let compiler = PolicyCompiler::new(&graph, "test-cluster");
        let output = compiler.compile("nonexistent", "default");
        assert!(output.is_empty());
    }

    #[test]
    fn spiffe_uses_trust_domain() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let api_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service(ns, "api", &api_spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "my-cluster");
        let output = compiler.compile("api", "prod-ns");

        let principals = &output.authorization_policies[0].spec.rules[0].from[0]
            .source
            .principals;
        assert!(principals[0].starts_with("lattice.my-cluster.local/ns/prod-ns/sa/"));
        assert_eq!(
            principals[0],
            "lattice.my-cluster.local/ns/prod-ns/sa/gateway"
        );
    }

    #[test]
    fn cilium_policy_always_generated() {
        let graph = ServiceGraph::new();
        let ns = "default";

        let spec = make_service_spec(vec![], vec![]);
        graph.put_service(ns, "my-app", &spec);

        let compiler = PolicyCompiler::new(&graph, "test-cluster");
        let output = compiler.compile("my-app", ns);

        assert_eq!(output.cilium_policies.len(), 1);

        // DNS egress always present
        assert!(output.cilium_policies[0].spec.egress.iter().any(|e| e
            .to_ports
            .iter()
            .any(|pr| pr.ports.iter().any(|p| p.port == "53"))));

        // No ztunnel HBONE ingress for services without callers or external deps
        assert!(
            output.cilium_policies[0].spec.ingress.is_empty(),
            "service with no callers or external deps should have no ingress rules"
        );
    }

    #[test]
    fn fqdn_egress_generates_service_entry() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let labels = BTreeMap::from([("lattice.dev/name".to_string(), "api".to_string())]);
        let mut spec = make_mesh_member_spec(labels, vec![], vec![], vec![]);
        spec.egress = vec![EgressRule {
            target: EgressTarget::Fqdn("api.stripe.com".to_string()),
            ports: vec![443],
        }];
        graph.put_mesh_member(ns, "api", &spec);

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", ns);

        assert_eq!(output.service_entries.len(), 1);
        let entry = &output.service_entries[0];
        assert!(entry.spec.hosts.contains(&"api.stripe.com".to_string()));
        assert_eq!(entry.spec.location, "MESH_EXTERNAL");
    }

    #[test]
    fn total_count() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let labels = BTreeMap::from([("lattice.dev/name".to_string(), "api".to_string())]);
        let mut spec = make_mesh_member_spec(
            labels,
            vec![("http", 8080, lattice_common::crd::PeerAuth::Strict)],
            vec!["gateway"],
            vec![],
        );
        spec.egress = vec![EgressRule {
            target: EgressTarget::Fqdn("api.stripe.com".to_string()),
            ports: vec![443],
        }];
        graph.put_mesh_member(ns, "api", &spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", ns);

        assert_eq!(output.cilium_policies.len(), 1);

        // AuthorizationPolicies:
        //    - allow inbound from gateway
        //    - waypoint->pod ztunnel allow policy
        //    - FQDN egress access policy for stripe
        assert_eq!(output.authorization_policies.len(), 3);

        assert_eq!(output.service_entries.len(), 1);

        // Total: 1 Cilium + 3 AuthZ + 1 ServiceEntry = 5
        assert_eq!(output.total_count(), 5);
    }

    #[test]
    fn cilium_fqdn_field_serializes_correctly() {
        let rule = CiliumEgressRule {
            to_endpoints: vec![],
            to_entities: vec![],
            to_fqdns: vec![FqdnSelector {
                match_name: Some("api.example.com".to_string()),
                match_pattern: None,
            }],
            to_cidr: vec!["10.0.0.0/8".to_string()],
            to_ports: vec![],
        };

        let json = serde_json::to_string(&rule).expect("rule should serialize");

        assert!(json.contains("\"toFQDNs\""));
        assert!(json.contains("\"toCIDR\""));
    }

    #[test]
    fn wildcard_inbound_generates_policy() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let api_spec = make_service_spec(vec![], vec!["*"]);
        graph.put_service(ns, "api", &api_spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", ns);

        assert!(!output.authorization_policies.is_empty());
        assert!(output.authorization_policies[0].spec.rules[0].from[0]
            .source
            .principals
            .iter()
            .any(|p| p.contains("gateway")));
    }

    #[test]
    fn cilium_hbone_ingress_and_egress_for_mesh_service() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let api_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service(ns, "api", &api_spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");

        // Check api (has inbound callers, no outbound)
        let api_cnp = &compiler.compile("api", ns).cilium_policies[0];
        assert_eq!(
            api_cnp.spec.ingress.len(),
            1,
            "api should have HBONE ingress"
        );
        let ingress = &api_cnp.spec.ingress[0];
        assert!(ingress.from_entities.contains(&"cluster".to_string()));
        assert!(ingress.to_ports[0].ports[0].port == mesh::HBONE_PORT.to_string());
        assert!(
            !api_cnp
                .spec
                .egress
                .iter()
                .any(|e| e.to_ports.iter().any(|pr| pr
                    .ports
                    .iter()
                    .any(|p| p.port == mesh::HBONE_PORT.to_string()))),
            "api should not have HBONE egress (no outbound deps)"
        );

        // Check gateway (has outbound deps, no inbound callers)
        let gw_cnp = &compiler.compile("gateway", ns).cilium_policies[0];
        assert!(gw_cnp.spec.ingress.is_empty(), "gateway has no callers");
        let hbone_egress = gw_cnp.spec.egress.iter().find(|e| {
            e.to_ports.iter().any(|pr| {
                pr.ports
                    .iter()
                    .any(|p| p.port == mesh::HBONE_PORT.to_string())
            })
        });
        assert!(
            hbone_egress.is_some(),
            "gateway should have HBONE egress for local deps"
        );
    }

    #[test]
    fn cilium_hbone_with_fqdn_egress() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let labels = BTreeMap::from([("lattice.dev/name".to_string(), "api".to_string())]);
        let mut spec = make_mesh_member_spec(
            labels,
            vec![("http", 8080, lattice_common::crd::PeerAuth::Strict)],
            vec!["gateway"],
            vec![],
        );
        spec.egress = vec![EgressRule {
            target: EgressTarget::Fqdn("api.stripe.com".to_string()),
            ports: vec![443],
        }];
        graph.put_mesh_member(ns, "api", &spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", ns);

        let cnp = &output.cilium_policies[0];

        assert_eq!(cnp.spec.ingress.len(), 1);
        assert!(cnp.spec.ingress[0]
            .from_entities
            .contains(&"cluster".to_string()));

        let hbone_port = mesh::HBONE_PORT.to_string();
        assert!(
            cnp.spec.egress.iter().any(|e| e
                .to_ports
                .iter()
                .any(|pr| pr.ports.iter().any(|p| p.port == hbone_port))),
            "should have HBONE egress for FQDN egress deps"
        );

        assert!(
            cnp.spec.egress.iter().any(|e| !e.to_fqdns.is_empty()),
            "should have FQDN egress for stripe"
        );
    }

    // =========================================================================
    // Permissive / Webhook policy generation
    // =========================================================================

    fn make_mesh_member_spec(
        labels: std::collections::BTreeMap<String, String>,
        ports: Vec<(&str, u16, lattice_common::crd::PeerAuth)>,
        callers: Vec<&str>,
        deps: Vec<&str>,
    ) -> lattice_common::crd::LatticeMeshMemberSpec {
        use lattice_common::crd::{CallerRef, MeshMemberPort, MeshMemberTarget, ServiceRef};

        lattice_common::crd::LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(labels),
            ports: ports
                .into_iter()
                .map(|(name, port, peer_auth)| MeshMemberPort {
                    port,
                    service_port: None,
                    name: name.to_string(),
                    peer_auth,
                })
                .collect(),
            allowed_callers: callers
                .into_iter()
                .map(|c| CallerRef {
                    name: c.to_string(),
                    namespace: None,
                })
                .collect(),
            dependencies: deps.into_iter().map(ServiceRef::local).collect(),
            egress: vec![],
            allow_peer_traffic: false,
            ingress: None,
            service_account: None,
            depends_all: false,
        }
    }

    #[test]
    fn permissive_port_generates_peer_auth_and_authz() {
        use lattice_common::crd::PeerAuth;

        let graph = ServiceGraph::new();
        let ns = "webhook-ns";

        let labels = BTreeMap::from([("app".to_string(), "webhook".to_string())]);
        let spec = make_mesh_member_spec(
            labels,
            vec![
                ("https", 8443, PeerAuth::Strict),
                ("webhook", 9443, PeerAuth::Permissive),
            ],
            vec!["api"],
            vec![],
        );
        graph.put_mesh_member(ns, "webhook-handler", &spec);

        let api_spec = make_service_spec(vec!["webhook-handler"], vec![]);
        graph.put_service(ns, "api", &api_spec);

        let compiler = PolicyCompiler::new(&graph, "test-cluster");
        let output = compiler.compile("webhook-handler", ns);

        // Should have PeerAuthentication with permissive override on port 9443
        assert_eq!(output.peer_authentications.len(), 1);
        let pa = &output.peer_authentications[0];
        assert!(pa
            .spec
            .port_level_mtls
            .as_ref()
            .unwrap()
            .contains_key("9443"));
        assert_eq!(
            pa.spec.port_level_mtls.as_ref().unwrap()["9443"].mode,
            "PERMISSIVE"
        );
        assert!(!pa
            .spec
            .port_level_mtls
            .as_ref()
            .unwrap()
            .contains_key("8443"));

        // Should have an AuthorizationPolicy allowing plaintext on port 9443
        let plaintext_authz = output
            .authorization_policies
            .iter()
            .find(|ap| ap.metadata.name.starts_with("allow-plaintext-"))
            .expect("should have plaintext allow policy");
        let ports = &plaintext_authz.spec.rules[0].to[0].operation.ports;
        assert_eq!(ports, &["9443"]);
        assert!(
            plaintext_authz.spec.rules[0].from.is_empty(),
            "permissive should allow any caller"
        );
    }

    #[test]
    fn webhook_port_generates_peer_auth_and_authz() {
        use lattice_common::crd::PeerAuth;

        let graph = ServiceGraph::new();
        let ns = "webhook-ns";

        let labels = BTreeMap::from([("app".to_string(), "admission".to_string())]);
        let spec = make_mesh_member_spec(
            labels,
            vec![("webhook", 9443, PeerAuth::Webhook)],
            vec![],
            vec![],
        );
        graph.put_mesh_member(ns, "admission-webhook", &spec);

        let compiler = PolicyCompiler::new(&graph, "test-cluster");
        let output = compiler.compile("admission-webhook", ns);

        // PeerAuthentication: port 9443 is PERMISSIVE (both Webhook and Permissive need this)
        assert_eq!(output.peer_authentications.len(), 1);
        assert!(output.peer_authentications[0]
            .spec
            .port_level_mtls
            .as_ref()
            .unwrap()
            .contains_key("9443"));

        // AuthorizationPolicy: empty from (Istio can't distinguish plaintext source)
        let plaintext_authz = output
            .authorization_policies
            .iter()
            .find(|ap| ap.metadata.name.starts_with("allow-plaintext-"))
            .expect("should have plaintext allow policy");
        assert!(plaintext_authz.spec.rules[0].from.is_empty());
    }

    #[test]
    fn webhook_port_cilium_restricts_to_kube_apiserver() {
        use lattice_common::crd::PeerAuth;

        let graph = ServiceGraph::new();
        let ns = "webhook-ns";

        let labels = BTreeMap::from([("app".to_string(), "admission".to_string())]);
        let spec = make_mesh_member_spec(
            labels,
            vec![("webhook", 9443, PeerAuth::Webhook)],
            vec![],
            vec![],
        );
        graph.put_mesh_member(ns, "admission-webhook", &spec);

        let compiler = PolicyCompiler::new(&graph, "test-cluster");
        let output = compiler.compile("admission-webhook", ns);

        let cnp = &output.cilium_policies[0];

        // Should have HBONE ingress (ztunnel intercepts kube-apiserver webhook calls in ambient)
        let hbone_rule = cnp
            .spec
            .ingress
            .iter()
            .find(|r| {
                r.to_ports
                    .iter()
                    .any(|tp| tp.ports.iter().any(|p| p.port == "15008"))
            })
            .expect("webhook-only service should have HBONE ingress for ztunnel delivery");
        assert!(hbone_rule.from_entities.contains(&"cluster".to_string()));

        // Should have an ingress rule with fromEntities on port 9443
        // Needs remote-node, kube-apiserver, and host for cross-node DNAT delivery
        let webhook_rule = cnp
            .spec
            .ingress
            .iter()
            .find(|r| r.from_entities.contains(&"remote-node".to_string()))
            .expect("should have remote-node ingress rule for webhook");
        assert!(webhook_rule
            .from_entities
            .contains(&"kube-apiserver".to_string()));
        assert!(webhook_rule.from_entities.contains(&"host".to_string()));
        assert!(webhook_rule.to_ports[0]
            .ports
            .iter()
            .any(|p| p.port == "9443"));
    }

    #[test]
    fn permissive_port_cilium_allows_any_source() {
        use lattice_common::crd::PeerAuth;

        let graph = ServiceGraph::new();
        let ns = "webhook-ns";

        let labels = BTreeMap::from([("app".to_string(), "svc".to_string())]);
        let spec = make_mesh_member_spec(
            labels,
            vec![("metrics", 9090, PeerAuth::Permissive)],
            vec![],
            vec![],
        );
        graph.put_mesh_member(ns, "metrics-svc", &spec);

        let compiler = PolicyCompiler::new(&graph, "test-cluster");
        let output = compiler.compile("metrics-svc", ns);

        let cnp = &output.cilium_policies[0];

        // Should have an ingress rule with empty endpoint selector (any source), NOT fromEntities
        let broad_rule = cnp
            .spec
            .ingress
            .iter()
            .find(|r| {
                r.from_entities.is_empty()
                    && !r.from_endpoints.is_empty()
                    && r.to_ports
                        .iter()
                        .any(|pr| pr.ports.iter().any(|p| p.port == "9090"))
            })
            .expect("should have broad ingress rule for permissive port");
        assert!(broad_rule.from_endpoints[0].match_labels.is_empty());
    }

    #[test]
    fn mixed_permissive_and_webhook_ports() {
        use lattice_common::crd::PeerAuth;

        let graph = ServiceGraph::new();
        let ns = "mixed-ns";

        let labels = BTreeMap::from([("app".to_string(), "mixed".to_string())]);
        let spec = make_mesh_member_spec(
            labels,
            vec![
                ("http", 8080, PeerAuth::Strict),
                ("metrics", 9090, PeerAuth::Permissive),
                ("webhook", 9443, PeerAuth::Webhook),
            ],
            vec![],
            vec![],
        );
        graph.put_mesh_member(ns, "mixed-svc", &spec);

        let compiler = PolicyCompiler::new(&graph, "test-cluster");
        let output = compiler.compile("mixed-svc", ns);

        // PeerAuthentication should have PERMISSIVE on both 9090 and 9443
        let pa = &output.peer_authentications[0];
        assert!(pa
            .spec
            .port_level_mtls
            .as_ref()
            .unwrap()
            .contains_key("9090"));
        assert!(pa
            .spec
            .port_level_mtls
            .as_ref()
            .unwrap()
            .contains_key("9443"));
        assert!(!pa
            .spec
            .port_level_mtls
            .as_ref()
            .unwrap()
            .contains_key("8080"));

        // Cilium: separate ingress rules for permissive (any) and webhook (kube-apiserver)
        let cnp = &output.cilium_policies[0];
        let has_broad = cnp.spec.ingress.iter().any(|r| {
            r.from_entities.is_empty()
                && r.to_ports
                    .iter()
                    .any(|pr| pr.ports.iter().any(|p| p.port == "9090"))
        });
        let has_webhook = cnp.spec.ingress.iter().any(|r| {
            r.from_entities.contains(&"kube-apiserver".to_string())
                && r.to_ports
                    .iter()
                    .any(|pr| pr.ports.iter().any(|p| p.port == "9443"))
        });
        assert!(has_broad, "should have broad ingress for permissive port");
        assert!(
            has_webhook,
            "should have kube-apiserver ingress for webhook port"
        );
    }

    #[test]
    fn strict_only_ports_generate_no_permissive_policies() {
        let graph = ServiceGraph::new();
        let ns = "strict-ns";

        let spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service(ns, "api", &spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "test-cluster");
        let output = compiler.compile("api", ns);

        assert!(
            output.peer_authentications.is_empty(),
            "strict-only should have no PeerAuthentication"
        );
        assert!(
            !output
                .authorization_policies
                .iter()
                .any(|ap| ap.metadata.name.starts_with("allow-plaintext-")),
            "strict-only should have no plaintext allow policy"
        );
    }

    // =========================================================================
    // Inline FQDN egress policy generation
    // =========================================================================

    #[test]
    fn fqdn_egress_generates_service_entry_and_authz() {
        use lattice_common::crd::{EgressRule, EgressTarget, MeshMemberPort, MeshMemberTarget};

        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        // Put a mesh member with an FQDN egress rule
        let spec = lattice_common::crd::LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                "app".to_string(),
                "api".to_string(),
            )])),
            ports: vec![MeshMemberPort {
                port: 8080,
                service_port: None,
                name: "http".to_string(),
                peer_auth: lattice_common::crd::PeerAuth::Strict,
            }],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![EgressRule {
                target: EgressTarget::Fqdn("api.stripe.com".to_string()),
                ports: vec![443],
            }],
            allow_peer_traffic: false,
            ingress: None,
            service_account: None,
            depends_all: false,
        };
        graph.put_mesh_member(ns, "api", &spec);

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", ns);

        // Should have a ServiceEntry for api.stripe.com
        assert_eq!(output.service_entries.len(), 1);
        let entry = &output.service_entries[0];
        assert!(entry.spec.hosts.contains(&"api.stripe.com".to_string()));
        assert_eq!(entry.spec.location, "MESH_EXTERNAL");
        assert_eq!(entry.spec.resolution, "DNS");
        assert_eq!(entry.spec.ports[0].number, 443);
        assert_eq!(entry.spec.ports[0].protocol, "HTTPS");

        // Should have an AuthorizationPolicy targeting the ServiceEntry
        let fqdn_authz = output
            .authorization_policies
            .iter()
            .find(|ap| ap.metadata.name.starts_with("allow-fqdn-"))
            .expect("should have FQDN egress access policy");
        assert_eq!(
            fqdn_authz.spec.target_refs[0].kind, "ServiceEntry",
            "should target ServiceEntry"
        );
        assert!(fqdn_authz.spec.rules[0].from[0]
            .source
            .principals
            .iter()
            .any(|p| p.contains("api")));

        // Should also have ztunnel waypoint allow policy (has external deps)
        let waypoint_policy = output
            .authorization_policies
            .iter()
            .find(|ap| ap.metadata.name.starts_with("allow-wp-to-"));
        assert!(
            waypoint_policy.is_some(),
            "should have waypoint allow policy for FQDN egress"
        );
    }

    #[test]
    fn fqdn_egress_without_ports_generates_no_to_block() {
        use lattice_common::crd::{EgressRule, EgressTarget, MeshMemberPort, MeshMemberTarget};

        let graph = ServiceGraph::new();
        let ns = "test-ns";

        let spec = lattice_common::crd::LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                "app".to_string(),
                "svc".to_string(),
            )])),
            ports: vec![MeshMemberPort {
                port: 8080,
                service_port: None,
                name: "http".to_string(),
                peer_auth: lattice_common::crd::PeerAuth::Strict,
            }],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![EgressRule {
                target: EgressTarget::Fqdn("example.com".to_string()),
                ports: vec![],
            }],
            allow_peer_traffic: false,
            ingress: None,
            service_account: None,
            depends_all: false,
        };
        graph.put_mesh_member(ns, "svc", &spec);

        let compiler = PolicyCompiler::new(&graph, "test-cluster");
        let output = compiler.compile("svc", ns);

        let fqdn_authz = output
            .authorization_policies
            .iter()
            .find(|ap| ap.metadata.name.starts_with("allow-fqdn-"))
            .expect("should have FQDN egress access policy");
        assert!(
            fqdn_authz.spec.rules[0].to.is_empty(),
            "no ports means no 'to' block"
        );
    }

    #[test]
    fn fqdn_egress_cilium_gets_fqdn_rule() {
        use lattice_common::crd::{EgressRule, EgressTarget, MeshMemberPort, MeshMemberTarget};

        let graph = ServiceGraph::new();
        let ns = "test-ns";

        let spec = lattice_common::crd::LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                "app".to_string(),
                "svc".to_string(),
            )])),
            ports: vec![MeshMemberPort {
                port: 8080,
                service_port: None,
                name: "http".to_string(),
                peer_auth: lattice_common::crd::PeerAuth::Strict,
            }],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![EgressRule {
                target: EgressTarget::Fqdn("external.example.com".to_string()),
                ports: vec![443],
            }],
            allow_peer_traffic: false,
            ingress: None,
            service_account: None,
            depends_all: false,
        };
        graph.put_mesh_member(ns, "svc", &spec);

        let compiler = PolicyCompiler::new(&graph, "test-cluster");
        let output = compiler.compile("svc", ns);

        // Cilium policy should have FQDN egress rule
        let cnp = &output.cilium_policies[0];
        assert!(
            cnp.spec.egress.iter().any(|e| e
                .to_fqdns
                .iter()
                .any(|f| f.match_name == Some("external.example.com".to_string()))),
            "should have Cilium FQDN egress for external.example.com"
        );
    }
}
