//! Network policy types and compilation for Lattice services
//!
//! This module provides policy compilation logic implementing a defense-in-depth model:
//!
//! - **L7 (Istio AuthorizationPolicy)**: mTLS identity-based access control using SPIFFE principals
//! - **L4 (CiliumNetworkPolicy)**: eBPF-based network enforcement at the kernel level
//!
//! For policy generation, use [`PolicyCompiler`].
//!
//! # Future: Trait-Based Provider Abstraction
//!
//! Policy compilation is split into provider-specific sub-modules:
//! - [`istio_ambient`]: L7 policies (AuthorizationPolicy, ServiceEntry)
//! - [`cilium`]: L4 policies (CiliumNetworkPolicy)
//!
//! To support alternative mesh/CNI providers:
//! 1. Define `trait L7Provider` with methods matching `istio_ambient.rs` signatures
//! 2. Define `trait L4Provider` with methods matching `cilium.rs` signatures
//! 3. Make `PolicyCompiler` generic: `PolicyCompiler<L4, L7>`
//! 4. The existing sub-modules become the first trait implementations

mod cilium;
mod istio_ambient;

pub use lattice_common::policy::{
    AuthorizationOperation, AuthorizationPolicy, AuthorizationPolicySpec, AuthorizationRule,
    AuthorizationSource, CiliumEgressRule, CiliumIngressRule, CiliumNetworkPolicy,
    CiliumNetworkPolicySpec, CiliumPort, CiliumPortRule, DnsMatch, DnsRules, EndpointSelector,
    FqdnSelector, OperationSpec, PolicyMetadata, ServiceEntry, ServiceEntryPort, ServiceEntrySpec,
    SourceSpec, TargetRef, WorkloadSelector,
};

use crate::graph::{ServiceGraph, ServiceType};

// =============================================================================
// Generated Policies Container
// =============================================================================

/// Collection of all policies generated for a service
#[derive(Clone, Debug, Default)]
pub struct GeneratedPolicies {
    /// Istio AuthorizationPolicies
    pub authorization_policies: Vec<AuthorizationPolicy>,
    /// Cilium Network Policies
    pub cilium_policies: Vec<CiliumNetworkPolicy>,
    /// Istio ServiceEntries
    pub service_entries: Vec<ServiceEntry>,
}

impl GeneratedPolicies {
    /// Create empty policy collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any policies were generated
    pub fn is_empty(&self) -> bool {
        self.authorization_policies.is_empty()
            && self.cilium_policies.is_empty()
            && self.service_entries.is_empty()
    }

    /// Total count of all generated policies
    pub fn total_count(&self) -> usize {
        self.authorization_policies.len() + self.cilium_policies.len() + self.service_entries.len()
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

    /// Compile policies for a service
    ///
    /// Returns empty policies if service is not in graph or has no active edges.
    pub fn compile(&self, name: &str, namespace: &str) -> GeneratedPolicies {
        let Some(service_node) = self.graph.get_service(namespace, name) else {
            return GeneratedPolicies::new();
        };

        // Skip Unknown services
        if service_node.type_ == ServiceType::Unknown {
            return GeneratedPolicies::new();
        }

        let mut output = GeneratedPolicies::new();

        // Get active edges
        let inbound_edges = self.graph.get_active_inbound_edges(namespace, name);
        let outbound_edges = self.graph.get_active_outbound_edges(namespace, name);

        // Generate L7 AuthorizationPolicy for inbound traffic
        if !inbound_edges.is_empty() {
            if let Some(auth_policy) =
                self.compile_authorization_policy(&service_node, namespace, &inbound_edges)
            {
                output.authorization_policies.push(auth_policy);
            }

            // Generate waypoint allow policy
            if let Some(waypoint_policy) = self.compile_waypoint_policy(&service_node, namespace) {
                output.authorization_policies.push(waypoint_policy);
            }
        }

        // Generate CiliumNetworkPolicy
        output.cilium_policies.push(self.compile_cilium_policy(
            &service_node,
            namespace,
            &inbound_edges,
            &outbound_edges,
        ));

        // Generate ServiceEntries and AuthorizationPolicies for external dependencies
        // NOTE: We only generate ALLOW policies, not DENY policies for external services.
        // Istio evaluates DENY before ALLOW, so a DENY would block all traffic before
        // the ALLOW could permit authorized callers. The mesh-default-deny handles
        // unauthorized access (callers without an ALLOW policy are denied by default).
        for edge in &outbound_edges {
            if let Some(callee) = self
                .graph
                .get_service(&edge.callee_namespace, &edge.callee_name)
            {
                if callee.type_ == ServiceType::External {
                    if let Some(entry) = self.compile_service_entry(&callee, &edge.callee_namespace)
                    {
                        output.service_entries.push(entry);
                    }
                    // Generate ALLOW policy for THIS service to access the external
                    output
                        .authorization_policies
                        .push(self.compile_external_access_policy(
                            &service_node.name,
                            &callee,
                            namespace,
                        ));
                }
            }
        }

        output
    }

    /// Check if a string is an IP address (IPv4 or IPv6)
    pub(crate) fn is_ip_address(host: &str) -> bool {
        use std::net::IpAddr;
        host.parse::<IpAddr>().is_ok()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        ContainerSpec, DependencyDirection, DeploySpec, LatticeExternalServiceSpec, PortSpec,
        ReplicaSpec, Resolution, ResourceSpec, ResourceType, ServicePortsSpec,
    };
    use crate::graph::ServiceGraph;
    use lattice_common::mesh;
    use std::collections::BTreeMap;

    fn make_external_spec(allowed: Vec<&str>) -> LatticeExternalServiceSpec {
        LatticeExternalServiceSpec {
            endpoints: BTreeMap::from([(
                "api".to_string(),
                "https://api.stripe.com:443".to_string(),
            )]),
            allowed_requesters: allowed.into_iter().map(String::from).collect(),
            resolution: Resolution::Dns,
            description: None,
        }
    }

    fn make_service_spec(deps: Vec<&str>, callers: Vec<&str>) -> crate::crd::LatticeServiceSpec {
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
                    inbound: None,
                    outbound: None,
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
                    inbound: None,
                    outbound: None,
                },
            );
        }

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
                security: None,
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

        crate::crd::LatticeServiceSpec {
            containers,
            resources,
            service: Some(ServicePortsSpec { ports }),
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
            ingress: None,
            sidecars: BTreeMap::new(),
            sysctls: BTreeMap::new(),
            host_network: None,
            share_process_namespace: None,
            backup: None,
        }
    }

    #[test]
    fn story_bilateral_agreement_generates_policy() {
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
        assert_eq!(auth.metadata.name, "allow-to-api");
        assert!(auth.spec.rules[0].from[0]
            .source
            .principals
            .iter()
            .any(|p| p.contains("gateway")));
    }

    #[test]
    fn story_no_policy_without_bilateral_agreement() {
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
    fn story_no_policies_when_not_in_graph() {
        let graph = ServiceGraph::new();
        let compiler = PolicyCompiler::new(&graph, "test-cluster");
        let output = compiler.compile("nonexistent", "default");
        assert!(output.is_empty());
    }

    #[test]
    fn story_spiffe_uses_trust_domain() {
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
    fn story_cilium_policy_always_generated() {
        let graph = ServiceGraph::new();
        let ns = "default";

        let spec = make_service_spec(vec![], vec![]);
        graph.put_service(ns, "my-app", &spec);

        let compiler = PolicyCompiler::new(&graph, "test-cluster");
        let output = compiler.compile("my-app", ns);

        assert_eq!(output.cilium_policies.len(), 1);
        let cnp = &output.cilium_policies[0];
        assert_eq!(cnp.metadata.name, "policy-my-app");

        assert!(cnp.spec.egress.iter().any(|e| e
            .to_ports
            .iter()
            .any(|pr| pr.ports.iter().any(|p| p.port == "53"))));

        assert!(cnp
            .spec
            .ingress
            .iter()
            .any(|i| i.from_endpoints.iter().any(|ep| ep
                .match_labels
                .get(mesh::CILIUM_WAYPOINT_FOR_LABEL)
                .map(|v| v == mesh::WAYPOINT_FOR_SERVICE)
                .unwrap_or(false))));

        assert!(cnp
            .spec
            .ingress
            .iter()
            .any(|i| i.to_ports.iter().any(|pr| pr
                .ports
                .iter()
                .any(|p| p.port == mesh::HBONE_PORT.to_string()))));
    }

    #[test]
    fn story_external_service_generates_service_entry() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let api_spec = make_service_spec(vec!["stripe-api"], vec![]);
        graph.put_service(ns, "api", &api_spec);

        graph.put_external_service(ns, "stripe-api", &make_external_spec(vec!["api"]));

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", "prod-ns");

        assert_eq!(output.service_entries.len(), 1);
        let entry = &output.service_entries[0];
        assert_eq!(entry.metadata.name, "stripe-api");
        assert!(entry.spec.hosts.contains(&"api.stripe.com".to_string()));
        assert_eq!(entry.spec.location, "MESH_EXTERNAL");
    }

    #[test]
    fn story_total_count() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        // api: allows inbound from gateway, calls external stripe
        let api_spec = make_service_spec(vec!["stripe"], vec!["gateway"]);
        graph.put_service(ns, "api", &api_spec);

        // gateway: calls api (bilateral agreement with api's inbound)
        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        // stripe: external service that allows api to call it
        graph.put_external_service(ns, "stripe", &make_external_spec(vec!["api"]));

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", "prod-ns");

        // Verify specific policies are generated:
        // 1. CiliumNetworkPolicy for api
        assert_eq!(output.cilium_policies.len(), 1);
        assert_eq!(output.cilium_policies[0].metadata.name, "policy-api");

        // 2. AuthorizationPolicies:
        //    - allow-to-api: allows callers with bilateral agreement to reach api
        //    - allow-waypoint-to-api: allows waypoint proxy to reach api for L7 policy
        //    - allow-api-to-stripe: allows api to call stripe external service
        assert_eq!(output.authorization_policies.len(), 3);
        let authz_names: Vec<_> = output
            .authorization_policies
            .iter()
            .map(|p| p.metadata.name.as_str())
            .collect();
        assert!(authz_names.contains(&"allow-to-api"));
        assert!(authz_names.contains(&"allow-waypoint-to-api"));
        assert!(authz_names.contains(&"allow-api-to-stripe"));

        // 3. ServiceEntry for stripe external service
        assert_eq!(output.service_entries.len(), 1);
        assert_eq!(output.service_entries[0].metadata.name, "stripe");

        // Total: 1 Cilium + 3 AuthZ + 1 ServiceEntry = 5
        assert_eq!(output.total_count(), 5);
    }

    #[test]
    fn story_cilium_fqdn_field_serializes_correctly() {
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
    fn story_is_ip_address_detection() {
        assert!(PolicyCompiler::is_ip_address("1.1.1.1"));
        assert!(PolicyCompiler::is_ip_address("::1"));
        assert!(!PolicyCompiler::is_ip_address("example.com"));
        assert!(!PolicyCompiler::is_ip_address("api.stripe.com"));
    }

    #[test]
    fn story_gateway_allow_policy_generated() {
        let graph = ServiceGraph::new();
        let compiler = PolicyCompiler::new(&graph, "prod-cluster");

        let policy = compiler.compile_gateway_allow_policy("api", "prod-ns", &[8080, 8443]);

        assert_eq!(policy.metadata.name, "allow-gateway-to-api");
        assert_eq!(policy.spec.action, "ALLOW");

        let principals = &policy.spec.rules[0].from[0].source.principals;
        assert!(principals
            .iter()
            .any(|p| p.contains("envoy-gateway-system")));

        let ports = &policy.spec.rules[0].to[0].operation.ports;
        assert!(ports.contains(&"8080".to_string()));
        assert!(ports.contains(&"8443".to_string()));
    }

    #[test]
    fn story_wildcard_inbound_generates_policy() {
        let graph = ServiceGraph::new();
        let ns = "prod-ns";

        let api_spec = make_service_spec(vec![], vec!["*"]);
        graph.put_service(ns, "api", &api_spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", ns);

        assert!(!output.authorization_policies.is_empty());
        let auth = &output.authorization_policies[0];
        assert_eq!(auth.metadata.name, "allow-to-api");
        assert!(auth.spec.rules[0].from[0]
            .source
            .principals
            .iter()
            .any(|p| p.contains("gateway")));
    }

    #[test]
    fn story_ipv6_cidr_uses_128_prefix() {
        use crate::crd::ParsedEndpoint;

        // Create a service node with IPv4 and IPv6 endpoints
        let mut node = crate::graph::ServiceNode::unknown("test-ns", "external-svc");
        node.endpoints.insert(
            "ipv4".to_string(),
            ParsedEndpoint {
                protocol: "tcp".to_string(),
                host: "192.168.1.1".to_string(),
                port: 443,
                url: "tcp://192.168.1.1:443".to_string(),
            },
        );
        node.endpoints.insert(
            "ipv6".to_string(),
            ParsedEndpoint {
                protocol: "tcp".to_string(),
                host: "2001:db8::1".to_string(),
                port: 443,
                url: "tcp://[2001:db8::1]:443".to_string(),
            },
        );

        let (fqdns, cidrs) = PolicyCompiler::categorize_external_endpoints(&node);

        // Should have no FQDNs (only IPs)
        assert!(fqdns.is_empty());

        // Should have both CIDRs with correct prefixes
        assert_eq!(cidrs.len(), 2);
        assert!(cidrs.contains(&"192.168.1.1/32".to_string()));
        assert!(cidrs.contains(&"2001:db8::1/128".to_string()));
    }

    #[test]
    fn story_mixed_endpoints_categorized_correctly() {
        use crate::crd::ParsedEndpoint;

        // Create a service node with mixed FQDN and IP endpoints
        let mut node = crate::graph::ServiceNode::unknown("test-ns", "external-svc");
        node.endpoints.insert(
            "fqdn".to_string(),
            ParsedEndpoint {
                protocol: "https".to_string(),
                host: "api.example.com".to_string(),
                port: 443,
                url: "https://api.example.com".to_string(),
            },
        );
        node.endpoints.insert(
            "ipv4".to_string(),
            ParsedEndpoint {
                protocol: "tcp".to_string(),
                host: "10.0.0.1".to_string(),
                port: 8080,
                url: "tcp://10.0.0.1:8080".to_string(),
            },
        );

        let (fqdns, cidrs) = PolicyCompiler::categorize_external_endpoints(&node);

        assert_eq!(fqdns.len(), 1);
        assert_eq!(fqdns[0].match_name, Some("api.example.com".to_string()));

        assert_eq!(cidrs.len(), 1);
        assert!(cidrs.contains(&"10.0.0.1/32".to_string()));
    }
}
