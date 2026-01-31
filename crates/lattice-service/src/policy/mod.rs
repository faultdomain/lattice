//! Network policy types and compilation for Lattice services
//!
//! This module provides policy compilation logic implementing a defense-in-depth model:
//!
//! - **L7 (Istio AuthorizationPolicy)**: mTLS identity-based access control using SPIFFE principals
//! - **L4 (CiliumNetworkPolicy)**: eBPF-based network enforcement at the kernel level
//!
//! For policy generation, use [`PolicyCompiler`].

pub use lattice_common::policy::{
    AuthorizationOperation, AuthorizationPolicy, AuthorizationPolicySpec, AuthorizationRule,
    AuthorizationSource, CiliumEgressRule, CiliumIngressRule, CiliumNetworkPolicy,
    CiliumNetworkPolicySpec, CiliumPort, CiliumPortRule, EndpointSelector, FqdnSelector,
    OperationSpec, PolicyMetadata, ServiceEntry, ServiceEntryPort, ServiceEntrySpec, SourceSpec,
    TargetRef, WorkloadSelector,
};

use std::collections::BTreeMap;

use crate::graph::{ActiveEdge, ServiceGraph, ServiceNode, ServiceType};
use crate::mesh;

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
                    // Generate default-deny for this ServiceEntry
                    output
                        .authorization_policies
                        .push(Self::compile_external_default_deny(
                            &callee.name,
                            &edge.callee_namespace,
                        ));
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
    fn is_ip_address(host: &str) -> bool {
        use std::net::IpAddr;
        host.parse::<IpAddr>().is_ok()
    }

    /// Generate SPIFFE principal for AuthorizationPolicy
    fn spiffe_principal(&self, namespace: &str, service_name: &str) -> String {
        mesh::trust_domain::principal(&self.cluster_name, namespace, service_name)
    }

    fn waypoint_principal(&self, namespace: &str) -> String {
        mesh::trust_domain::waypoint_principal(&self.cluster_name, namespace)
    }

    fn compile_authorization_policy(
        &self,
        service: &ServiceNode,
        namespace: &str,
        inbound_edges: &[ActiveEdge],
    ) -> Option<AuthorizationPolicy> {
        if inbound_edges.is_empty() {
            return None;
        }

        let principals: Vec<String> = inbound_edges
            .iter()
            .map(|edge| self.spiffe_principal(&edge.caller_namespace, &edge.caller_name))
            .collect();

        let ports: Vec<String> = service.ports.values().map(|p| p.to_string()).collect();

        if ports.is_empty() {
            return None;
        }

        Some(AuthorizationPolicy::new(
            PolicyMetadata::new(format!("allow-to-{}", service.name), namespace),
            AuthorizationPolicySpec {
                target_refs: vec![TargetRef {
                    group: String::new(),
                    kind: "Service".to_string(),
                    name: service.name.clone(),
                }],
                selector: None,
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![AuthorizationSource {
                        source: SourceSpec { principals },
                    }],
                    to: vec![AuthorizationOperation {
                        operation: OperationSpec {
                            ports,
                            hosts: vec![],
                        },
                    }],
                }],
            },
        ))
    }

    fn compile_waypoint_policy(
        &self,
        service: &ServiceNode,
        namespace: &str,
    ) -> Option<AuthorizationPolicy> {
        let ports: Vec<String> = service.ports.values().map(|p| p.to_string()).collect();

        if ports.is_empty() {
            return None;
        }

        let mut match_labels = BTreeMap::new();
        match_labels.insert(lattice_common::LABEL_NAME.to_string(), service.name.clone());

        Some(AuthorizationPolicy::new(
            PolicyMetadata::new(format!("allow-waypoint-to-{}", service.name), namespace),
            AuthorizationPolicySpec {
                target_refs: vec![],
                selector: Some(WorkloadSelector { match_labels }),
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![AuthorizationSource {
                        source: SourceSpec {
                            principals: vec![self.waypoint_principal(namespace)],
                        },
                    }],
                    to: vec![AuthorizationOperation {
                        operation: OperationSpec {
                            ports,
                            hosts: vec![],
                        },
                    }],
                }],
            },
        ))
    }

    fn compile_cilium_policy(
        &self,
        service: &ServiceNode,
        namespace: &str,
        inbound_edges: &[ActiveEdge],
        outbound_edges: &[ActiveEdge],
    ) -> CiliumNetworkPolicy {
        let mut endpoint_labels = BTreeMap::new();
        endpoint_labels.insert(
            lattice_common::CILIUM_LABEL_NAME.to_string(),
            service.name.clone(),
        );

        // Build ingress rules
        let mut ingress_rules = Vec::new();

        // Allow from callers if there are inbound edges
        if !inbound_edges.is_empty() {
            let from_endpoints: Vec<EndpointSelector> = inbound_edges
                .iter()
                .map(|edge| {
                    let mut labels = BTreeMap::new();
                    labels.insert(
                        lattice_common::CILIUM_LABEL_NAMESPACE.to_string(),
                        edge.caller_namespace.clone(),
                    );
                    labels.insert(
                        lattice_common::CILIUM_LABEL_NAME.to_string(),
                        edge.caller_name.clone(),
                    );
                    EndpointSelector {
                        match_labels: labels,
                    }
                })
                .collect();

            let to_ports: Vec<CiliumPortRule> = if service.ports.is_empty() {
                vec![]
            } else {
                vec![CiliumPortRule {
                    ports: service
                        .ports
                        .values()
                        .flat_map(|p| {
                            vec![
                                CiliumPort {
                                    port: p.to_string(),
                                    protocol: "TCP".to_string(),
                                },
                                CiliumPort {
                                    port: p.to_string(),
                                    protocol: "UDP".to_string(),
                                },
                            ]
                        })
                        .collect(),
                }]
            };

            ingress_rules.push(CiliumIngressRule {
                from_endpoints,
                to_ports,
            });
        }

        // Allow traffic from waypoint proxy on HBONE port
        let mut waypoint_ingress_labels = BTreeMap::new();
        waypoint_ingress_labels.insert(
            lattice_common::CILIUM_LABEL_NAMESPACE.to_string(),
            namespace.to_string(),
        );
        waypoint_ingress_labels.insert(
            format!("k8s:{}", mesh::WAYPOINT_FOR_LABEL),
            mesh::WAYPOINT_FOR_SERVICE.to_string(),
        );

        ingress_rules.push(CiliumIngressRule {
            from_endpoints: vec![EndpointSelector {
                match_labels: waypoint_ingress_labels,
            }],
            to_ports: vec![CiliumPortRule {
                ports: vec![CiliumPort {
                    port: mesh::HBONE_PORT.to_string(),
                    protocol: "TCP".to_string(),
                }],
            }],
        });

        // Build egress rules
        let mut egress_rules = Vec::new();

        // Always allow DNS to kube-dns
        let mut kube_dns_labels = BTreeMap::new();
        kube_dns_labels.insert(
            lattice_common::CILIUM_LABEL_NAMESPACE.to_string(),
            "kube-system".to_string(),
        );
        kube_dns_labels.insert("k8s:k8s-app".to_string(), "kube-dns".to_string());
        egress_rules.push(CiliumEgressRule {
            to_endpoints: vec![EndpointSelector {
                match_labels: kube_dns_labels,
            }],
            to_entities: vec![],
            to_fqdns: vec![],
            to_cidr: vec![],
            to_ports: vec![CiliumPortRule {
                ports: vec![
                    CiliumPort {
                        port: "53".to_string(),
                        protocol: "UDP".to_string(),
                    },
                    CiliumPort {
                        port: "53".to_string(),
                        protocol: "TCP".to_string(),
                    },
                ],
            }],
        });

        // Always allow HBONE to waypoint
        let mut waypoint_egress_labels = BTreeMap::new();
        waypoint_egress_labels.insert(
            format!("k8s:{}", mesh::WAYPOINT_FOR_LABEL),
            mesh::WAYPOINT_FOR_SERVICE.to_string(),
        );
        egress_rules.push(CiliumEgressRule {
            to_endpoints: vec![EndpointSelector {
                match_labels: waypoint_egress_labels,
            }],
            to_entities: vec![],
            to_fqdns: vec![],
            to_cidr: vec![],
            to_ports: vec![CiliumPortRule {
                ports: vec![CiliumPort {
                    port: mesh::HBONE_PORT.to_string(),
                    protocol: "TCP".to_string(),
                }],
            }],
        });

        // Add egress rules for dependencies
        for edge in outbound_edges {
            if let Some(callee) = self
                .graph
                .get_service(&edge.callee_namespace, &edge.callee_name)
            {
                match callee.type_ {
                    ServiceType::Local => {
                        let mut dep_labels = BTreeMap::new();
                        dep_labels.insert(
                            lattice_common::CILIUM_LABEL_NAMESPACE.to_string(),
                            edge.callee_namespace.clone(),
                        );
                        dep_labels.insert(
                            lattice_common::CILIUM_LABEL_NAME.to_string(),
                            edge.callee_name.clone(),
                        );

                        let to_ports: Vec<CiliumPortRule> = if callee.ports.is_empty() {
                            vec![]
                        } else {
                            vec![CiliumPortRule {
                                ports: callee
                                    .ports
                                    .values()
                                    .flat_map(|p| {
                                        vec![
                                            CiliumPort {
                                                port: p.to_string(),
                                                protocol: "TCP".to_string(),
                                            },
                                            CiliumPort {
                                                port: p.to_string(),
                                                protocol: "UDP".to_string(),
                                            },
                                        ]
                                    })
                                    .collect(),
                            }]
                        };

                        egress_rules.push(CiliumEgressRule {
                            to_endpoints: vec![EndpointSelector {
                                match_labels: dep_labels,
                            }],
                            to_entities: vec![],
                            to_fqdns: vec![],
                            to_cidr: vec![],
                            to_ports,
                        });
                    }
                    ServiceType::External => {
                        let mut fqdns: Vec<FqdnSelector> = Vec::new();
                        let mut cidrs: Vec<String> = Vec::new();

                        for ep in callee.endpoints.values() {
                            if Self::is_ip_address(&ep.host) {
                                cidrs.push(format!("{}/32", ep.host));
                            } else {
                                fqdns.push(FqdnSelector {
                                    match_name: Some(ep.host.clone()),
                                    match_pattern: None,
                                });
                            }
                        }

                        let ports: Vec<CiliumPort> = callee
                            .endpoints
                            .values()
                            .map(|ep| CiliumPort {
                                port: ep.port.to_string(),
                                protocol: "TCP".to_string(),
                            })
                            .collect();

                        let to_ports = if ports.is_empty() {
                            vec![]
                        } else {
                            vec![CiliumPortRule { ports }]
                        };

                        if !fqdns.is_empty() {
                            egress_rules.push(CiliumEgressRule {
                                to_endpoints: vec![],
                                to_entities: vec![],
                                to_fqdns: fqdns,
                                to_cidr: vec![],
                                to_ports: to_ports.clone(),
                            });
                        }

                        if !cidrs.is_empty() {
                            egress_rules.push(CiliumEgressRule {
                                to_endpoints: vec![],
                                to_entities: vec![],
                                to_fqdns: vec![],
                                to_cidr: cidrs,
                                to_ports,
                            });
                        }
                    }
                    ServiceType::Unknown => {}
                }
            }
        }

        CiliumNetworkPolicy::new(
            PolicyMetadata::new(format!("policy-{}", service.name), namespace),
            CiliumNetworkPolicySpec {
                endpoint_selector: EndpointSelector {
                    match_labels: endpoint_labels,
                },
                ingress: ingress_rules,
                egress: egress_rules,
            },
        )
    }

    /// Compile an AuthorizationPolicy to allow Envoy Gateway to reach a service
    pub fn compile_gateway_allow_policy(
        &self,
        service_name: &str,
        namespace: &str,
        ports: &[u16],
    ) -> AuthorizationPolicy {
        let gateway_principal = mesh::trust_domain::gateway_principal(&self.cluster_name);
        let port_strings: Vec<String> = ports.iter().map(|p| p.to_string()).collect();

        AuthorizationPolicy::new(
            PolicyMetadata::new(format!("allow-gateway-to-{}", service_name), namespace),
            AuthorizationPolicySpec {
                target_refs: vec![TargetRef {
                    group: String::new(),
                    kind: "Service".to_string(),
                    name: service_name.to_string(),
                }],
                selector: None,
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![AuthorizationSource {
                        source: SourceSpec {
                            principals: vec![gateway_principal],
                        },
                    }],
                    to: if port_strings.is_empty() {
                        vec![]
                    } else {
                        vec![AuthorizationOperation {
                            operation: OperationSpec {
                                ports: port_strings,
                                hosts: vec![],
                            },
                        }]
                    },
                }],
            },
        )
    }

    fn compile_service_entry(
        &self,
        service: &ServiceNode,
        namespace: &str,
    ) -> Option<ServiceEntry> {
        if service.endpoints.is_empty() {
            return None;
        }

        let hosts: Vec<String> = service
            .endpoints
            .values()
            .map(|ep| ep.host.clone())
            .collect();

        let ports: Vec<ServiceEntryPort> = service
            .endpoints
            .iter()
            .map(|(name, ep)| ServiceEntryPort {
                number: ep.port,
                name: name.clone(),
                protocol: ep.protocol.to_uppercase(),
            })
            .collect();

        let mut metadata = PolicyMetadata::new(&service.name, namespace);
        metadata.labels.insert(
            mesh::USE_WAYPOINT_LABEL.to_string(),
            format!("{}-waypoint", namespace),
        );

        let resolution = service
            .resolution
            .as_ref()
            .map(|r| r.to_istio_format())
            .unwrap_or("DNS")
            .to_string();

        Some(ServiceEntry::new(
            metadata,
            ServiceEntrySpec {
                hosts,
                ports,
                location: "MESH_EXTERNAL".to_string(),
                resolution,
            },
        ))
    }

    fn compile_external_default_deny(external_name: &str, namespace: &str) -> AuthorizationPolicy {
        AuthorizationPolicy::new(
            PolicyMetadata::new(format!("deny-all-to-{}", external_name), namespace),
            AuthorizationPolicySpec {
                target_refs: vec![TargetRef {
                    group: "networking.istio.io".to_string(),
                    kind: "ServiceEntry".to_string(),
                    name: external_name.to_string(),
                }],
                selector: None,
                action: String::new(),
                rules: vec![],
            },
        )
    }

    fn compile_external_access_policy(
        &self,
        caller: &str,
        external_service: &ServiceNode,
        namespace: &str,
    ) -> AuthorizationPolicy {
        let ports: Vec<String> = external_service
            .endpoints
            .values()
            .map(|ep| ep.port.to_string())
            .collect();

        AuthorizationPolicy::new(
            PolicyMetadata::new(
                format!("allow-{}-to-{}", caller, external_service.name),
                namespace,
            ),
            AuthorizationPolicySpec {
                target_refs: vec![TargetRef {
                    group: "networking.istio.io".to_string(),
                    kind: "ServiceEntry".to_string(),
                    name: external_service.name.clone(),
                }],
                selector: None,
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![AuthorizationSource {
                        source: SourceSpec {
                            principals: vec![self.spiffe_principal(namespace, caller)],
                        },
                    }],
                    to: if ports.is_empty() {
                        vec![]
                    } else {
                        vec![AuthorizationOperation {
                            operation: OperationSpec {
                                ports,
                                hosts: vec![],
                            },
                        }]
                    },
                }],
            },
        )
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
                .get("k8s:istio.io/waypoint-for")
                .map(|v| v == "service")
                .unwrap_or(false))));

        assert!(cnp.spec.ingress.iter().any(|i| i
            .to_ports
            .iter()
            .any(|pr| pr.ports.iter().any(|p| p.port == "15008"))));
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

        let api_spec = make_service_spec(vec!["stripe"], vec!["gateway"]);
        graph.put_service(ns, "api", &api_spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(ns, "gateway", &gateway_spec);

        graph.put_external_service(ns, "stripe", &make_external_spec(vec!["api"]));

        let compiler = PolicyCompiler::new(&graph, "prod-cluster");
        let output = compiler.compile("api", "prod-ns");

        assert_eq!(output.total_count(), 6);
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
}
