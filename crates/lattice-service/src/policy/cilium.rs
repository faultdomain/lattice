//! L4 policy compilation: CiliumNetworkPolicy
//!
//! Generates eBPF-based network enforcement at the kernel level using Cilium.
//!
//! Port handling: Cilium service-based policies (`toServices`) automatically
//! translate K8s Service ports to container targetPorts. For ingress rules,
//! we specify the service port and Cilium handles the mapping internally.

use std::collections::BTreeMap;

use crate::graph::{ActiveEdge, ServiceNode, ServiceType};
use lattice_common::policy::{
    CiliumEgressRule, CiliumIngressRule, CiliumNetworkPolicy, CiliumNetworkPolicySpec, CiliumPort,
    CiliumPortRule, DnsMatch, DnsRules, EndpointSelector, FqdnSelector, K8sServiceRef,
    K8sServiceSelector, PolicyMetadata,
};
use lattice_common::{mesh, CILIUM_LABEL_NAME, CILIUM_LABEL_NAMESPACE};

use super::PolicyCompiler;

impl<'a> PolicyCompiler<'a> {
    pub(super) fn compile_cilium_policy(
        &self,
        service: &ServiceNode,
        namespace: &str,
        inbound_edges: &[ActiveEdge],
        outbound_edges: &[ActiveEdge],
    ) -> CiliumNetworkPolicy {
        let mut endpoint_labels = BTreeMap::new();
        endpoint_labels.insert(CILIUM_LABEL_NAME.to_string(), service.name.clone());

        // Build ingress rules
        let mut ingress_rules = Vec::new();

        // Allow from callers if there are inbound edges
        if !inbound_edges.is_empty() {
            let from_endpoints: Vec<EndpointSelector> = inbound_edges
                .iter()
                .map(|edge| {
                    let mut labels = BTreeMap::new();
                    labels.insert(
                        CILIUM_LABEL_NAMESPACE.to_string(),
                        edge.caller_namespace.clone(),
                    );
                    labels.insert(CILIUM_LABEL_NAME.to_string(), edge.caller_name.clone());
                    EndpointSelector::from_labels(labels)
                })
                .collect();

            let to_ports = Self::build_service_port_rules(service);

            ingress_rules.push(CiliumIngressRule {
                from_endpoints,
                to_ports,
            });
        }

        // Allow traffic from waypoint proxy on HBONE port
        let mut waypoint_ingress_labels = BTreeMap::new();
        waypoint_ingress_labels.insert(CILIUM_LABEL_NAMESPACE.to_string(), namespace.to_string());
        waypoint_ingress_labels.insert(
            mesh::CILIUM_WAYPOINT_FOR_LABEL.to_string(),
            mesh::WAYPOINT_FOR_SERVICE.to_string(),
        );

        ingress_rules.push(CiliumIngressRule {
            from_endpoints: vec![EndpointSelector::from_labels(waypoint_ingress_labels)],
            to_ports: vec![CiliumPortRule {
                ports: vec![CiliumPort {
                    port: mesh::HBONE_PORT.to_string(),
                    protocol: "TCP".to_string(),
                }],
                rules: None,
            }],
        });

        // Build egress rules
        let mut egress_rules = Vec::new();

        // Check if service has external FQDN dependencies (need DNS interception for toFQDNs)
        let has_external_fqdns = outbound_edges.iter().any(|edge| {
            self.graph
                .get_service(&edge.callee_namespace, &edge.callee_name)
                .map(|callee| {
                    callee.type_ == ServiceType::External
                        && callee
                            .endpoints
                            .values()
                            .any(|ep| !Self::is_ip_address(&ep.host))
                })
                .unwrap_or(false)
        });

        // Always allow DNS to kube-dns (with DNS interception if we have external FQDNs)
        let mut kube_dns_labels = BTreeMap::new();
        kube_dns_labels.insert(
            CILIUM_LABEL_NAMESPACE.to_string(),
            "kube-system".to_string(),
        );
        kube_dns_labels.insert("k8s:k8s-app".to_string(), "kube-dns".to_string());
        egress_rules.push(CiliumEgressRule {
            to_endpoints: vec![EndpointSelector::from_labels(kube_dns_labels)],
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
                // DNS interception rules required for toFQDNs to work
                rules: if has_external_fqdns {
                    Some(DnsRules {
                        dns: vec![DnsMatch {
                            match_pattern: Some("*".to_string()),
                        }],
                    })
                } else {
                    None
                },
            }],
            ..Default::default()
        });

        // Always allow HBONE to waypoint
        let mut waypoint_egress_labels = BTreeMap::new();
        waypoint_egress_labels.insert(
            mesh::CILIUM_WAYPOINT_FOR_LABEL.to_string(),
            mesh::WAYPOINT_FOR_SERVICE.to_string(),
        );
        egress_rules.push(CiliumEgressRule {
            to_endpoints: vec![EndpointSelector::from_labels(waypoint_egress_labels)],
            to_ports: vec![CiliumPortRule {
                ports: vec![CiliumPort {
                    port: mesh::HBONE_PORT.to_string(),
                    protocol: "TCP".to_string(),
                }],
                rules: None,
            }],
            ..Default::default()
        });

        // Add egress rules for dependencies
        self.build_egress_rules_for_dependencies(outbound_edges, &mut egress_rules);

        CiliumNetworkPolicy::new(
            PolicyMetadata::new(format!("policy-{}", service.name), namespace),
            CiliumNetworkPolicySpec {
                endpoint_selector: EndpointSelector::from_labels(endpoint_labels),
                ingress: ingress_rules,
                egress: egress_rules,
            },
        )
    }

    /// Build egress rules for all outbound dependencies
    ///
    /// This handles both local (in-cluster) and external service dependencies,
    /// generating appropriate Cilium egress rules for each.
    fn build_egress_rules_for_dependencies(
        &self,
        outbound_edges: &[ActiveEdge],
        egress_rules: &mut Vec<CiliumEgressRule>,
    ) {
        for edge in outbound_edges {
            if let Some(callee) = self
                .graph
                .get_service(&edge.callee_namespace, &edge.callee_name)
            {
                match callee.type_ {
                    ServiceType::Local => {
                        Self::build_local_dependency_rule(edge, egress_rules);
                    }
                    ServiceType::External => {
                        self.build_external_dependency_rules(&callee, egress_rules);
                    }
                    ServiceType::Unknown => {}
                }
            }
        }
    }

    /// Build egress rule for a local (in-cluster) service dependency.
    ///
    /// Uses `toServices` with `k8sService` so Cilium resolves the service's
    /// endpoints and translates service ports to targetPorts automatically.
    fn build_local_dependency_rule(edge: &ActiveEdge, egress_rules: &mut Vec<CiliumEgressRule>) {
        egress_rules.push(CiliumEgressRule {
            to_services: vec![K8sServiceSelector {
                k8s_service: K8sServiceRef {
                    service_name: edge.callee_name.clone(),
                    namespace: edge.callee_namespace.clone(),
                },
            }],
            ..Default::default()
        });
    }

    /// Build egress rules for an external service dependency
    ///
    /// Generates separate rules for FQDN-based and CIDR-based endpoints.
    fn build_external_dependency_rules(
        &self,
        callee: &ServiceNode,
        egress_rules: &mut Vec<CiliumEgressRule>,
    ) {
        let (fqdns, cidrs) = Self::categorize_external_endpoints(callee);
        let to_ports = Self::build_external_port_rules(callee);

        // Add FQDN-based egress rule if there are FQDN endpoints
        if !fqdns.is_empty() {
            egress_rules.push(CiliumEgressRule {
                to_fqdns: fqdns,
                to_ports: to_ports.clone(),
                ..Default::default()
            });
        }

        // Add CIDR-based egress rule if there are IP endpoints
        if !cidrs.is_empty() {
            egress_rules.push(CiliumEgressRule {
                to_cidr: cidrs,
                to_ports,
                ..Default::default()
            });
        }
    }

    /// Categorize external endpoints into FQDNs and CIDRs
    pub(crate) fn categorize_external_endpoints(
        callee: &ServiceNode,
    ) -> (Vec<FqdnSelector>, Vec<String>) {
        let mut fqdns: Vec<FqdnSelector> = Vec::new();
        let mut cidrs: Vec<String> = Vec::new();

        for ep in callee.endpoints.values() {
            if Self::is_ip_address(&ep.host) {
                // IPv6 addresses use /128 prefix, IPv4 addresses use /32
                let prefix = if ep.host.contains(':') { 128 } else { 32 };
                cidrs.push(format!("{}/{}", ep.host, prefix));
            } else {
                fqdns.push(FqdnSelector {
                    match_name: Some(ep.host.clone()),
                    match_pattern: None,
                });
            }
        }

        (fqdns, cidrs)
    }

    /// Build port rules for ingress using the K8s Service port.
    ///
    /// Cilium translates service ports to container targetPorts internally,
    /// so we always specify the service-facing port in policy rules.
    fn build_service_port_rules(service: &ServiceNode) -> Vec<CiliumPortRule> {
        if service.ports.is_empty() {
            vec![]
        } else {
            vec![CiliumPortRule {
                ports: service
                    .ports
                    .values()
                    .flat_map(|pm| {
                        vec![
                            CiliumPort {
                                port: pm.service_port.to_string(),
                                protocol: "TCP".to_string(),
                            },
                            CiliumPort {
                                port: pm.service_port.to_string(),
                                protocol: "UDP".to_string(),
                            },
                        ]
                    })
                    .collect(),
                rules: None,
            }]
        }
    }

    /// Generate a CiliumIngressRule allowing the Istio gateway proxy to reach
    /// a service. The gateway runs in the same namespace, selected by its
    /// `istio.io/gateway-name` label.
    pub(crate) fn compile_gateway_ingress_rule(
        gateway_name: &str,
        ports: &[u16],
    ) -> CiliumIngressRule {
        let mut labels = BTreeMap::new();
        labels.insert(
            "k8s:istio.io/gateway-name".to_string(),
            gateway_name.to_string(),
        );

        let to_ports = if ports.is_empty() {
            vec![]
        } else {
            vec![CiliumPortRule {
                ports: ports
                    .iter()
                    .map(|p| CiliumPort {
                        port: p.to_string(),
                        protocol: "TCP".to_string(),
                    })
                    .collect(),
                rules: None,
            }]
        };

        CiliumIngressRule {
            from_endpoints: vec![EndpointSelector::from_labels(labels)],
            to_ports,
        }
    }

    /// Build port rules for external service endpoints (TCP only)
    fn build_external_port_rules(callee: &ServiceNode) -> Vec<CiliumPortRule> {
        let ports: Vec<CiliumPort> = callee
            .endpoints
            .values()
            .map(|ep| CiliumPort {
                port: ep.port.to_string(),
                protocol: "TCP".to_string(),
            })
            .collect();

        if ports.is_empty() {
            vec![]
        } else {
            vec![CiliumPortRule { ports, rules: None }]
        }
    }
}
