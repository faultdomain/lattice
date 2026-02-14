//! L4 policy compilation: CiliumNetworkPolicy
//!
//! Generates eBPF-based network enforcement at the kernel level using Cilium.
//!
//! ## Ambient mesh interaction
//!
//! In Istio ambient mesh, ztunnel wraps all pod-to-pod traffic in HBONE
//! (port 15008). Cilium sees the raw pod-to-pod connection on port 15008,
//! so it cannot distinguish individual service ports at L4.
//!
//! Enforcement is split across two layers:
//! - **Cilium (L4)**: Broad HBONE allow for mesh traffic, plus DNS and
//!   external FQDN/CIDR rules for non-mesh egress.
//! - **Istio AuthorizationPolicy (L7)**: Identity-based enforcement using
//!   SPIFFE identities inside the HBONE tunnel.

use std::collections::BTreeMap;

use crate::graph::{ActiveEdge, ServiceNode, ServiceType};
use lattice_common::kube_utils::ObjectMeta;
use lattice_common::policy::{
    CiliumEgressRule, CiliumIngressRule, CiliumNetworkPolicy, CiliumNetworkPolicySpec, CiliumPort,
    CiliumPortRule, DnsMatch, DnsRules, EndpointSelector, FqdnSelector,
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
        has_external_deps: bool,
    ) -> CiliumNetworkPolicy {
        let mut endpoint_labels = BTreeMap::new();
        endpoint_labels.insert(CILIUM_LABEL_NAME.to_string(), service.name.clone());

        // Build ingress: allow HBONE from any mesh pod if this service has callers.
        // Cilium sees pod-to-pod on port 15008; Istio AuthorizationPolicy enforces
        // which specific callers are permitted via SPIFFE identities.
        let ingress_rules = if !inbound_edges.is_empty() || has_external_deps {
            vec![Self::hbone_ingress_rule()]
        } else {
            vec![]
        };

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

        // Allow HBONE egress if this service has any outbound deps (local or external).
        // Ztunnel wraps all connections in HBONE, so Cilium sees pod-to-pod on
        // port 15008 regardless of the actual service port.
        if !outbound_edges.is_empty() {
            egress_rules.push(Self::hbone_egress_rule());
        }

        // Add egress rules for external dependencies (FQDN/CIDR-based, not HBONE)
        self.build_egress_rules_for_external_deps(outbound_edges, &mut egress_rules);

        CiliumNetworkPolicy::new(
            ObjectMeta::new(format!("policy-{}", service.name), namespace),
            CiliumNetworkPolicySpec {
                endpoint_selector: EndpointSelector::from_labels(endpoint_labels),
                ingress: ingress_rules,
                egress: egress_rules,
            },
        )
    }

    /// Build egress rules for external (non-mesh) dependencies only.
    /// Local service dependencies are covered by the broad HBONE egress rule.
    fn build_egress_rules_for_external_deps(
        &self,
        outbound_edges: &[ActiveEdge],
        egress_rules: &mut Vec<CiliumEgressRule>,
    ) {
        for edge in outbound_edges {
            if let Some(callee) = self
                .graph
                .get_service(&edge.callee_namespace, &edge.callee_name)
            {
                if callee.type_ == ServiceType::External {
                    self.build_external_dependency_rules(&callee, egress_rules);
                }
            }
        }
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

    /// Broad HBONE ingress: allow any pod to deliver traffic on port 15008.
    /// Identity enforcement is handled by Istio AuthorizationPolicy at L7.
    fn hbone_ingress_rule() -> CiliumIngressRule {
        CiliumIngressRule {
            from_endpoints: vec![EndpointSelector::from_labels(BTreeMap::new())],
            to_ports: vec![CiliumPortRule {
                ports: vec![CiliumPort {
                    port: mesh::HBONE_PORT.to_string(),
                    protocol: "TCP".to_string(),
                }],
                rules: None,
            }],
        }
    }

    /// Broad HBONE egress: allow this pod to reach any pod on port 15008.
    /// In ambient mesh, ztunnel redirects all outbound connections to HBONE,
    /// so Cilium sees pod-to-pod connections on port 15008 regardless of the
    /// original service port.
    fn hbone_egress_rule() -> CiliumEgressRule {
        CiliumEgressRule {
            to_endpoints: vec![EndpointSelector::from_labels(BTreeMap::new())],
            to_ports: vec![CiliumPortRule {
                ports: vec![CiliumPort {
                    port: mesh::HBONE_PORT.to_string(),
                    protocol: "TCP".to_string(),
                }],
                rules: None,
            }],
            ..Default::default()
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
