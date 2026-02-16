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

use lattice_common::crd::{derived_name, EgressTarget};
use lattice_common::graph::{ActiveEdge, ServiceNode, ServiceType};
use lattice_common::kube_utils::ObjectMeta;
use lattice_common::policy::cilium::{
    CiliumEgressRule, CiliumIngressRule, CiliumNetworkPolicy, CiliumNetworkPolicySpec, CiliumPort,
    CiliumPortRule, DnsMatch, DnsRules, EndpointSelector, FqdnSelector,
};
use lattice_common::{mesh, CILIUM_LABEL_NAMESPACE};

use super::PolicyCompiler;

impl<'a> PolicyCompiler<'a> {
    /// Compile a CiliumNetworkPolicy for a mesh member.
    ///
    /// Uses the member's custom selector labels for the endpoint selector.
    /// Permissive ports get direct TCP ingress (not HBONE) for plaintext callers.
    /// Non-mesh egress rules (entity, CIDR, FQDN) are applied from the spec.
    pub(super) fn compile_cilium_policy(
        &self,
        service: &ServiceNode,
        namespace: &str,
        inbound_edges: &[ActiveEdge],
        outbound_edges: &[ActiveEdge],
    ) -> CiliumNetworkPolicy {
        let endpoint_labels = service.cilium_match_labels();

        let mut ingress_rules = Vec::new();

        // Direct TCP ingress for broadly permissive ports (any source)
        let broad_ports = service.permissive_port_numbers();
        if !broad_ports.is_empty() {
            ingress_rules.push(CiliumIngressRule {
                from_endpoints: vec![EndpointSelector::from_labels(BTreeMap::new())],
                to_ports: Self::build_tcp_port_rules(&broad_ports),
                ..Default::default()
            });
        }

        // Direct TCP ingress for webhook ports.
        // kube-apiserver webhook calls go through kube-proxy DNAT, so Cilium sees
        // the source identity as remote-node (cross-node) or host (same-node),
        // not kube-apiserver. All three entities are needed for reliable delivery.
        let webhook_ports = service.webhook_port_numbers();
        if !webhook_ports.is_empty() {
            ingress_rules.push(CiliumIngressRule {
                from_entities: vec![
                    "remote-node".to_string(),
                    "kube-apiserver".to_string(),
                    "host".to_string(),
                ],
                to_ports: Self::build_tcp_port_rules(&webhook_ports),
                ..Default::default()
            });
        }

        // HBONE ingress: ztunnel wraps all inbound traffic on port 15008 in ambient mesh.
        // Required whenever this pod accepts any inbound traffic (mesh callers, webhooks,
        // permissive ports, or infrastructure callers like vmagent).
        let has_infra_callers = self.has_infrastructure_callers(service, inbound_edges);
        if !inbound_edges.is_empty() || !ingress_rules.is_empty() || has_infra_callers {
            ingress_rules.insert(0, Self::hbone_ingress_rule());
        }

        // Build egress rules
        let mut egress_rules = Vec::new();

        // Check if service has external FQDN dependencies or FQDN egress rules
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
        let has_fqdn_egress = service
            .egress_rules
            .iter()
            .any(|r| matches!(r.target, EgressTarget::Fqdn(_)));

        // Always allow DNS to kube-dns
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
                rules: if has_external_fqdns || has_fqdn_egress {
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

        // HBONE egress for outbound mesh dependencies
        if !outbound_edges.is_empty() {
            egress_rules.push(Self::hbone_egress_rule());
        }

        // External deps egress (FQDN/CIDR from outbound edges)
        self.build_egress_rules_for_external_deps(outbound_edges, &mut egress_rules);

        // Non-mesh egress rules from spec (entity, CIDR, FQDN)
        for rule in &service.egress_rules {
            let to_ports = Self::build_tcp_port_rules(&rule.ports);

            match &rule.target {
                EgressTarget::Entity(entity) => {
                    egress_rules.push(CiliumEgressRule {
                        to_entities: vec![entity.clone()],
                        to_ports,
                        ..Default::default()
                    });
                }
                EgressTarget::Cidr(cidr) => {
                    egress_rules.push(CiliumEgressRule {
                        to_cidr: vec![cidr.clone()],
                        to_ports,
                        ..Default::default()
                    });
                }
                EgressTarget::Fqdn(fqdn) => {
                    egress_rules.push(CiliumEgressRule {
                        to_fqdns: vec![FqdnSelector {
                            match_name: Some(fqdn.clone()),
                            match_pattern: None,
                        }],
                        to_ports,
                        ..Default::default()
                    });
                }
            }
        }

        CiliumNetworkPolicy::new(
            ObjectMeta::new(
                derived_name("cnp-mesh-", &[namespace, &service.name]),
                namespace,
            ),
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
    fn build_external_dependency_rules(
        &self,
        callee: &ServiceNode,
        egress_rules: &mut Vec<CiliumEgressRule>,
    ) {
        let (fqdns, cidrs) = Self::categorize_external_endpoints(callee);
        let to_ports = Self::build_external_port_rules(callee);

        if !fqdns.is_empty() {
            egress_rules.push(CiliumEgressRule {
                to_fqdns: fqdns,
                to_ports: to_ports.clone(),
                ..Default::default()
            });
        }

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

    /// Broad HBONE ingress: allow any pod in the cluster to deliver traffic on port 15008.
    /// Identity enforcement is handled by Istio AuthorizationPolicy at L7.
    ///
    /// Uses `fromEntities: [cluster]` instead of `fromEndpoints: [{}]` because
    /// empty endpoint selectors in namespaced CNPs only match same-namespace pods.
    /// HBONE traffic is cross-namespace (ztunnel on any node delivers to any pod).
    fn hbone_ingress_rule() -> CiliumIngressRule {
        CiliumIngressRule {
            from_entities: vec!["cluster".to_string()],
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

    /// Broad HBONE egress: allow this pod to reach any pod in the cluster on port 15008.
    ///
    /// Uses `toEntities: [cluster]` instead of `toEndpoints: [{}]` because
    /// empty endpoint selectors in namespaced CNPs only match same-namespace pods.
    /// HBONE traffic is cross-namespace (ztunnel delivers to pods in any namespace).
    fn hbone_egress_rule() -> CiliumEgressRule {
        CiliumEgressRule {
            to_entities: vec!["cluster".to_string()],
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

    /// Build a CiliumPortRule list from a slice of port numbers (TCP only).
    ///
    /// Returns an empty vec if no ports are given, otherwise a single rule with all ports.
    fn build_tcp_port_rules(ports: &[u16]) -> Vec<CiliumPortRule> {
        if ports.is_empty() {
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
        }
    }

    /// Build port rules for external service endpoints (TCP only)
    fn build_external_port_rules(callee: &ServiceNode) -> Vec<CiliumPortRule> {
        let ports: Vec<u16> = callee.endpoints.values().map(|ep| ep.port).collect();
        Self::build_tcp_port_rules(&ports)
    }
}
