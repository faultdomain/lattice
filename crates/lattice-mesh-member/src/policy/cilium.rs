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
use lattice_common::graph::{ActiveEdge, ServiceNode};
use lattice_common::kube_utils::ObjectMeta;
use lattice_common::policy::cilium::{
    CiliumEgressRule, CiliumIngressRule, CiliumNetworkPolicy, CiliumNetworkPolicySpec, CiliumPort,
    CiliumPortRule, DnsMatch, DnsRules, EndpointSelector, FqdnSelector,
};
use lattice_common::{mesh, CILIUM_LABEL_NAMESPACE};

use super::PolicyCompiler;

// =============================================================================
// Reusable rule builders (pub(crate) for use by IngressCompiler)
// =============================================================================

/// Broad HBONE ingress: allow any pod in the cluster to deliver traffic on port 15008.
/// Identity enforcement is handled by Istio AuthorizationPolicy at L7.
///
/// Uses `fromEntities: [cluster]` instead of `fromEndpoints: [{}]` because
/// empty endpoint selectors in namespaced CNPs only match same-namespace pods.
/// HBONE traffic is cross-namespace (ztunnel on any node delivers to any pod).
pub(crate) fn hbone_ingress_rule() -> CiliumIngressRule {
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
pub(crate) fn hbone_egress_rule() -> CiliumEgressRule {
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

/// DNS egress: allow this pod to reach kube-dns on port 53 (UDP + TCP).
///
/// When `dns_rules` is `Some`, Cilium's DNS-aware proxy intercepts queries and
/// caches FQDN→IP mappings, which is required for FQDN-based egress rules to work.
pub(crate) fn dns_egress_rule(dns_rules: Option<DnsRules>) -> CiliumEgressRule {
    let mut kube_dns_labels = BTreeMap::new();
    kube_dns_labels.insert(
        CILIUM_LABEL_NAMESPACE.to_string(),
        "kube-system".to_string(),
    );
    kube_dns_labels.insert("k8s:k8s-app".to_string(), "kube-dns".to_string());
    CiliumEgressRule {
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
            rules: dns_rules,
        }],
        ..Default::default()
    }
}

/// Build a CiliumPortRule list from a slice of port numbers (TCP only).
///
/// Returns an empty vec if no ports are given, otherwise a single rule with all ports.
pub(crate) fn build_tcp_port_rules(ports: &[u16]) -> Vec<CiliumPortRule> {
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

// =============================================================================
// PolicyCompiler — Cilium policy for mesh members
// =============================================================================

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
                to_ports: build_tcp_port_rules(&broad_ports),
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
                to_ports: build_tcp_port_rules(&webhook_ports),
                ..Default::default()
            });
        }

        // HBONE ingress: ztunnel wraps all inbound traffic on port 15008 in ambient mesh.
        // Required whenever this pod accepts any inbound traffic (mesh callers, webhooks,
        // permissive ports, infrastructure callers like vmagent, or peer traffic).
        let has_infra_callers = self.has_infrastructure_callers(service);
        if !inbound_edges.is_empty()
            || !ingress_rules.is_empty()
            || has_infra_callers
            || service.allow_peer_traffic
        {
            ingress_rules.insert(0, hbone_ingress_rule());
        }

        // Build egress rules
        let mut egress_rules = Vec::new();

        let has_fqdn_egress = service
            .egress_rules
            .iter()
            .any(|r| matches!(r.target, EgressTarget::Fqdn(_)));

        // Always allow DNS to kube-dns. When FQDN egress is configured,
        // enable the DNS proxy so Cilium can resolve FQDN→IP mappings.
        let fqdn_rules = if has_fqdn_egress {
            Some(DnsRules {
                dns: vec![DnsMatch {
                    match_pattern: Some("*".to_string()),
                }],
            })
        } else {
            None
        };
        egress_rules.push(dns_egress_rule(fqdn_rules));

        // HBONE egress for outbound mesh dependencies, external FQDN egress, or peer traffic
        if !outbound_edges.is_empty() || has_fqdn_egress || service.allow_peer_traffic {
            egress_rules.push(hbone_egress_rule());
        }

        // Non-mesh egress rules from spec (entity, CIDR, FQDN)
        for rule in &service.egress_rules {
            let to_ports = build_tcp_port_rules(&rule.ports);

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
                _ => {}
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
}
