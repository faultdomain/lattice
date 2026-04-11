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

use lattice_common::kube_utils::ObjectMeta;
use lattice_common::policy::cilium::{
    CiliumEgressRule, CiliumIngressRule, CiliumNetworkPolicy, CiliumNetworkPolicySpec, CiliumPort,
    CiliumPortRule, DnsMatch, DnsRules, EndpointSelector, FqdnSelector,
};
use lattice_common::{mesh, CILIUM_LABEL_NAMESPACE};
use lattice_crd::crd::{derived_name, EgressTarget, NetworkProtocol};
use lattice_graph::{ActiveEdge, ServiceNode};

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

/// Broad HBONE egress: allow this pod to reach any destination on port 15008.
///
/// Includes both "cluster" (local pods/nodes) and "world" (cross-cluster
/// east-west gateway IPs). HBONE is always mTLS-protected by Istio, so
/// allowing world on this port has no security impact. Including world
/// unconditionally prevents cross-cluster HBONE from breaking when remote
/// services are transiently removed from the service graph.
pub(crate) fn hbone_egress_rule() -> CiliumEgressRule {
    CiliumEgressRule {
        to_entities: vec!["cluster".to_string(), "world".to_string()],
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

/// Build a CiliumPortRule list from a slice of port numbers and protocol.
///
/// Returns an empty vec if no ports are given, otherwise a single rule with all ports.
pub(crate) fn build_port_rules(ports: &[u16], protocol: NetworkProtocol) -> Vec<CiliumPortRule> {
    if ports.is_empty() {
        vec![]
    } else {
        vec![CiliumPortRule {
            ports: ports
                .iter()
                .map(|p| CiliumPort {
                    port: p.to_string(),
                    protocol: protocol.as_str().to_string(),
                })
                .collect(),
            rules: None,
        }]
    }
}

/// Ingress rule for permissive ports (any in-cluster source).
///
/// Uses `fromEntities: [cluster]` because empty endpoint selectors in
/// namespaced CNPs only match same-namespace pods. Permissive ports accept
/// traffic from non-mesh callers in other namespaces.
fn permissive_port_ingress(ports: &[u16]) -> Option<CiliumIngressRule> {
    if ports.is_empty() {
        return None;
    }
    Some(CiliumIngressRule {
        from_entities: vec!["cluster".to_string()],
        to_ports: build_port_rules(ports, NetworkProtocol::Tcp),
        ..Default::default()
    })
}

/// Ingress rule for webhook ports (kube-apiserver + external callers).
///
/// kube-apiserver webhook calls go through kube-proxy DNAT, so Cilium sees
/// the source identity as remote-node (cross-node) or host (same-node).
/// "world" is needed for child cluster nodes connecting over real networks.
/// "cluster" covers in-cluster cross-namespace callers.
fn webhook_port_ingress(ports: &[u16]) -> Option<CiliumIngressRule> {
    if ports.is_empty() {
        return None;
    }
    Some(CiliumIngressRule {
        from_entities: vec![
            "cluster".to_string(),
            "remote-node".to_string(),
            "kube-apiserver".to_string(),
            "host".to_string(),
            "world".to_string(),
        ],
        to_ports: build_port_rules(ports, NetworkProtocol::Tcp),
        ..Default::default()
    })
}

/// Convert spec egress rules (entity, CIDR, FQDN) to Cilium egress rules.
fn spec_egress_rules(service: &ServiceNode) -> Vec<CiliumEgressRule> {
    service
        .egress_rules
        .iter()
        .filter_map(|rule| {
            let to_ports = build_port_rules(&rule.ports, rule.protocol);
            match &rule.target {
                EgressTarget::Entity(entity) => Some(CiliumEgressRule {
                    to_entities: vec![entity.clone()],
                    to_ports,
                    ..Default::default()
                }),
                EgressTarget::Cidr(cidr) => Some(CiliumEgressRule {
                    to_cidr: vec![cidr.clone()],
                    to_ports,
                    ..Default::default()
                }),
                EgressTarget::Fqdn(fqdn) => Some(CiliumEgressRule {
                    to_fqdns: vec![FqdnSelector {
                        match_name: Some(fqdn.clone()),
                        match_pattern: None,
                    }],
                    to_ports,
                    ..Default::default()
                }),
                _ => None,
            }
        })
        .collect()
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

        ingress_rules.extend(permissive_port_ingress(&service.permissive_port_numbers()));
        ingress_rules.extend(webhook_port_ingress(&service.webhook_port_numbers()));

        // HBONE ingress: ztunnel wraps all inbound traffic on port 15008 in ambient mesh.
        // Required whenever this pod accepts any inbound traffic (mesh callers, webhooks,
        // permissive ports, or peer traffic).
        if !inbound_edges.is_empty()
            || !ingress_rules.is_empty()
            || service.allow_peer_traffic
            || service.advertise.is_some()
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

        // HBONE egress: always allow for ambient services. HBONE is mTLS on
        // port 15008 — gating it on graph state causes flapping when remote
        // services are transiently removed. Istio enforces identity at L7.
        if service.ambient {
            egress_rules.push(hbone_egress_rule());
        }

        // Direct egress for outbound edges to non-ambient callees.
        // HBONE covers ambient-to-ambient traffic via ztunnel, but non-ambient
        // callees require direct L4 egress on their service ports.
        for edge in outbound_edges {
            let callee = match self
                .graph
                .get_service(&edge.callee_namespace, &edge.callee_name)
            {
                Some(c) => c,
                None => continue,
            };
            if callee.ambient {
                continue; // HBONE covers this
            }
            let mut labels = callee.cilium_match_labels();
            if edge.callee_namespace != namespace {
                labels.insert(
                    CILIUM_LABEL_NAMESPACE.to_string(),
                    edge.callee_namespace.clone(),
                );
            }
            let port_numbers: Vec<u16> = callee.ports.values().map(|pm| pm.target_port).collect();
            if !port_numbers.is_empty() {
                egress_rules.push(CiliumEgressRule {
                    to_endpoints: vec![EndpointSelector::from_labels(labels)],
                    to_ports: build_port_rules(&port_numbers, NetworkProtocol::Tcp),
                    ..Default::default()
                });
            }
        }

        egress_rules.extend(spec_egress_rules(service));

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

    /// Compile a CiliumNetworkPolicy for an out-of-ambient member.
    ///
    /// These pods have `istio.io/dataplane-mode: none` — no ztunnel, no HBONE.
    /// All traffic is direct L4. No `fromEntities: [cluster]` — only specific
    /// label-based callers and peer group members are allowed.
    pub(super) fn compile_direct_cilium_policy(
        &self,
        service: &ServiceNode,
        namespace: &str,
    ) -> CiliumNetworkPolicy {
        let endpoint_labels = service.cilium_match_labels();
        let mut ingress_rules = Vec::new();

        // Peer traffic: pods matching our own selector can reach us on any port
        if service.allow_peer_traffic {
            ingress_rules.push(CiliumIngressRule {
                from_endpoints: vec![EndpointSelector::from_labels(endpoint_labels.clone())],
                ..Default::default()
            });
        }

        ingress_rules.extend(permissive_port_ingress(&service.permissive_port_numbers()));
        ingress_rules.extend(webhook_port_ingress(&service.webhook_port_numbers()));

        // Bilateral agreement callers: label-based ingress with port restrictions
        let inbound_edges = self
            .graph
            .get_active_inbound_edges(namespace, &service.name);
        for edge in &inbound_edges {
            let caller = match self
                .graph
                .get_service(&edge.caller_namespace, &edge.caller_name)
            {
                Some(c) => c,
                None => continue,
            };
            let mut labels = caller.cilium_match_labels();
            if edge.caller_namespace != namespace {
                labels.insert(
                    CILIUM_LABEL_NAMESPACE.to_string(),
                    edge.caller_namespace.clone(),
                );
            }
            let port_numbers: Vec<u16> = service.ports.values().map(|pm| pm.target_port).collect();
            ingress_rules.push(CiliumIngressRule {
                from_endpoints: vec![EndpointSelector::from_labels(labels)],
                to_ports: build_port_rules(&port_numbers, NetworkProtocol::Tcp),
                ..Default::default()
            });
        }

        // Egress: DNS + peer traffic + non-mesh egress rules
        let mut egress_rules = Vec::new();
        egress_rules.push(dns_egress_rule(None));

        // Peer egress: match our own selector (same pods we allow inbound from)
        if service.allow_peer_traffic {
            egress_rules.push(CiliumEgressRule {
                to_endpoints: vec![EndpointSelector::from_labels(endpoint_labels.clone())],
                ..Default::default()
            });
        }

        egress_rules.extend(spec_egress_rules(service));

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
