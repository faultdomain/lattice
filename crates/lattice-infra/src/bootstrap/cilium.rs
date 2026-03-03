//! Cilium CNI manifest generation
//!
//! Embeds pre-rendered Cilium manifests from build time.
//! Provides CiliumClusterwideNetworkPolicy generation for mesh security.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use lattice_common::mesh::{CILIUM_GATEWAY_NAME_LABEL, HBONE_PORT, ISTIOD_XDS_PORT};
use lattice_common::policy::cilium::{
    CiliumClusterwideNetworkPolicy, CiliumClusterwideSpec, CiliumPort, CiliumPortRule,
    ClusterwideEgressRule, ClusterwideIngressRule, ClusterwideMetadata, DnsMatch, DnsRules,
    EnableDefaultDeny, EndpointSelector, MatchExpression,
};

use super::split_yaml_documents;
use lattice_common::system_namespaces;

/// Pre-rendered Cilium manifests, split into individual YAML documents.
static CILIUM_MANIFESTS: LazyLock<Vec<String>> =
    LazyLock::new(|| split_yaml_documents(include_str!(concat!(env!("OUT_DIR"), "/cilium.yaml"))));

/// Generate Cilium manifests for a cluster
///
/// Returns pre-rendered manifests embedded at build time.
pub fn generate_cilium_manifests() -> &'static [String] {
    &CILIUM_MANIFESTS
}

/// Get Cilium version
pub fn cilium_version() -> &'static str {
    env!("CILIUM_VERSION")
}

/// Generate a CiliumClusterwideNetworkPolicy to allow ztunnel/ambient traffic.
///
/// This is required for Istio ambient mode when using default-deny policies.
/// The ztunnel uses link-local address 169.254.7.127 for SNAT-ed kubelet health probes.
/// See: https://istio.io/latest/docs/ambient/install/platform-prerequisites/
///
/// Key fields:
/// - enableDefaultDeny: false for both egress/ingress to not interfere with other policies
/// - endpointSelector: {} selects all pods
/// - fromCIDR: allows health probes from ztunnel's link-local address
pub fn generate_ztunnel_allowlist() -> CiliumClusterwideNetworkPolicy {
    CiliumClusterwideNetworkPolicy::new(
        ClusterwideMetadata::new("allow-ambient-hostprobes"),
        CiliumClusterwideSpec {
            description: Some(
                "Allows SNAT-ed kubelet health check probes into ambient pods".to_string(),
            ),
            enable_default_deny: Some(EnableDefaultDeny {
                egress: false,
                ingress: false,
            }),
            endpoint_selector: EndpointSelector::default(),
            ingress: vec![ClusterwideIngressRule {
                from_cidr: vec!["169.254.7.127/32".to_string()],
                from_endpoints: vec![],
                to_ports: vec![],
            }],
            egress: vec![],
        },
    )
}

/// Generate a CiliumClusterwideNetworkPolicy for mesh-wide default-deny.
///
/// This provides L4 defense-in-depth alongside Istio's L7 AuthorizationPolicy.
/// Traffic not explicitly allowed by service-specific policies is denied.
///
/// Per Cilium docs: https://docs.cilium.io/en/latest/network/servicemesh/default-deny-ingress-policy/
/// - No ingress rules = deny all ingress
/// - Only allow DNS egress to kube-dns
/// - Exclude system namespaces from policy
pub fn generate_default_deny() -> CiliumClusterwideNetworkPolicy {
    CiliumClusterwideNetworkPolicy::new(
        ClusterwideMetadata::new("default-deny"),
        CiliumClusterwideSpec {
            description: Some(
                "Block all ingress traffic by default, allow DNS and K8s API egress".to_string(),
            ),
            enable_default_deny: None,
            endpoint_selector: EndpointSelector {
                match_labels: BTreeMap::new(),
                match_expressions: vec![MatchExpression {
                    key: "k8s:io.kubernetes.pod.namespace".to_string(),
                    operator: "NotIn".to_string(),
                    values: system_namespaces::all()
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                }],
            },
            ingress: vec![],
            egress: vec![
                ClusterwideEgressRule {
                    to_endpoints: vec![EndpointSelector::from_labels(BTreeMap::from([
                        (
                            "k8s:io.kubernetes.pod.namespace".to_string(),
                            "kube-system".to_string(),
                        ),
                        ("k8s:k8s-app".to_string(), "kube-dns".to_string()),
                    ]))],
                    to_entities: vec![],
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
                        rules: Some(DnsRules {
                            dns: vec![DnsMatch {
                                match_pattern: Some("*".to_string()),
                            }],
                        }),
                    }],
                },
                ClusterwideEgressRule {
                    to_endpoints: vec![],
                    to_entities: vec!["kube-apiserver".to_string()],
                    to_cidr: vec![],
                    to_ports: vec![],
                },
            ],
        },
    )
}

/// Generate a CiliumClusterwideNetworkPolicy for all Istio Gateway API proxy pods.
///
/// This covers both waypoint proxies and ingress gateways — any pod created by
/// Istio's Gateway API controller carries the `gateway.networking.k8s.io/gateway-name`
/// label. All such pods need to:
/// 1. Connect to istiod for xDS configuration and certificate signing
/// 2. Forward traffic to services (internal and external) after L7 processing
///
/// Using a single cluster-wide policy avoids duplicating namespace-scoped policies
/// per service namespace.
pub fn generate_mesh_proxy_egress_policy() -> CiliumClusterwideNetworkPolicy {
    CiliumClusterwideNetworkPolicy::new(
        ClusterwideMetadata::new("mesh-proxy-egress"),
        CiliumClusterwideSpec {
            description: Some(
                "Allow Istio mesh proxy pods (waypoints + ingress gateways) to reach istiod and forward traffic".to_string(),
            ),
            enable_default_deny: None,
            endpoint_selector: EndpointSelector {
                match_labels: BTreeMap::new(),
                match_expressions: vec![MatchExpression {
                    key: CILIUM_GATEWAY_NAME_LABEL.to_string(),
                    operator: "Exists".to_string(),
                    values: vec![],
                }],
            },
            ingress: vec![],
            egress: vec![
                // Allow DNS resolution to kube-dns
                ClusterwideEgressRule {
                    to_endpoints: vec![EndpointSelector::from_labels(BTreeMap::from([
                        (
                            "k8s:io.kubernetes.pod.namespace".to_string(),
                            "kube-system".to_string(),
                        ),
                        ("k8s:k8s-app".to_string(), "kube-dns".to_string()),
                    ]))],
                    to_entities: vec![],
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
                        rules: None,
                    }],
                },
                // Allow xDS and certificate signing to istiod
                ClusterwideEgressRule {
                    to_endpoints: vec![EndpointSelector::from_labels(BTreeMap::from([
                        (
                            "k8s:io.kubernetes.pod.namespace".to_string(),
                            "istio-system".to_string(),
                        ),
                        ("k8s:app".to_string(), "istiod".to_string()),
                    ]))],
                    to_entities: vec![],
                    to_cidr: vec![],
                    to_ports: vec![CiliumPortRule {
                        ports: vec![CiliumPort {
                            port: ISTIOD_XDS_PORT.to_string(),
                            protocol: "TCP".to_string(),
                        }],
                        rules: None,
                    }],
                },
                // Allow HBONE traffic
                ClusterwideEgressRule {
                    to_endpoints: vec![],
                    to_entities: vec![],
                    to_cidr: vec![],
                    to_ports: vec![CiliumPortRule {
                        ports: vec![CiliumPort {
                            port: HBONE_PORT.to_string(),
                            protocol: "TCP".to_string(),
                        }],
                        rules: None,
                    }],
                },
                // Allow proxies to forward traffic to non-system internal endpoints
                ClusterwideEgressRule {
                    to_endpoints: vec![EndpointSelector {
                        match_labels: BTreeMap::new(),
                        match_expressions: vec![MatchExpression {
                            key: "k8s:io.kubernetes.pod.namespace".to_string(),
                            operator: "NotIn".to_string(),
                            values: system_namespaces::all()
                                .iter()
                                .map(|s| s.to_string())
                                .collect(),
                        }],
                    }],
                    to_entities: vec![],
                    to_cidr: vec![],
                    to_ports: vec![],
                },
                // Allow proxies to forward traffic to external services
                ClusterwideEgressRule {
                    to_endpoints: vec![],
                    to_entities: vec![],
                    to_cidr: vec!["0.0.0.0/0".to_string()],
                    to_ports: vec![],
                },
            ],
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cilium_manifests() {
        let manifests = generate_cilium_manifests();
        assert!(!manifests.is_empty());
        let combined = manifests.join("\n");
        // Check for core Cilium components
        assert!(combined.contains("kind: DaemonSet"));
        assert!(combined.contains("cilium-agent"));
    }

    #[test]
    fn test_cilium_version() {
        assert_eq!(cilium_version(), env!("CILIUM_VERSION"));
    }

    #[test]
    fn test_ztunnel_allowlist() {
        let policy = generate_ztunnel_allowlist();

        // Check metadata
        assert_eq!(policy.metadata.name, "allow-ambient-hostprobes");

        // Should allow ztunnel link-local address for health probes
        assert!(policy
            .spec
            .ingress
            .iter()
            .any(|r| r.from_cidr.contains(&"169.254.7.127/32".to_string())));

        // Should have enableDefaultDeny set to false (per Istio docs)
        let enable_deny = policy.spec.enable_default_deny.as_ref().unwrap();
        assert!(!enable_deny.egress);
        assert!(!enable_deny.ingress);

        // Should have ingress rule with fromCIDR
        assert!(!policy.spec.ingress.is_empty());
        assert!(policy.spec.ingress.iter().any(|r| !r.from_cidr.is_empty()));
    }

    #[test]
    fn test_mesh_proxy_egress_policy() {
        let policy = generate_mesh_proxy_egress_policy();

        assert_eq!(policy.metadata.name, "mesh-proxy-egress");

        // Endpoint selector uses Exists on gateway-name label to match all Gateway API pods
        assert!(policy.spec.endpoint_selector.match_labels.is_empty());
        assert_eq!(policy.spec.endpoint_selector.match_expressions.len(), 1);
        let expr = &policy.spec.endpoint_selector.match_expressions[0];
        assert_eq!(expr.key, CILIUM_GATEWAY_NAME_LABEL);
        assert_eq!(expr.operator, "Exists");
        assert!(expr.values.is_empty());

        // Should have egress rules for DNS, istiod, HBONE, internal, and external forwarding
        assert_eq!(policy.spec.egress.len(), 5);

        // First egress rule: DNS
        let dns_rule = &policy.spec.egress[0];
        assert!(dns_rule
            .to_endpoints
            .iter()
            .any(|e| e.match_labels.get("k8s:k8s-app") == Some(&"kube-dns".to_string())));

        // Second egress rule: istiod xDS
        let istiod_rule = &policy.spec.egress[1];
        assert!(istiod_rule
            .to_endpoints
            .iter()
            .any(|e| e.match_labels.get("k8s:app") == Some(&"istiod".to_string())));
        assert!(istiod_rule.to_ports.iter().any(|p| p
            .ports
            .iter()
            .any(|port| port.port == ISTIOD_XDS_PORT.to_string())));

        // Third egress rule: HBONE
        let hbone_rule = &policy.spec.egress[2];
        assert!(hbone_rule.to_ports.iter().any(|p| p
            .ports
            .iter()
            .any(|port| port.port == HBONE_PORT.to_string())));

        // Fourth egress rule: internal forwarding excludes system namespaces
        let internal_rule = &policy.spec.egress[3];
        assert!(!internal_rule.to_endpoints.is_empty());
        let expr = &internal_rule.to_endpoints[0].match_expressions[0];
        assert_eq!(expr.key, "k8s:io.kubernetes.pod.namespace");
        assert_eq!(expr.operator, "NotIn");
        assert!(expr.values.contains(&"kube-system".to_string()));
        assert!(expr.values.contains(&"istio-system".to_string()));

        // Fifth egress rule: external forwarding
        let external_rule = &policy.spec.egress[4];
        assert_eq!(external_rule.to_cidr, vec!["0.0.0.0/0".to_string()]);
    }

    #[test]
    fn test_default_deny() {
        let policy = generate_default_deny();

        // Check metadata
        assert_eq!(policy.metadata.name, "default-deny");

        // Should exclude system namespaces via matchExpressions
        assert!(!policy.spec.endpoint_selector.match_expressions.is_empty());
        let expr = &policy.spec.endpoint_selector.match_expressions[0];
        assert_eq!(expr.key, "k8s:io.kubernetes.pod.namespace");
        assert_eq!(expr.operator, "NotIn");
        assert!(expr.values.contains(&"kube-system".to_string()));
        assert!(expr.values.contains(&"cert-manager".to_string()));
        assert!(expr.values.contains(&"capi-system".to_string()));

        // Should allow DNS and K8s API egress
        assert!(!policy.spec.egress.is_empty());
        assert!(policy.spec.egress.iter().any(|r| {
            r.to_endpoints
                .iter()
                .any(|e| e.match_labels.get("k8s:k8s-app") == Some(&"kube-dns".to_string()))
        }));
        assert!(policy
            .spec
            .egress
            .iter()
            .any(|r| r.to_entities.contains(&"kube-apiserver".to_string())));

        // NO ingress rules = implicit deny all
        assert!(policy.spec.ingress.is_empty());
    }
}
