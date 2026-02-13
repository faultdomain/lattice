//! Cilium CNI manifest generation
//!
//! Embeds pre-rendered Cilium manifests from build time.
//! Also provides CiliumNetworkPolicy generation for Lattice components.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use lattice_common::kube_utils::ObjectMeta;
use lattice_common::mesh::{CILIUM_GATEWAY_NAME_LABEL, HBONE_PORT, ISTIOD_XDS_PORT};
use lattice_common::policy::{
    CiliumClusterwideNetworkPolicy, CiliumClusterwideSpec, CiliumEgressRule, CiliumIngressRule,
    CiliumNetworkPolicy, CiliumNetworkPolicySpec, CiliumPort, CiliumPortRule,
    ClusterwideEgressRule, ClusterwideIngressRule, ClusterwideMetadata, DnsMatch, DnsRules,
    EnableDefaultDeny, EndpointSelector, FqdnSelector, MatchExpression,
};
use lattice_common::{
    DEFAULT_AUTH_PROXY_PORT, DEFAULT_BOOTSTRAP_PORT, DEFAULT_GRPC_PORT, DEFAULT_PROXY_PORT,
    LATTICE_SYSTEM_NAMESPACE, LOCAL_SECRETS_PORT,
};

use super::split_yaml_documents;
use crate::system_namespaces;

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
                // Allow proxies to forward traffic to any internal endpoint
                ClusterwideEgressRule {
                    to_endpoints: vec![EndpointSelector::default()],
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

/// Generate a CiliumNetworkPolicy for the Lattice operator/agent.
///
/// This policy restricts the operator to only communicate with:
/// - DNS (kube-dns in kube-system)
/// - Kubernetes API server
/// - Parent cell (if parent_host is provided)
///
/// This follows the principle of least privilege - the agent should only
/// be able to reach what it needs for normal operation.
///
/// IMPORTANT: For FQDN-based egress rules to work, the DNS egress rule must include
/// `rules.dns` with a matching pattern. This tells Cilium's DNS proxy to intercept
/// the DNS queries and cache the FQDN-to-IP mappings.
pub fn generate_operator_network_policy(
    parent_host: Option<&str>,
    parent_port: u16,
) -> CiliumNetworkPolicy {
    // Determine DNS match pattern - if we have a hostname parent, we need to intercept its DNS
    let dns_rules = if let Some(host) = parent_host {
        if host.parse::<std::net::IpAddr>().is_ok() {
            // IP address - no DNS interception needed
            None
        } else {
            // Hostname - Cilium needs to intercept DNS to learn the IP
            Some(DnsRules {
                dns: vec![DnsMatch {
                    match_pattern: Some("*".to_string()),
                }],
            })
        }
    } else {
        None
    };

    let mut egress_rules = vec![
        // DNS to kube-dns (with DNS interception rules if we have an FQDN parent)
        CiliumEgressRule {
            to_endpoints: vec![EndpointSelector::from_labels(BTreeMap::from([
                (
                    "k8s:io.kubernetes.pod.namespace".to_string(),
                    "kube-system".to_string(),
                ),
                ("k8s:k8s-app".to_string(), "kube-dns".to_string()),
            ]))],
            to_services: vec![],
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
                rules: dns_rules,
            }],
        },
        // K8s API server
        CiliumEgressRule {
            to_endpoints: vec![],
            to_services: vec![],
            to_entities: vec!["kube-apiserver".to_string()],
            to_fqdns: vec![],
            to_cidr: vec![],
            to_ports: vec![],
        },
    ];

    // Add parent cell if specified
    if let Some(host) = parent_host {
        let is_ip = host.parse::<std::net::IpAddr>().is_ok();
        let parent_ports = vec![CiliumPortRule {
            ports: vec![
                CiliumPort {
                    port: DEFAULT_BOOTSTRAP_PORT.to_string(),
                    protocol: "TCP".to_string(),
                },
                CiliumPort {
                    port: parent_port.to_string(),
                    protocol: "TCP".to_string(),
                },
            ],
            rules: None,
        }];

        if is_ip {
            // For IP addresses (Docker), use CIDR rule
            egress_rules.push(CiliumEgressRule {
                to_endpoints: vec![],
                to_services: vec![],
                to_entities: vec![],
                to_fqdns: vec![],
                to_cidr: vec![format!("{}/32", host)],
                to_ports: parent_ports,
            });
        } else {
            // For hostnames (AWS NLB, etc.), use FQDN rule
            egress_rules.push(CiliumEgressRule {
                to_endpoints: vec![],
                to_services: vec![],
                to_entities: vec![],
                to_fqdns: vec![FqdnSelector {
                    match_name: Some(host.to_string()),
                    match_pattern: None,
                }],
                to_cidr: vec![],
                to_ports: parent_ports,
            });
        }
    }

    CiliumNetworkPolicy::new(
        ObjectMeta::new("lattice-operator", LATTICE_SYSTEM_NAMESPACE),
        CiliumNetworkPolicySpec {
            endpoint_selector: EndpointSelector::from_labels(BTreeMap::from([(
                "app".to_string(),
                "lattice-operator".to_string(),
            )])),
            ingress: vec![CiliumIngressRule {
                from_endpoints: vec![],
                to_ports: vec![CiliumPortRule {
                    ports: vec![
                        CiliumPort {
                            port: DEFAULT_BOOTSTRAP_PORT.to_string(),
                            protocol: "TCP".to_string(),
                        },
                        CiliumPort {
                            port: DEFAULT_GRPC_PORT.to_string(),
                            protocol: "TCP".to_string(),
                        },
                        CiliumPort {
                            port: DEFAULT_PROXY_PORT.to_string(),
                            protocol: "TCP".to_string(),
                        },
                        CiliumPort {
                            port: DEFAULT_AUTH_PROXY_PORT.to_string(),
                            protocol: "TCP".to_string(),
                        },
                        CiliumPort {
                            port: LOCAL_SECRETS_PORT.to_string(),
                            protocol: "TCP".to_string(),
                        },
                    ],
                    rules: None,
                }],
            }],
            egress: egress_rules,
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
    fn test_operator_network_policy_without_parent() {
        let policy = generate_operator_network_policy(None, 50051);

        // Check metadata
        assert_eq!(policy.metadata.name, "lattice-operator");
        assert_eq!(policy.metadata.namespace, LATTICE_SYSTEM_NAMESPACE);

        // Should have DNS egress
        let dns_rule = policy.spec.egress.iter().find(|r| {
            r.to_endpoints
                .iter()
                .any(|e| e.match_labels.get("k8s:k8s-app") == Some(&"kube-dns".to_string()))
        });
        assert!(dns_rule.is_some());
        let dns_rule = dns_rule.unwrap();
        assert!(dns_rule
            .to_ports
            .iter()
            .any(|p| p.ports.iter().any(|port| port.port == "53")));

        // DNS rules should be None when no FQDN parent
        let dns_port_rule = &dns_rule.to_ports[0];
        assert!(
            dns_port_rule.rules.is_none(),
            "DNS rules should be None when no FQDN parent"
        );

        // Should have API server egress
        assert!(policy
            .spec
            .egress
            .iter()
            .any(|r| r.to_entities.contains(&"kube-apiserver".to_string())));

        // Should NOT have parent rules (no FQDN or CIDR)
        assert!(policy.spec.egress.iter().all(|r| r.to_fqdns.is_empty()));
        assert!(policy.spec.egress.iter().all(|r| r.to_cidr.is_empty()));

        // Should have ingress for cell ports
        assert!(policy.spec.ingress.iter().any(|r| {
            r.to_ports
                .iter()
                .any(|p| p.ports.iter().any(|port| port.port == "8443"))
        }));
        assert!(policy.spec.ingress.iter().any(|r| {
            r.to_ports
                .iter()
                .any(|p| p.ports.iter().any(|port| port.port == "50051"))
        }));
    }

    #[test]
    fn test_operator_network_policy_with_parent_hostname() {
        let policy = generate_operator_network_policy(Some("cell.example.com"), 50051);

        // Should have parent FQDN rule for hostname
        let fqdn_rule = policy.spec.egress.iter().find(|r| !r.to_fqdns.is_empty());
        assert!(fqdn_rule.is_some());
        let fqdn_rule = fqdn_rule.unwrap();
        assert!(fqdn_rule
            .to_fqdns
            .iter()
            .any(|f| f.match_name == Some("cell.example.com".to_string())));

        // Should allow both bootstrap and gRPC ports
        assert!(fqdn_rule
            .to_ports
            .iter()
            .any(|p| p.ports.iter().any(|port| port.port == "8443")));
        assert!(fqdn_rule
            .to_ports
            .iter()
            .any(|p| p.ports.iter().any(|port| port.port == "50051")));

        // Should NOT use toCIDR for hostname
        assert!(fqdn_rule.to_cidr.is_empty());

        // Should have DNS with interception rules (required for toFQDNs to work)
        let dns_rule = policy.spec.egress.iter().find(|r| {
            r.to_endpoints
                .iter()
                .any(|e| e.match_labels.get("k8s:k8s-app") == Some(&"kube-dns".to_string()))
        });
        assert!(dns_rule.is_some());
        let dns_rule = dns_rule.unwrap();
        let dns_port_rule = &dns_rule.to_ports[0];
        assert!(
            dns_port_rule.rules.is_some(),
            "DNS egress must have rules.dns for FQDN policies to work"
        );
        let dns_rules = dns_port_rule.rules.as_ref().unwrap();
        assert!(
            dns_rules.dns.iter().any(|d| d.match_pattern.is_some()),
            "DNS rules must have a match pattern"
        );

        // Should have API server egress
        assert!(policy
            .spec
            .egress
            .iter()
            .any(|r| r.to_entities.contains(&"kube-apiserver".to_string())));
    }

    #[test]
    fn test_operator_network_policy_with_parent_ip() {
        let policy = generate_operator_network_policy(Some("172.18.255.10"), 50051);

        // Should have parent CIDR rule for IP address
        let cidr_rule = policy.spec.egress.iter().find(|r| !r.to_cidr.is_empty());
        assert!(cidr_rule.is_some());
        let cidr_rule = cidr_rule.unwrap();
        assert!(cidr_rule.to_cidr.contains(&"172.18.255.10/32".to_string()));

        // Should allow both bootstrap and gRPC ports
        assert!(cidr_rule
            .to_ports
            .iter()
            .any(|p| p.ports.iter().any(|port| port.port == "8443")));
        assert!(cidr_rule
            .to_ports
            .iter()
            .any(|p| p.ports.iter().any(|port| port.port == "50051")));

        // Should NOT use toFQDNs for IP
        assert!(cidr_rule.to_fqdns.is_empty());

        // DNS rules should be None for IP parent (no FQDN to intercept)
        let dns_rule = policy.spec.egress.iter().find(|r| {
            r.to_endpoints
                .iter()
                .any(|e| e.match_labels.get("k8s:k8s-app") == Some(&"kube-dns".to_string()))
        });
        assert!(dns_rule.is_some());
        let dns_port_rule = &dns_rule.unwrap().to_ports[0];
        assert!(
            dns_port_rule.rules.is_none(),
            "DNS rules should be None for IP parent"
        );

        // Should have API server egress
        assert!(policy
            .spec
            .egress
            .iter()
            .any(|r| r.to_entities.contains(&"kube-apiserver".to_string())));
    }

    #[test]
    fn test_operator_network_policy_custom_port() {
        let policy = generate_operator_network_policy(Some("parent.local"), 4001);

        // Should use custom gRPC port and default bootstrap port
        let fqdn_rule = policy
            .spec
            .egress
            .iter()
            .find(|r| !r.to_fqdns.is_empty())
            .unwrap();
        assert!(fqdn_rule
            .to_ports
            .iter()
            .any(|p| p.ports.iter().any(|port| port.port == "4001")));
        assert!(fqdn_rule
            .to_ports
            .iter()
            .any(|p| p.ports.iter().any(|port| port.port == "8443")));
        assert!(fqdn_rule
            .to_fqdns
            .iter()
            .any(|f| f.match_name == Some("parent.local".to_string())));
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

        // Should have egress rules for istiod, HBONE, internal, and external forwarding
        assert_eq!(policy.spec.egress.len(), 4);

        // First egress rule: istiod xDS
        let istiod_rule = &policy.spec.egress[0];
        assert!(istiod_rule
            .to_endpoints
            .iter()
            .any(|e| e.match_labels.get("k8s:app") == Some(&"istiod".to_string())));
        assert!(istiod_rule.to_ports.iter().any(|p| p
            .ports
            .iter()
            .any(|port| port.port == ISTIOD_XDS_PORT.to_string())));

        // Second egress rule: HBONE
        let hbone_rule = &policy.spec.egress[1];
        assert!(hbone_rule.to_ports.iter().any(|p| p
            .ports
            .iter()
            .any(|port| port.port == HBONE_PORT.to_string())));
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
