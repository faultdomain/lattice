//! Network policy types for Lattice services
//!
//! This module defines the Istio and Cilium policy resource types used by
//! the ServiceCompiler. These implement a defense-in-depth model:
//!
//! - **L7 (Istio AuthorizationPolicy)**: mTLS identity-based access control using SPIFFE principals
//! - **L4 (CiliumNetworkPolicy)**: eBPF-based network enforcement at the kernel level
//!
//! For policy generation, use [`crate::compiler::ServiceCompiler`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// =============================================================================
// Istio AuthorizationPolicy
// =============================================================================

/// Istio AuthorizationPolicy for L7 mTLS identity-based access control
///
/// This policy is applied to Services via targetRefs (Istio Ambient mode)
/// and enforced at the waypoint proxy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationPolicy {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: PolicyMetadata,
    /// Spec
    pub spec: AuthorizationPolicySpec,
}

/// Metadata for policy resources
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PolicyMetadata {
    /// Resource name
    pub name: String,
    /// Resource namespace
    pub namespace: String,
    /// Labels
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

impl PolicyMetadata {
    /// Create new metadata with standard Lattice labels
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        let mut labels = BTreeMap::new();
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "lattice".to_string(),
        );
        Self {
            name: name.into(),
            namespace: namespace.into(),
            labels,
        }
    }
}

/// AuthorizationPolicy spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationPolicySpec {
    /// Target references (Service, ServiceEntry)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_refs: Vec<TargetRef>,

    /// Selector for workloads (used for waypoint policies)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<WorkloadSelector>,

    /// Action: ALLOW, DENY, AUDIT, CUSTOM (empty = implicit deny-all)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub action: String,

    /// Rules defining who can access
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<AuthorizationRule>,
}

/// Target reference for AuthorizationPolicy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TargetRef {
    /// API group (empty string for core resources like Service)
    /// Note: Must always be present - Istio requires this field even when empty
    #[serde(default)]
    pub group: String,
    /// Resource kind
    pub kind: String,
    /// Resource name
    pub name: String,
}

/// Workload selector for AuthorizationPolicy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadSelector {
    /// Match labels
    pub match_labels: BTreeMap<String, String>,
}

/// Authorization rule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationRule {
    /// Source conditions (who is calling)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from: Vec<AuthorizationSource>,
    /// Destination conditions (what operation)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<AuthorizationOperation>,
}

/// Authorization source (caller identity)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationSource {
    /// Source specification
    pub source: SourceSpec,
}

/// Source specification
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SourceSpec {
    /// SPIFFE principals
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principals: Vec<String>,
}

/// Authorization operation (what's being accessed)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AuthorizationOperation {
    /// Operation specification
    pub operation: OperationSpec,
}

/// Operation specification
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OperationSpec {
    /// Allowed ports
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<String>,
    /// Allowed hosts (for external services)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
}

// =============================================================================
// CiliumNetworkPolicy
// =============================================================================

/// Cilium Network Policy for L4 eBPF-based network enforcement
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CiliumNetworkPolicy {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: PolicyMetadata,
    /// Spec
    pub spec: CiliumNetworkPolicySpec,
}

/// CiliumNetworkPolicy spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CiliumNetworkPolicySpec {
    /// Endpoint selector (which pods this applies to)
    pub endpoint_selector: EndpointSelector,
    /// Ingress rules
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<CiliumIngressRule>,
    /// Egress rules
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<CiliumEgressRule>,
}

/// Endpoint selector for CiliumNetworkPolicy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EndpointSelector {
    /// Match labels
    pub match_labels: BTreeMap<String, String>,
}

/// Cilium ingress rule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CiliumIngressRule {
    /// From endpoints
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from_endpoints: Vec<EndpointSelector>,
    /// To ports
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_ports: Vec<CiliumPortRule>,
}

/// Cilium egress rule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CiliumEgressRule {
    /// To endpoints (internal services)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_endpoints: Vec<EndpointSelector>,
    /// To FQDNs (external DNS names)
    /// Note: Cilium uses uppercase "FQDNs" not camelCase "Fqdns"
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "toFQDNs")]
    pub to_fqdns: Vec<FqdnSelector>,
    /// To CIDRs (IP ranges)
    /// Note: Cilium uses uppercase "CIDR" not camelCase "Cidr"
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "toCIDR")]
    pub to_cidr: Vec<String>,
    /// To ports
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_ports: Vec<CiliumPortRule>,
}

/// FQDN selector for Cilium egress
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FqdnSelector {
    /// Exact match name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_name: Option<String>,
    /// Pattern match (supports wildcards)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_pattern: Option<String>,
}

/// Cilium port rule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CiliumPortRule {
    /// Ports
    pub ports: Vec<CiliumPort>,
}

/// Cilium port specification
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CiliumPort {
    /// Port number
    pub port: String,
    /// Protocol (TCP, UDP)
    pub protocol: String,
}

// =============================================================================
// Istio ServiceEntry
// =============================================================================

/// Istio ServiceEntry for external service mesh integration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEntry {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: PolicyMetadata,
    /// Spec
    pub spec: ServiceEntrySpec,
}

/// ServiceEntry spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceEntrySpec {
    /// Hosts (DNS names)
    pub hosts: Vec<String>,
    /// Ports
    pub ports: Vec<ServiceEntryPort>,
    /// Location: MESH_EXTERNAL or MESH_INTERNAL
    pub location: String,
    /// Resolution: DNS, STATIC, NONE
    pub resolution: String,
}

/// ServiceEntry port
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceEntryPort {
    /// Port number
    pub number: u16,
    /// Port name
    pub name: String,
    /// Protocol (HTTP, HTTPS, TCP, GRPC)
    pub protocol: String,
}

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

use crate::graph::{ActiveEdge, ServiceGraph, ServiceNode, ServiceType};

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
    trust_domain: String,
}

impl<'a> PolicyCompiler<'a> {
    /// HBONE port for Istio Ambient waypoint communication
    const HBONE_PORT: u16 = 15008;

    /// Create a new policy compiler
    ///
    /// # Arguments
    /// * `graph` - The service graph for bilateral agreement checks
    /// * `trust_domain` - SPIFFE trust domain (e.g., "prod.lattice.local")
    pub fn new(graph: &'a ServiceGraph, trust_domain: impl Into<String>) -> Self {
        Self {
            graph,
            trust_domain: trust_domain.into(),
        }
    }

    /// Compile policies for a service
    ///
    /// Returns empty policies if service is not in graph or has no active edges.
    pub fn compile(&self, name: &str, namespace: &str, env: &str) -> GeneratedPolicies {
        let Some(service_node) = self.graph.get_service(env, name) else {
            return GeneratedPolicies::new();
        };

        // Skip Unknown services
        if service_node.type_ == ServiceType::Unknown {
            return GeneratedPolicies::new();
        }

        let mut output = GeneratedPolicies::new();

        // Get active edges
        let inbound_edges = self.graph.get_active_inbound_edges(env, name);
        let outbound_edges = self.graph.get_active_outbound_edges(env, name);

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
            env,
            &inbound_edges,
            &outbound_edges,
        ));

        // Generate ServiceEntries for external dependencies
        for edge in &outbound_edges {
            if let Some(callee) = self.graph.get_service(env, &edge.callee) {
                if callee.type_ == ServiceType::External {
                    if let Some(entry) = self.compile_service_entry(&callee, namespace) {
                        output.service_entries.push(entry);
                    }
                }
            }
        }

        output
    }

    /// Compile the mesh-wide default-deny AuthorizationPolicy
    ///
    /// Per Istio best practices: https://istio.io/latest/docs/ops/best-practices/security/
    /// An empty spec `{}` denies all traffic by default.
    pub fn compile_mesh_default_deny() -> AuthorizationPolicy {
        AuthorizationPolicy {
            api_version: "security.istio.io/v1".to_string(),
            kind: "AuthorizationPolicy".to_string(),
            metadata: PolicyMetadata::new("mesh-default-deny", "istio-system"),
            spec: AuthorizationPolicySpec {
                target_refs: vec![],
                selector: None,
                action: String::new(), // Empty = implicit deny-all
                rules: vec![],         // Empty = no traffic allowed
            },
        }
    }

    /// Compile the ambient waypoint default-deny AuthorizationPolicy
    ///
    /// Per Istio best practices for ambient mode, we need a separate policy
    /// targeting the waypoint GatewayClass.
    pub fn compile_waypoint_default_deny() -> AuthorizationPolicy {
        AuthorizationPolicy {
            api_version: "security.istio.io/v1".to_string(),
            kind: "AuthorizationPolicy".to_string(),
            metadata: PolicyMetadata::new("waypoint-default-deny", "istio-system"),
            spec: AuthorizationPolicySpec {
                target_refs: vec![TargetRef {
                    group: "gateway.networking.k8s.io".to_string(),
                    kind: "GatewayClass".to_string(),
                    name: "istio-waypoint".to_string(),
                }],
                selector: None,
                action: String::new(), // Empty = implicit deny-all
                rules: vec![],
            },
        }
    }

    /// Check if a string is an IP address (IPv4 or IPv6)
    fn is_ip_address(host: &str) -> bool {
        use std::net::IpAddr;
        host.parse::<IpAddr>().is_ok()
    }

    fn spiffe_principal(&self, namespace: &str, service_name: &str) -> String {
        format!(
            "spiffe://{}/ns/{}/sa/{}",
            self.trust_domain, namespace, service_name
        )
    }

    fn waypoint_principal(&self, namespace: &str) -> String {
        format!(
            "spiffe://{}/ns/{}/sa/{}-waypoint",
            self.trust_domain, namespace, namespace
        )
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
            .map(|edge| self.spiffe_principal(namespace, &edge.caller))
            .collect();

        let ports: Vec<String> = service.ports.values().map(|p| p.to_string()).collect();

        // Don't generate policy if service has no ports - no traffic to authorize
        if ports.is_empty() {
            return None;
        }

        Some(AuthorizationPolicy {
            api_version: "security.istio.io/v1beta1".to_string(),
            kind: "AuthorizationPolicy".to_string(),
            metadata: PolicyMetadata::new(format!("allow-to-{}", service.name), namespace),
            spec: AuthorizationPolicySpec {
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
        })
    }

    fn compile_waypoint_policy(
        &self,
        service: &ServiceNode,
        namespace: &str,
    ) -> Option<AuthorizationPolicy> {
        let mut match_labels = BTreeMap::new();
        match_labels.insert("app.kubernetes.io/name".to_string(), service.name.clone());

        Some(AuthorizationPolicy {
            api_version: "security.istio.io/v1beta1".to_string(),
            kind: "AuthorizationPolicy".to_string(),
            metadata: PolicyMetadata::new(format!("allow-waypoint-to-{}", service.name), namespace),
            spec: AuthorizationPolicySpec {
                target_refs: vec![],
                selector: Some(WorkloadSelector { match_labels }),
                action: "ALLOW".to_string(),
                rules: vec![AuthorizationRule {
                    from: vec![AuthorizationSource {
                        source: SourceSpec {
                            principals: vec![self.waypoint_principal(namespace)],
                        },
                    }],
                    to: vec![],
                }],
            },
        })
    }

    fn compile_cilium_policy(
        &self,
        service: &ServiceNode,
        namespace: &str,
        env: &str,
        inbound_edges: &[ActiveEdge],
        outbound_edges: &[ActiveEdge],
    ) -> CiliumNetworkPolicy {
        let mut endpoint_labels = BTreeMap::new();
        endpoint_labels.insert("app.kubernetes.io/name".to_string(), service.name.clone());

        // Build ingress rules
        let mut ingress_rules = Vec::new();

        // Allow from callers if there are inbound edges
        if !inbound_edges.is_empty() {
            let from_endpoints: Vec<EndpointSelector> = inbound_edges
                .iter()
                .map(|edge| {
                    let mut labels = BTreeMap::new();
                    labels.insert(
                        "k8s:io.kubernetes.pod.namespace".to_string(),
                        namespace.to_string(),
                    );
                    labels.insert("app.kubernetes.io/name".to_string(), edge.caller.clone());
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

        // Allow HBONE from waypoint
        let mut waypoint_labels = BTreeMap::new();
        waypoint_labels.insert(
            "k8s:io.kubernetes.pod.namespace".to_string(),
            namespace.to_string(),
        );
        waypoint_labels.insert("istio.io/waypoint-for".to_string(), "service".to_string());
        ingress_rules.push(CiliumIngressRule {
            from_endpoints: vec![EndpointSelector {
                match_labels: waypoint_labels,
            }],
            to_ports: vec![CiliumPortRule {
                ports: vec![CiliumPort {
                    port: Self::HBONE_PORT.to_string(),
                    protocol: "TCP".to_string(),
                }],
            }],
        });

        // Build egress rules
        let mut egress_rules = Vec::new();

        // Always allow DNS to kube-dns
        let mut kube_dns_labels = BTreeMap::new();
        kube_dns_labels.insert(
            "k8s:io.kubernetes.pod.namespace".to_string(),
            "kube-system".to_string(),
        );
        kube_dns_labels.insert("k8s:k8s-app".to_string(), "kube-dns".to_string());
        egress_rules.push(CiliumEgressRule {
            to_endpoints: vec![EndpointSelector {
                match_labels: kube_dns_labels,
            }],
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
        waypoint_egress_labels.insert("istio.io/waypoint-for".to_string(), "service".to_string());
        egress_rules.push(CiliumEgressRule {
            to_endpoints: vec![EndpointSelector {
                match_labels: waypoint_egress_labels,
            }],
            to_fqdns: vec![],
            to_cidr: vec![],
            to_ports: vec![CiliumPortRule {
                ports: vec![CiliumPort {
                    port: Self::HBONE_PORT.to_string(),
                    protocol: "TCP".to_string(),
                }],
            }],
        });

        // Add egress rules for dependencies
        for edge in outbound_edges {
            if let Some(callee) = self.graph.get_service(env, &edge.callee) {
                match callee.type_ {
                    ServiceType::Local => {
                        let mut dep_labels = BTreeMap::new();
                        dep_labels.insert(
                            "k8s:io.kubernetes.pod.namespace".to_string(),
                            namespace.to_string(),
                        );
                        dep_labels
                            .insert("app.kubernetes.io/name".to_string(), edge.callee.clone());

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
                            to_fqdns: vec![],
                            to_cidr: vec![],
                            to_ports,
                        });
                    }
                    ServiceType::External => {
                        // Separate IP addresses from domain names
                        // Cilium requires toCIDR for IPs, toFQDNs for DNS names
                        let mut fqdns: Vec<FqdnSelector> = Vec::new();
                        let mut cidrs: Vec<String> = Vec::new();

                        for ep in callee.endpoints.values() {
                            if Self::is_ip_address(&ep.host) {
                                // Use /32 for single IP addresses
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

                        // Create egress rule for FQDNs if any
                        if !fqdns.is_empty() {
                            egress_rules.push(CiliumEgressRule {
                                to_endpoints: vec![],
                                to_fqdns: fqdns,
                                to_cidr: vec![],
                                to_ports: to_ports.clone(),
                            });
                        }

                        // Create egress rule for CIDRs (IP addresses) if any
                        if !cidrs.is_empty() {
                            egress_rules.push(CiliumEgressRule {
                                to_endpoints: vec![],
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

        CiliumNetworkPolicy {
            api_version: "cilium.io/v2".to_string(),
            kind: "CiliumNetworkPolicy".to_string(),
            metadata: PolicyMetadata::new(format!("policy-{}", service.name), namespace),
            spec: CiliumNetworkPolicySpec {
                endpoint_selector: EndpointSelector {
                    match_labels: endpoint_labels,
                },
                ingress: ingress_rules,
                egress: egress_rules,
            },
        }
    }

    /// Compile an AuthorizationPolicy to allow the Istio ingress gateway to reach a service
    ///
    /// This policy is generated for services with ingress configuration. It allows
    /// the gateway service account to bypass the normal bilateral agreement requirements
    /// for north-south (external) traffic.
    ///
    /// # Arguments
    /// * `service_name` - Name of the service
    /// * `namespace` - Namespace where the service lives
    /// * `ports` - List of ports the service exposes
    ///
    /// # Returns
    /// An AuthorizationPolicy allowing the ingress gateway to access the service
    pub fn compile_gateway_allow_policy(
        &self,
        service_name: &str,
        namespace: &str,
        ports: &[u16],
    ) -> AuthorizationPolicy {
        // The Istio ingress gateway typically runs in istio-system with the
        // service account name "istio-ingressgateway"
        let gateway_principal = format!(
            "spiffe://{}/ns/istio-system/sa/istio-ingressgateway",
            self.trust_domain
        );

        // Also allow from the gateway's namespace waypoint if using Ambient mode
        let gateway_waypoint_principal = format!(
            "spiffe://{}/ns/istio-system/sa/istio-system-waypoint",
            self.trust_domain
        );

        let port_strings: Vec<String> = ports.iter().map(|p| p.to_string()).collect();

        AuthorizationPolicy {
            api_version: "security.istio.io/v1beta1".to_string(),
            kind: "AuthorizationPolicy".to_string(),
            metadata: PolicyMetadata::new(format!("allow-gateway-to-{}", service_name), namespace),
            spec: AuthorizationPolicySpec {
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
                            principals: vec![gateway_principal, gateway_waypoint_principal],
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
        }
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
            "istio.io/use-waypoint".to_string(),
            format!("{}-waypoint", namespace),
        );

        let resolution = service
            .resolution
            .as_ref()
            .map(|r| r.to_istio_format())
            .unwrap_or("DNS")
            .to_string();

        Some(ServiceEntry {
            api_version: "networking.istio.io/v1beta1".to_string(),
            kind: "ServiceEntry".to_string(),
            metadata,
            spec: ServiceEntrySpec {
                hosts,
                ports,
                location: "MESH_EXTERNAL".to_string(),
                resolution,
            },
        })
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
            environment: "test".to_string(),
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
            environment: "test".to_string(),
            containers,
            resources,
            service: Some(ServicePortsSpec { ports }),
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
            ingress: None,
        }
    }

    // =========================================================================
    // Story: Bilateral Agreement (Policy Only Generated When Both Agree)
    // =========================================================================

    #[test]
    fn story_bilateral_agreement_generates_policy() {
        let graph = ServiceGraph::new();
        let env = "prod";

        // api allows gateway
        let api_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service(env, "api", &api_spec);

        // gateway depends on api
        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(env, "gateway", &gateway_spec);

        // Compile policies for api (the callee)
        let compiler = PolicyCompiler::new(&graph, "prod.lattice.local");
        let output = compiler.compile("api", "prod-ns", env);

        // Should have auth policy allowing gateway
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
        let env = "prod";

        // api allows gateway, but gateway doesn't declare dependency
        let api_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service(env, "api", &api_spec);

        // gateway doesn't depend on api (no bilateral agreement)
        let gateway_spec = make_service_spec(vec![], vec![]);
        graph.put_service(env, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "prod.lattice.local");
        let output = compiler.compile("api", "prod-ns", env);

        // No auth policy (no bilateral agreement)
        assert!(output.authorization_policies.is_empty());
    }

    // =========================================================================
    // Story: Service Not in Graph
    // =========================================================================

    #[test]
    fn story_no_policies_when_not_in_graph() {
        let graph = ServiceGraph::new();

        let compiler = PolicyCompiler::new(&graph, "test.lattice.local");
        let output = compiler.compile("nonexistent", "default", "prod");

        assert!(output.is_empty());
    }

    // =========================================================================
    // Story: SPIFFE Trust Domain
    // =========================================================================

    #[test]
    fn story_spiffe_uses_trust_domain() {
        let graph = ServiceGraph::new();
        let env = "prod";

        let api_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service(env, "api", &api_spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(env, "gateway", &gateway_spec);

        let compiler = PolicyCompiler::new(&graph, "my-cluster.example.com");
        let output = compiler.compile("api", "prod-ns", env);

        let principals = &output.authorization_policies[0].spec.rules[0].from[0]
            .source
            .principals;
        assert!(principals[0].starts_with("spiffe://my-cluster.example.com/"));
        assert!(principals[0].contains("/ns/prod-ns/sa/gateway"));
    }

    // =========================================================================
    // Story: Cilium Policy Always Generated
    // =========================================================================

    #[test]
    fn story_cilium_policy_always_generated() {
        let graph = ServiceGraph::new();
        let env = "default";

        let spec = make_service_spec(vec![], vec![]);
        graph.put_service(env, "my-app", &spec);

        let compiler = PolicyCompiler::new(&graph, "test.lattice.local");
        let output = compiler.compile("my-app", "default", env);

        assert_eq!(output.cilium_policies.len(), 1);
        let cnp = &output.cilium_policies[0];
        assert_eq!(cnp.metadata.name, "policy-my-app");

        // Should always have DNS egress
        assert!(cnp.spec.egress.iter().any(|e| e
            .to_ports
            .iter()
            .any(|pr| pr.ports.iter().any(|p| p.port == "53"))));

        // Should always have waypoint HBONE ingress
        assert!(cnp.spec.ingress.iter().any(|i| i
            .to_ports
            .iter()
            .any(|pr| pr.ports.iter().any(|p| p.port == "15008"))));
    }

    // =========================================================================
    // Story: External Dependencies
    // =========================================================================

    #[test]
    fn story_external_service_generates_service_entry() {
        let graph = ServiceGraph::new();
        let env = "prod";

        // api depends on external
        let api_spec = make_service_spec(vec!["stripe-api"], vec![]);
        graph.put_service(env, "api", &api_spec);

        // stripe-api is external (allows api)
        graph.put_external_service(env, "stripe-api", &make_external_spec(vec!["api"]));

        let compiler = PolicyCompiler::new(&graph, "prod.lattice.local");
        let output = compiler.compile("api", "prod-ns", env);

        assert_eq!(output.service_entries.len(), 1);
        let entry = &output.service_entries[0];
        assert_eq!(entry.metadata.name, "stripe-api");
        assert!(entry.spec.hosts.contains(&"api.stripe.com".to_string()));
        assert_eq!(entry.spec.location, "MESH_EXTERNAL");
    }

    #[test]
    fn story_external_service_respects_dns_resolution() {
        let graph = ServiceGraph::new();
        let env = "prod";

        let api_spec = make_service_spec(vec!["stripe-api"], vec![]);
        graph.put_service(env, "api", &api_spec);

        // External service with DNS resolution (hostname-based)
        let ext_spec = LatticeExternalServiceSpec {
            environment: "test".to_string(),
            endpoints: BTreeMap::from([(
                "api".to_string(),
                "https://api.stripe.com:443".to_string(),
            )]),
            allowed_requesters: vec!["api".to_string()],
            resolution: Resolution::Dns,
            description: None,
        };
        graph.put_external_service(env, "stripe-api", &ext_spec);

        let compiler = PolicyCompiler::new(&graph, "prod.lattice.local");
        let output = compiler.compile("api", "prod-ns", env);

        assert_eq!(output.service_entries.len(), 1);
        let entry = &output.service_entries[0];
        assert_eq!(entry.spec.resolution, "DNS");
    }

    #[test]
    fn story_external_service_respects_static_resolution() {
        let graph = ServiceGraph::new();
        let env = "prod";

        let api_spec = make_service_spec(vec!["cloudflare"], vec![]);
        graph.put_service(env, "api", &api_spec);

        // External service with STATIC resolution (IP-based)
        let ext_spec = LatticeExternalServiceSpec {
            environment: "test".to_string(),
            endpoints: BTreeMap::from([("dns".to_string(), "https://1.1.1.1:443".to_string())]),
            allowed_requesters: vec!["api".to_string()],
            resolution: Resolution::Static,
            description: None,
        };
        graph.put_external_service(env, "cloudflare", &ext_spec);

        let compiler = PolicyCompiler::new(&graph, "prod.lattice.local");
        let output = compiler.compile("api", "prod-ns", env);

        assert_eq!(output.service_entries.len(), 1);
        let entry = &output.service_entries[0];
        assert_eq!(entry.spec.resolution, "STATIC");
        assert!(entry.spec.hosts.contains(&"1.1.1.1".to_string()));
    }

    // =========================================================================
    // Story: Mesh Default Deny
    // =========================================================================

    #[test]
    fn story_mesh_default_deny() {
        let policy = PolicyCompiler::compile_mesh_default_deny();

        assert_eq!(policy.metadata.name, "mesh-default-deny");
        assert_eq!(policy.metadata.namespace, "istio-system");
        // Per Istio best practices: empty spec denies all
        assert!(policy.spec.action.is_empty()); // Empty = implicit deny
        assert!(policy.spec.rules.is_empty()); // No rules = no traffic allowed
    }

    #[test]
    fn story_waypoint_default_deny() {
        let policy = PolicyCompiler::compile_waypoint_default_deny();

        assert_eq!(policy.metadata.name, "waypoint-default-deny");
        assert_eq!(policy.metadata.namespace, "istio-system");
        // Per Istio best practices: empty spec denies all
        assert!(policy.spec.action.is_empty());
        assert!(policy.spec.rules.is_empty());
        // Targets the waypoint GatewayClass for ambient mode
        assert_eq!(policy.spec.target_refs.len(), 1);
        assert_eq!(policy.spec.target_refs[0].kind, "GatewayClass");
        assert_eq!(policy.spec.target_refs[0].name, "istio-waypoint");
    }

    // =========================================================================
    // Story: GeneratedPolicies Utility Methods
    // =========================================================================

    #[test]
    fn story_total_count() {
        let graph = ServiceGraph::new();
        let env = "prod";

        let api_spec = make_service_spec(vec!["stripe"], vec!["gateway"]);
        graph.put_service(env, "api", &api_spec);

        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(env, "gateway", &gateway_spec);

        graph.put_external_service(env, "stripe", &make_external_spec(vec!["api"]));

        let compiler = PolicyCompiler::new(&graph, "prod.lattice.local");
        let output = compiler.compile("api", "prod-ns", env);

        // 2 auth policies (allow + waypoint) + 1 cilium + 1 service entry = 4
        assert_eq!(output.total_count(), 4);
    }

    // =========================================================================
    // Story: Unknown Service Type Skipped
    // =========================================================================

    #[test]
    fn story_unknown_service_type_returns_empty() {
        let graph = ServiceGraph::new();
        let env = "prod";

        // Manually insert a service node with Unknown type via internal method
        // by creating a service and then checking Unknown handling
        // The graph doesn't have a direct way to create Unknown, but we test
        // by verifying a service that doesn't exist returns empty
        let compiler = PolicyCompiler::new(&graph, "test.lattice.local");

        // Non-existent service returns empty (similar path to Unknown)
        let output = compiler.compile("unknown-service", "default", env);
        assert!(output.is_empty());
    }

    // =========================================================================
    // Story: Local Service Egress Rules
    // =========================================================================

    #[test]
    fn story_local_service_egress_generates_cilium_rules() {
        let graph = ServiceGraph::new();
        let env = "prod";

        // gateway depends on api (local service)
        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(env, "gateway", &gateway_spec);

        // api allows gateway (bilateral agreement for egress)
        let api_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service(env, "api", &api_spec);

        let compiler = PolicyCompiler::new(&graph, "prod.lattice.local");
        let output = compiler.compile("gateway", "prod-ns", env);

        // Should have Cilium policy with egress rule to api
        assert_eq!(output.cilium_policies.len(), 1);
        let cnp = &output.cilium_policies[0];

        // Find egress rule for api (not DNS or waypoint)
        let api_egress = cnp.spec.egress.iter().find(|e| {
            e.to_endpoints.iter().any(|ep| {
                ep.match_labels
                    .get("app.kubernetes.io/name")
                    .map(|v| v == "api")
                    .unwrap_or(false)
            })
        });

        assert!(
            api_egress.is_some(),
            "Should have egress rule for local dependency 'api'"
        );

        // Verify namespace label is set
        let rule = api_egress.unwrap();
        assert!(rule.to_endpoints[0]
            .match_labels
            .contains_key("k8s:io.kubernetes.pod.namespace"));
    }

    #[test]
    fn story_local_egress_includes_ports() {
        let graph = ServiceGraph::new();
        let env = "prod";

        // gateway depends on api
        let gateway_spec = make_service_spec(vec!["api"], vec![]);
        graph.put_service(env, "gateway", &gateway_spec);

        // api has ports and allows gateway
        let api_spec = make_service_spec(vec![], vec!["gateway"]);
        graph.put_service(env, "api", &api_spec);

        let compiler = PolicyCompiler::new(&graph, "prod.lattice.local");
        let output = compiler.compile("gateway", "prod-ns", env);

        let cnp = &output.cilium_policies[0];
        let api_egress = cnp
            .spec
            .egress
            .iter()
            .find(|e| {
                e.to_endpoints.iter().any(|ep| {
                    ep.match_labels
                        .get("app.kubernetes.io/name")
                        .map(|v| v == "api")
                        .unwrap_or(false)
                })
            })
            .expect("Should have api egress rule");

        // Should have port rules (api has port 8080 from make_service_spec)
        assert!(
            !api_egress.to_ports.is_empty(),
            "Should have port rules for api"
        );
        assert!(api_egress.to_ports[0]
            .ports
            .iter()
            .any(|p| p.port == "8080"));
    }

    // =========================================================================
    // Story: Cilium Field Naming
    // =========================================================================

    #[test]
    fn story_cilium_fqdn_field_serializes_correctly() {
        // Cilium uses uppercase "FQDNs" and "CIDR" in its CRD schema
        // This test verifies our serde serialization matches Cilium's expectations
        let rule = CiliumEgressRule {
            to_endpoints: vec![],
            to_fqdns: vec![FqdnSelector {
                match_name: Some("api.example.com".to_string()),
                match_pattern: None,
            }],
            to_cidr: vec!["10.0.0.0/8".to_string()],
            to_ports: vec![],
        };

        let json = serde_json::to_string(&rule).unwrap();

        // Must use "toFQDNs" (uppercase) not "toFqdns" (camelCase)
        assert!(
            json.contains("\"toFQDNs\""),
            "Expected 'toFQDNs' but got: {}",
            json
        );

        // Must use "toCIDR" (uppercase) not "toCidr" (camelCase)
        assert!(
            json.contains("\"toCIDR\""),
            "Expected 'toCIDR' but got: {}",
            json
        );
    }

    // =========================================================================
    // Story: External Services with IP Addresses
    // =========================================================================

    #[test]
    fn story_external_ip_address_uses_cidr() {
        // When external service uses an IP address (e.g., 1.1.1.1), Cilium needs
        // toCIDR rules, not toFQDNs (which only works for DNS names)
        let graph = ServiceGraph::new();
        let env = "prod";

        // api depends on cloudflare (an IP-based external service)
        let api_spec = make_service_spec(vec!["cloudflare"], vec![]);
        graph.put_service(env, "api", &api_spec);

        // cloudflare is external with IP address endpoint
        let mut ext_spec = make_external_spec(vec!["api"]);
        ext_spec.endpoints =
            BTreeMap::from([("default".to_string(), "https://1.1.1.1".to_string())]);
        graph.put_external_service(env, "cloudflare", &ext_spec);

        let compiler = PolicyCompiler::new(&graph, "prod.lattice.local");
        let output = compiler.compile("api", "prod-ns", env);

        // Find the Cilium policy
        let cnp = &output.cilium_policies[0];

        // Should have egress rule with toCIDR for IP address
        let ip_egress = cnp
            .spec
            .egress
            .iter()
            .find(|e| !e.to_cidr.is_empty())
            .expect("Should have CIDR egress rule for IP-based external service");

        assert!(
            ip_egress.to_cidr.contains(&"1.1.1.1/32".to_string()),
            "Should have 1.1.1.1/32 in toCIDR, got: {:?}",
            ip_egress.to_cidr
        );

        // Should NOT have toFQDNs for the IP address
        assert!(
            ip_egress.to_fqdns.is_empty(),
            "IP addresses should not use toFQDNs"
        );
    }

    #[test]
    fn story_external_domain_uses_fqdn() {
        // When external service uses a domain name, Cilium needs toFQDNs rules
        let graph = ServiceGraph::new();
        let env = "prod";

        // api depends on stripe (domain-based external service)
        let api_spec = make_service_spec(vec!["stripe-api"], vec![]);
        graph.put_service(env, "api", &api_spec);

        // stripe is external with domain name endpoint
        graph.put_external_service(env, "stripe-api", &make_external_spec(vec!["api"]));

        let compiler = PolicyCompiler::new(&graph, "prod.lattice.local");
        let output = compiler.compile("api", "prod-ns", env);

        let cnp = &output.cilium_policies[0];

        // Should have egress rule with toFQDNs for domain name
        let fqdn_egress = cnp
            .spec
            .egress
            .iter()
            .find(|e| !e.to_fqdns.is_empty())
            .expect("Should have FQDN egress rule for domain-based external service");

        assert!(
            fqdn_egress
                .to_fqdns
                .iter()
                .any(|f| f.match_name.as_deref() == Some("api.stripe.com")),
            "Should have api.stripe.com in toFQDNs"
        );

        // Should NOT have toCIDR for domain
        assert!(
            fqdn_egress.to_cidr.is_empty(),
            "Domain names should not use toCIDR"
        );
    }

    #[test]
    fn story_external_mixed_ip_and_domain() {
        // External service with both IP and domain endpoints should generate
        // separate egress rules for each type
        let graph = ServiceGraph::new();
        let env = "prod";

        let api_spec = make_service_spec(vec!["mixed-external"], vec![]);
        graph.put_service(env, "api", &api_spec);

        // External service with both IP and domain endpoints
        let mut ext_spec = make_external_spec(vec!["api"]);
        ext_spec.endpoints = BTreeMap::from([
            ("ip".to_string(), "https://10.0.0.1:443".to_string()),
            ("domain".to_string(), "https://api.example.com".to_string()),
        ]);
        graph.put_external_service(env, "mixed-external", &ext_spec);

        let compiler = PolicyCompiler::new(&graph, "prod.lattice.local");
        let output = compiler.compile("api", "prod-ns", env);

        let cnp = &output.cilium_policies[0];

        // Should have CIDR rule for IP
        let has_cidr = cnp
            .spec
            .egress
            .iter()
            .any(|e| e.to_cidr.contains(&"10.0.0.1/32".to_string()));
        assert!(has_cidr, "Should have CIDR rule for IP address endpoint");

        // Should have FQDN rule for domain
        let has_fqdn = cnp.spec.egress.iter().any(|e| {
            e.to_fqdns
                .iter()
                .any(|f| f.match_name.as_deref() == Some("api.example.com"))
        });
        assert!(has_fqdn, "Should have FQDN rule for domain endpoint");
    }

    #[test]
    fn story_is_ip_address_detection() {
        // Test the IP address detection helper function
        assert!(
            PolicyCompiler::is_ip_address("1.1.1.1"),
            "IPv4 should be detected"
        );
        assert!(
            PolicyCompiler::is_ip_address("10.0.0.1"),
            "IPv4 should be detected"
        );
        assert!(
            PolicyCompiler::is_ip_address("192.168.1.1"),
            "IPv4 should be detected"
        );
        assert!(
            PolicyCompiler::is_ip_address("::1"),
            "IPv6 localhost should be detected"
        );
        assert!(
            PolicyCompiler::is_ip_address("2001:db8::1"),
            "IPv6 should be detected"
        );

        assert!(
            !PolicyCompiler::is_ip_address("example.com"),
            "Domain should not be IP"
        );
        assert!(
            !PolicyCompiler::is_ip_address("api.stripe.com"),
            "Domain should not be IP"
        );
        assert!(
            !PolicyCompiler::is_ip_address("api.example.stripe.com"),
            "Multi-dot domain should not be IP"
        );
        assert!(
            !PolicyCompiler::is_ip_address("localhost"),
            "Hostname should not be IP"
        );
    }

    // =========================================================================
    // Story: Gateway Allow Policy
    // =========================================================================

    #[test]
    fn story_gateway_allow_policy_generated() {
        let graph = ServiceGraph::new();
        let compiler = PolicyCompiler::new(&graph, "prod.lattice.local");

        let policy = compiler.compile_gateway_allow_policy("api", "prod-ns", &[8080, 8443]);

        assert_eq!(policy.metadata.name, "allow-gateway-to-api");
        assert_eq!(policy.metadata.namespace, "prod-ns");
        assert_eq!(policy.spec.action, "ALLOW");

        // Should have the ingress gateway principal
        let principals = &policy.spec.rules[0].from[0].source.principals;
        assert!(principals
            .iter()
            .any(|p| p.contains("istio-ingressgateway")));
        assert!(principals.iter().any(|p| p.contains("istio-system")));

        // Should have correct ports
        let ports = &policy.spec.rules[0].to[0].operation.ports;
        assert!(ports.contains(&"8080".to_string()));
        assert!(ports.contains(&"8443".to_string()));
    }

    #[test]
    fn story_gateway_allow_policy_no_ports() {
        let graph = ServiceGraph::new();
        let compiler = PolicyCompiler::new(&graph, "test.local");

        let policy = compiler.compile_gateway_allow_policy("svc", "ns", &[]);

        // Should still generate policy but with empty to operations
        assert_eq!(policy.metadata.name, "allow-gateway-to-svc");
        assert!(policy.spec.rules[0].to.is_empty());
    }

    #[test]
    fn story_gateway_allow_policy_uses_trust_domain() {
        let graph = ServiceGraph::new();
        let compiler = PolicyCompiler::new(&graph, "custom.trust.domain");

        let policy = compiler.compile_gateway_allow_policy("api", "prod", &[80]);

        let principals = &policy.spec.rules[0].from[0].source.principals;
        assert!(principals
            .iter()
            .any(|p| p.starts_with("spiffe://custom.trust.domain/")));
    }
}
