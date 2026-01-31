//! Cilium CiliumNetworkPolicy types
//!
//! Types for generating CiliumNetworkPolicy resources for L4 eBPF-based
//! network enforcement at the kernel level.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::PolicyMetadata;
use crate::kube_utils::HasApiResource;

/// Cilium Network Policy for L4 eBPF-based network enforcement
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CiliumNetworkPolicy {
    /// API version
    #[serde(default = "CiliumNetworkPolicy::api_version")]
    pub api_version: String,
    /// Kind
    #[serde(default = "CiliumNetworkPolicy::kind")]
    pub kind: String,
    /// Metadata
    pub metadata: PolicyMetadata,
    /// Spec
    pub spec: CiliumNetworkPolicySpec,
}

impl HasApiResource for CiliumNetworkPolicy {
    const API_VERSION: &'static str = "cilium.io/v2";
    const KIND: &'static str = "CiliumNetworkPolicy";
}

impl CiliumNetworkPolicy {
    fn api_version() -> String {
        <Self as HasApiResource>::API_VERSION.to_string()
    }
    fn kind() -> String {
        <Self as HasApiResource>::KIND.to_string()
    }

    /// Create a new CiliumNetworkPolicy
    pub fn new(metadata: PolicyMetadata, spec: CiliumNetworkPolicySpec) -> Self {
        Self {
            api_version: Self::api_version(),
            kind: Self::kind(),
            metadata,
            spec,
        }
    }
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
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
    /// To entities (special Cilium entities like kube-apiserver, world, host)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_entities: Vec<String>,
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

/// Cilium Clusterwide Network Policy for cluster-scoped L4 enforcement
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CiliumClusterwideNetworkPolicy {
    /// API version
    #[serde(default = "CiliumClusterwideNetworkPolicy::api_version")]
    pub api_version: String,
    /// Kind
    #[serde(default = "CiliumClusterwideNetworkPolicy::kind")]
    pub kind: String,
    /// Metadata
    pub metadata: ClusterwideMetadata,
    /// Spec
    pub spec: CiliumClusterwideSpec,
}

impl HasApiResource for CiliumClusterwideNetworkPolicy {
    const API_VERSION: &'static str = "cilium.io/v2";
    const KIND: &'static str = "CiliumClusterwideNetworkPolicy";
}

impl CiliumClusterwideNetworkPolicy {
    fn api_version() -> String {
        <Self as HasApiResource>::API_VERSION.to_string()
    }
    fn kind() -> String {
        <Self as HasApiResource>::KIND.to_string()
    }

    /// Create a new CiliumClusterwideNetworkPolicy
    pub fn new(metadata: ClusterwideMetadata, spec: CiliumClusterwideSpec) -> Self {
        Self {
            api_version: Self::api_version(),
            kind: Self::kind(),
            metadata,
            spec,
        }
    }
}

/// Metadata for clusterwide resources (no namespace)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ClusterwideMetadata {
    /// Resource name
    pub name: String,
    /// Labels
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

impl ClusterwideMetadata {
    /// Create new metadata with standard Lattice labels
    pub fn new(name: impl Into<String>) -> Self {
        let mut labels = BTreeMap::new();
        labels.insert(
            crate::LABEL_MANAGED_BY.to_string(),
            crate::LABEL_MANAGED_BY_LATTICE.to_string(),
        );
        Self {
            name: name.into(),
            labels,
        }
    }
}

/// CiliumClusterwideNetworkPolicy spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CiliumClusterwideSpec {
    /// Description of the policy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Enable default deny behavior
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_default_deny: Option<EnableDefaultDeny>,
    /// Endpoint selector
    pub endpoint_selector: ClusterwideEndpointSelector,
    /// Ingress rules
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<ClusterwideIngressRule>,
    /// Egress rules
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<ClusterwideEgressRule>,
}

/// Enable default deny configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EnableDefaultDeny {
    /// Enable default deny for egress
    #[serde(default)]
    pub egress: bool,
    /// Enable default deny for ingress
    #[serde(default)]
    pub ingress: bool,
}

/// Endpoint selector with match expressions support
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClusterwideEndpointSelector {
    /// Match labels
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub match_labels: BTreeMap<String, String>,
    /// Match expressions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_expressions: Vec<MatchExpression>,
}

/// Label selector requirement
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MatchExpression {
    /// Label key
    pub key: String,
    /// Operator: In, NotIn, Exists, DoesNotExist
    pub operator: String,
    /// Values for In/NotIn operators
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
}

/// Clusterwide ingress rule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClusterwideIngressRule {
    /// From CIDRs
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "fromCIDR")]
    pub from_cidr: Vec<String>,
    /// From endpoints
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from_endpoints: Vec<EndpointSelector>,
    /// To ports
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_ports: Vec<CiliumPortRule>,
}

/// Clusterwide egress rule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClusterwideEgressRule {
    /// To endpoints
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_endpoints: Vec<EndpointSelector>,
    /// To entities
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_entities: Vec<String>,
    /// To CIDRs
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "toCIDR")]
    pub to_cidr: Vec<String>,
    /// To ports with optional DNS rules
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_ports: Vec<ClusterwidePortRule>,
}

/// Port rule with optional DNS rules
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ClusterwidePortRule {
    /// Ports
    pub ports: Vec<CiliumPort>,
    /// DNS rules
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<DnsRules>,
}

/// DNS rules for egress
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DnsRules {
    /// DNS match patterns
    pub dns: Vec<DnsMatch>,
}

/// DNS match pattern
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DnsMatch {
    /// Match pattern (e.g., "*" or "*.example.com")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_pattern: Option<String>,
}
