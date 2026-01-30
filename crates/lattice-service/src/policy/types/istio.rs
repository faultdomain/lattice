//! Istio AuthorizationPolicy types
//!
//! Types for generating Istio AuthorizationPolicy resources used in
//! ambient mode L7 mTLS identity-based access control.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
