//! Istio policy types
//!
//! Types for generating Istio policy resources:
//! - AuthorizationPolicy: mTLS identity-based access control
//! - PeerAuthentication: mTLS mode configuration
//!
//! ## AuthorizationPolicy constructors
//!
//! - `allow_to_workload()`: Ztunnel-enforced via pod selector. Default for services
//!   without L7 needs. Works with or without a waypoint.
//! - `allow_to_service()`: Waypoint-enforced via Service targetRefs. Use only when
//!   L7 enforcement is needed (external deps, rate limiting, header matching).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::kube_utils::{HasApiResource, ObjectMeta};

/// Istio AuthorizationPolicy for L7 mTLS identity-based access control
///
/// This policy is applied to Services via targetRefs (Istio Ambient mode)
/// and enforced at the waypoint proxy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationPolicy {
    /// API version
    #[serde(default = "AuthorizationPolicy::api_version")]
    pub api_version: String,
    /// Kind
    #[serde(default = "AuthorizationPolicy::kind")]
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: AuthorizationPolicySpec,
}

impl HasApiResource for AuthorizationPolicy {
    const API_VERSION: &'static str = "security.istio.io/v1";
    const KIND: &'static str = "AuthorizationPolicy";
}

impl AuthorizationPolicy {
    fn api_version() -> String {
        <Self as HasApiResource>::API_VERSION.to_string()
    }
    fn kind() -> String {
        <Self as HasApiResource>::KIND.to_string()
    }

    /// Create a new AuthorizationPolicy
    pub fn new(metadata: ObjectMeta, spec: AuthorizationPolicySpec) -> Self {
        Self {
            api_version: Self::api_version(),
            kind: Self::kind(),
            metadata,
            spec,
        }
    }

    /// Ztunnel-enforced ALLOW policy targeting pods via label selector.
    ///
    /// Works in any ambient namespace, with or without a waypoint. Ztunnel sees
    /// the original caller identity and enforces directly. Use this for services
    /// that don't need L7 enforcement (no waypoint in the traffic path).
    pub fn allow_to_workload(
        name: impl Into<String>,
        namespace: impl Into<String>,
        match_labels: BTreeMap<String, String>,
        principals: Vec<String>,
        ports: Vec<String>,
    ) -> Self {
        Self::new(
            ObjectMeta::new(name, namespace),
            AuthorizationPolicySpec {
                target_refs: vec![],
                selector: Some(WorkloadSelector { match_labels }),
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
        )
    }

    /// Waypoint-enforced ALLOW policy targeting a K8s Service via targetRefs.
    ///
    /// The waypoint proxy evaluates this policy. Use this only for services that
    /// need L7 enforcement (external dependencies, rate limiting, header matching).
    pub fn allow_to_service(
        name: impl Into<String>,
        namespace: impl Into<String>,
        service_name: impl Into<String>,
        principals: Vec<String>,
        ports: Vec<String>,
    ) -> Self {
        Self::new(
            ObjectMeta::new(name, namespace),
            AuthorizationPolicySpec {
                target_refs: vec![TargetRef {
                    group: String::new(),
                    kind: "Service".to_string(),
                    name: service_name.into(),
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
        )
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
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
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

/// Istio PeerAuthentication for mTLS configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PeerAuthentication {
    /// API version
    #[serde(default = "PeerAuthentication::api_version")]
    pub api_version: String,
    /// Kind
    #[serde(default = "PeerAuthentication::kind")]
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: PeerAuthenticationSpec,
}

impl HasApiResource for PeerAuthentication {
    const API_VERSION: &'static str = "security.istio.io/v1";
    const KIND: &'static str = "PeerAuthentication";
}

impl PeerAuthentication {
    fn api_version() -> String {
        <Self as HasApiResource>::API_VERSION.to_string()
    }
    fn kind() -> String {
        <Self as HasApiResource>::KIND.to_string()
    }

    /// Create a new PeerAuthentication
    pub fn new(metadata: ObjectMeta, spec: PeerAuthenticationSpec) -> Self {
        Self {
            api_version: Self::api_version(),
            kind: Self::kind(),
            metadata,
            spec,
        }
    }
}

/// PeerAuthentication spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PeerAuthenticationSpec {
    /// mTLS configuration
    pub mtls: MtlsConfig,
}

/// mTLS configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MtlsConfig {
    /// mTLS mode: STRICT, PERMISSIVE, DISABLE
    pub mode: String,
}
