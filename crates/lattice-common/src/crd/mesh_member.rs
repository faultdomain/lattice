//! LatticeMeshMember CRD — policy-only mesh enrollment
//!
//! Allows pre-existing workloads (monitoring, webhooks, stateful operators) to
//! participate in the bilateral agreement mesh without Lattice managing their
//! Deployment or Service resources.

use std::collections::BTreeMap;

use aws_lc_rs::digest;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::ServiceRef;
use super::workload::ingress::IngressSpec;

// =============================================================================
// CRD
// =============================================================================

/// Spec for a LatticeMeshMember — enrolls existing workloads in the mesh
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeMeshMember",
    plural = "latticemeshmembers",
    shortname = "lmm",
    namespaced,
    status = "LatticeMeshMemberStatus",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Scope","type":"string","jsonPath":".status.scope"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeMeshMemberSpec {
    /// Which workloads to target
    pub target: MeshMemberTarget,

    /// Ports this member exposes
    pub ports: Vec<MeshMemberPort>,

    /// Services allowed to call this member (bilateral agreement inbound side)
    #[serde(default)]
    pub allowed_callers: Vec<CallerRef>,

    /// Services this member depends on (bilateral agreement outbound side)
    #[serde(default)]
    pub dependencies: Vec<ServiceRef>,

    /// Non-mesh egress rules (entity, CIDR, FQDN targets)
    #[serde(default)]
    pub egress: Vec<EgressRule>,

    /// Allow traffic between pods matching this member's own selector
    #[serde(default)]
    pub allow_peer_traffic: bool,

    /// Ingress configuration for exposing this member externally
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<IngressSpec>,
}

/// Target workloads for a mesh member
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum MeshMemberTarget {
    /// Match pods by label selector
    Selector(BTreeMap<String, String>),
    /// Match all pods in a namespace
    Namespace(String),
}

/// A port exposed by a mesh member
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MeshMemberPort {
    /// Port number
    pub port: u16,
    /// Port name (must be a valid DNS label)
    pub name: String,
    /// mTLS enforcement mode for this port
    #[serde(default)]
    pub peer_auth: PeerAuth,
}

/// mTLS enforcement mode per-port
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum PeerAuth {
    /// Require mTLS (default)
    #[default]
    Strict,
    /// Allow plaintext from any source
    Permissive,
    /// Allow plaintext from kube-apiserver only (admission webhooks)
    Webhook,
}

/// A service allowed to call this mesh member
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Hash)]
pub struct CallerRef {
    /// Service name (or "*" for wildcard)
    pub name: String,
    /// Namespace (defaults to same namespace if omitted)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

impl CallerRef {
    /// Resolve namespace using a default
    pub fn resolve_namespace<'a>(&'a self, default_namespace: &'a str) -> &'a str {
        self.namespace.as_deref().unwrap_or(default_namespace)
    }
}

/// Non-mesh egress rule
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EgressRule {
    /// Egress target
    pub target: EgressTarget,
    /// Allowed ports
    #[serde(default)]
    pub ports: Vec<u16>,
}

/// Target for egress rules
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum EgressTarget {
    /// Cilium entity (e.g., "world", "kube-apiserver")
    Entity(String),
    /// CIDR range
    Cidr(String),
    /// DNS name
    Fqdn(String),
}

// =============================================================================
// Status
// =============================================================================

/// Status of a LatticeMeshMember
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeMeshMemberStatus {
    /// Current phase
    #[serde(default)]
    pub phase: MeshMemberPhase,
    /// Workload or Namespace scope
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<MeshMemberScope>,
    /// Human-readable message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Last observed generation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// Status conditions
    #[serde(default)]
    pub conditions: Vec<super::types::Condition>,
}

/// Phase of a mesh member
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum MeshMemberPhase {
    /// Waiting for reconciliation
    #[default]
    Pending,
    /// Policies applied successfully
    Ready,
    /// Policy generation or application failed
    Failed,
}

/// Scope of a mesh member
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum MeshMemberScope {
    /// Targets specific workloads by label selector
    Workload,
    /// Targets all pods in a namespace
    Namespace,
}

// =============================================================================
// Helpers
// =============================================================================

impl LatticeMeshMemberSpec {
    /// Validate the spec
    pub fn validate(&self) -> Result<(), String> {
        // A mesh member must either expose ports (server) or have dependencies (client)
        if self.ports.is_empty() && self.dependencies.is_empty() {
            return Err("at least one port or dependency is required".to_string());
        }

        for port in &self.ports {
            super::validate_dns_label(&port.name, "port name")?;
        }

        if let MeshMemberTarget::Namespace(ref ns) = self.target {
            if ns.is_empty() {
                return Err("namespace target cannot be empty".to_string());
            }
        }

        if let MeshMemberTarget::Selector(ref labels) = self.target {
            if labels.is_empty() {
                return Err("selector must have at least one label".to_string());
            }
            for key in labels.keys() {
                if key.is_empty() {
                    return Err("selector label key cannot be empty".to_string());
                }
            }
        }

        Ok(())
    }

    /// Return target labels (empty map for namespace-scoped)
    pub fn target_labels(&self) -> BTreeMap<String, String> {
        match &self.target {
            MeshMemberTarget::Selector(labels) => labels.clone(),
            MeshMemberTarget::Namespace(_) => BTreeMap::new(),
        }
    }

    /// Return effective target namespace
    pub fn target_namespace<'a>(&'a self, owner_ns: &'a str) -> &'a str {
        match &self.target {
            MeshMemberTarget::Namespace(ns) => ns.as_str(),
            MeshMemberTarget::Selector(_) => owner_ns,
        }
    }
}

/// Generate a deterministic, K8s-safe name from a prefix and input parts.
///
/// Uses FIPS-compliant SHA-256 via `aws_lc_rs` and takes the first 8 hex chars.
/// Result: `{prefix}{hash8}` (max 63 chars with short prefixes).
pub fn derived_name(prefix: &str, parts: &[&str]) -> String {
    let input = parts.join("/");
    let hash = digest::digest(&digest::SHA256, input.as_bytes());
    let hex: String = hash.as_ref()[..4]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    format!("{}{}", prefix, hex)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_spec() -> LatticeMeshMemberSpec {
        LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                "app".to_string(),
                "prometheus".to_string(),
            )])),
            ports: vec![MeshMemberPort {
                port: 9090,
                name: "metrics".to_string(),
                peer_auth: PeerAuth::Strict,
            }],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![],
            allow_peer_traffic: false,
            ingress: None,
        }
    }

    #[test]
    fn validate_valid_spec() {
        assert!(valid_spec().validate().is_ok());
    }

    #[test]
    fn validate_empty_ports_and_deps_fails() {
        let mut spec = valid_spec();
        spec.ports.clear();
        spec.dependencies.clear();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn validate_client_only_valid() {
        let mut spec = valid_spec();
        spec.ports.clear();
        spec.dependencies.push(ServiceRef::local("some-service"));
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_invalid_port_name_fails() {
        let mut spec = valid_spec();
        spec.ports[0].name = "INVALID".to_string();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn validate_empty_selector_fails() {
        let mut spec = valid_spec();
        spec.target = MeshMemberTarget::Selector(BTreeMap::new());
        assert!(spec.validate().is_err());
    }

    #[test]
    fn validate_empty_namespace_target_fails() {
        let mut spec = valid_spec();
        spec.target = MeshMemberTarget::Namespace(String::new());
        assert!(spec.validate().is_err());
    }

    #[test]
    fn validate_namespace_target_valid() {
        let mut spec = valid_spec();
        spec.target = MeshMemberTarget::Namespace("monitoring".to_string());
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn derived_name_deterministic() {
        let a = derived_name("cnp-mesh-", &["monitoring", "prometheus"]);
        let b = derived_name("cnp-mesh-", &["monitoring", "prometheus"]);
        assert_eq!(a, b);
    }

    #[test]
    fn derived_name_different_inputs() {
        let a = derived_name("cnp-mesh-", &["ns1", "svc1"]);
        let b = derived_name("cnp-mesh-", &["ns2", "svc2"]);
        assert_ne!(a, b);
    }

    #[test]
    fn derived_name_format() {
        let name = derived_name("cnp-mesh-", &["monitoring", "prometheus"]);
        assert!(name.starts_with("cnp-mesh-"));
        assert_eq!(name.len(), "cnp-mesh-".len() + 8);
    }

    #[test]
    fn target_labels_selector() {
        let spec = valid_spec();
        let labels = spec.target_labels();
        assert_eq!(labels.get("app"), Some(&"prometheus".to_string()));
    }

    #[test]
    fn target_labels_namespace() {
        let mut spec = valid_spec();
        spec.target = MeshMemberTarget::Namespace("monitoring".to_string());
        assert!(spec.target_labels().is_empty());
    }

    #[test]
    fn target_namespace_selector() {
        let spec = valid_spec();
        assert_eq!(spec.target_namespace("default"), "default");
    }

    #[test]
    fn target_namespace_explicit() {
        let mut spec = valid_spec();
        spec.target = MeshMemberTarget::Namespace("monitoring".to_string());
        assert_eq!(spec.target_namespace("default"), "monitoring");
    }
}
