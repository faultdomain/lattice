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
    pub allowed_callers: Vec<ServiceRef>,

    /// Services this member depends on (bilateral agreement outbound side)
    #[serde(default)]
    pub dependencies: Vec<ServiceRef>,

    /// Non-mesh egress rules (entity, CIDR, FQDN targets)
    #[serde(default)]
    pub egress: Vec<EgressRule>,

    /// Allow traffic between pods matching this member's own selector
    #[serde(default)]
    pub allow_peer_traffic: bool,

    /// Wildcard outbound: this member can call any service that allows it
    #[serde(default)]
    pub depends_all: bool,

    /// Ingress configuration for exposing this member externally
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<IngressSpec>,

    /// Kubernetes ServiceAccount name for SPIFFE identity.
    /// Defaults to the LMM resource name if omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,

    /// Whether this member participates in the Istio ambient mesh (L7 enforcement).
    /// When `false`, pods get `istio.io/dataplane-mode: none` and only Cilium L4
    /// policies are generated (no AuthorizationPolicy, PeerAuthentication, or ServiceEntry).
    /// Defaults to `true`.
    #[serde(default = "default_true")]
    pub ambient: bool,
}

fn default_true() -> bool {
    true
}

/// Target workloads for a mesh member
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
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
    /// Port number (container/target port)
    pub port: u16,
    /// Kubernetes Service port. When the Service uses a port mapping
    /// (`port: 80, targetPort: 8080`), this holds the Service-facing port
    /// so Gateway API backendRefs can reference it correctly.
    /// Defaults to `port` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_port: Option<u16>,
    /// Port name (must be a valid DNS label)
    pub name: String,
    /// mTLS enforcement mode for this port
    #[serde(default)]
    pub peer_auth: PeerAuth,
}

/// mTLS enforcement mode per-port
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerAuth {
    /// Require mTLS (default)
    #[default]
    Strict,
    /// Allow plaintext from any source
    Permissive,
    /// Allow plaintext from kube-apiserver only (admission webhooks)
    Webhook,
}

/// Network protocol for egress rules.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum NetworkProtocol {
    /// TCP (default)
    #[default]
    Tcp,
    /// UDP
    Udp,
}

impl NetworkProtocol {
    /// Returns the protocol name as used in Cilium/K8s ("TCP" or "UDP").
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
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
    /// Protocol (defaults to TCP)
    #[serde(default)]
    pub protocol: NetworkProtocol,
}

/// Target for egress rules
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum EgressTarget {
    /// Cilium entity (e.g., "world", "kube-apiserver")
    Entity(String),
    /// CIDR range
    Cidr(String),
    /// DNS name
    Fqdn(String),
}

impl EgressTarget {
    /// Build the appropriate EgressTarget for a host string.
    /// IPs use CIDR/32 (Istio rejects bare IPs as ServiceEntry hosts),
    /// hostnames use FQDN.
    pub fn for_host(host: &str) -> Self {
        if host.parse::<std::net::IpAddr>().is_ok() {
            Self::Cidr(format!("{}/32", host))
        } else {
            Self::Fqdn(host.to_string())
        }
    }
}

impl EgressRule {
    /// Create a TCP egress rule (the common case).
    pub fn tcp(target: EgressTarget, ports: Vec<u16>) -> Self {
        Self {
            target,
            ports,
            protocol: NetworkProtocol::Tcp,
        }
    }

    /// Create a UDP egress rule.
    pub fn udp(target: EgressTarget, ports: Vec<u16>) -> Self {
        Self {
            target,
            ports,
            protocol: NetworkProtocol::Udp,
        }
    }

    /// Parse an entity egress reference from an external-service resource id.
    ///
    /// Format: `entity:<name>` or `entity:<name>:<port>`
    ///
    /// Returns `None` if `id` doesn't start with `entity:` or the name is empty.
    ///
    /// # Examples
    /// - `entity:world` → Entity("world"), port 443
    /// - `entity:world:443` → Entity("world"), port 443
    /// - `entity:kube-apiserver:6443` → Entity("kube-apiserver"), port 6443
    /// - `entity:name:notaport` → Entity("name:notaport"), port 443
    pub fn from_entity_id(id: &str) -> Option<Self> {
        let rest = id.strip_prefix("entity:")?;
        let (name, port) = if let Some((n, p)) = rest.rsplit_once(':') {
            match p.parse::<u16>() {
                Ok(port) => (n.to_string(), port),
                Err(_) => (rest.to_string(), 443),
            }
        } else {
            (rest.to_string(), 443)
        };
        if name.is_empty() {
            return None;
        }
        Some(EgressRule::tcp(EgressTarget::Entity(name), vec![port]))
    }
}

// =============================================================================
// Status
// =============================================================================

/// Status of a LatticeMeshMember
///
/// All optional fields serialize as `null` (no `skip_serializing_if`) so that
/// merge-patch status updates correctly clear stale values.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeMeshMemberStatus {
    /// Current phase
    #[serde(default)]
    pub phase: MeshMemberPhase,
    /// Workload or Namespace scope
    #[serde(default)]
    pub scope: Option<MeshMemberScope>,
    /// Human-readable message
    #[serde(default)]
    pub message: Option<String>,
    /// Last observed generation
    #[serde(default)]
    pub observed_generation: Option<i64>,
    /// Status conditions
    #[serde(default)]
    pub conditions: Vec<super::types::Condition>,
    /// Resources applied by the controller, tracked for orphan cleanup.
    /// When a dependency is removed, resources in the old set but not the new set are deleted.
    #[serde(default)]
    pub applied_resources: Vec<AppliedResourceRef>,
}

/// Reference to an applied mesh resource, tracked for orphan cleanup.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct AppliedResourceRef {
    /// Kubernetes resource kind (e.g. "AuthorizationPolicy", "PeerAuthentication")
    pub kind: String,
    /// Resource name
    pub name: String,
}

/// Phase of a mesh member
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum MeshMemberPhase {
    /// Waiting for reconciliation
    #[default]
    Pending,
    /// Core policies applied, waiting for deferred resources (e.g. ServiceEntries)
    Progressing,
    /// Policies applied successfully
    Ready,
    /// Policy generation or application failed
    Failed,
}

impl std::fmt::Display for MeshMemberPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Progressing => write!(f, "Progressing"),
            Self::Ready => write!(f, "Ready"),
            Self::Failed => write!(f, "Failed"),
        }
    }
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
    pub fn validate(&self) -> Result<(), crate::ValidationError> {
        for port in &self.ports {
            super::validate_dns_label(&port.name, "port name").map_err(crate::ValidationError::new)?;
        }

        if let MeshMemberTarget::Namespace(ref ns) = self.target {
            if ns.is_empty() {
                return Err(crate::ValidationError::new("namespace target cannot be empty"));
            }
        }

        if let MeshMemberTarget::Selector(ref labels) = self.target {
            if labels.is_empty() {
                return Err(crate::ValidationError::new(
                    "selector must have at least one label",
                ));
            }
            for key in labels.keys() {
                if key.is_empty() {
                    return Err(crate::ValidationError::new(
                        "selector label key cannot be empty",
                    ));
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
                service_port: None,
                name: "metrics".to_string(),
                peer_auth: PeerAuth::Strict,
            }],
            allowed_callers: vec![],
            dependencies: vec![],
            egress: vec![],
            allow_peer_traffic: false,
            depends_all: false,
            ingress: None,
            service_account: None,
            ambient: true,
        }
    }

    #[test]
    fn validate_valid_spec() {
        assert!(valid_spec().validate().is_ok());
    }

    #[test]
    fn validate_empty_ports_and_deps_valid() {
        let mut spec = valid_spec();
        spec.ports.clear();
        spec.dependencies.clear();
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_client_only_valid() {
        let mut spec = valid_spec();
        spec.ports.clear();
        spec.dependencies.push(ServiceRef::local("some-service"));
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_egress_only_valid() {
        let mut spec = valid_spec();
        spec.ports.clear();
        spec.dependencies.clear();
        spec.egress.push(EgressRule::tcp(
            EgressTarget::Entity("world".to_string()),
            vec![443],
        ));
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_empty_everything_valid() {
        let mut spec = valid_spec();
        spec.ports.clear();
        spec.dependencies.clear();
        spec.egress.clear();
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn validate_depends_all_only_valid() {
        let mut spec = valid_spec();
        spec.ports.clear();
        spec.dependencies.clear();
        spec.egress.clear();
        spec.depends_all = true;
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

    // =========================================================================
    // Story: EgressRule::from_entity_id
    // =========================================================================

    #[test]
    fn entity_world_default_port() {
        let rule = EgressRule::from_entity_id("entity:world").unwrap();
        assert_eq!(rule.target, EgressTarget::Entity("world".to_string()));
        assert_eq!(rule.ports, vec![443]);
    }

    #[test]
    fn entity_world_explicit_443() {
        let rule = EgressRule::from_entity_id("entity:world:443").unwrap();
        assert_eq!(rule.target, EgressTarget::Entity("world".to_string()));
        assert_eq!(rule.ports, vec![443]);
    }

    #[test]
    fn entity_kube_apiserver_custom_port() {
        let rule = EgressRule::from_entity_id("entity:kube-apiserver:6443").unwrap();
        assert_eq!(
            rule.target,
            EgressTarget::Entity("kube-apiserver".to_string())
        );
        assert_eq!(rule.ports, vec![6443]);
    }

    #[test]
    fn entity_empty_name_returns_none() {
        assert!(EgressRule::from_entity_id("entity:").is_none());
    }

    #[test]
    fn entity_invalid_port_treated_as_name() {
        let rule = EgressRule::from_entity_id("entity:name:notaport").unwrap();
        assert_eq!(
            rule.target,
            EgressTarget::Entity("name:notaport".to_string())
        );
        assert_eq!(rule.ports, vec![443]);
    }

    #[test]
    fn non_entity_prefix_returns_none() {
        assert!(EgressRule::from_entity_id("fqdn:example.com").is_none());
        assert!(EgressRule::from_entity_id("world:443").is_none());
    }

    // =========================================================================
    // Story: EgressTarget::for_host
    // =========================================================================

    #[test]
    fn for_host_ip_uses_cidr() {
        assert_eq!(
            EgressTarget::for_host("172.18.0.11"),
            EgressTarget::Cidr("172.18.0.11/32".to_string())
        );
    }

    #[test]
    fn for_host_fqdn_uses_fqdn() {
        assert_eq!(
            EgressTarget::for_host("keycloak.example.com"),
            EgressTarget::Fqdn("keycloak.example.com".to_string())
        );
    }

    #[test]
    fn for_host_ipv6_uses_cidr() {
        assert_eq!(
            EgressTarget::for_host("::1"),
            EgressTarget::Cidr("::1/32".to_string())
        );
    }
}
