//! Shared constants, error types, and utilities for Lattice crates.
//!
//! This is the leaf dependency — no Kubernetes controller logic, no CRD types.
//! Both `lattice-crd` and `lattice-common` depend on this.

pub mod quantity;
pub mod system_namespaces;
pub mod template_types;
pub mod yaml;

// ============================================================================
// Namespace constants
// ============================================================================

/// Namespace for Lattice system resources (CA, credentials, operator)
pub const LATTICE_SYSTEM_NAMESPACE: &str = "lattice-system";

/// Namespace for external-dns resources
pub const EXTERNAL_DNS_NAMESPACE: &str = "external-dns";

// ============================================================================
// Port constants
// ============================================================================

/// Default port for the agent-cell gRPC stream
pub const DEFAULT_GRPC_PORT: u16 = 50051;

/// Default port for the kubeadm bootstrap webhook
pub const DEFAULT_BOOTSTRAP_PORT: u16 = 8443;

/// Default port for the K8s API proxy
pub const DEFAULT_PROXY_PORT: u16 = 8081;

// ============================================================================
// Secret type constants
// ============================================================================

/// Kubernetes TLS secret type
pub const SECRET_TYPE_TLS: &str = "kubernetes.io/tls";

/// Kubernetes Docker config secret type
pub const SECRET_TYPE_DOCKERCONFIG: &str = "kubernetes.io/dockerconfigjson";

/// Kubernetes service account token secret type
pub const SECRET_TYPE_SA_TOKEN: &str = "kubernetes.io/service-account-token";

// ============================================================================
// Kubernetes labels
// ============================================================================

/// Standard name label key - identifies the name of the application
pub const LABEL_NAME: &str = "app.kubernetes.io/name";

/// Cilium selector for app name label
pub const CILIUM_LABEL_NAME: &str = "k8s:app.kubernetes.io/name";

/// Cilium selector for pod namespace
pub const CILIUM_LABEL_NAMESPACE: &str = "k8s:io.kubernetes.pod.namespace";

// ============================================================================
// Monitoring constants
// ============================================================================

/// Namespace for monitoring stack (VictoriaMetrics, Prometheus)
pub const MONITORING_NAMESPACE: &str = "monitoring";

/// DaemonSet name for the VMAgent node collector
pub const VMAGENT_NODE_NAME: &str = "vmagent";

/// ServiceAccount name for the VMAgent metrics collector
pub const VMAGENT_SA_NAME: &str = "vmagent-lattice-metrics";

// ============================================================================
// Error types
// ============================================================================

/// Validation error returned by CRD `validate()` methods.
///
/// Converted to `lattice_common::Error::Validation` via `From` impl.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ValidationError(pub String);

impl ValidationError {
    /// Create a new validation error.
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

// ============================================================================
// SPIFFE trust domain
// ============================================================================

/// SPIFFE trust domain utilities for constructing principal identities.
pub mod trust_domain {
    /// Build a SPIFFE principal string from trust domain, namespace, and service account.
    ///
    /// Format: `{trust_domain}/ns/{namespace}/sa/{service_account}`
    pub fn principal(trust_domain: &str, namespace: &str, service_account: &str) -> String {
        format!("{}/ns/{}/sa/{}", trust_domain, namespace, service_account)
    }
}

// ============================================================================
// Kubernetes metadata utilities
// ============================================================================

/// Strip cluster-specific metadata fields from an ObjectMeta for export/import.
///
/// Removes uid, resourceVersion, creationTimestamp, managedFields, and generation
/// so the object can be cleanly applied to another cluster.
pub fn strip_export_metadata(
    meta: &mut k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
) {
    meta.uid = None;
    meta.resource_version = None;
    meta.creation_timestamp = None;
    meta.managed_fields = None;
    meta.generation = None;
}

// ============================================================================
// Hashing
// ============================================================================

/// Compute a deterministic hash of the input string, returning a 16-char hex digest.
///
/// Uses truncated SHA-256 for stability across Rust toolchain versions.
pub fn deterministic_hash(input: &str) -> String {
    use aws_lc_rs::digest;
    let hash = digest::digest(&digest::SHA256, input.as_bytes());
    hash.as_ref()[..8]
        .iter()
        .fold(String::with_capacity(16), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
            s
        })
}

/// Compute a full SHA-256 hash of arbitrary bytes.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    use aws_lc_rs::digest;
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

// ============================================================================
// Route hashing
// ============================================================================

/// Trait for types that can be hashed as a service route.
///
/// Implemented by both `SubtreeService` (proto, cell-side) and `ClusterRoute`
/// (CRD, agent-side). A single `hash_routes` function uses this trait so both
/// sides produce identical hashes. If either type's field layout changes, the
/// compiler forces both impls to be updated.
pub trait RouteHashable {
    fn route_name(&self) -> &str;
    fn route_namespace(&self) -> &str;
    fn route_hostname(&self) -> &str;
    fn route_address(&self) -> &str;
    fn route_port(&self) -> u16;
    fn route_protocol(&self) -> &str;
    fn route_allowed_services(&self) -> &[String];
    /// Iterate service ports in deterministic (sorted) order.
    fn route_service_ports(&self) -> Vec<(&str, u16)>;
}

/// Hash a slice of routes. Sorts by (namespace, name) then serializes each
/// route's fields into a deterministic byte buffer and SHA-256s the result.
///
/// Used by both cell and agent to compute per-cluster route hashes.
pub fn hash_routes(routes: &[impl RouteHashable]) -> Vec<u8> {
    let mut sorted: Vec<usize> = (0..routes.len()).collect();
    sorted.sort_by(|&a, &b| {
        let (ra, rb) = (&routes[a], &routes[b]);
        (ra.route_namespace(), ra.route_name()).cmp(&(rb.route_namespace(), rb.route_name()))
    });

    let mut buf = Vec::new();
    for &idx in &sorted {
        let r = &routes[idx];
        buf.extend_from_slice(r.route_name().as_bytes());
        buf.extend_from_slice(r.route_namespace().as_bytes());
        buf.extend_from_slice(r.route_hostname().as_bytes());
        buf.extend_from_slice(r.route_address().as_bytes());
        buf.extend_from_slice(&r.route_port().to_le_bytes());
        buf.extend_from_slice(r.route_protocol().as_bytes());
        for allowed in r.route_allowed_services() {
            buf.extend_from_slice(allowed.as_bytes());
        }
        for (name, port) in r.route_service_ports() {
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(&port.to_le_bytes());
        }
    }
    sha256(&buf)
}

/// Combine per-cluster route hashes into a single deterministic hash.
///
/// Used by both cell (`PeerRouteIndex::hash_excluding`) and agent.
pub fn combine_cluster_hashes(hashes: &std::collections::BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut buf = Vec::new();
    for (name, h) in hashes {
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(h);
    }
    if buf.is_empty() {
        return Vec::new();
    }
    sha256(&buf)
}

// ============================================================================
// DNS utilities
// ============================================================================

/// Sanitize a string into a valid DNS label (`[a-z]([-a-z0-9]*[a-z0-9])?`).
///
/// Replaces non-alphanumeric characters with `-`, lowercases, strips leading
/// digits/dashes (must start with a letter), trims trailing dashes, and
/// truncates to 63 characters.
pub fn sanitize_dns_label(s: &str) -> Option<String> {
    let sanitized: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = sanitized.trim_start_matches(|c: char| !c.is_ascii_lowercase());
    let trimmed = trimmed.trim_end_matches('-');
    if trimmed.is_empty() {
        return None;
    }
    let truncated: String = trimmed.chars().take(63).collect();
    let truncated = truncated.trim_end_matches('-');
    if truncated.is_empty() {
        None
    } else {
        Some(truncated.to_string())
    }
}

/// Validate that a string is already a valid DNS label.
///
/// Sanitizes the input via [`sanitize_dns_label`] and checks that the result
/// matches the original. `field` is used in error messages to identify
/// what kind of name failed (e.g. "container name", "port name").
pub fn validate_dns_label(name: &str, field: &str) -> Result<(), String> {
    match sanitize_dns_label(name) {
        Some(ref sanitized) if sanitized == name => Ok(()),
        _ => Err(format!(
            "{} '{}' is not a valid DNS label (must be lowercase alphanumeric with hyphens, max 63 chars)",
            field, name
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_passthrough() {
        assert_eq!(sanitize_dns_label("hello").unwrap(), "hello");
    }

    #[test]
    fn sanitize_uppercase() {
        assert_eq!(sanitize_dns_label("Hello").unwrap(), "hello");
    }

    #[test]
    fn sanitize_special_chars() {
        assert_eq!(
            sanitize_dns_label("wg_confs.conf").unwrap(),
            "wg-confs-conf"
        );
    }

    #[test]
    fn sanitize_leading_digits() {
        assert_eq!(sanitize_dns_label("123abc").unwrap(), "abc");
    }

    #[test]
    fn sanitize_empty() {
        assert!(sanitize_dns_label("").is_none());
    }

    #[test]
    fn sanitize_truncates_to_63() {
        let long = "a".repeat(100);
        assert_eq!(sanitize_dns_label(&long).unwrap().len(), 63);
    }
}
