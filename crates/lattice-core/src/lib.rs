//! Shared constants, error types, and utilities for Lattice crates.
//!
//! This is the leaf dependency — no Kubernetes controller logic, no CRD types.
//! Both `lattice-crd` and `lattice-common` depend on this.

pub mod quantity;
pub mod system_namespaces;
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
        assert_eq!(sanitize_dns_label("wg_confs.conf").unwrap(), "wg-confs-conf");
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
