//! System namespace registry for default-deny policy exclusions
//!
//! Single source of truth for namespaces excluded from the cluster-wide
//! default-deny CiliumClusterwideNetworkPolicy. Only namespaces that have
//! a circular dependency with the policy infrastructure itself belong here
//! (e.g., Cilium can't enforce policies on its own pods, the mesh control
//! plane must operate outside the mesh it manages).
//!
//! Namespaces with LatticeMeshMember coverage (kthena-system, monitoring,
//! keda) are NOT listed here -- their pods get explicit CiliumNetworkPolicies
//! and PeerAuthentication resources from the MeshMember controller.

use std::collections::HashSet;
use std::sync::LazyLock;

use crate::EXTERNAL_DNS_NAMESPACE;

/// CAPI provider namespace for AWS
pub const CAPA_NAMESPACE: &str = "capa-system";
/// CAPI provider namespace for Proxmox
pub const CAPMOX_NAMESPACE: &str = "capmox-system";
/// CAPI provider namespace for OpenStack
pub const CAPO_NAMESPACE: &str = "capo-system";
/// Velero backup namespace
pub const VELERO_NAMESPACE: &str = "velero";

/// Core Kubernetes namespaces
pub const CORE: &[&str] = &["kube-system", "kube-public", "kube-node-lease"];

/// CNI (Cilium) namespace -- can't enforce policies on itself
pub const CNI: &[&str] = &["cilium-system"];

/// Service mesh (Istio) namespace -- control plane must be outside the mesh
pub const MESH: &[&str] = &["istio-system"];

/// Certificate management namespace (serves webhooks, no MeshMember yet)
pub const CERT: &[&str] = &["cert-manager"];

/// Cluster API namespaces (serve webhooks, no MeshMembers yet)
pub const CAPI: &[&str] = &[
    "capi-system",
    "capi-kubeadm-bootstrap-system",
    "capi-kubeadm-control-plane-system",
    "rke2-bootstrap-system",
    "rke2-control-plane-system",
    "capd-system",
    CAPO_NAMESPACE,
    CAPA_NAMESPACE,
    CAPMOX_NAMESPACE,
    "capi-ipam-in-cluster-system",
];

/// Infrastructure addons (no MeshMember, need API server access)
pub const ADDONS: &[&str] = &[EXTERNAL_DNS_NAMESPACE, VELERO_NAMESPACE];

/// All namespace slices that are excluded from default-deny.
const ALL_SLICES: &[&[&str]] = &[CORE, CNI, MESH, CERT, CAPI, ADDONS];

/// Get all system namespaces that should be excluded from default-deny policies.
///
/// Returns a sorted, deduplicated list of all infrastructure namespaces.
pub fn all() -> Vec<&'static str> {
    let mut namespaces: Vec<&'static str> =
        ALL_SLICES.iter().flat_map(|s| s.iter()).copied().collect();
    namespaces.sort();
    namespaces.dedup();
    namespaces
}

/// Pre-computed set for O(1) system namespace lookups.
static SYSTEM_NAMESPACE_SET: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| ALL_SLICES.iter().flat_map(|s| s.iter()).copied().collect());

/// Check if a namespace is a system namespace that should be excluded from
/// default-deny policies.
pub fn is_system_namespace(namespace: &str) -> bool {
    SYSTEM_NAMESPACE_SET.contains(namespace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LATTICE_SYSTEM_NAMESPACE;

    #[test]
    fn all_returns_sorted_unique_namespaces() {
        let namespaces = all();

        let mut sorted = namespaces.clone();
        sorted.sort();
        assert_eq!(namespaces, sorted);

        let mut deduped = namespaces.clone();
        deduped.dedup();
        assert_eq!(namespaces.len(), deduped.len());
    }

    #[test]
    fn all_includes_critical_namespaces() {
        let namespaces = all();

        assert!(namespaces.contains(&"kube-system"));
        assert!(namespaces.contains(&"cilium-system"));
        assert!(namespaces.contains(&"istio-system"));
        assert!(namespaces.contains(&"cert-manager"));
        assert!(namespaces.contains(&"capi-system"));
        assert!(namespaces.contains(&"external-dns"));
        assert!(namespaces.contains(&"velero"));
    }

    #[test]
    fn mesh_managed_namespaces_excluded() {
        let namespaces = all();

        // These namespaces have full MeshMember coverage and are NOT system namespaces
        assert!(!namespaces.contains(&LATTICE_SYSTEM_NAMESPACE));
        assert!(!namespaces.contains(&"kthena-system"));
        assert!(!namespaces.contains(&"monitoring"));
        assert!(!namespaces.contains(&"keda"));
    }

    #[test]
    fn capi_includes_all_providers() {
        assert!(CAPI.contains(&"capd-system"));
        assert!(CAPI.contains(&CAPA_NAMESPACE));
        assert!(CAPI.contains(&CAPO_NAMESPACE));
        assert!(CAPI.contains(&CAPMOX_NAMESPACE));
    }

    #[test]
    fn is_system_namespace_works() {
        assert!(is_system_namespace("kube-system"));
        assert!(is_system_namespace("istio-system"));
        assert!(is_system_namespace("cert-manager"));
        assert!(!is_system_namespace(LATTICE_SYSTEM_NAMESPACE));
        assert!(!is_system_namespace("kthena-system"));
        assert!(!is_system_namespace("monitoring"));
        assert!(!is_system_namespace("keda"));
        assert!(!is_system_namespace("default"));
        assert!(!is_system_namespace("my-app"));
    }
}
