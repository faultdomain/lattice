//! System namespace registry for policy exclusions
//!
//! Single source of truth for namespaces that should be excluded from
//! default-deny network policies. These are infrastructure namespaces
//! that require unrestricted network access to function.

use lattice_common::{CAPA_NAMESPACE, CAPMOX_NAMESPACE, CAPO_NAMESPACE, LATTICE_SYSTEM_NAMESPACE};

/// Core Kubernetes namespaces
pub const CORE: &[&str] = &["kube-system", "kube-public", "kube-node-lease"];

/// Lattice operator namespace
pub const LATTICE: &[&str] = &[LATTICE_SYSTEM_NAMESPACE];

/// CNI (Cilium) namespace
pub const CNI: &[&str] = &["cilium-system"];

/// Service mesh (Istio) namespace
pub const MESH: &[&str] = &["istio-system"];

/// Certificate management namespace
pub const CERT: &[&str] = &["cert-manager"];

/// GPU infrastructure namespaces (GPU Operator + HAMi)
pub const GPU: &[&str] = &["gpu-operator", "hami-system"];

/// Monitoring namespaces (VictoriaMetrics + Prometheus Adapter)
pub const MONITORING: &[&str] = &["monitoring"];

/// Cluster API namespaces (core + bootstrap + control plane + providers)
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

/// Get all system namespaces that should be excluded from default-deny policies.
///
/// Returns a sorted, deduplicated list of all infrastructure namespaces.
pub fn all() -> Vec<&'static str> {
    let mut namespaces: Vec<&'static str> = CORE
        .iter()
        .chain(LATTICE.iter())
        .chain(CNI.iter())
        .chain(MESH.iter())
        .chain(CERT.iter())
        .chain(GPU.iter())
        .chain(MONITORING.iter())
        .chain(CAPI.iter())
        .copied()
        .collect();

    namespaces.sort();
    namespaces.dedup();
    namespaces
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_returns_sorted_unique_namespaces() {
        let namespaces = all();

        // Should be sorted
        let mut sorted = namespaces.clone();
        sorted.sort();
        assert_eq!(namespaces, sorted);

        // Should have no duplicates
        let mut deduped = namespaces.clone();
        deduped.dedup();
        assert_eq!(namespaces.len(), deduped.len());
    }

    #[test]
    fn all_includes_critical_namespaces() {
        let namespaces = all();

        assert!(namespaces.contains(&"kube-system"));
        assert!(namespaces.contains(&LATTICE_SYSTEM_NAMESPACE));
        assert!(namespaces.contains(&"cilium-system"));
        assert!(namespaces.contains(&"istio-system"));
        assert!(namespaces.contains(&"cert-manager"));
        assert!(namespaces.contains(&"capi-system"));
        assert!(namespaces.contains(&"monitoring"));
    }

    #[test]
    fn capi_includes_all_providers() {
        assert!(CAPI.contains(&"capd-system")); // Docker
        assert!(CAPI.contains(&CAPA_NAMESPACE)); // AWS
        assert!(CAPI.contains(&CAPO_NAMESPACE)); // OpenStack
        assert!(CAPI.contains(&CAPMOX_NAMESPACE)); // Proxmox
    }
}
