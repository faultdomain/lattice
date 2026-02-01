//! Centralized constants for the lattice-capi crate
//!
//! All shared constants should be defined here to avoid duplication
//! and inconsistency across provider implementations.

// =============================================================================
// Infrastructure Provider API Versions
// =============================================================================

/// Docker infrastructure API group (used in refs)
pub const DOCKER_INFRASTRUCTURE_API_GROUP: &str = "infrastructure.cluster.x-k8s.io";

/// Docker infrastructure API version for kubeadm (v1beta2 - latest CAPI)
pub const DOCKER_INFRASTRUCTURE_API_VERSION_V1BETA2: &str =
    "infrastructure.cluster.x-k8s.io/v1beta2";

/// Docker infrastructure API version for RKE2 (v1beta1 - required by CAPRKE2)
/// See: https://github.com/rancher/cluster-api-provider-rke2/issues/789
pub const DOCKER_INFRASTRUCTURE_API_VERSION_V1BETA1: &str =
    "infrastructure.cluster.x-k8s.io/v1beta1";

/// Proxmox infrastructure API version
pub const PROXMOX_API_VERSION: &str = "infrastructure.cluster.x-k8s.io/v1alpha1";

/// OpenStack infrastructure API version
pub const OPENSTACK_API_VERSION: &str = "infrastructure.cluster.x-k8s.io/v1beta1";

/// AWS infrastructure API version
pub const AWS_API_VERSION: &str = "infrastructure.cluster.x-k8s.io/v1beta2";

// =============================================================================
// Default Values
// =============================================================================

/// Default namespace for CAPI resources when not specified
pub const DEFAULT_NAMESPACE: &str = "default";

/// Default kube-vip image for VIP management
pub const DEFAULT_KUBE_VIP_IMAGE: &str = "ghcr.io/kube-vip/kube-vip:v0.8.0";

/// Default VIP network interface for Proxmox
pub const DEFAULT_VIP_INTERFACE_PROXMOX: &str = "ens18";

/// Default node CIDR for OpenStack
pub const DEFAULT_NODE_CIDR_OPENSTACK: &str = "10.6.0.0/24";

/// Default network interface for VIP configuration (generic)
pub const DEFAULT_NETWORK_INTERFACE: &str = "eth0";

/// Infrastructure API group for all CAPI providers
pub const INFRASTRUCTURE_API_GROUP: &str = "infrastructure.cluster.x-k8s.io";

/// Default DNS servers used when not specified
pub const DEFAULT_DNS_SERVERS: &[&str] = &["8.8.8.8", "8.8.4.4"];

/// Kubernetes API server port
pub const KUBERNETES_API_SERVER_PORT: u16 = 6443;

// =============================================================================
// Helper Functions
// =============================================================================

/// Get namespace from cluster metadata or return default
///
/// This provides a standardized way to handle namespace resolution across
/// all providers. The priority is:
/// 1. Cluster's metadata.namespace (if set)
/// 2. Provider's configured namespace
/// 3. DEFAULT_NAMESPACE as fallback
pub fn get_namespace_or_default(
    cluster_namespace: Option<&str>,
    provider_namespace: &str,
) -> String {
    cluster_namespace
        .filter(|ns| !ns.is_empty())
        .map(String::from)
        .unwrap_or_else(|| {
            if provider_namespace.is_empty() {
                DEFAULT_NAMESPACE.to_string()
            } else {
                provider_namespace.to_string()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_namespace_or_default_uses_cluster_namespace() {
        let result = get_namespace_or_default(Some("my-namespace"), "provider-ns");
        assert_eq!(result, "my-namespace");
    }

    #[test]
    fn test_get_namespace_or_default_uses_provider_namespace() {
        let result = get_namespace_or_default(None, "provider-ns");
        assert_eq!(result, "provider-ns");
    }

    #[test]
    fn test_get_namespace_or_default_uses_default() {
        let result = get_namespace_or_default(None, "");
        assert_eq!(result, "default");
    }

    #[test]
    fn test_get_namespace_or_default_handles_empty_cluster_namespace() {
        let result = get_namespace_or_default(Some(""), "provider-ns");
        assert_eq!(result, "provider-ns");
    }
}
