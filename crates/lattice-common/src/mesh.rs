//! Service mesh constants for Istio Ambient + Cilium
//!
//! Single source of truth for mesh-related constants used across policy
//! and ingress compilation. We're committed to Istio Ambient mode with
//! Cilium CNI - no abstraction layer needed.

// =============================================================================
// Ports
// =============================================================================

/// HBONE port for Istio Ambient waypoint communication.
///
/// In ambient mode, traffic flows: client -> ztunnel -> waypoint:15008 -> service
/// HBONE (HTTP-Based Overlay Network Encapsulation) is Istio's L7 tunnel protocol.
pub const HBONE_PORT: u16 = 15008;

/// Istiod xDS port for control plane communication.
pub const ISTIOD_XDS_PORT: u16 = 15012;

// =============================================================================
// Gateway Classes
// =============================================================================

/// Istio waypoint GatewayClass for ambient mesh L7 enforcement.
pub const WAYPOINT_GATEWAY_CLASS: &str = "istio-waypoint";

/// Istio GatewayClass for north-south ingress.
///
/// Istiod natively reconciles Gateway API resources. Gateway proxy pods are
/// created per-Gateway in the service namespace, automatically enrolled in
/// ambient mesh with SPIFFE identity.
pub const INGRESS_GATEWAY_CLASS: &str = "istio";

// =============================================================================
// Labels
// =============================================================================

/// Label key indicating what type of traffic a waypoint handles.
/// Value: "service" for service-destined traffic.
pub const WAYPOINT_FOR_LABEL: &str = "istio.io/waypoint-for";

/// Label key to route traffic through a specific waypoint.
/// Value: name of the waypoint Gateway (e.g., "{namespace}-waypoint").
pub const USE_WAYPOINT_LABEL: &str = "istio.io/use-waypoint";

/// Cilium label selector for Gateway API gateway-name label.
///
/// Present on all pods created by a Gateway API controller (both ingress
/// gateways and waypoint proxies). Used for cluster-wide Cilium policies
/// that apply to all mesh proxy pods.
pub const CILIUM_GATEWAY_NAME_LABEL: &str = "k8s:gateway.networking.k8s.io/gateway-name";

/// Label key for Istio dataplane mode.
/// Value: "ambient" to enroll pods in ambient mesh.
pub const DATAPLANE_MODE_LABEL: &str = "istio.io/dataplane-mode";

// =============================================================================
// Label Values
// =============================================================================

/// Value for WAYPOINT_FOR_LABEL indicating service-destined traffic.
pub const WAYPOINT_FOR_SERVICE: &str = "service";

/// Value for DATAPLANE_MODE_LABEL enabling ambient mesh enrollment.
pub const DATAPLANE_MODE_AMBIENT: &str = "ambient";

// =============================================================================
// Naming Helpers
// =============================================================================

/// Get the waypoint Gateway name for a namespace.
///
/// Waypoints are per-namespace in Istio Ambient mode.
pub fn waypoint_name(namespace: &str) -> String {
    format!("{}-waypoint", namespace)
}

/// Get the shared ingress Gateway name for a namespace.
///
/// A single shared Gateway per namespace reduces resource overhead.
/// Individual services bind to it via listener `section_name` references.
pub fn ingress_gateway_name(namespace: &str) -> String {
    format!("{}-ingress", namespace)
}

// =============================================================================
// Trust Domain Helpers
// =============================================================================

/// Trust domain module for SPIFFE identity generation.
///
/// Lattice uses per-cluster trust domains: `lattice.{cluster}.local`
/// This provides multi-cluster isolation while maintaining a consistent format.
pub mod trust_domain {
    /// Build the trust domain for a cluster.
    ///
    /// Format: `lattice.{cluster_name}.local`
    pub fn cluster_domain(cluster_name: &str) -> String {
        format!("lattice.{}.local", cluster_name)
    }

    /// Build a SPIFFE principal for a service account.
    ///
    /// Format: `lattice.{cluster}.local/ns/{namespace}/sa/{service_account}`
    ///
    /// Note: The principal does NOT include the `spiffe://` prefix.
    /// Istio adds it internally.
    pub fn principal(cluster_name: &str, namespace: &str, service_account: &str) -> String {
        format!(
            "lattice.{}.local/ns/{}/sa/{}",
            cluster_name, namespace, service_account
        )
    }

    /// Build a SPIFFE principal for a namespace's waypoint proxy.
    ///
    /// Waypoint service accounts follow the pattern: `{namespace}-waypoint`
    pub fn waypoint_principal(cluster_name: &str, namespace: &str) -> String {
        principal(cluster_name, namespace, &super::waypoint_name(namespace))
    }

    /// Build a SPIFFE principal for the namespace's shared ingress gateway proxy.
    ///
    /// The gateway name is derived deterministically from the namespace
    /// (`{namespace}-ingress`), so only cluster_name and namespace are needed.
    /// Istio creates a service account `{gateway_name}-istio` for the proxy.
    pub fn gateway_principal(cluster_name: &str, namespace: &str) -> String {
        let gw_name = super::ingress_gateway_name(namespace);
        principal(cluster_name, namespace, &format!("{}-istio", gw_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hbone_port_is_correct() {
        assert_eq!(HBONE_PORT, 15008);
    }

    #[test]
    fn waypoint_gateway_class_is_istio() {
        assert_eq!(WAYPOINT_GATEWAY_CLASS, "istio-waypoint");
    }

    #[test]
    fn cluster_domain_format() {
        assert_eq!(trust_domain::cluster_domain("prod"), "lattice.prod.local");
    }

    #[test]
    fn principal_format_no_spiffe_prefix() {
        let principal = trust_domain::principal("prod", "default", "api");
        assert_eq!(principal, "lattice.prod.local/ns/default/sa/api");
        assert!(!principal.starts_with("spiffe://"));
    }

    #[test]
    fn waypoint_principal_format() {
        let principal = trust_domain::waypoint_principal("prod", "myns");
        assert_eq!(principal, "lattice.prod.local/ns/myns/sa/myns-waypoint");
    }

    #[test]
    fn gateway_principal_format() {
        let principal = trust_domain::gateway_principal("prod", "my-ns");
        assert_eq!(
            principal,
            "lattice.prod.local/ns/my-ns/sa/my-ns-ingress-istio"
        );
    }

    #[test]
    fn ingress_gateway_name_format() {
        assert_eq!(ingress_gateway_name("prod"), "prod-ingress");
        assert_eq!(ingress_gateway_name("my-ns"), "my-ns-ingress");
    }

}
