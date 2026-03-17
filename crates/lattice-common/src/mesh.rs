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

/// ConfigMap name containing the Lattice CA trust bundle for cross-cluster mTLS.
///
/// Gateway API frontend mTLS references this ConfigMap to validate client certs.
/// The operator ensures this ConfigMap exists with the CA trust bundle PEM.
pub const LATTICE_CA_CONFIGMAP: &str = "lattice-ca-trust";

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

/// Get the service account name for the namespace's ingress gateway proxy.
///
/// Istio creates a service account `{gateway_name}-istio` for the proxy pod.
pub fn ingress_gateway_sa_name(namespace: &str) -> String {
    format!("{}-istio", ingress_gateway_name(namespace))
}

// =============================================================================
// Trust Domain Helpers
// =============================================================================

/// Trust domain module for SPIFFE identity generation.
///
/// SPIFFE principal helpers for Istio AuthorizationPolicy.
///
/// Per Istio docs (since 1.4), AuthorizationPolicy should use `cluster.local`
/// as the trust domain — Istio treats it as a pointer to the actual trust
/// domain, making policies resilient to trust domain changes and migrations.
/// The real trust domain (from meshConfig.trustDomain) is only needed for
/// istiod configuration, NOT for policy generation.
pub mod principal {
    /// The trust domain alias used in AuthorizationPolicy principals.
    /// Istio resolves this to the actual mesh trust domain at evaluation time.
    const POLICY_TRUST_DOMAIN: &str = "cluster.local";

    /// Build a SPIFFE principal for a service account.
    ///
    /// Format: `cluster.local/ns/{namespace}/sa/{service_account}`
    ///
    /// Note: The principal does NOT include the `spiffe://` prefix.
    /// Istio adds it internally.
    pub fn service(namespace: &str, service_account: &str) -> String {
        format!("{POLICY_TRUST_DOMAIN}/ns/{namespace}/sa/{service_account}")
    }

    /// Build a SPIFFE principal for a namespace's waypoint proxy.
    ///
    /// Waypoint service accounts follow the pattern: `{namespace}-waypoint`
    pub fn waypoint(namespace: &str) -> String {
        service(namespace, &super::waypoint_name(namespace))
    }

    /// Build a SPIFFE principal for the namespace's shared ingress gateway proxy.
    ///
    /// Istio creates a service account `{gateway_name}-istio` for the proxy.
    pub fn gateway(namespace: &str) -> String {
        service(namespace, &super::ingress_gateway_sa_name(namespace))
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
    fn principal_uses_cluster_local() {
        let p = principal::service("default", "api");
        assert_eq!(p, "cluster.local/ns/default/sa/api");
        assert!(!p.starts_with("spiffe://"));
    }

    #[test]
    fn waypoint_principal_format() {
        let p = principal::waypoint("myns");
        assert_eq!(p, "cluster.local/ns/myns/sa/myns-waypoint");
    }

    #[test]
    fn gateway_principal_format() {
        let p = principal::gateway("my-ns");
        assert_eq!(p, "cluster.local/ns/my-ns/sa/my-ns-ingress-istio");
    }

    #[test]
    fn ingress_gateway_name_format() {
        assert_eq!(ingress_gateway_name("prod"), "prod-ingress");
        assert_eq!(ingress_gateway_name("my-ns"), "my-ns-ingress");
    }

    #[test]
    fn ingress_gateway_sa_name_format() {
        assert_eq!(ingress_gateway_sa_name("prod"), "prod-ingress-istio");
        assert_eq!(ingress_gateway_sa_name("my-ns"), "my-ns-ingress-istio");
    }
}
