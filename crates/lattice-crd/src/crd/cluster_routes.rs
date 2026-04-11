//! LatticeClusterRoutes CRD — multi-cluster service route registry
//!
//! One per child cluster, reconciled by the cell from subtree registry data.
//! Contains service routes advertised by the child via heartbeat. Enables:
//!
//! - **DMZ proxy**: data plane adapters watch this CRD to route external traffic
//! - **Cross-cluster discovery**: siblings resolve dependencies across clusters
//! - **Observability**: operators see which services are available where

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Spec for LatticeClusterRoutes — routes advertised by a child cluster
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeClusterRoutes",
    plural = "latticeclusterroutes",
    shortname = "lcr",
    namespaced = false,
    status = "LatticeClusterRoutesStatus",
    printcolumn = r#"{"name":"Routes","type":"integer","jsonPath":".status.routeCount"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeClusterRoutesSpec {
    /// Advertised service routes from this cluster
    #[serde(default)]
    pub routes: Vec<ClusterRoute>,
}

/// A service route advertised by a cluster
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClusterRoute {
    /// LatticeService name
    pub service_name: String,

    /// LatticeService namespace
    pub service_namespace: String,

    /// Ingress hostname
    pub hostname: String,

    /// Gateway address (LoadBalancer IP)
    pub address: String,

    /// Gateway port
    pub port: u16,

    /// Protocol (HTTP, HTTPS, TCP, GRPC)
    #[serde(default = "default_protocol")]
    pub protocol: String,

    /// Allowed callers (cluster/namespace/name) from the advertise config.
    /// Empty = fail-closed (nobody allowed). Use ["*"] for open access.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_services: Vec<String>,

    /// Backend service ports (name → port) from the LatticeService spec.
    /// Used to create Service stubs with matching ports so istiod can
    /// merge remote endpoints. Empty = use gateway port only (legacy).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub service_ports: BTreeMap<String, u16>,
}

fn default_protocol() -> String {
    "HTTP".to_string()
}

impl lattice_core::RouteHashable for ClusterRoute {
    fn route_name(&self) -> &str {
        &self.service_name
    }
    fn route_namespace(&self) -> &str {
        &self.service_namespace
    }
    fn route_hostname(&self) -> &str {
        &self.hostname
    }
    fn route_address(&self) -> &str {
        &self.address
    }
    fn route_port(&self) -> u16 {
        self.port
    }
    fn route_protocol(&self) -> &str {
        &self.protocol
    }
    fn route_allowed_services(&self) -> &[String] {
        &self.allowed_services
    }
    fn route_service_ports(&self) -> Vec<(&str, u16)> {
        self.service_ports
            .iter()
            .map(|(k, &v)| (k.as_str(), v))
            .collect()
    }
}

impl ClusterRoute {
    /// Validate a route for safety before it enters the route table.
    ///
    /// Returns `Err(reason)` if the route should be rejected. Used by both
    /// the heartbeat ingestion path (server.rs) and the local discovery path
    /// (route_reconciler.rs) to ensure identical validation regardless of source.
    pub fn validate(&self) -> Result<(), String> {
        // Address and port are required for externally routable routes but
        // optional for mesh-internal routes (advertise-only, no external gateway).
        // Consumers of mesh-internal routes use the service FQDN via Istio
        // multi-cluster, not the gateway address.
        let has_gateway = !self.address.is_empty() || self.port > 0;
        if has_gateway {
            if self.port == 0 {
                return Err("port is 0".to_string());
            }
            if self.address.is_empty() {
                return Err("empty address".to_string());
            }
        }
        if self.hostname.is_empty() {
            return Err("empty hostname".to_string());
        }
        // Block hostnames that look like URLs or internal K8s service names
        if self.hostname.contains("://")
            || self.hostname.ends_with(".svc.cluster.local")
            || self.hostname.contains(':')
        {
            return Err(format!(
                "invalid hostname '{}' (URL, internal K8s service, or contains port)",
                self.hostname
            ));
        }
        // Block dangerous IP addresses
        if let Ok(ip) = self.address.parse::<std::net::IpAddr>() {
            let dangerous = match ip {
                std::net::IpAddr::V4(v4) => {
                    v4.is_loopback()
                        || v4.is_unspecified()
                        || v4.is_link_local()
                        || v4.is_multicast()
                        || v4.is_broadcast()
                }
                std::net::IpAddr::V6(v6) => {
                    v6.is_loopback()
                        || v6.is_unspecified()
                        || v6.is_multicast()
                        || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local
                }
            };
            if dangerous {
                return Err(format!("dangerous address '{}'", self.address));
            }
        }
        // Block system namespace hijacking
        if crate::system_namespaces::is_system_namespace(&self.service_namespace)
            || self.service_namespace == crate::LATTICE_SYSTEM_NAMESPACE
        {
            return Err(format!(
                "cannot advertise in system namespace '{}'",
                self.service_namespace
            ));
        }
        // Validate service_ports: port values must be valid, names must be DNS labels,
        // and total count is bounded to prevent CRD bloat.
        const MAX_SERVICE_PORTS: usize = 100;
        if self.service_ports.len() > MAX_SERVICE_PORTS {
            return Err(format!(
                "too many service_ports ({}, max {})",
                self.service_ports.len(),
                MAX_SERVICE_PORTS
            ));
        }
        for (name, &port) in &self.service_ports {
            if port == 0 {
                return Err(format!("service_ports['{name}']: port is 0"));
            }
            lattice_core::validate_dns_label(name, "service_ports name")?;
        }
        Ok(())
    }
}

/// Status for LatticeClusterRoutes
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeClusterRoutesStatus {
    /// Current phase
    #[serde(default)]
    pub phase: ClusterRoutesPhase,

    /// Number of active routes
    #[serde(default)]
    pub route_count: u32,

    /// Last time the route table was updated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_updated: Option<String>,

    /// The generation observed by the controller.
    /// Used to detect out-of-band modifications to the spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// Phase of the cluster routes
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub enum ClusterRoutesPhase {
    /// Waiting for initial heartbeat with routes
    #[default]
    Pending,
    /// Routes synced from heartbeat
    Ready,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_route_roundtrip() {
        let route = ClusterRoute {
            service_name: "jellyfin".to_string(),
            service_namespace: "media".to_string(),
            hostname: "jellyfin.home.arpa".to_string(),
            address: "10.0.0.217".to_string(),
            port: 8096,
            protocol: "HTTP".to_string(),
            allowed_services: vec!["edge/edge/haproxy-fw".to_string()],
            service_ports: BTreeMap::from([("http".to_string(), 8096)]),
        };

        let json = serde_json::to_string(&route).unwrap();
        let parsed: ClusterRoute = serde_json::from_str(&json).unwrap();
        assert_eq!(route, parsed);
    }

    #[test]
    fn cluster_route_protocol_defaults_to_http() {
        let json = r#"{
            "serviceName": "api",
            "serviceNamespace": "default",
            "hostname": "api.example.com",
            "address": "10.0.0.1",
            "port": 80
        }"#;

        let route: ClusterRoute = serde_json::from_str(json).unwrap();
        assert_eq!(route.protocol, "HTTP");
    }

    #[test]
    fn cluster_routes_spec_empty_routes_default() {
        let json = r#"{}"#;
        let spec: LatticeClusterRoutesSpec = serde_json::from_str(json).unwrap();
        assert!(spec.routes.is_empty());
    }

    #[test]
    fn cluster_routes_status_defaults() {
        let status = LatticeClusterRoutesStatus::default();
        assert_eq!(status.phase, ClusterRoutesPhase::Pending);
        assert_eq!(status.route_count, 0);
        assert!(status.last_updated.is_none());
        assert!(status.observed_generation.is_none());
    }

    #[test]
    fn cluster_routes_status_with_observed_generation() {
        let status = LatticeClusterRoutesStatus {
            phase: ClusterRoutesPhase::Ready,
            route_count: 3,
            last_updated: Some("2026-03-14T00:00:00Z".to_string()),
            observed_generation: Some(5),
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("observedGeneration"));
        let parsed: LatticeClusterRoutesStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.observed_generation, Some(5));
    }
}
