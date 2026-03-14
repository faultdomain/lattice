//! LatticeClusterRoutes CRD — multi-cluster service route registry
//!
//! One per child cluster, reconciled by the cell from subtree registry data.
//! Contains service routes advertised by the child via heartbeat. Enables:
//!
//! - **DMZ proxy**: data plane adapters watch this CRD to route external traffic
//! - **Cross-cluster discovery**: siblings resolve dependencies across clusters
//! - **Observability**: operators see which services are available where

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
}

fn default_protocol() -> String {
    "HTTP".to_string()
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
