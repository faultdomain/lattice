//! Docker/Kind provider configuration (CAPD)
//!
//! This provider is for local development and testing only.
//! It uses the Cluster API Provider for Docker (CAPD).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Docker/Kind provider configuration
///
/// Docker provider uses sensible defaults for local development and testing.
/// The only configurable field is `lb_cidr` for Cilium LB-IPAM.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DockerConfig {
    /// CIDR block for Cilium LB-IPAM (e.g., "172.18.255.0/28")
    ///
    /// Allocates IPs from the kind bridge network for LoadBalancer services.
    /// Required for parent clusters that need a stable LoadBalancer IP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lb_cidr: Option<String>,
}
