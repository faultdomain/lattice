//! Istio ServiceEntry types
//!
//! Types for generating Istio ServiceEntry resources for external service
//! mesh integration (registering external services with the mesh).

use serde::{Deserialize, Serialize};

use crate::kube_utils::{HasApiResource, ObjectMeta};

/// Istio ServiceEntry for external service mesh integration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEntry {
    /// API version
    #[serde(default = "ServiceEntry::api_version")]
    pub api_version: String,
    /// Kind
    #[serde(default = "ServiceEntry::kind")]
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: ServiceEntrySpec,
}

impl HasApiResource for ServiceEntry {
    const API_VERSION: &'static str = "networking.istio.io/v1";
    const KIND: &'static str = "ServiceEntry";
}

crate::impl_api_resource_defaults!(ServiceEntry);

impl ServiceEntry {
    /// Create a new ServiceEntry
    pub fn new(metadata: ObjectMeta, spec: ServiceEntrySpec) -> Self {
        Self {
            api_version: Self::api_version(),
            kind: Self::kind(),
            metadata,
            spec,
        }
    }
}

/// ServiceEntry spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceEntrySpec {
    /// Hosts (DNS names)
    pub hosts: Vec<String>,
    /// Endpoints for STATIC resolution
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<ServiceEntryEndpoint>,
    /// Ports
    pub ports: Vec<ServiceEntryPort>,
    /// Location: MESH_EXTERNAL or MESH_INTERNAL
    pub location: String,
    /// Resolution: DNS, STATIC, NONE
    pub resolution: String,
}

/// ServiceEntry endpoint for STATIC resolution
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceEntryEndpoint {
    /// IP address of the endpoint
    pub address: String,
}

/// ServiceEntry port
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceEntryPort {
    /// Port number
    pub number: u16,
    /// Port name
    pub name: String,
    /// Protocol (HTTP, HTTPS, TCP, GRPC)
    pub protocol: String,
}
