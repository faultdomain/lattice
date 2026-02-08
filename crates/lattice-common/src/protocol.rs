//! Protocol types for agent-cell communication
//!
//! These types are shared between the agent (client) and cell (server)
//! for HTTP and gRPC-based operations.

use serde::{Deserialize, Serialize};

/// CSR signing request from agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrRequest {
    /// CSR in PEM format
    pub csr_pem: String,
}

/// CSR signing response with signed certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrResponse {
    /// Signed certificate in PEM format
    pub certificate_pem: String,
    /// CA certificate in PEM format (for verifying peer)
    pub ca_certificate_pem: String,
}

/// Resources distributed from parent cell to child clusters
///
/// Used during pivot to sync CloudProviders, SecretProviders, CedarPolicies,
/// OIDCProviders, and their referenced secrets from the parent to the child cluster.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DistributableResources {
    /// Serialized CloudProvider CRDs (JSON bytes)
    pub cloud_providers: Vec<Vec<u8>>,
    /// Serialized SecretProvider CRDs (JSON bytes)
    pub secrets_providers: Vec<Vec<u8>>,
    /// Serialized Secret resources (JSON bytes)
    pub secrets: Vec<Vec<u8>>,
    /// Serialized CedarPolicy CRDs (JSON bytes)
    pub cedar_policies: Vec<Vec<u8>>,
    /// Serialized OIDCProvider CRDs (JSON bytes)
    pub oidc_providers: Vec<Vec<u8>>,
}

impl DistributableResources {
    /// Check if there are no resources to distribute
    pub fn is_empty(&self) -> bool {
        self.cloud_providers.is_empty()
            && self.secrets_providers.is_empty()
            && self.secrets.is_empty()
            && self.cedar_policies.is_empty()
            && self.oidc_providers.is_empty()
    }
}
