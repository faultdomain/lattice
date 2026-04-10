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
    /// One-time CSR token issued during bootstrap (authenticates the request)
    pub csr_token: String,
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
/// Used during pivot to sync InfraProviders, SecretProviders, ImageProviders,
/// CedarPolicies, OIDCProviders, and their referenced secrets from the parent
/// to the child cluster.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DistributableResources {
    /// Serialized InfraProvider CRDs (JSON bytes)
    pub cloud_providers: Vec<Vec<u8>>,
    /// Serialized SecretProvider CRDs (JSON bytes)
    pub secrets_providers: Vec<Vec<u8>>,
    /// Serialized Secret resources (JSON bytes)
    pub secrets: Vec<Vec<u8>>,
    /// Serialized CedarPolicy CRDs (JSON bytes)
    pub cedar_policies: Vec<Vec<u8>>,
    /// Serialized OIDCProvider CRDs (JSON bytes)
    pub oidc_providers: Vec<Vec<u8>>,
    /// Serialized ImageProvider CRDs (JSON bytes)
    pub image_providers: Vec<Vec<u8>>,
    /// Serialized LatticePackage CRDs (JSON bytes)
    pub packages: Vec<Vec<u8>>,
}

impl DistributableResources {
    /// Check if there are no resources to distribute
    pub fn is_empty(&self) -> bool {
        self.cloud_providers.is_empty()
            && self.secrets_providers.is_empty()
            && self.secrets.is_empty()
            && self.cedar_policies.is_empty()
            && self.oidc_providers.is_empty()
            && self.image_providers.is_empty()
            && self.packages.is_empty()
    }

    /// Total number of resources across all categories
    pub fn total_count(&self) -> usize {
        self.cloud_providers.len()
            + self.secrets_providers.len()
            + self.secrets.len()
            + self.cedar_policies.len()
            + self.oidc_providers.len()
            + self.image_providers.len()
            + self.packages.len()
    }

    /// Convert all resources to JSON strings, skipping any that aren't valid UTF-8.
    ///
    /// Order: secrets first (credentials needed by providers), then providers,
    /// then policies.
    pub fn into_json_strings(self) -> Vec<String> {
        let all_bytes = [
            self.secrets,
            self.cloud_providers,
            self.secrets_providers,
            self.image_providers,
            self.cedar_policies,
            self.oidc_providers,
            self.packages,
        ];
        all_bytes
            .into_iter()
            .flatten()
            .filter_map(|bytes| String::from_utf8(bytes).ok())
            .collect()
    }
}
