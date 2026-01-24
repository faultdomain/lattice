//! Infrastructure provider types for E2E tests
//!
//! Provider types are used as hints for test behavior (e.g., which verification
//! steps to run). Actual cluster configuration comes from LatticeCluster CRD files.

#![cfg(feature = "provider-e2e")]

use lattice_operator::crd::ProviderType;

/// Supported infrastructure providers
///
/// Used as hints for test behavior - the actual configuration comes from CRD files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfraProvider {
    Docker,
    Aws,
    OpenStack,
    Proxmox,
}

impl From<ProviderType> for InfraProvider {
    fn from(pt: ProviderType) -> Self {
        match pt {
            ProviderType::Docker => Self::Docker,
            ProviderType::Aws => Self::Aws,
            ProviderType::OpenStack => Self::OpenStack,
            ProviderType::Proxmox => Self::Proxmox,
            ProviderType::Gcp | ProviderType::Azure => Self::Aws, // Treat as cloud provider
        }
    }
}

impl std::fmt::Display for InfraProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Docker => "docker",
            Self::Aws => "aws",
            Self::OpenStack => "openstack",
            Self::Proxmox => "proxmox",
        };
        write!(f, "{}", name)
    }
}
