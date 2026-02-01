//! CAPI (Cluster API) management crate
//!
//! This crate provides:
//! - Provider trait and implementations for infrastructure providers (AWS, Docker, OpenStack, Proxmox)
//! - CAPIClient for managing CAPI resources (apply manifests, check readiness, scale pools)
//! - CapiInstaller for installing/upgrading CAPI providers via clusterctl

pub mod client;
pub mod installer;
pub mod provider;

// Re-export client types
pub use client::{CAPIClient, CAPIClientImpl};

#[cfg(test)]
pub use client::MockCAPIClient;

// Re-export installer types
pub use installer::{
    copy_credentials_to_provider_namespace, ensure_capi_installed, CapiInstaller,
    CapiProviderConfig, CapiProviderType, ClusterctlInstaller, DesiredProvider, InfraProviderInfo,
    InstalledProvider, ProviderAction,
};

#[cfg(test)]
pub use installer::MockCapiInstaller;

// Re-export provider types
pub use provider::{
    control_plane_name, create_provider, pool_resource_suffix, AwsProvider, BootstrapInfo,
    CAPIManifest, DockerProvider, ManifestMetadata, OpenStackProvider, Provider, ProxmoxProvider,
};
