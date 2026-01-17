//! Provider-specific configuration types for infrastructure provisioning.
//!
//! Each provider module contains the configuration struct for its respective
//! Cluster API provider:
//! - CAPMOX (Proxmox)
//! - CAPD (Docker/Kind) - local development only

mod docker;
mod proxmox;

pub use docker::DockerConfig;
pub use proxmox::ProxmoxConfig;
