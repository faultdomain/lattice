//! Provider-specific configuration types for infrastructure provisioning.
//!
//! Each provider module contains the configuration struct for its respective
//! Cluster API provider:
//! - CAPA (AWS)
//! - CAPO (OpenStack)
//! - CAPMOX (Proxmox)
//! - CAPD (Docker/Kind) - local development only

mod aws;
mod docker;
mod openstack;
mod proxmox;

pub use aws::AwsConfig;
pub use docker::DockerConfig;
pub use openstack::OpenstackConfig;
pub use proxmox::ProxmoxConfig;
