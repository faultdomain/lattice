//! Provider-specific configuration types for infrastructure provisioning.
//!
//! Each provider module contains the configuration struct for its respective
//! Cluster API provider:
//! - CAPD (Docker/Kind) - local development only
//! - CAPMOX (Proxmox) - on-premises virtualization
//! - CAPO (OpenStack) - private/public cloud

mod docker;
mod openstack;
mod proxmox;

pub use docker::DockerConfig;
pub use openstack::OpenStackConfig;
pub use proxmox::{Ipv4PoolConfig, Ipv6PoolConfig, ProxmoxConfig};
