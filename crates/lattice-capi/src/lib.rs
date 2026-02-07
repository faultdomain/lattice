//! CAPI (Cluster API) management crate
//!
//! This crate provides:
//! - Provider trait and implementations for infrastructure providers (AWS, Docker, OpenStack, Proxmox)
//! - CAPIClient for managing CAPI resources (apply manifests, check readiness, scale pools)
//! - NativeInstaller for installing/upgrading CAPI providers from bundled manifests

pub mod client;
pub mod constants;
pub mod installer;
pub mod provider;
