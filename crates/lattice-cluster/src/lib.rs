//! Cluster lifecycle management for Lattice
//!
//! This crate provides Kubernetes cluster provisioning and management:
//!
//! - **Provider**: Infrastructure providers (Docker, Proxmox, AWS, OpenStack)
//! - **CAPI**: Cluster API integration for cluster lifecycle
//! - **Agent**: gRPC agent for parent-child cluster communication
//! - **Pivot**: CAPI resource transfer for self-management
//! - **Controller**: Kubernetes controller for LatticeCluster CRD

pub mod agent;
pub mod bootstrap;
pub mod capi;
pub mod cilium;
pub mod controller;
pub mod parent;
pub mod pivot;
pub mod provider;

// Re-export key types
pub use agent::client::{AgentClient, AgentClientConfig};
pub use bootstrap::{
    BootstrapState, ClusterRegistration, DefaultManifestGenerator, ManifestGenerator,
};
pub use capi::{CapiInstaller, CapiProviderConfig};
pub use controller::{error_policy, reconcile, Context};
pub use parent::ParentServers;
pub use provider::{create_provider, CAPIManifest, Provider};

// Re-export from dependencies
pub use lattice_common::{crd, error, Error, Result, DEFAULT_BOOTSTRAP_PORT, DEFAULT_GRPC_PORT};
pub use lattice_infra::{CertificateAuthority, PkiError};
