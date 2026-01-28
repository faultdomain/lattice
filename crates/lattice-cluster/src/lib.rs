//! Cluster lifecycle management for Lattice
//!
//! This crate provides the Kubernetes controller for LatticeCluster CRDs.
//!
//! Related crates:
//! - `lattice-cell`: Parent cluster infrastructure (servers, connections)
//! - `lattice-agent`: Child cluster runtime (agent client)
//! - `lattice-capi`: CAPI provider management and client

pub mod controller;

// Re-export controller types
pub use controller::{
    error_policy, reconcile, Context, ContextBuilder, KubeClient, KubeClientImpl, PivotOperations,
    PivotOperationsImpl,
};

// Re-export CAPI types from lattice-capi
pub use lattice_capi::{create_provider, CAPIClient, CAPIClientImpl, CAPIManifest, Provider};

// Re-export common error types
pub use lattice_common::{Error, Result};
