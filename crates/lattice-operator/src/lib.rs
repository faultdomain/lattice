//! Lattice Kubernetes operator for multi-cluster lifecycle management

#![deny(missing_docs)]

// Startup and agent modules for main.rs
pub mod agent;
pub mod startup;

// Re-export cell modules from lattice-cell
pub use lattice_cell::bootstrap;
pub use lattice_cell::parent;

// Re-export CAPI from lattice-capi
pub use lattice_capi as capi;

// Re-export provider controllers
pub use lattice_cloud_provider as cloud_provider;
pub use lattice_secrets_provider as secrets_provider;

// Re-export controllers - these need to stay local as they orchestrate everything
pub mod controller;

// Re-export infrastructure modules from lattice-infra
pub mod infra;

// Re-export common types
pub use lattice_common::{
    crd, error, fips, graph, retry, template, Error, Result, DEFAULT_BOOTSTRAP_PORT,
    DEFAULT_GRPC_PORT,
};
