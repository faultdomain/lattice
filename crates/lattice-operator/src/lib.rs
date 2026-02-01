//! Lattice Kubernetes operator for multi-cluster lifecycle management

#![deny(missing_docs)]

// Startup and agent modules for main.rs
pub mod agent;
pub mod startup;

// Re-export cell modules from lattice-cell
pub use lattice_cell::bootstrap;
pub use lattice_cell::cilium;
pub use lattice_cell::parent;

// Re-export from lattice-capi
pub use lattice_capi::provider;

// Re-export pivot from lattice-agent
pub use lattice_agent::pivot;

// Re-export CAPI from lattice-capi
pub use lattice_capi as capi;

// Re-export provider controllers
pub use lattice_cloud_provider as cloud_provider;
pub use lattice_secrets_provider as secrets_provider;

// Re-export controllers - these need to stay local as they orchestrate everything
pub mod controller;

// Re-export infrastructure modules from lattice-infra
pub mod infra;
pub use lattice_infra::pki;

// Re-export proto from lattice-proto
pub use lattice_proto as proto;

// Re-export common types
pub use lattice_common::{
    crd, error, fips, graph, retry, template, Error, Result, DEFAULT_BOOTSTRAP_PORT,
    DEFAULT_GRPC_PORT,
};
