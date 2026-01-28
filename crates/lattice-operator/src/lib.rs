//! Lattice Kubernetes operator for multi-cluster lifecycle management

#![deny(missing_docs)]

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

// Re-export crash-resilient cleanup functions
pub use lattice_agent::cleanup_stale_pivot_secrets;
pub use lattice_cell::cleanup_stale_unpivot_secrets;

// Re-export service modules from lattice-service
pub use lattice_service::compiler;
pub use lattice_service::ingress;
pub use lattice_service::policy;
pub use lattice_service::workload;

// Re-export provider controllers
pub use lattice_cloud_provider as cloud_provider;
pub use lattice_secrets_provider as secrets_provider;

// Re-export Cedar authorization
pub use lattice_cedar as cedar;

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
