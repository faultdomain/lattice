//! Lattice Kubernetes operator for multi-cluster lifecycle management

#![deny(missing_docs)]

// Re-export cluster modules from lattice-cluster
pub use lattice_cluster::agent;
pub use lattice_cluster::bootstrap;
pub use lattice_cluster::capi;
pub use lattice_cluster::cilium;
pub use lattice_cluster::parent;
pub use lattice_cluster::pivot;
pub use lattice_cluster::provider;

// Re-export service modules from lattice-service
pub use lattice_service::compiler;
pub use lattice_service::ingress;
pub use lattice_service::policy;
pub use lattice_service::webhook;
pub use lattice_service::workload;

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
