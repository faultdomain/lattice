//! Lattice Kubernetes operator for multi-cluster lifecycle management

#![deny(missing_docs)]

/// Agent connectivity (outbound gRPC stream to parent cell)
pub mod agent;
/// Cell proxy backend for K8s API proxying through hierarchy
pub mod cell_proxy_backend;
/// Subtree event forwarder
pub mod forwarder;
/// Startup utilities (CRD install, infrastructure, recovery, cell service)
pub mod startup;
