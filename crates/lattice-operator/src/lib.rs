//! Lattice Kubernetes operator for multi-cluster lifecycle management

#![deny(missing_docs)]

pub mod agent;
pub mod bootstrap;
pub mod capi;
pub mod cilium;
pub mod compiler;
pub mod controller;
pub mod infra;
pub mod install;
pub mod parent;
pub mod pivot;
pub mod pki;
pub mod policy;
pub mod proto;
pub mod provider;
pub mod webhook;
pub mod workload;

// Re-export common types
pub use lattice_common::{
    crd, error, fips, graph, retry, template, Error, Result, DEFAULT_BOOTSTRAP_PORT,
    DEFAULT_GRPC_PORT,
};
