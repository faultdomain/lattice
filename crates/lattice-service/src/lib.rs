//! Service workload compilation and controller for Lattice
//!
//! This crate compiles LatticeService CRDs into Kubernetes workload resources:
//!
//! - **Compiler**: Compiles LatticeService CRDs to Deployments, Services, MeshMembers, etc.
//! - **Workload**: Generates Deployments, Services, PVCs, and related resources
//! - **Controller**: Kubernetes controller for LatticeService/ExternalService CRDs

pub mod compiler;
pub mod controller;
pub mod workload;

// Bridge lattice_common types into this crate's namespace.
// Internal modules use `crate::crd`, `crate::graph`, etc.
pub(crate) use lattice_common::{crd, graph, Error};
