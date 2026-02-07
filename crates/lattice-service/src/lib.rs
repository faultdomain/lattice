//! Service mesh management for Lattice
//!
//! This crate provides service graph compilation and policy generation:
//!
//! - **Compiler**: Compiles LatticeService CRDs to Kubernetes resources
//! - **Policy**: Generates Cilium and Istio network policies
//! - **Workload**: Generates Deployments, Services, PVCs, and related resources
//! - **Ingress**: Gateway API and waypoint configuration
//! - **Controller**: Kubernetes controller for LatticeService/ExternalService CRDs

pub mod compiler;
pub mod controller;
pub mod ingress;
pub mod policy;
pub mod policy_controller;
pub mod workload;

// Bridge lattice_common types into this crate's namespace.
// Internal modules use `crate::crd`, `crate::graph`, etc.
pub(crate) use lattice_common::{crd, graph, Error};
