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

// Re-export key types
pub use compiler::{CompileError, CompiledService, ServiceCompiler};
pub use controller::{
    error_policy as service_error_policy, error_policy_external, reconcile as service_reconcile,
    reconcile_external, ServiceContext,
};
pub use policy::{AuthorizationPolicy, CiliumNetworkPolicy, PolicyCompiler};
pub use workload::WorkloadCompiler;

// Re-export from dependencies
pub use lattice_common::{crd, error, graph, Error, Result};
