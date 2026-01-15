//! Infrastructure component manifest generation
//!
//! Provides manifest generators for infrastructure components that Lattice
//! manages on every cluster:
//!
//! - **Cilium**: CNI (deployed at bootstrap, reconciled by controller)
//! - **Istio**: Service mesh for mTLS and authorization policies
//! - **Flux**: GitOps for self-management
//!
//! # Architecture
//!
//! Bootstrap uses these generators to deploy initial infrastructure.
//! The controller uses the SAME generators for day-2 reconciliation,
//! ensuring no drift between initial deployment and upgrades.
//!
//! # Version Pinning
//!
//! Component versions are pinned to the Lattice release. When Lattice
//! upgrades, the controller applies updated manifests automatically.

pub mod cilium;
pub mod flux;
pub mod istio;

pub use cilium::{
    generate_default_deny, generate_operator_network_policy, generate_ztunnel_allowlist,
    CiliumConfig, CiliumReconciler,
};
pub use flux::{generate_gitops_resources, FluxConfig, FluxReconciler, ResolvedGitCredentials};
pub use istio::{IstioConfig, IstioReconciler};
