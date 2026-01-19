//! Infrastructure component manifest generation
//!
//! Provides manifest generators for infrastructure components that Lattice
//! manages on every cluster:
//!
//! - **Cilium**: CNI (deployed at bootstrap, reconciled by controller)
//! - **Istio Ambient**: Service mesh (ztunnel for mTLS, waypoint for L7)
//! - **Flux**: GitOps for self-management
//! - **cert-manager**: Certificate management (CAPI dependency)
//! - **CAPI**: Cluster API providers for self-management
//!
//! # Architecture
//!
//! Bootstrap webhook generates ALL infrastructure manifests upfront.
//! This allows cert-manager, CAPI, Istio, and Flux to install
//! in parallel with the operator starting up.
//!
//! The operator "adopts" pre-installed components by checking if each
//! is already installed and skipping installation if so. This ensures:
//! - Faster cluster creation (parallel installation)
//! - No drift between bootstrap and day-2 reconciliation
//! - Single source of truth for manifest generation
//!
//! # Version Pinning
//!
//! Component versions are pinned to the Lattice release. When Lattice
//! upgrades, the controller applies updated manifests automatically.

pub mod bootstrap;
pub mod cilium;
pub mod flux;
pub mod istio;

pub use bootstrap::{generate_all as generate_infrastructure_manifests, InfrastructureConfig};
pub use cilium::{
    cilium_version, generate_cilium_manifests, generate_default_deny,
    generate_operator_network_policy, generate_ztunnel_allowlist,
};
pub use flux::{generate_gitops_resources, FluxConfig, FluxReconciler, ResolvedGitCredentials};
pub use istio::{IstioConfig, IstioReconciler};
