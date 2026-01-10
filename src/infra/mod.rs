//! Infrastructure component manifest generation
//!
//! Provides manifest generators for infrastructure components that Lattice
//! manages on every cluster:
//!
//! - **Cilium**: CNI (deployed at bootstrap, reconciled by controller)
//! - **Istio**: Service mesh for mTLS and authorization policies
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
pub mod istio;

pub use cilium::{generate_operator_network_policy, CiliumConfig, CiliumReconciler};
pub use istio::{IstioConfig, IstioReconciler};
