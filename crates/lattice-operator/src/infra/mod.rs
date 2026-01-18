//! Infrastructure component manifest generation
//!
//! Provides manifest generators for infrastructure components that Lattice
//! manages on every cluster:
//!
//! - **Cilium**: CNI (deployed at bootstrap, reconciled by controller)
//! - **Istio Ambient**: Service mesh L4 (ztunnel for mTLS)
//! - **kgateway**: L7 proxy for ingress and waypoint (rate limiting, transforms)
//! - **Flux**: GitOps for self-management
//!
//! # Architecture
//!
//! Bootstrap uses these generators to deploy initial infrastructure.
//! The controller uses the SAME generators for day-2 reconciliation,
//! ensuring no drift between initial deployment and upgrades.
//!
//! # L7 Proxy Architecture
//!
//! kgateway replaces Istio's gateway and waypoint proxies:
//! - **North-South**: kgateway GatewayClass for ingress with rate limiting
//! - **East-West**: kgateway-waypoint GatewayClass for Istio Ambient L7
//!
//! # Version Pinning
//!
//! Component versions are pinned to the Lattice release. When Lattice
//! upgrades, the controller applies updated manifests automatically.

pub mod cilium;
pub mod flux;
pub mod istio;
pub mod kgateway;

pub use cilium::{
    cilium_version, generate_cilium_manifests, generate_default_deny,
    generate_operator_network_policy, generate_ztunnel_allowlist,
};
pub use flux::{generate_gitops_resources, FluxConfig, FluxReconciler, ResolvedGitCredentials};
pub use istio::{IstioConfig, IstioReconciler};
pub use kgateway::{KgatewayConfig, KgatewayReconciler};
