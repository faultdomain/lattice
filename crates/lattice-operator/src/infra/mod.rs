//! Infrastructure component manifest generation
//!
//! Provides manifest generators for infrastructure components that Lattice
//! manages on every cluster:
//!
//! - **Cilium**: CNI (deployed at bootstrap, reconciled by controller)
//! - **Istio Ambient**: Service mesh (ztunnel for mTLS, waypoint for L7)
//! - **cert-manager**: Certificate management (CAPI dependency)
//! - **CAPI**: Cluster API providers for self-management
//!
//! # Architecture
//!
//! Bootstrap webhook generates ALL infrastructure manifests upfront.
//! This allows cert-manager, CAPI, and Istio to install in parallel
//! with the operator starting up.
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
pub mod istio;

pub use bootstrap::{generate_all as generate_infrastructure_manifests, InfrastructureConfig};
pub use cilium::{
    cilium_version, generate_cilium_manifests, generate_default_deny,
    generate_operator_network_policy, generate_waypoint_egress_policy, generate_ztunnel_allowlist,
};
pub use istio::{IstioConfig, IstioReconciler};

/// Split a multi-document YAML string into individual documents.
///
/// Filters out empty documents and documents without a `kind:` field.
/// Normalizes output to always have `---` prefix for kubectl apply compatibility.
pub fn split_yaml_documents(yaml: &str) -> Vec<String> {
    yaml.split("\n---")
        .map(|doc| doc.trim())
        .filter(|doc| !doc.is_empty() && doc.contains("kind:"))
        .map(|doc| {
            if doc.starts_with("---") {
                doc.to_string()
            } else {
                format!("---\n{}", doc)
            }
        })
        .collect()
}
