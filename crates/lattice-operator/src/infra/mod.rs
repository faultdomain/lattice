//! Infrastructure component manifest generation
//!
//! Re-exports from lattice-infra crate for infrastructure manifest generation.

// Re-export from lattice-infra
pub use lattice_infra::bootstrap;
pub use lattice_infra::bootstrap::cilium;
pub use lattice_infra::bootstrap::istio;

pub use lattice_infra::{
    generate_all, generate_capi, generate_certmanager, generate_cilium_manifests, generate_core,
    generate_default_deny, generate_gateway_api_crds, generate_operator_network_policy,
    generate_waypoint_egress_policy, generate_ztunnel_allowlist, split_yaml_documents,
    InfrastructureConfig, IstioConfig, IstioReconciler,
};

// Alias for backwards compatibility
pub use lattice_infra::generate_all as generate_infrastructure_manifests;

// Re-export cilium_version if needed
pub use lattice_infra::cilium_version;
