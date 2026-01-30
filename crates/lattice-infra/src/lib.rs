//! Infrastructure components for Lattice
//!
//! This crate provides shared infrastructure used by both cluster and service operators:
//!
//! - **PKI**: Certificate authority, certificate generation, CSR signing
//! - **Bootstrap**: Manifest generation for Cilium, Istio, Gateway API
//!
//! Note: cert-manager and CAPI providers are installed via `clusterctl init`,
//! which manages their lifecycle including upgrades.
//!
//! # Architecture
//!
//! The infrastructure components are designed to be stateless where possible,
//! with persistence handled at the operator level (e.g., CA secrets stored in K8s).

pub mod bootstrap;
pub mod mtls;
pub mod pki;
pub mod system_namespaces;

// Re-export main types
pub use bootstrap::cilium::{
    cilium_version, generate_cilium_manifests, generate_default_deny,
    generate_operator_network_policy, generate_waypoint_egress_policy, generate_ztunnel_allowlist,
};
pub use bootstrap::eso::generate_eso;
pub use bootstrap::{
    generate_all, generate_core, generate_gateway_api_crds, generate_istio, split_yaml_documents,
    InfrastructureConfig, IstioConfig, IstioReconciler,
};
pub use mtls::{
    extract_cluster_id_from_cert, verify_cert_chain, ClientMtlsConfig, MtlsError, ServerMtlsConfig,
};
pub use pki::{CertificateAuthority, PkiError};
