//! Infrastructure components for Lattice
//!
//! This crate provides shared infrastructure used by both cluster and service operators:
//!
//! - **PKI**: Certificate authority, certificate generation, CSR signing
//! - **Bootstrap**: Manifest generation for Cilium, Istio, cert-manager, CAPI
//!
//! # Architecture
//!
//! The infrastructure components are designed to be stateless where possible,
//! with persistence handled at the operator level (e.g., CA secrets stored in K8s).

pub mod bootstrap;
pub mod pki;

// Re-export main types
pub use bootstrap::cilium::{
    cilium_version, generate_cilium_manifests, generate_default_deny,
    generate_operator_network_policy, generate_waypoint_egress_policy, generate_ztunnel_allowlist,
};
pub use bootstrap::{
    generate_all, generate_capi, generate_certmanager, generate_core, generate_gateway_api_crds,
    generate_istio, split_yaml_documents, InfrastructureConfig, IstioConfig, IstioReconciler,
};
pub use pki::{CertificateAuthority, PkiError};
