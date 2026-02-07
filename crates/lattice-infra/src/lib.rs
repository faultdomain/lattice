//! Infrastructure components for Lattice
//!
//! This crate provides shared infrastructure used by both cluster and service operators:
//!
//! - **PKI**: Certificate authority, certificate generation, CSR signing
//! - **Bootstrap**: Manifest generation for Cilium, Istio, Gateway API, ESO, Velero, etc.
//!
//! Note: cert-manager and CAPI providers are installed via the native CAPI installer,
//! which manages their lifecycle including upgrades.
//!
//! # Architecture
//!
//! The infrastructure components are designed to be stateless where possible,
//! with persistence handled at the operator level (e.g., CA secrets stored in K8s).
//!
//! # Public API
//!
//! ## Bootstrap
//! Access via `lattice_infra::bootstrap::*`:
//! - [`bootstrap::InfrastructureConfig`]: Configuration for infrastructure manifest generation
//! - [`bootstrap::IstioConfig`], [`bootstrap::IstioReconciler`]: Istio manifest generation
//! - [`bootstrap::cilium`]: Cilium manifests and network policy generators
//! - [`bootstrap::eso`]: External Secrets Operator manifests
//! - [`bootstrap::generate_core`]: Top-level generator
//!
//! ## PKI
//! - [`pki::CertificateAuthority`]: CA operations for signing CSRs
//! - [`pki::PkiError`]: Error type for PKI operations
//!
//! ## mTLS
//! - [`mtls::ServerMtlsConfig`], [`mtls::ClientMtlsConfig`]: TLS configuration for gRPC
//! - [`mtls::MtlsError`]: Error type for mTLS operations

pub mod bootstrap;
pub mod mtls;
pub mod pki;
pub mod system_namespaces;

// Re-export mTLS types (commonly used across many crates)
pub use mtls::{
    extract_cluster_id_from_cert, verify_cert_chain, ClientMtlsConfig, MtlsError, ServerMtlsConfig,
};
