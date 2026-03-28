//! CertIssuer controller for Lattice
//!
//! Validates certificate issuer configuration and dependencies (secrets,
//! DNSProvider refs). Updates CertIssuer status to Ready or Failed.

#![deny(missing_docs)]

mod controller;

pub use controller::reconcile;
