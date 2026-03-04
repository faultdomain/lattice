//! InfraProvider controller for Lattice
//!
//! This controller watches InfraProvider CRDs and:
//! - Validates cloud credentials
//! - Updates InfraProvider status
//! - (Future) Manages cloud-specific resources

#![deny(missing_docs)]

mod controller;

pub use controller::reconcile;
