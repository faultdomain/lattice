//! CloudProvider controller for Lattice
//!
//! This controller watches CloudProvider CRDs and:
//! - Validates cloud credentials
//! - Updates CloudProvider status
//! - (Future) Manages cloud-specific resources

#![deny(missing_docs)]

mod controller;

pub use controller::reconcile;
