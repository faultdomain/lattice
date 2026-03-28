//! DNSProvider controller for Lattice
//!
//! Validates DNS provider configuration and credentials.
//! Updates DNSProvider status to Ready or Failed.

#![deny(missing_docs)]

mod dns_provider;

pub use dns_provider::reconcile;
