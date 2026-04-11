//! Lattice Custom Resource Definitions
//!
//! All CRD types used by the Lattice operator. Re-exported through
//! `lattice_common::crd` for backwards compatibility.
//!
//! Shared utilities (constants, error types, parsing) live in `lattice-core`
//! and are re-exported here for convenience.

pub mod crd;

// Re-export everything from lattice-core so CRD code can use `crate::*`
pub use lattice_core::*;
