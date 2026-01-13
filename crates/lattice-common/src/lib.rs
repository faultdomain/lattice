//! Common types for Lattice: CRDs, errors, and utilities

#![deny(missing_docs)]

pub mod crd;
pub mod error;
pub mod fips;
pub mod graph;
pub mod retry;
pub mod template;

pub use error::Error;

/// Result type alias using our custom Error type
pub type Result<T> = std::result::Result<T, Error>;

/// Default port for the bootstrap HTTPS server
pub const DEFAULT_BOOTSTRAP_PORT: u16 = 8443;

/// Default port for the gRPC server (agent-cell communication)
pub const DEFAULT_GRPC_PORT: u16 = 50051;
