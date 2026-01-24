//! Common types for Lattice: CRDs, errors, and utilities

#![deny(missing_docs)]

pub mod clusterctl;
pub mod crd;
pub mod error;
pub mod fips;
pub mod graph;
pub mod kube_utils;
pub mod retry;
pub mod template;

pub use error::Error;

/// Result type alias using our custom Error type
pub type Result<T> = std::result::Result<T, Error>;

/// Default port for the bootstrap HTTPS server
pub const DEFAULT_BOOTSTRAP_PORT: u16 = 8443;

/// Default port for the gRPC server (agent-cell communication)
pub const DEFAULT_GRPC_PORT: u16 = 50051;

/// Namespace for Lattice system resources (CA, credentials, operator)
pub const LATTICE_SYSTEM_NAMESPACE: &str = "lattice-system";

/// Label key for resources that should be distributed to child clusters
pub const DISTRIBUTE_LABEL_KEY: &str = "lattice.io/distribute";

/// Label selector for distributable resources (for Kubernetes API queries)
pub const DISTRIBUTE_LABEL_SELECTOR: &str = "lattice.io/distribute=true";
