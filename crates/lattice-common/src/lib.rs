//! Common types for Lattice: CRDs, errors, and utilities

#![deny(missing_docs)]

pub mod clusterctl;
pub mod crd;
pub mod credentials;
pub mod error;
pub mod fips;
pub mod graph;
pub mod kube_utils;
pub mod protocol;
pub mod retry;
pub mod template;

pub use credentials::{AwsCredentials, CredentialError};
pub use error::Error;
pub use protocol::{CsrRequest, CsrResponse, DistributableResources};

/// Result type alias using our custom Error type
pub type Result<T> = std::result::Result<T, Error>;

/// Default port for the bootstrap HTTPS server
pub const DEFAULT_BOOTSTRAP_PORT: u16 = 8443;

/// Default port for the gRPC server (agent-cell communication)
pub const DEFAULT_GRPC_PORT: u16 = 50051;

/// Namespace for Lattice system resources (CA, credentials, operator)
pub const LATTICE_SYSTEM_NAMESPACE: &str = "lattice-system";

// CAPI provider namespaces
/// Target namespace for CAPA (AWS) provider
pub const CAPA_NAMESPACE: &str = "capa-system";
/// Target namespace for CAPMOX (Proxmox) provider
pub const CAPMOX_NAMESPACE: &str = "capmox-system";
/// Target namespace for CAPO (OpenStack) provider
pub const CAPO_NAMESPACE: &str = "capo-system";

// CAPI provider credential secret names
/// Secret name for Proxmox credentials
pub const PROXMOX_CREDENTIALS_SECRET: &str = "proxmox-credentials";
/// Secret name for AWS credentials
pub const AWS_CREDENTIALS_SECRET: &str = "aws-credentials";
/// Secret name for OpenStack credentials
pub const OPENSTACK_CREDENTIALS_SECRET: &str = "openstack-cloud-config";
