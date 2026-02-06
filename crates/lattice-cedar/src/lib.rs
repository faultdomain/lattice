//! Cedar policy engine for Lattice authorization
//!
//! Provides fine-grained access control using Cedar policies loaded from CRDs.
//! Used by both `lattice-api` (cluster access) and `lattice-service` (secret access).
//!
//! # Entity Model
//!
//! ```text
//! Lattice::User::"alice@example.com"          (principal)
//! Lattice::Group::"admins"                    (principal)
//! Lattice::Service::"payments/checkout"       (principal — namespace/name)
//! Lattice::Action::"AccessCluster"            (action)
//! Lattice::Action::"AccessSecret"             (action)
//! Lattice::Cluster::"prod"                    (resource)
//! Lattice::SecretPath::"vault-prod:db/creds"  (resource — provider:path)
//! ```

#![deny(missing_docs)]

mod engine;
mod entities;
mod secret_auth;

pub use engine::{ClusterAttributes, Error, PolicyEngine};
pub use secret_auth::{DenialReason, SecretAuthzRequest, SecretAuthzResult, SecretDenial};
