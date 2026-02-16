//! Cedar policy engine for Lattice authorization
//!
//! Provides fine-grained access control using Cedar policies loaded from CRDs.
//! Used by both `lattice-api` (cluster access) and `lattice-service` (secret + security access).
//!
//! # Entity Model
//!
//! ```text
//! Lattice::User::"alice@example.com"                (principal)
//! Lattice::Group::"admins"                          (principal)
//! Lattice::Service::"payments/checkout"             (principal — namespace/name)
//! Lattice::Action::"AccessCluster"                  (action)
//! Lattice::Action::"AccessSecret"                   (action)
//! Lattice::Action::"AccessVolume"                   (action)
//! Lattice::Action::"OverrideSecurity"               (action)
//! Lattice::Cluster::"prod"                          (resource)
//! Lattice::SecretPath::"vault-prod:db/creds"        (resource — provider:path)
//! Lattice::SecurityOverride::"capability:NET_ADMIN" (resource — override id)
//! Lattice::Volume::"media/media-storage"            (resource — namespace/volume_id)
//! ```

#![deny(missing_docs)]

mod engine;
mod entities;
mod mesh_auth;
mod secret_auth;
mod security_auth;
mod volume_auth;

pub use engine::{ClusterAttributes, DenialReason, Error, PolicyEngine};
pub use mesh_auth::{MeshWildcardRequest, MeshWildcardResult, WildcardDirection};
pub use secret_auth::{SecretAuthzRequest, SecretAuthzResult, SecretDenial};
pub use security_auth::{
    SecurityAuthzRequest, SecurityAuthzResult, SecurityDenial, SecurityOverrideRequest,
};
pub use volume_auth::{VolumeAuthzRequest, VolumeAuthzResult, VolumeDenial};
