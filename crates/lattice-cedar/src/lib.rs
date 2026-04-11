//! Cedar policy engine for Lattice RBAC/ABAC authorization
//!
//! Provides fine-grained access control using Cedar policies loaded from CRDs.
//! Used for both infrastructure authorization (workload compilation) and API
//! route authorization (frontend-to-backend auth).
//!
//! # Entity Model
//!
//! ## Principals
//!
//! ```text
//! Lattice::User::"alice@example.com"                (human user)
//! Lattice::Group::"admins"                          (user group)
//! Lattice::Service::"payments/checkout"             (workload — namespace/name)
//!   attrs: namespace, name, kind ("service", "job", "model")
//! ```
//!
//! ## Actions
//!
//! ```text
//! Lattice::Action::"AccessCluster"                  (cluster access)
//! Lattice::Action::"AccessSecret"                   (secret path access)
//! Lattice::Action::"AccessVolume"                   (shared volume access)
//! Lattice::Action::"AccessExternalEndpoint"         (external endpoint access)
//! Lattice::Action::"OverrideSecurity"               (security override)
//! Lattice::Action::"AllowWildcard"                  (mesh wildcard)
//! Lattice::Action::"<any>"                          (actions are open — define as needed)
//! ```
//!
//! ## Resources
//!
//! ```text
//! Lattice::Cluster::"prod"                          (cluster)
//! Lattice::ApiRoute::"GET:/api/v1/endpoints"        (API route — method:path)
//! Lattice::ExternalEndpoint::"api.stripe.com:443"   (external endpoint — host:port)
//! Lattice::SecretPath::"vault-prod:db/creds"        (secret — provider:path)
//! Lattice::SecurityOverride::"capability:NET_ADMIN" (security override)
//! Lattice::Volume::"media/media-storage"            (shared volume — namespace/id)
//! Lattice::Mesh::"inbound"                          (mesh wildcard direction)
//! ```

#![deny(missing_docs)]

mod context;
mod engine;
/// Cedar entity builders for constructing principals, actions, and resources.
pub mod entities;
mod external_endpoint_auth;
mod image_auth;
mod mesh_auth;
mod secret_auth;
mod security_auth;
mod volume_auth;

pub use context::AuthContext;
pub use engine::{ClusterAttributes, DenialReason, Error, PolicyEngine};
pub use entities::{
    build_api_route_entity, build_entity_uid, build_service_entity, build_user_entity,
};
pub use external_endpoint_auth::{
    ExternalEndpointAuthzRequest, ExternalEndpointAuthzResult, ExternalEndpointDenial,
};
pub use mesh_auth::{MeshWildcardRequest, MeshWildcardResult, WildcardDirection};
pub use secret_auth::{SecretAuthzRequest, SecretAuthzResult, SecretDenial};
pub use security_auth::{
    SecurityAuthzRequest, SecurityAuthzResult, SecurityDenial, SecurityOverrideRequest,
};
pub use image_auth::{ImageDenial, ImageVerifyRequest, ImageVerifyResult};
pub use volume_auth::{VolumeAuthzRequest, VolumeAuthzResult, VolumeDenial};
