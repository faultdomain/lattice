//! Cedar authorization engine for Lattice service mesh
//!
//! This crate provides Cedar policy evaluation as an Envoy ext_authz gRPC service.
//! It adds user-to-resource authorization (via OIDC/JWT + Cedar policies) on top of
//! the existing service-to-service authorization (Cilium L4 + Istio L7).
//!
//! ## Architecture
//!
//! ```text
//! Request -> Cilium L4 -> Istio L7 (mTLS) -> Cedar ExtAuth (this) -> Service
//!                                                   |
//!                                                   +-- JWT validation (OIDC)
//!                                                   +-- Cedar policy evaluation
//! ```
//!
//! ## Integration
//!
//! This crate is used by `lattice-operator` when `--enable-cedar-authz` is set.
//! The operator starts the ExtAuth gRPC server alongside the other controllers.
//!
//! ## Example Policy
//!
//! ```cedar
//! // Allow admin role to access anything
//! permit(
//!     principal,
//!     action,
//!     resource
//! ) when {
//!     principal.roles.contains("admin")
//! };
//!
//! // Deny access to /admin paths for non-admins
//! forbid(
//!     principal,
//!     action,
//!     resource
//! ) when {
//!     resource.path.startsWith("/admin") &&
//!     !principal.roles.contains("admin")
//! };
//! ```

#![deny(missing_docs)]

pub mod controller;
pub mod entity;
pub mod jwt;
pub mod metrics;
pub mod policy;
pub mod server;

mod error;

pub use controller::{error_policy, reconcile, Context};
pub use entity::{Action, EntityBuilder, Principal, Resource};
pub use error::{CedarError, Result};
pub use jwt::{JwksCache, JwtValidator};
pub use policy::{PolicyCompiler, PolicyStore};
pub use server::CedarAuthzServer;

/// Default port for the Cedar ExtAuth gRPC server
pub const DEFAULT_CEDAR_GRPC_PORT: u16 = 50052;
