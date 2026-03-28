//! Shared authentication primitives for Lattice services
//!
//! This crate contains auth logic shared between lattice-api (K8s auth proxy)
//! and lattice-console (product API). Service-specific adapters (CRD loading,
//! API key validation, ServiceAccount TokenReview) live in their respective crates.

pub mod bearer;
pub mod error;
pub mod identity;
pub mod oidc;

pub use bearer::extract_bearer_token;
pub use error::AuthError;
pub use identity::{AuthMethod, Identity};
pub use oidc::{OidcConfig, OidcValidator};
