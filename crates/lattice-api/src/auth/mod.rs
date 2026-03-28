//! Authentication module
//!
//! Provides OIDC and ServiceAccount token validation with helpers
//! for extracting authenticated user identity from requests.

mod authorize;
mod oidc;
/// OIDCProvider validation controller
pub mod oidc_controller;

pub use authorize::{authenticate, authenticate_and_authorize, extract_bearer_token};
pub use oidc::{from_crd as oidc_from_crd, OidcConfig, OidcValidator, UserIdentity};
