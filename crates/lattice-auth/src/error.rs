//! Authentication error types
//!
//! Shared across all Lattice services. Each service maps these to its own
//! HTTP error format (K8s Status for lattice-api, ApiErrorBody for lattice-console).

/// Authentication error
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Token is missing, expired, or invalid
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Auth system misconfiguration (missing OIDC provider, bad JWKS, etc.)
    #[error("auth config error: {0}")]
    Config(String),

    /// Transient failure (network, DNS, etc.)
    #[error("auth internal error: {0}")]
    Internal(String),
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        AuthError::Unauthorized(e.to_string())
    }
}
