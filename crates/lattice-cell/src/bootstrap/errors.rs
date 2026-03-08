//! Bootstrap endpoint error types

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use lattice_infra::pki::PkiError;
use thiserror::Error;

/// Bootstrap endpoint errors
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// Invalid or expired token
    #[error("invalid or expired token")]
    InvalidToken,

    /// Token already used
    #[error("token already used")]
    TokenAlreadyUsed,

    /// Cluster not found
    #[error("cluster not found: {0}")]
    ClusterNotFound(String),

    /// Missing authorization header
    #[error("missing authorization header")]
    MissingAuth,

    /// CSR signing error
    #[error("CSR signing failed: {0}")]
    CsrSigningFailed(String),

    /// Cluster not bootstrapped yet
    #[error("cluster not bootstrapped: {0}")]
    ClusterNotBootstrapped(String),

    /// Manifest generation failed
    #[error("manifest generation failed: {0}")]
    ManifestGeneration(String),

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for BootstrapError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            BootstrapError::InvalidToken => (StatusCode::UNAUTHORIZED, self.to_string()),
            BootstrapError::TokenAlreadyUsed => (StatusCode::GONE, self.to_string()),
            BootstrapError::ClusterNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            BootstrapError::MissingAuth => (StatusCode::UNAUTHORIZED, self.to_string()),
            BootstrapError::CsrSigningFailed(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            BootstrapError::ClusterNotBootstrapped(_) => {
                (StatusCode::PRECONDITION_FAILED, self.to_string())
            }
            BootstrapError::ManifestGeneration(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "manifest generation failed".to_string(),
            ),
            BootstrapError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string(),
            ),
        };

        (status, Json(serde_json::json!({"error": message}))).into_response()
    }
}

impl From<PkiError> for BootstrapError {
    fn from(e: PkiError) -> Self {
        BootstrapError::CsrSigningFailed(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Story: HTTP error responses map to correct status codes
    ///
    /// Different error types return appropriate HTTP status codes
    /// for proper client error handling.
    #[tokio::test]
    async fn error_http_responses() {
        use axum::http::StatusCode;

        // Authentication errors -> 401 Unauthorized
        let auth_err = BootstrapError::InvalidToken.into_response();
        assert_eq!(auth_err.status(), StatusCode::UNAUTHORIZED);

        let missing_auth = BootstrapError::MissingAuth.into_response();
        assert_eq!(missing_auth.status(), StatusCode::UNAUTHORIZED);

        // Token already used -> 410 Gone (resource no longer available)
        let used_err = BootstrapError::TokenAlreadyUsed.into_response();
        assert_eq!(used_err.status(), StatusCode::GONE);

        // Unknown cluster -> 404 Not Found
        let not_found = BootstrapError::ClusterNotFound("x".to_string()).into_response();
        assert_eq!(not_found.status(), StatusCode::NOT_FOUND);

        // CSR before bootstrap -> 412 Precondition Failed
        let precondition = BootstrapError::ClusterNotBootstrapped("x".to_string()).into_response();
        assert_eq!(precondition.status(), StatusCode::PRECONDITION_FAILED);

        // Bad CSR -> 400 Bad Request
        let bad_csr = BootstrapError::CsrSigningFailed("error".to_string()).into_response();
        assert_eq!(bad_csr.status(), StatusCode::BAD_REQUEST);

        // Internal errors -> 500 (and message hidden for security)
        let internal = BootstrapError::Internal("secret details".to_string()).into_response();
        assert_eq!(internal.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Story: PkiError converts to BootstrapError correctly
    ///
    /// When CSR signing fails due to PKI errors (invalid CSR format, etc.),
    /// the error should be properly converted to a BootstrapError.
    #[test]
    fn pki_error_converts_to_bootstrap_error() {
        use lattice_infra::pki::PkiError;

        // Test the From<PkiError> implementation
        let pki_error = PkiError::InvalidCsr("malformed CSR data".to_string());
        let bootstrap_error: BootstrapError = pki_error.into();

        match bootstrap_error {
            BootstrapError::CsrSigningFailed(msg) => {
                assert!(msg.contains("malformed CSR"));
            }
            _ => panic!("Expected CsrSigningFailed"),
        }
    }
}
