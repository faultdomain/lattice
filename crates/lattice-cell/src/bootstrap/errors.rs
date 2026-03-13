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
        let (status, client_message) = match &self {
            BootstrapError::InvalidToken | BootstrapError::MissingAuth => {
                (StatusCode::UNAUTHORIZED, "authentication failed")
            }
            BootstrapError::TokenAlreadyUsed => (StatusCode::GONE, "token already used"),
            BootstrapError::ClusterNotFound(_) => (StatusCode::NOT_FOUND, "cluster not found"),
            BootstrapError::CsrSigningFailed(_) => (StatusCode::BAD_REQUEST, "CSR signing failed"),
            BootstrapError::ClusterNotBootstrapped(_) => {
                (StatusCode::PRECONDITION_FAILED, "cluster not bootstrapped")
            }
            BootstrapError::ManifestGeneration(_) | BootstrapError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };

        // Log the full error detail server-side, return generic message to client
        tracing::warn!(error = %self, status = %status, "Bootstrap error response");

        let body = serde_json::json!({
            "kind": "Status",
            "apiVersion": "v1",
            "status": "Failure",
            "message": client_message,
            "code": status.as_u16()
        });

        (status, Json(body)).into_response()
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

    async fn assert_status_response(resp: Response, expected_status: StatusCode, expected_msg: &str) {
        use axum::body::to_bytes;

        assert_eq!(resp.status(), expected_status);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["kind"], "Status");
        assert_eq!(json["apiVersion"], "v1");
        assert_eq!(json["status"], "Failure");
        assert_eq!(json["message"], expected_msg);
        assert_eq!(json["code"], expected_status.as_u16());
    }

    /// HTTP error responses map to correct status codes and use K8s Status format
    /// with generic client messages (no detail leakage).
    #[tokio::test]
    async fn error_http_responses() {
        assert_status_response(
            BootstrapError::InvalidToken.into_response(),
            StatusCode::UNAUTHORIZED,
            "authentication failed",
        ).await;

        assert_status_response(
            BootstrapError::MissingAuth.into_response(),
            StatusCode::UNAUTHORIZED,
            "authentication failed",
        ).await;

        assert_status_response(
            BootstrapError::TokenAlreadyUsed.into_response(),
            StatusCode::GONE,
            "token already used",
        ).await;

        assert_status_response(
            BootstrapError::ClusterNotFound("x".to_string()).into_response(),
            StatusCode::NOT_FOUND,
            "cluster not found",
        ).await;

        assert_status_response(
            BootstrapError::ClusterNotBootstrapped("x".to_string()).into_response(),
            StatusCode::PRECONDITION_FAILED,
            "cluster not bootstrapped",
        ).await;

        assert_status_response(
            BootstrapError::CsrSigningFailed("error".to_string()).into_response(),
            StatusCode::BAD_REQUEST,
            "CSR signing failed",
        ).await;

        // Internal errors hide details
        assert_status_response(
            BootstrapError::Internal("secret details".to_string()).into_response(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error",
        ).await;

        assert_status_response(
            BootstrapError::ManifestGeneration("oops".to_string()).into_response(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error",
        ).await;
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
