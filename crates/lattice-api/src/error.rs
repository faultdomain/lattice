//! Error types for the auth proxy

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Result type for auth proxy operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for auth proxy operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Authentication failed (invalid or missing token)
    #[error("authentication failed: {0}")]
    Unauthorized(String),

    /// Authorization failed (user not allowed to access resource)
    #[error("authorization failed: {0}")]
    Forbidden(String),

    /// Cluster not found in subtree
    #[error("cluster not found: {0}")]
    ClusterNotFound(String),

    /// Failed to proxy request
    #[error("proxy error: {0}")]
    Proxy(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),

    /// Internal server error
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, client_message) = match &self {
            Error::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "authentication failed"),
            Error::Forbidden(_) => (StatusCode::FORBIDDEN, "authorization failed"),
            Error::ClusterNotFound(_) => (StatusCode::SERVICE_UNAVAILABLE, "cluster not available"),
            Error::Proxy(_) => (StatusCode::SERVICE_UNAVAILABLE, "proxy error"),
            Error::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
            Error::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };

        // Log the full error detail server-side, return generic message to client
        tracing::warn!(error = %self, status = %status, "API error response");

        let reason = match &self {
            Error::Unauthorized(_) => "Unauthorized",
            Error::Forbidden(_) => "Forbidden",
            Error::ClusterNotFound(_) | Error::Proxy(_) => "ServiceUnavailable",
            Error::Config(_) | Error::Internal(_) => "InternalError",
        };

        // Return an exact K8s API server Status response so client-go
        // handles it the same way it handles a real API server error.
        let body = serde_json::json!({
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": "Failure",
            "message": client_message,
            "reason": reason,
            "details": {
                "retryAfterSeconds": 1
            },
            "code": status.as_u16()
        });

        (status, axum::Json(body)).into_response()
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        Error::Unauthorized(e.to_string())
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Proxy(e.to_string())
    }
}

impl From<kube::Error> for Error {
    fn from(e: kube::Error) -> Self {
        Error::Internal(e.to_string())
    }
}
