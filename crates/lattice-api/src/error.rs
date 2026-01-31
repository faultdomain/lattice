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
        let (status, message) = match &self {
            Error::Unauthorized(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            Error::Forbidden(_) => (StatusCode::FORBIDDEN, self.to_string()),
            Error::ClusterNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            Error::Proxy(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            Error::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Error::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        // Return K8s-style Status response
        let body = serde_json::json!({
            "kind": "Status",
            "apiVersion": "v1",
            "status": "Failure",
            "message": message,
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
