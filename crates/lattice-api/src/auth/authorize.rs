//! Combined authentication and authorization
//!
//! Provides a unified interface for authenticating and authorizing requests
//! in a single call, reducing code duplication in handlers.

use std::sync::Arc;

use axum::http::HeaderMap;
use tracing::debug;

use crate::auth::UserIdentity;
use crate::auth_chain::AuthChain;
use crate::cedar::{ClusterAttributes, PolicyEngine};
use crate::error::{Error, Result};

/// Extract bearer token from Authorization header
pub fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Authenticate and authorize a request in one call
///
/// Combines token validation and Cedar policy evaluation.
pub async fn authenticate_and_authorize(
    auth: &Arc<AuthChain>,
    cedar: &Arc<PolicyEngine>,
    headers: &HeaderMap,
    cluster: &str,
    attrs: &ClusterAttributes,
) -> Result<UserIdentity> {
    let token = extract_bearer_token(headers)
        .ok_or_else(|| Error::Unauthorized("Missing Authorization header".into()))?;

    let identity = auth.validate(token).await?;

    debug!(
        user = %identity.username,
        cluster = %cluster,
        "Checking authorization"
    );

    cedar
        .authorize_cluster(&identity.username, &identity.groups, cluster, attrs, None)
        .await
        .map_err(|e| match e {
            lattice_cedar::Error::Forbidden(msg) => Error::Forbidden(msg),
            lattice_cedar::Error::Config(msg) => Error::Config(msg),
            other => Error::Internal(other.to_string()),
        })?;

    Ok(identity)
}

/// Authenticate a request (without authorization)
///
/// Use this when you only need to validate the token without checking
/// Cedar policies (e.g., for the kubeconfig endpoint).
pub async fn authenticate(auth: &Arc<AuthChain>, headers: &HeaderMap) -> Result<UserIdentity> {
    let token = extract_bearer_token(headers)
        .ok_or_else(|| Error::Unauthorized("Missing Authorization header".into()))?;

    auth.validate(token).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer abc123".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), Some("abc123"));
    }

    #[test]
    fn test_extract_bearer_token_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn test_extract_bearer_token_wrong_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Basic abc123".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn test_extract_bearer_token_no_space() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearerabc123".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), None);
    }
}
