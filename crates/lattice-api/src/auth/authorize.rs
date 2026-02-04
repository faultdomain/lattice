//! Combined authentication and authorization
//!
//! Provides a unified interface for authenticating and authorizing requests
//! in a single call, reducing code duplication in handlers.

use std::sync::Arc;

use axum::http::HeaderMap;
use tracing::debug;

use crate::auth::UserIdentity;
use crate::auth_chain::AuthChain;
use crate::cedar::PolicyEngine;
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
/// This is a convenience function that combines token validation and
/// Cedar policy evaluation. Use this in handlers to reduce boilerplate.
///
/// # Arguments
///
/// * `auth` - Authentication chain for token validation
/// * `cedar` - Cedar policy engine for authorization
/// * `headers` - Request headers (must contain Authorization header)
/// * `cluster` - Target cluster name for authorization
/// * `action` - K8s verb (get, list, create, update, delete, etc.)
///
/// # Returns
///
/// The authenticated user identity if successful, or an error if:
/// - No Authorization header is present
/// - The token is invalid or expired
/// - The user is not authorized to perform the action on the cluster
pub async fn authenticate_and_authorize(
    auth: &Arc<AuthChain>,
    cedar: &Arc<PolicyEngine>,
    headers: &HeaderMap,
    cluster: &str,
    action: &str,
) -> Result<UserIdentity> {
    // Extract and validate token
    let token = extract_bearer_token(headers)
        .ok_or_else(|| Error::Unauthorized("Missing Authorization header".into()))?;

    let identity = auth.validate(token).await?;

    debug!(
        user = %identity.username,
        cluster = %cluster,
        action = %action,
        "Checking authorization"
    );

    // Check Cedar authorization
    cedar.authorize(&identity, cluster, action).await?;

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
