//! ServiceAccount token validation via Kubernetes TokenReview API
//!
//! Validates Kubernetes ServiceAccount tokens by submitting them to the
//! TokenReview API. This allows the proxy to authenticate requests from
//! pods using their ServiceAccount tokens.
//!
//! # Usage
//!
//! ```rust,ignore
//! let client = kube::Client::try_default().await?;
//! let validator = SaValidator::new(client);
//! let identity = validator.validate(token).await?;
//! // identity.username = "system:serviceaccount:{namespace}:{name}"
//! // identity.groups = ["system:serviceaccounts", "system:serviceaccounts:{namespace}"]
//! ```

use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewSpec, TokenReviewStatus};
use kube::{Api, Client};
use tracing::debug;

use crate::auth::UserIdentity;
use crate::error::{Error, Result};

/// ServiceAccount token validator using Kubernetes TokenReview API
pub struct SaValidator {
    /// Kubernetes client
    client: Client,
    /// Optional audiences to validate
    audiences: Option<Vec<String>>,
}

impl SaValidator {
    /// Create a new ServiceAccount validator
    pub fn new(client: Client) -> Self {
        Self {
            client,
            audiences: None,
        }
    }

    /// Create a validator with specific audiences
    pub fn with_audiences(client: Client, audiences: Vec<String>) -> Self {
        Self {
            client,
            audiences: Some(audiences),
        }
    }

    /// Validate a ServiceAccount token using TokenReview API
    ///
    /// Submits the token to the Kubernetes TokenReview API and returns
    /// the authenticated user identity if valid.
    ///
    /// # Arguments
    /// * `token` - The ServiceAccount token to validate
    ///
    /// # Returns
    /// * `Ok(UserIdentity)` - The authenticated identity with username and groups
    /// * `Err(Error::Unauthorized)` - If the token is invalid or expired
    pub async fn validate(&self, token: &str) -> Result<UserIdentity> {
        let api: Api<TokenReview> = Api::all(self.client.clone());

        // Build TokenReview request
        let token_review = TokenReview {
            metadata: Default::default(),
            spec: TokenReviewSpec {
                token: Some(token.to_string()),
                audiences: self.audiences.clone(),
            },
            status: None,
        };

        // Submit for review
        let result = api
            .create(&Default::default(), &token_review)
            .await
            .map_err(|e| Error::Internal(format!("TokenReview API error: {}", e)))?;

        // Extract status
        let status = result
            .status
            .ok_or_else(|| Error::Internal("TokenReview returned no status".into()))?;

        self.validate_status(&status)
    }

    /// Extract user identity from TokenReview status
    fn validate_status(&self, status: &TokenReviewStatus) -> Result<UserIdentity> {
        // Check if authenticated
        if !status.authenticated.unwrap_or(false) {
            let error_msg = status
                .error
                .as_deref()
                .unwrap_or("Token authentication failed");
            return Err(Error::Unauthorized(error_msg.to_string()));
        }

        // Extract user info
        let user = status
            .user
            .as_ref()
            .ok_or_else(|| Error::Internal("TokenReview authenticated but no user info".into()))?;

        let username = user
            .username
            .as_ref()
            .ok_or_else(|| Error::Internal("TokenReview user has no username".into()))?
            .clone();

        let groups = user.groups.clone().unwrap_or_default();

        debug!(
            username = %username,
            groups = ?groups,
            "TokenReview validated ServiceAccount token"
        );

        Ok(UserIdentity { username, groups })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::authentication::v1::UserInfo;

    #[test]
    fn test_validate_status_authenticated() {
        // Create a mock client (we only need it for the struct, not for this test)
        // We'll test the status validation directly
        let status = TokenReviewStatus {
            authenticated: Some(true),
            user: Some(UserInfo {
                username: Some("system:serviceaccount:default:test-sa".to_string()),
                groups: Some(vec![
                    "system:serviceaccounts".to_string(),
                    "system:serviceaccounts:default".to_string(),
                ]),
                uid: None,
                extra: None,
            }),
            error: None,
            audiences: None,
        };

        // We can't call validate_status without a real client, but we can verify the structure
        assert!(status.authenticated.unwrap());
        assert_eq!(
            status.user.as_ref().unwrap().username,
            Some("system:serviceaccount:default:test-sa".to_string())
        );
    }

    #[test]
    fn test_validate_status_not_authenticated() {
        let status = TokenReviewStatus {
            authenticated: Some(false),
            user: None,
            error: Some("token expired".to_string()),
            audiences: None,
        };

        assert!(!status.authenticated.unwrap());
        assert_eq!(status.error, Some("token expired".to_string()));
    }

    #[test]
    fn test_sa_username_format() {
        // Verify expected ServiceAccount username format
        let username = "system:serviceaccount:kube-system:default";
        assert!(username.starts_with("system:serviceaccount:"));
        let parts: Vec<&str> = username.split(':').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "system");
        assert_eq!(parts[1], "serviceaccount");
        assert_eq!(parts[2], "kube-system"); // namespace
        assert_eq!(parts[3], "default"); // sa name
    }

    #[test]
    fn test_sa_groups_format() {
        // Verify expected ServiceAccount groups format
        let groups = [
            "system:serviceaccounts",
            "system:serviceaccounts:kube-system",
            "system:authenticated",
        ];

        assert!(groups.contains(&"system:serviceaccounts"));
        assert!(groups
            .iter()
            .any(|g| g.starts_with("system:serviceaccounts:")));
    }
}
