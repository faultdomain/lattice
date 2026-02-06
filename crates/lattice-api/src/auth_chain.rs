//! Authentication chain with fallback support
//!
//! Provides a unified authentication interface that tries multiple validators
//! in sequence. Currently supports:
//! 1. OIDC token validation (for human users)
//! 2. ServiceAccount token validation via TokenReview (for pods/services)
//!
//! # Fallback Order
//!
//! 1. If OIDC is configured, try OIDC validation first
//! 2. If OIDC fails or is not configured, try ServiceAccount validation
//! 3. Return the first successful result, or the last error
//!
//! # Dynamic Reload
//!
//! The OIDC validator can be swapped at runtime when OIDCProvider CRDs change.
//! The `set_oidc()` method replaces the validator under a write lock, and
//! `validate()` snapshots the Arc under a read lock before validation.
//!
//! # Usage
//!
//! ```rust,ignore
//! // Both validators
//! let chain = AuthChain::new(oidc_validator, sa_validator);
//!
//! // OIDC only (original behavior)
//! let chain = AuthChain::oidc_only(oidc_validator);
//!
//! // SA only (for testing)
//! let chain = AuthChain::sa_only(sa_validator);
//!
//! // Validate a token
//! let identity = chain.validate(token).await?;
//!
//! // Dynamic reload (from OIDCProvider watcher)
//! chain.set_oidc(Some(Arc::new(new_validator))).await;
//! ```

use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::debug;

use crate::auth::{OidcConfig, OidcValidator, UserIdentity};
use crate::error::{Error, Result};
use crate::sa_auth::SaValidator;

/// Authentication chain that tries multiple validators
pub struct AuthChain {
    /// Optional OIDC validator (for human users), swappable at runtime
    oidc: Arc<RwLock<Option<Arc<OidcValidator>>>>,
    /// Optional ServiceAccount validator (for pods/services)
    sa: Option<Arc<SaValidator>>,
}

impl AuthChain {
    /// Create a new authentication chain with both OIDC and SA validators
    ///
    /// OIDC is tried first, with SA as fallback.
    pub fn new(oidc: Arc<OidcValidator>, sa: Arc<SaValidator>) -> Self {
        Self {
            oidc: Arc::new(RwLock::new(Some(oidc))),
            sa: Some(sa),
        }
    }

    /// Create an authentication chain with only OIDC validation
    ///
    /// Use this for backwards compatibility or when SA auth is not needed.
    pub fn oidc_only(oidc: Arc<OidcValidator>) -> Self {
        Self {
            oidc: Arc::new(RwLock::new(Some(oidc))),
            sa: None,
        }
    }

    /// Create an authentication chain with only SA validation
    ///
    /// Use this for testing or when OIDC is not configured.
    pub fn sa_only(sa: Arc<SaValidator>) -> Self {
        Self {
            oidc: Arc::new(RwLock::new(None)),
            sa: Some(sa),
        }
    }

    /// Create an empty authentication chain (for testing)
    ///
    /// This will reject all tokens.
    pub fn none() -> Self {
        Self {
            oidc: Arc::new(RwLock::new(None)),
            sa: None,
        }
    }

    /// Swap the OIDC validator at runtime (called by OIDCProvider watcher)
    pub async fn set_oidc(&self, oidc: Option<Arc<OidcValidator>>) {
        let mut guard = self.oidc.write().await;
        *guard = oidc;
    }

    /// Get a clone of the OIDC configuration if available
    pub async fn oidc_config(&self) -> Option<OidcConfig> {
        let guard = self.oidc.read().await;
        guard
            .as_ref()
            .filter(|o| !o.config().issuer_url.is_empty())
            .map(|o| o.config().clone())
    }

    /// Validate a token using the authentication chain
    ///
    /// Tries validators in order:
    /// 1. OIDC (if configured with a valid issuer)
    /// 2. ServiceAccount TokenReview (if available)
    ///
    /// Returns the first successful validation result.
    pub async fn validate(&self, token: &str) -> Result<UserIdentity> {
        let mut last_error: Option<Error> = None;

        // Snapshot the OIDC validator under read lock, then release
        let oidc_snapshot = {
            let guard = self.oidc.read().await;
            guard.clone()
        };

        // Try OIDC first if configured
        if let Some(ref oidc) = oidc_snapshot {
            if !oidc.config().issuer_url.is_empty() {
                debug!("Trying OIDC validation");
                match oidc.validate(token).await {
                    Ok(identity) => {
                        debug!(username = %identity.username, "OIDC validation succeeded");
                        return Ok(identity);
                    }
                    Err(e) => {
                        debug!(error = %e, "OIDC validation failed, trying next validator");
                        last_error = Some(e);
                    }
                }
            }
        }

        // Try ServiceAccount validation as fallback
        if let Some(sa) = &self.sa {
            debug!("Trying ServiceAccount TokenReview validation");
            match sa.validate(token).await {
                Ok(identity) => {
                    debug!(username = %identity.username, "ServiceAccount validation succeeded");
                    return Ok(identity);
                }
                Err(e) => {
                    debug!(error = %e, "ServiceAccount validation failed");
                    last_error = Some(e);
                }
            }
        }

        // Return the last error, or a generic error if no validators were configured
        Err(last_error
            .unwrap_or_else(|| Error::Config("No authentication validators configured".into())))
    }
}

impl Default for AuthChain {
    fn default() -> Self {
        Self::none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_auth_chain_none() {
        let chain = AuthChain::none();
        assert!(chain.oidc.read().await.is_none());
        assert!(chain.sa.is_none());
    }

    #[tokio::test]
    async fn test_auth_chain_oidc_only() {
        let oidc = Arc::new(OidcValidator::new());
        let chain = AuthChain::oidc_only(oidc);
        assert!(chain.oidc.read().await.is_some());
        assert!(chain.sa.is_none());
    }

    #[tokio::test]
    async fn test_oidc_config_none_when_no_issuer() {
        let oidc = Arc::new(OidcValidator::new()); // Default has empty issuer
        let chain = AuthChain::oidc_only(oidc);
        assert!(chain.oidc_config().await.is_none());
    }

    #[tokio::test]
    async fn test_oidc_config_accessor() {
        let config = OidcConfig {
            issuer_url: "https://idp.example.com".to_string(),
            client_id: "test-client".to_string(),
            ..Default::default()
        };
        let oidc = Arc::new(OidcValidator::with_config(config));
        let chain = AuthChain::oidc_only(oidc);

        let retrieved = chain.oidc_config().await.unwrap();
        assert_eq!(retrieved.issuer_url, "https://idp.example.com");
        assert_eq!(retrieved.client_id, "test-client");
    }

    #[tokio::test]
    async fn test_validate_no_validators() {
        let chain = AuthChain::none();
        let result = chain.validate("some-token").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No authentication validators"));
    }

    #[tokio::test]
    async fn test_validate_oidc_not_configured() {
        // OIDC with no issuer should be skipped
        let oidc = Arc::new(OidcValidator::new());
        let chain = AuthChain::oidc_only(oidc);

        let result = chain.validate("some-token").await;
        assert!(result.is_err());
        // Should fail because OIDC has no issuer configured
    }

    #[tokio::test]
    async fn test_set_oidc_dynamic_swap() {
        let chain = AuthChain::none();
        assert!(chain.oidc_config().await.is_none());

        // Set an OIDC validator dynamically
        let config = OidcConfig {
            issuer_url: "https://new-idp.example.com".to_string(),
            client_id: "new-client".to_string(),
            ..Default::default()
        };
        let oidc = Arc::new(OidcValidator::with_config(config));
        chain.set_oidc(Some(oidc)).await;

        let retrieved = chain.oidc_config().await.unwrap();
        assert_eq!(retrieved.issuer_url, "https://new-idp.example.com");

        // Clear it
        chain.set_oidc(None).await;
        assert!(chain.oidc_config().await.is_none());
    }
}
