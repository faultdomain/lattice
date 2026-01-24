//! Bootstrap token generation and validation
//!
//! Tokens are cryptographically secure random strings used for one-time
//! authentication during cluster bootstrap.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use thiserror::Error;

/// Error type for token generation failures
#[derive(Debug, Error)]
#[error("failed to generate cryptographically secure random bytes: FIPS RNG unavailable")]
pub struct TokenGenerationError;

/// Error type for token parsing failures
#[derive(Debug, Error)]
#[error("invalid token: not valid base64")]
pub struct TokenParseError;

/// A bootstrap token for cluster registration
#[derive(Clone)]
pub struct BootstrapToken {
    /// The raw token bytes
    raw: Vec<u8>,
    /// The token as a string
    string: String,
}

impl BootstrapToken {
    /// Generate a new random bootstrap token
    ///
    /// # Panics
    ///
    /// Panics if the FIPS-validated cryptographic RNG fails. This is a
    /// catastrophic system failure - if the RNG doesn't work, the system
    /// cannot operate securely. Use [`try_generate`] if you need to handle
    /// this error explicitly.
    pub fn generate() -> Self {
        Self::try_generate().unwrap_or_else(|e| {
            panic!(
                "CRITICAL: {}. The system cannot operate securely without \
                 a working cryptographic random number generator.",
                e
            )
        })
    }

    /// Try to generate a new random bootstrap token
    ///
    /// Returns an error if the FIPS-validated cryptographic RNG fails.
    /// This is rare and typically indicates a serious system problem.
    fn try_generate() -> Result<Self, TokenGenerationError> {
        // Use aws-lc-rs for FIPS-compliant random generation
        let mut raw = vec![0u8; 32];
        aws_lc_rs::rand::fill(&mut raw).map_err(|_| TokenGenerationError)?;

        let string = URL_SAFE_NO_PAD.encode(&raw);

        Ok(Self { raw, string })
    }

    /// Create a token from an existing string (for validation)
    ///
    /// Returns an error if the string is not valid base64.
    pub fn from_string(s: &str) -> Result<Self, TokenParseError> {
        let raw = URL_SAFE_NO_PAD.decode(s).map_err(|_| TokenParseError)?;
        Ok(Self {
            raw,
            string: s.to_string(),
        })
    }

    /// Get the token as a string
    pub fn as_str(&self) -> &str {
        &self.string
    }

    /// Get a SHA-256 hash of the token (for storage)
    pub fn hash(&self) -> String {
        use aws_lc_rs::digest::{digest, SHA256};
        let hash = digest(&SHA256, &self.raw);
        URL_SAFE_NO_PAD.encode(hash.as_ref())
    }
}

impl std::fmt::Debug for BootstrapToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't expose the actual token in debug output
        f.debug_struct("BootstrapToken")
            .field("hash", &self.hash())
            .finish()
    }
}

impl std::fmt::Display for BootstrapToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashmap::DashMap;
    use std::time::{Duration, Instant};

    // =========================================================================
    // Test-only TokenStore implementation
    // =========================================================================
    //
    // This is used only for testing token lifecycle. Production code uses
    // BootstrapState which has its own token management.

    /// Token metadata stored in the token store
    #[derive(Clone, Debug)]
    struct TokenMetadata {
        token_hash: String,
        expires_at: Instant,
        used: bool,
    }

    /// Thread-safe token store for testing
    struct TokenStore {
        tokens: DashMap<String, TokenMetadata>,
        default_ttl: Duration,
    }

    impl TokenStore {
        fn new() -> Self {
            Self {
                tokens: DashMap::new(),
                default_ttl: Duration::from_secs(3600),
            }
        }

        fn with_ttl(ttl: Duration) -> Self {
            Self {
                tokens: DashMap::new(),
                default_ttl: ttl,
            }
        }

        fn create_token(&self, cluster_id: &str) -> BootstrapToken {
            let token = BootstrapToken::generate();
            let now = Instant::now();

            let metadata = TokenMetadata {
                token_hash: token.hash(),
                expires_at: now + self.default_ttl,
                used: false,
            };

            self.tokens.insert(cluster_id.to_string(), metadata);
            token
        }

        fn validate(&self, cluster_id: &str, token: &str) -> bool {
            match self.tokens.get(cluster_id) {
                Some(metadata) => {
                    if Instant::now() > metadata.expires_at {
                        return false;
                    }
                    if metadata.used {
                        return false;
                    }
                    let provided = match BootstrapToken::from_string(token) {
                        Ok(t) => t,
                        Err(_) => return false,
                    };
                    provided.hash() == metadata.token_hash
                }
                None => false,
            }
        }

        fn consume(&self, cluster_id: &str, token: &str) -> bool {
            match self.tokens.get_mut(cluster_id) {
                Some(mut metadata) => {
                    if Instant::now() > metadata.expires_at {
                        return false;
                    }
                    if metadata.used {
                        return false;
                    }
                    let provided = match BootstrapToken::from_string(token) {
                        Ok(t) => t,
                        Err(_) => return false,
                    };
                    if provided.hash() != metadata.token_hash {
                        return false;
                    }
                    metadata.used = true;
                    true
                }
                None => false,
            }
        }

        fn cleanup_expired(&self) {
            let now = Instant::now();
            self.tokens.retain(|_, v| now < v.expires_at);
        }

        fn len(&self) -> usize {
            self.tokens.len()
        }

        fn is_empty(&self) -> bool {
            self.tokens.is_empty()
        }
    }

    impl Default for TokenStore {
        fn default() -> Self {
            Self::new()
        }
    }

    // =========================================================================
    // Token Security Stories
    // =========================================================================

    #[test]
    fn story_tokens_are_cryptographically_unique() {
        let token1 = BootstrapToken::generate();
        let token2 = BootstrapToken::generate();

        assert_ne!(token1.as_str(), token2.as_str());
        assert_ne!(token1.hash(), token2.hash());
    }

    #[test]
    fn story_tokens_are_url_safe_for_http_transport() {
        let token = BootstrapToken::generate();

        assert!(
            token
                .as_str()
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "Token should contain only URL-safe characters"
        );
    }

    #[test]
    fn story_token_hashes_enable_secure_validation() {
        let token = BootstrapToken::generate();

        let hash1 = token.hash();
        let hash2 = token.hash();
        assert_eq!(hash1, hash2, "Hash should be deterministic");

        let token_str = token.as_str().to_string();
        let reconstructed =
            BootstrapToken::from_string(&token_str).expect("valid base64 token should parse");
        assert_eq!(
            token.hash(),
            reconstructed.hash(),
            "Reconstructed token should hash the same"
        );
    }

    #[test]
    fn story_debug_output_protects_token_secrecy() {
        let token = BootstrapToken::generate();
        let debug = format!("{:?}", token);

        assert!(
            !debug.contains(token.as_str()),
            "Debug output must not expose token value"
        );
        assert!(
            debug.contains("hash"),
            "Debug output should show hash for traceability"
        );
    }

    // =========================================================================
    // Cluster Registration Flow Stories
    // =========================================================================

    #[test]
    fn story_cell_creates_token_for_new_cluster() {
        let store = TokenStore::new();
        let token = store.create_token("workload-cluster-prod-1");

        assert!(
            store.validate("workload-cluster-prod-1", token.as_str()),
            "Token should be valid for its cluster"
        );
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn story_agent_authenticates_with_valid_token() {
        let store = TokenStore::new();
        let token = store.create_token("new-workload");

        let is_valid = store.validate("new-workload", token.as_str());
        assert!(is_valid, "Valid token should authenticate");

        let consumed = store.consume("new-workload", token.as_str());
        assert!(consumed, "Token consumption should succeed");
    }

    #[test]
    fn story_token_cannot_be_reused_after_consumption() {
        let store = TokenStore::new();
        let token = store.create_token("secure-cluster");

        assert!(
            store.consume("secure-cluster", token.as_str()),
            "First use should succeed"
        );
        assert!(
            !store.consume("secure-cluster", token.as_str()),
            "Replay attempt should fail"
        );
        assert!(
            !store.validate("secure-cluster", token.as_str()),
            "Validation should fail for consumed token"
        );
    }

    // =========================================================================
    // Attack Prevention Stories
    // =========================================================================

    #[test]
    fn story_forged_tokens_are_rejected() {
        let store = TokenStore::new();
        store.create_token("legitimate-cluster");

        assert!(
            !store.validate("legitimate-cluster", "forged-token-attempt"),
            "Forged tokens must be rejected"
        );
    }

    #[test]
    fn story_invalid_base64_fails_explicitly() {
        let valid = BootstrapToken::from_string("dGVzdA");
        assert!(valid.is_ok(), "Valid base64 should parse");

        let invalid = BootstrapToken::from_string("not!valid@base64#");
        assert!(invalid.is_err(), "Invalid base64 should fail");

        let invalid2 = BootstrapToken::from_string("also-not-valid");
        assert!(invalid2.is_err(), "Invalid base64 should fail");
    }

    #[test]
    fn story_tokens_are_bound_to_specific_cluster() {
        let store = TokenStore::new();
        let token = store.create_token("cluster-alpha");

        assert!(
            !store.validate("cluster-beta", token.as_str()),
            "Token should only work for its designated cluster"
        );
    }

    #[test]
    fn story_expired_tokens_are_rejected() {
        let store = TokenStore::with_ttl(Duration::from_millis(1));
        let token = store.create_token("slow-cluster");

        std::thread::sleep(Duration::from_millis(10));

        assert!(
            !store.validate("slow-cluster", token.as_str()),
            "Expired token validation should fail"
        );
        assert!(
            !store.consume("slow-cluster", token.as_str()),
            "Expired token consumption should fail"
        );
    }

    // =========================================================================
    // Token Store Maintenance Stories
    // =========================================================================

    #[test]
    fn story_cleanup_removes_expired_tokens() {
        let store = TokenStore::with_ttl(Duration::from_millis(1));

        store.create_token("abandoned-cluster-1");
        store.create_token("abandoned-cluster-2");
        assert_eq!(store.len(), 2);

        std::thread::sleep(Duration::from_millis(10));
        store.cleanup_expired();

        assert!(store.is_empty(), "Expired tokens should be cleaned up");
    }

    #[test]
    fn story_cleanup_preserves_active_tokens() {
        let store = TokenStore::with_ttl(Duration::from_secs(3600));
        store.create_token("active-cluster");
        store.cleanup_expired();

        assert_eq!(store.len(), 1, "Active tokens should be preserved");
    }

    #[test]
    fn story_token_store_has_sensible_defaults() {
        let store = TokenStore::default();

        assert!(store.is_empty());

        let token = store.create_token("test-cluster");
        assert!(store.validate("test-cluster", token.as_str()));
    }
}
