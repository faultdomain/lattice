//! Bootstrap token generation and validation
//!
//! Tokens are cryptographically secure random strings used for one-time
//! authentication during cluster bootstrap.

use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use dashmap::DashMap;
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
    pub fn try_generate() -> Result<Self, TokenGenerationError> {
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

/// Token metadata stored in the token store
#[derive(Clone, Debug)]
pub struct TokenMetadata {
    /// Hash of the token
    pub token_hash: String,
    /// When the token expires
    pub expires_at: Instant,
    /// Whether the token has been used
    pub used: bool,
}

/// Thread-safe token store
pub struct TokenStore {
    /// Tokens indexed by cluster_id
    tokens: DashMap<String, TokenMetadata>,
    /// Default TTL for new tokens
    default_ttl: Duration,
}

impl TokenStore {
    /// Create a new token store with default 1 hour TTL
    pub fn new() -> Self {
        Self {
            tokens: DashMap::new(),
            default_ttl: Duration::from_secs(3600),
        }
    }

    /// Create a new token store with custom TTL
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            tokens: DashMap::new(),
            default_ttl: ttl,
        }
    }

    /// Generate and store a new token for a cluster
    pub fn create_token(&self, cluster_id: &str) -> BootstrapToken {
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

    /// Validate a token for a cluster without consuming it
    pub fn validate(&self, cluster_id: &str, token: &str) -> bool {
        match self.tokens.get(cluster_id) {
            Some(metadata) => {
                // Check expiry
                if Instant::now() > metadata.expires_at {
                    return false;
                }

                // Check if already used
                if metadata.used {
                    return false;
                }

                // Verify hash - invalid base64 is always rejected
                let provided = match BootstrapToken::from_string(token) {
                    Ok(t) => t,
                    Err(_) => return false,
                };
                provided.hash() == metadata.token_hash
            }
            None => false,
        }
    }

    /// Validate and consume a token (one-time use)
    pub fn consume(&self, cluster_id: &str, token: &str) -> bool {
        match self.tokens.get_mut(cluster_id) {
            Some(mut metadata) => {
                // Check expiry
                if Instant::now() > metadata.expires_at {
                    return false;
                }

                // Check if already used
                if metadata.used {
                    return false;
                }

                // Verify hash - invalid base64 is always rejected
                let provided = match BootstrapToken::from_string(token) {
                    Ok(t) => t,
                    Err(_) => return false,
                };
                if provided.hash() != metadata.token_hash {
                    return false;
                }

                // Mark as used
                metadata.used = true;
                true
            }
            None => false,
        }
    }

    /// Remove expired tokens (for cleanup)
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.tokens.retain(|_, v| now < v.expires_at);
    }

    /// Get the number of tokens in the store
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Check if store is empty
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Token Security Stories
    // =========================================================================
    //
    // Bootstrap tokens are security-critical. They authenticate new clusters
    // during the kubeadm postKubeadmCommands callback. These tests verify
    // the cryptographic properties that make tokens secure.

    /// Story: Each generated token is cryptographically unique
    ///
    /// Tokens use FIPS-compliant random generation, ensuring attackers cannot
    /// predict valid tokens even if they know how tokens are generated.
    #[test]
    fn story_tokens_are_cryptographically_unique() {
        let token1 = BootstrapToken::generate();
        let token2 = BootstrapToken::generate();

        // Tokens should be different (probability of collision is negligible)
        assert_ne!(token1.as_str(), token2.as_str());

        // Each token should have a unique hash
        assert_ne!(token1.hash(), token2.hash());
    }

    /// Story: Tokens use URL-safe encoding for transport
    ///
    /// Tokens may be transmitted via HTTP callbacks, so they must only
    /// contain URL-safe characters (alphanumeric, dash, underscore).
    #[test]
    fn story_tokens_are_url_safe_for_http_transport() {
        let token = BootstrapToken::generate();

        // Verify URL-safe encoding
        assert!(
            token
                .as_str()
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "Token should contain only URL-safe characters"
        );
    }

    /// Story: Token hashes are deterministic for validation
    ///
    /// The cell stores token hashes (not raw tokens) for security. When a
    /// cluster presents its token, we must be able to hash it and compare.
    #[test]
    fn story_token_hashes_enable_secure_validation() {
        let token = BootstrapToken::generate();

        // Hash must be deterministic
        let hash1 = token.hash();
        let hash2 = token.hash();
        assert_eq!(hash1, hash2, "Hash should be deterministic");

        // Reconstructed token from string should hash identically
        let token_str = token.as_str().to_string();
        let reconstructed =
            BootstrapToken::from_string(&token_str).expect("valid base64 token should parse");
        assert_eq!(
            token.hash(),
            reconstructed.hash(),
            "Reconstructed token should hash the same"
        );
    }

    /// Story: Token debug output never exposes the secret value
    ///
    /// If tokens appear in logs, they must not expose the actual value.
    /// Debug output shows the hash for traceability, not the secret.
    #[test]
    fn story_debug_output_protects_token_secrecy() {
        let token = BootstrapToken::generate();
        let debug = format!("{:?}", token);

        // Secret value must NOT appear
        assert!(
            !debug.contains(token.as_str()),
            "Debug output must not expose token value"
        );

        // Hash should appear for traceability
        assert!(
            debug.contains("hash"),
            "Debug output should show hash for traceability"
        );
    }

    // =========================================================================
    // Cluster Registration Flow Stories
    // =========================================================================
    //
    // These tests demonstrate the token lifecycle during cluster bootstrap:
    // 1. Cell creates token for new cluster
    // 2. Token is sent to cluster during kubeadm
    // 3. Agent presents token to authenticate
    // 4. Token is consumed (one-time use)

    /// Story: Cell creates token for a new cluster registration
    ///
    /// Before a workload cluster is provisioned, the cell creates a bootstrap
    /// token that will be used to authenticate the cluster's first connection.
    #[test]
    fn story_cell_creates_token_for_new_cluster() {
        let store = TokenStore::new();

        // Cell creates token for the cluster being provisioned
        let token = store.create_token("workload-cluster-prod-1");

        // Token should be immediately valid for that cluster
        assert!(
            store.validate("workload-cluster-prod-1", token.as_str()),
            "Token should be valid for its cluster"
        );

        // Token store should track it
        assert_eq!(store.len(), 1);
    }

    /// Story: Agent presents valid token during registration
    ///
    /// When the agent starts (after kubeadm installs it), it presents the
    /// bootstrap token to authenticate with the cell.
    #[test]
    fn story_agent_authenticates_with_valid_token() {
        let store = TokenStore::new();
        let token = store.create_token("new-workload");

        // Agent presents the token - should succeed
        let is_valid = store.validate("new-workload", token.as_str());
        assert!(is_valid, "Valid token should authenticate");

        // After validation, consume the token (one-time use)
        let consumed = store.consume("new-workload", token.as_str());
        assert!(consumed, "Token consumption should succeed");
    }

    /// Story: Token is single-use to prevent replay attacks
    ///
    /// Once a token is consumed during registration, it cannot be reused.
    /// This prevents attackers from replaying captured tokens.
    #[test]
    fn story_token_cannot_be_reused_after_consumption() {
        let store = TokenStore::new();
        let token = store.create_token("secure-cluster");

        // First use succeeds
        assert!(
            store.consume("secure-cluster", token.as_str()),
            "First use should succeed"
        );

        // Replay attempt fails
        assert!(
            !store.consume("secure-cluster", token.as_str()),
            "Replay attempt should fail"
        );

        // Even validation fails after consumption
        assert!(
            !store.validate("secure-cluster", token.as_str()),
            "Validation should fail for consumed token"
        );
    }

    // =========================================================================
    // Attack Prevention Stories
    // =========================================================================
    //
    // These tests verify the system rejects various attack vectors.

    /// Story: Invalid tokens are rejected
    ///
    /// Attackers attempting to use forged or guessed tokens must be rejected.
    #[test]
    fn story_forged_tokens_are_rejected() {
        let store = TokenStore::new();
        store.create_token("legitimate-cluster");

        // Attempt with a forged/guessed token
        assert!(
            !store.validate("legitimate-cluster", "forged-token-attempt"),
            "Forged tokens must be rejected"
        );
    }

    /// Story: Invalid base64 strings fail explicitly when parsing
    ///
    /// Tokens must be valid base64. Invalid input returns an error rather
    /// than silently producing an empty or predictable token.
    #[test]
    fn story_invalid_base64_fails_explicitly() {
        // Valid base64 should parse
        let valid = BootstrapToken::from_string("dGVzdA");
        assert!(valid.is_ok(), "Valid base64 should parse");

        // Invalid base64 with illegal characters should fail
        let invalid = BootstrapToken::from_string("not!valid@base64#");
        assert!(invalid.is_err(), "Invalid base64 should fail");

        // All invalid tokens would hash to same value if we used unwrap_or_default
        // This test verifies we fail explicitly instead
        let invalid2 = BootstrapToken::from_string("also-not-valid");
        assert!(invalid2.is_err(), "Invalid base64 should fail");
    }

    /// Story: Tokens cannot be used for wrong cluster
    ///
    /// Each token is bound to a specific cluster. An attacker with a valid
    /// token for one cluster cannot use it to register a different cluster.
    #[test]
    fn story_tokens_are_bound_to_specific_cluster() {
        let store = TokenStore::new();
        let token = store.create_token("cluster-alpha");

        // Attempt to use alpha's token for a different cluster
        assert!(
            !store.validate("cluster-beta", token.as_str()),
            "Token should only work for its designated cluster"
        );
    }

    /// Story: Expired tokens are rejected even if otherwise valid
    ///
    /// Tokens have a TTL. If a cluster doesn't bootstrap in time, the
    /// token expires and cannot be used.
    #[test]
    fn story_expired_tokens_are_rejected() {
        // Very short TTL for test
        let store = TokenStore::with_ttl(Duration::from_millis(1));
        let token = store.create_token("slow-cluster");

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(10));

        // Both validation and consumption should fail
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
    //
    // These tests cover operational aspects of token management.

    /// Story: Periodic cleanup removes expired tokens
    ///
    /// Over time, unclaimed tokens expire. Periodic cleanup prevents the
    /// token store from growing unbounded.
    #[test]
    fn story_cleanup_removes_expired_tokens() {
        let store = TokenStore::with_ttl(Duration::from_millis(1));

        // Create tokens for clusters that never registered
        store.create_token("abandoned-cluster-1");
        store.create_token("abandoned-cluster-2");
        assert_eq!(store.len(), 2);

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(10));

        // Run cleanup
        store.cleanup_expired();

        // Expired tokens should be removed
        assert!(store.is_empty(), "Expired tokens should be cleaned up");
    }

    /// Story: Cleanup preserves active tokens
    ///
    /// Cleanup should only remove expired tokens, not valid ones.
    #[test]
    fn story_cleanup_preserves_active_tokens() {
        let store = TokenStore::with_ttl(Duration::from_secs(3600)); // 1 hour TTL

        store.create_token("active-cluster");

        // Run cleanup
        store.cleanup_expired();

        // Token should still be there
        assert_eq!(store.len(), 1, "Active tokens should be preserved");
    }

    /// Story: Token store supports default construction
    #[test]
    fn story_token_store_has_sensible_defaults() {
        let store = TokenStore::default();

        // Should work like TokenStore::new()
        assert!(store.is_empty());

        let token = store.create_token("test-cluster");
        assert!(store.validate("test-cluster", token.as_str()));
    }
}
