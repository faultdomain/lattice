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
        Self::try_generate().expect("FIPS-validated RNG failed - system cannot operate securely")
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

    /// Minimum raw bytes for a valid token (128 bits of entropy)
    const MIN_TOKEN_BYTES: usize = 16;

    /// Create a token from an existing string (for validation)
    ///
    /// Returns an error if the string is not valid base64 or has insufficient entropy.
    pub fn from_string(s: &str) -> Result<Self, TokenParseError> {
        let raw = URL_SAFE_NO_PAD.decode(s).map_err(|_| TokenParseError)?;
        if raw.len() < Self::MIN_TOKEN_BYTES {
            return Err(TokenParseError);
        }
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

    #[test]
    fn tokens_are_cryptographically_unique() {
        let token1 = BootstrapToken::generate();
        let token2 = BootstrapToken::generate();

        assert_ne!(token1.as_str(), token2.as_str());
        assert_ne!(token1.hash(), token2.hash());
    }

    #[test]
    fn tokens_are_url_safe_for_http_transport() {
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
    fn token_hashes_are_deterministic() {
        let token = BootstrapToken::generate();

        let hash1 = token.hash();
        let hash2 = token.hash();
        assert_eq!(hash1, hash2);

        let reconstructed =
            BootstrapToken::from_string(token.as_str()).expect("valid base64 token should parse");
        assert_eq!(token.hash(), reconstructed.hash());
    }

    #[test]
    fn debug_output_protects_token_secrecy() {
        let token = BootstrapToken::generate();
        let debug = format!("{:?}", token);

        assert!(!debug.contains(token.as_str()));
        assert!(debug.contains("hash"));
    }

    #[test]
    fn invalid_base64_fails_explicitly() {
        let token = BootstrapToken::generate();
        assert!(BootstrapToken::from_string(token.as_str()).is_ok());

        // Too short (4 bytes < MIN_TOKEN_BYTES)
        assert!(BootstrapToken::from_string("dGVzdA").is_err());
        assert!(BootstrapToken::from_string("not!valid@base64#").is_err());
    }

    #[test]
    fn display_shows_token_value() {
        let token = BootstrapToken::generate();
        let displayed = format!("{}", token);
        assert_eq!(displayed, token.as_str());
    }
}
