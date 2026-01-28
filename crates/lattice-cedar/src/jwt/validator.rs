//! JWT validation
//!
//! FIPS-compliant JWT validation using aws-lc-rs.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, warn};

use super::JwksCache;
use crate::error::{CedarError, Result};

/// Standard JWT claims
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Claims {
    /// Subject (user ID)
    #[serde(default)]
    pub sub: Option<String>,

    /// Issuer
    #[serde(default)]
    pub iss: Option<String>,

    /// Audience (can be string or array)
    #[serde(default)]
    pub aud: Option<Audience>,

    /// Expiration time (Unix timestamp)
    #[serde(default)]
    pub exp: Option<u64>,

    /// Not before time (Unix timestamp)
    #[serde(default)]
    pub nbf: Option<u64>,

    /// Issued at time (Unix timestamp)
    #[serde(default)]
    pub iat: Option<u64>,

    /// JWT ID
    #[serde(default)]
    pub jti: Option<String>,

    /// All claims (for custom claim extraction)
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// Audience claim (can be string or array)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Audience {
    /// Single audience
    Single(String),
    /// Multiple audiences
    Multiple(Vec<String>),
}

impl Audience {
    /// Check if the audience contains a specific value
    pub fn contains(&self, aud: &str) -> bool {
        match self {
            Audience::Single(s) => s == aud,
            Audience::Multiple(v) => v.iter().any(|a| a == aud),
        }
    }
}

/// Validated JWT token
#[derive(Debug, Clone)]
pub struct ValidatedToken {
    /// Token claims
    pub claims: Claims,
    /// Key ID used for validation
    pub kid: Option<String>,
    /// Algorithm used
    pub alg: String,
}

impl ValidatedToken {
    /// Get the subject claim
    pub fn subject(&self) -> Option<&str> {
        self.claims.sub.as_deref()
    }

    /// Get a custom claim by path (dot-separated)
    ///
    /// Example: `token.get_claim("custom.roles")` returns the value at `custom.roles`
    pub fn get_claim(&self, path: &str) -> Option<&Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current: Option<&Value> = None;

        for (i, part) in parts.iter().enumerate() {
            if i == 0 {
                current = self.claims.extra.get(*part);
            } else if let Some(Value::Object(obj)) = current {
                current = obj.get(*part);
            } else {
                return None;
            }
        }

        current
    }

    /// Get roles from a configurable claim path
    pub fn get_roles(&self, claim_path: &str) -> Vec<String> {
        match self.get_claim(claim_path) {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            Some(Value::String(s)) => vec![s.clone()],
            _ => vec![],
        }
    }

    /// Get groups from a configurable claim path
    pub fn get_groups(&self, claim_path: &str) -> Vec<String> {
        self.get_roles(claim_path) // Same logic
    }
}

/// JWT header
#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    typ: Option<String>,
}

/// JWT validation configuration
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Expected issuer
    pub issuer: String,
    /// Expected audience
    pub audience: String,
    /// JWKS URI for key retrieval
    pub jwks_uri: String,
    /// Clock skew tolerance in seconds (default: 60)
    pub clock_skew: u64,
}

/// JWT validator with JWKS caching
#[derive(Debug)]
pub struct JwtValidator {
    /// JWKS cache
    jwks_cache: Arc<JwksCache>,
    /// Default clock skew tolerance
    clock_skew: u64,
}

impl JwtValidator {
    /// Create a new JWT validator
    pub fn new(jwks_cache: Arc<JwksCache>) -> Self {
        Self {
            jwks_cache,
            clock_skew: 60,
        }
    }

    /// Create a validator with custom clock skew tolerance
    pub fn with_clock_skew(jwks_cache: Arc<JwksCache>, clock_skew: u64) -> Self {
        Self {
            jwks_cache,
            clock_skew,
        }
    }

    /// Validate a JWT token
    ///
    /// Validates:
    /// - Signature (using JWKS)
    /// - Expiration (exp claim)
    /// - Not before (nbf claim)
    /// - Issuer (iss claim)
    /// - Audience (aud claim)
    pub async fn validate(&self, token: &str, config: &ValidationConfig) -> Result<ValidatedToken> {
        // Split token into parts
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(CedarError::jwt_validation("invalid token format"));
        }

        let header_b64 = parts[0];
        let payload_b64 = parts[1];
        let signature_b64 = parts[2];

        // Decode header
        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| CedarError::jwt_validation(format!("invalid header encoding: {}", e)))?;

        let header: JwtHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| CedarError::jwt_validation(format!("invalid header: {}", e)))?;

        // Verify algorithm is allowed (FIPS-compatible)
        if !is_fips_algorithm(&header.alg) {
            return Err(CedarError::jwt_validation(format!(
                "unsupported algorithm: {} (FIPS requires RS256, RS384, RS512, ES256, ES384, ES512)",
                header.alg
            )));
        }

        // Get the signing key
        let jwk = self
            .jwks_cache
            .get_key(&config.jwks_uri, header.kid.as_deref())
            .await?;

        // Verify signature
        self.verify_signature(&header.alg, &jwk, header_b64, payload_b64, signature_b64)?;

        // Decode payload
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| CedarError::jwt_validation(format!("invalid payload encoding: {}", e)))?;

        let claims: Claims = serde_json::from_slice(&payload_bytes)
            .map_err(|e| CedarError::jwt_validation(format!("invalid payload: {}", e)))?;

        // Validate claims
        self.validate_claims(&claims, config)?;

        Ok(ValidatedToken {
            claims,
            kid: header.kid,
            alg: header.alg,
        })
    }

    fn verify_signature(
        &self,
        alg: &str,
        jwk: &super::jwks::Jwk,
        header_b64: &str,
        payload_b64: &str,
        signature_b64: &str,
    ) -> Result<()> {
        let message = format!("{}.{}", header_b64, payload_b64);
        let signature = URL_SAFE_NO_PAD.decode(signature_b64).map_err(|e| {
            CedarError::jwt_validation(format!("invalid signature encoding: {}", e))
        })?;

        match alg {
            "RS256" | "RS384" | "RS512" => {
                self.verify_rsa_signature(alg, jwk, message.as_bytes(), &signature)
            }
            "ES256" | "ES384" | "ES512" => {
                self.verify_ec_signature(alg, jwk, message.as_bytes(), &signature)
            }
            _ => Err(CedarError::jwt_validation(format!(
                "unsupported algorithm: {}",
                alg
            ))),
        }
    }

    fn verify_rsa_signature(
        &self,
        alg: &str,
        jwk: &super::jwks::Jwk,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        use aws_lc_rs::signature::{self, UnparsedPublicKey};

        let n = jwk
            .n
            .as_ref()
            .ok_or_else(|| CedarError::jwt_validation("RSA key missing modulus"))?;
        let e = jwk
            .e
            .as_ref()
            .ok_or_else(|| CedarError::jwt_validation("RSA key missing exponent"))?;

        // Decode key components
        let n_bytes = URL_SAFE_NO_PAD
            .decode(n)
            .map_err(|e| CedarError::jwt_validation(format!("invalid RSA modulus: {}", e)))?;
        let e_bytes = URL_SAFE_NO_PAD
            .decode(e)
            .map_err(|e| CedarError::jwt_validation(format!("invalid RSA exponent: {}", e)))?;

        // Build public key in PKCS#1 DER format
        let public_key_der = build_rsa_public_key_der(&n_bytes, &e_bytes);

        let algorithm: &dyn signature::VerificationAlgorithm = match alg {
            "RS256" => &signature::RSA_PKCS1_2048_8192_SHA256,
            "RS384" => &signature::RSA_PKCS1_2048_8192_SHA384,
            "RS512" => &signature::RSA_PKCS1_2048_8192_SHA512,
            _ => {
                return Err(CedarError::jwt_validation(format!(
                    "unsupported RSA algorithm: {}",
                    alg
                )))
            }
        };

        let public_key = UnparsedPublicKey::new(algorithm, &public_key_der);
        public_key
            .verify(message, signature)
            .map_err(|_| CedarError::jwt_validation("signature verification failed"))
    }

    fn verify_ec_signature(
        &self,
        alg: &str,
        jwk: &super::jwks::Jwk,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        use aws_lc_rs::signature::{self, UnparsedPublicKey};

        let x = jwk
            .x
            .as_ref()
            .ok_or_else(|| CedarError::jwt_validation("EC key missing x coordinate"))?;
        let y = jwk
            .y
            .as_ref()
            .ok_or_else(|| CedarError::jwt_validation("EC key missing y coordinate"))?;

        let x_bytes = URL_SAFE_NO_PAD
            .decode(x)
            .map_err(|e| CedarError::jwt_validation(format!("invalid EC x coordinate: {}", e)))?;
        let y_bytes = URL_SAFE_NO_PAD
            .decode(y)
            .map_err(|e| CedarError::jwt_validation(format!("invalid EC y coordinate: {}", e)))?;

        // Build uncompressed EC public key (0x04 || x || y)
        let mut public_key_bytes = vec![0x04];
        public_key_bytes.extend_from_slice(&x_bytes);
        public_key_bytes.extend_from_slice(&y_bytes);

        let algorithm: &dyn signature::VerificationAlgorithm = match alg {
            "ES256" => &signature::ECDSA_P256_SHA256_FIXED,
            "ES384" => &signature::ECDSA_P384_SHA384_FIXED,
            "ES512" => {
                // Note: ES512 uses P-521 curve, but aws-lc-rs may not support ECDSA_P521
                // Fall back to error for now
                return Err(CedarError::jwt_validation(
                    "ES512 not supported in current FIPS configuration",
                ));
            }
            _ => {
                return Err(CedarError::jwt_validation(format!(
                    "unsupported EC algorithm: {}",
                    alg
                )))
            }
        };

        let public_key = UnparsedPublicKey::new(algorithm, &public_key_bytes);
        public_key
            .verify(message, signature)
            .map_err(|_| CedarError::jwt_validation("signature verification failed"))
    }

    fn validate_claims(&self, claims: &Claims, config: &ValidationConfig) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let clock_skew = config.clock_skew.max(self.clock_skew);

        // Check expiration
        if let Some(exp) = claims.exp {
            if now > exp + clock_skew {
                debug!(exp = exp, now = now, "Token expired");
                return Err(CedarError::jwt_validation("token expired"));
            }
        }

        // Check not before
        if let Some(nbf) = claims.nbf {
            if now + clock_skew < nbf {
                debug!(nbf = nbf, now = now, "Token not yet valid");
                return Err(CedarError::jwt_validation("token not yet valid"));
            }
        }

        // Check issuer
        match &claims.iss {
            Some(iss) if iss == &config.issuer => {}
            Some(iss) => {
                warn!(expected = %config.issuer, actual = %iss, "Issuer mismatch");
                return Err(CedarError::jwt_validation(format!(
                    "invalid issuer: expected {}, got {}",
                    config.issuer, iss
                )));
            }
            None => {
                return Err(CedarError::jwt_validation("missing issuer claim"));
            }
        }

        // Check audience
        match &claims.aud {
            Some(aud) if aud.contains(&config.audience) => {}
            Some(_) => {
                return Err(CedarError::jwt_validation(format!(
                    "invalid audience: expected {}",
                    config.audience
                )));
            }
            None => {
                return Err(CedarError::jwt_validation("missing audience claim"));
            }
        }

        Ok(())
    }
}

/// Check if algorithm is FIPS-compliant
fn is_fips_algorithm(alg: &str) -> bool {
    matches!(
        alg,
        "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512"
    )
}

/// Build RSA public key in DER format from n and e components
fn build_rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    // RSA public key in PKCS#1 format:
    // RSAPublicKey ::= SEQUENCE {
    //     modulus           INTEGER,
    //     publicExponent    INTEGER
    // }

    fn encode_integer(value: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();

        // Strip leading zeros but keep one if the high bit is set
        let value = match value.iter().position(|&b| b != 0) {
            Some(pos) => &value[pos..],
            None => &[0u8],
        };

        // Add leading zero if high bit is set (to ensure positive number)
        let needs_padding = !value.is_empty() && (value[0] & 0x80) != 0;
        let len = value.len() + if needs_padding { 1 } else { 0 };

        encoded.push(0x02); // INTEGER tag
        encode_length(len, &mut encoded);
        if needs_padding {
            encoded.push(0x00);
        }
        encoded.extend_from_slice(value);

        encoded
    }

    fn encode_length(len: usize, out: &mut Vec<u8>) {
        if len < 128 {
            out.push(len as u8);
        } else if len < 256 {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        }
    }

    let n_encoded = encode_integer(n);
    let e_encoded = encode_integer(e);
    let content_len = n_encoded.len() + e_encoded.len();

    let mut der = Vec::new();
    der.push(0x30); // SEQUENCE tag
    encode_length(content_len, &mut der);
    der.extend_from_slice(&n_encoded);
    der.extend_from_slice(&e_encoded);

    der
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audience_contains() {
        let single = Audience::Single("api".to_string());
        assert!(single.contains("api"));
        assert!(!single.contains("other"));

        let multiple = Audience::Multiple(vec!["api".to_string(), "web".to_string()]);
        assert!(multiple.contains("api"));
        assert!(multiple.contains("web"));
        assert!(!multiple.contains("other"));
    }

    #[test]
    fn test_fips_algorithm_check() {
        assert!(is_fips_algorithm("RS256"));
        assert!(is_fips_algorithm("RS384"));
        assert!(is_fips_algorithm("RS512"));
        assert!(is_fips_algorithm("ES256"));
        assert!(is_fips_algorithm("ES384"));
        assert!(is_fips_algorithm("ES512"));
        assert!(!is_fips_algorithm("HS256"));
        assert!(!is_fips_algorithm("none"));
    }

    #[test]
    fn test_get_claim() {
        let mut extra = HashMap::new();
        extra.insert(
            "custom".to_string(),
            serde_json::json!({
                "roles": ["admin", "user"],
                "nested": {
                    "value": 42
                }
            }),
        );

        let token = ValidatedToken {
            claims: Claims {
                sub: Some("user123".to_string()),
                extra,
                ..Default::default()
            },
            kid: None,
            alg: "RS256".to_string(),
        };

        // Test nested path
        let roles = token.get_claim("custom.roles");
        assert!(roles.is_some());

        // Test deep nested path
        let nested_value = token.get_claim("custom.nested.value");
        assert!(nested_value.is_some());
        assert_eq!(nested_value.unwrap(), &serde_json::json!(42));

        // Test non-existent path
        assert!(token.get_claim("nonexistent.path").is_none());
    }

    #[test]
    fn test_get_roles() {
        let mut extra = HashMap::new();
        extra.insert("roles".to_string(), serde_json::json!(["admin", "user"]));

        let token = ValidatedToken {
            claims: Claims {
                extra,
                ..Default::default()
            },
            kid: None,
            alg: "RS256".to_string(),
        };

        let roles = token.get_roles("roles");
        assert_eq!(roles, vec!["admin", "user"]);
    }

    #[test]
    fn test_build_rsa_der() {
        // Simple test with known values
        let n = vec![0x00, 0x01, 0x02, 0x03];
        let e = vec![0x01, 0x00, 0x01]; // 65537

        let der = build_rsa_public_key_der(&n, &e);

        // Should start with SEQUENCE tag
        assert_eq!(der[0], 0x30);
    }
}
