//! JWKS (JSON Web Key Set) caching
//!
//! Fetches and caches JWKS from OIDC providers with automatic refresh.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::error::{CedarError, Result};

/// Default refresh interval for JWKS (1 hour)
const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

/// Grace period after expiry when stale keys can still be used (24 hours)
const STALE_GRACE_PERIOD: Duration = Duration::from_secs(86400);

/// A JSON Web Key
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// Key type (e.g., "RSA", "EC")
    pub kty: String,

    /// Key ID
    #[serde(default)]
    pub kid: Option<String>,

    /// Algorithm (e.g., "RS256", "ES256")
    #[serde(default)]
    pub alg: Option<String>,

    /// Public key use (e.g., "sig")
    #[serde(default, rename = "use")]
    pub use_: Option<String>,

    // RSA key components
    /// RSA modulus (base64url)
    #[serde(default)]
    pub n: Option<String>,

    /// RSA public exponent (base64url)
    #[serde(default)]
    pub e: Option<String>,

    // EC key components
    /// EC curve name (e.g., "P-256")
    #[serde(default)]
    pub crv: Option<String>,

    /// EC x coordinate (base64url)
    #[serde(default)]
    pub x: Option<String>,

    /// EC y coordinate (base64url)
    #[serde(default)]
    pub y: Option<String>,
}

impl Jwk {
    /// Check if this key can be used for signature verification
    pub fn is_signing_key(&self) -> bool {
        self.use_.as_deref() != Some("enc")
    }

    /// Check if this is an RSA key
    pub fn is_rsa(&self) -> bool {
        self.kty == "RSA" && self.n.is_some() && self.e.is_some()
    }

    /// Check if this is an EC key
    pub fn is_ec(&self) -> bool {
        self.kty == "EC" && self.x.is_some() && self.y.is_some()
    }
}

/// JSON Web Key Set
#[derive(Debug, Clone, Deserialize)]
pub struct JwkSet {
    /// Array of JSON Web Keys
    pub keys: Vec<Jwk>,
}

/// Cached JWKS entry
#[derive(Debug, Clone)]
struct CachedJwks {
    /// The key set
    keys: JwkSet,
    /// When this entry was fetched
    fetched_at: Instant,
    /// Keys indexed by kid for fast lookup
    by_kid: HashMap<String, Jwk>,
}

impl CachedJwks {
    fn new(keys: JwkSet) -> Self {
        let by_kid = keys
            .keys
            .iter()
            .filter_map(|k| k.kid.clone().map(|kid| (kid, k.clone())))
            .collect();

        Self {
            keys,
            fetched_at: Instant::now(),
            by_kid,
        }
    }

    fn is_fresh(&self) -> bool {
        self.fetched_at.elapsed() < DEFAULT_REFRESH_INTERVAL
    }

    fn is_stale(&self) -> bool {
        self.fetched_at.elapsed() > DEFAULT_REFRESH_INTERVAL + STALE_GRACE_PERIOD
    }

    fn get_by_kid(&self, kid: &str) -> Option<&Jwk> {
        self.by_kid.get(kid)
    }

    fn get_first_signing_key(&self) -> Option<&Jwk> {
        self.keys.keys.iter().find(|k| k.is_signing_key())
    }
}

/// JWKS cache with automatic refresh
///
/// Caches JWKS from multiple issuers with configurable refresh intervals.
/// Provides graceful degradation when fetch fails (uses stale keys).
#[derive(Debug)]
pub struct JwksCache {
    /// Cached key sets by issuer URL
    cache: RwLock<HashMap<String, CachedJwks>>,
    /// HTTP client for fetching JWKS
    client: reqwest::Client,
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksCache {
    /// Create a new JWKS cache
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            cache: RwLock::new(HashMap::new()),
            client,
        }
    }

    /// Create a JWKS cache with a custom HTTP client
    pub fn with_client(client: reqwest::Client) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            client,
        }
    }

    /// Get a key by kid from a specific issuer
    ///
    /// Fetches JWKS if not cached or if refresh is needed.
    pub async fn get_key(&self, jwks_uri: &str, kid: Option<&str>) -> Result<Jwk> {
        // Check cache first
        {
            let cache = self.cache.read();
            if let Some(cached) = cache.get(jwks_uri) {
                if cached.is_fresh() {
                    return self.find_key(cached, kid);
                }
            }
        }

        // Need to fetch or refresh
        self.refresh(jwks_uri).await?;

        // Get from updated cache
        let cache = self.cache.read();
        let cached = cache
            .get(jwks_uri)
            .ok_or_else(|| CedarError::jwks_fetch(jwks_uri, "cache miss after refresh"))?;

        self.find_key(cached, kid)
    }

    /// Force refresh JWKS for an issuer
    pub async fn refresh(&self, jwks_uri: &str) -> Result<()> {
        debug!(jwks_uri = %jwks_uri, "Fetching JWKS");

        let response = self
            .client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| CedarError::jwks_fetch(jwks_uri, format!("request failed: {}", e)))?;

        if !response.status().is_success() {
            // Try to use stale cache
            let cache = self.cache.read();
            if let Some(cached) = cache.get(jwks_uri) {
                if !cached.is_stale() {
                    warn!(
                        jwks_uri = %jwks_uri,
                        status = %response.status(),
                        "JWKS fetch failed, using stale cache"
                    );
                    return Ok(());
                }
            }

            return Err(CedarError::jwks_fetch(
                jwks_uri,
                format!("HTTP {}", response.status()),
            ));
        }

        let jwks: JwkSet = response
            .json()
            .await
            .map_err(|e| CedarError::jwks_fetch(jwks_uri, format!("invalid JSON: {}", e)))?;

        info!(
            jwks_uri = %jwks_uri,
            key_count = jwks.keys.len(),
            "JWKS fetched successfully"
        );

        let cached = CachedJwks::new(jwks);
        self.cache.write().insert(jwks_uri.to_string(), cached);

        Ok(())
    }

    /// Hint to preload JWKS for an issuer
    ///
    /// This is a hint that the JWKS will be needed soon. Currently this is a no-op
    /// as JWKS are fetched lazily on first use. In the future, this could be used
    /// to warm up the cache.
    pub fn preload(&self, _jwks_uri: String) {
        // JWKS are fetched lazily on first use via get_key()
        // This method exists for API compatibility and future optimization
    }

    /// Clear the cache
    pub fn clear(&self) {
        self.cache.write().clear();
    }

    fn find_key(&self, cached: &CachedJwks, kid: Option<&str>) -> Result<Jwk> {
        if let Some(kid) = kid {
            cached
                .get_by_kid(kid)
                .cloned()
                .ok_or_else(|| CedarError::jwt_validation(format!("key not found: {}", kid)))
        } else {
            cached
                .get_first_signing_key()
                .cloned()
                .ok_or_else(|| CedarError::jwt_validation("no signing key found in JWKS"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwk_is_signing_key() {
        let signing_key = Jwk {
            kty: "RSA".to_string(),
            kid: Some("key1".to_string()),
            alg: Some("RS256".to_string()),
            use_: Some("sig".to_string()),
            n: Some("modulus".to_string()),
            e: Some("exponent".to_string()),
            crv: None,
            x: None,
            y: None,
        };
        assert!(signing_key.is_signing_key());

        let enc_key = Jwk {
            kty: "RSA".to_string(),
            kid: Some("key2".to_string()),
            alg: Some("RSA-OAEP".to_string()),
            use_: Some("enc".to_string()),
            n: Some("modulus".to_string()),
            e: Some("exponent".to_string()),
            crv: None,
            x: None,
            y: None,
        };
        assert!(!enc_key.is_signing_key());
    }

    #[test]
    fn test_jwk_type_detection() {
        let rsa_key = Jwk {
            kty: "RSA".to_string(),
            kid: None,
            alg: None,
            use_: None,
            n: Some("n".to_string()),
            e: Some("e".to_string()),
            crv: None,
            x: None,
            y: None,
        };
        assert!(rsa_key.is_rsa());
        assert!(!rsa_key.is_ec());

        let ec_key = Jwk {
            kty: "EC".to_string(),
            kid: None,
            alg: None,
            use_: None,
            n: None,
            e: None,
            crv: Some("P-256".to_string()),
            x: Some("x".to_string()),
            y: Some("y".to_string()),
        };
        assert!(!ec_key.is_rsa());
        assert!(ec_key.is_ec());
    }

    #[test]
    fn test_cached_jwks_lookup() {
        let jwks = JwkSet {
            keys: vec![
                Jwk {
                    kty: "RSA".to_string(),
                    kid: Some("key1".to_string()),
                    alg: Some("RS256".to_string()),
                    use_: Some("sig".to_string()),
                    n: Some("n".to_string()),
                    e: Some("e".to_string()),
                    crv: None,
                    x: None,
                    y: None,
                },
                Jwk {
                    kty: "RSA".to_string(),
                    kid: Some("key2".to_string()),
                    alg: Some("RS256".to_string()),
                    use_: Some("sig".to_string()),
                    n: Some("n".to_string()),
                    e: Some("e".to_string()),
                    crv: None,
                    x: None,
                    y: None,
                },
            ],
        };

        let cached = CachedJwks::new(jwks);

        assert!(cached.get_by_kid("key1").is_some());
        assert!(cached.get_by_kid("key2").is_some());
        assert!(cached.get_by_kid("nonexistent").is_none());
        assert!(cached.get_first_signing_key().is_some());
    }

    #[test]
    fn test_cache_freshness() {
        let jwks = JwkSet { keys: vec![] };
        let cached = CachedJwks::new(jwks);

        // Should be fresh immediately
        assert!(cached.is_fresh());
        assert!(!cached.is_stale());
    }
}
