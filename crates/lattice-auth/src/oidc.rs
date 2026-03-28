//! OIDC authentication
//!
//! Validates OIDC tokens and extracts user identity.
//!
//! This module contains the core OIDC validation logic shared between
//! lattice-api and lattice-console. CRD-specific loading (OIDCProvider)
//! lives in lattice-api as adapter code.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::error::AuthError;
use crate::identity::Identity;

type Result<T> = std::result::Result<T, AuthError>;

/// OIDC configuration
#[derive(Clone, Debug)]
pub struct OidcConfig {
    /// OIDC issuer URL
    pub issuer_url: String,
    /// OIDC client ID
    pub client_id: String,
    /// Allowed audiences (includes client_id if empty)
    pub audiences: Vec<String>,
    /// JWT claim to use as username
    pub username_claim: String,
    /// JWT claim to use as groups
    pub groups_claim: String,
    /// Optional prefix to add to usernames
    pub username_prefix: Option<String>,
    /// Optional prefix to add to groups
    pub groups_prefix: Option<String>,
    /// JWKS refresh interval
    pub jwks_refresh_interval: Duration,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer_url: String::new(),
            client_id: String::new(),
            audiences: Vec::new(),
            username_claim: "sub".to_string(),
            groups_claim: "groups".to_string(),
            username_prefix: None,
            groups_prefix: None,
            jwks_refresh_interval: Duration::from_secs(3600),
        }
    }
}

/// JWKS cache entry
struct JwksCache {
    /// JWKS keys indexed by kid
    keys: HashMap<String, DecodingKey>,
    /// When the cache was last refreshed
    last_refresh: Instant,
}

/// JWT claims structure (flexible to handle various claim names)
///
/// Note: iss, aud, exp are validated by jsonwebtoken during decode(),
/// so we don't need to deserialize or check them here.
#[derive(Debug, Deserialize)]
struct JwtClaims {
    /// Subject (always present)
    sub: Option<String>,
    /// Email (common username claim)
    email: Option<String>,
    /// Preferred username
    preferred_username: Option<String>,
    /// Groups claim (may be array or single value)
    #[serde(default)]
    groups: GroupsClaim,
    /// Custom claims stored for flexible access
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

/// Groups claim can be array or single string
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(untagged)]
enum GroupsClaim {
    #[default]
    None,
    Single(String),
    Multiple(Vec<String>),
}

impl GroupsClaim {
    fn into_vec(self) -> Vec<String> {
        match self {
            GroupsClaim::None => vec![],
            GroupsClaim::Single(s) => vec![s],
            GroupsClaim::Multiple(v) => v,
        }
    }
}

/// OIDC discovery document
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    issuer: String,
    jwks_uri: String,
}

/// JWKS document
#[derive(Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<JwkKey>,
}

/// Individual JWK key
#[derive(Debug, Deserialize)]
struct JwkKey {
    /// Key type (RSA, EC)
    kty: String,
    /// Key ID
    kid: Option<String>,
    /// RSA modulus (for RSA keys)
    n: Option<String>,
    /// RSA exponent (for RSA keys)
    e: Option<String>,
    /// EC curve (for EC keys)
    crv: Option<String>,
    /// EC x coordinate (for EC keys)
    x: Option<String>,
    /// EC y coordinate (for EC keys)
    y: Option<String>,
}

/// Maximum number of distinct unknown `kid` values that trigger a JWKS refresh
/// per refresh interval. Prevents unauthenticated users from triggering unbounded
/// outbound HTTP requests to the OIDC provider (SSRF amplification).
const MAX_UNKNOWN_KIDS: usize = 5;

/// OIDC token validator
pub struct OidcValidator {
    /// OIDC configuration
    config: OidcConfig,
    /// JWKS cache
    jwks_cache: Arc<RwLock<Option<JwksCache>>>,
    /// Serializes JWKS refresh attempts to prevent thundering herd
    refresh_lock: tokio::sync::Mutex<()>,
    /// Set of unknown `kid` values that have already triggered a JWKS refresh.
    /// Cleared on each scheduled refresh.
    refreshed_kids: std::sync::Mutex<HashSet<String>>,
    /// Whether HTTP issuer URLs are allowed (for dev/testing)
    allow_insecure_http: bool,
}

impl OidcValidator {
    /// Create a new validator (placeholder for testing)
    pub fn new() -> Self {
        Self {
            config: OidcConfig::default(),
            jwks_cache: Arc::new(RwLock::new(None)),
            refresh_lock: tokio::sync::Mutex::new(()),
            refreshed_kids: std::sync::Mutex::new(HashSet::new()),
            allow_insecure_http: false,
        }
    }

    /// Create validator with explicit configuration
    pub fn with_config(config: OidcConfig) -> Self {
        Self {
            config,
            jwks_cache: Arc::new(RwLock::new(None)),
            refresh_lock: tokio::sync::Mutex::new(()),
            refreshed_kids: std::sync::Mutex::new(HashSet::new()),
            allow_insecure_http: false,
        }
    }

    /// Create validator with explicit configuration and insecure HTTP allowed
    pub fn with_config_insecure(config: OidcConfig) -> Self {
        Self {
            config,
            jwks_cache: Arc::new(RwLock::new(None)),
            refresh_lock: tokio::sync::Mutex::new(()),
            refreshed_kids: std::sync::Mutex::new(HashSet::new()),
            allow_insecure_http: true,
        }
    }

    /// Get the OIDC configuration
    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    /// Whether insecure HTTP is allowed
    pub fn allow_insecure_http(&self) -> bool {
        self.allow_insecure_http
    }

    /// Validate an OIDC token and extract user identity
    pub async fn validate(&self, token: &str) -> Result<Identity> {
        if self.config.issuer_url.is_empty() {
            return Err(AuthError::Config("OIDC not configured".into()));
        }

        // Reject excessively long tokens to prevent DoS via base64 decode
        if token.len() > 16_384 {
            return Err(AuthError::Unauthorized("Token too large".into()));
        }

        // Decode header to get kid and algorithm
        let header = decode_header(token)?;
        let kid = header.kid.as_deref();
        let alg = header.alg;

        // Restrict to asymmetric algorithms only to prevent algorithm substitution attacks
        use jsonwebtoken::Algorithm;
        match alg {
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => {}
            _ => {
                return Err(AuthError::Unauthorized(format!(
                    "Unsupported JWT algorithm: {:?}",
                    alg
                )));
            }
        }

        debug!(kid = ?kid, alg = ?alg, "Decoded JWT header");

        // Get decoding key from JWKS
        let key = self.get_decoding_key(kid).await?;

        // Build validation with the verified asymmetric algorithm
        let mut validation = Validation::new(alg);
        validation.set_issuer(&[&self.config.issuer_url]);
        validation.set_audience(&self.config.audiences);
        validation.validate_exp = true;

        // Decode and validate token
        let token_data = decode::<JwtClaims>(token, &key, &validation)?;
        let claims = token_data.claims;

        // Extract username from configured claim
        let raw_username = self.extract_claim(&claims, &self.config.username_claim)?;
        let username = match &self.config.username_prefix {
            Some(prefix) => format!("{}{}", prefix, raw_username),
            None => raw_username,
        };

        // Extract groups from configured claim
        let raw_groups = self.extract_groups(&claims);
        let groups = match &self.config.groups_prefix {
            Some(prefix) => raw_groups
                .into_iter()
                .map(|g| format!("{}{}", prefix, g))
                .collect(),
            None => raw_groups,
        };

        debug!(username = %username, groups = ?groups, "Validated OIDC token");

        Ok(Identity { username, groups })
    }

    /// Extract a claim value by name
    fn extract_claim(&self, claims: &JwtClaims, claim_name: &str) -> Result<String> {
        let value = match claim_name {
            "sub" => claims.sub.clone(),
            "email" => claims.email.clone(),
            "preferred_username" => claims.preferred_username.clone(),
            _ => claims
                .extra
                .get(claim_name)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        };

        value.ok_or_else(|| {
            AuthError::Unauthorized(format!("Missing required claim: {}", claim_name))
        })
    }

    /// Extract groups from claims
    ///
    /// When a custom `groups_claim` is configured, only that claim is used.
    /// No fallback to the standard `groups` claim — falling back could grant
    /// unexpected group memberships from a claim the admin didn't intend.
    fn extract_groups(&self, claims: &JwtClaims) -> Vec<String> {
        if self.config.groups_claim == "groups" {
            return claims.groups.clone().into_vec();
        }

        // Custom claim configured — use only that claim, no fallback
        if let Some(value) = claims.extra.get(&self.config.groups_claim) {
            if let Some(arr) = value.as_array() {
                return arr
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect();
            }
            if let Some(s) = value.as_str() {
                return vec![s.to_string()];
            }
        }

        vec![]
    }

    /// Get decoding key from JWKS cache, refreshing if needed.
    async fn get_decoding_key(&self, kid: Option<&str>) -> Result<DecodingKey> {
        self.ensure_jwks_fresh().await?;

        if let Some(key) = self.lookup_key(kid).await {
            return Ok(key);
        }

        // Key not found — could be legitimate key rotation. Force refresh once,
        // rate-limited per-kid to prevent SSRF amplification.
        let kid_str = kid.unwrap_or("none").to_string();
        {
            let mut refreshed = self
                .refreshed_kids
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if refreshed.contains(&kid_str) {
                return Err(AuthError::Unauthorized(format!(
                    "No matching key found in JWKS for kid: {:?}",
                    kid
                )));
            }
            if refreshed.len() >= MAX_UNKNOWN_KIDS {
                warn!(kid = ?kid, max = MAX_UNKNOWN_KIDS, "Rate-limiting JWKS refresh: too many distinct unknown kids");
                return Err(AuthError::Unauthorized(format!(
                    "No matching key found in JWKS for kid: {:?}",
                    kid
                )));
            }
            refreshed.insert(kid_str);
        }
        debug!(kid = ?kid, "Key not found in JWKS cache, forcing refresh for possible key rotation");
        self.force_refresh_jwks().await?;

        self.lookup_key(kid).await.ok_or_else(|| {
            AuthError::Unauthorized(format!("No matching key found in JWKS for kid: {:?}", kid))
        })
    }

    /// Look up a key in the current JWKS cache
    async fn lookup_key(&self, kid: Option<&str>) -> Option<DecodingKey> {
        let cache = self.jwks_cache.read().await;
        let cache = cache.as_ref()?;
        match kid {
            Some(kid) => cache.keys.get(kid).cloned(),
            None => {
                if cache.keys.len() == 1 {
                    cache.keys.values().next().cloned()
                } else {
                    warn!(
                        key_count = cache.keys.len(),
                        "JWT has no kid and JWKS has multiple keys — rejecting"
                    );
                    None
                }
            }
        }
    }

    /// Ensure JWKS cache is populated and not expired
    async fn ensure_jwks_fresh(&self) -> Result<()> {
        let needs_refresh = {
            let cache = self.jwks_cache.read().await;
            match &*cache {
                None => true,
                Some(c) => c.last_refresh.elapsed() > self.config.jwks_refresh_interval,
            }
        };

        if needs_refresh {
            self.force_refresh_jwks().await?;
            self.refreshed_kids
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
        }
        Ok(())
    }

    /// Force a JWKS refresh, serializing concurrent attempts
    async fn force_refresh_jwks(&self) -> Result<()> {
        let _guard = self.refresh_lock.lock().await;
        let still_needs = {
            let cache = self.jwks_cache.read().await;
            match &*cache {
                None => true,
                Some(c) => c.last_refresh.elapsed() > Duration::from_secs(5),
            }
        };
        if still_needs {
            self.refresh_jwks().await?;
        }
        Ok(())
    }

    /// Refresh JWKS from the issuer
    async fn refresh_jwks(&self) -> Result<()> {
        let validated =
            validate_issuer_url(&self.config.issuer_url, self.allow_insecure_http).await?;

        // Build a pinned HTTP client that connects to the validated IPs only
        let mut client_builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
        for addr in &validated.resolved_ips {
            client_builder = client_builder.resolve(&validated.host, *addr);
        }
        let pinned_client = client_builder
            .build()
            .map_err(|e| AuthError::Config(format!("Failed to create pinned HTTP client: {}", e)))?;

        // Fetch OIDC discovery document
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer_url.trim_end_matches('/')
        );

        debug!(url = %discovery_url, "Fetching OIDC discovery document");

        let discovery: OidcDiscovery = pinned_client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to fetch OIDC discovery: {}", e)))?
            .json()
            .await
            .map_err(|e| {
                AuthError::Internal(format!("Invalid OIDC discovery response: {}", e))
            })?;

        if discovery.issuer != self.config.issuer_url {
            return Err(AuthError::Config(format!(
                "Issuer mismatch: expected {}, got {}",
                self.config.issuer_url, discovery.issuer
            )));
        }

        validate_jwks_uri_origin(&self.config.issuer_url, &discovery.jwks_uri)?;

        debug!(url = %discovery.jwks_uri, "Fetching JWKS");

        let jwks: JwksDocument = pinned_client
            .get(&discovery.jwks_uri)
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to fetch JWKS: {}", e)))?
            .json()
            .await
            .map_err(|e| AuthError::Internal(format!("Invalid JWKS response: {}", e)))?;

        let mut keys = HashMap::new();
        for jwk in jwks.keys {
            if let Some(key) = self.jwk_to_decoding_key(&jwk)? {
                let kid = jwk.kid.unwrap_or_else(|| "default".to_string());
                keys.insert(kid, key);
            }
        }

        if keys.is_empty() {
            return Err(AuthError::Config("No usable keys found in JWKS".into()));
        }

        info!(key_count = keys.len(), "Refreshed JWKS cache");

        let mut cache = self.jwks_cache.write().await;
        *cache = Some(JwksCache {
            keys,
            last_refresh: Instant::now(),
        });

        Ok(())
    }

    /// Convert a JWK to a DecodingKey
    fn jwk_to_decoding_key(&self, jwk: &JwkKey) -> Result<Option<DecodingKey>> {
        match jwk.kty.as_str() {
            "RSA" => {
                let n = jwk
                    .n
                    .as_ref()
                    .ok_or_else(|| AuthError::Config("RSA key missing 'n'".into()))?;
                let e = jwk
                    .e
                    .as_ref()
                    .ok_or_else(|| AuthError::Config("RSA key missing 'e'".into()))?;

                DecodingKey::from_rsa_components(n, e)
                    .map(Some)
                    .map_err(|e| AuthError::Config(format!("Invalid RSA key: {}", e)))
            }
            "EC" => {
                let crv = jwk
                    .crv
                    .as_ref()
                    .ok_or_else(|| AuthError::Config("EC key missing 'crv'".into()))?;
                let x = jwk
                    .x
                    .as_ref()
                    .ok_or_else(|| AuthError::Config("EC key missing 'x'".into()))?;
                let y = jwk
                    .y
                    .as_ref()
                    .ok_or_else(|| AuthError::Config("EC key missing 'y'".into()))?;

                match crv.as_str() {
                    "P-256" => DecodingKey::from_ec_components(x, y)
                        .map(Some)
                        .map_err(|e| AuthError::Config(format!("Invalid EC P-256 key: {}", e))),
                    "P-384" => DecodingKey::from_ec_components(x, y)
                        .map(Some)
                        .map_err(|e| AuthError::Config(format!("Invalid EC P-384 key: {}", e))),
                    _ => {
                        warn!(crv = %crv, "Unsupported EC curve");
                        Ok(None)
                    }
                }
            }
            kty => {
                warn!(kty = %kty, "Unsupported key type");
                Ok(None)
            }
        }
    }
}

/// Resolved OIDC issuer URL with pinned IP addresses.
#[derive(Debug)]
struct ValidatedIssuer {
    host: String,
    resolved_ips: Vec<std::net::SocketAddr>,
}

/// Validate that an OIDC issuer URL is safe to fetch from.
///
/// Requires HTTPS (unless `allow_insecure_http` is set).
/// Resolves hostnames via DNS and returns the resolved IPs so callers can
/// pin them in the HTTP client, preventing DNS rebinding.
async fn validate_issuer_url(url: &str, allow_insecure_http: bool) -> Result<ValidatedIssuer> {
    if !url.starts_with("https://") {
        if url.starts_with("http://") && allow_insecure_http {
            warn!(
                "OIDC issuer URL uses HTTP (allowed via config): {}",
                url
            );
        } else {
            return Err(AuthError::Config(format!(
                "OIDC issuer URL must use HTTPS: {}",
                url
            )));
        }
    }

    let host = extract_host(url)
        .ok_or_else(|| AuthError::Config(format!("Failed to parse host from issuer URL: {}", url)))?;

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let port = extract_port(url).unwrap_or(443);
        Ok(ValidatedIssuer {
            host: host.clone(),
            resolved_ips: vec![std::net::SocketAddr::new(ip, port)],
        })
    } else {
        let port = extract_port(url).unwrap_or(443);
        let addrs = tokio::net::lookup_host(format!("{}:{}", host, port))
            .await
            .map_err(|e| {
                AuthError::Config(format!(
                    "Failed to resolve OIDC issuer hostname '{}': {}",
                    host, e
                ))
            })?;

        let resolved: Vec<std::net::SocketAddr> = addrs.collect();
        if resolved.is_empty() {
            return Err(AuthError::Config(format!(
                "OIDC issuer hostname '{}' did not resolve to any addresses",
                host
            )));
        }

        Ok(ValidatedIssuer {
            host,
            resolved_ips: resolved,
        })
    }
}

/// Extract the port from a URL, if present.
fn extract_port(url: &str) -> Option<u16> {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host_port = after_scheme.split('/').next()?;
    if host_port.starts_with('[') {
        // IPv6: [::1]:443
        let after_bracket = host_port.split(']').nth(1)?;
        after_bracket.strip_prefix(':')?.parse().ok()
    } else {
        host_port.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
    }
}

/// Extract the host portion from a URL (without port).
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host_port = after_scheme.split('/').next()?;
    let host = if host_port.starts_with('[') {
        // IPv6: [::1]:443
        host_port.split(']').next().map(|h| &h[1..])?
    } else {
        host_port
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(host_port)
    };
    Some(host.to_string())
}

/// Validate that the JWKS URI shares the same origin as the issuer URL.
fn validate_jwks_uri_origin(issuer_url: &str, jwks_uri: &str) -> Result<()> {
    let issuer_origin = extract_origin(issuer_url);
    let jwks_origin = extract_origin(jwks_uri);

    match (issuer_origin, jwks_origin) {
        (Some(issuer), Some(jwks)) if issuer == jwks => Ok(()),
        (Some(issuer), Some(jwks)) => Err(AuthError::Config(format!(
            "JWKS URI origin mismatch: issuer is '{}' but jwks_uri points to '{}'",
            issuer, jwks
        ))),
        _ => Err(AuthError::Config(format!(
            "Failed to parse origin from issuer '{}' or jwks_uri '{}'",
            issuer_url, jwks_uri
        ))),
    }
}

/// Extract "scheme://host[:port]" from a URL
fn extract_origin(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let scheme = &url[..scheme_end];
    let after_scheme = &url[scheme_end + 3..];
    let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
    let host = &after_scheme[..host_end];
    Some(format!("{}://{}", scheme, host))
}

impl Default for OidcValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_groups_claim_none() {
        let groups = GroupsClaim::None;
        assert!(groups.into_vec().is_empty());
    }

    #[test]
    fn test_groups_claim_single() {
        let groups = GroupsClaim::Single("admins".to_string());
        assert_eq!(groups.into_vec(), vec!["admins"]);
    }

    #[test]
    fn test_groups_claim_multiple() {
        let groups = GroupsClaim::Multiple(vec!["admins".to_string(), "developers".to_string()]);
        assert_eq!(groups.into_vec(), vec!["admins", "developers"]);
    }

    #[test]
    fn test_oidc_config_default() {
        let config = OidcConfig::default();
        assert_eq!(config.username_claim, "sub");
        assert_eq!(config.groups_claim, "groups");
        assert!(config.issuer_url.is_empty());
    }

    #[test]
    fn test_oidc_validator_new() {
        let validator = OidcValidator::new();
        assert!(validator.config.issuer_url.is_empty());
    }

    #[tokio::test]
    async fn test_validate_without_config() {
        let validator = OidcValidator::new();
        let result = validator.validate("some-token").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not configured"));
    }

    #[tokio::test]
    async fn test_validate_issuer_url_accepts_https_ip_literals() {
        assert!(validate_issuer_url("https://8.8.8.8", false).await.is_ok());
        assert!(validate_issuer_url("https://1.1.1.1", false).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_issuer_url_rejects_http() {
        let result = validate_issuer_url("http://8.8.8.8", false).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTPS"));
    }

    #[tokio::test]
    async fn test_validate_issuer_url_allows_http_when_configured() {
        assert!(validate_issuer_url("http://8.8.8.8:8080/realms/test", true)
            .await
            .is_ok());
        assert!(validate_issuer_url("ftp://8.8.8.8:8080", true)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_validate_issuer_url_rejects_unresolvable_hostname() {
        let result =
            validate_issuer_url("https://this-hostname-does-not-exist.invalid", false).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("resolve"),
            "Expected DNS resolution error, got: {err}"
        );
    }

    #[test]
    fn test_extract_host_various_formats() {
        assert_eq!(
            extract_host("https://example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_host("https://example.com:443"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_host("https://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_host("https://10.0.0.1:8443/path"),
            Some("10.0.0.1".to_string())
        );
    }
}
