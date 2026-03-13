//! OIDC authentication
//!
//! Validates OIDC tokens and extracts user identity for Cedar authorization.
//!
//! # Provider Inheritance
//!
//! OIDC providers can be inherited from parent clusters:
//! - If an inherited provider exists (labeled `lattice.dev/inherited: true`), it's used by default
//! - Local providers only take effect if `allow_child_override: true` on the inherited provider
//! - This ensures authentication cannot be bypassed by child clusters

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use kube::{Api, Client};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::error::{Error, Result};
use lattice_common::crd::OIDCProvider;
use lattice_common::{is_local_resource, LATTICE_SYSTEM_NAMESPACE};

/// Validated user identity from OIDC token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentity {
    /// Username (from configured claim, default: sub)
    pub username: String,
    /// Groups (from configured claim, default: groups)
    pub groups: Vec<String>,
}

/// OIDC configuration loaded from OIDCProvider CRD
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

/// Maximum number of force-refresh attempts from unknown `kid` values per
/// refresh interval. Prevents unauthenticated users from triggering unbounded
/// outbound HTTP requests to the OIDC provider (SSRF amplification).
const MAX_UNKNOWN_KID_REFRESHES: u32 = 3;

/// OIDC token validator
pub struct OidcValidator {
    /// OIDC configuration
    config: OidcConfig,
    /// JWKS cache
    jwks_cache: Arc<RwLock<Option<JwksCache>>>,
    /// Serializes JWKS refresh attempts to prevent thundering herd
    refresh_lock: tokio::sync::Mutex<()>,
    /// HTTP client for fetching JWKS
    http_client: reqwest::Client,
    /// Counter for force-refresh attempts triggered by unknown `kid` values.
    /// Reset on each successful scheduled refresh.
    unknown_kid_refresh_count: std::sync::atomic::AtomicU32,
}

impl OidcValidator {
    /// Create a new validator (placeholder for testing)
    pub fn new() -> Self {
        Self {
            config: OidcConfig::default(),
            jwks_cache: Arc::new(RwLock::new(None)),
            refresh_lock: tokio::sync::Mutex::new(()),
            http_client: reqwest::Client::new(),
            unknown_kid_refresh_count: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Create validator from OIDCProvider CRD
    ///
    /// Loads the appropriate OIDCProvider from lattice-system namespace,
    /// respecting inheritance rules:
    /// - Inherited providers take precedence by default
    /// - Local providers only used if inherited provider has `allow_child_override: true`
    pub async fn from_crd(client: &Client) -> Result<Self> {
        let api: Api<OIDCProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

        // Fetch all providers in one call, partition into inherited and local
        let all_providers = api.list(&Default::default()).await?;
        let mut inherited: Option<OIDCProvider> = None;
        let mut local: Option<OIDCProvider> = None;
        for provider in all_providers.items {
            if is_local_resource(&provider.metadata) {
                local.get_or_insert(provider);
            } else {
                inherited.get_or_insert(provider);
            }
        }

        // Determine which provider to use
        let (provider, source) = match (inherited, local) {
            // Both exist: use inherited unless allow_child_override is true
            (Some(inherited_provider), Some(local_provider)) => {
                if inherited_provider.spec.allow_child_override {
                    info!(
                        inherited_issuer = %inherited_provider.spec.issuer_url,
                        local_issuer = %local_provider.spec.issuer_url,
                        "Using local OIDC provider (child override allowed)"
                    );
                    (local_provider, "local")
                } else {
                    debug!(
                        inherited_issuer = %inherited_provider.spec.issuer_url,
                        local_issuer = %local_provider.spec.issuer_url,
                        "Ignoring local OIDC provider (child override not allowed)"
                    );
                    (inherited_provider, "inherited")
                }
            }
            // Only inherited exists
            (Some(inherited_provider), None) => (inherited_provider, "inherited"),
            // Only local exists
            (None, Some(local_provider)) => (local_provider, "local"),
            // None exist
            (None, None) => {
                return Err(Error::Config(
                    "No OIDCProvider found in lattice-system".into(),
                ));
            }
        };

        let spec = &provider.spec;

        // Validate issuer URL to prevent SSRF via CRD manipulation
        validate_issuer_url(&spec.issuer_url)?;

        let audiences = if spec.audiences.is_empty() {
            vec![spec.client_id.clone()]
        } else {
            spec.audiences.clone()
        };

        let config = OidcConfig {
            issuer_url: spec.issuer_url.clone(),
            client_id: spec.client_id.clone(),
            audiences,
            username_claim: spec.username_claim.clone(),
            groups_claim: spec.groups_claim.clone(),
            username_prefix: spec.username_prefix.clone(),
            groups_prefix: spec.groups_prefix.clone(),
            jwks_refresh_interval: Duration::from_secs(spec.jwks_refresh_interval_seconds as u64),
        };

        info!(
            issuer = %config.issuer_url,
            client_id = %config.client_id,
            source = source,
            "Loaded OIDC configuration from CRD"
        );

        Ok(Self {
            config,
            jwks_cache: Arc::new(RwLock::new(None)),
            refresh_lock: tokio::sync::Mutex::new(()),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(|e| Error::Config(format!("Failed to create HTTP client: {}", e)))?,
            unknown_kid_refresh_count: std::sync::atomic::AtomicU32::new(0),
        })
    }

    /// Create validator with explicit configuration (for testing)
    pub fn with_config(config: OidcConfig) -> Self {
        Self {
            config,
            jwks_cache: Arc::new(RwLock::new(None)),
            refresh_lock: tokio::sync::Mutex::new(()),
            http_client: reqwest::Client::new(),
            unknown_kid_refresh_count: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Get the OIDC configuration
    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    /// Validate an OIDC token and extract user identity
    ///
    /// # Arguments
    /// * `token` - Bearer token from Authorization header
    ///
    /// # Returns
    /// User identity with username and groups
    pub async fn validate(&self, token: &str) -> Result<UserIdentity> {
        // Check if we have a valid configuration
        if self.config.issuer_url.is_empty() {
            return Err(Error::Config("OIDC not configured".into()));
        }

        // Reject excessively long tokens to prevent DoS via base64 decode
        if token.len() > 16_384 {
            return Err(Error::Unauthorized("Token too large".into()));
        }

        // Decode header to get kid and algorithm
        let header = decode_header(token)?;
        let kid = header.kid.as_deref();
        let alg = header.alg;

        // Restrict to asymmetric algorithms only to prevent algorithm substitution
        // attacks (e.g., using HMAC with a public key as the secret)
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
                return Err(Error::Unauthorized(format!(
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

        Ok(UserIdentity { username, groups })
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

        value.ok_or_else(|| Error::Unauthorized(format!("Missing required claim: {}", claim_name)))
    }

    /// Extract groups from claims
    fn extract_groups(&self, claims: &JwtClaims) -> Vec<String> {
        if self.config.groups_claim == "groups" {
            return claims.groups.clone().into_vec();
        }

        // Try to get from extra claims
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

        // Fall back to standard groups claim
        claims.groups.clone().into_vec()
    }

    /// Get decoding key from JWKS cache, refreshing if needed.
    ///
    /// On a cache miss for an unknown `kid`, triggers a refresh before failing.
    /// This handles legitimate key rotation where the IdP starts signing with a
    /// new key before our cache TTL expires, preventing auth outages.
    async fn get_decoding_key(&self, kid: Option<&str>) -> Result<DecodingKey> {
        // Refresh if cache is empty or expired
        self.ensure_jwks_fresh().await?;

        // Try to find the key
        if let Some(key) = self.lookup_key(kid).await {
            return Ok(key);
        }

        // Key not found — could be a legitimate key rotation. Force refresh
        // once and retry, but rate-limit to prevent unauthenticated users from
        // triggering unbounded outbound requests (SSRF amplification).
        let attempts = self.unknown_kid_refresh_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if attempts >= MAX_UNKNOWN_KID_REFRESHES {
            warn!(kid = ?kid, attempts, max = MAX_UNKNOWN_KID_REFRESHES, "Rate-limiting JWKS refresh for unknown kid");
            return Err(Error::Unauthorized(format!("No matching key found in JWKS for kid: {:?}", kid)));
        }
        debug!(kid = ?kid, "Key not found in JWKS cache, forcing refresh for possible key rotation");
        self.force_refresh_jwks().await?;

        self.lookup_key(kid).await.ok_or_else(|| {
            Error::Unauthorized(format!("No matching key found in JWKS for kid: {:?}", kid))
        })
    }

    /// Look up a key in the current JWKS cache
    ///
    /// When `kid` is None, requires exactly one key in the JWKS to avoid
    /// non-deterministic key selection from HashMap iteration order.
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
            // Reset the unknown-kid refresh counter on scheduled refresh,
            // since the cache is now fresh and any previous unknown kids
            // may now be present after key rotation.
            self.unknown_kid_refresh_count.store(0, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    }

    /// Force a JWKS refresh, serializing concurrent attempts
    async fn force_refresh_jwks(&self) -> Result<()> {
        let _guard = self.refresh_lock.lock().await;
        // Re-check after acquiring lock — another task may have refreshed already.
        // Use a short threshold (5s) to avoid re-fetching if we literally just did.
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
        // Fetch OIDC discovery document
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer_url.trim_end_matches('/')
        );

        debug!(url = %discovery_url, "Fetching OIDC discovery document");

        let discovery: OidcDiscovery = self
            .http_client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("Failed to fetch OIDC discovery: {}", e)))?
            .json()
            .await
            .map_err(|e| Error::Internal(format!("Invalid OIDC discovery response: {}", e)))?;

        // Validate issuer matches
        if discovery.issuer != self.config.issuer_url {
            return Err(Error::Config(format!(
                "Issuer mismatch: expected {}, got {}",
                self.config.issuer_url, discovery.issuer
            )));
        }

        // Validate jwks_uri shares the same origin as the issuer to prevent
        // MITM redirection of JWKS fetches to attacker-controlled servers
        validate_jwks_uri_origin(&self.config.issuer_url, &discovery.jwks_uri)?;

        // Fetch JWKS
        debug!(url = %discovery.jwks_uri, "Fetching JWKS");

        let jwks: JwksDocument = self
            .http_client
            .get(&discovery.jwks_uri)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("Failed to fetch JWKS: {}", e)))?
            .json()
            .await
            .map_err(|e| Error::Internal(format!("Invalid JWKS response: {}", e)))?;

        // Convert JWK keys to decoding keys
        let mut keys = HashMap::new();
        for jwk in jwks.keys {
            if let Some(key) = self.jwk_to_decoding_key(&jwk)? {
                let kid = jwk.kid.unwrap_or_else(|| "default".to_string());
                keys.insert(kid, key);
            }
        }

        if keys.is_empty() {
            return Err(Error::Config("No usable keys found in JWKS".into()));
        }

        info!(key_count = keys.len(), "Refreshed JWKS cache");

        // Update cache
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
                    .ok_or_else(|| Error::Config("RSA key missing 'n'".into()))?;
                let e = jwk
                    .e
                    .as_ref()
                    .ok_or_else(|| Error::Config("RSA key missing 'e'".into()))?;

                DecodingKey::from_rsa_components(n, e)
                    .map(Some)
                    .map_err(|e| Error::Config(format!("Invalid RSA key: {}", e)))
            }
            "EC" => {
                let crv = jwk
                    .crv
                    .as_ref()
                    .ok_or_else(|| Error::Config("EC key missing 'crv'".into()))?;
                let x = jwk
                    .x
                    .as_ref()
                    .ok_or_else(|| Error::Config("EC key missing 'x'".into()))?;
                let y = jwk
                    .y
                    .as_ref()
                    .ok_or_else(|| Error::Config("EC key missing 'y'".into()))?;

                match crv.as_str() {
                    "P-256" => DecodingKey::from_ec_components(x, y)
                        .map(Some)
                        .map_err(|e| Error::Config(format!("Invalid EC P-256 key: {}", e))),
                    "P-384" => DecodingKey::from_ec_components(x, y)
                        .map(Some)
                        .map_err(|e| Error::Config(format!("Invalid EC P-384 key: {}", e))),
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

/// Validate that an OIDC issuer URL is safe to fetch from.
///
/// Prevents SSRF by requiring HTTPS and rejecting IP-literal URLs pointing to
/// private/reserved ranges (RFC 1918, loopback, link-local, cloud metadata).
/// Hostnames are allowed since we can't reliably pre-resolve them, but blocking
/// IP literals covers the direct SSRF vector.
fn validate_issuer_url(url: &str) -> Result<()> {
    if !url.starts_with("https://") {
        return Err(Error::Config(format!(
            "OIDC issuer URL must use HTTPS: {}",
            url
        )));
    }

    let host = extract_host(url).ok_or_else(|| {
        Error::Config(format!("Failed to parse host from issuer URL: {}", url))
    })?;

    // If the host is an IP literal, check it's not a private/reserved address
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_private_ip(&ip) {
            return Err(Error::Config(format!(
                "OIDC issuer URL must not point to a private/reserved IP address: {}",
                url
            )));
        }
    }

    Ok(())
}

/// Extract the host portion from a URL (without port).
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let host_port = after_scheme.split('/').next()?;
    // Strip port if present
    let host = if host_port.starts_with('[') {
        // IPv6: [::1]:443
        host_port.split(']').next().map(|h| &h[1..])?
    } else {
        host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port)
    };
    Some(host.to_string())
}

/// Check if an IP address is private, loopback, link-local, or otherwise reserved.
fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()              // 127.0.0.0/8
                || v4.is_private()        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local()     // 169.254.0.0/16 (includes cloud metadata)
                || v4.is_broadcast()      // 255.255.255.255
                || v4.is_unspecified()    // 0.0.0.0
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()              // ::1
                || v6.is_unspecified()    // ::
                // fc00::/7 (unique local)
                || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Validate that the JWKS URI shares the same origin (scheme + host) as the issuer URL.
///
/// Prevents MITM attacks where a compromised discovery document redirects JWKS
/// fetches to an attacker-controlled server while keeping the issuer field correct.
fn validate_jwks_uri_origin(issuer_url: &str, jwks_uri: &str) -> Result<()> {
    let issuer_origin = extract_origin(issuer_url);
    let jwks_origin = extract_origin(jwks_uri);

    match (issuer_origin, jwks_origin) {
        (Some(issuer), Some(jwks)) if issuer == jwks => Ok(()),
        (Some(issuer), Some(jwks)) => Err(Error::Config(format!(
            "JWKS URI origin mismatch: issuer is '{}' but jwks_uri points to '{}'",
            issuer, jwks
        ))),
        _ => Err(Error::Config(format!(
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
    // Host ends at first '/' or end of string
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

    #[test]
    fn test_validate_issuer_url_accepts_https() {
        assert!(validate_issuer_url("https://accounts.google.com").is_ok());
        assert!(validate_issuer_url("https://idp.example.com/realms/lattice").is_ok());
    }

    #[test]
    fn test_validate_issuer_url_rejects_http() {
        let result = validate_issuer_url("http://accounts.google.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTPS"));
    }

    #[test]
    fn test_validate_issuer_url_rejects_private_ips() {
        assert!(validate_issuer_url("https://10.0.0.1").is_err());
        assert!(validate_issuer_url("https://172.16.0.1").is_err());
        assert!(validate_issuer_url("https://192.168.1.1").is_err());
        assert!(validate_issuer_url("https://127.0.0.1").is_err());
    }

    #[test]
    fn test_validate_issuer_url_rejects_link_local() {
        // Cloud metadata endpoint
        assert!(validate_issuer_url("https://169.254.169.254").is_err());
    }

    #[test]
    fn test_validate_issuer_url_accepts_public_ip() {
        assert!(validate_issuer_url("https://8.8.8.8").is_ok());
    }

    #[test]
    fn test_validate_issuer_url_accepts_hostname() {
        // Hostnames can't be pre-resolved so they're allowed
        assert!(validate_issuer_url("https://internal.corp.example.com").is_ok());
    }

    #[test]
    fn test_extract_host_various_formats() {
        assert_eq!(extract_host("https://example.com"), Some("example.com".to_string()));
        assert_eq!(extract_host("https://example.com:443"), Some("example.com".to_string()));
        assert_eq!(extract_host("https://example.com/path"), Some("example.com".to_string()));
        assert_eq!(extract_host("https://10.0.0.1:8443/path"), Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_ip(&"169.254.169.254".parse().unwrap()));
        assert!(is_private_ip(&"::1".parse().unwrap()));
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip(&"1.1.1.1".parse().unwrap()));
    }
}
