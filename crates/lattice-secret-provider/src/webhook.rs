//! Local secrets webhook handler
//!
//! Serves K8s Secrets from the `lattice-secrets` namespace for ESO's webhook
//! provider. Only secrets with the `lattice.dev/secret-source: "true"` label
//! are served; all others return 404.
//!
//! All requests must include a valid `Authorization: Basic <base64>` header
//! matching the credentials stored in the `lattice-webhook-auth` K8s Secret.
//!
//! ESO protocol:
//! - URL template: `.../secret/{{ .remoteRef.key }}/{{ .remoteRef.property }}`
//! - `spec.data` entries: ESO renders property (e.g. `/secret/foo/password`)
//! - `dataFrom.extract`: ESO renders empty property (e.g. `/secret/foo/`)
//! - `result.jsonPath: "$"` tells ESO to use the response as-is

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use base64::Engine;
use kube::api::Api;
use kube::Client;
use tracing::info;

use lattice_common::{LOCAL_SECRETS_NAMESPACE, LOCAL_SECRETS_PORT};

/// Label that must be present (and set to "true") on source secrets
const SECRET_SOURCE_LABEL: &str = "lattice.dev/secret-source";

/// Credentials for webhook Basic auth
#[derive(Clone, Debug)]
pub struct WebhookCredentials {
    /// HTTP Basic auth username
    pub username: String,
    /// HTTP Basic auth password (zeroized on drop)
    pub password: zeroize::Zeroizing<String>,
}

impl WebhookCredentials {
    /// Compute the expected `Authorization` header value
    pub fn basic_auth_header(&self) -> String {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.username, *self.password));
        format!("Basic {encoded}")
    }
}

/// Shared state for webhook handlers
struct WebhookState {
    client: Client,
    expected_auth: String,
}

/// Start the webhook HTTP server on `LOCAL_SECRETS_PORT`
///
/// Returns an error if the server fails to bind or encounters a fatal error.
pub async fn start_webhook_server(
    client: Client,
    credentials: WebhookCredentials,
) -> Result<(), std::io::Error> {
    let state = Arc::new(WebhookState {
        expected_auth: credentials.basic_auth_header(),
        client,
    });
    let app = Router::new()
        .route("/secret/{name}/{*rest}", get(handle_with_property))
        .route("/secret/{name}", get(handle_all_keys))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state);
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], LOCAL_SECRETS_PORT));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(addr = %addr, "Local secrets webhook started (Basic auth enabled)");
    axum::serve(listener, app).await
}

/// Validate the Authorization header against expected credentials.
fn check_auth(headers: &HeaderMap, expected: &str) -> Result<(), (StatusCode, String)> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "missing Authorization header".to_string(),
        ))?;

    // Use constant-time comparison to prevent timing side-channel attacks
    use subtle::ConstantTimeEq;
    if auth.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1 {
        return Err((StatusCode::UNAUTHORIZED, "invalid credentials".to_string()));
    }

    Ok(())
}

/// Fetch and decode a labeled K8s Secret from the `lattice-secrets` namespace.
async fn fetch_secret_data(
    client: &Client,
    name: &str,
) -> Result<BTreeMap<String, String>, (StatusCode, String)> {
    let api: Api<k8s_openapi::api::core::v1::Secret> =
        Api::namespaced(client.clone(), LOCAL_SECRETS_NAMESPACE);

    let secret = api.get(name).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            format!("secret '{}' not found: {}", name, e),
        )
    })?;

    if !is_labeled_source(&secret) {
        return Err((
            StatusCode::NOT_FOUND,
            format!("secret '{}' not labeled as source", name),
        ));
    }

    let mut result = BTreeMap::new();

    if let Some(data) = secret.data {
        for (key, value) in data {
            let decoded =
                String::from_utf8(value.0.clone()).unwrap_or_else(|_| hex_encode(&value.0));
            result.insert(key, decoded);
        }
    }

    if let Some(string_data) = secret.string_data {
        result.extend(string_data);
    }

    Ok(result)
}

/// Resolve a secret request: return one property or the full map.
///
/// Empty property → full JSON map (for `dataFrom.extract`).
/// Non-empty property → single JSON value (for `spec.data` entries).
fn resolve_secret(
    data: BTreeMap<String, String>,
    name: &str,
    property: &str,
) -> Result<Response, (StatusCode, String)> {
    if property.is_empty() {
        return Ok(axum::Json(data).into_response());
    }

    match data.get(property) {
        Some(value) => Ok(axum::Json(value).into_response()),
        None => Err((
            StatusCode::NOT_FOUND,
            format!("property '{}' not found in secret '{}'", property, name),
        )),
    }
}

/// Handle `GET /secret/{name}/{*rest}` — property extraction or empty-property fallback.
///
/// The `{*rest}` catch-all matches both:
/// - `/secret/foo/password` (rest = "/password") → returns single key
/// - `/secret/foo/` (rest = "/") → empty property → returns full map
///
/// The trailing-slash case occurs when ESO renders `{{ .remoteRef.property }}`
/// as empty for `dataFrom.extract`.
async fn handle_with_property(
    State(state): State<Arc<WebhookState>>,
    headers: HeaderMap,
    Path((name, rest)): Path<(String, String)>,
) -> Result<Response, (StatusCode, String)> {
    check_auth(&headers, &state.expected_auth)?;
    let data = fetch_secret_data(&state.client, &name).await?;
    let property = rest.trim_matches('/');
    resolve_secret(data, &name, property)
}

/// Handle `GET /secret/{name}` — return all keys as a flat JSON map.
async fn handle_all_keys(
    State(state): State<Arc<WebhookState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    check_auth(&headers, &state.expected_auth)?;
    let data = fetch_secret_data(&state.client, &name).await?;
    resolve_secret(data, &name, "")
}

/// Check whether a K8s Secret has the `lattice.dev/secret-source: "true"` label.
fn is_labeled_source(secret: &k8s_openapi::api::core::v1::Secret) -> bool {
    secret
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(SECRET_SOURCE_LABEL))
        .is_some_and(|v| v == "true")
}

/// Fallback hex encoding for binary data that isn't valid UTF-8.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn secret_source_label_constant() {
        assert_eq!(SECRET_SOURCE_LABEL, "lattice.dev/secret-source");
    }

    #[test]
    fn hex_encode_fallback_produces_hex() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn unlabeled_secret_is_not_source() {
        assert!(!is_labeled_source(
            &k8s_openapi::api::core::v1::Secret::default()
        ));
    }

    #[test]
    fn wrong_label_value_is_not_source() {
        let mut secret = k8s_openapi::api::core::v1::Secret::default();
        secret.metadata.labels = Some(BTreeMap::from([(
            SECRET_SOURCE_LABEL.to_string(),
            "false".to_string(),
        )]));
        assert!(!is_labeled_source(&secret));
    }

    #[test]
    fn correct_label_is_source() {
        let mut secret = k8s_openapi::api::core::v1::Secret::default();
        secret.metadata.labels = Some(BTreeMap::from([(
            SECRET_SOURCE_LABEL.to_string(),
            "true".to_string(),
        )]));
        assert!(is_labeled_source(&secret));
    }

    #[test]
    fn resolve_secret_empty_property_returns_full_map() {
        let data = BTreeMap::from([
            ("username".to_string(), "admin".to_string()),
            ("password".to_string(), "s3cret".to_string()),
        ]);
        assert!(resolve_secret(data, "test", "").is_ok());
    }

    #[test]
    fn resolve_secret_with_property_returns_single_value() {
        let data = BTreeMap::from([
            ("username".to_string(), "admin".to_string()),
            ("password".to_string(), "s3cret".to_string()),
        ]);
        assert!(resolve_secret(data, "test", "password").is_ok());
    }

    #[test]
    fn resolve_secret_missing_property_returns_not_found() {
        let data = BTreeMap::from([("username".to_string(), "admin".to_string())]);
        let (status, msg) = resolve_secret(data, "test", "missing").unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(msg.contains("missing"));
    }

    #[test]
    fn basic_auth_header_encodes_correctly() {
        let creds = WebhookCredentials {
            username: "user".to_string(),
            password: zeroize::Zeroizing::new("pass".to_string()),
        };
        let expected_b64 = base64::engine::general_purpose::STANDARD.encode("user:pass");
        assert_eq!(creds.basic_auth_header(), format!("Basic {expected_b64}"));
    }

    #[test]
    fn check_auth_accepts_valid_credentials() {
        let expected = WebhookCredentials {
            username: "user".to_string(),
            password: zeroize::Zeroizing::new("pass".to_string()),
        }
        .basic_auth_header();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_str(&expected).unwrap());
        assert!(check_auth(&headers, &expected).is_ok());
    }

    #[test]
    fn check_auth_rejects_missing_header() {
        let (status, _) = check_auth(&HeaderMap::new(), "Basic xxx").unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn check_auth_rejects_wrong_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Basic wrong"));
        let (status, _) = check_auth(&headers, "Basic correct").unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
