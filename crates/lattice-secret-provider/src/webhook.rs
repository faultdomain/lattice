//! Local secrets webhook handler
//!
//! Serves K8s Secrets from the `lattice-secrets` namespace for ESO's webhook
//! provider. Only secrets with the `lattice.dev/secret-source: "true"` label
//! are served; all others return 404.
//!
//! ESO protocol:
//! - URL template: `.../secret/{{ .remoteRef.key }}/{{ .remoteRef.property }}`
//! - `spec.data` entries: ESO renders property (e.g. `/secret/foo/password`)
//! - `dataFrom.extract`: ESO renders empty property (e.g. `/secret/foo/`)
//! - `result.jsonPath: "$"` tells ESO to use the response as-is

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use kube::api::Api;
use kube::Client;
use tracing::info;

use lattice_common::{LOCAL_SECRETS_NAMESPACE, LOCAL_SECRETS_PORT};

/// Label that must be present (and set to "true") on source secrets
const SECRET_SOURCE_LABEL: &str = "lattice.dev/secret-source";

/// Build the webhook router with a shared `Client` state
fn webhook_routes(client: Client) -> Router {
    Router::new()
        // Catch-all handles both `/secret/foo/bar` and `/secret/foo/` (empty property)
        .route("/secret/{name}/{*rest}", get(handle_with_property))
        .route("/secret/{name}", get(handle_all_keys))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(client)
}

/// Start the webhook HTTP server on `LOCAL_SECRETS_PORT`
pub async fn start_webhook_server(client: Client) {
    let app = webhook_routes(client);
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], LOCAL_SECRETS_PORT));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => {
            info!(addr = %addr, "Local secrets webhook started");
            l
        }
        Err(e) => {
            tracing::error!(error = %e, port = LOCAL_SECRETS_PORT, "Failed to bind local secrets webhook port");
            return;
        }
    };
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!(error = %e, "Local secrets webhook server error");
    }
}

/// Fetch and decode a labeled K8s Secret from the `lattice-secrets` namespace.
async fn fetch_secret_data(
    client: Client,
    name: &str,
) -> Result<BTreeMap<String, String>, (StatusCode, String)> {
    let api: Api<k8s_openapi::api::core::v1::Secret> =
        Api::namespaced(client, LOCAL_SECRETS_NAMESPACE);

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
            format!(
                "property '{}' not found in secret '{}' (available: {:?})",
                property,
                name,
                data.keys().collect::<Vec<_>>()
            ),
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
    State(client): State<Client>,
    Path((name, rest)): Path<(String, String)>,
) -> Result<Response, (StatusCode, String)> {
    let data = fetch_secret_data(client, &name).await?;
    let property = rest.trim_matches('/');
    resolve_secret(data, &name, property)
}

/// Handle `GET /secret/{name}` — return all keys as a flat JSON map.
async fn handle_all_keys(
    State(client): State<Client>,
    Path(name): Path<String>,
) -> Result<Response, (StatusCode, String)> {
    let data = fetch_secret_data(client, &name).await?;
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

    #[test]
    fn secret_source_label_constant() {
        assert_eq!(SECRET_SOURCE_LABEL, "lattice.dev/secret-source");
    }

    #[test]
    fn hex_encode_fallback_produces_hex() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "deadbeef");
    }

    #[test]
    fn unlabeled_secret_is_not_source() {
        let secret = k8s_openapi::api::core::v1::Secret::default();
        assert!(!is_labeled_source(&secret));
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
        let response = resolve_secret(data, "test", "");
        assert!(response.is_ok());
    }

    #[test]
    fn resolve_secret_with_property_returns_single_value() {
        let data = BTreeMap::from([
            ("username".to_string(), "admin".to_string()),
            ("password".to_string(), "s3cret".to_string()),
        ]);
        let response = resolve_secret(data, "test", "password");
        assert!(response.is_ok());
    }

    #[test]
    fn resolve_secret_missing_property_returns_not_found() {
        let data = BTreeMap::from([("username".to_string(), "admin".to_string())]);
        let response = resolve_secret(data, "test", "missing");
        assert!(response.is_err());
        let (status, msg) = response.unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(msg.contains("missing"));
    }
}
