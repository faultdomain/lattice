//! Local secrets webhook handler
//!
//! Serves K8s Secrets from the `lattice-secrets` namespace for ESO's webhook
//! provider. Only secrets with the `lattice.dev/secret-source: "true"` label
//! are served; all others return 404.
//!
//! ESO protocol:
//! - `GET /secret/{name}` → flat JSON `{"key1":"val1", "key2":"val2"}` (for dataFrom)
//! - `GET /secret/{name}/{property}` → single JSON string `"val1"` (for data entries)
//! - `remoteRef.key` becomes the `{name}` path parameter
//! - `remoteRef.property` becomes the `{property}` path parameter
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
        .route("/secret/{name}/{property}", get(get_secret_property))
        .route("/secret/{name}", get(get_secret))
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

/// Handle `GET /secret/{name}` — return all keys as a flat JSON map.
///
/// Used by ESO `dataFrom.extract` (no property) and ESO templates.
async fn get_secret(
    State(client): State<Client>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let data = fetch_secret_data(client, &name).await?;
    Ok(axum::Json(data))
}

/// Handle `GET /secret/{name}/{property}` — return a single key's value.
///
/// Used by ESO `data` entries with `remoteRef.property`. The ClusterSecretStore
/// URL template renders `{{ .remoteRef.property }}` into the path, so ESO
/// requests e.g. `/secret/local-db-creds/password` and gets just `"s3cret-p@ss"`.
async fn get_secret_property(
    State(client): State<Client>,
    Path((name, property)): Path<(String, String)>,
) -> Result<Response, (StatusCode, String)> {
    let data = fetch_secret_data(client, &name).await?;

    if property.is_empty() {
        return Ok(axum::Json(data).into_response());
    }

    match data.get(&property) {
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

/// Check whether a K8s Secret has the `lattice.dev/secret-source: "true"` label.
///
/// This is the gate that prevents arbitrary secrets from being exposed via the
/// webhook — only explicitly labeled secrets are served.
fn is_labeled_source(secret: &k8s_openapi::api::core::v1::Secret) -> bool {
    secret
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(SECRET_SOURCE_LABEL))
        .is_some_and(|v| v == "true")
}

/// Fallback hex encoding for binary data that isn't valid UTF-8.
/// Binary secrets that aren't valid UTF-8 are rare; hex is safe and debuggable.
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
    fn local_secrets_port_matches_controller() {
        assert_eq!(LOCAL_SECRETS_PORT, 8787);
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
}
