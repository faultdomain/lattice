//! Local secrets webhook handler
//!
//! Serves K8s Secrets from the `lattice-secrets` namespace as flat JSON maps
//! for ESO's webhook provider. Only secrets with the `lattice.dev/secret-source: "true"`
//! label are served; all others return 404.
//!
//! ESO protocol:
//! - `GET /secret/{name}` → flat JSON `{"key1":"val1", "key2":"val2"}`
//! - `remoteRef.key` becomes the `{name}` path parameter
//! - `result.jsonPath: "$"` tells ESO to use the full response map

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use kube::api::Api;
use kube::Client;
use tracing::info;

use crate::controller::{LOCAL_SECRETS_NAMESPACE, LOCAL_SECRETS_PORT};

/// Label that must be present (and set to "true") on source secrets
const SECRET_SOURCE_LABEL: &str = "lattice.dev/secret-source";

/// Build the webhook router with a shared `Client` state
pub fn webhook_routes(client: Client) -> Router {
    Router::new()
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

/// Handle `GET /secret/{name}` — look up a K8s Secret and return its data as flat JSON
async fn get_secret(
    State(client): State<Client>,
    Path(name): Path<String>,
) -> Result<Json<BTreeMap<String, String>>, (StatusCode, String)> {
    let api: Api<k8s_openapi::api::core::v1::Secret> =
        Api::namespaced(client, LOCAL_SECRETS_NAMESPACE);

    let secret = api.get(&name).await.map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            format!("secret '{}' not found: {}", name, e),
        )
    })?;

    // Only serve secrets explicitly labeled as sources
    let labels = secret.metadata.labels.as_ref();
    let is_source = labels
        .and_then(|l| l.get(SECRET_SOURCE_LABEL))
        .is_some_and(|v| v == "true");
    if !is_source {
        return Err((
            StatusCode::NOT_FOUND,
            format!("secret '{}' not labeled as source", name),
        ));
    }

    let mut result = BTreeMap::new();

    // Decode base64-encoded `data` entries
    if let Some(data) = secret.data {
        for (key, value) in data {
            let decoded =
                String::from_utf8(value.0.clone()).unwrap_or_else(|_| hex_encode(&value.0));
            result.insert(key, decoded);
        }
    }

    // `stringData` entries are plain text (unusual on read, but handle gracefully)
    if let Some(string_data) = secret.string_data {
        result.extend(string_data);
    }

    Ok(Json(result))
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
}
