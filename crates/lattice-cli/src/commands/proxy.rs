//! Proxy connection utilities.
//!
//! Provides shared logic for fetching proxy kubeconfigs. Used by `lattice login`
//! and `lattice install`.

use std::time::Duration;

use tracing::{debug, warn};

use crate::{Error, Result};

/// Maximum number of retry attempts for transient (5xx / connection) errors.
const MAX_RETRIES: u32 = 5;
/// Initial backoff delay between retries.
const INITIAL_BACKOFF: Duration = Duration::from_secs(2);

/// Fetch kubeconfig JSON from the proxy's `/kubeconfig` endpoint.
///
/// Retries on transient errors (5xx, connection failures) with exponential
/// backoff. Fails immediately on 4xx errors (auth/permission problems).
pub(crate) async fn fetch_kubeconfig(server: &str, token: &str, insecure: bool) -> Result<String> {
    let client = if insecure {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| Error::command_failed(format!("failed to build HTTP client: {}", e)))?
    } else {
        reqwest::Client::new()
    };

    let url = format!("{}/kubeconfig", server.trim_end_matches('/'));
    let mut backoff = INITIAL_BACKOFF;

    for attempt in 1..=MAX_RETRIES {
        debug!("Fetching kubeconfig from {} (attempt {})", url, attempt);

        let result = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .timeout(Duration::from_secs(10))
            .send()
            .await;

        let response = match result {
            Ok(r) => r,
            Err(e) => {
                if attempt == MAX_RETRIES {
                    return Err(Error::command_failed(format!(
                        "failed to connect to {} after {} attempts: {}",
                        url, MAX_RETRIES, e
                    )));
                }
                warn!(
                    "Failed to connect to {} (attempt {}/{}): {}, retrying in {:?}",
                    url, attempt, MAX_RETRIES, e, backoff
                );
                tokio::time::sleep(backoff).await;
                backoff *= 2;
                continue;
            }
        };

        let status = response.status();
        if status.is_success() {
            let body = response
                .text()
                .await
                .map_err(|e| {
                    Error::command_failed(format!("failed to read response body: {}", e))
                })?;

            serde_json::from_str::<serde_json::Value>(&body).map_err(|e| {
                Error::command_failed(format!("proxy returned invalid JSON: {}", e))
            })?;

            return Ok(body);
        }

        // 4xx errors are not transient — fail immediately
        if status.is_client_error() {
            let body = response.text().await.unwrap_or_default();
            return Err(Error::command_failed(format!(
                "proxy returned {} from {}: {}",
                status, url, body
            )));
        }

        // 5xx errors are transient — retry
        let body = response.text().await.unwrap_or_default();
        if attempt == MAX_RETRIES {
            return Err(Error::command_failed(format!(
                "proxy returned {} from {} after {} attempts: {}",
                status, url, MAX_RETRIES, body
            )));
        }
        warn!(
            "Proxy returned {} (attempt {}/{}): {}, retrying in {:?}",
            status, attempt, MAX_RETRIES, body, backoff
        );
        tokio::time::sleep(backoff).await;
        backoff *= 2;
    }

    unreachable!("loop always returns")
}

/// Extract cluster names (context names) from a proxy kubeconfig JSON string.
pub(crate) fn extract_cluster_names(kubeconfig_json: &str) -> Result<Vec<String>> {
    let kc: kube::config::Kubeconfig = serde_json::from_str(kubeconfig_json)
        .map_err(|e| Error::command_failed(format!("failed to parse kubeconfig: {}", e)))?;
    Ok(kc
        .contexts
        .iter()
        .filter_map(|c| c.name.clone().into())
        .collect())
}
