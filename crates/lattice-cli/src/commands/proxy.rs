//! Proxy connection utilities.
//!
//! Provides shared logic for fetching proxy kubeconfigs. Used by `lattice login`
//! and `lattice install`.

use std::fmt;
use std::time::Duration;

use lattice_common::retry::{retry_with_backoff_bail, RetryConfig};
use tracing::debug;

use crate::{Error, Result};

/// Internal error type that distinguishes fatal (4xx) from transient errors.
/// Converted back to `crate::Error` after the retry loop.
enum FetchError {
    /// Transient error (connection failure, 5xx) — retry
    Transient(String),
    /// Fatal error (4xx, parse failure) — bail immediately
    Fatal(String),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::Transient(msg) | FetchError::Fatal(msg) => f.write_str(msg),
        }
    }
}

impl From<FetchError> for Error {
    fn from(e: FetchError) -> Self {
        match e {
            FetchError::Transient(msg) | FetchError::Fatal(msg) => Error::command_failed(msg),
        }
    }
}

/// Fetch kubeconfig JSON from the proxy's `/kubeconfig` endpoint.
///
/// Retries on transient errors (5xx, connection failures) with exponential
/// backoff. Fails immediately on 4xx errors (auth/permission problems).
///
/// Use `max_attempts = 0` for infinite retries (e.g. during install when the
/// operator may need time to become ready).
///
/// Set `retry_forbidden = true` to treat 403 as transient (e.g. during install
/// when the CedarPolicy may not have been loaded by the controller yet).
pub(crate) async fn fetch_kubeconfig(
    server: &str,
    token: &str,
    insecure: bool,
    format: Option<&str>,
    max_attempts: u32,
    retry_forbidden: bool,
) -> Result<String> {
    let client = if insecure {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| Error::command_failed(format!("failed to build HTTP client: {}", e)))?
    } else {
        reqwest::Client::new()
    };

    let mut url = format!("{}/kubeconfig", server.trim_end_matches('/'));
    if let Some(fmt) = format {
        url = format!("{}?format={}", url, fmt);
    }

    let retry_config = RetryConfig {
        max_attempts,
        initial_delay: Duration::from_secs(2),
        max_delay: Duration::from_secs(30),
        backoff_multiplier: 2.0,
    };

    retry_with_backoff_bail(
        &retry_config,
        "fetch_kubeconfig",
        || async {
            debug!("Fetching kubeconfig from {}", url);

            let response = client
                .get(&url)
                .header("Authorization", format!("Bearer {}", token))
                .timeout(Duration::from_secs(10))
                .send()
                .await
                .map_err(|e| {
                    FetchError::Transient(format!("failed to connect to {}: {}", url, e))
                })?;

            let status = response.status();
            if status.is_success() {
                let body = response.text().await.map_err(|e| {
                    FetchError::Fatal(format!("failed to read response body: {}", e))
                })?;

                serde_json::from_str::<serde_json::Value>(&body).map_err(|e| {
                    FetchError::Fatal(format!("proxy returned invalid JSON: {}", e))
                })?;

                return Ok(body);
            }

            let body = response.text().await.unwrap_or_default();

            if status.is_client_error() {
                // 401/403 are transient during startup — the auth proxy or Cedar
                // policies may not be fully initialized yet. Retry instead of failing.
                if status == reqwest::StatusCode::UNAUTHORIZED
                    || (retry_forbidden && status == reqwest::StatusCode::FORBIDDEN)
                {
                    return Err(FetchError::Transient(format!(
                        "proxy returned {} from {}: {}",
                        status, url, body
                    )));
                }
                return Err(FetchError::Fatal(format!(
                    "proxy returned {} from {}: {}",
                    status, url, body
                )));
            }

            Err(FetchError::Transient(format!(
                "proxy returned {} from {}: {}",
                status, url, body
            )))
        },
        |e| matches!(e, FetchError::Fatal(_)),
    )
    .await
    .map_err(Error::from)
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
