//! Proxy connection utilities.
//!
//! Provides shared logic for fetching proxy kubeconfigs. Used by `lattice login`
//! and `lattice install`.

use tracing::debug;

use crate::{Error, Result};

/// Fetch kubeconfig JSON from the proxy's `/kubeconfig` endpoint.
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
    debug!("Fetching kubeconfig from {}", url);

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| Error::command_failed(format!("failed to connect to {}: {}", url, e)))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(Error::command_failed(format!(
            "proxy returned {} from {}: {}",
            status, url, body
        )));
    }

    let body = response
        .text()
        .await
        .map_err(|e| Error::command_failed(format!("failed to read response body: {}", e)))?;

    serde_json::from_str::<serde_json::Value>(&body)
        .map_err(|e| Error::command_failed(format!("proxy returned invalid JSON: {}", e)))?;

    Ok(body)
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
