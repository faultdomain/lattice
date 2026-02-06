//! Proxy connection resolution utilities.
//!
//! Provides shared logic for discovering the Lattice auth proxy, creating
//! ServiceAccount tokens, and fetching proxy kubeconfigs. Used by `lattice login`.

use kube::api::ListParams;
use kube::Api;
use lattice_operator::crd::LatticeCluster;
use tracing::{debug, info};

use crate::{Error, Result};

/// Parameters for resolving a proxy connection.
///
/// Used by `lattice login` to discover/connect to the proxy, authenticate,
/// and fetch a kubeconfig.
pub(crate) struct ProxyConnectionParams {
    pub kubeconfig: Option<String>,
    pub server: Option<String>,
    pub token: Option<String>,
    pub namespace: String,
    pub service_account: String,
    pub port_forward: bool,
    pub insecure: bool,
}

/// Resolve the proxy server URL and bearer token.
///
/// Returns `(server_url, token, Option<PortForward>)`. The `PortForward` is kept
/// alive as long as the caller holds it — dropping it kills the kubectl process.
///
/// Priority:
/// - `server` overrides auto-discovered proxy URL
/// - `token` overrides auto-generated SA token
/// - `kubeconfig` provides both via cluster introspection
/// - `port_forward` forces a kubectl port-forward instead of direct access
pub(crate) async fn resolve_proxy_connection(
    params: &ProxyConnectionParams,
) -> Result<(String, String, Option<super::port_forward::PortForward>)> {
    if let (Some(server), Some(token)) = (&params.server, &params.token) {
        return Ok((server.clone(), token.clone(), None));
    }

    let kubeconfig_path = params.kubeconfig.as_deref().ok_or_else(|| {
        Error::validation(
            "--kubeconfig is required (or provide both --server and --token for direct mode)",
        )
    })?;

    let (server, port_forward) = match &params.server {
        Some(s) => (s.clone(), None),
        None => {
            debug!("Discovering proxy endpoint from cluster");
            let endpoint = discover_proxy_endpoint(kubeconfig_path).await?;

            if params.port_forward || is_docker_internal_ip(&endpoint) {
                if is_docker_internal_ip(&endpoint) {
                    info!(
                        "Detected Docker-internal IP in endpoint ({}), using port-forward",
                        endpoint
                    );
                }
                let pf = super::port_forward::PortForward::start(
                    kubeconfig_path,
                    lattice_common::DEFAULT_AUTH_PROXY_PORT,
                )
                .await?;
                let url = pf.url.clone();
                (url, Some(pf))
            } else {
                (endpoint, None)
            }
        }
    };

    let token = match &params.token {
        Some(t) => t.clone(),
        None => {
            debug!(
                "Creating SA token (namespace={}, sa={})",
                params.namespace, params.service_account
            );
            super::create_sa_token(
                kubeconfig_path,
                &params.namespace,
                &params.service_account,
                "1h",
            )?
        }
    };

    Ok((server, token, port_forward))
}

/// Discover the auth proxy endpoint from a parent cluster's LatticeCluster CRD.
pub(crate) async fn discover_proxy_endpoint(kubeconfig_path: &str) -> Result<String> {
    let client = super::kube_client_from_path(kubeconfig_path).await?;

    let api: Api<LatticeCluster> = Api::all(client);
    let clusters = api
        .list(&ListParams::default())
        .await
        .map_err(|e| Error::command_failed(format!("failed to list LatticeCluster CRDs: {}", e)))?
        .items;

    let parent = clusters
        .iter()
        .find(|c| c.spec.is_parent())
        .ok_or_else(|| {
            Error::command_failed(
                "no parent cluster found (no LatticeCluster with parent_config). \
                 Use --server to specify the proxy URL manually.",
            )
        })?;

    parent
        .spec
        .parent_config
        .as_ref()
        .and_then(|e| e.auth_proxy_endpoint())
        .ok_or_else(|| {
            Error::command_failed(
                "parent cluster has no proxy endpoint (host not set). \
                 Use --server to specify the proxy URL manually.",
            )
        })
}

/// Check if a URL contains a Docker-internal IP (172.18.x.x subnet).
pub(crate) fn is_docker_internal_ip(url: &str) -> bool {
    let host = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = host.split(':').next().unwrap_or(host);
    host.starts_with("172.18.")
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_docker_internal_ip() {
        assert!(is_docker_internal_ip("https://172.18.255.1:8082"));
        assert!(is_docker_internal_ip("https://172.18.0.2:8082"));
        assert!(is_docker_internal_ip("http://172.18.1.1:8082"));
        assert!(is_docker_internal_ip("172.18.100.5"));

        assert!(!is_docker_internal_ip("https://10.0.0.1:8082"));
        assert!(!is_docker_internal_ip("https://192.168.1.1:8082"));
        assert!(!is_docker_internal_ip("https://lattice.example.com:8082"));
        assert!(!is_docker_internal_ip("https://172.19.0.1:8082"));
    }
}
