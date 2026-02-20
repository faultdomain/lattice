//! Kubernetes client helpers for e2e tests
#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use kube::{
    api::{Api, PostParams},
    config::{KubeConfigOptions, Kubeconfig},
    Client,
};
use lattice_common::retry::{retry_with_backoff, RetryConfig};

/// Create a kube client from a kubeconfig file with proper timeouts.
///
/// Retries on transient connection failures (up to 10 attempts with exponential backoff).
pub async fn client_from_kubeconfig(path: &str) -> Result<Client, String> {
    let path = path.to_string();
    retry_with_backoff(
        &RetryConfig::with_max_attempts(10),
        "create_kube_client",
        || {
            let path = path.clone();
            async move { client_from_kubeconfig_inner(&path).await }
        },
    )
    .await
}

/// Create a Kubernetes resource with retry logic (survives port-forward restarts).
///
/// Wraps `api.create()` with exponential backoff. If a transient error caused
/// the resource to be created server-side but the response was lost, subsequent
/// retries will get `AlreadyExists` (409). We handle this by fetching the
/// existing resource instead of retrying forever.
pub async fn create_with_retry<K>(api: &Api<K>, resource: &K, name: &str) -> Result<K, String>
where
    K: kube::Resource + Clone + serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug,
{
    let api = api.clone();
    let resource = resource.clone();
    let name = name.to_string();
    let op_name = format!("create_{}", name);
    retry_with_backoff(&RetryConfig::with_max_attempts(60), &op_name, || {
        let api = api.clone();
        let resource = resource.clone();
        let name = name.clone();
        async move {
            match api.create(&PostParams::default(), &resource).await {
                Ok(created) => Ok(created),
                Err(kube::Error::Api(ref err_resp)) if err_resp.code == 409 => {
                    // AlreadyExists — a previous attempt succeeded but we lost the response.
                    // Fetch the existing resource so callers get a valid object back.
                    api.get(&name)
                        .await
                        .map_err(|e| format!("Failed to get existing {}: {}", name, e))
                }
                Err(e) => Err(format!("Failed to create {}: {}", name, e)),
            }
        }
    })
    .await
}

/// Patch a Kubernetes resource with retry logic (survives port-forward restarts).
pub async fn patch_with_retry<K>(
    api: &Api<K>,
    name: &str,
    params: &kube::api::PatchParams,
    patch: &kube::api::Patch<serde_json::Value>,
) -> Result<K, String>
where
    K: kube::Resource + Clone + serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug,
{
    let api = api.clone();
    let name = name.to_string();
    let params = params.clone();
    let patch = patch.clone();
    let op_name = format!("patch_{}", name);
    retry_with_backoff(&RetryConfig::with_max_attempts(60), &op_name, || {
        let api = api.clone();
        let name = name.clone();
        let params = params.clone();
        let patch = patch.clone();
        async move {
            api.patch(&name, &params, &patch)
                .await
                .map_err(|e| format!("Failed to patch {}: {}", name, e))
        }
    })
    .await
}

/// Inner function for client creation (called by retry wrapper).
async fn client_from_kubeconfig_inner(path: &str) -> Result<Client, String> {
    let kubeconfig =
        Kubeconfig::read_from(path).map_err(|e| format!("Failed to read kubeconfig: {}", e))?;

    let mut config =
        kube::Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
            .await
            .map_err(|e| format!("Failed to create kube config: {}", e))?;

    config.connect_timeout = Some(Duration::from_secs(5));
    config.read_timeout = Some(Duration::from_secs(30));

    Client::try_from(config).map_err(|e| format!("Failed to create client: {}", e))
}
