//! cert-manager manifest generation and installation
//!
//! Embeds pre-rendered cert-manager manifests from build time.
//! Includes control-plane tolerations so cert-manager schedules on tainted CP nodes
//! before workers are available.

use std::sync::LazyLock;
use std::time::Duration;

use kube::Client;

use lattice_common::kube_utils::{self, apply_manifests, ApplyOptions};
use lattice_common::retry::{retry_with_backoff, RetryConfig};

use super::{namespace_yaml, split_yaml_documents};

static CERT_MANAGER_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml("cert-manager")];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/cert-manager.yaml"
    ))));
    manifests
});

pub fn generate_cert_manager() -> &'static [String] {
    &CERT_MANAGER_MANIFESTS
}

pub fn cert_manager_version() -> &'static str {
    env!("CERT_MANAGER_VERSION")
}

/// Install cert-manager and wait for its deployments to be ready.
///
/// cert-manager is required before CAPI providers (they depend on cert-manager webhooks).
/// The manifests include control-plane tolerations so cert-manager schedules on tainted
/// CP nodes before workers are available.
pub async fn ensure_cert_manager(client: &Client) -> anyhow::Result<()> {
    let manifests = generate_cert_manager();
    tracing::info!(
        version = cert_manager_version(),
        documents = manifests.len(),
        "Installing cert-manager"
    );

    let retry = RetryConfig {
        initial_delay: Duration::from_secs(2),
        ..RetryConfig::default()
    };
    retry_with_backoff(&retry, "cert-manager", || {
        let client = client.clone();
        let manifests = manifests.to_vec();
        async move {
            apply_manifests(&client, &manifests, &ApplyOptions::default()).await
        }
    })
    .await?;

    kube_utils::wait_for_all_deployments(client, "cert-manager", Duration::from_secs(300))
        .await
        .map_err(|e| anyhow::anyhow!("cert-manager deployments not ready: {}", e))?;

    tracing::info!("cert-manager ready");
    Ok(())
}
