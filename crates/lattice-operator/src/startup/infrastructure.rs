//! Infrastructure installation utilities
//!
//! Provides functions for installing infrastructure components like Istio, Cilium, and CAPI.

use std::time::Duration;

use kube::api::ListParams;
use kube::{Api, Client};

use crate::capi::{ensure_capi_installed, CapiProviderConfig, ClusterctlInstaller};
use crate::crd::{CloudProvider, LatticeCluster, ProviderType};
use crate::infra::bootstrap::{self, InfrastructureConfig};

use super::manifests::apply_manifests;

/// Reconcile infrastructure components
///
/// Ensures all infrastructure is installed. Server-side apply handles idempotency.
/// This runs on every controller startup, applying the latest manifests.
///
/// IMPORTANT: Uses the SAME generate_all() function as the bootstrap webhook.
/// This guarantees upgrades work by changing Lattice version - on restart,
/// the operator re-applies identical infrastructure manifests.
pub async fn ensure_infrastructure(client: &Client) -> anyhow::Result<()> {
    let is_bootstrap_cluster = std::env::var("LATTICE_ROOT_INSTALL").is_ok()
        || std::env::var("LATTICE_BOOTSTRAP_CLUSTER")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

    tracing::info!(
        is_bootstrap_cluster,
        "Applying infrastructure manifests (server-side apply)..."
    );

    if is_bootstrap_cluster {
        // Bootstrap cluster (KIND): Use generate_core() + clusterctl init
        // This is a temporary cluster that doesn't need full self-management infra
        // Use "bootstrap" as the cluster name for the trust domain
        let manifests = bootstrap::generate_core("bootstrap", true)
            .await
            .map_err(|e| anyhow::anyhow!("failed to generate core infrastructure: {}", e))?;
        tracing::info!(count = manifests.len(), "applying core infrastructure");
        apply_manifests(client, &manifests).await?;

        tracing::info!("Installing CAPI on bootstrap cluster...");
        ensure_capi_on_bootstrap(client).await?;
    } else {
        // Workload cluster: Read provider/bootstrap from LatticeCluster CRD
        // This is the source of truth - same values used by bootstrap webhook
        let clusters: Api<LatticeCluster> = Api::all(client.clone());
        let list = clusters.list(&ListParams::default()).await?;

        let cluster = list.items.first().ok_or_else(|| {
            anyhow::anyhow!(
                "no LatticeCluster found - workload clusters must have a LatticeCluster CRD \
                 (pivoted from parent). This indicates a failed or incomplete pivot."
            )
        })?;

        let provider = cluster.spec.provider.provider_type();
        let bootstrap = cluster.spec.provider.kubernetes.bootstrap.clone();
        let cluster_name = cluster
            .metadata
            .name
            .clone()
            .ok_or_else(|| anyhow::anyhow!("LatticeCluster missing metadata.name"))?;

        tracing::info!(provider = ?provider, bootstrap = ?bootstrap, cluster = %cluster_name, "read config from LatticeCluster CRD");

        let config = InfrastructureConfig {
            provider,
            bootstrap,
            cluster_name,
            skip_cilium_policies: false,
        };

        let manifests = bootstrap::generate_all(&config)
            .await
            .map_err(|e| anyhow::anyhow!("failed to generate infrastructure manifests: {}", e))?;
        tracing::info!(
            count = manifests.len(),
            "applying all infrastructure (same as bootstrap webhook)"
        );
        apply_manifests(client, &manifests).await?;
    }

    tracing::info!("Infrastructure installation complete");
    Ok(())
}

/// Install CAPI on the bootstrap cluster.
///
/// The bootstrap cluster needs CAPI installed BEFORE a LatticeCluster is created,
/// because the installer waits for CAPI CRDs to be available. Without this, the
/// installer hangs in Phase 2 waiting for CRDs that would only be installed when
/// a LatticeCluster is reconciled (Phase 3).
///
/// Uses LATTICE_PROVIDER env var to determine which infrastructure provider to install.
/// Reads CloudProvider CRD (created by install command) for credentials.
///
/// NOTE: CloudProvider is created by the install command AFTER the operator starts,
/// so this function waits for it to exist before proceeding.
async fn ensure_capi_on_bootstrap(client: &Client) -> anyhow::Result<()> {
    let provider_str = std::env::var("LATTICE_PROVIDER").unwrap_or_else(|_| "docker".to_string());
    let provider_ref =
        std::env::var("LATTICE_PROVIDER_REF").unwrap_or_else(|_| provider_str.clone());

    let infrastructure: ProviderType = provider_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid LATTICE_PROVIDER '{}': {}", provider_str, e))?;

    tracing::info!(infrastructure = %provider_str, "Installing CAPI providers for bootstrap cluster");

    // Wait for CloudProvider to be created by install command
    let cloud_providers: Api<CloudProvider> = Api::namespaced(client.clone(), "lattice-system");
    tracing::info!(provider_ref = %provider_ref, "Waiting for CloudProvider...");
    let cp = loop {
        match cloud_providers.get(&provider_ref).await {
            Ok(cp) => break cp,
            Err(kube::Error::Api(e)) if e.code == 404 => {
                tracing::debug!(provider_ref = %provider_ref, "CloudProvider not found, waiting...");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to get CloudProvider '{}': {}",
                    provider_ref,
                    e
                ));
            }
        }
    };
    tracing::info!(provider_ref = %provider_ref, "CloudProvider found");

    // Copy credentials to CAPI provider namespace if present
    if let Some(ref secret_ref) = cp.spec.credentials_secret_ref {
        crate::capi::copy_credentials_to_provider_namespace(client, infrastructure, secret_ref)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to copy provider credentials: {}", e))?;
    }

    let config = CapiProviderConfig::new(infrastructure)
        .map_err(|e| anyhow::anyhow!("Failed to create CAPI config: {}", e))?;
    ensure_capi_installed(&ClusterctlInstaller::new(), &config)
        .await
        .map_err(|e| anyhow::anyhow!("CAPI installation failed: {}", e))?;

    tracing::info!(infrastructure = %provider_str, "CAPI providers installed successfully");
    Ok(())
}
