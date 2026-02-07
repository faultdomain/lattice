//! Infrastructure installation utilities
//!
//! Provides functions for installing infrastructure components like Istio, Cilium, and CAPI.

use std::time::Duration;

use kube::api::ListParams;
use kube::{Api, Client};

use lattice_common::{
    apply_manifests_with_discovery, ApplyOptions, ParentConfig, LATTICE_SYSTEM_NAMESPACE,
};

/// Maximum retries for infrastructure apply (handles transient 503 errors during startup)
const INFRA_APPLY_MAX_RETRIES: u32 = 10;
/// Delay between infrastructure apply retries
const INFRA_APPLY_RETRY_DELAY: Duration = Duration::from_secs(5);

use lattice_capi::installer::{
    copy_credentials_to_provider_namespace, CapiInstaller, CapiProviderConfig, NativeInstaller,
};
use lattice_common::crd::{CloudProvider, LatticeCluster, ProviderType};
use lattice_infra::bootstrap::{self, InfrastructureConfig};

use super::polling::{wait_for_resource, DEFAULT_POLL_INTERVAL, DEFAULT_RESOURCE_TIMEOUT};

/// Apply manifests with retry logic for transient errors (503, connection issues).
///
/// During cluster startup, the API server may return 503 while webhooks or
/// other services are still initializing. This function retries on such errors.
async fn apply_manifests_with_retry(
    client: &Client,
    manifests: &[String],
    context: &str,
) -> anyhow::Result<()> {
    let mut last_error = None;

    for attempt in 1..=INFRA_APPLY_MAX_RETRIES {
        match apply_manifests_with_discovery(client, manifests, &ApplyOptions::default()).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                let err_str = e.to_string();
                // Retry on transient errors (503, connection refused, etc.)
                let is_transient = err_str.contains("503")
                    || err_str.contains("Service Unavailable")
                    || err_str.contains("connection refused")
                    || err_str.contains("connection reset");

                if is_transient && attempt < INFRA_APPLY_MAX_RETRIES {
                    tracing::warn!(
                        attempt = attempt,
                        max_attempts = INFRA_APPLY_MAX_RETRIES,
                        error = %err_str,
                        context = context,
                        "Transient error applying manifests, retrying..."
                    );
                    tokio::time::sleep(INFRA_APPLY_RETRY_DELAY).await;
                    last_error = Some(e);
                    continue;
                }

                // Non-transient error or max retries reached
                return Err(e.into());
            }
        }
    }

    Err(last_error
        .map(|e| anyhow::anyhow!("{}", e))
        .unwrap_or_else(|| anyhow::anyhow!("max retries reached")))
}

/// Reconcile Service-mode infrastructure (Istio, Gateway API, ESO, Cilium policies)
///
/// Reads config from env vars instead of LatticeCluster CRD, so it can run
/// independently in Service mode without requiring a LatticeCluster to exist.
pub async fn ensure_service_infrastructure(client: &Client) -> anyhow::Result<()> {
    let cluster_name = std::env::var("LATTICE_CLUSTER_NAME").unwrap_or_else(|_| "default".into());
    let is_bootstrap = lattice_common::is_bootstrap_cluster();

    tracing::info!(
        cluster = %cluster_name,
        is_bootstrap,
        "Applying Service mode infrastructure..."
    );

    let config = InfrastructureConfig {
        cluster_name,
        skip_service_mesh: false,
        skip_cilium_policies: is_bootstrap,
        ..Default::default()
    };

    let manifests = bootstrap::generate_core(&config)
        .await
        .map_err(|e| anyhow::anyhow!("failed to generate service infrastructure: {}", e))?;
    tracing::info!(count = manifests.len(), "applying service infrastructure");
    apply_manifests_with_retry(client, &manifests, "service infrastructure").await?;

    tracing::info!("Service infrastructure installation complete");
    Ok(())
}

/// Reconcile Cluster-mode infrastructure (CAPI, operator network policies)
///
/// Reads provider/bootstrap from LatticeCluster CRD (the source of truth).
/// Ensures all infrastructure is installed. Server-side apply handles idempotency.
///
/// IMPORTANT: Uses the SAME generate_core() function as the bootstrap webhook.
/// This guarantees upgrades work by changing Lattice version - on restart,
/// the operator re-applies identical infrastructure manifests.
pub async fn ensure_cluster_infrastructure(client: &Client) -> anyhow::Result<()> {
    let is_bootstrap = lattice_common::is_bootstrap_cluster();

    tracing::info!(
        is_bootstrap_cluster = is_bootstrap,
        "Applying infrastructure manifests (server-side apply)..."
    );

    if is_bootstrap {
        // Bootstrap cluster (KIND): Skip Cilium policies, use "bootstrap" as cluster name
        // This is a temporary cluster that doesn't need full self-management infra
        let config = InfrastructureConfig {
            cluster_name: "bootstrap".to_string(),
            skip_cilium_policies: true,
            skip_service_mesh: true,
            monitoring: false,
            backups: false,
            external_secrets: false,
            ..Default::default()
        };
        let manifests = bootstrap::generate_core(&config)
            .await
            .map_err(|e| anyhow::anyhow!("failed to generate core infrastructure: {}", e))?;
        tracing::info!(count = manifests.len(), "applying core infrastructure");
        apply_manifests_with_retry(client, &manifests, "core infrastructure").await?;

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

        let mut config = InfrastructureConfig::from(cluster);

        // Read parent config if it exists (indicates we have an upstream parent cell)
        if let Ok(Some(parent)) = ParentConfig::read(client).await {
            config.parent_host = Some(parent.endpoint.host);
            config.parent_grpc_port = parent.endpoint.grpc_port;
        }

        tracing::info!(
            provider = ?config.provider,
            bootstrap = ?config.bootstrap,
            cluster = %config.cluster_name,
            parent_host = ?config.parent_host,
            "read config from LatticeCluster CRD"
        );

        let manifests = bootstrap::generate_core(&config)
            .await
            .map_err(|e| anyhow::anyhow!("failed to generate infrastructure manifests: {}", e))?;
        tracing::info!(
            count = manifests.len(),
            "applying all infrastructure (same as bootstrap webhook)"
        );
        apply_manifests_with_retry(client, &manifests, "full infrastructure").await?;
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
    let cloud_providers: Api<CloudProvider> =
        Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    tracing::info!(provider_ref = %provider_ref, "Waiting for CloudProvider...");
    let cp = wait_for_resource(
        &format!("CloudProvider '{}'", provider_ref),
        DEFAULT_RESOURCE_TIMEOUT,
        DEFAULT_POLL_INTERVAL,
        || {
            let cloud_providers = cloud_providers.clone();
            let provider_ref = provider_ref.clone();
            async move {
                match cloud_providers.get(&provider_ref).await {
                    Ok(cp) => Ok(Some(cp)),
                    Err(kube::Error::Api(e)) if e.code == 404 => Ok(None),
                    Err(e) => Err(format!("API error: {}", e)),
                }
            }
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("{}", e))?;
    tracing::info!(provider_ref = %provider_ref, "CloudProvider found");

    // Copy credentials to CAPI provider namespace if present
    if let Some(ref secret_ref) = cp.spec.credentials_secret_ref {
        copy_credentials_to_provider_namespace(client, infrastructure, secret_ref)
            .await
            .map_err(|e| anyhow::anyhow!("failed to copy provider credentials: {}", e))?;
    }

    let config = CapiProviderConfig::new(infrastructure)
        .map_err(|e| anyhow::anyhow!("failed to create CAPI config: {}", e))?;
    NativeInstaller::new()
        .ensure(&config)
        .await
        .map_err(|e| anyhow::anyhow!("CAPI installation failed: {}", e))?;

    tracing::info!(infrastructure = %provider_str, "CAPI providers installed successfully");
    Ok(())
}
