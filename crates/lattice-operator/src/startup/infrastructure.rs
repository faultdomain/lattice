//! Infrastructure installation
//!
//! Single entry point: `ensure_infrastructure`. Reads config from the
//! LatticeCluster CRD when available, falls back to env vars for
//! service-only mode. Optionally installs CAPI when an installer is provided.

use std::time::Duration;

use kube::api::ListParams;
use kube::{Api, Client};

use lattice_common::retry::{retry_with_backoff, RetryConfig};
use lattice_common::{
    apply_manifests_with_discovery, ApplyOptions, ParentConfig, LATTICE_SYSTEM_NAMESPACE,
};

use lattice_capi::installer::{
    copy_credentials_to_provider_namespace, CapiInstaller, CapiProviderConfig,
};
use lattice_common::crd::{CloudProvider, LatticeCluster, ProviderType};
use lattice_infra::bootstrap::{self, InfrastructureConfig};

use super::polling::{wait_for_resource, DEFAULT_POLL_INTERVAL, DEFAULT_RESOURCE_TIMEOUT};

/// Install all infrastructure components.
///
/// Config resolution order:
/// 1. **Bootstrap cluster**: minimal config (no monitoring, backups, ESO, mesh)
/// 2. **LatticeCluster CRD exists**: read all settings from CRD (cluster/all mode)
/// 3. **No CRD**: env vars only, no monitoring/backups (service-only mode)
///
/// When `capi_installer` is provided, also installs CAPI providers.
pub async fn ensure_infrastructure(
    client: &Client,
    capi_installer: Option<&dyn CapiInstaller>,
) -> anyhow::Result<()> {
    let is_bootstrap = lattice_common::is_bootstrap_cluster();

    tracing::info!(is_bootstrap, "Installing infrastructure...");

    if is_bootstrap {
        let config = InfrastructureConfig {
            cluster_name: "bootstrap".to_string(),
            skip_cilium_policies: true,
            skip_service_mesh: true,
            monitoring: false,
            backups: false,
            ..Default::default()
        };

        apply_infra(client, &config).await?;

        if let Some(installer) = capi_installer {
            ensure_capi_on_bootstrap(client, installer).await?;
        }
    } else {
        // Resolve config from LatticeCluster CRD or env vars.
        // When capi_installer is Some we're in cluster/all mode and a
        // LatticeCluster MUST exist (pivoted from parent), so wait for it.
        let cluster = find_lattice_cluster(client, capi_installer.is_some()).await?;

        let config = match &cluster {
            Some(c) => {
                let mut cfg = InfrastructureConfig::from(c);
                if let Ok(Some(parent)) = ParentConfig::read(client).await {
                    cfg.parent_host = Some(parent.endpoint.host);
                    cfg.parent_grpc_port = parent.endpoint.grpc_port;
                }
                tracing::info!(
                    provider = ?cfg.provider,
                    bootstrap = ?cfg.bootstrap,
                    cluster = %cfg.cluster_name,
                    parent_host = ?cfg.parent_host,
                    monitoring = cfg.monitoring,
                    backups = cfg.backups,
                    "config from LatticeCluster CRD"
                );
                cfg
            }
            None => {
                // Service-only mode: no CRD, no monitoring/backups
                let cluster_name =
                    std::env::var("LATTICE_CLUSTER_NAME").unwrap_or_else(|_| "default".into());
                tracing::info!(cluster = %cluster_name, "no LatticeCluster CRD, using env config");
                InfrastructureConfig {
                    cluster_name,
                    monitoring: false,
                    backups: false,
                    ..Default::default()
                }
            }
        };

        apply_infra(client, &config).await?;

        // Install CAPI so the cluster can self-manage
        if let (Some(installer), Some(c)) = (capi_installer, &cluster) {
            let provider_type = c.spec.provider.provider_type();
            let cloud_providers: Api<CloudProvider> =
                Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
            let cp = cloud_providers.get(&c.spec.provider_ref).await.ok();
            ensure_capi(client, provider_type, cp.as_ref(), installer).await?;
        }
    }

    tracing::info!("Infrastructure installation complete");
    Ok(())
}

/// Find the LatticeCluster instance.
///
/// When `required` is true (cluster/all mode), retries forever with
/// exponential backoff until the API server registers the CRD and an
/// instance appears (the CRD definition may have just been applied).
/// When `required` is false (service-only mode), returns `None` immediately
/// if no instance exists.
async fn find_lattice_cluster(
    client: &Client,
    required: bool,
) -> anyhow::Result<Option<LatticeCluster>> {
    let clusters: Api<LatticeCluster> = Api::all(client.clone());

    if !required {
        return Ok(clusters
            .list(&ListParams::default())
            .await
            .ok()
            .and_then(|list| list.items.into_iter().next()));
    }

    // Cluster/all mode: the LatticeCluster must exist (pivoted from parent).
    // Retry forever — the API server may still be registering the CRD schema.
    let retry = RetryConfig {
        initial_delay: Duration::from_secs(1),
        ..RetryConfig::infinite()
    };
    retry_with_backoff(&retry, "find LatticeCluster", || {
        let clusters = clusters.clone();
        async move {
            match clusters.list(&ListParams::default()).await {
                Ok(list) => match list.items.into_iter().next() {
                    Some(c) => Ok(c),
                    None => Err(String::from("no LatticeCluster instance found yet")),
                },
                Err(e) => Err(format!("API error: {e}")),
            }
        }
    })
    .await
    .map(Some)
    .map_err(|e| anyhow::anyhow!("{}", e))
}

/// Generate and apply infrastructure manifests with infinite retry.
async fn apply_infra(client: &Client, config: &InfrastructureConfig) -> anyhow::Result<()> {
    let manifests = bootstrap::generate_core(config)
        .await
        .map_err(|e| anyhow::anyhow!("failed to generate infrastructure: {}", e))?;
    tracing::info!(count = manifests.len(), "applying infrastructure manifests");

    let retry = RetryConfig {
        initial_delay: Duration::from_secs(2),
        ..RetryConfig::infinite()
    };
    retry_with_backoff(&retry, "infrastructure", || {
        let client = client.clone();
        let manifests = manifests.clone();
        async move {
            apply_manifests_with_discovery(&client, &manifests, &ApplyOptions::default()).await
        }
    })
    .await
    .map_err(Into::into)
}

/// Install CAPI on the bootstrap cluster.
///
/// Waits for the CloudProvider CRD (created by `lattice install` after the
/// operator starts) before installing providers.
async fn ensure_capi_on_bootstrap(
    client: &Client,
    installer: &dyn CapiInstaller,
) -> anyhow::Result<()> {
    let provider_str = std::env::var("LATTICE_PROVIDER").unwrap_or_else(|_| "docker".to_string());
    let provider_ref =
        std::env::var("LATTICE_PROVIDER_REF").unwrap_or_else(|_| provider_str.clone());

    let infrastructure: ProviderType = provider_str
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid LATTICE_PROVIDER '{}': {}", provider_str, e))?;

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

    ensure_capi(client, infrastructure, Some(&cp), installer).await
}

/// Install CAPI providers with optional credential copying.
async fn ensure_capi(
    client: &Client,
    provider_type: ProviderType,
    cloud_provider: Option<&CloudProvider>,
    installer: &dyn CapiInstaller,
) -> anyhow::Result<()> {
    tracing::info!(infrastructure = ?provider_type, "Installing CAPI providers");

    if let Some(cp) = cloud_provider {
        if let Some(ref secret_ref) = cp.k8s_secret_ref() {
            copy_credentials_to_provider_namespace(client, provider_type, secret_ref)
                .await
                .map_err(|e| anyhow::anyhow!("failed to copy provider credentials: {}", e))?;
        }
    }

    let config = CapiProviderConfig::new(provider_type)
        .map_err(|e| anyhow::anyhow!("failed to create CAPI config: {}", e))?;
    installer
        .ensure(&config)
        .await
        .map_err(|e| anyhow::anyhow!("CAPI installation failed: {}", e))?;

    tracing::info!(infrastructure = ?provider_type, "CAPI providers installed");
    Ok(())
}
