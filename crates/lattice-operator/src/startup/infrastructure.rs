//! Infrastructure installation
//!
//! Split into two phases:
//! - `ensure_capi_infrastructure`: blocking — installs cert-manager + CAPI (schedules on tainted CP)
//! - `spawn_general_infrastructure`: background — installs Istio, ESO, monitoring (needs workers)

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
use lattice_common::crd::{
    BackupsConfig, CloudProvider, LatticeCluster, MonitoringConfig, ProviderType,
};
use lattice_common::kube_utils;
use lattice_infra::bootstrap::{self, cert_manager, InfrastructureConfig};

use super::polling::{wait_for_resource, DEFAULT_POLL_INTERVAL, DEFAULT_RESOURCE_TIMEOUT};

/// Install critical infrastructure (cert-manager + CAPI) that must complete
/// before controllers start.
///
/// This is the blocking part of infrastructure setup. cert-manager and CAPI
/// have control-plane tolerations so they schedule on tainted CP nodes.
/// CAPI then provisions workers for the rest of the infrastructure.
///
/// When `capi_installer` is provided, installs cert-manager + CAPI providers.
pub async fn ensure_capi_infrastructure(
    client: &Client,
    capi_installer: Option<&dyn CapiInstaller>,
) -> anyhow::Result<()> {
    let is_bootstrap = lattice_common::is_bootstrap_cluster();

    if is_bootstrap {
        if let Some(installer) = capi_installer {
            ensure_capi_on_bootstrap(client, installer).await?;
        }
    } else {
        let cluster = find_lattice_cluster(client, capi_installer.is_some()).await?;

        if let (Some(installer), Some(c)) = (capi_installer, &cluster) {
            ensure_cert_manager(client).await?;
            let provider_type = c.spec.provider.provider_type();
            let cloud_providers: Api<CloudProvider> =
                Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
            let cp = cloud_providers.get(&c.spec.provider_ref).await.ok();
            ensure_capi(client, provider_type, cp.as_ref(), installer).await?;
        }
    }

    Ok(())
}

/// Install general infrastructure (Istio, ESO, VictoriaMetrics, etc.) in the
/// background. These components need workers to schedule, so they retry until
/// workers are available. Runs as a background task — does not block startup.
///
/// `cluster_mode` indicates whether a LatticeCluster CRD is expected (true for
/// cluster/all modes where CAPI was installed).
pub fn spawn_general_infrastructure(client: Client, cluster_mode: bool) {
    tokio::spawn(async move {
        if let Err(e) = ensure_general_infrastructure(&client, cluster_mode).await {
            tracing::error!(error = %e, "general infrastructure installation failed");
        }
    });
}

/// Internal: resolve config and apply general infrastructure manifests.
async fn ensure_general_infrastructure(client: &Client, cluster_mode: bool) -> anyhow::Result<()> {
    let is_bootstrap = lattice_common::is_bootstrap_cluster();

    tracing::info!(is_bootstrap, "Installing general infrastructure...");

    let config = if is_bootstrap {
        InfrastructureConfig {
            cluster_name: "bootstrap".to_string(),
            skip_cilium_policies: true,
            skip_service_mesh: true,
            monitoring: MonitoringConfig {
                enabled: false,
                ha: false,
            },
            backups: BackupsConfig { enabled: false },
            ..Default::default()
        }
    } else {
        let cluster = find_lattice_cluster(client, cluster_mode).await?;

        match &cluster {
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
                    monitoring = ?cfg.monitoring,
                    backups = ?cfg.backups,
                    "config from LatticeCluster CRD"
                );
                cfg
            }
            None => {
                let cluster_name =
                    std::env::var("LATTICE_CLUSTER_NAME").unwrap_or_else(|_| "default".into());
                tracing::info!(cluster = %cluster_name, "no LatticeCluster CRD, using env config");
                InfrastructureConfig {
                    cluster_name,
                    monitoring: MonitoringConfig {
                        enabled: false,
                        ha: false,
                    },
                    backups: BackupsConfig { enabled: false },
                    ..Default::default()
                }
            }
        }
    };

    apply_infra(client, &config).await?;

    tracing::info!("General infrastructure installation complete");
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

    ensure_cert_manager(client).await?;
    ensure_capi(client, infrastructure, Some(&cp), installer).await
}

/// Install cert-manager from pre-rendered Helm manifests (embedded at build time).
///
/// cert-manager is required before CAPI providers (they depend on cert-manager webhooks).
/// The manifests include control-plane tolerations so cert-manager schedules on tainted
/// CP nodes before workers are available.
async fn ensure_cert_manager(client: &Client) -> anyhow::Result<()> {
    let manifests = cert_manager::generate_cert_manager();
    tracing::info!(
        version = cert_manager::cert_manager_version(),
        documents = manifests.len(),
        "Installing cert-manager"
    );

    let retry = RetryConfig {
        initial_delay: Duration::from_secs(2),
        ..RetryConfig::infinite()
    };
    retry_with_backoff(&retry, "cert-manager", || {
        let client = client.clone();
        let manifests = manifests.to_vec();
        async move {
            apply_manifests_with_discovery(&client, &manifests, &ApplyOptions::default()).await
        }
    })
    .await?;

    // Wait for cert-manager deployments to be ready before installing CAPI
    kube_utils::wait_for_all_deployments(client, "cert-manager", Duration::from_secs(300))
        .await
        .map_err(|e| anyhow::anyhow!("cert-manager deployments not ready: {}", e))?;

    tracing::info!("cert-manager ready");
    Ok(())
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
