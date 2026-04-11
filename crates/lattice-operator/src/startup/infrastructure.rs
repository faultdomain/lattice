//! Phased infrastructure installation
//!
//! Infrastructure is installed in two stages:
//! - `ensure_capi_infrastructure`: blocking — cert-manager, ESO, credential sync, CAPI
//! - `spawn_general_infrastructure`: background — remaining phases with health gates

use std::time::Duration;

use kube::api::ListParams;
use kube::{Api, Client, ResourceExt};

use lattice_common::retry::{retry_with_backoff, RetryConfig};
use lattice_common::{ParentConnectionConfig, SharedConfig};
use lattice_core::LATTICE_SYSTEM_NAMESPACE;

use lattice_capi::installer::{CapiInstaller, CapiProviderConfig};
use lattice_common::crd::{
    BackupsConfig, InfraProvider, LatticeCluster, MonitoringConfig, ProviderType,
};
use lattice_infra::bootstrap::{self, InfrastructureConfig};

use super::polling::{wait_for_resource, DEFAULT_POLL_INTERVAL, DEFAULT_RESOURCE_TIMEOUT};

/// Install critical infrastructure (cert-manager + CAPI) that must complete
/// before controllers start.
///
/// cert-manager is applied as phase 0 of the phased infrastructure system
/// with its health gate (all deployments in cert-manager namespace ready).
/// CAPI providers are then installed via the native CAPI installer.
pub async fn ensure_capi_infrastructure(
    client: &Client,
    capi_installer: Option<&dyn CapiInstaller>,
    config: &SharedConfig,
) -> anyhow::Result<()> {
    if config.is_bootstrap_cluster {
        if let Some(installer) = capi_installer {
            ensure_capi_on_bootstrap(client, installer, config).await?;
        }
    } else {
        let cluster = find_lattice_cluster(client, capi_installer.is_some()).await?;

        if let (Some(installer), Some(c)) = (capi_installer, &cluster) {
            apply_prereqs_phase(client).await?;
            let provider_type = c.spec.provider.provider_type();
            let cloud_providers: Api<InfraProvider> =
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
pub fn spawn_general_infrastructure(
    client: Client,
    cluster_mode: bool,
    config: SharedConfig,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    tokio::spawn(async move { ensure_general_infrastructure(&client, cluster_mode, &config).await })
}

/// Delay before starting background infrastructure to avoid competing with
/// controller startup for API server resources. Controllers need watches
/// established quickly; infrastructure manifests can wait.
const INFRA_STAGGER_DELAY: Duration = Duration::from_secs(5);

/// Internal: resolve config and apply infrastructure phases.
async fn ensure_general_infrastructure(
    client: &Client,
    cluster_mode: bool,
    config: &SharedConfig,
) -> anyhow::Result<()> {
    // Stagger to avoid competing with controller watch setup for API server capacity.
    // Controllers are starting concurrently and need to establish ~16 watches.
    tokio::time::sleep(INFRA_STAGGER_DELAY).await;

    let is_bootstrap = config.is_bootstrap_cluster;

    tracing::info!(is_bootstrap, "Installing general infrastructure...");

    let infra_config = resolve_infra_config(client, is_bootstrap, cluster_mode, config).await?;

    // If we couldn't determine remote networks (CRD list error), skip infra apply
    // to avoid overwriting existing meshNetworks with stale data.
    if infra_config.remote_networks.is_none() {
        tracing::warn!("Skipping infrastructure apply — LatticeClusterRoutes not available");
        return Ok(());
    }

    let phases = bootstrap::generate_phases(&infra_config)
        .map_err(|e| anyhow::anyhow!("failed to generate infrastructure: {}", e))?;

    tracing::info!(
        phases = phases.len(),
        "Applying infrastructure phases (skipping cert-manager — already applied)"
    );

    // Skip phase 0 (cert-manager) — it was already applied in the blocking path.
    bootstrap::apply_all_phases(client, &phases, 1).await?;

    tracing::info!("General infrastructure installation complete");
    Ok(())
}

/// Resolve infrastructure config from cluster CRD or environment.
async fn resolve_infra_config(
    client: &Client,
    is_bootstrap: bool,
    cluster_mode: bool,
    config: &SharedConfig,
) -> anyhow::Result<InfrastructureConfig> {
    if is_bootstrap {
        return Ok(InfrastructureConfig {
            cluster_name: "bootstrap".to_string(),
            skip_cilium_policies: true,
            skip_service_mesh: true,
            monitoring: MonitoringConfig {
                enabled: false,
                ha: false,
            },
            backups: BackupsConfig { enabled: false },
            ..Default::default()
        });
    }

    let cluster = find_lattice_cluster(client, cluster_mode).await?;

    let istio_ca = lattice_infra::bootstrap::resolve_istio_ca(client).await;

    match &cluster {
        Some(c) => {
            let mut cfg = InfrastructureConfig::from(c);
            cfg.trust_domain = istio_ca.trust_domain;
            cfg.root_ca = istio_ca.root_ca;
            if let Ok(Some(parent)) = ParentConnectionConfig::read(client).await {
                cfg.parent_host = Some(parent.endpoint.host);
                cfg.parent_grpc_port = parent.endpoint.grpc_port;
            }
            // Populate remote networks for Istio meshNetworks.
            // None = error listing CRDs (skip apply to avoid clobbering).
            // Some(vec![]) = no routes exist yet (valid, apply empty networks).
            cfg.remote_networks = lattice_infra::bootstrap::discover_remote_networks(client).await;
            tracing::info!(
                provider = ?cfg.provider,
                bootstrap = ?cfg.bootstrap,
                cluster = %cfg.cluster_name,
                parent_host = ?cfg.parent_host,
                monitoring = ?cfg.monitoring,
                backups = ?cfg.backups,
                "config from LatticeCluster CRD"
            );
            Ok(cfg)
        }
        None => {
            let cluster_name = config
                .cluster_name_required()
                .map_err(|e| anyhow::anyhow!("{} (required for infrastructure generation)", e))?
                .to_string();
            tracing::info!(cluster = %cluster_name, "no LatticeCluster CRD, using env config");
            Ok(InfrastructureConfig {
                cluster_name,
                trust_domain: istio_ca.trust_domain,
                root_ca: istio_ca.root_ca,
                monitoring: MonitoringConfig {
                    enabled: false,
                    ha: false,
                },
                backups: BackupsConfig { enabled: false },
                ..Default::default()
            })
        }
    }
}

/// Apply cert-manager and ESO concurrently, then create the local webhook store.
///
/// Both are independent — ESO manages its own webhook certs. Deploying them
/// in a single phase lets them start in parallel, reducing bootstrap time.
/// CAPI depends on both being ready (cert-manager for CAPI webhooks, ESO for
/// credential sync).
async fn apply_prereqs_phase(client: &Client) -> anyhow::Result<()> {
    use lattice_infra::bootstrap::{eso, InfraComponent, InfraPhase};

    let config = InfrastructureConfig::default();
    let phases = bootstrap::generate_phases(&config)
        .map_err(|e| anyhow::anyhow!("failed to generate infrastructure: {}", e))?;

    let cert_manager_component = phases
        .first()
        .ok_or_else(|| anyhow::anyhow!("no phases generated"))?
        .components
        .first()
        .ok_or_else(|| anyhow::anyhow!("cert-manager phase has no components"))?;

    let phase = InfraPhase {
        name: "prereqs",
        components: vec![
            cert_manager_component.clone(),
            InfraComponent {
                name: "eso",
                version: eso::eso_version(),
                manifests: eso::generate_eso().to_vec(),
                health_namespace: Some("external-secrets"),
            },
        ],
    };

    bootstrap::apply_phase(client, &phase).await?;

    lattice_secret_provider::controller::ensure_local_webhook_infrastructure(client)
        .await
        .map_err(|e| anyhow::anyhow!("failed to create local webhook infrastructure: {}", e))?;

    tracing::info!("cert-manager, ESO, and local webhook ClusterSecretStore ready");
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
        ..RetryConfig::default()
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

/// Install CAPI on the bootstrap cluster.
///
/// Bootstrap sequence:
/// - Wait for InfraProvider (created by `lattice install`)
/// - cert-manager (ESO and CAPI depend on it)
/// - ESO + local webhook ClusterSecretStore (InfraProvider credentials flow through ESO)
/// - Wait for ESO to sync the InfraProvider's credentials secret
/// - CAPI providers (reads the ESO-synced credentials)
async fn ensure_capi_on_bootstrap(
    client: &Client,
    installer: &dyn CapiInstaller,
    config: &SharedConfig,
) -> anyhow::Result<()> {
    let provider_ref = config.provider_ref.clone();
    let infrastructure = config.provider;

    let cloud_providers: Api<InfraProvider> =
        Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    tracing::info!(provider_ref = %provider_ref, "Waiting for InfraProvider...");
    let cp = wait_for_resource(
        &format!("InfraProvider '{}'", provider_ref),
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

    apply_prereqs_phase(client).await?;
    ensure_capi(client, infrastructure, Some(&cp), installer).await
}

/// Install CAPI providers with ESO credential sync to provider namespace.
async fn ensure_capi(
    client: &Client,
    provider_type: ProviderType,
    cloud_provider: Option<&InfraProvider>,
    installer: &dyn CapiInstaller,
) -> anyhow::Result<()> {
    tracing::info!(infrastructure = ?provider_type, "Installing CAPI providers");

    if let Some(cp) = cloud_provider {
        if let Some(ref credentials) = cp.spec.credentials {
            let target_ns = lattice_capi::installer::infra_provider_namespace(provider_type);
            if let Some(ns) = target_ns {
                lattice_secret_provider::credentials::ensure_credentials(
                    client,
                    &cp.name_any(),
                    credentials,
                    cp.spec.credential_data.as_ref(),
                    ns,
                    "lattice-operator",
                )
                .await
                .map_err(|e| anyhow::anyhow!("failed to sync credentials to {ns}: {e}"))?;
            }
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
