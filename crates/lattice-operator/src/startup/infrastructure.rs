//! Phased infrastructure installation
//!
//! Infrastructure is installed in two stages:
//! - `ensure_capi_infrastructure`: blocking — applies cert-manager phase + CAPI
//! - `spawn_general_infrastructure`: background — applies remaining phases with health gates

use std::time::Duration;

use kube::api::ListParams;
use kube::{Api, Client};

use lattice_common::retry::{retry_with_backoff, RetryConfig};
use lattice_common::{
    ParentConnectionConfig, SharedConfig, CA_CERT_KEY, CA_KEY_KEY, CA_SECRET,
    LATTICE_SYSTEM_NAMESPACE,
};

use lattice_capi::installer::{
    copy_credentials_to_provider_namespace, CapiInstaller, CapiProviderConfig,
};
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
            apply_cert_manager_phase(client).await?;
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

    // Only provide root_ca if cacerts doesn't already exist — regenerating
    // the intermediate CA on every startup would break in-flight mTLS.
    let root_ca = if cacerts_exists(client).await {
        tracing::info!("cacerts Secret already exists, skipping intermediate CA generation");
        None
    } else {
        read_root_ca(client).await
    };

    match &cluster {
        Some(c) => {
            let mut cfg = InfrastructureConfig::from(c);
            cfg.root_ca = root_ca;
            if let Ok(Some(parent)) = ParentConnectionConfig::read(client).await {
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
                root_ca,
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

/// Apply the cert-manager phase (phase 0) with health gate.
///
/// This is the only phase that runs in the blocking path because CAPI
/// depends on cert-manager webhooks being ready.
async fn apply_cert_manager_phase(client: &Client) -> anyhow::Result<()> {
    // Generate a minimal config — cert-manager phase doesn't depend on cluster config
    let config = InfrastructureConfig::default();
    let phases = bootstrap::generate_phases(&config)
        .map_err(|e| anyhow::anyhow!("failed to generate infrastructure: {}", e))?;

    let cert_manager_phase = phases
        .first()
        .ok_or_else(|| anyhow::anyhow!("no phases generated"))?;

    debug_assert_eq!(cert_manager_phase.name, "cert-manager");

    bootstrap::apply_phase(client, cert_manager_phase).await?;
    Ok(())
}

/// Check if the `cacerts` Secret already exists in `istio-system`.
async fn cacerts_exists(client: &Client) -> bool {
    let secrets: Api<k8s_openapi::api::core::v1::Secret> =
        Api::namespaced(client.clone(), "istio-system");
    secrets.get("cacerts").await.is_ok()
}

/// Read the Lattice root CA from the `lattice-ca` Secret in `lattice-system`.
///
/// Returns `None` if the Secret doesn't exist yet (bootstrap cluster before CA init)
/// or if the PEM data is invalid. This is not an error — the cacerts Secret for Istio
/// will simply be skipped, and istiod will use a self-signed CA.
async fn read_root_ca(
    client: &Client,
) -> Option<lattice_infra::pki::CertificateAuthority> {
    let secrets: Api<k8s_openapi::api::core::v1::Secret> =
        Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let secret = secrets.get(CA_SECRET).await.ok()?;
    let data = secret.data?;

    let cert_pem = data.get(CA_CERT_KEY).and_then(|b| String::from_utf8(b.0.clone()).ok())?;
    let key_pem = data.get(CA_KEY_KEY).and_then(|b| String::from_utf8(b.0.clone()).ok())?;

    match lattice_infra::pki::CertificateAuthority::from_pem(&cert_pem, &key_pem) {
        Ok(ca) => {
            tracing::info!("Loaded root CA for Istio cacerts generation");
            Some(ca)
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to load root CA, Istio cacerts will not be generated");
            None
        }
    }
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
/// Waits for the InfraProvider CRD (created by `lattice install` after the
/// operator starts) before installing providers.
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

    apply_cert_manager_phase(client).await?;
    ensure_capi(client, infrastructure, Some(&cp), installer).await
}

/// Install CAPI providers with optional credential copying.
async fn ensure_capi(
    client: &Client,
    provider_type: ProviderType,
    cloud_provider: Option<&InfraProvider>,
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
