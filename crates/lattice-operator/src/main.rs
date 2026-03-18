//! Lattice Operator - Kubernetes multi-cluster lifecycle management
//!
//! This is the main entry point. It handles CLI parsing and starts subsystems.
//! All business logic lives in library modules.
//!
//! # Architecture: Vertical Slices
//!
//! Each `ControllerMode` is a vertical slice that owns its full lifecycle:
//! CRDs, infrastructure, shared state, and controllers.
//!
//! # HA Leader Election
//!
//! When running with replicas > 1, pods compete for leadership using Kubernetes
//! Leases. Only the leader runs controllers and accepts traffic. The leader writes
//! Endpoints directly to route all Service traffic to itself.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use clap::{Parser, Subcommand};
use futures::StreamExt;
use kube::runtime::watcher::{self, Event};
use kube::{Api, CustomResourceExt};

use lattice_api::{AuthChain, OidcValidator, SaValidator, ServerConfig as AuthProxyConfig};
use lattice_capi::installer::{CapiInstaller, NativeInstaller};
use lattice_cedar::PolicyEngine;
use lattice_cell::bootstrap::DefaultManifestGenerator;
use lattice_cell::parent::{ParentConfig, ParentServers};
use lattice_common::crd::{
    ClusterConfig, LatticeCluster, LatticeService, MonitoringConfig, OIDCProvider,
};
use lattice_common::graph::ServiceGraph;
use lattice_common::retry::{retry_with_backoff, RetryConfig};
use lattice_common::telemetry::{init_telemetry, TelemetryConfig};
use lattice_common::CrdRegistry;
use lattice_common::SharedConfig;
use lattice_common::{
    lattice_svc_dns, LeaderElector, CELL_SERVICE_NAME, DEFAULT_AUTH_PROXY_PORT,
    DEFAULT_HEALTH_PORT, LATTICE_SYSTEM_NAMESPACE, LEADER_LEASE_NAME, OPERATOR_NAME,
};
use lattice_operator::agent::start_agent_with_retry;
use lattice_operator::cell_proxy_backend::CellProxyBackend;
use lattice_operator::forwarder::SubtreeForwarder;
use lattice_operator::startup::{
    ensure_capi_infrastructure, ensure_cluster_crds, ensure_service_crds, get_cell_server_sans,
    re_register_existing_clusters, spawn_general_infrastructure, start_ca_rotation,
    wait_for_api_ready_for,
};

mod controller_runner;
mod metrics;

#[derive(Parser, Debug)]
#[command(name = "lattice", version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    crd: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

/// Vertical slice modes for the modular monolith architecture.
///
/// Each mode runs a specific subset of controllers and infrastructure:
/// - `All`: Complete operator (default for single-deployment scenarios)
/// - `Cluster`: Cluster lifecycle (provisioning, pivoting, scaling) + cell infrastructure
/// - `Service`: Service mesh (policies, workloads, ingress) - no cell infrastructure
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum ControllerMode {
    /// Run all controllers and infrastructure
    #[default]
    All,
    /// Run cluster lifecycle controller + cell infrastructure (gRPC, bootstrap, auth proxy)
    Cluster,
    /// Run service mesh controller only (no cell infrastructure)
    Service,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Controller {
        #[arg(long, short, value_enum, default_value = "all")]
        mode: ControllerMode,
    },
}

/// Owns controller futures and cleanup resources for a vertical slice
struct SliceHandle {
    controllers: Vec<Pin<Box<dyn Future<Output = ()> + Send>>>,
    parent_servers: Option<Arc<ParentServers<DefaultManifestGenerator>>>,
    agent_token: Option<tokio_util::sync::CancellationToken>,
    graph_auditor_token: Option<tokio_util::sync::CancellationToken>,
    auth_proxy_handle: Option<tokio::task::JoinHandle<()>>,
    infra_handle: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_crypto();
    let prom_registry = init_telemetry_global();

    let cli = Cli::parse();

    if cli.crd {
        println!(
            "{}",
            serde_json::to_string(&LatticeCluster::crd())
                .map_err(|e| anyhow::anyhow!("failed to serialize CRD: {}", e))?
        );
        return Ok(());
    }

    match cli.command {
        Some(Commands::Controller { mode }) => run_controller(mode, prom_registry).await,
        None => run_controller(ControllerMode::All, prom_registry).await,
    }
}

fn init_crypto() {
    // Panics on failure — FIPS mode is mandatory
    lattice_common::fips::install_crypto_provider();
    eprintln!("FIPS mode: ENABLED");
}

fn init_telemetry_global() -> Option<prometheus::Registry> {
    let config = TelemetryConfig {
        service_name: OPERATOR_NAME.to_string(),
        ..Default::default()
    };

    match init_telemetry(config) {
        Ok(registry) => {
            tracing::info!("Telemetry initialized");
            Some(registry)
        }
        Err(e) => {
            eprintln!("WARNING: Failed to initialize telemetry: {}", e);
            // Fall back to basic tracing
            use tracing_subscriber::{fmt, prelude::*, EnvFilter};
            let _ = tracing_subscriber::registry()
                .with(fmt::layer())
                .with(EnvFilter::from_default_env())
                .try_init();
            None
        }
    }
}

async fn run_controller(
    mode: ControllerMode,
    prom_registry: Option<prometheus::Registry>,
) -> anyhow::Result<()> {
    tracing::info!(?mode, "Starting...");

    // Parse all LATTICE_* env vars once at startup
    let config = Arc::new(
        lattice_common::LatticeConfig::from_env()
            .map_err(|e| anyhow::anyhow!("Failed to parse operator config: {}", e))?,
    );

    // Create client with proper timeouts (5s connect, 30s read)
    let client = lattice_common::kube_utils::create_client(None, None, None).await?;

    // Get pod identity from Downward API env vars (set in deployment manifest)
    let pod_name = std::env::var("POD_NAME").unwrap_or_else(|_| {
        // Fallback for local development — log so misconfigured deployments are visible
        let name = format!("lattice-operator-{}", uuid::Uuid::new_v4());
        tracing::warn!(pod_name = %name, "POD_NAME not set (expected from Downward API), using generated name");
        name
    });

    let debug_enabled = config.debug;
    let graph_holder: Arc<OnceLock<Arc<ServiceGraph>>> = Arc::new(OnceLock::new());

    // Start health server (runs on all pods for K8s probes)
    let health_handle = start_health_server(prom_registry, graph_holder.clone(), debug_enabled);

    // Ensure webhook auth credentials exist (all pods load or create on first run).
    // This must happen before starting the webhook so every replica validates the
    // same credentials. The K8s Secret acts as the coordination point — the first
    // pod to run creates it, others load the existing one.
    let webhook_creds =
        lattice_secret_provider::controller::ensure_webhook_credentials(&client).await?;

    // Start the local secrets webhook on ALL pods (before leader election).
    // The webhook is a stateless HTTP reader — any replica can serve ESO requests.
    // Infrastructure setup (namespace, Service, ClusterSecretStore) happens on the
    // leader later, but the HTTP endpoint must be available on every pod so the
    // Service (which selects all operator pods) never routes to a non-listening replica.
    let webhook_client = client.clone();
    tokio::spawn(async move {
        if let Err(e) =
            lattice_secret_provider::webhook::start_webhook_server(webhook_client, webhook_creds)
                .await
        {
            tracing::error!(error = %e, "Local secrets webhook server failed");
        }
    });

    // Start admission webhook server (all pods, stateless validation)
    let webhook_client = client.clone();
    tokio::spawn(async move {
        if let Err(e) = lattice_webhook::start_webhook_server(webhook_client).await {
            tracing::error!(error = %e, "Admission webhook server failed");
        }
    });

    // Acquire leadership using Kubernetes Lease BEFORE any initialization
    // Only the leader should install CRDs and infrastructure
    let elector = Arc::new(LeaderElector::new(
        client.clone(),
        LEADER_LEASE_NAME,
        LATTICE_SYSTEM_NAMESPACE,
        &pod_name,
    ));
    let mut guard = elector.acquire().await?;

    // Claim traffic by adding leader label to this pod
    // Service selector includes this label, so only leader gets traffic
    tracing::info!(pod = %pod_name, "Adding leader label to claim traffic...");
    guard.claim_traffic(&pod_name).await?;

    // Report running operator image in status.latticeImage on startup
    if let Some(ref self_name) = config.cluster_name {
        report_running_image(&client, self_name).await;
    }

    // Dispatch to the appropriate vertical slice
    tracing::info!("Starting Lattice controllers...");
    let handle = match mode {
        ControllerMode::Cluster => run_cluster_slice(&client, &config).await?,
        ControllerMode::Service => run_service_slice(&client, &graph_holder, &config).await?,
        ControllerMode::All => run_all_slices(&client, &graph_holder, &config).await?,
    };

    // Destructure handle so we can move controllers into select_all
    // while keeping the cleanup resources separate
    let SliceHandle {
        controllers,
        parent_servers,
        agent_token,
        graph_auditor_token,
        auth_proxy_handle,
        infra_handle,
    } = handle;

    // Run controllers until shutdown signal, controllers exit, or leadership lost
    let shutdown_signal = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Received shutdown signal");
    };

    let controllers = futures::future::select_all(controllers);

    let infra_future = async {
        if let Some(handle) = infra_handle {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "General infrastructure installation failed");
                    return true;
                }
                Err(e) => {
                    tracing::error!(error = %e, "General infrastructure task panicked");
                    return true;
                }
            }
        }
        // Never resolve if infra succeeded — let other branches drive shutdown
        std::future::pending::<bool>().await
    };

    tokio::select! {
        (_, idx, _) = controllers => {
            tracing::info!(controller_index = idx, "Controller exited");
        }
        _ = guard.lost() => {
            tracing::warn!("Leadership lost, shutting down");
        }
        failed = infra_future => {
            if failed {
                tracing::error!("Shutting down due to infrastructure failure");
            }
        }
        _ = shutdown_signal => {}
    }

    // Graceful shutdown: release leadership so standby can take over immediately
    tracing::info!("Releasing leadership for fast failover...");
    if let Err(e) = guard.release_leadership().await {
        tracing::warn!(error = %e, "Failed to release leadership (standby will wait for lease expiry)");
    }

    // Stop services
    health_handle.abort();
    if let Some(token) = agent_token {
        token.cancel();
    }
    if let Some(token) = graph_auditor_token {
        token.cancel();
    }
    if let Some(handle) = auth_proxy_handle {
        handle.abort();
    }
    if let Some(servers) = parent_servers {
        servers.shutdown().await;
    }
    tracing::info!("Shutdown complete");
    Ok(())
}

// ---------------------------------------------------------------------------
// Vertical slice functions
// ---------------------------------------------------------------------------

/// Cluster slice: LatticeCluster CRDs, cluster infra (CAPI, network policies),
/// Cedar, cell infra (gRPC, bootstrap, auth proxy), cluster + provider controllers
async fn run_cluster_slice(
    client: &kube::Client,
    config: &SharedConfig,
) -> anyhow::Result<SliceHandle> {
    let capi_installer: Arc<dyn CapiInstaller> = Arc::new(NativeInstaller::new());

    ensure_cluster_crds(client).await?;

    // Register admission webhook now that CRDs exist (avoids chicken-and-egg)
    spawn_admission_webhook_configuration(client.clone());

    // cert-manager + CAPI must complete before controllers (they need CAPI to reconcile)
    ensure_capi_infrastructure(client, Some(&*capi_installer), config).await?;

    // General infra (Istio, ESO, monitoring) runs in background — needs workers first
    let infra_handle = spawn_general_infrastructure(client.clone(), true, config.clone());

    wait_for_api_ready_for::<LatticeCluster>(client).await;

    let cedar = load_cedar_engine(client).await;

    let self_cluster_name = config.cluster_name.clone();
    let (parent_servers, agent_token, auth_proxy_handle, _route_update_tx) =
        setup_cell_infra(client, &self_cluster_name, cedar.clone(), config).await?;

    let mut controllers = controller_runner::build_cluster_controllers(
        client.clone(),
        self_cluster_name,
        Some(parent_servers.clone()),
        capi_installer,
        config.clone(),
    );
    controllers.extend(controller_runner::build_cluster_provider_controllers(
        client.clone(),
        cedar,
        config.clone(),
    ));

    Ok(SliceHandle {
        controllers,
        parent_servers: Some(parent_servers),
        agent_token: Some(agent_token),
        graph_auditor_token: None,
        auth_proxy_handle,
        infra_handle: Some(infra_handle),
    })
}

/// Service slice: Service CRDs, service infra (Istio, Gateway API, ESO, Cilium),
/// Cedar, CrdRegistry, service + provider controllers
async fn run_service_slice(
    client: &kube::Client,
    graph_holder: &Arc<OnceLock<Arc<ServiceGraph>>>,
    config: &SharedConfig,
) -> anyhow::Result<SliceHandle> {
    ensure_service_crds(client).await?;

    // Register admission webhook now that CRDs exist (avoids chicken-and-egg)
    spawn_admission_webhook_configuration(client.clone());

    // General infra runs in background (no CAPI in service-only mode)
    let infra_handle = spawn_general_infrastructure(client.clone(), false, config.clone());

    wait_for_api_ready_for::<LatticeService>(client).await;

    let cedar = load_cedar_engine(client).await;

    let cluster = ClusterConfig {
        cluster_name: config
            .cluster_name_required()
            .map_err(|e| anyhow::anyhow!(e))?
            .to_string(),
        provider_type: config.provider,
        monitoring: MonitoringConfig {
            enabled: config.monitoring_enabled,
            ha: config.monitoring_ha,
        },
    };
    let registry = Arc::new(CrdRegistry::new(client.clone()).await);
    let cost_provider: Option<Arc<dyn lattice_cost::CostProvider>> = Some(Arc::new(
        lattice_cost::ConfigMapCostProvider::new(client.clone()),
    ));

    let metrics_scraper = Arc::new(metrics::VmMetricsScraper::new(cluster.monitoring.ha)?);

    let (mut controllers, graph) = controller_runner::build_service_controllers(
        client.clone(),
        cluster.clone(),
        cedar.clone(),
        registry.clone(),
        metrics_scraper.clone(),
        cost_provider.clone(),
    )
    .await?;

    let _ = graph_holder.set(graph.clone());

    let graph_for_models = graph.clone();
    let graph_for_auditor = graph.clone();
    controllers.extend(
        controller_runner::build_job_controllers(
            client.clone(),
            cluster.clone(),
            cedar.clone(),
            graph,
            registry.clone(),
            metrics_scraper.clone(),
            cost_provider.clone(),
        )
        .await,
    );

    controllers.extend(
        controller_runner::build_model_controllers(
            client.clone(),
            cluster,
            cedar.clone(),
            graph_for_models,
            registry,
            metrics_scraper,
            cost_provider,
        )
        .await,
    );

    controllers.extend(controller_runner::build_service_provider_controllers(
        client.clone(),
        cedar,
        config.clone(),
    ));

    spawn_webhook_infrastructure(client.clone());

    let auditor_token = tokio_util::sync::CancellationToken::new();
    controller_runner::spawn_graph_auditor(
        client.clone(),
        graph_for_auditor,
        auditor_token.clone(),
    );

    Ok(SliceHandle {
        controllers,
        parent_servers: None,
        agent_token: None,
        graph_auditor_token: Some(auditor_token),
        auth_proxy_handle: None,
        infra_handle: Some(infra_handle),
    })
}

/// Spawn admission webhook configuration registration in background.
///
/// Reads the CA PEM from the webhook TLS Secret (created by `start_webhook_server`
/// on all pods before leader election) and applies the `ValidatingWebhookConfiguration`
/// resource so the K8s API server routes admission requests to the webhook.
/// Retries with backoff in case the TLS Secret hasn't been created yet.
fn spawn_admission_webhook_configuration(client: kube::Client) {
    tokio::spawn(async move {
        if let Err(e) = retry_with_backoff(
            &RetryConfig {
                initial_delay: Duration::from_secs(2),
                ..RetryConfig::default()
            },
            "ensure admission webhook configuration",
            || async {
                lattice_webhook::ensure_webhook_configuration(&client)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))
            },
        )
        .await
        {
            tracing::error!(error = %e, "failed to register admission webhook configuration");
        }
    });
}

/// Spawn ESO webhook K8s infrastructure (namespace, Service, ClusterSecretStore) in background.
///
/// ESO pods won't schedule until workers are available (no CP toleration),
/// so blocking would deadlock during bootstrap. The webhook HTTP server itself
/// is started on ALL pods before leader election (see `run_controller`).
fn spawn_webhook_infrastructure(client: kube::Client) {
    tokio::spawn(async move {
        if let Err(e) = retry_with_backoff(
            &RetryConfig {
                initial_delay: Duration::from_secs(2),
                ..RetryConfig::default()
            },
            "ensure local webhook infrastructure (waiting for ESO)",
            || async {
                lattice_secret_provider::controller::ensure_local_webhook_infrastructure(&client)
                    .await
            },
        )
        .await
        {
            tracing::error!(error = %e, "failed to ensure local webhook infrastructure");
        }
    });
}

/// All slices: union of Cluster + Service + Provider. Same behavior as the
/// monolithic path, but composed from the individual pieces.
async fn run_all_slices(
    client: &kube::Client,
    graph_holder: &Arc<OnceLock<Arc<ServiceGraph>>>,
    config: &SharedConfig,
) -> anyhow::Result<SliceHandle> {
    let capi_installer: Arc<dyn CapiInstaller> = Arc::new(NativeInstaller::new());

    // 1. Install ALL CRDs (union of cluster + service modes)
    ensure_cluster_crds(client).await?;
    ensure_service_crds(client).await?;

    // Register admission webhook now that CRDs exist (avoids chicken-and-egg)
    spawn_admission_webhook_configuration(client.clone());

    // cert-manager + CAPI must complete before controllers (they need CAPI to reconcile)
    ensure_capi_infrastructure(client, Some(&*capi_installer), config).await?;

    // General infra (Istio, ESO, monitoring) runs in background — needs workers first
    let infra_handle = spawn_general_infrastructure(client.clone(), true, config.clone());

    wait_for_api_ready_for::<LatticeCluster>(client).await;

    let cedar = load_cedar_engine(client).await;

    let self_cluster_name = config.cluster_name.clone();
    let (parent_servers, agent_token, auth_proxy_handle, _route_update_tx) =
        setup_cell_infra(client, &self_cluster_name, cedar.clone(), config).await?;

    let mut controllers = controller_runner::build_cluster_controllers(
        client.clone(),
        self_cluster_name,
        Some(parent_servers.clone()),
        capi_installer,
        config.clone(),
    );

    // Service controllers need provider type + monitoring from the LatticeCluster CRD
    let cluster = ClusterConfig {
        cluster_name: config
            .cluster_name_required()
            .map_err(|e| anyhow::anyhow!(e))?
            .to_string(),
        provider_type: controller_runner::resolve_provider_type_from_cluster(client).await,
        monitoring: controller_runner::resolve_monitoring_from_cluster(client).await,
    };
    let registry = Arc::new(CrdRegistry::new(client.clone()).await);
    let cost_provider: Option<Arc<dyn lattice_cost::CostProvider>> = Some(Arc::new(
        lattice_cost::ConfigMapCostProvider::new(client.clone()),
    ));
    let metrics_scraper = Arc::new(metrics::VmMetricsScraper::new(cluster.monitoring.ha)?);
    let (service_controllers, graph) = controller_runner::build_service_controllers(
        client.clone(),
        cluster.clone(),
        cedar.clone(),
        registry.clone(),
        metrics_scraper.clone(),
        cost_provider.clone(),
    )
    .await?;
    controllers.extend(service_controllers);

    let _ = graph_holder.set(graph.clone());

    let graph_for_models = graph.clone();
    let graph_for_auditor = graph.clone();
    controllers.extend(
        controller_runner::build_job_controllers(
            client.clone(),
            cluster.clone(),
            cedar.clone(),
            graph,
            registry.clone(),
            metrics_scraper.clone(),
            cost_provider.clone(),
        )
        .await,
    );

    controllers.extend(
        controller_runner::build_model_controllers(
            client.clone(),
            cluster,
            cedar.clone(),
            graph_for_models,
            registry,
            metrics_scraper,
            cost_provider,
        )
        .await,
    );

    controllers.extend(controller_runner::build_all_provider_controllers(
        client.clone(),
        cedar,
        config.clone(),
    ));

    spawn_webhook_infrastructure(client.clone());

    let auditor_token = tokio_util::sync::CancellationToken::new();
    controller_runner::spawn_graph_auditor(
        client.clone(),
        graph_for_auditor,
        auditor_token.clone(),
    );

    Ok(SliceHandle {
        controllers,
        parent_servers: Some(parent_servers),
        agent_token: Some(agent_token),
        graph_auditor_token: Some(auditor_token),
        auth_proxy_handle,
        infra_handle: Some(infra_handle),
    })
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Load Cedar policy engine from CRDs, falling back to default-deny
async fn load_cedar_engine(client: &kube::Client) -> Arc<PolicyEngine> {
    match PolicyEngine::from_crds(client).await {
        Ok(engine) => Arc::new(engine),
        Err(e) => {
            tracing::error!(
                error = %e,
                "Failed to load Cedar policies — falling back to default-deny. \
                 All secret access and security override requests will be denied."
            );
            lattice_common::metrics::record_cedar_load_failure();
            Arc::new(PolicyEngine::new())
        }
    }
}

/// Check whether the self-cluster CRD has `parent_config` set.
///
/// Returns `false` on 404 or any error (safe default for leaf clusters).
async fn has_parent_config(client: &kube::Client) -> bool {
    matches!(
        lattice_common::ParentConnectionConfig::read(client).await,
        Ok(Some(_))
    )
}

/// Set up cell infrastructure (gRPC servers, agent connection, auth proxy)
///
/// Always creates `ParentServers` (CA + registries are needed by agent SubtreeForwarder).
/// Always starts agent connection if `self_cluster_name` is set.
///
/// For cells (bootstrap or has parent_config): starts servers, auth proxy, CA rotation,
/// and crash recovery immediately.
///
/// For leaf clusters: spawns a background `cell_activation_watcher` that polls the
/// self-cluster CRD every 30s and promotes to cell when `parent_config` appears.
///
/// Returns (parent_servers, agent_cancellation_token, auth_proxy_handle)
async fn setup_cell_infra(
    client: &kube::Client,
    self_cluster_name: &Option<String>,
    cedar: Arc<PolicyEngine>,
    config: &SharedConfig,
) -> anyhow::Result<(
    Arc<ParentServers<DefaultManifestGenerator>>,
    tokio_util::sync::CancellationToken,
    Option<tokio::task::JoinHandle<()>>,
    Option<lattice_cell::route_reconciler::RouteUpdateSender>,
)> {
    let is_bootstrap = config.is_bootstrap_cluster;

    // Create cell servers (always — CA + registries needed by agent SubtreeForwarder)
    let parent_config = ParentConfig::from_config(config);
    let servers = Arc::new(ParentServers::new(parent_config, client).await?);

    // Start route reconciler on ALL clusters (not just parents).
    // Watches local LatticeServices with advertise: true, merges with child routes.
    // On leaf clusters the child channel is unused but the local watcher still runs.
    let (route_update_tx, all_routes_rx) = match self_cluster_name.as_ref() {
        Some(name) => {
            let (tx, rx) = lattice_cell::route_reconciler::spawn_route_reconciler(
                name.clone(),
                client.clone(),
            );
            (Some(tx), Some(rx))
        }
        None => (None, None),
    };

    // Start agent connection to parent (if we have one)
    let agent_token = tokio_util::sync::CancellationToken::new();
    if let Some(ref name) = self_cluster_name {
        let client = client.clone();
        let name = name.clone();
        let token = agent_token.clone();
        let subtree_forwarder =
            SubtreeForwarder::new(servers.subtree_registry(), servers.agent_registry());
        let forwarder: Arc<dyn lattice_agent::K8sRequestForwarder> = Arc::new(subtree_forwarder);
        let exec_forwarder: Arc<dyn lattice_agent::ExecRequestForwarder> = Arc::new(
            SubtreeForwarder::new(servers.subtree_registry(), servers.agent_registry()),
        );
        tokio::spawn(async move {
            tokio::select! {
                _ = token.cancelled() => {}
                _ = start_agent_with_retry(&client, &name, forwarder, exec_forwarder) => {}
            }
        });
    }

    let is_cell = is_bootstrap || has_parent_config(client).await;

    let auth_proxy_handle = if is_cell {
        let extra_sans = get_cell_server_sans(client, self_cluster_name, is_bootstrap).await;
        let tx = route_update_tx
            .clone()
            .expect("route_update_tx required for cell");
        activate_cell_services(
            client,
            &servers,
            self_cluster_name,
            CellActivationParams {
                extra_sans,
                cedar,
                oidc_allow_insecure_http: config.oidc_allow_insecure_http,
                route_update_tx: tx,
                all_routes_rx: all_routes_rx.clone(),
            },
        )
        .await?
    } else {
        // Leaf cluster — spawn background watcher for promotion
        tracing::info!("Leaf cluster, cell servers deferred until parent_config is set");
        if let Some(ref name) = self_cluster_name {
            let watcher_client = client.clone();
            let watcher_name = name.clone();
            let watcher_servers = servers.clone();
            let watcher_cedar = cedar;
            let watcher_oidc_insecure = config.oidc_allow_insecure_http;
            let watcher_route_tx = route_update_tx
                .clone()
                .expect("route_update_tx required for leaf");
            let watcher_all_rx = all_routes_rx.clone();
            tokio::spawn(async move {
                cell_activation_watcher(
                    watcher_client,
                    watcher_name,
                    watcher_servers,
                    watcher_cedar,
                    watcher_oidc_insecure,
                    watcher_route_tx,
                    watcher_all_rx,
                )
                .await;
            });
        }
        None
    };

    Ok((servers, agent_token, auth_proxy_handle, route_update_tx))
}

/// Activate cell infrastructure: start servers, auth proxy, CA rotation, and crash recovery.
///
/// Shared by both immediate cell activation (in `setup_cell_infra`) and deferred
/// promotion (in `cell_activation_watcher`).
/// Parameters for activating cell services.
struct CellActivationParams {
    extra_sans: Vec<String>,
    cedar: Arc<PolicyEngine>,
    oidc_allow_insecure_http: bool,
    route_update_tx: lattice_cell::route_reconciler::RouteUpdateSender,
    all_routes_rx: Option<lattice_cell::route_reconciler::AllRoutesReceiver>,
}

async fn activate_cell_services(
    client: &kube::Client,
    servers: &Arc<ParentServers<DefaultManifestGenerator>>,
    cluster_name: &Option<String>,
    params: CellActivationParams,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    let CellActivationParams {
        extra_sans,
        cedar,
        oidc_allow_insecure_http,
        route_update_tx,
        all_routes_rx,
    } = params;
    servers
        .ensure_running(
            DefaultManifestGenerator::new(),
            &extra_sans,
            client.clone(),
            route_update_tx,
        )
        .await?;
    tracing::info!("Cell servers started");

    let handle = start_auth_proxy(
        client,
        servers.clone(),
        cluster_name,
        &extra_sans,
        cedar,
        oidc_allow_insecure_http,
        all_routes_rx,
    )
    .await;
    start_ca_rotation(servers.clone());

    if let Some(state) = servers.bootstrap_state().await {
        re_register_existing_clusters(client, &state, cluster_name, servers).await;
    }

    Ok(handle)
}

/// Background task that watches for `parent_config` to appear on the self-cluster CRD.
///
/// When promotion is detected (parent_config added), this function:
/// - Creates the LB Service
/// - Waits for the LB address
/// - Starts cell servers with the LB address as a TLS SAN
/// - Starts auth proxy and CA rotation
/// - Runs crash recovery (re-register existing clusters)
async fn cell_activation_watcher(
    client: kube::Client,
    self_cluster_name: String,
    servers: Arc<ParentServers<DefaultManifestGenerator>>,
    cedar: Arc<PolicyEngine>,
    oidc_allow_insecure_http: bool,
    route_update_tx: lattice_cell::route_reconciler::RouteUpdateSender,
    all_routes_rx: Option<lattice_cell::route_reconciler::AllRoutesReceiver>,
) {
    use lattice_operator::startup::{
        discover_cell_host, ensure_cell_service_exists, LOAD_BALANCER_POLL_INTERVAL,
    };

    loop {
        // Already running — done
        if servers.is_running() {
            return;
        }

        // Read self-cluster CRD
        let clusters: Api<LatticeCluster> = Api::all(client.clone());
        let cluster = match clusters.get(&self_cluster_name).await {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(error = %e, "cell_activation_watcher: failed to read self-cluster, retrying");
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
        };

        let Some(ref pc) = cluster.spec.parent_config else {
            tokio::time::sleep(Duration::from_secs(30)).await;
            continue;
        };

        // parent_config found — promote to cell
        tracing::info!("parent_config detected, promoting to cell...");
        let provider_type = cluster.spec.provider.provider_type();

        // Create LB Service
        if let Err(e) = ensure_cell_service_exists(
            &client,
            pc.bootstrap_port,
            pc.grpc_port,
            pc.proxy_port,
            provider_type,
        )
        .await
        {
            tracing::warn!(error = %e, "Failed to create cell Service, retrying");
            tokio::time::sleep(Duration::from_secs(10)).await;
            continue;
        }

        // Wait for LB address
        let lb_address = loop {
            match discover_cell_host(&client).await {
                Ok(Some(host)) => break host,
                Ok(None) => {
                    tracing::debug!("Waiting for cell LoadBalancer address...");
                    tokio::time::sleep(LOAD_BALANCER_POLL_INTERVAL).await;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to discover cell host, retrying");
                    tokio::time::sleep(LOAD_BALANCER_POLL_INTERVAL).await;
                }
            }
        };
        tracing::info!(host = %lb_address, "Cell host discovered");

        let extra_sans = vec![lb_address];
        let cluster_name = Some(self_cluster_name.clone());

        if let Err(e) = activate_cell_services(
            &client,
            &servers,
            &cluster_name,
            CellActivationParams {
                extra_sans,
                cedar: cedar.clone(),
                oidc_allow_insecure_http,
                route_update_tx: route_update_tx.clone(),
                all_routes_rx: all_routes_rx.clone(),
            },
        )
        .await
        {
            tracing::error!(error = %e, "Failed to activate cell services during promotion");
            tokio::time::sleep(Duration::from_secs(10)).await;
            continue;
        }

        tracing::info!("Cell infrastructure activated (cluster promoted to parent)");
        return;
    }
}

// ---------------------------------------------------------------------------
// Health, auth proxy, and watcher functions (unchanged)
// ---------------------------------------------------------------------------

/// Start the health check server for Kubernetes probes
///
/// Runs on all pods:
/// - `/healthz` - liveness probe (process alive)
/// - `/readyz` - readiness probe (ready to become leader or already leading)
/// - `/metrics` - Prometheus scrape endpoint (all OpenTelemetry metrics)
fn start_health_server(
    prom_registry: Option<prometheus::Registry>,
    graph_holder: Arc<OnceLock<Arc<ServiceGraph>>>,
    debug: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut app = Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route("/readyz", get(|| async { "ok" }));

        if debug {
            app = app.route(
                "/debug/graph",
                get(move || {
                    let holder = graph_holder.clone();
                    async move {
                        match holder.get() {
                            Some(graph) => (
                                axum::http::StatusCode::OK,
                                [(
                                    axum::http::header::CONTENT_TYPE,
                                    "application/json".to_string(),
                                )],
                                graph.dump_json().to_string(),
                            )
                                .into_response(),
                            None => (
                                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                                "graph not initialized",
                            )
                                .into_response(),
                        }
                    }
                }),
            );
            tracing::info!("Debug mode enabled: /debug/graph endpoint active");
        }

        if let Some(registry) = prom_registry {
            app = app.route(
                "/metrics",
                get(move || {
                    let registry = registry.clone();
                    async move {
                        use prometheus::Encoder;
                        let encoder = prometheus::TextEncoder::new();
                        let metric_families = registry.gather();
                        let mut buffer = Vec::new();
                        match encoder.encode(&metric_families, &mut buffer) {
                            Ok(()) => (
                                axum::http::StatusCode::OK,
                                [(
                                    axum::http::header::CONTENT_TYPE,
                                    encoder.format_type().to_string(),
                                )],
                                buffer,
                            )
                                .into_response(),
                            Err(e) => (
                                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                format!("metrics encoding error: {}", e),
                            )
                                .into_response(),
                        }
                    }
                }),
            );
        }

        let addr: SocketAddr = ([0, 0, 0, 0], DEFAULT_HEALTH_PORT).into();

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => {
                tracing::info!(port = DEFAULT_HEALTH_PORT, "Health server started");
                l
            }
            Err(e) => {
                tracing::error!(error = %e, port = DEFAULT_HEALTH_PORT, "Failed to bind health server port");
                return;
            }
        };

        if let Err(e) = axum::serve(listener, app.into_make_service()).await {
            tracing::error!(error = %e, "Health server error");
        }
    })
}

/// Start the auth proxy server for authenticated cluster access
///
/// The auth proxy provides:
/// - ServiceAccount token authentication (via TokenReview API)
/// - Cedar policy authorization
/// - Routing to local or child cluster K8s APIs
async fn start_auth_proxy(
    client: &kube::Client,
    parent_servers: Arc<ParentServers<DefaultManifestGenerator>>,
    cluster_name: &Option<String>,
    extra_sans: &[String],
    cedar: Arc<PolicyEngine>,
    oidc_allow_insecure_http: bool,
    all_routes_rx: Option<lattice_cell::route_reconciler::AllRoutesReceiver>,
) -> Option<tokio::task::JoinHandle<()>> {
    // Get cluster name (default to "unknown")
    let cluster_name = cluster_name
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

    // Accept both the custom "lattice-proxy" audience (used by TokenRequest
    // tokens like istiod's) and the default K8s API audience (used by
    // Secret-based admin tokens). The audiences list is passed in the
    // TokenReview spec so the API server validates against these instead
    // of its own default audience.
    let sa_validator = Arc::new(SaValidator::new(client.clone()).with_audiences(vec![
        lattice_common::kube_utils::PROXY_TOKEN_AUDIENCE.to_string(),
        "https://kubernetes.default.svc.cluster.local".to_string(),
    ]));

    // Try to load OIDC provider from CRD
    let oidc_validator = match OidcValidator::from_crd(client, oidc_allow_insecure_http).await {
        Ok(v) => {
            tracing::info!(issuer = %v.config().issuer_url, "OIDC authentication enabled");
            Some(Arc::new(v))
        }
        Err(e) => {
            tracing::info!(error = %e, "No OIDC provider configured, SA auth only");
            None
        }
    };

    // Create auth chain with OIDC (if available) + SA fallback
    let auth_chain = Arc::new(match oidc_validator {
        Some(oidc) => AuthChain::new(oidc, sa_validator),
        None => AuthChain::sa_only(sa_validator),
    });

    // Generate server certificate and get CA cert for kubeconfig generation
    // Include LB address in SANs if available (for external access)
    let ca_bundle = parent_servers.ca_bundle().read().await;
    let cell_dns = lattice_svc_dns(CELL_SERVICE_NAME);
    let mut sans: Vec<&str> = vec!["localhost", "127.0.0.1", &cell_dns];
    let extra_san_refs: Vec<&str> = extra_sans.iter().map(|s| s.as_str()).collect();
    sans.extend(extra_san_refs);
    let (cert_pem, key_pem) = match ca_bundle.generate_server_cert(&sans) {
        Ok((cert, key)) => (cert, key),
        Err(e) => {
            tracing::error!(error = %e, "Failed to generate auth proxy certificate");
            return None;
        }
    };
    let ca_cert_pem = ca_bundle.trust_bundle_pem();
    drop(ca_bundle);

    // Create server config
    let addr: SocketAddr = match format!("0.0.0.0:{}", DEFAULT_AUTH_PROXY_PORT).parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "Failed to parse auth proxy address");
            return None;
        }
    };

    // Use LB address for base_url if available (for external kubeconfig generation)
    // Fall back to internal service DNS if no LB
    let base_host = extra_sans.first().map(|s| s.as_str()).unwrap_or(&cell_dns);
    let base_url = format!("https://{}:{}", base_host, DEFAULT_AUTH_PROXY_PORT);

    // Clone values needed for the remote secret controller before they move into config
    let proxy_base_url = format!("https://{}:{}", cell_dns, DEFAULT_AUTH_PROXY_PORT);
    let proxy_ca_cert = ca_cert_pem.clone();

    // Clone base_url before it moves into config — needed for peer route sync
    let peer_proxy_url = base_url.clone();

    let config = AuthProxyConfig {
        addr,
        cert_pem,
        key_pem,
        ca_cert_pem,
        k8s_api_url: "https://kubernetes.default.svc".to_string(),
        cluster_name: cluster_name.clone(),
        base_url,
    };

    // Create backend from cell registries
    let subtree = parent_servers.subtree_registry();
    let agent_registry = parent_servers.agent_registry();
    let backend = Arc::new(CellProxyBackend::new(subtree, agent_registry));

    tracing::info!(addr = %addr, cluster = %cluster_name, "Starting auth proxy server");

    // Start remote secret controller for Istio multi-cluster discovery.
    // Tokens are requested per-reconcile via TokenRequest API against the
    // dedicated lattice-istiod-proxy SA — no static token embedding.
    controller_runner::spawn_remote_secret_controller(
        client.clone(),
        proxy_base_url,
        proxy_ca_cert.clone(),
    );

    // Enable peer route sync: the gRPC server will push sibling/parent routes
    // to connected children using the external auth proxy URL.
    if let Some(rx) = all_routes_rx {
        parent_servers
            .set_peer_config(peer_proxy_url, proxy_ca_cert, rx)
            .await;
    }

    // Start OIDCProvider watcher to reload OIDC config when CRDs change
    start_oidc_provider_watcher(client.clone(), auth_chain.clone(), oidc_allow_insecure_http);

    // Start in background task
    let handle = tokio::spawn(async move {
        if let Err(e) = lattice_api::start_server(config, auth_chain, cedar, backend).await {
            tracing::error!(error = %e, "Auth proxy server error");
        }
    });

    Some(handle)
}

/// Start a background task to watch for OIDCProvider CRD changes and reload the OIDC validator.
///
/// On any change (create/update/delete), re-loads from CRD. If no providers remain,
/// clears OIDC so SA auth is the only active validator.
fn start_oidc_provider_watcher(
    client: kube::Client,
    auth_chain: Arc<AuthChain>,
    allow_insecure_http: bool,
) {
    tokio::spawn(async move {
        let api: Api<OIDCProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

        // Use a shorter timeout than client's read_timeout to prevent "body read timed out"
        let watcher_config = watcher::Config::default().timeout(25);
        let watcher = watcher::watcher(api, watcher_config);
        let mut watcher = std::pin::pin!(watcher);

        tracing::info!("OIDCProvider watcher started");

        loop {
            match watcher.next().await {
                Some(Ok(Event::Apply(_)))
                | Some(Ok(Event::InitApply(_)))
                | Some(Ok(Event::Delete(_))) => {
                    tracing::info!("OIDCProvider changed, reloading...");
                    match OidcValidator::from_crd(&client, allow_insecure_http).await {
                        Ok(v) => {
                            tracing::info!(issuer = %v.config().issuer_url, "OIDC validator reloaded");
                            auth_chain.set_oidc(Some(Arc::new(v))).await;
                        }
                        Err(_) => {
                            tracing::info!("No OIDC providers configured, SA auth only");
                            auth_chain.set_oidc(None).await;
                        }
                    }
                }
                Some(Ok(Event::Init)) | Some(Ok(Event::InitDone)) => {
                    tracing::debug!("OIDCProvider watcher initialized");
                }
                Some(Err(e)) => {
                    tracing::warn!(error = %e, "OIDCProvider watcher error, retrying...");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                None => {
                    tracing::warn!("OIDCProvider watcher stream ended, restarting...");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    });
}

/// Report the currently running operator image in `status.latticeImage`.
///
/// Reads the `lattice-operator` Deployment image and patches the self-cluster's
/// LatticeCluster status so the image is visible immediately on startup,
/// even before the first reconcile loop.
async fn report_running_image(client: &kube::Client, cluster_name: &str) {
    use k8s_openapi::api::apps::v1::Deployment;

    let deploy_api: Api<Deployment> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

    let image = match deploy_api.get(OPERATOR_NAME).await {
        Ok(deploy) => deploy
            .spec
            .and_then(|s| s.template.spec)
            .and_then(|s| s.containers.first().cloned())
            .and_then(|c| c.image),
        Err(e) => {
            tracing::debug!(error = %e, "Could not read operator Deployment for image reporting");
            return;
        }
    };

    let Some(image) = image else {
        return;
    };

    let clusters: Api<LatticeCluster> = Api::all(client.clone());
    match clusters.get(cluster_name).await {
        Ok(cluster) => {
            let needs_update = cluster
                .status
                .as_ref()
                .and_then(|s| s.lattice_image.as_deref())
                != Some(&image);

            if needs_update {
                let mut status = cluster.status.unwrap_or_default();
                status.lattice_image = Some(image.clone());

                let patch = serde_json::json!({ "status": status });
                if let Err(e) = clusters
                    .patch_status(
                        cluster_name,
                        &kube::api::PatchParams::default(),
                        &kube::api::Patch::Merge(&patch),
                    )
                    .await
                {
                    tracing::warn!(error = %e, "Failed to report running image in status");
                } else {
                    tracing::info!(image = %image, "Reported running operator image in status");
                }
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "Could not read self-cluster for image reporting");
        }
    }
}
