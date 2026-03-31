//! Lattice Operator - Kubernetes multi-cluster lifecycle management
//!
//! This is the main entry point. It handles CLI parsing and starts subsystems.
//! All business logic lives in library modules.
//!
//! # Architecture: Per-Controller Leader Election
//!
//! Every controller runs behind its own Kubernetes Lease. Multiple replicas
//! compete for each lease independently, so controllers can distribute across
//! pods. Losing leadership of one controller doesn't affect the others.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use clap::Parser;
use futures::StreamExt;
use kube::runtime::watcher::{self, Event};
use kube::{Api, CustomResourceExt};
use tokio_util::sync::CancellationToken;

use lattice_api::{oidc_from_crd, AuthChain, SaValidator, ServerConfig as AuthProxyConfig};
use lattice_capi::installer::{CapiInstaller, NativeInstaller};
use lattice_cedar::PolicyEngine;
use lattice_cell::bootstrap::DefaultManifestGenerator;
use lattice_cell::parent::{ParentConfig, ParentServers};
use lattice_common::crd::{
    CedarPolicy, LatticeCluster, LatticeJob, LatticeMeshMember, LatticeModel, LatticeQuota,
    LatticeService, OIDCProvider,
};
use lattice_common::graph::ServiceGraph;
use lattice_common::retry::{retry_with_backoff, RetryConfig};
use lattice_common::telemetry::init_telemetry;
use lattice_common::CrdRegistry;
use lattice_common::SharedConfig;
use lattice_common::{
    lattice_svc_dns, CELL_SERVICE_NAME, DEFAULT_AUTH_PROXY_PORT, DEFAULT_HEALTH_PORT,
    LATTICE_SYSTEM_NAMESPACE, OPERATOR_NAME,
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
    /// Print CRD schema and exit
    #[arg(long)]
    crd: bool,
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

    run(prom_registry).await
}

fn init_crypto() {
    // Panics on failure — FIPS mode is mandatory
    lattice_common::fips::install_crypto_provider();
    eprintln!("FIPS mode: ENABLED");
}

fn init_telemetry_global() -> Option<prometheus::Registry> {
    let config = lattice_common::telemetry::TelemetryConfig {
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
            use tracing_subscriber::{fmt, prelude::*, EnvFilter};
            let _ = tracing_subscriber::registry()
                .with(fmt::layer())
                .with(EnvFilter::from_default_env())
                .try_init();
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Main startup
// ---------------------------------------------------------------------------

async fn run(prom_registry: Option<prometheus::Registry>) -> anyhow::Result<()> {
    tracing::info!("Starting Lattice operator (per-controller leader election)...");

    // Parse all LATTICE_* env vars once at startup
    let config = Arc::new(
        lattice_common::LatticeConfig::from_env()
            .map_err(|e| anyhow::anyhow!("Failed to parse operator config: {}", e))?,
    );

    // Create client with proper timeouts (5s connect, 30s read)
    let client = lattice_common::kube_utils::create_client(None, None, None).await?;

    // Get pod identity from Downward API env vars (set in deployment manifest)
    let pod_name = std::env::var("POD_NAME").unwrap_or_else(|_| {
        let name = format!("lattice-operator-{}", uuid::Uuid::new_v4());
        tracing::warn!(pod_name = %name, "POD_NAME not set (expected from Downward API), using generated name");
        name
    });

    let graph_holder: Arc<OnceLock<Arc<ServiceGraph>>> = Arc::new(OnceLock::new());
    let (quota_sender, quota_store) = lattice_quota::quota_channel();
    let cancel = CancellationToken::new();

    // ── Pre-election services (run on ALL pods) ──

    let health_handle = start_health_server(prom_registry, graph_holder.clone(), config.debug);

    let webhook_creds =
        lattice_secret_provider::controller::ensure_webhook_credentials(&client).await?;

    let webhook_client = client.clone();
    tokio::spawn(async move {
        if let Err(e) =
            lattice_secret_provider::webhook::start_webhook_server(webhook_client, webhook_creds)
                .await
        {
            tracing::error!(error = %e, "Local secrets webhook server failed");
        }
    });

    let webhook_client = client.clone();
    tokio::spawn(async move {
        if let Err(e) = lattice_webhook::start_webhook_server(webhook_client).await {
            tracing::error!(error = %e, "Admission webhook server failed");
        }
    });

    // ── Shared state ──

    let cedar = load_cedar_engine(&client).await;

    // Cedar policy reloader — runs on ALL pods (not behind leader election).
    // With per-controller leases the CedarPolicy controller may run on a
    // different pod than the auth proxy. This ensures every pod's PolicyEngine
    // stays current by watching CedarPolicy CRDs and reloading on changes,
    // with a periodic fallback for missed events during reconnects.
    spawn_cedar_policy_reloader(client.clone(), cedar.clone(), cancel.clone());

    let capi_installer: Arc<dyn CapiInstaller> = Arc::new(NativeInstaller::new());

    // Report running operator image in status.latticeImage
    if let Some(ref self_name) = config.cluster_name {
        report_running_image(&client, self_name).await;
    }

    // ── Spawn all controllers (each with its own Kubernetes Lease) ──

    tracing::info!("Spawning controllers with per-controller leader election...");

    // Infrastructure controller (CRD install, CAPI, Istio, ESO)
    tokio::spawn(controller_runner::leader_controller(
        client.clone(),
        pod_name.clone(),
        "infra",
        cancel.clone(),
        false,
        {
            let client = client.clone();
            let config = config.clone();
            let capi_installer = capi_installer.clone();
            move || {
                let client = client.clone();
                let config = config.clone();
                let capi_installer = capi_installer.clone();
                Box::pin(async move {
                    ensure_cluster_crds(&client)
                        .await
                        .expect("CRD install failed");
                    ensure_service_crds(&client)
                        .await
                        .expect("CRD install failed");
                    spawn_admission_webhook_configuration(client.clone());
                    ensure_capi_infrastructure(&client, Some(&*capi_installer), &config)
                        .await
                        .expect("CAPI infrastructure failed");
                    let handle = spawn_general_infrastructure(client.clone(), true, config.clone());
                    spawn_webhook_infrastructure(client);
                    // Wait for general infra then hold the lease forever
                    if let Err(e) = handle.await {
                        tracing::error!(error = ?e, "General infrastructure task failed");
                    }
                    std::future::pending::<()>().await;
                }) as Pin<Box<dyn Future<Output = ()> + Send>>
            }
        },
    ));

    // Watch channel for parent_servers — cell infra sends, cluster controller receives.
    let (parent_servers_tx, parent_servers_rx) = tokio::sync::watch::channel(None);

    // Cell infrastructure (gRPC server, bootstrap webhook, auth proxy)
    tokio::spawn(controller_runner::leader_controller(
        client.clone(),
        pod_name.clone(),
        "cell",
        cancel.clone(),
        true, // claim_traffic for gRPC/auth-proxy routing
        {
            let client = client.clone();
            let config = config.clone();
            let cedar = cedar.clone();
            let parent_servers_tx = parent_servers_tx.clone();
            move || {
                let client = client.clone();
                let config = config.clone();
                let cedar = cedar.clone();
                let parent_servers_tx = parent_servers_tx.clone();
                Box::pin(async move {
                    wait_for_api_ready_for::<LatticeCluster>(&client).await;
                    let self_cluster_name = config.cluster_name.clone();
                    match setup_cell_infra(&client, &self_cluster_name, cedar, &config).await {
                        Ok((servers, agent_token, _auth_proxy, _route_tx)) => {
                            let _ = parent_servers_tx.send(Some(servers.clone()));
                            // Guard ensures cell infra is torn down on leadership loss.
                            // Dropping a CancellationToken does NOT cancel it — the
                            // guard explicitly cancels and shuts down servers so agents
                            // reconnect to the new leader's gRPC server.
                            let _guard = CellInfraGuard { agent_token, servers };
                            std::future::pending::<()>().await;
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Cell infrastructure setup failed");
                        }
                    }
                }) as Pin<Box<dyn Future<Output = ()> + Send>>
            }
        },
    ));

    // LatticeCluster controller
    tokio::spawn(controller_runner::leader_controller(
        client.clone(),
        pod_name.clone(),
        "cluster",
        cancel.clone(),
        false,
        {
            let client = client.clone();
            let config = config.clone();
            let capi_installer = capi_installer.clone();
            let parent_servers_rx = parent_servers_rx.clone();
            move || {
                let client = client.clone();
                let config = config.clone();
                let capi_installer = capi_installer.clone();
                let mut parent_servers_rx = parent_servers_rx.clone();
                Box::pin(async move {
                    wait_for_api_ready_for::<LatticeCluster>(&client).await;
                    let self_cluster_name = config.cluster_name.clone();
                    // Use parent_servers if cell infra is running on this pod,
                    // otherwise proceed with None (cell is on another pod).
                    // Wait briefly since cell and cluster start concurrently.
                    let parent_servers = tokio::time::timeout(
                        Duration::from_secs(10),
                        async {
                            loop {
                                if let Some(ref ps) = *parent_servers_rx.borrow_and_update() {
                                    return Some(ps.clone());
                                }
                                if parent_servers_rx.changed().await.is_err() {
                                    return None; // sender dropped
                                }
                            }
                        },
                    )
                    .await
                    .unwrap_or(None);
                    controller_runner::build_cluster_controller(
                        client,
                        self_cluster_name,
                        parent_servers,
                        capi_installer,
                        config,
                    )
                    .await;
                }) as Pin<Box<dyn Future<Output = ()> + Send>>
            }
        },
    ));

    let ctx = controller_runner::SpawnContext {
        client: client.clone(),
        pod_name: pod_name.clone(),
        cancel: cancel.clone(),
        config: config.clone(),
        cedar: cedar.clone(),
        graph_holder: graph_holder.clone(),
        quota_store,
    };

    // Workload controllers (Service, Job, Model)
    ctx.spawn_workload::<LatticeService, _>("service", |p| {
        controller_runner::build_service_controller(p)
    });
    ctx.spawn_workload::<LatticeJob, _>("job", |p| controller_runner::build_job_controller(p));
    ctx.spawn_workload::<LatticeModel, _>("model", |p| {
        controller_runner::build_model_controller(p)
    });

    // LatticeMeshMember controller (needs graph but not full workload params)
    tokio::spawn(controller_runner::leader_controller(
        client.clone(),
        pod_name.clone(),
        "mesh-member",
        cancel.clone(),
        false,
        {
            let ctx = ctx.clone();
            move || {
                let ctx = ctx.clone();
                Box::pin(async move {
                    wait_for_api_ready_for::<LatticeMeshMember>(&ctx.client).await;
                    let cluster_name = ctx
                        .config
                        .cluster_name_required()
                        .expect("cluster name required")
                        .to_string();
                    let graph = controller_runner::ensure_graph(
                        &ctx.client,
                        &ctx.graph_holder,
                        &cluster_name,
                    )
                    .await;
                    let registry = Arc::new(CrdRegistry::new(ctx.client.clone()).await);
                    let auditor_token = CancellationToken::new();
                    controller_runner::spawn_graph_auditor(
                        ctx.client.clone(),
                        graph.clone(),
                        auditor_token.clone(),
                    );
                    controller_runner::build_mesh_member_controller(
                        ctx.client.clone(),
                        graph,
                        cluster_name,
                        ctx.cedar.clone(),
                        registry,
                    )
                    .await;
                    auditor_token.cancel();
                }) as Pin<Box<dyn Future<Output = ()> + Send>>
            }
        },
    ));

    // CedarPolicy (uses CedarValidationContext)
    tokio::spawn(controller_runner::leader_controller(
        client.clone(),
        pod_name.clone(),
        "cedar",
        cancel.clone(),
        false,
        {
            let client = client.clone();
            let cedar = cedar.clone();
            move || {
                let client = client.clone();
                let cedar = cedar.clone();
                Box::pin(async move {
                    wait_for_api_ready_for::<CedarPolicy>(&client).await;
                    let ctx = Arc::new(lattice_api::cedar::validation::CedarValidationContext {
                        client: client.clone(),
                        cedar,
                    });
                    controller_runner::simple_controller(
                        Api::<CedarPolicy>::all(client),
                        lattice_api::cedar::validation::reconcile,
                        ctx,
                        "CedarPolicy",
                    )
                    .await;
                }) as Pin<Box<dyn Future<Output = ()> + Send>>
            }
        },
    ));

    // LatticeQuota (uses QuotaContext with sender channel)
    tokio::spawn(controller_runner::leader_controller(
        client.clone(),
        pod_name.clone(),
        "quota",
        cancel.clone(),
        false,
        {
            let client = client.clone();
            move || {
                let client = client.clone();
                let quota_sender = quota_sender.clone();
                Box::pin(async move {
                    wait_for_api_ready_for::<LatticeQuota>(&client).await;
                    let ctx = Arc::new(lattice_quota::QuotaContext {
                        client: client.clone(),
                        sender: quota_sender,
                    });
                    controller_runner::simple_controller(
                        Api::<LatticeQuota>::all(client),
                        lattice_quota::reconcile,
                        ctx,
                        "LatticeQuota",
                    )
                    .await;
                }) as Pin<Box<dyn Future<Output = ()> + Send>>
            }
        },
    ));

    // Simple provider controllers (all use ControllerContext)
    ctx.spawn_provider("dns", lattice_dns_provider::reconcile, "DNSProvider");
    ctx.spawn_provider("cert", lattice_cert_issuer::reconcile, "CertIssuer");
    ctx.spawn_provider("cloud", lattice_cloud_provider::reconcile, "InfraProvider");
    ctx.spawn_provider(
        "secret",
        lattice_secret_provider::controller::reconcile,
        "SecretProvider",
    );
    ctx.spawn_provider(
        "oidc",
        lattice_api::auth::oidc_controller::reconcile,
        "OIDCProvider",
    );
    ctx.spawn_provider(
        "backup-store",
        lattice_backup::backup_store_controller::reconcile,
        "BackupStore",
    );
    ctx.spawn_provider(
        "cluster-backup",
        lattice_backup::cluster_backup_controller::reconcile,
        "ClusterBackup",
    );
    ctx.spawn_provider(
        "restore",
        lattice_backup::restore_controller::reconcile,
        "Restore",
    );
    ctx.spawn_provider::<LatticeService, _, _>(
        "service-backup",
        lattice_backup::service_backup_controller::reconcile,
        "ServiceBackup",
    );

    // ── Wait for shutdown signal ──

    let shutdown_signal = async {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to listen for SIGTERM");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Received SIGINT, shutting down");
            }
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM, shutting down");
            }
        }
    };

    shutdown_signal.await;

    // Cancel all controllers — each leader_controller loop will release its lease
    tracing::info!("Cancelling all controllers...");
    cancel.cancel();

    // Give controllers a moment to release leases gracefully
    tokio::time::sleep(Duration::from_secs(2)).await;

    health_handle.abort();
    tracing::info!("Shutdown complete");
    Ok(())
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

/// Reload Cedar policies on every pod via watcher + periodic fallback.
///
/// Runs on ALL pods (not behind leader election) so every pod's
/// PolicyEngine stays current — critical for the auth proxy which
/// may run on a different pod than the CedarPolicy controller.
///
/// Uses a K8s watcher for instant reaction to policy changes, with a
/// periodic reload every 60s as a safety net for missed events during
/// watch reconnects or startup races.
fn spawn_cedar_policy_reloader(
    client: kube::Client,
    cedar: Arc<PolicyEngine>,
    cancel: CancellationToken,
) {
    const PERIODIC_RELOAD_INTERVAL: Duration = Duration::from_secs(60);

    tokio::spawn(async move {
        wait_for_api_ready_for::<CedarPolicy>(&client).await;

        // Initial reload to pick up any policies created before this task started
        if let Err(e) = cedar.reload(&client).await {
            tracing::warn!(error = %e, "Initial Cedar policy reload failed");
        }

        let api: Api<CedarPolicy> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
        let watcher_config = watcher::Config::default().timeout(25);
        let mut stream = std::pin::pin!(watcher::watcher(api, watcher_config));
        let mut periodic = tokio::time::interval(PERIODIC_RELOAD_INTERVAL);
        periodic.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                // Watcher: reload immediately on any CedarPolicy change
                event = stream.next() => {
                    match event {
                        Some(Ok(Event::Apply(_) | Event::Delete(_))) => {
                            if let Err(e) = cedar.reload(&client).await {
                                tracing::warn!(error = %e, "Cedar policy reload failed");
                            }
                        }
                        Some(Ok(_)) => {} // Init, InitApply, InitDone
                        Some(Err(e)) => {
                            tracing::warn!(error = %e, "Cedar policy watcher error");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                        None => {
                            tracing::warn!("Cedar policy watcher stream ended, restarting");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
                // Periodic fallback: catch anything the watcher missed
                _ = periodic.tick() => {
                    if let Err(e) = cedar.reload(&client).await {
                        tracing::debug!(error = %e, "Periodic Cedar reload failed");
                    }
                }
            }
        }
    });
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

/// Drop guard that tears down cell infrastructure on leadership loss.
///
/// When the leader controller drops this future (leadership lost), the guard
/// cancels the agent token and shuts down the gRPC server. This forces
/// connected agents to reconnect to the new leader's fresh subtree registry.
struct CellInfraGuard {
    agent_token: CancellationToken,
    servers: Arc<ParentServers<DefaultManifestGenerator>>,
}

impl Drop for CellInfraGuard {
    fn drop(&mut self) {
        tracing::info!("Cell leadership lost, shutting down cell infrastructure");
        self.agent_token.cancel();
        let servers = self.servers.clone();
        tokio::spawn(async move {
            servers.shutdown().await;
        });
    }
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
/// Returns (parent_servers, agent_cancellation_token, auth_proxy_supervisor, route_update_tx)
async fn setup_cell_infra(
    client: &kube::Client,
    self_cluster_name: &Option<String>,
    cedar: Arc<PolicyEngine>,
    config: &SharedConfig,
) -> anyhow::Result<(
    Arc<ParentServers<DefaultManifestGenerator>>,
    CancellationToken,
    Option<tokio::task::JoinHandle<()>>,
    Option<lattice_cell::route_reconciler::RouteUpdateSender>,
)> {
    let is_bootstrap = config.is_bootstrap_cluster;

    // Create cell servers (always — CA + registries needed by agent SubtreeForwarder)
    let parent_config = ParentConfig::from_config(config);
    let servers = Arc::new(ParentServers::new(parent_config, client).await?);

    // Start route reconciler on ALL clusters (not just parents).
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
    let agent_token = CancellationToken::new();
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

    let auth_proxy_supervisor = if is_cell {
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
                    watcher_route_tx,
                    watcher_all_rx,
                )
                .await;
            });
        }
        None
    };

    Ok((servers, agent_token, auth_proxy_supervisor, route_update_tx))
}

/// Parameters for activating cell services.
struct CellActivationParams {
    extra_sans: Vec<String>,
    cedar: Arc<PolicyEngine>,
    route_update_tx: lattice_cell::route_reconciler::RouteUpdateSender,
    all_routes_rx: Option<lattice_cell::route_reconciler::AllRoutesReceiver>,
}

/// Activate cell infrastructure: start servers, auth proxy, CA rotation, and crash recovery.
async fn activate_cell_services(
    client: &kube::Client,
    servers: &Arc<ParentServers<DefaultManifestGenerator>>,
    cluster_name: &Option<String>,
    params: CellActivationParams,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    let CellActivationParams {
        extra_sans,
        cedar,
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
async fn cell_activation_watcher(
    client: kube::Client,
    self_cluster_name: String,
    servers: Arc<ParentServers<DefaultManifestGenerator>>,
    cedar: Arc<PolicyEngine>,
    route_update_tx: lattice_cell::route_reconciler::RouteUpdateSender,
    all_routes_rx: Option<lattice_cell::route_reconciler::AllRoutesReceiver>,
) {
    use lattice_operator::startup::{
        discover_cell_host, ensure_cell_service_exists, LOAD_BALANCER_POLL_INTERVAL,
    };

    loop {
        if servers.is_running() {
            return;
        }

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

        tracing::info!("parent_config detected, promoting to cell...");
        let provider_type = cluster.spec.provider.provider_type();

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

        let _proxy_handle = match activate_cell_services(
            &client,
            &servers,
            &cluster_name,
            CellActivationParams {
                extra_sans,
                cedar: cedar.clone(),
                route_update_tx: route_update_tx.clone(),
                all_routes_rx: all_routes_rx.clone(),
            },
        )
        .await
        {
            Ok(handle) => handle,
            Err(e) => {
                tracing::error!(error = %e, "Failed to activate cell services during promotion");
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };

        tracing::info!("Cell infrastructure activated (cluster promoted to parent)");
        std::future::pending::<()>().await;
    }
}

/// Spawn admission webhook configuration registration in background.
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

// ---------------------------------------------------------------------------
// Health, auth proxy, and watcher functions
// ---------------------------------------------------------------------------

/// Start the health check server for Kubernetes probes
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
async fn start_auth_proxy(
    client: &kube::Client,
    parent_servers: Arc<ParentServers<DefaultManifestGenerator>>,
    cluster_name: &Option<String>,
    extra_sans: &[String],
    cedar: Arc<PolicyEngine>,
    all_routes_rx: Option<lattice_cell::route_reconciler::AllRoutesReceiver>,
) -> Option<tokio::task::JoinHandle<()>> {
    let cluster_name = cluster_name
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

    let sa_validator = Arc::new(SaValidator::new(client.clone()).with_audiences(vec![
        lattice_common::kube_utils::PROXY_TOKEN_AUDIENCE.to_string(),
        "https://kubernetes.default.svc.cluster.local".to_string(),
    ]));

    let oidc_validator = match oidc_from_crd(client).await {
        Ok(v) => {
            tracing::info!(issuer = %v.config().issuer_url, "OIDC authentication enabled");
            Some(Arc::new(v))
        }
        Err(e) => {
            tracing::info!(error = %e, "No OIDC provider configured, SA auth only");
            None
        }
    };

    let auth_chain = Arc::new(match oidc_validator {
        Some(oidc) => AuthChain::new(oidc, sa_validator),
        None => AuthChain::sa_only(sa_validator),
    });

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

    let addr: SocketAddr = match format!("0.0.0.0:{}", DEFAULT_AUTH_PROXY_PORT).parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "Failed to parse auth proxy address");
            return None;
        }
    };

    let base_host = extra_sans.first().map(|s| s.as_str()).unwrap_or(&cell_dns);
    let base_url = format!("https://{}:{}", base_host, DEFAULT_AUTH_PROXY_PORT);

    let proxy_ca_cert = ca_cert_pem.clone();
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

    let subtree = parent_servers.subtree_registry();
    let agent_registry = parent_servers.agent_registry();
    let backend = Arc::new(CellProxyBackend::new(subtree, agent_registry));

    tracing::info!(addr = %addr, cluster = %cluster_name, "Starting auth proxy server");

    controller_runner::spawn_remote_secret_controller(client.clone());

    if let Some(rx) = all_routes_rx {
        parent_servers
            .set_peer_config(peer_proxy_url, proxy_ca_cert, rx)
            .await;
    }

    start_oidc_provider_watcher(client.clone(), auth_chain.clone());

    let proxy_handle = match lattice_api::start_server(
        config.clone(),
        auth_chain.clone(),
        cedar.clone(),
        backend.clone(),
    )
    .await
    {
        Ok(handle) => handle,
        Err(e) => {
            tracing::error!(error = %e, "Failed to start auth proxy");
            return None;
        }
    };

    let supervisor = tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(30);

        proxy_handle.wait().await;

        loop {
            tracing::warn!(restart_in = ?backoff, "Auth proxy exited, restarting...");
            tokio::time::sleep(backoff).await;

            match lattice_api::start_server(
                config.clone(),
                auth_chain.clone(),
                cedar.clone(),
                backend.clone(),
            )
            .await
            {
                Ok(handle) => {
                    tracing::info!("Auth proxy restarted");
                    backoff = Duration::from_secs(1);
                    handle.wait().await;
                }
                Err(e) => {
                    tracing::error!(error = %e, "Auth proxy restart failed");
                }
            }

            backoff = std::cmp::min(backoff * 2, max_backoff);
        }
    });

    Some(supervisor)
}

/// Start a background task to watch for OIDCProvider CRD changes and reload the OIDC validator.
fn start_oidc_provider_watcher(client: kube::Client, auth_chain: Arc<AuthChain>) {
    tokio::spawn(async move {
        let api: Api<OIDCProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

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
                    match oidc_from_crd(&client).await {
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
