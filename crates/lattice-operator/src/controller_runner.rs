//! Controller runner - starts and manages all Kubernetes controllers
//!
//! This module handles the creation and running of all controllers.

use std::future::Future;
use std::sync::Arc;

use futures::StreamExt;
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Api, Client};

use lattice_operator::bootstrap::DefaultManifestGenerator;
use lattice_operator::cloud_provider::{self as cloud_provider_ctrl, ControllerContext};
use lattice_operator::controller::{
    error_policy, error_policy_external, reconcile, reconcile_external, service_error_policy,
    service_reconcile, Context, ServiceContext,
};
use lattice_operator::crd::{
    CloudProvider, LatticeCluster, LatticeExternalService, LatticeService, ProviderType,
    SecretsProvider,
};
use lattice_operator::parent::ParentServers;
use lattice_operator::secrets_provider as secrets_provider_ctrl;

use crate::ControllerMode;

/// Run all controllers until shutdown
pub async fn run_controllers(
    client: Client,
    mode: ControllerMode,
    self_cluster_name: Option<String>,
    parent_servers: Option<Arc<ParentServers<DefaultManifestGenerator>>>,
) {
    let run_cluster = matches!(mode, ControllerMode::All | ControllerMode::Cluster);
    let run_service = matches!(mode, ControllerMode::All | ControllerMode::Service);
    let run_provider = matches!(mode, ControllerMode::All | ControllerMode::Provider);

    log_enabled_controllers(run_cluster, run_service, run_provider);

    // Build cluster controller context and controller (only if needed)
    let cluster_controller = if run_cluster {
        let mut ctx_builder = Context::builder(client.clone());
        if let Some(servers) = parent_servers {
            ctx_builder = ctx_builder.parent_servers(servers);
        }
        if let Some(ref name) = self_cluster_name {
            tracing::info!(cluster = %name, "Running as self-managed cluster");
            ctx_builder = ctx_builder.self_cluster_name(name.clone());
        }
        let ctx = Arc::new(ctx_builder.build());
        let clusters: Api<LatticeCluster> = Api::all(client.clone());
        create_cluster_controller(clusters, ctx)
    } else {
        None
    };

    // Build service controller context and controllers (only if needed)
    let (service_controller, external_controller) = if run_service {
        // Get provider type for topology-aware scheduling
        let clusters: Api<LatticeCluster> = Api::all(client.clone());
        let provider_type = match clusters.list(&kube::api::ListParams::default()).await {
            Ok(list) => list
                .items
                .first()
                .map(|c| c.spec.provider.provider_type())
                .unwrap_or(ProviderType::Docker),
            Err(e) => {
                tracing::warn!(error = %e, "failed to read LatticeCluster, defaulting to Docker");
                ProviderType::Docker
            }
        };

        let cluster_name_for_service = self_cluster_name.unwrap_or_else(|| "default".to_string());
        let service_ctx = Arc::new(ServiceContext::from_client(
            client.clone(),
            cluster_name_for_service,
            provider_type,
        ));
        create_service_controllers(client.clone(), service_ctx)
    } else {
        (None, None)
    };

    // Build provider controllers (only if needed)
    let (cloud_provider_controller, secrets_provider_controller) = if run_provider {
        (
            create_cloud_provider_controller(client.clone()),
            create_secrets_provider_controller(client),
        )
    } else {
        (None, None)
    };

    // Run all controllers until one exits
    tokio::select! {
        _ = run_optional_controller(cloud_provider_controller) => tracing::info!("CloudProvider controller completed"),
        _ = run_optional_controller(secrets_provider_controller) => tracing::info!("SecretsProvider controller completed"),
        _ = run_optional_controller(cluster_controller) => tracing::info!("Cluster controller completed"),
        _ = run_optional_controller(service_controller) => tracing::info!("Service controller completed"),
        _ = run_optional_controller(external_controller) => tracing::info!("External service controller completed"),
    }
}

/// Run an optional controller, or wait forever if None.
///
/// This helper consolidates the pattern of conditionally running a controller
/// based on whether it was enabled. When the controller is None, it simply
/// waits forever (pending), allowing tokio::select! to wait on other branches.
async fn run_optional_controller<F: Future<Output = ()>>(controller: Option<F>) {
    match controller {
        Some(ctrl) => ctrl.await,
        None => std::future::pending::<()>().await,
    }
}

fn log_enabled_controllers(run_cluster: bool, run_service: bool, run_provider: bool) {
    tracing::info!("Starting Lattice controllers...");
    if run_cluster {
        tracing::info!("- LatticeCluster controller");
    }
    if run_service {
        tracing::info!("- LatticeService controller");
        tracing::info!("- LatticeExternalService controller");
    }
    if run_provider {
        tracing::info!("- CloudProvider controller");
        tracing::info!("- SecretsProvider controller");
    }
}

/// Watcher timeout (seconds) - must be less than client read_timeout (30s)
/// This forces the API server to close the watch before the client times out,
/// preventing "body read timed out" errors on idle watches.
const WATCH_TIMEOUT_SECS: u32 = 25;

fn create_cluster_controller(
    clusters: Api<LatticeCluster>,
    ctx: Arc<Context>,
) -> Option<impl std::future::Future<Output = ()>> {
    Some(
        Controller::new(
            clusters,
            WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(log_reconcile_result("Cluster")),
    )
}

fn create_service_controllers(
    client: Client,
    ctx: Arc<ServiceContext>,
) -> (
    Option<impl std::future::Future<Output = ()>>,
    Option<impl std::future::Future<Output = ()>>,
) {
    let services: Api<LatticeService> = Api::all(client.clone());
    let external_services: Api<LatticeExternalService> = Api::all(client);

    let graph_for_watch = ctx.graph.clone();
    let services_for_watch = services.clone();

    let svc_ctrl = Controller::new(
        services,
        WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
    )
    .watches(
        services_for_watch,
        WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
        move |service| {
            let graph = graph_for_watch.clone();
            let namespace = match service.metadata.namespace.as_deref() {
                Some(ns) => ns,
                None => return vec![],
            };
            let name = service.metadata.name.as_deref().unwrap_or_default();

            // Get affected services (dependencies + dependents)
            let mut affected: Vec<String> = graph.get_dependencies(namespace, name);
            affected.extend(graph.get_dependents(namespace, name));
            affected.sort();
            affected.dedup();

            tracing::debug!(
                service = %name,
                namespace = %namespace,
                affected_count = affected.len(),
                "Triggering re-reconciliation of affected services"
            );

            let ns = namespace.to_string();
            affected
                .into_iter()
                .map(|dep| ObjectRef::<LatticeService>::new(&dep).within(&ns))
                .collect()
        },
    )
    .shutdown_on_signal()
    .run(service_reconcile, service_error_policy, ctx.clone())
    .for_each(log_reconcile_result("Service"));

    let ext_ctrl = Controller::new(
        external_services,
        WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
    )
    .shutdown_on_signal()
    .run(reconcile_external, error_policy_external, ctx)
    .for_each(log_reconcile_result("ExternalService"));

    (Some(svc_ctrl), Some(ext_ctrl))
}

fn create_cloud_provider_controller(client: Client) -> Option<impl std::future::Future<Output = ()>> {
    let cloud_providers: Api<CloudProvider> = Api::all(client.clone());
    let ctx = Arc::new(ControllerContext::new(client));

    Some(
        Controller::new(
            cloud_providers,
            WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
        )
        .shutdown_on_signal()
        .run(
            cloud_provider_ctrl::reconcile,
            lattice_common::default_error_policy,
            ctx,
        )
        .for_each(log_reconcile_result("CloudProvider")),
    )
}

fn create_secrets_provider_controller(client: Client) -> Option<impl std::future::Future<Output = ()>> {
    let secrets_providers: Api<SecretsProvider> = Api::all(client.clone());
    let ctx = Arc::new(ControllerContext::new(client));

    Some(
        Controller::new(
            secrets_providers,
            WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
        )
        .shutdown_on_signal()
        .run(
            secrets_provider_ctrl::reconcile,
            lattice_common::default_error_policy,
            ctx,
        )
        .for_each(log_reconcile_result("SecretsProvider")),
    )
}

/// Creates a closure for logging reconciliation results.
///
/// This consolidates the duplicated pattern of logging Ok/Err results from controller runs.
fn log_reconcile_result<T: std::fmt::Debug, E: std::fmt::Debug>(
    controller_name: &'static str,
) -> impl Fn(Result<T, E>) -> std::future::Ready<()> {
    move |result| {
        match result {
            Ok(action) => tracing::debug!(?action, "{} reconciliation completed", controller_name),
            Err(e) => tracing::error!(error = ?e, "{} reconciliation error", controller_name),
        }
        std::future::ready(())
    }
}
