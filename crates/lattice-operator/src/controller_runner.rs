//! Controller runner - builds controller futures for each vertical slice
//!
//! Each `build_*` function returns a Vec of boxed futures that can be composed
//! by the caller. This keeps controller construction pure and testable.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use futures::StreamExt;
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Api, Client};

use lattice_api::auth::oidc_controller as oidc_provider_ctrl;
use lattice_api::cedar::validation as cedar_validation_ctrl;
use lattice_backup::backup_policy_controller as backup_policy_ctrl;
use lattice_backup::restore_controller as restore_ctrl;
use lattice_capi::installer::CapiInstaller;
use lattice_cedar::PolicyEngine;
use lattice_cell::bootstrap::DefaultManifestGenerator;
use lattice_cell::parent::ParentServers;
use lattice_cloud_provider as cloud_provider_ctrl;
use lattice_cluster::controller::{error_policy, reconcile, Context};
use lattice_common::crd::{
    CedarPolicy, CloudProvider, LatticeBackupPolicy, LatticeCluster, LatticeExternalService,
    LatticeRestore, LatticeService, LatticeServicePolicy, ModelArtifact, OIDCProvider,
    ProviderType, SecretProvider,
};
use lattice_common::ControllerContext;
use lattice_model_cache::{self as model_cache_ctrl, ModelCacheContext};
use lattice_secret_provider as secrets_provider_ctrl;
use lattice_service::controller::{
    error_policy as service_error_policy, error_policy_external, reconcile as service_reconcile,
    reconcile_external, DiscoveredCrds, ServiceContext,
};
use lattice_service::policy_controller as service_policy_ctrl;

/// Watcher timeout (seconds) - must be less than client read_timeout (30s)
/// This forces the API server to close the watch before the client times out,
/// preventing "body read timed out" errors on idle watches.
const WATCH_TIMEOUT_SECS: u32 = 25;

/// Build cluster controller futures
pub fn build_cluster_controllers(
    client: Client,
    self_cluster_name: Option<String>,
    parent_servers: Option<Arc<ParentServers<DefaultManifestGenerator>>>,
    capi_installer: Arc<dyn CapiInstaller>,
) -> Vec<Pin<Box<dyn Future<Output = ()> + Send>>> {
    let mut ctx_builder = Context::builder(client.clone()).capi_installer(capi_installer);
    if let Some(servers) = parent_servers {
        ctx_builder = ctx_builder.parent_servers(servers);
    }
    if let Some(ref name) = self_cluster_name {
        tracing::info!(cluster = %name, "Running as self-managed cluster");
        ctx_builder = ctx_builder.self_cluster_name(name.clone());
    }
    let ctx = Arc::new(ctx_builder.build());
    let clusters: Api<LatticeCluster> = Api::all(client);

    tracing::info!("- LatticeCluster controller");

    vec![Box::pin(
        Controller::new(
            clusters,
            WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(log_reconcile_result("Cluster")),
    )]
}

/// Build service controller futures (LatticeService, LatticeExternalService, LatticeServicePolicy)
pub fn build_service_controllers(
    client: Client,
    cluster_name: String,
    provider_type: ProviderType,
    cedar: Arc<PolicyEngine>,
    crds: Arc<DiscoveredCrds>,
    monitoring_enabled: bool,
) -> Vec<Pin<Box<dyn Future<Output = ()> + Send>>> {
    let watcher_config = || WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS);
    let service_ctx = Arc::new(ServiceContext::from_client(
        client.clone(),
        cluster_name,
        provider_type,
        cedar,
        crds,
        monitoring_enabled,
    ));

    let services: Api<LatticeService> = Api::all(client.clone());
    let services_for_watch = services.clone();
    let graph_for_watch = service_ctx.graph.clone();

    let svc_ctrl = Controller::new(services, watcher_config())
        .watches(services_for_watch, watcher_config(), move |service| {
            let graph = graph_for_watch.clone();
            let namespace = match service.metadata.namespace.as_deref() {
                Some(ns) => ns,
                None => return vec![],
            };
            let name = service.metadata.name.as_deref().unwrap_or_default();

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
        })
        .shutdown_on_signal()
        .run(service_reconcile, service_error_policy, service_ctx.clone())
        .for_each(log_reconcile_result("Service"));

    let ext_ctrl = Controller::new(
        Api::<LatticeExternalService>::all(client.clone()),
        watcher_config(),
    )
    .shutdown_on_signal()
    .run(reconcile_external, error_policy_external, service_ctx)
    .for_each(log_reconcile_result("ExternalService"));

    let policy_ctx = Arc::new(ControllerContext::new(client.clone()));
    let policy_ctrl = Controller::new(
        Api::<LatticeServicePolicy>::all(client.clone()),
        watcher_config(),
    )
    .shutdown_on_signal()
    .run(
        service_policy_ctrl::reconcile,
        lattice_common::default_error_policy,
        policy_ctx,
    )
    .for_each(log_reconcile_result("ServicePolicy"));

    let model_ctx = Arc::new(ModelCacheContext::new(client.clone()));
    let discover = model_cache_ctrl::discover_models(model_ctx.client.clone());
    let model_ctrl = Controller::new(Api::<ModelArtifact>::all(client), watcher_config())
        .watches(
            Api::<LatticeService>::all(model_ctx.client.clone()),
            watcher_config(),
            discover,
        )
        .shutdown_on_signal()
        .run(
            model_cache_ctrl::reconcile,
            model_cache_ctrl::error_policy,
            model_ctx,
        )
        .for_each(log_reconcile_result("ModelArtifact"));

    tracing::info!("- LatticeService controller");
    tracing::info!("- LatticeExternalService controller");
    tracing::info!("- LatticeServicePolicy controller");
    tracing::info!("- ModelArtifact controller");

    vec![
        Box::pin(svc_ctrl),
        Box::pin(ext_ctrl),
        Box::pin(policy_ctrl),
        Box::pin(model_ctrl),
    ]
}

/// Build provider controller futures (CloudProvider, SecretProvider, CedarPolicy, OIDCProvider)
pub fn build_provider_controllers(client: Client) -> Vec<Pin<Box<dyn Future<Output = ()> + Send>>> {
    let ctx = Arc::new(ControllerContext::new(client.clone()));
    let watcher_config = || WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS);

    let cloud_ctrl = Controller::new(Api::<CloudProvider>::all(client.clone()), watcher_config())
        .shutdown_on_signal()
        .run(
            cloud_provider_ctrl::reconcile,
            lattice_common::default_error_policy,
            ctx.clone(),
        )
        .for_each(log_reconcile_result("CloudProvider"));

    let secrets_ctrl = Controller::new(
        Api::<SecretProvider>::all(client.clone()),
        watcher_config(),
    )
    .shutdown_on_signal()
    .run(
        secrets_provider_ctrl::reconcile,
        lattice_common::default_error_policy,
        ctx.clone(),
    )
    .for_each(log_reconcile_result("SecretProvider"));

    let cedar_ctrl = Controller::new(Api::<CedarPolicy>::all(client.clone()), watcher_config())
        .shutdown_on_signal()
        .run(
            cedar_validation_ctrl::reconcile,
            lattice_common::default_error_policy,
            ctx.clone(),
        )
        .for_each(log_reconcile_result("CedarPolicy"));

    let oidc_ctrl = Controller::new(Api::<OIDCProvider>::all(client.clone()), watcher_config())
        .shutdown_on_signal()
        .run(
            oidc_provider_ctrl::reconcile,
            lattice_common::default_error_policy,
            ctx.clone(),
        )
        .for_each(log_reconcile_result("OIDCProvider"));

    let backup_ctrl = Controller::new(
        Api::<LatticeBackupPolicy>::all(client.clone()),
        watcher_config(),
    )
    .shutdown_on_signal()
    .run(
        backup_policy_ctrl::reconcile,
        lattice_common::default_error_policy,
        ctx.clone(),
    )
    .for_each(log_reconcile_result("BackupPolicy"));

    let restore_ctrl = Controller::new(Api::<LatticeRestore>::all(client), watcher_config())
        .shutdown_on_signal()
        .run(
            restore_ctrl::reconcile,
            lattice_common::default_error_policy,
            ctx,
        )
        .for_each(log_reconcile_result("Restore"));

    tracing::info!("- CloudProvider controller");
    tracing::info!("- SecretProvider controller");
    tracing::info!("- CedarPolicy controller");
    tracing::info!("- OIDCProvider controller");
    tracing::info!("- LatticeBackupPolicy controller");
    tracing::info!("- LatticeRestore controller");

    vec![
        Box::pin(cloud_ctrl),
        Box::pin(secrets_ctrl),
        Box::pin(cedar_ctrl),
        Box::pin(oidc_ctrl),
        Box::pin(backup_ctrl),
        Box::pin(restore_ctrl),
    ]
}

/// Resolve provider type from env var (for Service mode, which has no LatticeCluster)
pub fn resolve_provider_type_from_env() -> ProviderType {
    std::env::var("LATTICE_PROVIDER")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(ProviderType::Docker)
}

/// Resolve provider type from the first LatticeCluster CRD
pub async fn resolve_provider_type_from_cluster(client: &Client) -> ProviderType {
    match read_first_cluster(client).await {
        Some(cluster) => cluster.spec.provider.provider_type(),
        None => ProviderType::Docker,
    }
}

/// Resolve monitoring status from env var (for Service mode, which has no LatticeCluster).
/// Defaults to true (monitoring is enabled by default).
pub fn resolve_monitoring_from_env() -> bool {
    std::env::var("LATTICE_MONITORING")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(true)
}

/// Resolve monitoring status from the first LatticeCluster CRD
pub async fn resolve_monitoring_from_cluster(client: &Client) -> bool {
    match read_first_cluster(client).await {
        Some(cluster) => cluster.spec.monitoring,
        None => true,
    }
}

/// Read the first LatticeCluster from the API server, or None if unavailable.
async fn read_first_cluster(client: &Client) -> Option<LatticeCluster> {
    let clusters: Api<LatticeCluster> = Api::all(client.clone());
    match clusters.list(&kube::api::ListParams::default()).await {
        Ok(list) => list.items.into_iter().next(),
        Err(e) => {
            tracing::warn!(error = %e, "failed to read LatticeCluster");
            None
        }
    }
}

/// Creates a closure for logging reconciliation results.
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
