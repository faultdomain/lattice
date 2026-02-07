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
use lattice_api::PolicyEngine;
use lattice_backup::backup_policy_controller as backup_policy_ctrl;
use lattice_backup::restore_controller as restore_ctrl;
use lattice_cell::bootstrap::DefaultManifestGenerator;
use lattice_cell::parent::ParentServers;
use lattice_cloud_provider as cloud_provider_ctrl;
use lattice_common::ControllerContext;
use lattice_cluster::controller::{error_policy, reconcile, Context};
use lattice_common::crd::{
    CedarPolicy, CloudProvider, LatticeBackupPolicy, LatticeCluster, LatticeExternalService,
    LatticeRestore, LatticeService, LatticeServicePolicy, ModelArtifact, OIDCProvider,
    ProviderType, SecretsProvider,
};
use lattice_model_cache::{self as model_cache_ctrl, ModelCacheContext};
use lattice_secrets_provider as secrets_provider_ctrl;
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
) -> Vec<Pin<Box<dyn Future<Output = ()> + Send>>> {
    let mut ctx_builder = Context::builder(client.clone());
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
) -> Vec<Pin<Box<dyn Future<Output = ()> + Send>>> {
    let service_ctx = Arc::new(ServiceContext::from_client(
        client.clone(),
        cluster_name,
        provider_type,
        cedar,
        crds,
    ));

    let services: Api<LatticeService> = Api::all(client.clone());
    let external_services: Api<LatticeExternalService> = Api::all(client.clone());

    let graph_for_watch = service_ctx.graph.clone();
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
    .run(service_reconcile, service_error_policy, service_ctx.clone())
    .for_each(log_reconcile_result("Service"));

    let ext_ctrl = Controller::new(
        external_services,
        WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
    )
    .shutdown_on_signal()
    .run(reconcile_external, error_policy_external, service_ctx)
    .for_each(log_reconcile_result("ExternalService"));

    let policies: Api<LatticeServicePolicy> = Api::all(client.clone());
    let policy_ctx = Arc::new(ControllerContext::new(client.clone()));
    let policy_ctrl = Controller::new(
        policies,
        WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
    )
    .shutdown_on_signal()
    .run(
        service_policy_ctrl::reconcile,
        lattice_common::default_error_policy,
        policy_ctx,
    )
    .for_each(log_reconcile_result("ServicePolicy"));

    let model_artifacts: Api<ModelArtifact> = Api::all(client.clone());
    let services_for_model_watch: Api<LatticeService> = Api::all(client.clone());
    let model_ctx = Arc::new(ModelCacheContext::new(client));
    let discover = model_cache_ctrl::discover_models(model_ctx.client.clone());
    let model_ctrl = Controller::new(
        model_artifacts,
        WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
    )
    .watches(
        services_for_model_watch,
        WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
        move |service| discover(service),
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

/// Build provider controller futures (CloudProvider, SecretsProvider, CedarPolicy, OIDCProvider)
pub fn build_provider_controllers(client: Client) -> Vec<Pin<Box<dyn Future<Output = ()> + Send>>> {
    let cloud_providers: Api<CloudProvider> = Api::all(client.clone());
    let cp_ctx = Arc::new(ControllerContext::new(client.clone()));
    let cloud_ctrl = Controller::new(
        cloud_providers,
        WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
    )
    .shutdown_on_signal()
    .run(
        cloud_provider_ctrl::reconcile,
        lattice_common::default_error_policy,
        cp_ctx,
    )
    .for_each(log_reconcile_result("CloudProvider"));

    let secrets_providers: Api<SecretsProvider> = Api::all(client.clone());
    let sp_ctx = Arc::new(ControllerContext::new(client.clone()));
    let secrets_ctrl = Controller::new(
        secrets_providers,
        WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
    )
    .shutdown_on_signal()
    .run(
        secrets_provider_ctrl::reconcile,
        lattice_common::default_error_policy,
        sp_ctx,
    )
    .for_each(log_reconcile_result("SecretsProvider"));

    let cedar_policies: Api<CedarPolicy> = Api::all(client.clone());
    let cedar_ctx = Arc::new(ControllerContext::new(client.clone()));
    let cedar_ctrl = Controller::new(
        cedar_policies,
        WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
    )
    .shutdown_on_signal()
    .run(
        cedar_validation_ctrl::reconcile,
        lattice_common::default_error_policy,
        cedar_ctx,
    )
    .for_each(log_reconcile_result("CedarPolicy"));

    let oidc_providers: Api<OIDCProvider> = Api::all(client.clone());
    let oidc_ctx = Arc::new(ControllerContext::new(client.clone()));
    let oidc_ctrl = Controller::new(
        oidc_providers,
        WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
    )
    .shutdown_on_signal()
    .run(
        oidc_provider_ctrl::reconcile,
        lattice_common::default_error_policy,
        oidc_ctx,
    )
    .for_each(log_reconcile_result("OIDCProvider"));

    let backup_policies: Api<LatticeBackupPolicy> = Api::all(client.clone());
    let bp_ctx = Arc::new(ControllerContext::new(client.clone()));
    let backup_ctrl = Controller::new(
        backup_policies,
        WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
    )
    .shutdown_on_signal()
    .run(
        backup_policy_ctrl::reconcile,
        lattice_common::default_error_policy,
        bp_ctx,
    )
    .for_each(log_reconcile_result("BackupPolicy"));

    let restores: Api<LatticeRestore> = Api::all(client.clone());
    let restore_ctx = Arc::new(ControllerContext::new(client));
    let restore_ctrl_future = Controller::new(
        restores,
        WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
    )
    .shutdown_on_signal()
    .run(
        restore_ctrl::reconcile,
        lattice_common::default_error_policy,
        restore_ctx,
    )
    .for_each(log_reconcile_result("Restore"));

    tracing::info!("- CloudProvider controller");
    tracing::info!("- SecretsProvider controller");
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
        Box::pin(restore_ctrl_future),
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
    let clusters: Api<LatticeCluster> = Api::all(client.clone());
    match clusters.list(&kube::api::ListParams::default()).await {
        Ok(list) => list
            .items
            .first()
            .map(|c| c.spec.provider.provider_type())
            .unwrap_or(ProviderType::Docker),
        Err(e) => {
            tracing::warn!(error = %e, "failed to read LatticeCluster, defaulting to Docker");
            ProviderType::Docker
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
