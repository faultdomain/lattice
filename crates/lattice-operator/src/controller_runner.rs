//! Controller runner - starts and manages all Kubernetes controllers
//!
//! This module handles the creation and running of all controllers.

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
    parent_servers: Arc<ParentServers<DefaultManifestGenerator>>,
) {
    let run_cluster = matches!(mode, ControllerMode::All | ControllerMode::Cluster);
    let run_service = matches!(mode, ControllerMode::All | ControllerMode::Service);

    // Build cluster controller context
    let mut ctx_builder = Context::builder(client.clone()).parent_servers(parent_servers);
    if let Some(ref name) = self_cluster_name {
        tracing::info!(cluster = %name, "Running as self-managed cluster");
        ctx_builder = ctx_builder.self_cluster_name(name.clone());
    }
    let ctx = Arc::new(ctx_builder.build());

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

    // Build service controller context
    let cluster_name_for_service = self_cluster_name.unwrap_or_else(|| "default".to_string());
    let service_ctx = Arc::new(ServiceContext::from_client(
        client.clone(),
        cluster_name_for_service,
        provider_type,
    ));

    log_enabled_controllers(run_cluster, run_service);

    // Create controller futures
    let cluster_controller = create_cluster_controller(run_cluster, clusters, ctx);
    let (service_controller, external_controller) =
        create_service_controllers(run_service, client.clone(), service_ctx);
    let cloud_provider_controller = create_cloud_provider_controller(client.clone());
    let secrets_provider_controller = create_secrets_provider_controller(client);

    // Run all controllers until one exits
    tokio::select! {
        _ = cloud_provider_controller => tracing::info!("CloudProvider controller completed"),
        _ = secrets_provider_controller => tracing::info!("SecretsProvider controller completed"),
        _ = async {
            if let Some(ctrl) = cluster_controller { ctrl.await; }
            else { std::future::pending::<()>().await; }
        } => tracing::info!("Cluster controller completed"),
        _ = async {
            if let Some(ctrl) = service_controller { ctrl.await; }
            else { std::future::pending::<()>().await; }
        } => tracing::info!("Service controller completed"),
        _ = async {
            if let Some(ctrl) = external_controller { ctrl.await; }
            else { std::future::pending::<()>().await; }
        } => tracing::info!("External service controller completed"),
    }
}

fn log_enabled_controllers(run_cluster: bool, run_service: bool) {
    tracing::info!("Starting Lattice controllers...");
    if run_cluster {
        tracing::info!("- LatticeCluster controller");
    }
    if run_service {
        tracing::info!("- LatticeService controller");
        tracing::info!("- LatticeExternalService controller");
    }
    tracing::info!("- CloudProvider controller");
    tracing::info!("- SecretsProvider controller");
}

fn create_cluster_controller(
    enabled: bool,
    clusters: Api<LatticeCluster>,
    ctx: Arc<Context>,
) -> Option<impl std::future::Future<Output = ()>> {
    if !enabled {
        return None;
    }

    Some(
        Controller::new(clusters, WatcherConfig::default())
            .shutdown_on_signal()
            .run(reconcile, error_policy, ctx)
            .for_each(|result| async move {
                match result {
                    Ok(action) => tracing::debug!(?action, "Cluster reconciliation completed"),
                    Err(e) => tracing::error!(error = ?e, "Cluster reconciliation error"),
                }
            }),
    )
}

fn create_service_controllers(
    enabled: bool,
    client: Client,
    ctx: Arc<ServiceContext>,
) -> (
    Option<impl std::future::Future<Output = ()>>,
    Option<impl std::future::Future<Output = ()>>,
) {
    if !enabled {
        return (None, None);
    }

    let services: Api<LatticeService> = Api::all(client.clone());
    let external_services: Api<LatticeExternalService> = Api::all(client);

    let graph_for_watch = ctx.graph.clone();
    let services_for_watch = services.clone();

    let svc_ctrl = Controller::new(services, WatcherConfig::default())
        .watches(
            services_for_watch,
            WatcherConfig::default(),
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
        .for_each(|result| async move {
            match result {
                Ok(action) => tracing::debug!(?action, "Service reconciliation completed"),
                Err(e) => tracing::error!(error = ?e, "Service reconciliation error"),
            }
        });

    let ext_ctrl = Controller::new(external_services, WatcherConfig::default())
        .shutdown_on_signal()
        .run(reconcile_external, error_policy_external, ctx)
        .for_each(|result| async move {
            match result {
                Ok(action) => tracing::debug!(?action, "External service reconciliation completed"),
                Err(e) => tracing::error!(error = ?e, "External service reconciliation error"),
            }
        });

    (Some(svc_ctrl), Some(ext_ctrl))
}

fn create_cloud_provider_controller(client: Client) -> impl std::future::Future<Output = ()> {
    let cloud_providers: Api<CloudProvider> = Api::all(client.clone());
    let ctx = Arc::new(ControllerContext::new(client));

    Controller::new(cloud_providers, WatcherConfig::default())
        .shutdown_on_signal()
        .run(
            cloud_provider_ctrl::reconcile,
            cloud_provider_ctrl::default_error_policy,
            ctx,
        )
        .for_each(|result| async move {
            match result {
                Ok(action) => tracing::debug!(?action, "CloudProvider reconciliation completed"),
                Err(e) => tracing::error!(error = ?e, "CloudProvider reconciliation error"),
            }
        })
}

fn create_secrets_provider_controller(client: Client) -> impl std::future::Future<Output = ()> {
    let secrets_providers: Api<SecretsProvider> = Api::all(client.clone());
    let ctx = Arc::new(ControllerContext::new(client));

    Controller::new(secrets_providers, WatcherConfig::default())
        .shutdown_on_signal()
        .run(
            secrets_provider_ctrl::reconcile,
            secrets_provider_ctrl::default_error_policy,
            ctx,
        )
        .for_each(|result| async move {
            match result {
                Ok(action) => tracing::debug!(?action, "SecretsProvider reconciliation completed"),
                Err(e) => tracing::error!(error = ?e, "SecretsProvider reconciliation error"),
            }
        })
}
