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
    LatticeMeshMember, LatticeRestore, LatticeService, LatticeServicePolicy, MonitoringConfig,
    OIDCProvider, ProviderType, SecretProvider,
};
use lattice_common::{ControllerContext, LATTICE_SYSTEM_NAMESPACE};
use lattice_mesh_member::controller as mesh_member_ctrl;
use lattice_secret_provider::controller as secrets_provider_ctrl;
use lattice_service::compiler::VMServiceScrapePhase;
use lattice_service::controller::{
    error_policy as service_error_policy, reconcile as service_reconcile, reconcile_external,
    DiscoveredCrds, ServiceContext,
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
pub async fn build_service_controllers(
    client: Client,
    cluster_name: String,
    provider_type: ProviderType,
    cedar: Arc<PolicyEngine>,
    crds: Arc<DiscoveredCrds>,
    monitoring: MonitoringConfig,
) -> Vec<Pin<Box<dyn Future<Output = ()> + Send>>> {
    let watcher_config = || WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS);
    let vm_service_scrape_ar = crds.vm_service_scrape.clone();
    let mut service_ctx = ServiceContext::from_client(
        client.clone(),
        cluster_name,
        provider_type,
        cedar,
        crds,
        monitoring,
    );
    service_ctx.extension_phases = vec![Arc::new(VMServiceScrapePhase::new(vm_service_scrape_ar))];

    // Warm the service graph before controllers start so existing services
    // aren't demoted to Compiling on restart due to missing dependency info.
    warmup_graph(&client, &service_ctx.graph).await;

    let service_ctx = Arc::new(service_ctx);

    let services: Api<LatticeService> = Api::all(client.clone());
    let services_for_watch = services.clone();
    let graph_for_dep_watch = service_ctx.graph.clone();
    let graph_for_cedar_watch = service_ctx.graph.clone();
    let graph_for_policy_watch = service_ctx.graph.clone();
    let graph_for_mm_watch = service_ctx.graph.clone();
    let cedar_policies: Api<CedarPolicy> =
        Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let service_policies: Api<LatticeServicePolicy> = Api::all(client.clone());
    let mesh_members_for_svc: Api<LatticeMeshMember> = Api::all(client.clone());

    let svc_ctrl = Controller::new(services, watcher_config())
        .watches(services_for_watch, watcher_config(), move |service| {
            let graph = graph_for_dep_watch.clone();
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
        .watches(cedar_policies, watcher_config(), move |_policy| {
            let refs = all_service_refs(&graph_for_cedar_watch);
            tracing::info!(
                service_count = refs.len(),
                "CedarPolicy changed, re-reconciling all services"
            );
            refs
        })
        .watches(service_policies, watcher_config(), move |policy| {
            let graph = graph_for_policy_watch.clone();
            let policy_name = policy
                .metadata
                .name
                .as_deref()
                .unwrap_or_default()
                .to_string();
            let policy_ns = policy
                .metadata
                .namespace
                .as_deref()
                .unwrap_or_default()
                .to_string();

            graph.put_policy(lattice_common::graph::PolicyNode::from(&policy));

            let refs = all_service_refs(&graph);
            tracing::info!(
                policy = %policy_name,
                namespace = %policy_ns,
                service_count = refs.len(),
                "LatticeServicePolicy changed, re-reconciling services"
            );
            refs
        })
        .watches(mesh_members_for_svc, watcher_config(), move |member| {
            let graph = graph_for_mm_watch.clone();
            let namespace = match member.metadata.namespace.as_deref() {
                Some(ns) => ns,
                None => return vec![],
            };
            let name = member.metadata.name.as_deref().unwrap_or_default();

            // MeshMember changes can affect bilateral agreements with services
            let mut affected: Vec<String> = graph.get_dependencies(namespace, name);
            affected.extend(graph.get_dependents(namespace, name));
            affected.sort();
            affected.dedup();

            tracing::debug!(
                mesh_member = %name,
                namespace = %namespace,
                affected_count = affected.len(),
                "MeshMember changed, re-reconciling affected services"
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
    .run(
        reconcile_external,
        service_error_policy,
        service_ctx.clone(),
    )
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

    // ── MeshMember controller ──
    let mm_crds = Arc::new(mesh_member_ctrl::MeshMemberDiscoveredCrds::discover(&client).await);
    let mm_ctx = Arc::new(mesh_member_ctrl::MeshMemberContext {
        client: client.clone(),
        graph: service_ctx.graph.clone(),
        cluster_name: service_ctx.cluster_name.clone(),
        crds: mm_crds,
    });

    let mesh_members: Api<LatticeMeshMember> = Api::all(client.clone());

    let mm_ctrl = Controller::new(mesh_members, watcher_config())
        .shutdown_on_signal()
        .run(
            mesh_member_ctrl::reconcile,
            mesh_member_ctrl::error_policy,
            mm_ctx,
        )
        .for_each(log_reconcile_result("MeshMember"));

    tracing::info!("- LatticeService controller");
    tracing::info!("- LatticeExternalService controller");
    tracing::info!("- LatticeServicePolicy controller");
    tracing::info!("- LatticeMeshMember controller");

    vec![
        Box::pin(svc_ctrl),
        Box::pin(ext_ctrl),
        Box::pin(policy_ctrl),
        Box::pin(mm_ctrl),
    ]
}

/// Build provider controller futures (CloudProvider, SecretProvider, CedarPolicy, OIDCProvider)
pub fn build_provider_controllers(
    client: Client,
    cedar: Arc<PolicyEngine>,
) -> Vec<Pin<Box<dyn Future<Output = ()> + Send>>> {
    let ctx = Arc::new(ControllerContext::new(client.clone()));
    let cedar_ctx = Arc::new(cedar_validation_ctrl::CedarValidationContext {
        client: client.clone(),
        cedar,
    });
    let watcher_config = || WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS);

    let cloud_ctrl = Controller::new(Api::<CloudProvider>::all(client.clone()), watcher_config())
        .shutdown_on_signal()
        .run(
            cloud_provider_ctrl::reconcile,
            lattice_common::default_error_policy,
            ctx.clone(),
        )
        .for_each(log_reconcile_result("CloudProvider"));

    let secrets_ctrl =
        Controller::new(Api::<SecretProvider>::all(client.clone()), watcher_config())
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
            cedar_ctx,
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

/// Resolve monitoring config from env var (for Service mode, which has no LatticeCluster).
/// Defaults to enabled + HA.
pub fn resolve_monitoring_from_env() -> MonitoringConfig {
    let enabled = std::env::var("LATTICE_MONITORING")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(true);
    let ha = std::env::var("LATTICE_MONITORING_HA")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(true);
    MonitoringConfig { enabled, ha }
}

/// Resolve monitoring config from the first LatticeCluster CRD
pub async fn resolve_monitoring_from_cluster(client: &Client) -> MonitoringConfig {
    match read_first_cluster(client).await {
        Some(cluster) => cluster.spec.monitoring,
        None => MonitoringConfig::default(),
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

/// Pre-populate the ServiceGraph with all existing resources so that
/// reconciliation after an operator restart doesn't demote Ready services
/// to Compiling while waiting for dependency information to trickle in.
async fn warmup_graph(client: &Client, graph: &lattice_common::graph::ServiceGraph) {
    warmup_list::<LatticeService>(client, "LatticeServices", |item| {
        let ns = item.metadata.namespace.as_deref().unwrap_or_default();
        let name = item.metadata.name.as_deref().unwrap_or_default();
        graph.put_service(ns, name, &item.spec);
    })
    .await;

    warmup_list::<LatticeExternalService>(client, "LatticeExternalServices", |item| {
        let ns = item.metadata.namespace.as_deref().unwrap_or_default();
        let name = item.metadata.name.as_deref().unwrap_or_default();
        graph.put_external_service(ns, name, &item.spec);
    })
    .await;

    warmup_list::<LatticeServicePolicy>(client, "LatticeServicePolicies", |item| {
        graph.put_policy(item.into());
    })
    .await;

    warmup_list::<LatticeMeshMember>(client, "LatticeMeshMembers", |item| {
        let ns = item.metadata.namespace.as_deref().unwrap_or_default();
        let name = item.metadata.name.as_deref().unwrap_or_default();
        graph.put_mesh_member(ns, name, &item.spec);
    })
    .await;
}

/// List all resources of type T and insert each into the graph via `insert_fn`.
async fn warmup_list<T>(client: &Client, label: &str, insert_fn: impl Fn(&T))
where
    T: kube::Resource<DynamicType = ()>
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + Send
        + Sync
        + 'static,
{
    let api: Api<T> = Api::all(client.clone());
    match api.list(&kube::api::ListParams::default()).await {
        Ok(list) => {
            for item in &list.items {
                insert_fn(item);
            }
            tracing::info!(
                count = list.items.len(),
                "Warmed ServiceGraph with {}",
                label
            );
        }
        Err(e) => tracing::warn!(error = %e, "Failed to list {} for graph warmup", label),
    }
}

/// Collect ObjectRefs for every service in the graph (used to trigger re-reconciliation of all services).
fn all_service_refs(graph: &lattice_common::graph::ServiceGraph) -> Vec<ObjectRef<LatticeService>> {
    let mut refs = Vec::new();
    for ns in graph.list_namespaces() {
        for svc in graph.list_services(&ns) {
            refs.push(ObjectRef::<LatticeService>::new(&svc.name).within(&ns));
        }
    }
    refs
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
