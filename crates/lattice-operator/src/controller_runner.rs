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
use lattice_backup::backup_store_controller as backup_store_ctrl;
use lattice_backup::cluster_backup_controller as cluster_backup_ctrl;
use lattice_backup::restore_controller as restore_ctrl;
use lattice_backup::service_backup_controller as service_backup_ctrl;
use lattice_capi::installer::CapiInstaller;
use lattice_cedar::PolicyEngine;
use lattice_cell::bootstrap::DefaultManifestGenerator;
use lattice_cell::parent::ParentServers;
use lattice_cloud_provider as cloud_provider_ctrl;
use lattice_cluster::controller::{error_policy, reconcile, Context};
use lattice_common::crd::{
    BackupStore, CedarPolicy, ClusterConfig, InfraProvider, LatticeCluster, LatticeClusterBackup,
    LatticeClusterRoutes, LatticeJob, LatticeMeshMember, LatticeModel, LatticeRestore,
    LatticeService, MonitoringConfig, OIDCProvider, ProviderType, SecretProvider,
};
use lattice_common::{ControllerContext, CrdRegistry, LATTICE_SYSTEM_NAMESPACE};
use lattice_cost::CostProvider;
use lattice_mesh_member::controller as mesh_member_ctrl;
use lattice_mesh_member::remote_secret;
use lattice_secret_provider::controller as secrets_provider_ctrl;
use lattice_service::compiler::VMServiceScrapePhase;
use lattice_service::controller::{reconcile as service_reconcile, ServiceContext};

/// Watcher timeout (seconds) - must be less than client read_timeout (30s)
/// This forces the API server to close the watch before the client times out,
/// preventing "body read timed out" errors on idle watches.
const WATCH_TIMEOUT_SECS: u32 = 25;

/// Build a standard controller future: create a `Controller`, wire shutdown,
/// run with `default_error_policy`, and log every reconciliation result.
///
/// This encapsulates the repeated pattern used by provider/backup controllers
/// that need no extra watches or custom error policies.
fn simple_controller<K, Ctx, ReconcileFut, Err>(
    api: Api<K>,
    reconcile_fn: impl FnMut(Arc<K>, Arc<Ctx>) -> ReconcileFut + Send + 'static,
    ctx: Arc<Ctx>,
    name: &'static str,
) -> Pin<Box<dyn Future<Output = ()> + Send>>
where
    K: kube::Resource<DynamicType = ()>
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + Send
        + Sync
        + 'static,
    Ctx: Send + Sync + 'static,
    ReconcileFut: Future<Output = Result<kube::runtime::controller::Action, Err>> + Send + 'static,
    Err: std::error::Error + lattice_common::Retryable + Send + 'static,
{
    Box::pin(
        Controller::new(api, WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS))
            .shutdown_on_signal()
            .run(reconcile_fn, lattice_common::default_error_policy, ctx)
            .for_each(log_reconcile_result(name)),
    )
}

/// Build cluster controller futures
pub fn build_cluster_controllers(
    client: Client,
    self_cluster_name: Option<String>,
    parent_servers: Option<Arc<ParentServers<DefaultManifestGenerator>>>,
    capi_installer: Arc<dyn CapiInstaller>,
    config: lattice_common::SharedConfig,
) -> Vec<Pin<Box<dyn Future<Output = ()> + Send>>> {
    let mut ctx_builder = Context::builder(client.clone(), config).capi_installer(capi_installer);
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

/// Build service controller futures (LatticeService, LatticeMeshMember)
///
/// Returns the controller futures and the shared ServiceGraph (for use by job controllers).
pub async fn build_service_controllers(
    client: Client,
    cluster: ClusterConfig,
    cedar: Arc<PolicyEngine>,
    registry: Arc<CrdRegistry>,
    metrics_scraper: Arc<crate::metrics::VmMetricsScraper>,
    cost_provider: Option<Arc<dyn CostProvider>>,
) -> (
    Vec<Pin<Box<dyn Future<Output = ()> + Send>>>,
    Arc<lattice_common::graph::ServiceGraph>,
) {
    let watcher_config = || WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS);
    let cedar_for_mm = cedar.clone();

    let svc_kube_client = Arc::new(lattice_service::controller::ServiceKubeClientImpl::new(
        client.clone(),
        registry.clone(),
    ));
    let svc_events = Arc::new(lattice_common::KubeEventPublisher::new(
        client.clone(),
        "lattice-service-controller",
    ));
    // Compute trust domain from the root CA for SPIFFE principal generation.
    // Falls back to "UNSET-TRUST-DOMAIN" if the CA secret doesn't exist yet.
    let trust_domain = lattice_infra::bootstrap::read_trust_domain(&client).await;

    let mut service_ctx = ServiceContext::new(
        svc_kube_client,
        Arc::new(
            lattice_common::graph::ServiceGraph::new(&trust_domain)
                .with_cluster_name(cluster.cluster_name.clone()),
        ),
        cluster,
        cedar.clone(),
        svc_events,
        metrics_scraper,
    );
    service_ctx.extension_phases = vec![Arc::new(VMServiceScrapePhase::new(registry.clone()))];
    service_ctx.cost_provider = cost_provider.clone();

    // Warm the service graph before controllers start so existing services
    // aren't demoted to Compiling on restart due to missing dependency info.
    warmup_graph(&client, &service_ctx.graph).await;

    let service_ctx = Arc::new(service_ctx);

    let services: Api<LatticeService> = Api::all(client.clone());
    let services_for_watch = services.clone();
    let graph_for_dep_watch = service_ctx.graph.clone();
    let graph_for_cedar_watch = service_ctx.graph.clone();
    let graph_for_mm_watch = service_ctx.graph.clone();
    let cedar_policies: Api<CedarPolicy> =
        Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let mesh_members_for_svc: Api<LatticeMeshMember> = Api::all(client.clone());
    let cluster_routes_for_svc: Api<LatticeClusterRoutes> = Api::all(client.clone());
    let graph_for_route_watch = service_ctx.graph.clone();

    let svc_ctrl = Controller::new(services, watcher_config())
        .watches(services_for_watch, watcher_config(), move |service| {
            let graph = graph_for_dep_watch.clone();
            let namespace = match service.metadata.namespace.as_deref() {
                Some(ns) => ns,
                None => return vec![],
            };
            let name = service.metadata.name.as_deref().unwrap_or_default();
            let ns = namespace.to_string();
            affected_neighbors(&graph, namespace, name)
                .into_iter()
                .map(|dep| ObjectRef::<LatticeService>::new(&dep).within(&ns))
                .collect()
        })
        .watches(cedar_policies, watcher_config(), move |_policy| {
            // The cedar validation controller reloads the PolicyEngine (which bumps
            // its own reload_epoch) and then patches the CedarPolicy status. That
            // status patch triggers another watch event, ensuring services
            // re-reconcile after reload is complete.
            let refs = all_service_refs(&graph_for_cedar_watch);
            tracing::info!(
                service_count = refs.len(),
                "CedarPolicy changed, re-reconciling all services"
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
            let ns = namespace.to_string();
            affected_neighbors(&graph, namespace, name)
                .into_iter()
                .map(|dep| ObjectRef::<LatticeService>::new(&dep).within(&ns))
                .collect()
        })
        .watches(cluster_routes_for_svc, watcher_config(), move |routes| {
            let graph = graph_for_route_watch.clone();
            let source_cluster = routes.metadata.name.as_deref().unwrap_or("unknown");
            graph.sync_remote_services(source_cluster, &routes.spec.routes);
            all_service_refs(&graph)
        })
        .shutdown_on_signal()
        .run(
            service_reconcile,
            lattice_common::default_error_policy,
            service_ctx.clone(),
        )
        .for_each(log_reconcile_result("Service"));

    // ── MeshMember controller ──
    let mm_ctx = Arc::new(mesh_member_ctrl::MeshMemberContext {
        client: client.clone(),
        graph: service_ctx.graph.clone(),
        cluster_name: service_ctx.cluster_name.clone(),
        registry,
        cedar: Some(cedar_for_mm),
    });

    let mesh_members: Api<LatticeMeshMember> = Api::all(client.clone());
    let mesh_members_for_mm_watch: Api<LatticeMeshMember> = Api::all(client.clone());
    let graph_for_mm_dep_watch = service_ctx.graph.clone();

    let mm_ctrl = Controller::new(mesh_members, watcher_config())
        .watches(mesh_members_for_mm_watch, watcher_config(), move |member| {
            let graph = graph_for_mm_dep_watch.clone();
            let namespace = match member.metadata.namespace.as_deref() {
                Some(ns) => ns,
                None => return vec![],
            };
            let name = member.metadata.name.as_deref().unwrap_or_default();
            let ns = namespace.to_string();
            let mut affected: Vec<String> = affected_neighbors(&graph, namespace, name);

            // Drain edge diffs to catch neighbors that affected_neighbors misses
            // (e.g., when A removes its outbound dep on B, B is no longer a neighbor)
            if let Some(diffs) = graph.drain_edge_diffs(namespace, name) {
                for (diff_ns, diff_name) in diffs {
                    if diff_ns == ns && !affected.contains(&diff_name) {
                        affected.push(diff_name);
                    }
                }
            }

            let mut refs: Vec<ObjectRef<LatticeMeshMember>> = affected
                .into_iter()
                .filter_map(|dep| {
                    let node = graph.get_service(&ns, &dep)?;
                    node.type_
                        .is_mesh_member()
                        .then(|| ObjectRef::<LatticeMeshMember>::new(&dep).within(&ns))
                })
                .collect();

            // depends_all services have dynamic outbound edges that aren't stored
            // in edges_out, so affected_neighbors() won't find them. Trigger all
            // depends_all services on any LMM change — the graph-hash skip gate
            // in the reconciler prevents unnecessary work.
            for (da_ns, da_name) in graph.depends_all_services() {
                if da_ns == ns && da_name == name {
                    continue;
                }
                refs.push(ObjectRef::<LatticeMeshMember>::new(&da_name).within(&da_ns));
            }

            refs
        })
        .watches(
            Api::<LatticeClusterRoutes>::all(client.clone()),
            watcher_config(),
            {
                let graph = service_ctx.graph.clone();
                move |_routes| all_mesh_member_refs(&graph)
            },
        )
        .shutdown_on_signal()
        .run(
            mesh_member_ctrl::reconcile,
            lattice_common::default_error_policy,
            mm_ctx,
        )
        .for_each(log_reconcile_result("MeshMember"));

    tracing::info!("- LatticeService controller");
    tracing::info!("- LatticeMeshMember controller");

    let graph = service_ctx.graph.clone();

    (vec![Box::pin(svc_ctrl), Box::pin(mm_ctrl)], graph)
}

/// Spawn the remote secret controller for Istio multi-cluster discovery.
///
/// Called after the auth proxy is running, since we need the proxy URL, CA cert,
/// and token. The controller watches `LatticeClusterRoutes` and creates Istio
/// remote secrets so istiod can natively discover services on remote clusters.
pub fn spawn_remote_secret_controller(
    client: Client,
    proxy_base_url: String,
    ca_cert_pem: String,
) -> tokio::task::JoinHandle<()> {
    let ctx = Arc::new(remote_secret::RemoteSecretContext {
        client: client.clone(),
        proxy_base_url,
        ca_cert_pem,
    });

    tracing::info!("- RemoteSecret controller");

    tokio::spawn(async move {
        Controller::new(
            Api::<LatticeClusterRoutes>::all(client),
            WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
        )
        .shutdown_on_signal()
        .run(
            remote_secret::reconcile,
            lattice_common::default_error_policy,
            ctx,
        )
        .for_each(log_reconcile_result("RemoteSecret"))
        .await;

        tracing::error!("RemoteSecret controller exited — multi-cluster discovery will stop");
    })
}

/// Build job controller futures (LatticeJob)
pub async fn build_job_controllers(
    client: Client,
    cluster: ClusterConfig,
    cedar: Arc<PolicyEngine>,
    graph: Arc<lattice_common::graph::ServiceGraph>,
    registry: Arc<CrdRegistry>,
    metrics_scraper: Arc<crate::metrics::VmMetricsScraper>,
    cost_provider: Option<Arc<dyn CostProvider>>,
) -> Vec<Pin<Box<dyn Future<Output = ()> + Send>>> {
    let watcher_config = || WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS);

    let kube_client = Arc::new(lattice_job::controller::JobKubeClientImpl::new(
        client.clone(),
        registry,
    ));
    let events = Arc::new(lattice_common::KubeEventPublisher::new(
        client.clone(),
        "lattice-job-controller",
    ));
    let mut job_ctx = lattice_job::controller::JobContext::new(
        kube_client,
        graph,
        cluster.cluster_name,
        cluster.provider_type,
        cedar,
        events,
        metrics_scraper,
    );
    job_ctx.cost_provider = cost_provider;
    let ctx = Arc::new(job_ctx);

    let jobs: Api<LatticeJob> = Api::all(client);

    let job_ctrl = Controller::new(jobs, watcher_config())
        .shutdown_on_signal()
        .run(
            lattice_job::controller::reconcile,
            lattice_common::default_error_policy,
            ctx,
        )
        .for_each(log_reconcile_result("Job"));

    tracing::info!("- LatticeJob controller");

    vec![Box::pin(job_ctrl)]
}

/// Build model controller futures (LatticeModel)
pub async fn build_model_controllers(
    client: Client,
    cluster: ClusterConfig,
    cedar: Arc<PolicyEngine>,
    graph: Arc<lattice_common::graph::ServiceGraph>,
    registry: Arc<CrdRegistry>,
    metrics_scraper: Arc<crate::metrics::VmMetricsScraper>,
    cost_provider: Option<Arc<dyn CostProvider>>,
) -> Vec<Pin<Box<dyn Future<Output = ()> + Send>>> {
    let watcher_config = || WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS);

    let kube_client = Arc::new(lattice_model::controller::ModelKubeClientImpl::new(
        client.clone(),
        registry,
    ));
    let events = Arc::new(lattice_common::KubeEventPublisher::new(
        client.clone(),
        "lattice-model-controller",
    ));
    let mut model_ctx = lattice_model::controller::ModelContext::new(
        kube_client,
        graph,
        cluster.cluster_name,
        cluster.provider_type,
        cedar,
        events,
        metrics_scraper,
    );
    model_ctx.cost_provider = cost_provider;
    let ctx = Arc::new(model_ctx);

    let models: Api<LatticeModel> = Api::all(client);

    let model_ctrl = Controller::new(models, watcher_config())
        .shutdown_on_signal()
        .run(
            lattice_model::controller::reconcile,
            lattice_common::default_error_policy,
            ctx,
        )
        .for_each(log_reconcile_result("Model"));

    tracing::info!("- LatticeModel controller");

    vec![Box::pin(model_ctrl)]
}

/// Build cluster-slice provider controllers (InfraProvider, SecretProvider, CedarPolicy, OIDCProvider)
///
/// These manage infrastructure-level provider configuration (cloud credentials,
/// secret backends, OIDC endpoints). CRDs are registered in `cluster_crds()`.
pub fn build_cluster_provider_controllers(
    client: Client,
    cedar: Arc<PolicyEngine>,
    config: lattice_common::SharedConfig,
) -> Vec<Pin<Box<dyn Future<Output = ()> + Send>>> {
    let ctx = Arc::new(ControllerContext::new(client.clone(), config));
    let cedar_ctx = Arc::new(cedar_validation_ctrl::CedarValidationContext {
        client: client.clone(),
        cedar,
    });

    tracing::info!("- InfraProvider controller");
    tracing::info!("- SecretProvider controller");
    tracing::info!("- CedarPolicy controller");
    tracing::info!("- OIDCProvider controller");

    vec![
        simple_controller(
            Api::<InfraProvider>::all(client.clone()),
            cloud_provider_ctrl::reconcile,
            ctx.clone(),
            "InfraProvider",
        ),
        simple_controller(
            Api::<SecretProvider>::all(client.clone()),
            secrets_provider_ctrl::reconcile,
            ctx.clone(),
            "SecretProvider",
        ),
        simple_controller(
            Api::<CedarPolicy>::all(client.clone()),
            cedar_validation_ctrl::reconcile,
            cedar_ctx,
            "CedarPolicy",
        ),
        simple_controller(
            Api::<OIDCProvider>::all(client),
            oidc_provider_ctrl::reconcile,
            ctx,
            "OIDCProvider",
        ),
    ]
}

/// Build service-slice provider controllers (BackupStore, ClusterBackup, Restore, ServiceBackup, CedarPolicy)
///
/// These manage application-level backup/restore and Cedar policy validation.
/// CRDs are registered in `service_crds()`.
pub fn build_service_provider_controllers(
    client: Client,
    cedar: Arc<PolicyEngine>,
    config: lattice_common::SharedConfig,
) -> Vec<Pin<Box<dyn Future<Output = ()> + Send>>> {
    let ctx = Arc::new(ControllerContext::new(client.clone(), config));
    let cedar_ctx = Arc::new(cedar_validation_ctrl::CedarValidationContext {
        client: client.clone(),
        cedar,
    });

    tracing::info!("- CedarPolicy controller");
    tracing::info!("- BackupStore controller");
    tracing::info!("- LatticeClusterBackup controller");
    tracing::info!("- LatticeRestore controller");
    tracing::info!("- ServiceBackupSchedule controller");

    vec![
        simple_controller(
            Api::<CedarPolicy>::all(client.clone()),
            cedar_validation_ctrl::reconcile,
            cedar_ctx,
            "CedarPolicy",
        ),
        simple_controller(
            Api::<BackupStore>::all(client.clone()),
            backup_store_ctrl::reconcile,
            ctx.clone(),
            "BackupStore",
        ),
        simple_controller(
            Api::<LatticeClusterBackup>::all(client.clone()),
            cluster_backup_ctrl::reconcile,
            ctx.clone(),
            "ClusterBackup",
        ),
        simple_controller(
            Api::<LatticeRestore>::all(client.clone()),
            restore_ctrl::reconcile,
            ctx.clone(),
            "Restore",
        ),
        simple_controller(
            Api::<LatticeService>::all(client),
            service_backup_ctrl::reconcile,
            ctx,
            "ServiceBackup",
        ),
    ]
}

/// Build ALL provider controllers (union of cluster + service slices, CedarPolicy deduplicated)
///
/// Used by `run_all_slices()` to avoid running the CedarPolicy controller twice.
pub fn build_all_provider_controllers(
    client: Client,
    cedar: Arc<PolicyEngine>,
    config: lattice_common::SharedConfig,
) -> Vec<Pin<Box<dyn Future<Output = ()> + Send>>> {
    let ctx = Arc::new(ControllerContext::new(client.clone(), config));
    let cedar_ctx = Arc::new(cedar_validation_ctrl::CedarValidationContext {
        client: client.clone(),
        cedar,
    });

    tracing::info!("- InfraProvider controller");
    tracing::info!("- SecretProvider controller");
    tracing::info!("- CedarPolicy controller");
    tracing::info!("- OIDCProvider controller");
    tracing::info!("- BackupStore controller");
    tracing::info!("- LatticeClusterBackup controller");
    tracing::info!("- LatticeRestore controller");
    tracing::info!("- ServiceBackupSchedule controller");

    vec![
        simple_controller(
            Api::<InfraProvider>::all(client.clone()),
            cloud_provider_ctrl::reconcile,
            ctx.clone(),
            "InfraProvider",
        ),
        simple_controller(
            Api::<SecretProvider>::all(client.clone()),
            secrets_provider_ctrl::reconcile,
            ctx.clone(),
            "SecretProvider",
        ),
        simple_controller(
            Api::<CedarPolicy>::all(client.clone()),
            cedar_validation_ctrl::reconcile,
            cedar_ctx,
            "CedarPolicy",
        ),
        simple_controller(
            Api::<OIDCProvider>::all(client.clone()),
            oidc_provider_ctrl::reconcile,
            ctx.clone(),
            "OIDCProvider",
        ),
        simple_controller(
            Api::<BackupStore>::all(client.clone()),
            backup_store_ctrl::reconcile,
            ctx.clone(),
            "BackupStore",
        ),
        simple_controller(
            Api::<LatticeClusterBackup>::all(client.clone()),
            cluster_backup_ctrl::reconcile,
            ctx.clone(),
            "ClusterBackup",
        ),
        simple_controller(
            Api::<LatticeRestore>::all(client.clone()),
            restore_ctrl::reconcile,
            ctx.clone(),
            "Restore",
        ),
        simple_controller(
            Api::<LatticeService>::all(client),
            service_backup_ctrl::reconcile,
            ctx,
            "ServiceBackup",
        ),
    ]
}

/// Resolve provider type from the first LatticeCluster CRD
pub async fn resolve_provider_type_from_cluster(client: &Client) -> ProviderType {
    match read_first_cluster(client).await {
        Some(cluster) => cluster.spec.provider.provider_type(),
        None => ProviderType::Docker,
    }
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

/// Compute the set of affected neighbor names when a service or mesh member changes.
///
/// Returns deduplicated names of all dependencies and dependents (excluding `self_name`).
fn affected_neighbors(
    graph: &lattice_common::graph::ServiceGraph,
    namespace: &str,
    self_name: &str,
) -> Vec<String> {
    let mut affected: Vec<String> = graph.get_dependencies(namespace, self_name);
    affected.extend(graph.get_dependents(namespace, self_name));
    affected.sort();
    affected.dedup();
    affected.retain(|n| n != self_name);
    affected
}

/// Extract namespace and name from K8s metadata, logging a warning and returning
/// None if either is missing (which would indicate a broken API server response).
fn resource_identity(meta: &kube::api::ObjectMeta, kind: &str) -> Option<(String, String)> {
    let ns = meta.namespace.as_deref();
    let name = meta.name.as_deref();
    match (ns, name) {
        (Some(ns), Some(name)) => Some((ns.to_string(), name.to_string())),
        _ => {
            tracing::warn!(
                kind,
                namespace = ?ns,
                name = ?name,
                "Skipping resource with missing metadata"
            );
            None
        }
    }
}

/// Pre-populate the ServiceGraph with all existing resources so that
/// reconciliation after an operator restart doesn't demote Ready services
/// to Compiling while waiting for dependency information to trickle in.
async fn warmup_graph(client: &Client, graph: &lattice_common::graph::ServiceGraph) {
    warmup_list::<LatticeService>(client, "LatticeServices", |item| {
        if let Some((ns, name)) = resource_identity(&item.metadata, "LatticeService") {
            graph.put_service(&ns, &name, &item.spec);
        }
    })
    .await;

    warmup_list::<LatticeMeshMember>(client, "LatticeMeshMembers", |item| {
        if let Some((ns, name)) = resource_identity(&item.metadata, "LatticeMeshMember") {
            graph.put_mesh_member(&ns, &name, &item.spec);
        }
    })
    .await;

    warmup_list::<LatticeJob>(client, "LatticeJobs", |item| {
        if let Some((ns, job_name)) = resource_identity(&item.metadata, "LatticeJob") {
            for (task_name, task_spec) in &item.spec.tasks {
                let task_full_name = format!("{}-{}", job_name, task_name);
                graph.put_workload(&ns, &task_full_name, &task_spec.workload, &[]);
            }
        }
    })
    .await;

    warmup_list::<LatticeModel>(client, "LatticeModels", |item| {
        if let Some((ns, model_name)) = resource_identity(&item.metadata, "LatticeModel") {
            let has_autoscaling = item.spec.roles.values().any(|r| r.autoscaling.is_some());
            let callers =
                lattice_model::compiler::model_callers(item.spec.routing.as_ref(), has_autoscaling);
            for (role_name, role_spec) in &item.spec.roles {
                let role_full_name = format!("{}-{}", model_name, role_name);
                graph.put_workload(&ns, &role_full_name, &role_spec.entry_workload, &callers);
            }
        }
    })
    .await;

    // Warm remote services from LatticeClusterRoutes (cross-cluster dependencies)
    warmup_list::<LatticeClusterRoutes>(client, "LatticeClusterRoutes", |item| {
        let source_cluster = item.metadata.name.as_deref().unwrap_or("unknown");
        for route in &item.spec.routes {
            graph.put_remote_service(source_cluster, route);
        }
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

/// Interval between graph audit cycles.
const GRAPH_AUDIT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

/// Spawn a background task that periodically removes orphaned graph nodes.
///
/// An orphan is a non-Unknown node in the graph whose backing CRD no longer
/// exists on the API server. This catches missed delete events that the
/// event-driven controllers can't self-heal from.
pub fn spawn_graph_auditor(
    client: Client,
    graph: Arc<lattice_common::graph::ServiceGraph>,
    token: tokio_util::sync::CancellationToken,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(GRAPH_AUDIT_INTERVAL);
        // First tick fires immediately — skip it so we don't audit right after warmup.
        interval.tick().await;

        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = interval.tick() => {
                    if let Err(e) = audit_graph_orphans(&client, &graph).await {
                        tracing::warn!(error = %e, "graph audit failed");
                    }
                }
            }
        }
        tracing::info!("graph auditor stopped");
    });
}

/// Compare the graph against the API server and fix divergence in both
/// directions: remove orphaned nodes and re-add missing ones.
async fn audit_graph_orphans(
    client: &Client,
    graph: &lattice_common::graph::ServiceGraph,
) -> Result<(), kube::Error> {
    let services = Api::<LatticeService>::all(client.clone())
        .list(&kube::api::ListParams::default())
        .await?;
    let mesh_members = Api::<LatticeMeshMember>::all(client.clone())
        .list(&kube::api::ListParams::default())
        .await?;
    let jobs = Api::<LatticeJob>::all(client.clone())
        .list(&kube::api::ListParams::default())
        .await?;
    let models = Api::<LatticeModel>::all(client.clone())
        .list(&kube::api::ListParams::default())
        .await?;

    // Build set of all CRD-backed names per namespace
    let mut crd_names: std::collections::HashMap<String, std::collections::HashSet<String>> =
        std::collections::HashMap::new();

    for svc in &services.items {
        if let Some((ns, name)) = resource_identity(&svc.metadata, "LatticeService") {
            crd_names.entry(ns).or_default().insert(name);
        }
    }
    for mm in &mesh_members.items {
        if let Some((ns, name)) = resource_identity(&mm.metadata, "LatticeMeshMember") {
            crd_names.entry(ns).or_default().insert(name);
        }
    }
    for job in &jobs.items {
        if let Some((ns, job_name)) = resource_identity(&job.metadata, "LatticeJob") {
            for task_name in job.spec.tasks.keys() {
                crd_names
                    .entry(ns.clone())
                    .or_default()
                    .insert(format!("{}-{}", job_name, task_name));
            }
        }
    }
    for model in &models.items {
        if let Some((ns, model_name)) = resource_identity(&model.metadata, "LatticeModel") {
            for role_name in model.spec.roles.keys() {
                crd_names
                    .entry(ns.clone())
                    .or_default()
                    .insert(format!("{}-{}", model_name, role_name));
            }
        }
    }

    // Remove orphaned graph nodes (exist in graph, no backing CRD)
    let mut removed = 0u64;
    for ns in graph.list_namespaces() {
        let known = crd_names.get(&ns);
        for name in graph.all_names_in_namespace(&ns) {
            if let Some(node) = graph.get_service(&ns, &name) {
                if node.type_.is_unknown() {
                    continue;
                }
            }
            let is_orphan = match known {
                Some(set) => !set.contains(&name),
                None => true,
            };
            if is_orphan {
                tracing::info!(namespace = %ns, name = %name, "removing orphaned graph node");
                graph.delete_service(&ns, &name);
                removed += 1;
            }
        }
    }

    // Re-add missing nodes (exist as CRD, missing from graph)
    let mut added = 0u64;
    for svc in &services.items {
        if let Some((ns, name)) = resource_identity(&svc.metadata, "LatticeService") {
            if graph.get_service(&ns, &name).is_none() {
                graph.put_service(&ns, &name, &svc.spec);
                added += 1;
            }
        }
    }
    for mm in &mesh_members.items {
        if let Some((ns, name)) = resource_identity(&mm.metadata, "LatticeMeshMember") {
            if graph.get_service(&ns, &name).is_none() {
                graph.put_mesh_member(&ns, &name, &mm.spec);
                added += 1;
            }
        }
    }
    for job in &jobs.items {
        if let Some((ns, job_name)) = resource_identity(&job.metadata, "LatticeJob") {
            for (task_name, task_spec) in &job.spec.tasks {
                let full_name = format!("{}-{}", job_name, task_name);
                if graph.get_service(&ns, &full_name).is_none() {
                    graph.put_workload(&ns, &full_name, &task_spec.workload, &[]);
                    added += 1;
                }
            }
        }
    }
    for model in &models.items {
        if let Some((ns, model_name)) = resource_identity(&model.metadata, "LatticeModel") {
            let has_autoscaling = model.spec.roles.values().any(|r| r.autoscaling.is_some());
            let callers = lattice_model::compiler::model_callers(
                model.spec.routing.as_ref(),
                has_autoscaling,
            );
            for (role_name, role_spec) in &model.spec.roles {
                let full_name = format!("{}-{}", model_name, role_name);
                if graph.get_service(&ns, &full_name).is_none() {
                    graph.put_workload(&ns, &full_name, &role_spec.entry_workload, &callers);
                    added += 1;
                }
            }
        }
    }

    if removed > 0 || added > 0 {
        tracing::info!(removed, added, "graph audit complete");
    }
    Ok(())
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

fn all_mesh_member_refs(
    graph: &lattice_common::graph::ServiceGraph,
) -> Vec<ObjectRef<LatticeMeshMember>> {
    let mut refs = Vec::new();
    for ns in graph.list_namespaces() {
        for svc in graph.list_services(&ns) {
            if svc.type_.is_mesh_member() || svc.type_.is_local() {
                refs.push(ObjectRef::<LatticeMeshMember>::new(&svc.name).within(&ns));
            }
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
