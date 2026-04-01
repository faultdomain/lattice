//! Controller runner - leader-elected controllers
//!
//! Each controller runs behind its own Kubernetes Lease via `leader_controller`.
//! The wrapper handles election, re-acquisition on leadership loss, and clean shutdown.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use futures::StreamExt;
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher::{self, Config as WatcherConfig};
use kube::runtime::{predicates, reflector, Controller, WatchStreamExt};
use kube::{Api, Client};
use tokio_util::sync::CancellationToken;

use lattice_capi::installer::CapiInstaller;
use lattice_cedar::PolicyEngine;
use lattice_cell::bootstrap::DefaultManifestGenerator;
use lattice_cell::parent::ParentServers;
use lattice_cluster::controller::{error_policy, reconcile, Context};
use lattice_common::crd::{
    CedarPolicy, ClusterConfig, LatticeCluster, LatticeClusterRoutes, LatticeJob,
    LatticeMeshMember, LatticeModel, LatticeService, MonitoringConfig, ProviderType,
};
use lattice_common::graph::ServiceGraph;
use lattice_common::{CrdRegistry, LeaderElector, LATTICE_SYSTEM_NAMESPACE};
use lattice_cost::CostProvider;
use lattice_mesh_member::controller as mesh_member_ctrl;
use lattice_mesh_member::remote_secret;
use lattice_service::compiler::VMServiceScrapePhase;
use lattice_service::controller::{reconcile as service_reconcile, ServiceContext};

/// Watcher timeout (seconds) - must be less than client read_timeout (30s)
/// This forces the API server to close the watch before the client times out,
/// preventing "body read timed out" errors on idle watches.
const WATCH_TIMEOUT_SECS: u32 = 25;

// ---------------------------------------------------------------------------
// Leader election wrapper
// ---------------------------------------------------------------------------

/// Run a controller behind its own Kubernetes Lease.
///
/// Acquires a per-controller lease (`lattice-ctrl-{name}`), calls `factory` to
/// build a fresh controller, and runs it. On leadership loss the controller
/// future is dropped (tearing down watches) and the lease is re-acquired.
///
/// If `claim_traffic` is true, the pod is labelled on acquisition so the
/// Kubernetes Service routes gRPC/auth-proxy traffic to this pod. The label
/// is removed on graceful shutdown.
pub async fn leader_controller<F>(
    client: Client,
    pod_name: String,
    name: &'static str,
    cancel: CancellationToken,
    claim_traffic: bool,
    factory: F,
) where
    F: Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static,
{
    let lease_name = format!("lattice-ctrl-{}", name);

    loop {
        let elector = Arc::new(LeaderElector::new(
            client.clone(),
            &lease_name,
            LATTICE_SYSTEM_NAMESPACE,
            &pod_name,
        ));

        let mut guard = tokio::select! {
            _ = cancel.cancelled() => return,
            result = elector.acquire() => match result {
                Ok(g) => g,
                Err(e) => {
                    tracing::error!(controller = name, error = %e, "lease acquisition failed");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            },
        };

        if claim_traffic {
            if let Err(e) = guard.claim_traffic(&pod_name).await {
                tracing::error!(controller = name, error = %e, "failed to claim traffic");
            }
        }

        tracing::info!(controller = name, "leadership acquired, starting controller");
        let controller = factory();

        tokio::select! {
            _ = cancel.cancelled() => {
                if claim_traffic {
                    let _ = guard.release_traffic().await;
                }
                let _ = guard.release_leadership().await;
                return;
            }
            _ = guard.lost() => {
                if claim_traffic {
                    let _ = guard.release_traffic().await;
                }
                tracing::warn!(controller = name, "leadership lost, will re-acquire");
            }
            _ = controller => {
                if claim_traffic {
                    let _ = guard.release_traffic().await;
                }
                tracing::error!(controller = name, "controller exited unexpectedly, restarting");
            }
        }
    }
}

/// Shared context for spawning leader-elected controllers.
///
/// Avoids passing `client`, `pod_name`, `cancel`, `config` repeatedly.
#[derive(Clone)]
pub struct SpawnContext {
    pub client: Client,
    pub pod_name: String,
    pub cancel: CancellationToken,
    pub config: lattice_common::SharedConfig,
    pub cedar: Arc<PolicyEngine>,
    pub graph_holder: Arc<OnceLock<Arc<ServiceGraph>>>,
}

impl SpawnContext {
    /// Spawn a simple provider controller with its own lease and CRD readiness wait.
    pub fn spawn_provider<K, ReconcileFut, Err>(
        &self,
        lease: &'static str,
        reconcile_fn: fn(Arc<K>, Arc<lattice_common::ControllerContext>) -> ReconcileFut,
        label: &'static str,
    ) -> tokio::task::JoinHandle<()>
    where
        K: kube::Resource<DynamicType = ()>
            + Clone
            + std::fmt::Debug
            + serde::de::DeserializeOwned
            + Send
            + Sync
            + 'static,
        ReconcileFut:
            Future<Output = Result<kube::runtime::controller::Action, Err>> + Send + 'static,
        Err: std::error::Error + lattice_common::Retryable + Send + 'static,
    {
        let client = self.client.clone();
        let config = self.config.clone();
        tokio::spawn(leader_controller(
            self.client.clone(),
            self.pod_name.clone(),
            lease,
            self.cancel.clone(),
            false,
            move || {
                let client = client.clone();
                let config = config.clone();
                Box::pin(async move {
                    lattice_operator::startup::wait_for_api_ready_for::<K>(&client).await;
                    let ctx = Arc::new(lattice_common::ControllerContext::new(
                        client.clone(),
                        config,
                    ));
                    simple_controller(Api::<K>::all(client), reconcile_fn, ctx, label).await;
                }) as Pin<Box<dyn Future<Output = ()> + Send>>
            },
        ))
    }

    /// Spawn a workload controller (Service, Job, or Model) with its own lease.
    ///
    /// Resolves shared workload params (graph, cluster config, registry, etc.)
    /// before building the controller.
    pub fn spawn_workload<K, F>(&self, lease: &'static str, build: F) -> tokio::task::JoinHandle<()>
    where
        K: kube::Resource<DynamicType = ()>
            + Clone
            + std::fmt::Debug
            + serde::de::DeserializeOwned
            + Send
            + Sync
            + 'static,
        F: Fn(WorkloadControllerParams) -> Pin<Box<dyn Future<Output = ()> + Send>>
            + Send
            + Sync
            + Clone
            + 'static,
    {
        let client = self.client.clone();
        let config = self.config.clone();
        let cedar = self.cedar.clone();
        let graph_holder = self.graph_holder.clone();
        tokio::spawn(leader_controller(
            self.client.clone(),
            self.pod_name.clone(),
            lease,
            self.cancel.clone(),
            false,
            move || {
                let client = client.clone();
                let config = config.clone();
                let cedar = cedar.clone();
                let graph_holder = graph_holder.clone();
                let build = build.clone();
                Box::pin(async move {
                    lattice_operator::startup::wait_for_api_ready_for::<K>(&client).await;
                    let params = resolve_workload_params(
                        &client,
                        &config,
                        &cedar,
                        &graph_holder,
                    )
                    .await;
                    build(params).await;
                }) as Pin<Box<dyn Future<Output = ()> + Send>>
            },
        ))
    }
}

/// Resolve WorkloadControllerParams from shared state.
async fn resolve_workload_params(
    client: &Client,
    config: &lattice_common::SharedConfig,
    cedar: &Arc<PolicyEngine>,
    graph_holder: &OnceLock<Arc<ServiceGraph>>,
) -> WorkloadControllerParams {
    let cluster = resolve_cluster_config(client, config)
        .await
        .expect("cluster config required");
    let graph = ensure_graph(client, graph_holder, &cluster.cluster_name).await;
    let registry = Arc::new(CrdRegistry::new(client.clone()).await);
    let cost_provider: Option<Arc<dyn lattice_cost::CostProvider>> = Some(Arc::new(
        lattice_cost::ConfigMapCostProvider::new(client.clone()),
    ));
    let metrics_scraper = Arc::new(
        crate::metrics::VmMetricsScraper::new(cluster.monitoring.ha).expect("metrics scraper"),
    );
    // Build per-controller resource cache with the types needed during compilation.
    // Each controller gets its own watch connections — no cross-pod state sharing.
    let cache = lattice_cache::ResourceCache::builder()
        .watch(kube::Api::<lattice_common::crd::LatticeQuota>::namespaced(
            client.clone(),
            lattice_common::LATTICE_SYSTEM_NAMESPACE,
        ))
        .watch(kube::Api::<k8s_openapi::api::core::v1::Namespace>::all(
            client.clone(),
        ))
        .build();

    WorkloadControllerParams {
        client: client.clone(),
        cluster,
        cedar: cedar.clone(),
        graph,
        registry,
        metrics_scraper,
        cost_provider,
        cache,
    }
}

// ---------------------------------------------------------------------------
// Shared state helpers
// ---------------------------------------------------------------------------

/// Ensure the ServiceGraph exists, creating and warming it if needed.
///
/// Uses `OnceLock` so the first caller creates the graph and subsequent
/// callers on the same pod reuse it. Retries trust domain discovery until
/// the root CA is available.
pub async fn ensure_graph(
    client: &Client,
    graph_holder: &OnceLock<Arc<ServiceGraph>>,
    cluster_name: &str,
) -> Arc<ServiceGraph> {
    if let Some(g) = graph_holder.get() {
        return g.clone();
    }

    loop {
        match lattice_infra::bootstrap::read_trust_domain(client).await {
            Some(td) => {
                let graph =
                    Arc::new(ServiceGraph::new(&td).with_cluster_name(cluster_name.to_string()));
                warmup_graph(client, &graph).await;
                let _ = graph_holder.set(graph);
                // Safe: we just set it above, or another caller set it first
                return graph_holder.get().expect("graph was just set").clone();
            }
            None => {
                tracing::info!("Trust domain not available yet, retrying in 5s...");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

/// Resolve ClusterConfig from the LatticeCluster CRD (with fallback).
pub async fn resolve_cluster_config(
    client: &Client,
    config: &lattice_common::SharedConfig,
) -> anyhow::Result<ClusterConfig> {
    let cluster_name = config
        .cluster_name_required()
        .map_err(|e| anyhow::anyhow!(e))?
        .to_string();
    Ok(ClusterConfig {
        cluster_name,
        provider_type: resolve_provider_type_from_cluster(client).await,
        monitoring: resolve_monitoring_from_cluster(client).await,
    })
}

/// Shared parameters for workload controllers (Service, Job, Model).
///
/// These controllers all need the same set of dependencies. Bundling them
/// avoids 8-argument function signatures and duplicated setup in factories.
pub struct WorkloadControllerParams {
    pub client: Client,
    pub cluster: ClusterConfig,
    pub cedar: Arc<PolicyEngine>,
    pub graph: Arc<ServiceGraph>,
    pub registry: Arc<CrdRegistry>,
    pub metrics_scraper: Arc<crate::metrics::VmMetricsScraper>,
    pub cost_provider: Option<Arc<dyn CostProvider>>,
    pub cache: lattice_cache::ResourceCache,
}

// ---------------------------------------------------------------------------
// Controller builder: simple_controller
// ---------------------------------------------------------------------------

/// Build a standard controller future: create a `Controller`, wire shutdown,
/// run with `default_error_policy`, and log every reconciliation result.
///
/// This encapsulates the repeated pattern used by provider/backup controllers
/// that need no extra watches or custom error policies.
pub fn simple_controller<K, Ctx, ReconcileFut, Err>(
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

// ---------------------------------------------------------------------------
// Individual controller builders
// ---------------------------------------------------------------------------

/// Build the LatticeCluster controller future.
pub fn build_cluster_controller(
    client: Client,
    self_cluster_name: Option<String>,
    parent_servers: Option<Arc<ParentServers<DefaultManifestGenerator>>>,
    capi_installer: Arc<dyn CapiInstaller>,
    config: lattice_common::SharedConfig,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
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

    Box::pin(
        Controller::new(
            clusters,
            WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS),
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(log_reconcile_result("Cluster")),
    )
}

/// Build the LatticeService controller future.
///
/// Requires a warmed ServiceGraph (call `ensure_graph` first).
pub fn build_service_controller(
    params: WorkloadControllerParams,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    let WorkloadControllerParams {
        client,
        cluster,
        cedar,
        graph,
        registry,
        metrics_scraper,
        cost_provider,
        cache,
    } = params;
    let watcher_config = || WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS);

    let svc_kube_client = Arc::new(lattice_service::controller::ServiceKubeClientImpl::new(
        client.clone(),
        registry.clone(),
    ));
    let svc_events = Arc::new(lattice_common::KubeEventPublisher::new(
        client.clone(),
        "lattice-service-controller",
    ));

    let mut service_ctx = ServiceContext::new(
        svc_kube_client,
        graph.clone(),
        cluster,
        cedar,
        svc_events,
        metrics_scraper,
    );
    service_ctx.extension_phases = vec![Arc::new(VMServiceScrapePhase::new(registry))];
    service_ctx.cost_provider = cost_provider;
    service_ctx.cache = cache;

    let service_ctx = Arc::new(service_ctx);

    let services: Api<LatticeService> = Api::all(client.clone());
    let services_for_watch = services.clone();
    let graph_for_dep_watch = graph.clone();
    let graph_for_cedar_watch = graph.clone();
    let graph_for_mm_watch = graph.clone();
    let graph_for_route_watch = graph;
    let cedar_policies: Api<CedarPolicy> =
        Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let mesh_members_for_svc: Api<LatticeMeshMember> = Api::all(client.clone());
    let cluster_routes_for_svc: Api<LatticeClusterRoutes> = Api::all(client.clone());

    let (reader, writer) = reflector::store();
    let svc_stream = reflector(writer, watcher::watcher(services, watcher_config()))
        .default_backoff()
        .applied_objects()
        .predicate_filter(predicates::generation, Default::default());

    let svc_ctrl = Controller::for_stream(svc_stream, reader)
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
            service_ctx,
        )
        .for_each(log_reconcile_result("Service"));

    tracing::info!("- LatticeService controller");

    Box::pin(svc_ctrl)
}

/// Build the LatticeMeshMember controller future.
///
/// Requires a warmed ServiceGraph (call `ensure_graph` first).
pub fn build_mesh_member_controller(
    client: Client,
    graph: Arc<ServiceGraph>,
    cluster_name: String,
    cedar: Arc<PolicyEngine>,
    registry: Arc<CrdRegistry>,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    let watcher_config = || WatcherConfig::default().timeout(WATCH_TIMEOUT_SECS);

    let mm_ctx = Arc::new(mesh_member_ctrl::MeshMemberContext {
        client: client.clone(),
        graph: graph.clone(),
        cluster_name,
        registry,
        cedar: Some(cedar),
    });

    let mesh_members: Api<LatticeMeshMember> = Api::all(client.clone());
    let mesh_members_for_mm_watch: Api<LatticeMeshMember> = Api::all(client.clone());
    let graph_for_mm_dep_watch = graph.clone();

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
            Api::<LatticeClusterRoutes>::all(client),
            watcher_config(),
            {
                let graph = graph.clone();
                move |routes| {
                    // Sync remote services to graph BEFORE triggering re-reconcile.
                    // Without this, MeshMember reconcile runs with stale graph state
                    // and generates CNPs missing cross-cluster HBONE egress rules.
                    let source_cluster = routes.metadata.name.as_deref().unwrap_or("unknown");
                    graph.sync_remote_services(source_cluster, &routes.spec.routes);
                    all_mesh_member_refs(&graph)
                }
            },
        )
        .shutdown_on_signal()
        .run(
            mesh_member_ctrl::reconcile,
            lattice_common::default_error_policy,
            mm_ctx,
        )
        .for_each(log_reconcile_result("MeshMember"));

    tracing::info!("- LatticeMeshMember controller");

    Box::pin(mm_ctrl)
}

/// Spawn the remote secret controller for Istio multi-cluster discovery.
///
/// Watches `LatticeClusterRoutes` and creates Istio remote secrets so istiod
/// can discover services on remote clusters. Local children use direct API
/// server kubeconfigs; peer clusters use the parent's auth proxy.
pub fn spawn_remote_secret_controller(client: Client) -> tokio::task::JoinHandle<()> {
    let ctx = Arc::new(remote_secret::RemoteSecretContext {
        client: client.clone(),
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

/// Build the LatticeJob controller future.
pub fn build_job_controller(
    params: WorkloadControllerParams,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    let WorkloadControllerParams {
        client,
        cluster,
        cedar,
        graph,
        registry,
        metrics_scraper,
        cost_provider,
        cache,
    } = params;
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
    job_ctx.cache = cache;
    let ctx = Arc::new(job_ctx);

    let jobs: Api<LatticeJob> = Api::all(client);
    let (reader, writer) = reflector::store();
    let job_stream = reflector(writer, watcher::watcher(jobs, watcher_config()))
        .default_backoff()
        .applied_objects()
        .predicate_filter(predicates::generation, Default::default());

    let job_ctrl = Controller::for_stream(job_stream, reader)
        .shutdown_on_signal()
        .run(
            lattice_job::controller::reconcile,
            lattice_common::default_error_policy,
            ctx,
        )
        .for_each(log_reconcile_result("Job"));

    tracing::info!("- LatticeJob controller");

    Box::pin(job_ctrl)
}

/// Build the LatticeModel controller future.
pub fn build_model_controller(
    params: WorkloadControllerParams,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    let WorkloadControllerParams {
        client,
        cluster,
        cedar,
        graph,
        registry,
        metrics_scraper,
        cost_provider,
        cache,
    } = params;
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
    model_ctx.cache = cache;
    let ctx = Arc::new(model_ctx);

    let models: Api<LatticeModel> = Api::all(client);
    let (reader, writer) = reflector::store();
    let model_stream = reflector(writer, watcher::watcher(models, watcher_config()))
        .default_backoff()
        .applied_objects()
        .predicate_filter(predicates::generation, Default::default());

    let model_ctrl = Controller::for_stream(model_stream, reader)
        .shutdown_on_signal()
        .run(
            lattice_model::controller::reconcile,
            lattice_common::default_error_policy,
            ctx,
        )
        .for_each(log_reconcile_result("Model"));

    tracing::info!("- LatticeModel controller");

    Box::pin(model_ctrl)
}

// ---------------------------------------------------------------------------
// Resolution helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Graph utilities
// ---------------------------------------------------------------------------

/// Compute the set of affected neighbor names when a service or mesh member changes.
///
/// Returns deduplicated names of all dependencies and dependents (excluding `self_name`).
fn affected_neighbors(graph: &ServiceGraph, namespace: &str, self_name: &str) -> Vec<String> {
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
pub async fn warmup_graph(client: &Client, graph: &ServiceGraph) {
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

// ---------------------------------------------------------------------------
// Graph auditor
// ---------------------------------------------------------------------------

/// Interval between graph audit cycles.
const GRAPH_AUDIT_INTERVAL: Duration = Duration::from_secs(300);

/// Spawn a background task that periodically removes orphaned graph nodes.
///
/// An orphan is a non-Unknown node in the graph whose backing CRD no longer
/// exists on the API server. This catches missed delete events that the
/// event-driven controllers can't self-heal from.
pub fn spawn_graph_auditor(client: Client, graph: Arc<ServiceGraph>, token: CancellationToken) {
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
async fn audit_graph_orphans(client: &Client, graph: &ServiceGraph) -> Result<(), kube::Error> {
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

// ---------------------------------------------------------------------------
// ObjectRef helpers
// ---------------------------------------------------------------------------

/// Collect ObjectRefs for every service in the graph (used to trigger re-reconciliation of all services).
fn all_service_refs(graph: &ServiceGraph) -> Vec<ObjectRef<LatticeService>> {
    let mut refs = Vec::new();
    for ns in graph.list_namespaces() {
        for svc in graph.list_services(&ns) {
            refs.push(ObjectRef::<LatticeService>::new(&svc.name).within(&ns));
        }
    }
    refs
}

fn all_mesh_member_refs(graph: &ServiceGraph) -> Vec<ObjectRef<LatticeMeshMember>> {
    graph
        .all_mesh_eligible()
        .into_iter()
        .map(|(ns, name)| ObjectRef::<LatticeMeshMember>::new(&name).within(&ns))
        .collect()
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
