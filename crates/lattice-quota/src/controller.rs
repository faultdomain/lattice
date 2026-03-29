//! LatticeQuota reconciliation controller
//!
//! Watches LatticeQuota CRDs, validates specs, tracks resource usage per
//! principal, and pushes snapshots through a watch channel for workload
//! controllers to consume.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use kube::api::Api;
use kube::runtime::controller::Action;
use kube::ResourceExt;
use tracing::{debug, info, warn};

use lattice_common::crd::{
    LatticeJob, LatticeModel, LatticeQuota, LatticeQuotaPhase, LatticeQuotaStatus, LatticeService,
    QuotaPrincipal,
};
use lattice_common::resources::{
    compute_workload_demand, parse_resource_by_key, WorkloadResourceDemand,
};
use lattice_common::{ReconcileError, LATTICE_SYSTEM_NAMESPACE, REQUEUE_ERROR_SECS};
use lattice_cost::CostProvider;

const FIELD_MANAGER: &str = "lattice-quota-controller";
const REQUEUE_SECS: u64 = 30;

/// Context for the quota controller.
pub struct QuotaContext {
    /// Kubernetes client
    pub client: kube::Client,
    /// Self-cluster name (for capacity reconciliation)
    pub cluster_name: Option<String>,
    /// Cost rate provider (for the ILP solver)
    pub cost_provider: Option<Arc<dyn CostProvider>>,
    /// Watch channel sender — pushes quota snapshots to workload controllers
    pub sender: crate::QuotaSender,
}

/// Reconcile a LatticeQuota.
pub async fn reconcile(
    quota: Arc<LatticeQuota>,
    ctx: Arc<QuotaContext>,
) -> Result<Action, ReconcileError> {
    let name = quota.name_any();
    let client = &ctx.client;
    let generation = quota.metadata.generation.unwrap_or(0);

    if let Err(e) = quota.spec.validate() {
        warn!(quota = %name, error = %e, "LatticeQuota spec invalid");
        update_status(
            client,
            &quota,
            LatticeQuotaPhase::Invalid,
            BTreeMap::new(),
            0,
            Some(e.to_string()),
            Some(generation),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
    }

    if !quota.spec.enabled {
        debug!(quota = %name, "LatticeQuota disabled, skipping");
        return Ok(Action::requeue(Duration::from_secs(REQUEUE_SECS * 10)));
    }

    let principal = match QuotaPrincipal::parse(&quota.spec.principal) {
        Ok(p) => p,
        Err(e) => {
            update_status(
                client,
                &quota,
                LatticeQuotaPhase::Invalid,
                BTreeMap::new(),
                0,
                Some(e.to_string()),
                Some(generation),
            )
            .await?;
            return Ok(Action::requeue(Duration::from_secs(REQUEUE_ERROR_SECS)));
        }
    };

    let (usage, workload_count, ns_labels) = compute_usage(client, &principal).await;
    let exceeded = is_exceeded(&usage, &quota.spec.soft);
    let phase = if exceeded {
        LatticeQuotaPhase::Exceeded
    } else {
        LatticeQuotaPhase::Active
    };

    update_status(
        client,
        &quota,
        phase,
        crate::format_demand_map(&usage),
        workload_count,
        None,
        Some(generation),
    )
    .await?;

    // Send full snapshot through the watch channel
    let all_quotas = list_all_quotas(client).await;
    let _ = ctx.sender.send(crate::QuotaSnapshot {
        quotas: all_quotas,
        namespace_labels: ns_labels,
    });

    info!(quota = %name, principal = %quota.spec.principal, phase = %phase, workloads = workload_count, "Reconciled LatticeQuota");

    // Reconcile cluster capacity
    if let Some(ref cluster_name) = ctx.cluster_name {
        let rates = load_rates(&ctx.cost_provider).await;
        if let Err(e) = crate::capacity::reconcile_capacity(client, cluster_name, &rates).await {
            warn!(error = %e, "Capacity reconciliation failed, will retry");
        }
    }

    Ok(Action::requeue(Duration::from_secs(REQUEUE_SECS)))
}

async fn load_rates(provider: &Option<Arc<dyn CostProvider>>) -> lattice_cost::CostRates {
    match provider {
        Some(p) => p.load_rates().await.unwrap_or_else(|e| {
            warn!(error = %e, "Cost rates unavailable, using uniform costs");
            lattice_cost::CostRates::uniform()
        }),
        None => lattice_cost::CostRates::uniform(),
    }
}

async fn list_all_quotas(client: &kube::Client) -> Vec<LatticeQuota> {
    Api::<LatticeQuota>::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE)
        .list(&Default::default())
        .await
        .map(|l| l.items)
        .unwrap_or_default()
}

/// Compute total resource usage for a principal. Returns usage, workload count,
/// and the namespace label cache (for the snapshot).
async fn compute_usage(
    client: &kube::Client,
    principal: &QuotaPrincipal,
) -> (
    WorkloadResourceDemand,
    u32,
    BTreeMap<String, BTreeMap<String, String>>,
) {
    let mut total = WorkloadResourceDemand::default();
    let mut count: u32 = 0;
    let mut ns_cache: HashMap<String, BTreeMap<String, String>> = HashMap::new();
    let empty = BTreeMap::new();

    if let Ok(services) = Api::<LatticeService>::all(client.clone())
        .list(&Default::default())
        .await
    {
        for svc in &services.items {
            let ns = svc.namespace().unwrap_or_default();
            let ns_labels = cached_ns_labels(client, &ns, &mut ns_cache).await;
            let annotations = svc.metadata.annotations.as_ref().unwrap_or(&empty);
            if !principal.matches_workload(&ns, &svc.name_any(), ns_labels, annotations) {
                continue;
            }
            if let Ok(demand) = compute_workload_demand(&svc.spec.workload, svc.spec.replicas) {
                total += &demand;
                count += 1;
            }
        }
    }

    if let Ok(jobs) = Api::<LatticeJob>::all(client.clone())
        .list(&Default::default())
        .await
    {
        for job in &jobs.items {
            let ns = job.namespace().unwrap_or_default();
            let ns_labels = cached_ns_labels(client, &ns, &mut ns_cache).await;
            let annotations = job.metadata.annotations.as_ref().unwrap_or(&empty);
            if !principal.matches_workload(&ns, &job.name_any(), ns_labels, annotations) {
                continue;
            }
            for task in job.spec.tasks.values() {
                if let Ok(demand) =
                    compute_workload_demand(&task.workload, task.replicas.unwrap_or(1))
                {
                    total += &demand;
                }
            }
            count += 1;
        }
    }

    if let Ok(models) = Api::<LatticeModel>::all(client.clone())
        .list(&Default::default())
        .await
    {
        for model in &models.items {
            let ns = model.namespace().unwrap_or_default();
            let ns_labels = cached_ns_labels(client, &ns, &mut ns_cache).await;
            let annotations = model.metadata.annotations.as_ref().unwrap_or(&empty);
            if !principal.matches_workload(&ns, &model.name_any(), ns_labels, annotations) {
                continue;
            }
            for role in model.spec.roles.values() {
                if let Ok(demand) =
                    compute_workload_demand(&role.entry_workload, role.replicas.unwrap_or(1))
                {
                    total += &demand;
                }
                if let (Some(ref ww), Some(wr)) = (&role.worker_workload, role.worker_replicas) {
                    if let Ok(demand) = compute_workload_demand(ww, wr) {
                        total += &demand;
                    }
                }
            }
            count += 1;
        }
    }

    let ns_labels_map: BTreeMap<String, BTreeMap<String, String>> = ns_cache.into_iter().collect();
    (total, count, ns_labels_map)
}

fn is_exceeded(usage: &WorkloadResourceDemand, soft: &BTreeMap<String, String>) -> bool {
    let raw = usage.to_raw_map();
    for (key, limit_str) in soft {
        if let Ok(limit) = parse_resource_by_key(key, limit_str) {
            if raw.get(key.as_str()).copied().unwrap_or(0) > limit {
                return true;
            }
        }
    }
    false
}

async fn cached_ns_labels<'a>(
    client: &kube::Client,
    namespace: &str,
    cache: &'a mut HashMap<String, BTreeMap<String, String>>,
) -> &'a BTreeMap<String, String> {
    if !cache.contains_key(namespace) {
        let api: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());
        let labels = api
            .get(namespace)
            .await
            .map(|ns| ns.metadata.labels.unwrap_or_default())
            .unwrap_or_default();
        cache.insert(namespace.to_string(), labels);
    }
    cache.get(namespace).expect("namespace was just inserted")
}

async fn update_status(
    client: &kube::Client,
    quota: &LatticeQuota,
    phase: LatticeQuotaPhase,
    used: BTreeMap<String, String>,
    workload_count: u32,
    message: Option<String>,
    observed_generation: Option<i64>,
) -> Result<(), ReconcileError> {
    let status = LatticeQuotaStatus {
        phase,
        used,
        workload_count,
        message,
        observed_generation,
    };
    lattice_common::kube_utils::patch_resource_status::<LatticeQuota>(
        client,
        &quota.name_any(),
        &quota
            .namespace()
            .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string()),
        &status,
        FIELD_MANAGER,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_exceeded_within_limits() {
        let usage = WorkloadResourceDemand {
            cpu_millis: 4000,
            memory_bytes: 8 * 1024 * 1024 * 1024,
            gpu_count: 2,
        };
        let soft = BTreeMap::from([
            ("cpu".into(), "8".into()),
            ("memory".into(), "16Gi".into()),
            ("nvidia.com/gpu".into(), "4".into()),
        ]);
        assert!(!is_exceeded(&usage, &soft));
    }

    #[test]
    fn is_exceeded_cpu_over() {
        let usage = WorkloadResourceDemand {
            cpu_millis: 10000,
            ..Default::default()
        };
        assert!(is_exceeded(
            &usage,
            &BTreeMap::from([("cpu".into(), "8".into())])
        ));
    }

    #[test]
    fn is_exceeded_gpu_over() {
        let usage = WorkloadResourceDemand {
            gpu_count: 5,
            ..Default::default()
        };
        assert!(is_exceeded(
            &usage,
            &BTreeMap::from([("nvidia.com/gpu".into(), "4".into())])
        ));
    }

    #[test]
    fn is_exceeded_empty_soft() {
        let usage = WorkloadResourceDemand {
            cpu_millis: 100000,
            memory_bytes: 100000000000,
            gpu_count: 100,
        };
        assert!(!is_exceeded(&usage, &BTreeMap::new()));
    }

    #[test]
    fn format_demand_map_whole_cores() {
        let demand = WorkloadResourceDemand {
            cpu_millis: 4000,
            memory_bytes: 8 * 1024 * 1024 * 1024,
            gpu_count: 2,
        };
        let map = crate::format_demand_map(&demand);
        assert_eq!(map.get("cpu").unwrap(), "4");
        assert_eq!(map.get("memory").unwrap(), "8Gi");
        assert_eq!(map.get("nvidia.com/gpu").unwrap(), "2");
    }

    #[test]
    fn format_demand_map_fractional_cpu() {
        let demand = WorkloadResourceDemand {
            cpu_millis: 1500,
            memory_bytes: 512 * 1024 * 1024,
            gpu_count: 0,
        };
        let map = crate::format_demand_map(&demand);
        assert_eq!(map.get("cpu").unwrap(), "1500m");
        assert_eq!(map.get("memory").unwrap(), "512Mi");
        assert!(map.get("nvidia.com/gpu").is_none());
    }

    #[test]
    fn format_demand_map_zero() {
        assert!(crate::format_demand_map(&WorkloadResourceDemand::default()).is_empty());
    }
}
