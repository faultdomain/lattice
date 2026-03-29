//! LatticeQuota reconciliation controller
//!
//! Watches LatticeQuota CRDs, validates specs, and tracks resource usage
//! per principal in status. Requeues periodically to keep usage current.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, ListParams};
use kube::runtime::controller::Action;
use kube::ResourceExt;
use tracing::{debug, info, warn};

use lattice_common::crd::{
    LatticeJob, LatticeModel, LatticeQuota, LatticeQuotaPhase, LatticeQuotaStatus,
    LatticeService, QuotaPrincipal,
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
    pub cost_provider: Option<std::sync::Arc<dyn CostProvider>>,
}

/// Reconcile a LatticeQuota
///
/// Validates the spec, computes current resource usage for the principal,
/// and updates status with usage and phase (Active vs Exceeded).
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

    let (usage, workload_count) = compute_usage(client, &principal).await;
    let exceeded = is_exceeded(&usage, &quota.spec.soft);
    let phase = if exceeded {
        LatticeQuotaPhase::Exceeded
    } else {
        LatticeQuotaPhase::Active
    };

    let used_map = crate::format_demand_map(&usage);

    update_status(
        client,
        &quota,
        phase,
        used_map,
        workload_count,
        None,
        Some(generation),
    )
    .await?;

    info!(
        quota = %name,
        principal = %quota.spec.principal,
        phase = %phase,
        workloads = workload_count,
        "Reconciled LatticeQuota"
    );

    // Reconcile cluster capacity if we have a cluster name
    if let Some(ref cluster_name) = ctx.cluster_name {
        let rates = match &ctx.cost_provider {
            Some(provider) => match provider.load_rates().await {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "Cost rates unavailable, using uniform costs");
                    lattice_cost::CostRates::uniform()
                }
            },
            None => {
                debug!("No cost provider configured, using uniform costs");
                lattice_cost::CostRates::uniform()
            }
        };

        if let Err(e) = crate::capacity::reconcile_capacity(client, cluster_name, &rates).await
        {
            warn!(error = %e, "Capacity reconciliation failed, will retry");
        }
    }

    Ok(Action::requeue(Duration::from_secs(REQUEUE_SECS)))
}

/// Compute total resource usage for a principal across all workload types.
async fn compute_usage(
    client: &kube::Client,
    principal: &QuotaPrincipal,
) -> (WorkloadResourceDemand, u32) {
    let mut total = WorkloadResourceDemand::default();
    let mut count: u32 = 0;
    let mut ns_cache: HashMap<String, BTreeMap<String, String>> = HashMap::new();
    let empty = BTreeMap::new();

    // Sum across LatticeServices
    if let Ok(services) = Api::<LatticeService>::all(client.clone())
        .list(&ListParams::default())
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

    // Sum across LatticeJobs
    if let Ok(jobs) = Api::<LatticeJob>::all(client.clone())
        .list(&ListParams::default())
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
                let replicas = task.replicas.unwrap_or(1);
                if let Ok(demand) = compute_workload_demand(&task.workload, replicas) {
                    total += &demand;
                }
            }
            count += 1;
        }
    }

    // Sum across LatticeModels
    if let Ok(models) = Api::<LatticeModel>::all(client.clone())
        .list(&ListParams::default())
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
                let entry_replicas = role.replicas.unwrap_or(1);
                if let Ok(demand) =
                    compute_workload_demand(&role.entry_workload, entry_replicas)
                {
                    total += &demand;
                }
                if let (Some(ref worker_workload), Some(worker_replicas)) =
                    (&role.worker_workload, role.worker_replicas)
                {
                    if let Ok(demand) = compute_workload_demand(worker_workload, worker_replicas) {
                        total += &demand;
                    }
                }
            }
            count += 1;
        }
    }

    (total, count)
}

/// Check if usage exceeds any soft limit using the shared resource parser.
fn is_exceeded(usage: &WorkloadResourceDemand, soft: &BTreeMap<String, String>) -> bool {
    let raw = usage.to_raw_map();
    for (key, limit_str) in soft {
        if let Ok(limit) = parse_resource_by_key(key, limit_str) {
            let actual = raw.get(key.as_str()).copied().unwrap_or(0);
            if actual > limit {
                return true;
            }
        }
    }
    false
}

/// Get namespace labels, caching across lookups within one reconcile.
async fn cached_ns_labels<'a>(
    client: &kube::Client,
    namespace: &str,
    cache: &'a mut HashMap<String, BTreeMap<String, String>>,
) -> &'a BTreeMap<String, String> {
    if !cache.contains_key(namespace) {
        let labels = fetch_namespace_labels(client, namespace).await;
        cache.insert(namespace.to_string(), labels);
    }
    cache.get(namespace).unwrap()
}

async fn fetch_namespace_labels(
    client: &kube::Client,
    namespace: &str,
) -> BTreeMap<String, String> {
    let ns_api: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());
    match ns_api.get(namespace).await {
        Ok(ns) => ns.metadata.labels.unwrap_or_default(),
        Err(_) => BTreeMap::new(),
    }
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
    let name = quota.name_any();
    let namespace = quota
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

    let status = LatticeQuotaStatus {
        phase,
        used,
        workload_count,
        message,
        observed_generation,
    };

    lattice_common::kube_utils::patch_resource_status::<LatticeQuota>(
        client,
        &name,
        &namespace,
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
            ("cpu".to_string(), "8".to_string()),
            ("memory".to_string(), "16Gi".to_string()),
            ("nvidia.com/gpu".to_string(), "4".to_string()),
        ]);
        assert!(!is_exceeded(&usage, &soft));
    }

    #[test]
    fn is_exceeded_cpu_over() {
        let usage = WorkloadResourceDemand {
            cpu_millis: 10000,
            ..Default::default()
        };
        let soft = BTreeMap::from([("cpu".to_string(), "8".to_string())]);
        assert!(is_exceeded(&usage, &soft));
    }

    #[test]
    fn is_exceeded_gpu_over() {
        let usage = WorkloadResourceDemand {
            gpu_count: 5,
            ..Default::default()
        };
        let soft = BTreeMap::from([("nvidia.com/gpu".to_string(), "4".to_string())]);
        assert!(is_exceeded(&usage, &soft));
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
        let map = crate::format_demand_map(&WorkloadResourceDemand::default());
        assert!(map.is_empty());
    }
}
