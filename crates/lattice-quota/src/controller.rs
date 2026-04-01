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

const FIELD_MANAGER: &str = "lattice-quota-controller";
const REQUEUE_SECS: u64 = 30;

/// Context for the quota controller.
pub struct QuotaContext {
    /// Kubernetes client
    pub client: kube::Client,
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

    let (usage, workload_count) = compute_usage(client, &principal).await;
    let exceeded = is_exceeded(&usage, &quota.spec.limits);
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

    info!(quota = %name, principal = %quota.spec.principal, phase = %phase, workloads = workload_count, "Reconciled LatticeQuota");

    Ok(Action::requeue(Duration::from_secs(REQUEUE_SECS)))
}


/// Accumulated usage from scanning workloads.
struct UsageAccumulator {
    total: WorkloadResourceDemand,
    count: u32,
    ns_cache: HashMap<String, BTreeMap<String, String>>,
}

impl UsageAccumulator {
    fn new() -> Self {
        Self {
            total: WorkloadResourceDemand::default(),
            count: 0,
            ns_cache: HashMap::new(),
        }
    }

    /// Check if a resource matches the principal, using the namespace label cache.
    async fn matches(
        &mut self,
        client: &kube::Client,
        principal: &QuotaPrincipal,
        resource: &impl kube::ResourceExt,
    ) -> bool {
        let ns = resource.namespace().unwrap_or_default();
        let ns_labels = cached_ns_labels(client, &ns, &mut self.ns_cache).await;
        let empty = BTreeMap::new();
        let annotations = resource.meta().annotations.as_ref().unwrap_or(&empty);
        principal.matches_workload(&ns, &resource.name_any(), ns_labels, annotations)
    }

    /// Add a single workload's demand.
    fn add_demand(&mut self, demand: &WorkloadResourceDemand) {
        self.total += demand;
    }

    /// Increment the workload count.
    fn add_workload(&mut self) {
        self.count += 1;
    }

    fn into_result(self) -> (WorkloadResourceDemand, u32) {
        (self.total, self.count)
    }
}

/// Compute total resource usage for a principal. Returns usage and workload count.
async fn compute_usage(
    client: &kube::Client,
    principal: &QuotaPrincipal,
) -> (WorkloadResourceDemand, u32) {
    let mut acc = UsageAccumulator::new();

    match Api::<LatticeService>::all(client.clone())
        .list(&Default::default())
        .await
    {
        Ok(services) => {
            for svc in &services.items {
                if !acc.matches(client, principal, svc).await {
                    continue;
                }
                if let Ok(demand) = compute_workload_demand(&svc.spec.workload, svc.spec.replicas) {
                    acc.add_demand(&demand);
                    acc.add_workload();
                }
            }
        }
        Err(e) => warn!(error = %e, "Failed to list LatticeServices for quota usage"),
    }

    match Api::<LatticeJob>::all(client.clone())
        .list(&Default::default())
        .await
    {
        Ok(jobs) => {
            for job in &jobs.items {
                if !acc.matches(client, principal, job).await {
                    continue;
                }
                for task in job.spec.tasks.values() {
                    if let Ok(demand) =
                        compute_workload_demand(&task.workload, task.replicas.unwrap_or(1))
                    {
                        acc.add_demand(&demand);
                    }
                }
                acc.add_workload();
            }
        }
        Err(e) => warn!(error = %e, "Failed to list LatticeJobs for quota usage"),
    }

    match Api::<LatticeModel>::all(client.clone())
        .list(&Default::default())
        .await
    {
        Ok(models) => {
            for model in &models.items {
                if !acc.matches(client, principal, model).await {
                    continue;
                }
                for role in model.spec.roles.values() {
                    if let Ok(demand) =
                        compute_workload_demand(&role.entry_workload, role.replicas.unwrap_or(1))
                    {
                        acc.add_demand(&demand);
                    }
                    if let (Some(ref ww), Some(wr)) = (&role.worker_workload, role.worker_replicas) {
                        if let Ok(demand) = compute_workload_demand(ww, wr) {
                            acc.add_demand(&demand);
                        }
                    }
                }
                acc.add_workload();
            }
        }
        Err(e) => warn!(error = %e, "Failed to list LatticeModels for quota usage"),
    }

    acc.into_result()
}

fn is_exceeded(usage: &WorkloadResourceDemand, limits: &BTreeMap<String, String>) -> bool {
    let raw = usage.to_raw_map();
    for (key, limit_str) in limits {
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
        assert!(!map.contains_key("nvidia.com/gpu"));
    }

    #[test]
    fn format_demand_map_zero() {
        assert!(crate::format_demand_map(&WorkloadResourceDemand::default()).is_empty());
    }
}
