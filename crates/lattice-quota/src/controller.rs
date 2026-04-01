//! LatticeQuota reconciliation controller
//!
//! Watches LatticeQuota CRDs, validates specs, tracks resource usage per
//! principal, and pushes snapshots through a watch channel for workload
//! controllers to consume.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::ResourceExt;
use tracing::{debug, info, warn};

use lattice_cache::ResourceCache;
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
    /// Kubernetes client (used for status writes only)
    pub client: kube::Client,
    /// Resource cache for reading workloads and namespaces
    pub cache: ResourceCache,
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

    let (usage, workload_count) = compute_usage(&ctx.cache, &principal);
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


/// Resolve namespace labels from the cache.
fn ns_labels(cache: &ResourceCache, namespace: &str) -> BTreeMap<String, String> {
    cache
        .get::<k8s_openapi::api::core::v1::Namespace>(namespace)
        .and_then(|ns| ns.metadata.labels.clone())
        .unwrap_or_default()
}

/// Check if a resource matches the principal using cached namespace labels.
fn matches_principal(
    cache: &ResourceCache,
    principal: &QuotaPrincipal,
    resource: &impl kube::ResourceExt,
) -> bool {
    let ns = resource.namespace().unwrap_or_default();
    let labels = ns_labels(cache, &ns);
    let empty = BTreeMap::new();
    let annotations = resource.meta().annotations.as_ref().unwrap_or(&empty);
    principal.matches_workload(&ns, &resource.name_any(), &labels, annotations)
}

/// Compute total resource usage for a principal. Returns usage and workload count.
fn compute_usage(
    cache: &ResourceCache,
    principal: &QuotaPrincipal,
) -> (WorkloadResourceDemand, u32) {
    let mut total = WorkloadResourceDemand::default();
    let mut count: u32 = 0;

    for svc in cache.list::<LatticeService>() {
        if !matches_principal(cache, principal, svc.as_ref()) {
            continue;
        }
        if let Ok(demand) = compute_workload_demand(&svc.spec.workload, svc.spec.replicas) {
            total += &demand;
            count += 1;
        }
    }

    for job in cache.list::<LatticeJob>() {
        if !matches_principal(cache, principal, job.as_ref()) {
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

    for model in cache.list::<LatticeModel>() {
        if !matches_principal(cache, principal, model.as_ref()) {
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

    (total, count)
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
