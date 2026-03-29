//! Quota enforcement for the workload compiler
//!
//! Called during `WorkloadCompiler::compile()` to reject workloads that would
//! exceed soft limits. Reads pre-computed usage from `LatticeQuotaStatus`.

use std::collections::BTreeMap;

use lattice_common::crd::workload::spec::WorkloadSpec;
use lattice_common::crd::{LatticeQuota, QuotaPrincipal};
use lattice_common::resources::{
    compute_workload_demand, parse_resource_by_key, WorkloadResourceDemand,
};

/// Quota enforcement error.
#[derive(Debug, thiserror::Error)]
pub enum QuotaError {
    /// Failed to parse resource quantities from the workload spec.
    #[error("failed to compute resource demand: {0}")]
    ComputeDemand(#[from] lattice_common::resources::QuantityParseError),

    /// Workload exceeds per-workload cap on a quota.
    #[error("quota '{quota}': {resource} ({actual}) exceeds maxPerWorkload ({limit})")]
    PerWorkloadExceeded {
        /// Quota name
        quota: String,
        /// Resource key (cpu, memory, nvidia.com/gpu)
        resource: String,
        /// Actual value
        actual: String,
        /// Limit value
        limit: String,
    },

    /// Adding this workload would exceed the quota's soft limit.
    #[error("quota '{quota}': {resource} would exceed soft limit ({used} used + {requested} requested > {limit} limit)")]
    SoftLimitExceeded {
        /// Quota name
        quota: String,
        /// Resource key
        resource: String,
        /// Current usage
        used: String,
        /// Requested amount
        requested: String,
        /// Soft limit
        limit: String,
    },

    /// Quota has an invalid principal (should not happen if controller validated).
    #[error("quota '{quota}' has invalid principal: {reason}")]
    InvalidPrincipal {
        /// Quota name
        quota: String,
        /// Parse error
        reason: String,
    },
}

/// Enforce quota limits for a workload about to be compiled.
///
/// Checks all enabled quotas whose principal matches this workload.
/// For each matching quota:
/// - Rejects if any single resource exceeds `maxPerWorkload`
/// - Rejects if `status.used + demand` would exceed `soft` limits
pub fn enforce_quotas(
    quotas: &[LatticeQuota],
    name: &str,
    namespace: &str,
    namespace_labels: &BTreeMap<String, String>,
    workload_annotations: &BTreeMap<String, String>,
    workload: &WorkloadSpec,
    replicas: u32,
) -> Result<(), QuotaError> {
    let demand = compute_workload_demand(workload, replicas)?;

    for quota in quotas {
        if !quota.spec.enabled {
            continue;
        }

        let quota_name = quota.metadata.name.as_deref().unwrap_or("unknown");

        let principal = QuotaPrincipal::parse(&quota.spec.principal).map_err(|e| {
            QuotaError::InvalidPrincipal {
                quota: quota_name.to_string(),
                reason: e.to_string(),
            }
        })?;

        if !principal.matches_workload(namespace, name, namespace_labels, workload_annotations) {
            continue;
        }

        if let Some(ref max) = quota.spec.max_per_workload {
            check_per_workload_limit(&demand, max, quota_name)?;
        }

        let used = quota
            .status
            .as_ref()
            .map(|s| &s.used)
            .cloned()
            .unwrap_or_default();

        check_soft_limit(&demand, &used, &quota.spec.soft, quota_name)?;
    }

    Ok(())
}

fn check_per_workload_limit(
    demand: &WorkloadResourceDemand,
    max: &BTreeMap<String, String>,
    quota_name: &str,
) -> Result<(), QuotaError> {
    let demand_map = demand_to_raw(demand);

    for (key, limit_str) in max {
        let limit = match parse_resource_by_key(key, limit_str) {
            Ok(v) => v,
            Err(_) => continue, // Invalid limits caught by CRD validation
        };
        let actual = demand_map.get(key.as_str()).copied().unwrap_or(0);
        if actual > limit {
            return Err(QuotaError::PerWorkloadExceeded {
                quota: quota_name.to_string(),
                resource: key.clone(),
                actual: crate::format_resource_value(key, actual),
                limit: limit_str.clone(),
            });
        }
    }
    Ok(())
}

fn check_soft_limit(
    demand: &WorkloadResourceDemand,
    used: &BTreeMap<String, String>,
    soft: &BTreeMap<String, String>,
    quota_name: &str,
) -> Result<(), QuotaError> {
    let demand_map = demand_to_raw(demand);

    for (key, limit_str) in soft {
        let limit = match parse_resource_by_key(key, limit_str) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let current = used
            .get(key)
            .and_then(|v| parse_resource_by_key(key, v).ok())
            .unwrap_or(0);
        let requested = demand_map.get(key.as_str()).copied().unwrap_or(0);

        if current + requested > limit {
            return Err(QuotaError::SoftLimitExceeded {
                quota: quota_name.to_string(),
                resource: key.clone(),
                used: crate::format_resource_value(key, current),
                requested: crate::format_resource_value(key, requested),
                limit: limit_str.clone(),
            });
        }
    }
    Ok(())
}

/// Map demand fields to raw i64 values keyed by resource name.
fn demand_to_raw(demand: &WorkloadResourceDemand) -> BTreeMap<&'static str, i64> {
    let mut map = BTreeMap::new();
    map.insert("cpu", demand.cpu_millis);
    map.insert("memory", demand.memory_bytes);
    map.insert("nvidia.com/gpu", demand.gpu_count as i64);
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::workload::container::ContainerSpec;
    use lattice_common::crd::workload::resources::{ResourceQuantity, ResourceRequirements};
    use lattice_common::crd::{LatticeQuotaPhase, LatticeQuotaSpec, LatticeQuotaStatus};

    fn make_workload(cpu: &str, memory: &str) -> WorkloadSpec {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "test:latest".to_string(),
                resources: Some(ResourceRequirements {
                    requests: Some(ResourceQuantity {
                        cpu: Some(cpu.to_string()),
                        memory: Some(memory.to_string()),
                        ..Default::default()
                    }),
                    limits: Some(ResourceQuantity {
                        cpu: Some(cpu.to_string()),
                        memory: Some(memory.to_string()),
                        ..Default::default()
                    }),
                }),
                ..Default::default()
            },
        );
        WorkloadSpec {
            containers,
            ..Default::default()
        }
    }

    fn make_quota(soft_cpu: &str, used_cpu: Option<&str>) -> LatticeQuota {
        let mut quota = LatticeQuota::new(
            "test-quota",
            LatticeQuotaSpec {
                principal: "Lattice::Group::\"team\"".to_string(),
                soft: BTreeMap::from([("cpu".to_string(), soft_cpu.to_string())]),
                hard: None,
                max_per_workload: None,
                enabled: true,
            },
        );
        quota.metadata.namespace = Some("lattice-system".to_string());

        if let Some(used) = used_cpu {
            quota.status = Some(LatticeQuotaStatus {
                phase: LatticeQuotaPhase::Active,
                used: BTreeMap::from([("cpu".to_string(), used.to_string())]),
                workload_count: 1,
                message: None,
                observed_generation: None,
            });
        }

        quota
    }

    fn team_labels() -> BTreeMap<String, String> {
        BTreeMap::from([("lattice.dev/group".to_string(), "team".to_string())])
    }

    #[test]
    fn enforce_within_limits() {
        let workload = make_workload("1", "1Gi");
        let quota = make_quota("10", Some("4"));

        let result = enforce_quotas(
            &[quota],
            "my-svc",
            "ns",
            &team_labels(),
            &BTreeMap::new(),
            &workload,
            1,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn enforce_exceeds_soft() {
        let workload = make_workload("8", "1Gi");
        let quota = make_quota("10", Some("4"));

        let result = enforce_quotas(
            &[quota],
            "my-svc",
            "ns",
            &team_labels(),
            &BTreeMap::new(),
            &workload,
            1,
        );
        assert!(matches!(result, Err(QuotaError::SoftLimitExceeded { .. })));
    }

    #[test]
    fn enforce_no_matching_quota() {
        let workload = make_workload("100", "1Gi");
        let quota = make_quota("1", None);
        let wrong_labels =
            BTreeMap::from([("lattice.dev/group".to_string(), "other".to_string())]);

        let result = enforce_quotas(
            &[quota],
            "my-svc",
            "ns",
            &wrong_labels,
            &BTreeMap::new(),
            &workload,
            1,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn enforce_disabled_quota_ignored() {
        let workload = make_workload("100", "1Gi");
        let mut quota = make_quota("1", None);
        quota.spec.enabled = false;

        let result = enforce_quotas(
            &[quota],
            "my-svc",
            "ns",
            &team_labels(),
            &BTreeMap::new(),
            &workload,
            1,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn enforce_per_workload_cap() {
        let workload = make_workload("16", "1Gi");
        let mut quota = make_quota("100", None);
        quota.spec.max_per_workload =
            Some(BTreeMap::from([("cpu".to_string(), "8".to_string())]));

        let result = enforce_quotas(
            &[quota],
            "my-svc",
            "ns",
            &team_labels(),
            &BTreeMap::new(),
            &workload,
            1,
        );
        assert!(matches!(
            result,
            Err(QuotaError::PerWorkloadExceeded { .. })
        ));
    }

    #[test]
    fn enforce_replicas_multiply() {
        let workload = make_workload("2", "1Gi");
        let quota = make_quota("10", Some("4"));

        // 2 CPU * 4 replicas = 8 CPU, 4 used + 8 = 12 > 10 soft limit
        let result = enforce_quotas(
            &[quota],
            "my-svc",
            "ns",
            &team_labels(),
            &BTreeMap::new(),
            &workload,
            4,
        );
        assert!(matches!(result, Err(QuotaError::SoftLimitExceeded { .. })));
    }

    #[test]
    fn enforce_invalid_principal_is_error() {
        let workload = make_workload("1", "1Gi");
        let mut quota = make_quota("100", None);
        quota.spec.principal = "bad-principal".to_string();

        let result = enforce_quotas(
            &[quota],
            "my-svc",
            "ns",
            &team_labels(),
            &BTreeMap::new(),
            &workload,
            1,
        );
        assert!(matches!(result, Err(QuotaError::InvalidPrincipal { .. })));
    }

    #[test]
    fn format_resource_value_cpu() {
        assert_eq!(crate::format_resource_value("cpu", 4000), "4");
        assert_eq!(crate::format_resource_value("cpu", 1500), "1500m");
    }

    #[test]
    fn format_resource_value_memory() {
        assert_eq!(
            crate::format_resource_value("memory", 8 * 1024 * 1024 * 1024),
            "8Gi"
        );
        assert_eq!(
            crate::format_resource_value("memory", 512 * 1024 * 1024),
            "512Mi"
        );
    }
}
