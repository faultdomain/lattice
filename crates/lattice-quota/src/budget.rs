//! QuotaBudget — the resolved effective limits for a workload's context.
//!
//! Instead of passing raw quota CRDs through the compiler, the controller
//! resolves which quotas apply and computes the effective budget: how much
//! capacity remains (soft limit minus current usage) for each resource.

use std::collections::BTreeMap;

use lattice_common::crd::LatticeQuota;
use lattice_common::resources::{parse_resource_by_key, WorkloadResourceDemand};

/// Pre-resolved quota budget for a workload's namespace/principal.
///
/// Contains the remaining capacity (soft - used) for each resource.
/// The compiler checks if the incoming workload fits within this budget.
#[derive(Clone, Debug, Default)]
pub struct QuotaBudget {
    /// Remaining capacity per resource (soft limit - current usage).
    /// Keys: "cpu" (millis), "memory" (bytes), "nvidia.com/gpu" (count), "cost" (USD/hr).
    pub remaining: BTreeMap<String, i64>,

    /// Per-workload caps (max any single workload can request).
    pub max_per_workload: BTreeMap<String, i64>,
}

impl QuotaBudget {
    /// Resolve the effective budget from quotas matching a workload.
    ///
    /// For each matching quota, takes the tightest (minimum) remaining
    /// capacity across all quotas. Per-workload caps are also minimized.
    pub fn from_matching_quotas(
        quotas: &[LatticeQuota],
        namespace: &str,
        name: &str,
        namespace_labels: &BTreeMap<String, String>,
        workload_annotations: &BTreeMap<String, String>,
    ) -> Self {
        use lattice_common::crd::QuotaPrincipal;

        let mut budget = Self::default();
        let mut has_match = false;

        for quota in quotas {
            if !quota.spec.enabled {
                continue;
            }

            let principal = match QuotaPrincipal::parse(&quota.spec.principal) {
                Ok(p) => p,
                Err(_) => continue,
            };

            if !principal.matches_workload(namespace, name, namespace_labels, workload_annotations)
            {
                continue;
            }

            has_match = true;
            let used = quota
                .status
                .as_ref()
                .map(|s| &s.used)
                .cloned()
                .unwrap_or_default();

            // For each resource in the soft limits, compute remaining = soft - used
            for (key, soft_str) in &quota.spec.soft {
                let soft = parse_resource_by_key(key, soft_str).unwrap_or(0);
                let current = used
                    .get(key)
                    .and_then(|v| parse_resource_by_key(key, v).ok())
                    .unwrap_or(0);
                let remaining = (soft - current).max(0);

                // Take the tightest constraint across all matching quotas
                let entry = budget.remaining.entry(key.clone()).or_insert(i64::MAX);
                *entry = (*entry).min(remaining);
            }

            // Per-workload caps: take the tightest
            if let Some(ref max) = quota.spec.max_per_workload {
                for (key, max_str) in max {
                    let max_val = parse_resource_by_key(key, max_str).unwrap_or(i64::MAX);
                    let entry = budget
                        .max_per_workload
                        .entry(key.clone())
                        .or_insert(i64::MAX);
                    *entry = (*entry).min(max_val);
                }
            }
        }

        // If no quotas matched, budget is unlimited (empty maps = no constraints)
        if !has_match {
            return Self::default();
        }

        budget
    }

    /// Check if a workload demand fits within this budget.
    ///
    /// Returns `Ok(())` if the workload fits, or `Err(reason)` with a
    /// human-readable explanation of which limit was exceeded.
    pub fn check(&self, demand: &WorkloadResourceDemand) -> Result<(), String> {
        if self.remaining.is_empty() && self.max_per_workload.is_empty() {
            return Ok(()); // No constraints
        }

        let raw = demand.to_raw_map();

        // Check per-workload caps first
        for (key, max) in &self.max_per_workload {
            let actual = raw.get(key.as_str()).copied().unwrap_or(0);
            if actual > *max {
                return Err(format!(
                    "{key} ({}) exceeds per-workload cap ({})",
                    crate::format_resource_value(key, actual),
                    crate::format_resource_value(key, *max),
                ));
            }
        }

        // Check remaining budget
        for (key, remaining) in &self.remaining {
            let requested = raw.get(key.as_str()).copied().unwrap_or(0);
            if requested > *remaining {
                return Err(format!(
                    "{key}: {} requested but only {} remaining in quota",
                    crate::format_resource_value(key, requested),
                    crate::format_resource_value(key, *remaining),
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{LatticeQuotaPhase, LatticeQuotaSpec, LatticeQuotaStatus};

    fn make_quota(soft_cpu: &str, used_cpu: Option<&str>, max_cpu: Option<&str>) -> LatticeQuota {
        let mut quota = LatticeQuota::new(
            "test-quota",
            LatticeQuotaSpec {
                principal: "Lattice::Group::\"team\"".to_string(),
                soft: BTreeMap::from([("cpu".to_string(), soft_cpu.to_string())]),
                hard: None,
                max_per_workload: max_cpu
                    .map(|v| BTreeMap::from([("cpu".to_string(), v.to_string())])),
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
    fn budget_from_single_quota() {
        let quota = make_quota("10", Some("4"), None);
        let budget = QuotaBudget::from_matching_quotas(
            &[quota],
            "ns",
            "svc",
            &team_labels(),
            &BTreeMap::new(),
        );
        // Remaining: 10 cores - 4 used = 6 cores = 6000m
        assert_eq!(budget.remaining.get("cpu"), Some(&6000));
    }

    #[test]
    fn budget_tightest_wins() {
        let q1 = make_quota("10", Some("4"), None); // 6 remaining
        let mut q2 = make_quota("8", Some("6"), None); // 2 remaining
        q2.metadata.name = Some("q2".to_string());

        let budget = QuotaBudget::from_matching_quotas(
            &[q1, q2],
            "ns",
            "svc",
            &team_labels(),
            &BTreeMap::new(),
        );
        // Tightest: 2 cores = 2000m
        assert_eq!(budget.remaining.get("cpu"), Some(&2000));
    }

    #[test]
    fn budget_no_match_unlimited() {
        let quota = make_quota("1", None, None);
        let budget = QuotaBudget::from_matching_quotas(
            &[quota],
            "ns",
            "svc",
            &BTreeMap::new(), // wrong labels
            &BTreeMap::new(),
        );
        assert!(budget.remaining.is_empty());
    }

    #[test]
    fn check_within_budget() {
        let quota = make_quota("10", Some("4"), None);
        let budget = QuotaBudget::from_matching_quotas(
            &[quota],
            "ns",
            "svc",
            &team_labels(),
            &BTreeMap::new(),
        );
        let demand = WorkloadResourceDemand {
            cpu_millis: 4000, // 4 cores, 6 remaining
            ..Default::default()
        };
        assert!(budget.check(&demand).is_ok());
    }

    #[test]
    fn check_exceeds_budget() {
        let quota = make_quota("10", Some("8"), None);
        let budget = QuotaBudget::from_matching_quotas(
            &[quota],
            "ns",
            "svc",
            &team_labels(),
            &BTreeMap::new(),
        );
        let demand = WorkloadResourceDemand {
            cpu_millis: 4000, // 4 cores, only 2 remaining
            ..Default::default()
        };
        assert!(budget.check(&demand).is_err());
    }

    #[test]
    fn check_per_workload_cap() {
        let quota = make_quota("100", None, Some("8"));
        let budget = QuotaBudget::from_matching_quotas(
            &[quota],
            "ns",
            "svc",
            &team_labels(),
            &BTreeMap::new(),
        );
        let demand = WorkloadResourceDemand {
            cpu_millis: 16000, // 16 cores, cap is 8
            ..Default::default()
        };
        let err = budget.check(&demand).unwrap_err();
        assert!(err.contains("per-workload cap"));
    }
}
