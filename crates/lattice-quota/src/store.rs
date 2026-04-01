//! Quota budget resolution from pre-fetched data.
//!
//! The `resolve_budget` function computes a workload's effective budget from
//! quota CRDs and namespace labels. Callers provide the data — typically
//! from a ResourceCache (reflector watches) so no API calls happen at
//! point of use.

use std::collections::BTreeMap;

use lattice_common::crd::LatticeQuota;

/// Resolve a `QuotaBudget` for a workload from pre-fetched quotas and namespace labels.
///
/// This is a pure computation — no I/O. The caller is responsible for
/// providing current quota and namespace data (e.g., from a reflector cache).
pub fn resolve_budget(
    quotas: &[LatticeQuota],
    namespace: &str,
    name: &str,
    namespace_labels: &BTreeMap<String, String>,
    workload_annotations: &BTreeMap<String, String>,
) -> crate::QuotaBudget {
    if quotas.is_empty() {
        return crate::QuotaBudget::default();
    }
    crate::QuotaBudget::from_matching_quotas(
        quotas,
        namespace,
        name,
        namespace_labels,
        workload_annotations,
    )
}
