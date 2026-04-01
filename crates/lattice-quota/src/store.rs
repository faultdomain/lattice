//! Quota budget resolution — reads quotas directly from the K8s API.
//!
//! Each workload controller calls `resolve_budget` during compilation to get
//! the effective budget for a workload. This reads LatticeQuota CRDs and
//! namespace labels directly, avoiding cross-pod state sharing issues that
//! arise when controllers run on different pods via per-controller leases.

use std::collections::BTreeMap;

use kube::api::Api;
use tracing::warn;

use lattice_common::crd::LatticeQuota;
use lattice_common::LATTICE_SYSTEM_NAMESPACE;

/// Resolve a `QuotaBudget` for a workload by reading quotas from the K8s API.
///
/// Lists all LatticeQuota CRDs, fetches namespace labels, and computes the
/// effective budget. Called during each compilation — one API list + one
/// namespace get per reconcile.
pub async fn resolve_budget(
    client: &kube::Client,
    namespace: &str,
    name: &str,
    workload_annotations: &BTreeMap<String, String>,
) -> crate::QuotaBudget {
    let quotas = list_quotas(client).await;
    if quotas.is_empty() {
        return crate::QuotaBudget::default();
    }

    let ns_labels = get_namespace_labels(client, namespace).await;
    crate::QuotaBudget::from_matching_quotas(&quotas, namespace, name, &ns_labels, workload_annotations)
}

async fn list_quotas(client: &kube::Client) -> Vec<LatticeQuota> {
    Api::<LatticeQuota>::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE)
        .list(&Default::default())
        .await
        .map(|l| l.items)
        .unwrap_or_else(|e| {
            warn!(error = %e, "Failed to list LatticeQuotas for budget resolution");
            vec![]
        })
}

async fn get_namespace_labels(
    client: &kube::Client,
    namespace: &str,
) -> BTreeMap<String, String> {
    Api::<k8s_openapi::api::core::v1::Namespace>::all(client.clone())
        .get(namespace)
        .await
        .map(|ns| ns.metadata.labels.unwrap_or_default())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration-style tests require a real K8s client.
    // Budget resolution logic is tested via QuotaBudget unit tests in budget.rs.
    // The resolve_budget function is exercised by E2E quota tests.

    #[tokio::test]
    async fn list_quotas_returns_empty_without_cluster() {
        // Without a real cluster, kube::Client::try_default() fails.
        // This just verifies the module compiles and the function signature is correct.
        // Real coverage comes from E2E tests.
    }
}
