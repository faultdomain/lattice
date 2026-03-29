//! Capacity reconciliation — applies solver output to MachineDeployments.
//!
//! Reads all quotas and pool specs, runs the ILP solver, and patches
//! MachineDeployment autoscaler annotations to match the computed plan.

use kube::api::{Api, DynamicObject, Patch, PatchParams};
use kube::Client;
use tracing::{debug, info, warn};

use lattice_common::crd::{LatticeCluster, LatticeQuota};
use lattice_common::kube_utils::build_api_resource;
use lattice_common::resources::{AUTOSCALER_MAX_SIZE, AUTOSCALER_MIN_SIZE};
use lattice_common::{capi_namespace, LATTICE_SYSTEM_NAMESPACE};
use lattice_cost::CostRates;

use crate::solver::{aggregate_quotas, solve, PoolCapacityPlan};

/// Reconcile cluster capacity based on all quotas.
///
/// Aggregates all enabled quotas, runs the ILP solver against the cluster's
/// pool specs and cost rates, and patches MachineDeployment annotations
/// with the resulting min/max node counts.
pub async fn reconcile_capacity(
    client: &Client,
    cluster_name: &str,
    rates: &CostRates,
) -> Result<(), String> {
    // List all quotas in lattice-system
    let quota_api: Api<LatticeQuota> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let quotas = quota_api
        .list(&Default::default())
        .await
        .map_err(|e| format!("failed to list quotas: {e}"))?;

    if quotas.items.is_empty() {
        debug!("No quotas found, skipping capacity reconciliation");
        return Ok(());
    }

    // Get the self-cluster's LatticeCluster (cluster-scoped)
    let cluster_api: Api<LatticeCluster> = Api::all(client.clone());
    let cluster = cluster_api
        .get(cluster_name)
        .await
        .map_err(|e| format!("failed to get LatticeCluster '{cluster_name}': {e}"))?;

    let demand = aggregate_quotas(&quotas.items);
    let plans = solve(&cluster.spec.nodes.worker_pools, &demand, rates);

    if plans.is_empty() {
        debug!("Solver produced no plans (no pools with capacity info)");
        return Ok(());
    }

    let capi_ns = capi_namespace(cluster_name);
    apply_plans(client, cluster_name, &capi_ns, &plans).await?;

    info!(
        cluster = %cluster_name,
        plans = plans.len(),
        "Applied capacity plans from quota solver"
    );
    Ok(())
}

/// Patch MachineDeployment annotations with solver-computed min/max.
async fn apply_plans(
    client: &Client,
    cluster_name: &str,
    capi_ns: &str,
    plans: &[PoolCapacityPlan],
) -> Result<(), String> {
    let ar = build_api_resource("cluster.x-k8s.io/v1beta2", "MachineDeployment");
    let md_api: Api<DynamicObject> = Api::namespaced_with(client.clone(), capi_ns, &ar);

    for plan in plans {
        let md_name = format!("{}-pool-{}", cluster_name, plan.pool_id);

        let patch = serde_json::json!({
            "metadata": {
                "annotations": {
                    AUTOSCALER_MIN_SIZE: plan.min_nodes.to_string(),
                    AUTOSCALER_MAX_SIZE: plan.max_nodes.to_string(),
                }
            }
        });

        match md_api
            .patch(
                &md_name,
                &PatchParams::apply("lattice-quota-solver"),
                &Patch::Merge(&patch),
            )
            .await
        {
            Ok(_) => {
                info!(
                    md = %md_name,
                    min = plan.min_nodes,
                    max = plan.max_nodes,
                    "Patched MachineDeployment autoscaler annotations"
                );
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(
                    md = %md_name,
                    "MachineDeployment not found, skipping (may not exist yet)"
                );
            }
            Err(e) => {
                warn!(
                    md = %md_name,
                    error = %e,
                    "Failed to patch MachineDeployment"
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn md_name_format() {
        let name = format!("{}-pool-{}", "my-cluster", "gpu");
        assert_eq!(name, "my-cluster-pool-gpu");
    }
}
