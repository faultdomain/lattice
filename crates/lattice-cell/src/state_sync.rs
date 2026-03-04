//! Hash-based state sync between child agents and parent cell.
//!
//! When a child's spec/status hashes change, the cell requests a full sync
//! and patches its local copy of the child's LatticeCluster CRD.

use kube::api::{Patch, PatchParams};
use kube::{Api, Client};
use tracing::{debug, warn};

use lattice_common::crd::{LatticeCluster, LatticeClusterSpec, LatticeClusterStatus};
use lattice_proto::StateSyncResponse;

/// Handle a StateSyncResponse from a child agent.
///
/// Deserializes the spec and status JSON, then patches the parent's local
/// copy of the child's LatticeCluster CRD. Best-effort: logs warnings on
/// failure but doesn't propagate errors.
pub async fn handle_state_sync_response(
    cluster_name: &str,
    sync: &StateSyncResponse,
    kube_client: &Client,
) {
    let spec: LatticeClusterSpec = match serde_json::from_slice(&sync.spec_json) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                cluster = %cluster_name,
                error = %e,
                "Failed to deserialize spec from state sync"
            );
            return;
        }
    };

    let status: LatticeClusterStatus = match serde_json::from_slice(&sync.status_json) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                cluster = %cluster_name,
                error = %e,
                "Failed to deserialize status from state sync"
            );
            return;
        }
    };

    let api: Api<LatticeCluster> = Api::all(kube_client.clone());

    // Patch spec
    let spec_patch = serde_json::json!({
        "spec": spec,
    });
    if let Err(e) = api
        .patch(
            cluster_name,
            &PatchParams::apply("lattice-state-sync"),
            &Patch::Merge(&spec_patch),
        )
        .await
    {
        warn!(
            cluster = %cluster_name,
            error = %e,
            "Failed to patch child cluster spec from state sync"
        );
        return;
    }

    // Patch status
    let status_patch = serde_json::json!({
        "status": status,
    });
    if let Err(e) = api
        .patch_status(
            cluster_name,
            &PatchParams::apply("lattice-state-sync"),
            &Patch::Merge(&status_patch),
        )
        .await
    {
        warn!(
            cluster = %cluster_name,
            error = %e,
            "Failed to patch child cluster status from state sync"
        );
        return;
    }

    debug!(
        cluster = %cluster_name,
        "Successfully synced child cluster spec + status"
    );
}
