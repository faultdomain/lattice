//! Cluster route reconciler — single writer for LatticeClusterRoutes CRDs
//!
//! Receives route updates from agent heartbeats via a channel and writes
//! them to `LatticeClusterRoutes` CRDs. Single writer eliminates TOCTOU
//! races from concurrent agent heartbeats.

use std::collections::HashMap;

use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use lattice_common::crd::{ClusterRoute, LatticeClusterRoutes, LatticeClusterRoutesSpec};

/// A route update received from an agent heartbeat
pub struct RouteUpdate {
    /// Cluster name that owns these routes
    pub cluster_name: String,
    /// Routes advertised by the cluster (full replacement)
    pub routes: Vec<ClusterRoute>,
}

/// Channel sender for route updates
pub type RouteUpdateSender = mpsc::Sender<RouteUpdate>;

/// Spawn the route reconciler task.
///
/// Returns a sender for submitting route updates. The reconciler runs until
/// the sender is dropped or the task is cancelled.
pub fn spawn_route_reconciler(client: Client) -> RouteUpdateSender {
    let (tx, rx) = mpsc::channel::<RouteUpdate>(256);
    tokio::spawn(run_route_reconciler(client, rx));
    tx
}

/// Run the route reconciler loop.
///
/// Receives route updates from the channel and writes them to the
/// `LatticeClusterRoutes` CRD. Multiple rapid updates for the same cluster
/// are naturally coalesced since each write is a full replacement.
async fn run_route_reconciler(client: Client, mut rx: mpsc::Receiver<RouteUpdate>) {
    let api: Api<LatticeClusterRoutes> = Api::all(client);
    // Track last-written state to skip no-op writes
    let mut last_written: HashMap<String, Vec<ClusterRoute>> = HashMap::new();

    info!("Route reconciler started");

    while let Some(update) = rx.recv().await {
        // Skip if routes haven't changed
        if let Some(prev) = last_written.get(&update.cluster_name) {
            if *prev == update.routes {
                continue;
            }
        }

        let route_count = update.routes.len() as u32;

        let route_table = LatticeClusterRoutes::new(
            &update.cluster_name,
            LatticeClusterRoutesSpec {
                routes: update.routes.clone(),
            },
        );

        let applied = match api
            .patch(
                &update.cluster_name,
                &PatchParams::apply("lattice-cell"),
                &Patch::Apply(route_table),
            )
            .await
        {
            Ok(applied) => applied,
            Err(e) => {
                error!(
                    cluster = %update.cluster_name,
                    error = %e,
                    "failed to write LatticeClusterRoutes"
                );
                continue;
            }
        };

        let observed_generation = applied.metadata.generation;

        let status = serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeClusterRoutes",
            "metadata": { "name": update.cluster_name },
            "status": {
                "phase": "Ready",
                "routeCount": route_count,
                "lastUpdated": chrono::Utc::now().to_rfc3339(),
                "observedGeneration": observed_generation,
            }
        });

        if let Err(e) = api
            .patch_status(
                &update.cluster_name,
                &PatchParams::apply("lattice-cell"),
                &Patch::Apply(status),
            )
            .await
        {
            warn!(
                cluster = %update.cluster_name,
                error = %e,
                "failed to patch LatticeClusterRoutes status"
            );
        }

        last_written.insert(update.cluster_name.clone(), update.routes);

        info!(
            cluster = %update.cluster_name,
            routes = route_count,
            "reconciled LatticeClusterRoutes"
        );
    }

    info!("Route reconciler stopped");
}
