//! Peer route synchronization — pushes sibling routes to children
//!
//! When a child's routes change, the parent pushes all other children's routes
//! to it as a `PeerRouteSync` command. This enables sibling-to-sibling service
//! discovery: each child's istiod creates remote secrets pointing to the parent's
//! auth proxy, which tunnels K8s API requests to the target sibling via gRPC.

use kube::Client;
use tracing::{debug, error, warn};

use lattice_proto::cell_command::Command;
use lattice_proto::{CellCommand, PeerRouteSync, SubtreeService};

use crate::SharedAgentRegistry;

/// Build peer routes for a specific child cluster.
///
/// Returns all routes from all clusters EXCEPT the specified child's own routes.
/// Includes the parent's routes and sibling routes — the child already knows
/// its own routes and only needs peers'.
pub fn peer_routes_for(
    all_routes: &[SubtreeService],
    exclude_cluster: &str,
) -> Vec<SubtreeService> {
    all_routes
        .iter()
        .filter(|r| r.cluster != exclude_cluster && !r.removed)
        .cloned()
        .collect()
}

use lattice_common::kube_utils::request_istiod_proxy_token;

/// Send a `PeerRouteSync` to a specific child with its peer routes.
pub async fn send_peer_routes(
    registry: &SharedAgentRegistry,
    child_cluster: &str,
    sibling_routes: Vec<SubtreeService>, // named sibling for the local variable, includes parent
    proxy_url: &str,
    ca_cert_pem: &str,
    proxy_token: &str,
    is_full_sync: bool,
) {
    let sync = PeerRouteSync {
        proxy_url: proxy_url.to_string(),
        ca_cert_pem: ca_cert_pem.to_string(),
        proxy_token: proxy_token.to_string(),
        peer_routes: sibling_routes,
        is_full_sync,
    };

    let cmd = CellCommand {
        command_id: format!("peer-routes-{}", child_cluster),
        command: Some(Command::PeerRouteSync(sync)),
    };

    if let Err(e) = registry.send_command(child_cluster, cmd).await {
        warn!(
            cluster = %child_cluster,
            error = %e,
            "Failed to send peer route sync"
        );
    } else {
        debug!(cluster = %child_cluster, "Sent peer route sync");
    }
}

/// Push sibling routes to all connected children.
///
/// Called when any child's routes change. Each child receives all routes
/// except its own. Requires a valid proxy token and the parent's external
/// proxy URL.
pub async fn broadcast_peer_routes(
    registry: &SharedAgentRegistry,
    all_routes: &[SubtreeService],
    proxy_url: &str,
    ca_cert_pem: &str,
    client: &Client,
) {
    // No sibling routes to push if there's only one child or no routes
    if all_routes.is_empty() {
        return;
    }

    let proxy_token = match request_istiod_proxy_token(client).await {
        Ok(t) => t,
        Err(e) => {
            error!(error = %e, "Failed to request proxy token for peer route sync");
            return;
        }
    };

    let connected = registry.connected_cluster_names();
    for child in &connected {
        let peers = peer_routes_for(all_routes, child);
        if peers.is_empty() {
            continue;
        }
        send_peer_routes(
            registry,
            child,
            peers,
            proxy_url,
            ca_cert_pem,
            &proxy_token,
            true,
        )
        .await;
    }
}
