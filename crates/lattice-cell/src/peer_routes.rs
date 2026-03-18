//! Peer route synchronization — pushes sibling/parent routes to children
//!
//! On each heartbeat, the parent compares the child's reported peer routes hash
//! with the expected hash. On mismatch, sends a full PeerRouteSync with all
//! routes the child doesn't own (parent + siblings).

use kube::Client;
use lattice_common::kube_utils::{request_istiod_proxy_token, sha256};
use tracing::{debug, error, info, warn};

use lattice_proto::cell_command::Command;
use lattice_proto::{CellCommand, PeerRouteSync, SubtreeService};

use crate::route_reconciler::TaggedRoute;
use crate::SharedAgentRegistry;

/// Convert tagged routes to proto, preserving the real source cluster name.
fn tagged_to_proto(routes: &[TaggedRoute]) -> Vec<SubtreeService> {
    routes
        .iter()
        .map(|(cluster, r)| SubtreeService {
            name: r.service_name.clone(),
            namespace: r.service_namespace.clone(),
            cluster: cluster.clone(),
            removed: false,
            hostname: r.hostname.clone(),
            address: r.address.clone(),
            port: r.port as u32,
            protocol: r.protocol.clone(),
            labels: Default::default(),
            allowed_services: r.allowed_services.clone(),
            service_ports: r.service_ports.iter().map(|(k, &v)| (k.clone(), v as u32)).collect(),
        })
        .collect()
}

/// Filter routes to exclude a specific cluster's own routes.
fn peer_routes_for(all: &[SubtreeService], exclude: &str) -> Vec<SubtreeService> {
    all.iter()
        .filter(|r| r.cluster != exclude && !r.removed)
        .cloned()
        .collect()
}

/// Compute the content hash for a set of peer routes.
///
/// Groups by cluster, sorts within each cluster by (namespace, name),
/// then hashes the sorted structure. Must match the agent-side hash.
fn hash_peer_routes(routes: &[SubtreeService]) -> Vec<u8> {
    use std::collections::BTreeMap;

    let mut by_cluster: BTreeMap<String, Vec<&SubtreeService>> = BTreeMap::new();
    for svc in routes {
        by_cluster.entry(svc.cluster.clone()).or_default().push(svc);
    }

    let mut per_cluster: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (cluster, mut svcs) in by_cluster {
        svcs.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
        let mut buf = Vec::new();
        for s in svcs {
            buf.extend_from_slice(s.name.as_bytes());
            buf.extend_from_slice(s.namespace.as_bytes());
            buf.extend_from_slice(s.hostname.as_bytes());
            buf.extend_from_slice(s.address.as_bytes());
            buf.extend_from_slice(&(s.port as u16).to_le_bytes());
            buf.extend_from_slice(s.protocol.as_bytes());
            for allowed in &s.allowed_services {
                buf.extend_from_slice(allowed.as_bytes());
            }
            // BTreeMap iteration is sorted by key
            for (name, port) in &s.service_ports {
                buf.extend_from_slice(name.as_bytes());
                buf.extend_from_slice(&(*port as u16).to_le_bytes());
            }
        }
        per_cluster.insert(cluster, sha256(&buf));
    }

    let mut outer = Vec::new();
    for (name, h) in &per_cluster {
        outer.extend_from_slice(name.as_bytes());
        outer.extend_from_slice(h);
    }
    sha256(&outer)
}

/// Max age before forcing a peer route resync for token refresh.
/// Set to 25 minutes — well under the 1-hour token lifetime.
const PEER_SYNC_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(25 * 60);

/// Check if a child's peer routes are stale and send a full sync if needed.
///
/// Called on every heartbeat. Sends a PeerRouteSync if:
/// - The child's reported hash doesn't match the expected hash, OR
/// - The last sync was more than 25 minutes ago (token refresh)
pub async fn check_and_sync_peer_routes(
    registry: &SharedAgentRegistry,
    child_cluster: &str,
    child_hash: &[u8],
    peer_config: &crate::server::PeerRouteConfig,
    client: &Client,
) {
    let tagged_routes = peer_config.all_routes.borrow().clone();
    let all_proto = tagged_to_proto(&tagged_routes);
    let peers = peer_routes_for(&all_proto, child_cluster);

    if peers.is_empty() {
        return;
    }

    let expected_hash = hash_peer_routes(&peers);
    let hash_matches = child_hash == expected_hash;
    let token_fresh = !registry.needs_peer_sync(child_cluster, PEER_SYNC_MAX_AGE);

    if hash_matches && token_fresh {
        return;
    }

    if !hash_matches {
        info!(cluster = %child_cluster, "Peer routes hash mismatch, sending full sync");
    } else {
        debug!(cluster = %child_cluster, "Refreshing peer proxy token");
    }

    let proxy_token = match request_istiod_proxy_token(client).await {
        Ok(t) => t,
        Err(e) => {
            error!(error = %e, "Failed to request proxy token for peer route sync");
            return;
        }
    };

    let sync = PeerRouteSync {
        proxy_url: peer_config.proxy_url.clone(),
        ca_cert_pem: peer_config.ca_cert_pem.clone(),
        proxy_token,
        peer_routes: peers,
        is_full_sync: true,
    };

    let cmd = CellCommand {
        command_id: format!("peer-routes-{}", child_cluster),
        command: Some(Command::PeerRouteSync(sync)),
    };

    if let Err(e) = registry.send_command(child_cluster, cmd).await {
        warn!(cluster = %child_cluster, error = %e, "Failed to send peer route sync");
    } else {
        registry.mark_peer_sync(child_cluster);
        debug!(cluster = %child_cluster, "Sent peer route sync");
    }
}
