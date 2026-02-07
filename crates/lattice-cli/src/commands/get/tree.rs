//! Cluster tree discovery from kubeconfig contexts
//!
//! Reads all contexts from the kubeconfig, connects to each, lists LatticeCluster
//! CRDs, and builds a tree based on which clusters have `parent_config` (are parents)
//! and which child CRDs exist on parent clusters.
//!
//! For proxy kubeconfigs (server URLs with `/clusters/` path on localhost), the
//! discovery automatically starts a `kubectl port-forward` if the proxy is
//! unreachable.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use kube::api::ListParams;
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::Api;
use lattice_common::crd::{LatticeCluster, LatticeClusterStatus};
use serde::Serialize;
use tracing::{debug, info, warn};

use crate::commands::port_forward::{check_health, PortForward};
use crate::{Error, Result};

/// A discovered cluster with its metadata
#[derive(Clone, Debug, Serialize)]
pub struct ClusterInfo {
    pub name: String,
    pub phase: String,
    pub provider: String,
    pub k8s_version: String,
    pub control_plane_ready: u32,
    pub control_plane_total: u32,
    pub workers_ready: u32,
    pub workers_total: u32,
    pub is_parent: bool,
    pub connected: bool,
    pub endpoint: Option<String>,
    pub creation_timestamp: Option<DateTime<Utc>>,
    pub message: Option<String>,
    pub pivot_complete: bool,
    pub bootstrap_complete: bool,
    pub conditions: Vec<ConditionInfo>,
    pub worker_pools: HashMap<String, WorkerPoolInfo>,
    /// The kubeconfig context this cluster was discovered from
    pub context: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConditionInfo {
    pub type_: String,
    pub status: String,
    pub reason: String,
    pub message: String,
    pub last_transition_time: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WorkerPoolInfo {
    pub desired_replicas: u32,
    pub ready_replicas: u32,
    pub autoscaling_enabled: bool,
    pub message: Option<String>,
}

/// The full cluster tree discovered from kubeconfig
#[derive(Clone, Debug, Serialize)]
pub struct ClusterTree {
    /// All discovered clusters keyed by name
    pub clusters: HashMap<String, ClusterInfo>,
    /// Parent name -> list of child cluster names (children are CRDs on that parent)
    pub children: HashMap<String, Vec<String>>,
    /// Root clusters (clusters that are not children of any other cluster)
    pub roots: Vec<String>,
}

impl ClusterTree {
    /// Compute the depth of a cluster in the tree (0 = root)
    pub fn depth(&self, name: &str) -> usize {
        for (parent, kids) in &self.children {
            if kids.iter().any(|k| k == name) {
                return 1 + self.depth(parent);
            }
        }
        0
    }

    /// Get children of a cluster
    pub fn children_of(&self, name: &str) -> &[String] {
        self.children.get(name).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// Discover all clusters from kubeconfig contexts.
///
/// For each context, connects and lists LatticeCluster CRDs. Builds the tree
/// by identifying which clusters are parents (have children CRDs on them) vs
/// leaf clusters.
///
/// Uses the kubeconfig resolution chain (explicit path > `LATTICE_KUBECONFIG` >
/// `~/.lattice/kubeconfig` > kube defaults).
///
/// Returns `(tree, Option<PortForward>)`. If a proxy kubeconfig is detected
/// and the proxy is unreachable, a port-forward is automatically started and
/// returned. The caller must hold this guard to keep the port-forward alive.
pub async fn discover_tree(
    explicit_kubeconfig: Option<&str>,
) -> Result<(ClusterTree, Option<PortForward>)> {
    let (kubeconfig, port_forward) = crate::commands::load_kubeconfig(explicit_kubeconfig).await?;

    let contexts: Vec<String> = kubeconfig
        .contexts
        .iter()
        .filter_map(|c| c.name.clone().into())
        .collect();

    if contexts.is_empty() {
        return Err(Error::command_failed("no contexts found in kubeconfig"));
    }

    // For each context, list LatticeCluster CRDs
    // A parent cluster will have its own CRD + child CRDs
    // A leaf cluster will have only its own CRD (the "self" cluster)
    let mut all_clusters: HashMap<String, ClusterInfo> = HashMap::new();
    // Track which clusters appear as CRDs on which context
    // context_name -> Vec<cluster_name>
    let mut crds_per_context: HashMap<String, Vec<String>> = HashMap::new();
    // Track the "self" cluster for each context (the one with parent_config or the only one)
    let mut self_cluster_for_context: HashMap<String, String> = HashMap::new();

    for ctx_name in &contexts {
        debug!("Discovering clusters from context: {}", ctx_name);

        let client = match client_for_context(&kubeconfig, ctx_name).await {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to connect to context {}: {}", ctx_name, e);
                continue;
            }
        };

        let api: Api<LatticeCluster> = Api::all(client);
        let clusters = match api.list(&ListParams::default()).await {
            Ok(list) => list.items,
            Err(e) => {
                warn!(
                    "Failed to list LatticeCluster CRDs in context {}: {}",
                    ctx_name, e
                );
                continue;
            }
        };

        if clusters.is_empty() {
            debug!("No LatticeCluster CRDs in context {}", ctx_name);
            continue;
        }

        let mut context_cluster_names = Vec::new();

        for cluster in &clusters {
            let name = cluster.metadata.name.clone().unwrap_or_default();
            context_cluster_names.push(name.clone());

            let status = cluster.status.as_ref();
            let default_status = LatticeClusterStatus::default();
            let st = status.unwrap_or(&default_status);

            let info = ClusterInfo {
                name: name.clone(),
                phase: st.phase.to_string(),
                provider: cluster.spec.provider.provider_type().to_string(),
                k8s_version: cluster.spec.provider.kubernetes.version.clone(),
                control_plane_total: cluster.spec.nodes.control_plane,
                control_plane_ready: st.ready_control_plane.unwrap_or(0),
                workers_total: cluster.spec.nodes.total_workers(),
                workers_ready: st.ready_workers.unwrap_or(0),
                is_parent: cluster.spec.is_parent(),
                connected: true,
                endpoint: st.endpoint.clone(),
                creation_timestamp: cluster.metadata.creation_timestamp.as_ref().map(|t| t.0),
                message: st.message.clone(),
                pivot_complete: st.pivot_complete,
                bootstrap_complete: st.bootstrap_complete,
                conditions: st
                    .conditions
                    .iter()
                    .map(|c| ConditionInfo {
                        type_: c.type_.clone(),
                        status: c.status.to_string(),
                        reason: c.reason.clone(),
                        message: c.message.clone(),
                        last_transition_time: c.last_transition_time,
                    })
                    .collect(),
                worker_pools: st
                    .worker_pools
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            WorkerPoolInfo {
                                desired_replicas: v.desired_replicas,
                                ready_replicas: v.ready_replicas,
                                autoscaling_enabled: v.autoscaling_enabled,
                                message: v.message.clone(),
                            },
                        )
                    })
                    .collect(),
                context: ctx_name.clone(),
            };

            all_clusters.insert(name, info);
        }

        // Identify the "self" cluster for this context:
        // - If there's exactly one cluster, that's the self cluster
        // - If there's a cluster with parent_config, that's the self cluster (it's the parent)
        // - Child CRDs on a parent context are the non-self clusters
        let self_cluster = if clusters.len() == 1 {
            clusters[0].metadata.name.clone().unwrap_or_default()
        } else {
            // The self cluster is the one with parent_config
            clusters
                .iter()
                .find(|c| c.spec.is_parent())
                .and_then(|c| c.metadata.name.clone())
                .unwrap_or_else(|| clusters[0].metadata.name.clone().unwrap_or_default())
        };

        self_cluster_for_context.insert(ctx_name.clone(), self_cluster);
        crds_per_context.insert(ctx_name.clone(), context_cluster_names);
    }

    // Build parent -> children relationships
    // A child cluster is one that appears as a CRD on a parent's context but is NOT the self cluster
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    let mut all_children: Vec<String> = Vec::new();

    for (ctx_name, crd_names) in &crds_per_context {
        if let Some(self_name) = self_cluster_for_context.get(ctx_name) {
            let child_names: Vec<String> = crd_names
                .iter()
                .filter(|n| *n != self_name)
                .cloned()
                .collect();

            if !child_names.is_empty() {
                all_children.extend(child_names.clone());
                children.insert(self_name.clone(), child_names);
            }
        }
    }

    // Roots are clusters that are not children of any other cluster
    let roots: Vec<String> = all_clusters
        .keys()
        .filter(|name| !all_children.contains(name))
        .cloned()
        .collect();

    Ok((
        ClusterTree {
            clusters: all_clusters,
            children,
            roots,
        },
        port_forward,
    ))
}

/// Build a kube Client for a specific kubeconfig context.
async fn client_for_context(kubeconfig: &Kubeconfig, context: &str) -> Result<kube::Client> {
    let options = KubeConfigOptions {
        context: Some(context.to_string()),
        ..Default::default()
    };
    crate::commands::kube_client_from_kubeconfig(kubeconfig.clone(), &options).await
}

/// Detect proxy kubeconfigs and start a port-forward if the proxy is unreachable.
///
/// A proxy kubeconfig has server URLs like `https://127.0.0.1:PORT/clusters/NAME`.
/// When the port is dead (e.g. the generating process exited), we extract the
/// management kubeconfig path from the exec credential args, start a new
/// port-forward, and rewrite the server URLs in place.
async fn maybe_start_proxy_port_forward(kubeconfig: &mut Kubeconfig) -> Option<PortForward> {
    // Find the common proxy base URL from cluster entries
    let proxy_base = find_proxy_base_url(kubeconfig)?;

    // Check if the proxy is already reachable
    if check_health(&proxy_base, std::time::Duration::from_secs(2)).await {
        debug!(
            "Proxy at {} is reachable, no port-forward needed",
            proxy_base
        );
        return None;
    }

    info!(
        "Proxy at {} is unreachable, attempting auto port-forward",
        proxy_base
    );

    // Extract the management kubeconfig path from exec credential args
    let mgmt_kubeconfig = extract_mgmt_kubeconfig(kubeconfig)?;

    // Start a port-forward
    let pf =
        match PortForward::start(&mgmt_kubeconfig, lattice_common::DEFAULT_AUTH_PROXY_PORT).await {
            Ok(pf) => pf,
            Err(e) => {
                warn!("Failed to auto-start port-forward: {}", e);
                return None;
            }
        };

    // Rewrite all proxy server URLs to use the new port
    let new_base = &pf.url;
    rewrite_proxy_urls(kubeconfig, &proxy_base, new_base);
    info!("Rewrote proxy URLs from {} to {}", proxy_base, new_base);

    Some(pf)
}

/// Find the common proxy base URL (e.g. `https://127.0.0.1:49284`) from a kubeconfig.
///
/// Returns `Some(base_url)` if any cluster server URL matches the proxy pattern
/// (localhost with `/clusters/` path). Returns `None` for normal kubeconfigs.
fn find_proxy_base_url(kubeconfig: &Kubeconfig) -> Option<String> {
    for named_cluster in &kubeconfig.clusters {
        if let Some(ref cluster) = named_cluster.cluster {
            if let Some(ref server) = cluster.server {
                // Proxy URLs look like https://127.0.0.1:PORT/clusters/NAME
                if let Some(path_start) = server.find("/clusters/") {
                    let base = &server[..path_start];
                    if base.contains("127.0.0.1")
                        || base.contains("localhost")
                        || base.contains("[::1]")
                    {
                        return Some(base.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Extract the management kubeconfig path from exec credential args.
///
/// The proxy kubeconfig uses `lattice token --kubeconfig=<path>` as the exec
/// credential plugin. We parse the `--kubeconfig=` arg to find the management
/// cluster's kubeconfig.
fn extract_mgmt_kubeconfig(kubeconfig: &Kubeconfig) -> Option<String> {
    for auth in &kubeconfig.auth_infos {
        if let Some(ref info) = auth.auth_info {
            if let Some(ref exec) = info.exec {
                if let Some(ref args) = exec.args {
                    for arg in args {
                        if let Some(path) = arg.strip_prefix("--kubeconfig=") {
                            return Some(path.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Rewrite proxy server URLs from the old base to the new base.
///
/// E.g. `https://127.0.0.1:49284/clusters/foo` -> `https://127.0.0.1:55555/clusters/foo`
fn rewrite_proxy_urls(kubeconfig: &mut Kubeconfig, old_base: &str, new_base: &str) {
    for named_cluster in &mut kubeconfig.clusters {
        if let Some(ref mut cluster) = named_cluster.cluster {
            if let Some(ref mut server) = cluster.server {
                if server.starts_with(old_base) {
                    let path = &server[old_base.len()..];
                    *server = format!("{}{}", new_base, path);
                }
            }
        }
    }
}
