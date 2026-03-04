//! Kubernetes resource quantity parsing, node helpers, and pool resource gathering.
//!
//! Shared by both the agent (heartbeat health gathering) and the cluster
//! controller (status reporting). One place for node classification, quantity
//! parsing, and per-pool capacity collection.

use std::collections::HashMap;

use k8s_openapi::api::core::v1::{Node, Pod};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use tracing::warn;

use crate::crd::PoolResourceSummary;

/// Label key that identifies which worker pool a node belongs to.
pub const POOL_LABEL: &str = "lattice.dev/pool";

/// GPU resource name in Kubernetes.
pub const GPU_RESOURCE: &str = "nvidia.com/gpu";

/// NFD label for GPU product type.
pub const GPU_TYPE_LABEL: &str = "nvidia.com/gpu.product";

// ---------------------------------------------------------------------------
// Node helpers
// ---------------------------------------------------------------------------

/// Check if a node is a control plane node based on labels.
pub fn is_control_plane_node(node: &Node) -> bool {
    node.metadata
        .labels
        .as_ref()
        .map(|l| l.contains_key("node-role.kubernetes.io/control-plane"))
        .unwrap_or(false)
}

/// Check if a node has the Ready condition set to True.
pub fn is_node_ready(node: &Node) -> bool {
    node.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .map(|conds| {
            conds
                .iter()
                .any(|c| c.type_ == "Ready" && c.status == "True")
        })
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Quantity parsing
// ---------------------------------------------------------------------------

/// Parse a Kubernetes CPU quantity to millicores.
///
/// Handles formats: `"1"` (cores), `"500m"` (millicores), `"1.5"` (fractional cores).
pub fn parse_cpu_millis(quantity: Option<&Quantity>) -> i64 {
    let s = match quantity {
        Some(q) => &q.0,
        None => return 0,
    };

    if let Some(millis) = s.strip_suffix('m') {
        millis.parse::<i64>().unwrap_or(0)
    } else if let Ok(cores) = s.parse::<f64>() {
        (cores * 1000.0) as i64
    } else {
        0
    }
}

/// Parse a Kubernetes memory quantity to bytes.
///
/// Handles binary suffixes (`Ki`, `Mi`, `Gi`, `Ti`), decimal suffixes
/// (`k`, `M`, `G`, `T`), and plain byte values.
pub fn parse_memory_bytes(quantity: Option<&Quantity>) -> i64 {
    let s = match quantity {
        Some(q) => &q.0,
        None => return 0,
    };

    if let Some(v) = s.strip_suffix("Ki") {
        return v.parse::<i64>().unwrap_or(0) * 1024;
    }
    if let Some(v) = s.strip_suffix("Mi") {
        return v.parse::<i64>().unwrap_or(0) * 1024 * 1024;
    }
    if let Some(v) = s.strip_suffix("Gi") {
        return v.parse::<i64>().unwrap_or(0) * 1024 * 1024 * 1024;
    }
    if let Some(v) = s.strip_suffix("Ti") {
        return v.parse::<i64>().unwrap_or(0) * 1024 * 1024 * 1024 * 1024;
    }
    if let Some(v) = s.strip_suffix('G') {
        return v.parse::<i64>().unwrap_or(0) * 1_000_000_000;
    }
    if let Some(v) = s.strip_suffix('M') {
        return v.parse::<i64>().unwrap_or(0) * 1_000_000;
    }
    if let Some(v) = s.strip_suffix('k') {
        return v.parse::<i64>().unwrap_or(0) * 1_000;
    }
    if let Some(v) = s.strip_suffix('T') {
        return v.parse::<i64>().unwrap_or(0) * 1_000_000_000_000;
    }

    s.parse::<i64>().unwrap_or(0)
}

/// Parse a Kubernetes quantity as a plain integer (for GPU counts).
pub fn parse_quantity_int(quantity: Option<&Quantity>) -> i64 {
    match quantity {
        Some(q) => q.0.parse::<i64>().unwrap_or(0),
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Per-pool resource gathering
// ---------------------------------------------------------------------------

/// Gather per-pool resource capacity from nodes and pods.
///
/// Groups worker nodes by the `lattice.dev/pool` label, reads allocatable
/// resources for the per-node shape, then sums pod resource requests across
/// each pool for allocation data.
pub async fn gather_pool_resources(client: &kube::Client) -> Vec<PoolResourceSummary> {
    let node_api: kube::Api<Node> = kube::Api::all(client.clone());
    let nodes = match node_api.list(&Default::default()).await {
        Ok(list) => list.items,
        Err(e) => {
            warn!(error = %e, "Failed to list nodes for pool resource gathering");
            return vec![];
        }
    };

    let mut pools: HashMap<String, PoolAcc> = HashMap::new();

    for node in &nodes {
        if is_control_plane_node(node) {
            continue;
        }

        let labels = node.metadata.labels.as_ref();
        let pool_name = match labels.and_then(|l| l.get(POOL_LABEL)) {
            Some(p) => p,
            None => continue,
        };

        let pool = pools.entry(pool_name.clone()).or_default();
        pool.total_nodes += 1;
        if is_node_ready(node) {
            pool.ready_nodes += 1;
        }

        // Use the first node's allocatable as the per-node shape
        // (all nodes in a pool have the same instance type)
        if let Some(allocatable) = node.status.as_ref().and_then(|s| s.allocatable.as_ref()) {
            if pool.node_cpu_millis == 0 {
                pool.node_cpu_millis = parse_cpu_millis(allocatable.get("cpu"));
                pool.node_memory_bytes = parse_memory_bytes(allocatable.get("memory"));
                pool.node_gpu_count = parse_quantity_int(allocatable.get(GPU_RESOURCE)) as u32;
            }
        }

        if pool.gpu_type.is_empty() {
            if let Some(gt) = labels.and_then(|l| l.get(GPU_TYPE_LABEL)) {
                pool.gpu_type = gt.clone();
            } else if pool.node_gpu_count > 0 {
                pool.gpu_type = "unknown".to_string();
            }
        }
    }

    if !pools.is_empty() {
        gather_pod_allocations(client, &nodes, &mut pools).await;
    }

    pools
        .into_iter()
        .map(|(name, acc)| acc.into_summary(name))
        .collect()
}

#[derive(Default)]
struct PoolAcc {
    ready_nodes: u32,
    total_nodes: u32,
    node_cpu_millis: i64,
    node_memory_bytes: i64,
    node_gpu_count: u32,
    gpu_type: String,
    allocated_cpu_millis: i64,
    allocated_memory_bytes: i64,
    allocated_gpu_count: u32,
}

impl PoolAcc {
    fn into_summary(self, pool_name: String) -> PoolResourceSummary {
        PoolResourceSummary {
            pool_name,
            ready_nodes: self.ready_nodes,
            total_nodes: self.total_nodes,
            node_cpu_millis: self.node_cpu_millis,
            node_memory_bytes: self.node_memory_bytes,
            node_gpu_count: self.node_gpu_count,
            gpu_type: self.gpu_type,
            allocated_cpu_millis: self.allocated_cpu_millis,
            allocated_memory_bytes: self.allocated_memory_bytes,
            allocated_gpu_count: self.allocated_gpu_count,
        }
    }
}

/// Sum pod resource requests and attribute them to pools by node assignment.
async fn gather_pod_allocations(
    client: &kube::Client,
    nodes: &[Node],
    pools: &mut HashMap<String, PoolAcc>,
) {
    let node_pool_map: HashMap<String, String> = nodes
        .iter()
        .filter_map(|n| {
            let name = n.metadata.name.as_ref()?;
            let pool = n.metadata.labels.as_ref()?.get(POOL_LABEL)?;
            Some((name.clone(), pool.clone()))
        })
        .collect();

    let pod_api: kube::Api<Pod> = kube::Api::all(client.clone());
    let pod_list = match pod_api.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            warn!(error = %e, "Failed to list pods for allocation gathering");
            return;
        }
    };

    for pod in &pod_list.items {
        let phase = pod
            .status
            .as_ref()
            .and_then(|s| s.phase.as_deref())
            .unwrap_or("");
        if phase == "Succeeded" || phase == "Failed" {
            continue;
        }

        let pool_name = match pod
            .spec
            .as_ref()
            .and_then(|s| s.node_name.as_ref())
            .and_then(|n| node_pool_map.get(n))
        {
            Some(p) => p.clone(),
            None => continue,
        };

        let pool = match pools.get_mut(&pool_name) {
            Some(p) => p,
            None => continue,
        };

        if let Some(spec) = &pod.spec {
            sum_container_requests(&spec.containers, pool);
            if let Some(init_containers) = &spec.init_containers {
                sum_container_requests(init_containers, pool);
            }
        }
    }
}

/// Sum resource requests from a slice of containers into a pool accumulator.
fn sum_container_requests(
    containers: &[k8s_openapi::api::core::v1::Container],
    pool: &mut PoolAcc,
) {
    for container in containers {
        if let Some(requests) = container
            .resources
            .as_ref()
            .and_then(|r| r.requests.as_ref())
        {
            pool.allocated_cpu_millis += parse_cpu_millis(requests.get("cpu"));
            pool.allocated_memory_bytes += parse_memory_bytes(requests.get("memory"));
            pool.allocated_gpu_count += parse_quantity_int(requests.get(GPU_RESOURCE)) as u32;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_whole_cores() {
        assert_eq!(parse_cpu_millis(Some(&Quantity("4".into()))), 4000);
    }

    #[test]
    fn cpu_millicores() {
        assert_eq!(parse_cpu_millis(Some(&Quantity("500m".into()))), 500);
    }

    #[test]
    fn cpu_fractional() {
        assert_eq!(parse_cpu_millis(Some(&Quantity("1.5".into()))), 1500);
    }

    #[test]
    fn cpu_none() {
        assert_eq!(parse_cpu_millis(None), 0);
    }

    #[test]
    fn memory_gi() {
        assert_eq!(
            parse_memory_bytes(Some(&Quantity("16Gi".into()))),
            16 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn memory_mi() {
        assert_eq!(
            parse_memory_bytes(Some(&Quantity("512Mi".into()))),
            512 * 1024 * 1024
        );
    }

    #[test]
    fn memory_plain_bytes() {
        assert_eq!(
            parse_memory_bytes(Some(&Quantity("1073741824".into()))),
            1073741824
        );
    }

    #[test]
    fn memory_decimal_g() {
        assert_eq!(
            parse_memory_bytes(Some(&Quantity("2G".into()))),
            2_000_000_000
        );
    }

    #[test]
    fn memory_none() {
        assert_eq!(parse_memory_bytes(None), 0);
    }

    #[test]
    fn gpu_count() {
        assert_eq!(parse_quantity_int(Some(&Quantity("8".into()))), 8);
    }

    #[test]
    fn gpu_none() {
        assert_eq!(parse_quantity_int(None), 0);
    }
}
