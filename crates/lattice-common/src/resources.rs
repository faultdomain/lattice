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

/// Error returned when a Kubernetes resource quantity string cannot be parsed.
#[derive(Debug, thiserror::Error)]
#[error("invalid resource quantity: {0}")]
pub struct QuantityParseError(pub String);

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

/// Parse a CPU quantity string to millicores.
///
/// Handles formats: `"1"` (cores), `"500m"` (millicores), `"1.5"` (fractional cores).
pub fn parse_cpu_millis_str(s: &str) -> Result<i64, QuantityParseError> {
    if let Some(millis) = s.strip_suffix('m') {
        millis
            .parse::<i64>()
            .map_err(|_| QuantityParseError(s.to_string()))
    } else {
        s.parse::<f64>()
            .map(|cores| (cores * 1000.0) as i64)
            .map_err(|_| QuantityParseError(s.to_string()))
    }
}

/// Parse a Kubernetes CPU `Quantity` to millicores.
///
/// Returns `Ok(0)` for `None` (no request = zero allocation).
pub fn parse_cpu_millis(quantity: Option<&Quantity>) -> Result<i64, QuantityParseError> {
    match quantity {
        Some(q) => parse_cpu_millis_str(&q.0),
        None => Ok(0),
    }
}

/// Parse a memory quantity string to bytes.
///
/// Handles binary suffixes (`Ki`, `Mi`, `Gi`, `Ti`), decimal suffixes
/// (`k`, `M`, `G`, `T`), and plain byte values.
pub fn parse_memory_bytes_str(s: &str) -> Result<i64, QuantityParseError> {
    let err = || QuantityParseError(s.to_string());
    let parse = |v: &str| v.parse::<i64>().map_err(|_| err());

    if let Some(v) = s.strip_suffix("Ki") {
        return Ok(parse(v)? * 1024);
    }
    if let Some(v) = s.strip_suffix("Mi") {
        return Ok(parse(v)? * 1024 * 1024);
    }
    if let Some(v) = s.strip_suffix("Gi") {
        return Ok(parse(v)? * 1024 * 1024 * 1024);
    }
    if let Some(v) = s.strip_suffix("Ti") {
        return Ok(parse(v)? * 1024 * 1024 * 1024 * 1024);
    }
    if let Some(v) = s.strip_suffix('G') {
        return Ok(parse(v)? * 1_000_000_000);
    }
    if let Some(v) = s.strip_suffix('M') {
        return Ok(parse(v)? * 1_000_000);
    }
    if let Some(v) = s.strip_suffix('k') {
        return Ok(parse(v)? * 1_000);
    }
    if let Some(v) = s.strip_suffix('T') {
        return Ok(parse(v)? * 1_000_000_000_000);
    }
    parse(s)
}

/// Parse a Kubernetes memory `Quantity` to bytes.
///
/// Returns `Ok(0)` for `None` (no request = zero allocation).
pub fn parse_memory_bytes(quantity: Option<&Quantity>) -> Result<i64, QuantityParseError> {
    match quantity {
        Some(q) => parse_memory_bytes_str(&q.0),
        None => Ok(0),
    }
}

/// Parse a Kubernetes quantity as a plain integer (for GPU counts).
///
/// Returns `Ok(0)` for `None`.
pub fn parse_quantity_int(quantity: Option<&Quantity>) -> Result<i64, QuantityParseError> {
    match quantity {
        Some(q) => q
            .0
            .parse::<i64>()
            .map_err(|_| QuantityParseError(q.0.clone())),
        None => Ok(0),
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
                pool.node_cpu_millis = parse_cpu_millis(allocatable.get("cpu"))
                    .unwrap_or_else(|e| { warn!(error = %e, "failed to parse node CPU allocatable"); 0 });
                pool.node_memory_bytes = parse_memory_bytes(allocatable.get("memory"))
                    .unwrap_or_else(|e| { warn!(error = %e, "failed to parse node memory allocatable"); 0 });
                pool.node_gpu_count = parse_quantity_int(allocatable.get(GPU_RESOURCE))
                    .unwrap_or_else(|e| { warn!(error = %e, "failed to parse node GPU allocatable"); 0 }) as u32;
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
            pool.allocated_cpu_millis += parse_cpu_millis(requests.get("cpu"))
                .unwrap_or_else(|e| { warn!(error = %e, "failed to parse pod CPU request"); 0 });
            pool.allocated_memory_bytes += parse_memory_bytes(requests.get("memory"))
                .unwrap_or_else(|e| { warn!(error = %e, "failed to parse pod memory request"); 0 });
            pool.allocated_gpu_count += parse_quantity_int(requests.get(GPU_RESOURCE))
                .unwrap_or_else(|e| { warn!(error = %e, "failed to parse pod GPU request"); 0 }) as u32;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_whole_cores() {
        assert_eq!(parse_cpu_millis(Some(&Quantity("4".into()))).unwrap(), 4000);
    }

    #[test]
    fn cpu_millicores() {
        assert_eq!(parse_cpu_millis(Some(&Quantity("500m".into()))).unwrap(), 500);
    }

    #[test]
    fn cpu_fractional() {
        assert_eq!(parse_cpu_millis(Some(&Quantity("1.5".into()))).unwrap(), 1500);
    }

    #[test]
    fn cpu_none() {
        assert_eq!(parse_cpu_millis(None).unwrap(), 0);
    }

    #[test]
    fn cpu_invalid() {
        assert!(parse_cpu_millis_str("abc").is_err());
        assert!(parse_cpu_millis_str("xm").is_err());
    }

    #[test]
    fn memory_gi() {
        assert_eq!(
            parse_memory_bytes(Some(&Quantity("16Gi".into()))).unwrap(),
            16 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn memory_mi() {
        assert_eq!(
            parse_memory_bytes(Some(&Quantity("512Mi".into()))).unwrap(),
            512 * 1024 * 1024
        );
    }

    #[test]
    fn memory_plain_bytes() {
        assert_eq!(
            parse_memory_bytes(Some(&Quantity("1073741824".into()))).unwrap(),
            1073741824
        );
    }

    #[test]
    fn memory_decimal_g() {
        assert_eq!(
            parse_memory_bytes(Some(&Quantity("2G".into()))).unwrap(),
            2_000_000_000
        );
    }

    #[test]
    fn memory_none() {
        assert_eq!(parse_memory_bytes(None).unwrap(), 0);
    }

    #[test]
    fn memory_invalid() {
        assert!(parse_memory_bytes_str("abcGi").is_err());
        assert!(parse_memory_bytes_str("xyz").is_err());
    }

    #[test]
    fn gpu_count() {
        assert_eq!(parse_quantity_int(Some(&Quantity("8".into()))).unwrap(), 8);
    }

    #[test]
    fn gpu_none() {
        assert_eq!(parse_quantity_int(None).unwrap(), 0);
    }

    #[test]
    fn gpu_invalid() {
        assert!(parse_quantity_int(Some(&Quantity("abc".into()))).is_err());
    }
}
