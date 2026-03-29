//! Quota controller for Lattice
//!
//! Owns the `LatticeQuota` CRD lifecycle and drives CAPI autoscaling:
//!
//! - Validates quota specs and tracks per-principal resource usage in status
//! - Computes aggregate hard/soft limits across all quotas on the cluster
//! - Translates quota sums into MachineDeployment min/max annotations
//! - Pool-level `min`/`max` overrides always win over quota-derived values
//!
//! Soft quotas define the burst ceiling (autoscaler max). Hard quotas define
//! guaranteed reserved capacity (autoscaler min). Soft-only quotas allow
//! scale-to-zero; hard quotas keep nodes provisioned even when idle.

#![deny(missing_docs)]

mod budget;
mod capacity;
mod controller;
pub mod solver;
mod store;

pub use budget::QuotaBudget;
pub use controller::{reconcile, QuotaContext};
pub use store::{channel as quota_channel, QuotaSender, QuotaSnapshot, QuotaStore};

use std::collections::BTreeMap;

use kube::api::Api;
use lattice_common::crd::LatticeQuota;
use lattice_common::LATTICE_SYSTEM_NAMESPACE;

use lattice_common::resources::{
    WorkloadResourceDemand, CPU_RESOURCE, GPU_RESOURCE, MEMORY_RESOURCE,
};

/// Fetch all enabled quotas from `lattice-system` namespace.
///
/// Returns an empty vec on failure (quota enforcement is best-effort —
/// if the API is unreachable, compilation proceeds without quota checks).
pub async fn fetch_quotas(client: &kube::Client) -> Vec<LatticeQuota> {
    let api: Api<LatticeQuota> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    match api.list(&Default::default()).await {
        Ok(list) => list.items.into_iter().filter(|q| q.spec.enabled).collect(),
        Err(e) => {
            tracing::debug!(error = %e, "Failed to list quotas, skipping enforcement");
            Vec::new()
        }
    }
}

/// Fetch labels for a namespace. Returns empty map on failure.
pub async fn fetch_namespace_labels(
    client: &kube::Client,
    namespace: &str,
) -> BTreeMap<String, String> {
    let api: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());
    match api.get(namespace).await {
        Ok(ns) => ns.metadata.labels.unwrap_or_default(),
        Err(_) => BTreeMap::new(),
    }
}

/// Format a raw resource value for human-readable display.
pub fn format_resource_value(key: &str, value: i64) -> String {
    match key {
        CPU_RESOURCE => {
            if value % 1000 == 0 {
                format!("{}", value / 1000)
            } else {
                format!("{}m", value)
            }
        }
        MEMORY_RESOURCE => {
            if value % (1024 * 1024 * 1024) == 0 {
                format!("{}Gi", value / (1024 * 1024 * 1024))
            } else if value % (1024 * 1024) == 0 {
                format!("{}Mi", value / (1024 * 1024))
            } else {
                value.to_string()
            }
        }
        _ => value.to_string(),
    }
}

/// Convert a `WorkloadResourceDemand` into a human-readable resource map.
pub fn format_demand_map(demand: &WorkloadResourceDemand) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if demand.cpu_millis > 0 {
        map.insert(
            CPU_RESOURCE.to_string(),
            format_resource_value(CPU_RESOURCE, demand.cpu_millis),
        );
    }
    if demand.memory_bytes > 0 {
        map.insert(
            MEMORY_RESOURCE.to_string(),
            format_resource_value(MEMORY_RESOURCE, demand.memory_bytes),
        );
    }
    if demand.gpu_count > 0 {
        map.insert(GPU_RESOURCE.to_string(), demand.gpu_count.to_string());
    }
    map
}
