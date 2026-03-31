//! Quota controller for Lattice
//!
//! Owns the `LatticeQuota` CRD lifecycle and drives CAPI autoscaling:
//!
//! - Validates quota specs and tracks per-principal resource usage in status
//! - Computes aggregate hard limits across all quotas on the cluster
//! - Translates hard quota sums into MachineDeployment min annotations
//! - Pool `spec.max` is the admin-configured autoscaler ceiling
//!
//! Hard quotas guarantee reserved capacity (autoscaler min). Soft quotas
//! are enforced at compile time (workload rejection) and don't affect
//! infrastructure scaling. The autoscaler handles scaling within spec.max.

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

use lattice_common::resources::{
    WorkloadResourceDemand, CPU_RESOURCE, GPU_RESOURCE, MEMORY_RESOURCE,
};

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
