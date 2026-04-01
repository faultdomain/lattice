//! Quota controller for Lattice
//!
//! Owns the `LatticeQuota` CRD lifecycle:
//!
//! - Validates quota specs and tracks per-principal resource usage in status
//! - Workload compilers resolve budgets from cached quota/namespace data
//!
//! Quotas are a budget system, not an infrastructure scaling system.
//! Pool `spec.min`/`spec.max` control autoscaler bounds directly.
//! The autoscaler handles scaling to meet pending pods.

#![deny(missing_docs)]

mod budget;
mod controller;
mod store;

pub use budget::QuotaBudget;
pub use controller::{reconcile, QuotaContext};
pub use store::resolve_budget;

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
