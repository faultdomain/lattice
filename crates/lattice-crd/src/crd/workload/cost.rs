//! Cost estimation types for Lattice workloads.
//!
//! `CostEstimate` is embedded in the status of every workload CRD
//! (LatticeService, LatticeJob, LatticeModel). It represents a point-in-time
//! hourly cost computed from the workload's resource requests multiplied by
//! rates from the `lattice-resource-rates` ConfigMap.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Estimated per-workload cost based on resource requests and current rates.
///
/// This is a point-in-time snapshot, not accumulated billing. Rates come from
/// the `lattice-resource-rates` ConfigMap in `lattice-system`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CostEstimate {
    /// Estimated hourly cost in USD (all replicas combined)
    pub hourly_cost: String,

    /// Per-resource-type cost breakdown
    pub breakdown: CostBreakdown,
}

/// Per-resource-type cost breakdown (all values are $/hour).
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CostBreakdown {
    /// CPU cost per hour (all replicas)
    pub cpu: String,

    /// Memory cost per hour (all replicas)
    pub memory: String,

    /// GPU cost per hour (all replicas), None if no GPUs requested
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<String>,
}
