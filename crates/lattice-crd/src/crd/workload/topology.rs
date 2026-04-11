//! Network topology types for topology-aware scheduling
//!
//! Shared types used by all workload CRDs (LatticeService, LatticeJob, LatticeModel)
//! to opt in to Volcano's network-topology-aware scheduler plugin.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Network topology configuration for a workload.
///
/// Controls Volcano's `network-topology-aware` scheduler plugin to co-place
/// pods under the same ToR switch or within the same network tier.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadNetworkTopology {
    /// Scheduling mode — hard rejects placement above max_tier, soft prefers it.
    pub mode: TopologyMode,

    /// Maximum HyperNode tier allowed for placement. Required when mode is Hard.
    ///
    /// Tier 1 = same rack (ToR switch), tier 2 = same zone, etc.
    /// Higher tiers allow wider placement at the cost of higher latency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tier: Option<u32>,
}

/// Topology scheduling mode
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[non_exhaustive]
pub enum TopologyMode {
    /// Pods MUST be placed within max_tier. Scheduling fails if impossible.
    Hard,
    /// Pods are PREFERRED to be placed within max_tier but can spill over.
    Soft,
}

impl WorkloadNetworkTopology {
    /// Validate the topology configuration.
    ///
    /// Returns an error if mode is Hard but max_tier is not set.
    pub fn validate(&self) -> Result<(), String> {
        if self.mode == TopologyMode::Hard && self.max_tier.is_none() {
            return Err("topology mode Hard requires maxTier to be set".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip_soft() {
        let topo = WorkloadNetworkTopology {
            mode: TopologyMode::Soft,
            max_tier: Some(2),
        };
        let json = serde_json::to_string(&topo).unwrap();
        let de: WorkloadNetworkTopology = serde_json::from_str(&json).unwrap();
        assert_eq!(topo, de);
    }

    #[test]
    fn serde_roundtrip_hard() {
        let topo = WorkloadNetworkTopology {
            mode: TopologyMode::Hard,
            max_tier: Some(1),
        };
        let json = serde_json::to_string(&topo).unwrap();
        let de: WorkloadNetworkTopology = serde_json::from_str(&json).unwrap();
        assert_eq!(topo, de);
    }

    #[test]
    fn soft_without_max_tier_is_valid() {
        let topo = WorkloadNetworkTopology {
            mode: TopologyMode::Soft,
            max_tier: None,
        };
        assert!(topo.validate().is_ok());
    }

    #[test]
    fn hard_without_max_tier_is_invalid() {
        let topo = WorkloadNetworkTopology {
            mode: TopologyMode::Hard,
            max_tier: None,
        };
        assert!(topo.validate().is_err());
    }

    #[test]
    fn hard_with_max_tier_is_valid() {
        let topo = WorkloadNetworkTopology {
            mode: TopologyMode::Hard,
            max_tier: Some(1),
        };
        assert!(topo.validate().is_ok());
    }

    #[test]
    fn camel_case_serialization() {
        let topo = WorkloadNetworkTopology {
            mode: TopologyMode::Soft,
            max_tier: Some(2),
        };
        let value: serde_json::Value = serde_json::to_value(&topo).unwrap();
        assert!(value.get("maxTier").is_some());
    }

    #[test]
    fn max_tier_none_omitted_in_json() {
        let topo = WorkloadNetworkTopology {
            mode: TopologyMode::Soft,
            max_tier: None,
        };
        let value: serde_json::Value = serde_json::to_value(&topo).unwrap();
        assert!(value.get("maxTier").is_none());
    }
}
