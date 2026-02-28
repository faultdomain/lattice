//! Cluster-level network topology configuration
//!
//! Configures HyperNode discovery for Volcano's network-topology-aware scheduling.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Cluster-level network topology configuration.
///
/// Enables Volcano HyperNode discovery for workload co-placement.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkTopologyConfig {
    /// How HyperNodes are discovered. None for manual mode
    /// (user creates HyperNode CRDs directly).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<TopologyDiscoverySpec>,
}

/// Discovery source — enum enforces exactly one config block per source type.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum TopologyDiscoverySpec {
    /// InfiniBand fabric discovery via Unified Fabric Manager
    Ufm(UfmDiscoveryConfig),
    /// Label-based discovery from Kubernetes node labels.
    /// If tiers is empty, auto-configured from cloud provider.
    Label(LabelDiscoveryConfig),
}

/// UFM-based topology discovery configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UfmDiscoveryConfig {
    /// UFM API endpoint URL
    pub endpoint: String,
    /// Secret reference containing UFM credentials
    pub credential_secret_ref: String,
    /// Skip TLS certificate verification (not recommended for production)
    #[serde(default)]
    pub insecure_skip_verify: bool,
    /// Discovery refresh interval (e.g. "10m"). Defaults to "10m".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
}

/// Label-based topology discovery configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabelDiscoveryConfig {
    /// Ordered label tiers (highest → lowest). Empty = auto-configure from provider.
    #[serde(default)]
    pub tiers: Vec<LabelTier>,
    /// Discovery refresh interval (e.g. "10m"). Defaults to "10m".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
}

/// A single label tier for label-based topology discovery
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabelTier {
    /// Kubernetes node label used for this tier
    pub node_label: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip_ufm() {
        let config = NetworkTopologyConfig {
            discovery: Some(TopologyDiscoverySpec::Ufm(UfmDiscoveryConfig {
                endpoint: "https://ufm.example.com".to_string(),
                credential_secret_ref: "ufm-creds".to_string(),
                insecure_skip_verify: false,
                interval: Some("10m".to_string()),
            })),
        };
        let json = serde_json::to_string(&config).unwrap();
        let de: NetworkTopologyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, de);
    }

    #[test]
    fn serde_roundtrip_label() {
        let config = NetworkTopologyConfig {
            discovery: Some(TopologyDiscoverySpec::Label(LabelDiscoveryConfig {
                tiers: vec![
                    LabelTier {
                        node_label: "topology.kubernetes.io/zone".to_string(),
                    },
                    LabelTier {
                        node_label: "kubernetes.io/hostname".to_string(),
                    },
                ],
                interval: None,
            })),
        };
        let json = serde_json::to_string(&config).unwrap();
        let de: NetworkTopologyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, de);
    }

    #[test]
    fn serde_roundtrip_manual() {
        let config = NetworkTopologyConfig { discovery: None };
        let json = serde_json::to_string(&config).unwrap();
        let de: NetworkTopologyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, de);
    }

    #[test]
    fn label_with_empty_tiers() {
        let config = NetworkTopologyConfig {
            discovery: Some(TopologyDiscoverySpec::Label(LabelDiscoveryConfig {
                tiers: vec![],
                interval: None,
            })),
        };
        let json = serde_json::to_string(&config).unwrap();
        let de: NetworkTopologyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, de);
    }
}
