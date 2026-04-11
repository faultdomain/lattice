//! Deployment strategy types.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Deployment strategy
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum DeployStrategy {
    /// Rolling update strategy
    #[default]
    Rolling,
    /// Canary deployment with progressive traffic shifting
    Canary,
}

/// Canary deployment configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CanarySpec {
    /// Interval between steps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,

    /// Error threshold before rollback
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u32>,

    /// Maximum traffic weight
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_weight: Option<u32>,

    /// Weight increment per step
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_weight: Option<u32>,
}

/// Deployment specification
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct DeploySpec {
    /// Deployment strategy
    #[serde(default)]
    pub strategy: DeployStrategy,

    /// Canary configuration (only if strategy is canary)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary: Option<CanarySpec>,
}
