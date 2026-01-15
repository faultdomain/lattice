//! Docker/Kind provider configuration (CAPD)
//!
//! This provider is for local development and testing only.
//! It uses the Cluster API Provider for Docker (CAPD).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Docker/Kind provider configuration
///
/// Docker provider uses sensible defaults and requires no configuration.
/// This is intended for local development and testing only.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DockerConfig {
    // No fields - Docker uses sensible defaults
}
