//! Volcano VCJob serialization types
//!
//! Typed representation of Volcano `batch.volcano.sh/v1alpha1` Job resources.
//! Uses serde for JSON serialization compatible with server-side apply.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Volcano VCJob resource (`batch.volcano.sh/v1alpha1` Kind: Job)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCJob {
    pub api_version: String,
    pub kind: String,
    pub metadata: VCJobMetadata,
    pub spec: VCJobSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCJobMetadata {
    pub name: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_references: Vec<OwnerReference>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OwnerReference {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_owner_deletion: Option<bool>,
}

/// VCJob spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCJobSpec {
    pub scheduler_name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_available: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retry: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_class_name: Option<String>,

    pub tasks: Vec<VCJobTask>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<VCJobTaskPolicy>,
}

/// A single task within a VCJob
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCJobTask {
    pub name: String,
    pub replicas: u32,
    /// Pod template — passed through as pre-serialized JSON from the workload compiler
    pub template: serde_json::Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<VCJobTaskPolicy>,
}

/// Volcano lifecycle policy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCJobTaskPolicy {
    pub event: String,
    pub action: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcjob_serialization_roundtrip() {
        let vcjob = VCJob {
            api_version: "batch.volcano.sh/v1alpha1".to_string(),
            kind: "Job".to_string(),
            metadata: VCJobMetadata {
                name: "test-job".to_string(),
                namespace: "default".to_string(),
                labels: BTreeMap::from([(
                    "app.kubernetes.io/managed-by".to_string(),
                    "lattice".to_string(),
                )]),
                owner_references: vec![],
            },
            spec: VCJobSpec {
                scheduler_name: "volcano".to_string(),
                min_available: Some(2),
                max_retry: None,
                queue: None,
                priority_class_name: None,
                tasks: vec![],
                policies: vec![],
            },
        };

        let json = serde_json::to_string(&vcjob).unwrap();
        let de: VCJob = serde_json::from_str(&json).unwrap();
        assert_eq!(vcjob, de);
    }
}
