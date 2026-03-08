//! Provision output structure
//!
//! Defines the output from provisioner execution, including resolved outputs
//! for template substitution and K8s manifests to apply.

use kube::api::DynamicObject;
use std::collections::HashMap;

use super::context::ResourceOutputs;

/// Output from provisioner execution
///
/// Contains both template substitution outputs and K8s manifests to apply.
/// Used by provisioners to return everything needed to configure a resource.
#[derive(Clone, Debug, Default)]
pub struct ProvisionOutput {
    /// Outputs for template substitution (resource_name -> outputs)
    ///
    /// These values are available as `${resources.NAME.*}` in templates.
    pub outputs: HashMap<String, ResourceOutputs>,

    /// K8s manifests to apply (PVCs, Secrets, ConfigMaps, etc.)
    ///
    /// These are applied to the cluster during provisioning.
    pub manifests: Vec<DynamicObject>,
}

impl ProvisionOutput {
    /// Create a new empty provision output
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with outputs for a single resource
    pub fn with_outputs(resource_name: impl Into<String>, outputs: ResourceOutputs) -> Self {
        let mut result = Self::new();
        result.outputs.insert(resource_name.into(), outputs);
        result
    }

    /// Check if this output is empty
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty() && self.manifests.is_empty()
    }

    /// Merge another ProvisionOutput into this one
    pub fn merge(&mut self, other: ProvisionOutput) {
        self.outputs.extend(other.outputs);
        self.manifests.extend(other.manifests);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provision_output_default() {
        let output = ProvisionOutput::default();
        assert!(output.is_empty());
    }

    #[test]
    fn test_provision_output_with_outputs() {
        let outputs = ResourceOutputs::builder()
            .output("claim_name", "my-pvc")
            .build();

        let output = ProvisionOutput::with_outputs("volume", outputs);
        assert!(!output.is_empty());
        assert!(output.outputs.contains_key("volume"));
    }

    #[test]
    fn test_provision_output_merge() {
        let mut output1 = ProvisionOutput::with_outputs(
            "vol1",
            ResourceOutputs::builder().output("name", "pvc1").build(),
        );
        let output2 = ProvisionOutput::with_outputs(
            "vol2",
            ResourceOutputs::builder().output("name", "pvc2").build(),
        );

        output1.merge(output2);

        assert!(output1.outputs.contains_key("vol1"));
        assert!(output1.outputs.contains_key("vol2"));
    }
}
