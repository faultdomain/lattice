//! Validator registry and trait for CRD admission validation

mod cluster;
mod job;
mod mesh_member;
mod model;
mod secret_provider;
mod service;

use kube::core::admission::{AdmissionRequest, AdmissionResponse};
use kube::core::DynamicObject;

/// Each CRD gets a validator that calls its existing validate() method
pub trait Validator: Send + Sync {
    /// The Kubernetes resource identifier (group, version, resource-plural)
    fn resource(&self) -> (&str, &str, &str);

    /// Validate an admission request. Returns allowed or denied.
    fn validate(&self, request: &AdmissionRequest<DynamicObject>) -> AdmissionResponse;
}

/// Registry that maps GVR triples to validators
pub struct ValidatorRegistry {
    validators: Vec<Box<dyn Validator>>,
}

impl ValidatorRegistry {
    /// Build a registry with all known Lattice CRD validators
    pub fn new() -> Self {
        let validators: Vec<Box<dyn Validator>> = vec![
            Box::new(cluster::ClusterValidator),
            Box::new(job::JobValidator),
            Box::new(service::ServiceValidator),
            Box::new(mesh_member::MeshMemberValidator),
            Box::new(model::ModelValidator),
            Box::new(secret_provider::SecretProviderValidator),
        ];
        Self { validators }
    }

    /// Look up a validator by (group, version, resource) from the admission request
    pub fn find(&self, group: &str, version: &str, resource: &str) -> Option<&dyn Validator> {
        self.validators
            .iter()
            .find(|v| {
                let (g, ver, res) = v.resource();
                g == group && ver == version && res == resource
            })
            .map(|v| v.as_ref())
    }
}

impl Default for ValidatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
pub(crate) mod tests_common {
    pub use crate::test_helpers::{make_admission_request, make_update_admission_request};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_finds_all_validators() {
        let registry = ValidatorRegistry::new();

        assert!(
            registry
                .find("lattice.dev", "v1alpha1", "latticeclusters")
                .is_some(),
            "should find LatticeCluster validator"
        );
        assert!(
            registry
                .find("lattice.dev", "v1alpha1", "latticejobs")
                .is_some(),
            "should find LatticeJob validator"
        );
        assert!(
            registry
                .find("lattice.dev", "v1alpha1", "latticeservices")
                .is_some(),
            "should find LatticeService validator"
        );
        assert!(
            registry
                .find("lattice.dev", "v1alpha1", "latticemeshmembers")
                .is_some(),
            "should find LatticeMeshMember validator"
        );
        assert!(
            registry
                .find("lattice.dev", "v1alpha1", "latticemodels")
                .is_some(),
            "should find LatticeModel validator"
        );
        assert!(
            registry
                .find("lattice.dev", "v1alpha1", "secretproviders")
                .is_some(),
            "should find SecretProvider validator"
        );
    }

    #[test]
    fn registry_returns_none_for_unknown_resource() {
        let registry = ValidatorRegistry::new();

        assert!(
            registry
                .find("lattice.dev", "v1alpha1", "unknown")
                .is_none(),
            "should not find unknown resource"
        );
        assert!(
            registry
                .find("other.group", "v1", "latticeclusters")
                .is_none(),
            "should not find resource in wrong group"
        );
    }
}
