//! Validator registry and trait for CRD admission validation

mod cluster;
mod job;
mod mesh_member;
mod model;
mod secret_provider;
mod service;

use kube::core::admission::{AdmissionRequest, AdmissionResponse};
use kube::core::DynamicObject;
use lattice_core::system_namespaces;
use serde::de::DeserializeOwned;

/// Reject workload CRDs deployed in system namespaces.
///
/// System namespaces host infrastructure without MeshMember coverage. Deploying
/// workload CRDs there would create services subject to default-deny without
/// explicit policies. Infrastructure namespaces WITH MeshMember coverage
/// (kthena-system, monitoring, keda) are not in the system list.
pub(crate) fn reject_system_namespace(
    request: &AdmissionRequest<DynamicObject>,
) -> Option<AdmissionResponse> {
    let namespace = request.namespace.as_deref().unwrap_or_default();
    if system_namespaces::is_system_namespace(namespace) {
        let response = AdmissionResponse::from(request);
        Some(response.deny(format!(
            "workload CRDs cannot be deployed in system namespace '{namespace}'"
        )))
    } else {
        None
    }
}

/// Parse a DynamicObject from an admission request into a concrete CRD type.
///
/// Handles the serialize-then-deserialize roundtrip that every validator needs,
/// with proper error handling (no `unwrap_or_default`). Returns the typed CRD
/// and the response handle for chaining allow/deny decisions.
#[allow(clippy::result_large_err)]
pub(crate) fn parse_admission_object<T: DeserializeOwned>(
    request: &AdmissionRequest<DynamicObject>,
    type_name: &str,
) -> Result<(AdmissionResponse, T), AdmissionResponse> {
    let response = AdmissionResponse::from(request);

    let obj = match &request.object {
        Some(obj) => obj,
        None => return Err(response.deny("no object in admission request")),
    };

    let raw = match serde_json::to_value(obj) {
        Ok(v) => v,
        Err(e) => return Err(response.deny(format!("failed to serialize admission object: {e}"))),
    };

    match serde_json::from_value(raw) {
        Ok(crd) => Ok((response, crd)),
        Err(e) => Err(response.deny(format!("failed to deserialize {type_name}: {e}"))),
    }
}

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
    pub use crate::test_helpers::{
        make_admission_request, make_admission_request_in_namespace, make_update_admission_request,
    };
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
