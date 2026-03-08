//! LatticeCluster admission validator

use kube::core::admission::{AdmissionRequest, AdmissionResponse, Operation};
use kube::core::DynamicObject;
use lattice_common::crd::LatticeCluster;

use super::Validator;

/// Validates LatticeCluster CREATE and UPDATE requests
pub struct ClusterValidator;

impl Validator for ClusterValidator {
    fn resource(&self) -> (&str, &str, &str) {
        ("lattice.dev", "v1alpha1", "latticeclusters")
    }

    fn validate(&self, request: &AdmissionRequest<DynamicObject>) -> AdmissionResponse {
        let response = AdmissionResponse::from(request);

        let obj = match &request.object {
            Some(obj) => obj,
            None => return response.deny("no object in admission request"),
        };

        let raw = serde_json::to_value(obj).unwrap_or_default();
        let cluster: LatticeCluster = match serde_json::from_value(raw) {
            Ok(c) => c,
            Err(e) => return response.deny(format!("failed to deserialize LatticeCluster: {e}")),
        };

        if let Err(e) = cluster.spec.validate() {
            return response.deny(format!("{e}"));
        }

        // On UPDATE: enforce parent_config immutability
        if request.operation == Operation::Update {
            if let Some(ref old_obj) = request.old_object {
                let old_raw = serde_json::to_value(old_obj).unwrap_or_default();
                if let Ok(old_cluster) = serde_json::from_value::<LatticeCluster>(old_raw) {
                    match (&old_cluster.spec.parent_config, &cluster.spec.parent_config) {
                        // None → None or Some(A) → Some(A): no change, allow
                        (None, None) => {}
                        (Some(old), Some(new)) if old == new => {}
                        // None → Some: promotion, allow
                        (None, Some(_)) => {}
                        // Some → None: demotion, deny
                        (Some(_), None) => {
                            return response.deny(
                                "spec.parentConfig cannot be removed once set. \
                                 Delete and recreate the cluster.",
                            );
                        }
                        // Some(A) → Some(B): modification, deny
                        (Some(_), Some(_)) => {
                            return response.deny(
                                "spec.parentConfig is immutable once set. \
                                 Delete and recreate the cluster to change parent configuration.",
                            );
                        }
                    }
                }
                // If old_object fails to deserialize, allow (fail-open for safety)
            }
            // If old_object is missing on UPDATE, allow (fail-open for safety)
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::tests_common::{make_admission_request, make_update_admission_request};

    fn valid_cluster_json() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeCluster",
            "metadata": { "name": "test-cluster" },
            "spec": {
                "providerRef": "aws-prod",
                "provider": {
                    "kubernetes": {
                        "version": "1.32.0",
                        "certSANs": ["127.0.0.1"]
                    },
                    "config": {
                        "docker": {}
                    }
                },
                "nodes": {
                    "controlPlane": { "replicas": 1 },
                    "workerPools": {
                        "default": { "replicas": 2 }
                    }
                },
                "latticeImage": "ghcr.io/evan-hines-js/lattice:latest"
            }
        })
    }

    fn parent_config_json() -> serde_json::Value {
        serde_json::json!({
            "grpcPort": 50051,
            "bootstrapPort": 8443,
            "proxyPort": 8081,
            "service": { "type": "LoadBalancer" }
        })
    }

    fn cluster_with_parent_config() -> serde_json::Value {
        let mut json = valid_cluster_json();
        json["spec"]["parentConfig"] = parent_config_json();
        json
    }

    #[test]
    fn allows_valid_cluster() {
        let validator = ClusterValidator;
        let request = make_admission_request(
            "lattice.dev",
            "v1alpha1",
            "latticeclusters",
            valid_cluster_json(),
        );
        let response = validator.validate(&request);
        assert!(response.allowed, "valid cluster should be allowed");
    }

    #[test]
    fn denies_empty_provider_ref() {
        let mut json = valid_cluster_json();
        json["spec"]["providerRef"] = serde_json::json!("");

        let validator = ClusterValidator;
        let request = make_admission_request("lattice.dev", "v1alpha1", "latticeclusters", json);
        let response = validator.validate(&request);
        assert!(!response.allowed, "empty providerRef should be denied");

        let message = &response.result.message;
        assert!(
            message.contains("provider_ref"),
            "error message should mention provider_ref, got: {message}"
        );
    }

    #[test]
    fn denies_zero_control_plane_replicas() {
        let mut json = valid_cluster_json();
        json["spec"]["nodes"]["controlPlane"]["replicas"] = serde_json::json!(0);

        let validator = ClusterValidator;
        let request = make_admission_request("lattice.dev", "v1alpha1", "latticeclusters", json);
        let response = validator.validate(&request);
        assert!(
            !response.allowed,
            "zero control plane replicas should be denied"
        );
    }

    #[test]
    fn denies_missing_object() {
        let request: AdmissionRequest<DynamicObject> = AdmissionRequest {
            object: None,
            ..make_admission_request(
                "lattice.dev",
                "v1alpha1",
                "latticeclusters",
                valid_cluster_json(),
            )
        };
        let validator = ClusterValidator;
        let response = validator.validate(&request);
        assert!(!response.allowed, "missing object should be denied");
    }

    #[test]
    fn allows_update_without_parent_config_change() {
        let mut new_json = valid_cluster_json();
        new_json["spec"]["nodes"]["workerPools"]["default"]["replicas"] = serde_json::json!(5);

        let validator = ClusterValidator;
        let request = make_update_admission_request(
            "lattice.dev",
            "v1alpha1",
            "latticeclusters",
            new_json,
            valid_cluster_json(),
        );
        let response = validator.validate(&request);
        assert!(
            response.allowed,
            "updating worker replicas without parent_config change should be allowed"
        );
    }

    #[test]
    fn allows_adding_parent_config() {
        let validator = ClusterValidator;
        let request = make_update_admission_request(
            "lattice.dev",
            "v1alpha1",
            "latticeclusters",
            cluster_with_parent_config(),
            valid_cluster_json(),
        );
        let response = validator.validate(&request);
        assert!(
            response.allowed,
            "adding parent_config (promotion) should be allowed"
        );
    }

    #[test]
    fn denies_removing_parent_config() {
        let validator = ClusterValidator;
        let request = make_update_admission_request(
            "lattice.dev",
            "v1alpha1",
            "latticeclusters",
            valid_cluster_json(),
            cluster_with_parent_config(),
        );
        let response = validator.validate(&request);
        assert!(!response.allowed, "removing parent_config should be denied");
        let message = &response.result.message;
        assert!(
            message.contains("cannot be removed"),
            "error should mention removal, got: {message}"
        );
    }

    #[test]
    fn denies_modifying_parent_config_ports() {
        let mut modified = cluster_with_parent_config();
        modified["spec"]["parentConfig"]["grpcPort"] = serde_json::json!(9999);

        let validator = ClusterValidator;
        let request = make_update_admission_request(
            "lattice.dev",
            "v1alpha1",
            "latticeclusters",
            modified,
            cluster_with_parent_config(),
        );
        let response = validator.validate(&request);
        assert!(
            !response.allowed,
            "modifying parent_config should be denied"
        );
        let message = &response.result.message;
        assert!(
            message.contains("immutable"),
            "error should mention immutability, got: {message}"
        );
    }

    #[test]
    fn allows_create_with_parent_config() {
        let validator = ClusterValidator;
        let request = make_admission_request(
            "lattice.dev",
            "v1alpha1",
            "latticeclusters",
            cluster_with_parent_config(),
        );
        let response = validator.validate(&request);
        assert!(
            response.allowed,
            "CREATE with parent_config should always be allowed"
        );
    }

    #[test]
    fn allows_create_without_parent_config() {
        let validator = ClusterValidator;
        let request = make_admission_request(
            "lattice.dev",
            "v1alpha1",
            "latticeclusters",
            valid_cluster_json(),
        );
        let response = validator.validate(&request);
        assert!(
            response.allowed,
            "CREATE without parent_config should always be allowed"
        );
    }

    #[test]
    fn allows_update_when_both_have_same_parent_config() {
        let validator = ClusterValidator;
        let mut updated = cluster_with_parent_config();
        updated["spec"]["nodes"]["workerPools"]["default"]["replicas"] = serde_json::json!(10);

        let request = make_update_admission_request(
            "lattice.dev",
            "v1alpha1",
            "latticeclusters",
            updated,
            cluster_with_parent_config(),
        );
        let response = validator.validate(&request);
        assert!(
            response.allowed,
            "update with unchanged parent_config should be allowed"
        );
    }
}
