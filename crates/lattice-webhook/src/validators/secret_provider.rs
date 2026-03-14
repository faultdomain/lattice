//! SecretProvider admission validator

use kube::core::admission::{AdmissionRequest, AdmissionResponse};
use kube::core::DynamicObject;
use lattice_common::crd::SecretProvider;

use super::{reject_system_namespace, Validator};

/// Validates SecretProvider CREATE and UPDATE requests
pub struct SecretProviderValidator;

impl Validator for SecretProviderValidator {
    fn resource(&self) -> (&str, &str, &str) {
        ("lattice.dev", "v1alpha1", "secretproviders")
    }

    fn validate(&self, request: &AdmissionRequest<DynamicObject>) -> AdmissionResponse {
        if let Some(denied) = reject_system_namespace(request) {
            return denied;
        }

        let response = AdmissionResponse::from(request);

        let obj = match &request.object {
            Some(obj) => obj,
            None => return response.deny("no object in admission request"),
        };

        let raw = match serde_json::to_value(obj) {
            Ok(v) => v,
            Err(e) => return response.deny(format!("failed to serialize admission object: {e}")),
        };
        let provider: SecretProvider = match serde_json::from_value(raw) {
            Ok(p) => p,
            Err(e) => return response.deny(format!("failed to deserialize SecretProvider: {e}")),
        };

        if let Err(e) = provider.spec.validate() {
            return response.deny(format!("{e}"));
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::tests_common::{
        make_admission_request, make_admission_request_in_namespace,
    };

    fn valid_secret_provider_json() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "SecretProvider",
            "metadata": { "name": "vault-prod", "namespace": "default" },
            "spec": {
                "provider": {
                    "vault": {
                        "server": "https://vault.example.com",
                        "path": "secret"
                    }
                }
            }
        })
    }

    #[test]
    fn allows_valid_secret_provider() {
        let validator = SecretProviderValidator;
        let request = make_admission_request(
            "lattice.dev",
            "v1alpha1",
            "secretproviders",
            valid_secret_provider_json(),
        );
        let response = validator.validate(&request);
        assert!(response.allowed, "valid secret provider should be allowed");
    }

    #[test]
    fn denies_empty_provider() {
        let json = serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "SecretProvider",
            "metadata": { "name": "bad-provider", "namespace": "default" },
            "spec": {
                "provider": {}
            }
        });

        let validator = SecretProviderValidator;
        let request = make_admission_request("lattice.dev", "v1alpha1", "secretproviders", json);
        let response = validator.validate(&request);
        assert!(!response.allowed, "empty provider should be denied");

        let message = &response.result.message;
        assert!(
            message.contains("exactly one provider key"),
            "error should mention the provider constraint, got: {message}"
        );
    }

    #[test]
    fn denies_multi_key_provider() {
        let json = serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "SecretProvider",
            "metadata": { "name": "multi-provider", "namespace": "default" },
            "spec": {
                "provider": {
                    "vault": {},
                    "aws": {}
                }
            }
        });

        let validator = SecretProviderValidator;
        let request = make_admission_request("lattice.dev", "v1alpha1", "secretproviders", json);
        let response = validator.validate(&request);
        assert!(!response.allowed, "multi-key provider should be denied");
    }

    #[test]
    fn denies_system_namespace() {
        let validator = SecretProviderValidator;
        let request = make_admission_request_in_namespace(
            "lattice.dev",
            "v1alpha1",
            "secretproviders",
            "kube-system",
            valid_secret_provider_json(),
        );
        let response = validator.validate(&request);
        assert!(!response.allowed, "system namespace should be denied");
    }

    #[test]
    fn denies_missing_object() {
        let request: AdmissionRequest<DynamicObject> = AdmissionRequest {
            object: None,
            ..make_admission_request(
                "lattice.dev",
                "v1alpha1",
                "secretproviders",
                valid_secret_provider_json(),
            )
        };
        let validator = SecretProviderValidator;
        let response = validator.validate(&request);
        assert!(!response.allowed, "missing object should be denied");
    }
}
