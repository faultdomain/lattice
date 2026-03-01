//! LatticeJob admission validator

use kube::core::admission::{AdmissionRequest, AdmissionResponse};
use kube::core::DynamicObject;
use lattice_common::crd::LatticeJob;

use super::Validator;

/// Validates LatticeJob CREATE and UPDATE requests
pub struct JobValidator;

impl Validator for JobValidator {
    fn resource(&self) -> (&str, &str, &str) {
        ("lattice.dev", "v1alpha1", "latticejobs")
    }

    fn validate(&self, request: &AdmissionRequest<DynamicObject>) -> AdmissionResponse {
        let response = AdmissionResponse::from(request);

        let obj = match &request.object {
            Some(obj) => obj,
            None => return response.deny("no object in admission request"),
        };

        let raw = serde_json::to_value(obj).unwrap_or_default();
        let job: LatticeJob = match serde_json::from_value(raw) {
            Ok(j) => j,
            Err(e) => return response.deny(format!("failed to deserialize LatticeJob: {e}")),
        };

        if let Err(e) = job.spec.validate() {
            return response.deny(format!("{e}"));
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::tests_common::make_admission_request;

    fn valid_job_json() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeJob",
            "metadata": { "name": "my-job", "namespace": "default" },
            "spec": {
                "tasks": {
                    "worker": {
                        "replicas": 2,
                        "workload": {
                            "containers": {
                                "main": {
                                    "image": "train:latest",
                                    "command": ["/usr/bin/python", "-c", "train()"],
                                    "resources": {
                                        "limits": { "cpu": "1", "memory": "1Gi" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn allows_valid_job() {
        let validator = JobValidator;
        let request =
            make_admission_request("lattice.dev", "v1alpha1", "latticejobs", valid_job_json());
        let response = validator.validate(&request);
        assert!(response.allowed, "valid job should be allowed");
    }

    #[test]
    fn denies_empty_tasks() {
        let json = serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeJob",
            "metadata": { "name": "bad-job", "namespace": "default" },
            "spec": {
                "tasks": {}
            }
        });

        let validator = JobValidator;
        let request = make_admission_request("lattice.dev", "v1alpha1", "latticejobs", json);
        let response = validator.validate(&request);
        assert!(!response.allowed, "empty tasks should be denied");
    }

    #[test]
    fn denies_training_missing_coordinator() {
        let json = serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeJob",
            "metadata": { "name": "bad-job", "namespace": "default" },
            "spec": {
                "training": {
                    "framework": "PyTorch",
                    "coordinatorTask": "nonexistent"
                },
                "tasks": {
                    "worker": {
                        "replicas": 1,
                        "workload": {
                            "containers": {
                                "main": {
                                    "image": "train:latest",
                                    "command": ["/usr/bin/python", "-c", "train()"],
                                    "resources": {
                                        "limits": { "cpu": "1", "memory": "1Gi" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        let validator = JobValidator;
        let request = make_admission_request("lattice.dev", "v1alpha1", "latticejobs", json);
        let response = validator.validate(&request);
        assert!(
            !response.allowed,
            "missing coordinator task should be denied"
        );
    }

    #[test]
    fn denies_training_container_without_command() {
        let json = serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeJob",
            "metadata": { "name": "bad-job", "namespace": "default" },
            "spec": {
                "training": {
                    "framework": "PyTorch",
                    "coordinatorTask": "worker"
                },
                "tasks": {
                    "worker": {
                        "replicas": 1,
                        "workload": {
                            "containers": {
                                "main": {
                                    "image": "train:latest",
                                    "resources": {
                                        "limits": { "cpu": "1", "memory": "1Gi" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        let validator = JobValidator;
        let request = make_admission_request("lattice.dev", "v1alpha1", "latticejobs", json);
        let response = validator.validate(&request);
        assert!(
            !response.allowed,
            "training container without command should be denied"
        );
    }

    #[test]
    fn denies_cron_with_checkpoint() {
        let json = serde_json::json!({
            "apiVersion": "lattice.dev/v1alpha1",
            "kind": "LatticeJob",
            "metadata": { "name": "bad-job", "namespace": "default" },
            "spec": {
                "schedule": "*/5 * * * *",
                "training": {
                    "framework": "PyTorch",
                    "coordinatorTask": "worker",
                    "checkpoint": { "volumeSize": "10Gi" }
                },
                "tasks": {
                    "worker": {
                        "replicas": 1,
                        "workload": {
                            "containers": {
                                "main": {
                                    "image": "train:latest",
                                    "command": ["/usr/bin/python", "-c", "train()"],
                                    "resources": {
                                        "limits": { "cpu": "1", "memory": "1Gi" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        let validator = JobValidator;
        let request = make_admission_request("lattice.dev", "v1alpha1", "latticejobs", json);
        let response = validator.validate(&request);
        assert!(!response.allowed, "cron with checkpoint should be denied");
    }

    #[test]
    fn denies_missing_object() {
        let request: AdmissionRequest<DynamicObject> = AdmissionRequest {
            object: None,
            ..make_admission_request("lattice.dev", "v1alpha1", "latticejobs", valid_job_json())
        };
        let validator = JobValidator;
        let response = validator.validate(&request);
        assert!(!response.allowed, "missing object should be denied");
    }
}
