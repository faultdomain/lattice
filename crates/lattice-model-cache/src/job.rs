//! Pre-fetch Job construction
//!
//! Builds Kubernetes Jobs that download model artifacts into PVCs.
//! Each Job runs a `model-loader` container with the model URI and
//! mounts the target PVC.

use std::collections::BTreeMap;

use k8s_openapi::api::batch::v1::{Job, JobSpec};
use k8s_openapi::api::core::v1::{
    Container, PersistentVolumeClaimVolumeSource, PodSpec, PodTemplateSpec, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;

use lattice_common::crd::ModelArtifactSpec;

/// Destination path inside the loader container where models are written
const MODEL_DEST_PATH: &str = "/models";

/// Build a Kubernetes Job that pre-fetches a model artifact into a PVC.
///
/// The Job:
/// - Runs a single `model-loader` container
/// - Mounts the model cache PVC at `/models`
/// - Passes `--uri` and optional `--revision` args
/// - Sets `ownerReferences` to the ModelArtifact (garbage collection)
/// - Uses `backoffLimit: 3` and `ttlSecondsAfterFinished: 300`
pub fn build_prefetch_job(
    spec: &ModelArtifactSpec,
    artifact_name: &str,
    artifact_uid: &str,
    namespace: &str,
    loader_image: &str,
) -> Job {
    let job_name = format!("model-prefetch-{}", artifact_name);

    let mut args = vec![
        "--uri".to_string(),
        spec.uri.clone(),
        format!("--dest={}", MODEL_DEST_PATH),
    ];
    if let Some(ref rev) = spec.revision {
        args.push("--revision".to_string());
        args.push(rev.clone());
    }

    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "lattice-model-cache".to_string(),
    );
    labels.insert(
        "lattice.dev/model-artifact".to_string(),
        artifact_name.to_string(),
    );

    let container = Container {
        name: "loader".to_string(),
        image: Some(loader_image.to_string()),
        command: Some(vec!["model-loader".to_string()]),
        args: Some(args),
        volume_mounts: Some(vec![VolumeMount {
            name: "model-store".to_string(),
            mount_path: MODEL_DEST_PATH.to_string(),
            ..Default::default()
        }]),
        ..Default::default()
    };

    let volume = Volume {
        name: "model-store".to_string(),
        persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
            claim_name: spec.pvc_name.clone(),
            read_only: Some(false),
        }),
        ..Default::default()
    };

    Job {
        metadata: ObjectMeta {
            name: Some(job_name),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![OwnerReference {
                api_version: "lattice.dev/v1alpha1".to_string(),
                kind: "ModelArtifact".to_string(),
                name: artifact_name.to_string(),
                uid: artifact_uid.to_string(),
                controller: Some(true),
                block_owner_deletion: Some(true),
            }]),
            ..Default::default()
        },
        spec: Some(JobSpec {
            backoff_limit: Some(3),
            ttl_seconds_after_finished: Some(300),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![container],
                    volumes: Some(vec![volume]),
                    restart_policy: Some("OnFailure".to_string()),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Check if a Job has completed successfully
pub fn is_job_complete(job: &Job) -> bool {
    job.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .map(|conditions| {
            conditions
                .iter()
                .any(|c| c.type_ == "Complete" && c.status == "True")
        })
        .unwrap_or(false)
}

/// Check if a Job has failed
pub fn is_job_failed(job: &Job) -> bool {
    job.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .map(|conditions| {
            conditions
                .iter()
                .any(|c| c.type_ == "Failed" && c.status == "True")
        })
        .unwrap_or(false)
}

/// Extract failure message from a failed Job
pub fn job_failure_message(job: &Job) -> Option<String> {
    job.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .and_then(|conditions| {
            conditions
                .iter()
                .find(|c| c.type_ == "Failed" && c.status == "True")
                .and_then(|c| c.message.clone())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::batch::v1::JobCondition;
    use k8s_openapi::api::batch::v1::JobStatus;

    fn sample_spec() -> ModelArtifactSpec {
        ModelArtifactSpec {
            uri: "huggingface://meta-llama/Llama-3.3-70B-Instruct".to_string(),
            revision: Some("main".to_string()),
            pvc_name: "model-cache-meta-llama-abc123".to_string(),
            size_bytes: None,
        }
    }

    #[test]
    fn job_name_includes_artifact_name() {
        let job = build_prefetch_job(
            &sample_spec(),
            "llama-70b",
            "uid-123",
            "default",
            "ghcr.io/lattice-cloud/model-loader:v1",
        );
        assert_eq!(
            job.metadata.name.as_deref(),
            Some("model-prefetch-llama-70b")
        );
    }

    #[test]
    fn job_namespace_matches() {
        let job = build_prefetch_job(
            &sample_spec(),
            "llama-70b",
            "uid-123",
            "ml-workloads",
            "ghcr.io/lattice-cloud/model-loader:v1",
        );
        assert_eq!(job.metadata.namespace.as_deref(), Some("ml-workloads"));
    }

    #[test]
    fn job_has_owner_reference() {
        let job = build_prefetch_job(
            &sample_spec(),
            "llama-70b",
            "uid-123",
            "default",
            "ghcr.io/lattice-cloud/model-loader:v1",
        );
        let refs = job.metadata.owner_references.as_ref().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].kind, "ModelArtifact");
        assert_eq!(refs[0].name, "llama-70b");
        assert_eq!(refs[0].uid, "uid-123");
        assert_eq!(refs[0].controller, Some(true));
    }

    #[test]
    fn job_mounts_pvc() {
        let job = build_prefetch_job(
            &sample_spec(),
            "llama-70b",
            "uid-123",
            "default",
            "ghcr.io/lattice-cloud/model-loader:v1",
        );
        let pod_spec = job.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
        let volumes = pod_spec.volumes.as_ref().unwrap();
        assert_eq!(volumes.len(), 1);
        assert_eq!(
            volumes[0]
                .persistent_volume_claim
                .as_ref()
                .unwrap()
                .claim_name,
            "model-cache-meta-llama-abc123"
        );

        let mounts = pod_spec.containers[0].volume_mounts.as_ref().unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].mount_path, MODEL_DEST_PATH);
    }

    #[test]
    fn job_passes_uri_and_revision_args() {
        let job = build_prefetch_job(
            &sample_spec(),
            "llama-70b",
            "uid-123",
            "default",
            "ghcr.io/lattice-cloud/model-loader:v1",
        );
        let container = &job
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers[0];
        let args = container.args.as_ref().unwrap();
        assert!(args.contains(&"--uri".to_string()));
        assert!(args.contains(&"huggingface://meta-llama/Llama-3.3-70B-Instruct".to_string()));
        assert!(args.contains(&"--revision".to_string()));
        assert!(args.contains(&"main".to_string()));
        assert!(args.contains(&format!("--dest={}", MODEL_DEST_PATH)));
    }

    #[test]
    fn job_omits_revision_when_none() {
        let mut spec = sample_spec();
        spec.revision = None;
        let job = build_prefetch_job(
            &spec,
            "llama-70b",
            "uid-123",
            "default",
            "ghcr.io/lattice-cloud/model-loader:v1",
        );
        let args = job
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers[0]
            .args
            .as_ref()
            .unwrap();
        assert!(!args.contains(&"--revision".to_string()));
    }

    #[test]
    fn job_has_backoff_and_ttl() {
        let job = build_prefetch_job(
            &sample_spec(),
            "llama-70b",
            "uid-123",
            "default",
            "ghcr.io/lattice-cloud/model-loader:v1",
        );
        let job_spec = job.spec.as_ref().unwrap();
        assert_eq!(job_spec.backoff_limit, Some(3));
        assert_eq!(job_spec.ttl_seconds_after_finished, Some(300));
    }

    #[test]
    fn job_has_restart_on_failure() {
        let job = build_prefetch_job(
            &sample_spec(),
            "llama-70b",
            "uid-123",
            "default",
            "ghcr.io/lattice-cloud/model-loader:v1",
        );
        let pod_spec = job.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
        assert_eq!(pod_spec.restart_policy.as_deref(), Some("OnFailure"));
    }

    #[test]
    fn job_has_managed_by_label() {
        let job = build_prefetch_job(
            &sample_spec(),
            "llama-70b",
            "uid-123",
            "default",
            "ghcr.io/lattice-cloud/model-loader:v1",
        );
        let labels = job.metadata.labels.as_ref().unwrap();
        assert_eq!(
            labels.get("app.kubernetes.io/managed-by"),
            Some(&"lattice-model-cache".to_string())
        );
        assert_eq!(
            labels.get("lattice.dev/model-artifact"),
            Some(&"llama-70b".to_string())
        );
    }

    #[test]
    fn job_uses_specified_loader_image() {
        let job = build_prefetch_job(
            &sample_spec(),
            "llama-70b",
            "uid-123",
            "default",
            "custom-registry.io/loader:v2",
        );
        let image = job
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers[0]
            .image
            .as_deref();
        assert_eq!(image, Some("custom-registry.io/loader:v2"));
    }

    // =========================================================================
    // Job status helper tests
    // =========================================================================

    fn job_with_condition(type_: &str, status: &str) -> Job {
        Job {
            status: Some(JobStatus {
                conditions: Some(vec![JobCondition {
                    type_: type_.to_string(),
                    status: status.to_string(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn is_job_complete_true_when_complete() {
        assert!(is_job_complete(&job_with_condition("Complete", "True")));
    }

    #[test]
    fn is_job_complete_false_when_failed() {
        assert!(!is_job_complete(&job_with_condition("Failed", "True")));
    }

    #[test]
    fn is_job_complete_false_when_no_status() {
        let job = Job::default();
        assert!(!is_job_complete(&job));
    }

    #[test]
    fn is_job_failed_true_when_failed() {
        assert!(is_job_failed(&job_with_condition("Failed", "True")));
    }

    #[test]
    fn is_job_failed_false_when_complete() {
        assert!(!is_job_failed(&job_with_condition("Complete", "True")));
    }

    #[test]
    fn is_job_failed_false_when_no_status() {
        let job = Job::default();
        assert!(!is_job_failed(&job));
    }

    #[test]
    fn job_failure_message_extracts_message() {
        let job = Job {
            status: Some(JobStatus {
                conditions: Some(vec![JobCondition {
                    type_: "Failed".to_string(),
                    status: "True".to_string(),
                    message: Some("BackoffLimitExceeded".to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            job_failure_message(&job),
            Some("BackoffLimitExceeded".to_string())
        );
    }

    #[test]
    fn job_failure_message_none_when_not_failed() {
        let job = job_with_condition("Complete", "True");
        assert_eq!(job_failure_message(&job), None);
    }
}
