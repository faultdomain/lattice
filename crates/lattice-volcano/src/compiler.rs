//! VCJob compilation from LatticeJob specs
//!
//! Maps LatticeJob fields to Volcano VCJob resources for gang scheduling.

use std::collections::BTreeMap;

use lattice_common::crd::{LatticeJob, LatticeJobSpec, RestartPolicy};

use crate::types::{OwnerReference, VCJob, VCJobMetadata, VCJobSpec, VCJobTask, VCJobTaskPolicy};

/// Compile a LatticeJob into a Volcano VCJob.
///
/// Takes the LatticeJob and pre-serialized pod template JSON for each task.
/// The caller (lattice-job compiler) is responsible for compiling workload specs
/// into pod templates via `WorkloadCompiler` and serializing them.
pub fn compile_vcjob(
    job: &LatticeJob,
    task_pod_templates: &BTreeMap<String, serde_json::Value>,
) -> VCJob {
    let name = job.metadata.name.as_deref().unwrap_or_default();
    let namespace = job.metadata.namespace.as_deref().unwrap_or("default");
    let uid = job.metadata.uid.as_deref().unwrap_or_default();

    let tasks = compile_tasks(&job.spec, task_pod_templates);

    let min_available = job
        .spec
        .min_available
        .or_else(|| Some(job.spec.tasks.values().map(|t| t.replicas).sum()));

    VCJob {
        api_version: "batch.volcano.sh/v1alpha1".to_string(),
        kind: "Job".to_string(),
        metadata: VCJobMetadata {
            name: name.to_string(),
            namespace: namespace.to_string(),
            labels: BTreeMap::from([
                (
                    "app.kubernetes.io/managed-by".to_string(),
                    "lattice".to_string(),
                ),
                ("app.kubernetes.io/name".to_string(), name.to_string()),
            ]),
            owner_references: vec![OwnerReference {
                api_version: "lattice.dev/v1alpha1".to_string(),
                kind: "LatticeJob".to_string(),
                name: name.to_string(),
                uid: uid.to_string(),
                controller: Some(true),
                block_owner_deletion: Some(true),
            }],
        },
        spec: VCJobSpec {
            scheduler_name: job.spec.scheduler_name.clone(),
            min_available,
            max_retry: job.spec.max_retry,
            queue: job.spec.queue.clone(),
            priority_class_name: job.spec.priority_class_name.clone(),
            tasks,
            policies: default_policies(),
        },
    }
}

fn compile_tasks(
    spec: &LatticeJobSpec,
    pod_templates: &BTreeMap<String, serde_json::Value>,
) -> Vec<VCJobTask> {
    spec.tasks
        .iter()
        .filter_map(|(task_name, task_spec)| {
            let mut template = pod_templates.get(task_name)?.clone();

            // Set restart policy on the pod spec
            let restart_policy = task_spec
                .restart_policy
                .as_ref()
                .unwrap_or(&RestartPolicy::Never);
            if let Some(spec) = template.get_mut("spec") {
                spec["restartPolicy"] = serde_json::Value::String(restart_policy.to_string());
            }

            Some(VCJobTask {
                name: task_name.clone(),
                replicas: task_spec.replicas,
                template,
                policies: vec![],
            })
        })
        .collect()
}

fn default_policies() -> Vec<VCJobTaskPolicy> {
    vec![
        VCJobTaskPolicy {
            event: "PodEvicted".to_string(),
            action: "RestartJob".to_string(),
        },
        VCJobTaskPolicy {
            event: "PodFailed".to_string(),
            action: "RestartJob".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{JobTaskSpec, LatticeJobSpec, RuntimeSpec, WorkloadSpec};

    fn test_job(tasks: BTreeMap<String, JobTaskSpec>) -> LatticeJob {
        let spec = LatticeJobSpec {
            tasks,
            ..Default::default()
        };

        let mut job = LatticeJob::new("test-job", spec);
        job.metadata.namespace = Some("default".to_string());
        job.metadata.uid = Some("test-uid-123".to_string());
        job
    }

    fn test_pod_template(image: &str) -> serde_json::Value {
        serde_json::json!({
            "metadata": {
                "labels": {"app": "test"}
            },
            "spec": {
                "containers": [{
                    "name": "main",
                    "image": image
                }]
            }
        })
    }

    #[test]
    fn single_task_vcjob() {
        let mut tasks = BTreeMap::new();
        tasks.insert(
            "worker".to_string(),
            JobTaskSpec {
                replicas: 3,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
                restart_policy: Some(RestartPolicy::OnFailure),
            },
        );

        let job = test_job(tasks);
        let templates =
            BTreeMap::from([("worker".to_string(), test_pod_template("worker:latest"))]);

        let vcjob = compile_vcjob(&job, &templates);

        assert_eq!(vcjob.api_version, "batch.volcano.sh/v1alpha1");
        assert_eq!(vcjob.kind, "Job");
        assert_eq!(vcjob.metadata.name, "test-job");
        assert_eq!(vcjob.spec.scheduler_name, "volcano");
        assert_eq!(vcjob.spec.min_available, Some(3));
        assert_eq!(vcjob.spec.tasks.len(), 1);
        assert_eq!(vcjob.spec.tasks[0].name, "worker");
        assert_eq!(vcjob.spec.tasks[0].replicas, 3);
        assert_eq!(
            vcjob.spec.tasks[0].template["spec"]["restartPolicy"],
            "OnFailure"
        );
    }

    #[test]
    fn multi_task_vcjob() {
        let mut tasks = BTreeMap::new();
        tasks.insert(
            "master".to_string(),
            JobTaskSpec {
                replicas: 1,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
                restart_policy: None,
            },
        );
        tasks.insert(
            "worker".to_string(),
            JobTaskSpec {
                replicas: 4,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
                restart_policy: Some(RestartPolicy::OnFailure),
            },
        );

        let job = test_job(tasks);
        let templates = BTreeMap::from([
            ("master".to_string(), test_pod_template("master:latest")),
            ("worker".to_string(), test_pod_template("worker:latest")),
        ]);

        let vcjob = compile_vcjob(&job, &templates);

        assert_eq!(vcjob.spec.tasks.len(), 2);
        assert_eq!(vcjob.spec.min_available, Some(5)); // 1 + 4
    }

    #[test]
    fn explicit_min_available_overrides_sum() {
        let mut tasks = BTreeMap::new();
        tasks.insert(
            "worker".to_string(),
            JobTaskSpec {
                replicas: 4,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
                restart_policy: None,
            },
        );

        let spec = LatticeJobSpec {
            min_available: Some(2),
            tasks,
            ..Default::default()
        };

        let mut job = LatticeJob::new("test-job", spec);
        job.metadata.namespace = Some("default".to_string());
        job.metadata.uid = Some("uid".to_string());

        let templates =
            BTreeMap::from([("worker".to_string(), test_pod_template("worker:latest"))]);

        let vcjob = compile_vcjob(&job, &templates);
        assert_eq!(vcjob.spec.min_available, Some(2));
    }

    #[test]
    fn owner_reference_set() {
        let job = test_job(BTreeMap::new());
        let vcjob = compile_vcjob(&job, &BTreeMap::new());

        assert_eq!(vcjob.metadata.owner_references.len(), 1);
        let oref = &vcjob.metadata.owner_references[0];
        assert_eq!(oref.kind, "LatticeJob");
        assert_eq!(oref.name, "test-job");
        assert_eq!(oref.controller, Some(true));
    }

    #[test]
    fn default_restart_policy_is_never() {
        let mut tasks = BTreeMap::new();
        tasks.insert(
            "worker".to_string(),
            JobTaskSpec {
                replicas: 1,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
                restart_policy: None,
            },
        );

        let job = test_job(tasks);
        let templates =
            BTreeMap::from([("worker".to_string(), test_pod_template("worker:latest"))]);

        let vcjob = compile_vcjob(&job, &templates);
        assert_eq!(
            vcjob.spec.tasks[0].template["spec"]["restartPolicy"],
            "Never"
        );
    }

    #[test]
    fn default_policies_present() {
        let job = test_job(BTreeMap::new());
        let vcjob = compile_vcjob(&job, &BTreeMap::new());
        assert_eq!(vcjob.spec.policies.len(), 2);
    }

    #[test]
    fn priority_class_name_propagated() {
        let spec = LatticeJobSpec {
            priority_class_name: Some("high-priority".to_string()),
            ..Default::default()
        };
        let mut job = LatticeJob::new("test-job", spec);
        job.metadata.namespace = Some("default".to_string());
        job.metadata.uid = Some("uid".to_string());

        let vcjob = compile_vcjob(&job, &BTreeMap::new());
        assert_eq!(
            vcjob.spec.priority_class_name,
            Some("high-priority".to_string())
        );
    }
}
