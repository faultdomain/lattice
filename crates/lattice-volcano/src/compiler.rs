//! VCJob compilation from LatticeJob specs
//!
//! Maps LatticeJob fields to Volcano VCJob resources for gang scheduling.

use std::collections::BTreeMap;

use lattice_common::crd::{LatticeJob, LatticeJobSpec, RestartPolicy, VolcanoPolicy};

use lattice_common::kube_utils::OwnerReference;

use crate::types::{
    self, VCCronJob, VCCronJobSpec, VCCronJobTemplate, VCJob, VCJobSpec, VCJobTask,
    VCJobTaskPolicy, VolcanoMetadata,
};

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

    // Training jobs enable the `svc` plugin so Volcano creates a headless
    // Service and sets hostname/subdomain on each pod for per-pod DNS
    // (e.g. `job-master-0.job.ns.svc.cluster.local`). Without `svc`,
    // only the service-level DNS record exists and MASTER_ADDR can't resolve.
    // `--publish-not-ready-addresses` is required because pods need to
    // discover each other before becoming ready (init_process_group blocks).
    let mut plugins = BTreeMap::from([("env".to_string(), vec![])]);
    if job.spec.training.is_some() {
        plugins.insert(
            "svc".to_string(),
            vec!["--publish-not-ready-addresses".to_string()],
        );
    }

    VCJob {
        api_version: "batch.volcano.sh/v1alpha1".to_string(),
        kind: "Job".to_string(),
        metadata: VolcanoMetadata {
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
            policies: match &job.spec.policies {
                Some(user_policies) => user_policies.iter().map(to_wire_policy).collect(),
                None => default_policies(job.spec.max_retry),
            },
            plugins,
            network_topology: job
                .spec
                .topology
                .as_ref()
                .map(types::network_topology_value),
        },
    }
}

/// Compile a LatticeJob into a Volcano VCCronJob.
///
/// Wraps the output of `compile_vcjob()` in a VCCronJob with cron scheduling fields.
/// Panics if `job.spec.schedule` is `None` — caller must check `is_cron()` first.
pub fn compile_vccronjob(job: &LatticeJob, vcjob: VCJob) -> VCCronJob {
    let schedule = job
        .spec
        .schedule
        .as_deref()
        .expect("compile_vccronjob called without schedule");

    VCCronJob {
        api_version: "batch.volcano.sh/v1alpha1".to_string(),
        kind: "CronJob".to_string(),
        metadata: vcjob.metadata.clone(),
        spec: VCCronJobSpec {
            schedule: schedule.to_string(),
            concurrency_policy: job.spec.concurrency_policy.as_ref().map(|p| p.to_string()),
            suspend: job.spec.suspend,
            successful_jobs_history_limit: job.spec.successful_jobs_history_limit,
            failed_jobs_history_limit: job.spec.failed_jobs_history_limit,
            starting_deadline_seconds: job.spec.starting_deadline_seconds,
            job_template: VCCronJobTemplate { spec: vcjob.spec },
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

            let task_policies = task_spec
                .policies
                .as_ref()
                .map(|p| p.iter().map(to_wire_policy).collect())
                .unwrap_or_default();

            Some(VCJobTask {
                name: task_name.clone(),
                replicas: task_spec.replicas,
                template,
                policies: task_policies,
            })
        })
        .collect()
}

/// Convert a typed `VolcanoPolicy` to a wire-format `VCJobTaskPolicy` with string fields.
fn to_wire_policy(policy: &VolcanoPolicy) -> VCJobTaskPolicy {
    VCJobTaskPolicy {
        event: policy.event.to_string(),
        action: policy.action.to_string(),
    }
}

fn default_policies(_max_retry: Option<u32>) -> Vec<VCJobTaskPolicy> {
    // PodEvicted and PodFailed both trigger RestartJob. Volcano manages
    // retries via maxRetry on the VCJob spec.
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
    use lattice_common::crd::{
        ConcurrencyPolicy, JobTaskSpec, LatticeJobSpec, RuntimeSpec, VolcanoPolicy,
        VolcanoPolicyAction, VolcanoPolicyEvent, WorkloadSpec,
    };

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

    use crate::test_utils::test_pod_template;

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
                policies: None,
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
        // Volcano env plugin injects VC_TASK_INDEX per pod
        assert!(vcjob.spec.plugins.contains_key("env"));
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
                policies: None,
            },
        );
        tasks.insert(
            "worker".to_string(),
            JobTaskSpec {
                replicas: 4,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
                restart_policy: Some(RestartPolicy::OnFailure),
                policies: None,
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
                policies: None,
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
                policies: None,
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
    fn default_policies_always_includes_pod_failed() {
        let job = test_job(BTreeMap::new());
        let vcjob = compile_vcjob(&job, &BTreeMap::new());
        // Both PodEvicted and PodFailed are always present
        assert_eq!(vcjob.spec.policies.len(), 2);
        assert_eq!(vcjob.spec.policies[0].event, "PodEvicted");
        assert_eq!(vcjob.spec.policies[1].event, "PodFailed");
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

    #[test]
    fn compile_vccronjob_wraps_vcjob() {
        let mut tasks = BTreeMap::new();
        tasks.insert(
            "worker".to_string(),
            JobTaskSpec {
                replicas: 2,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
                restart_policy: Some(RestartPolicy::Never),
                policies: None,
            },
        );

        let spec = LatticeJobSpec {
            schedule: Some("*/10 * * * *".to_string()),
            concurrency_policy: Some(ConcurrencyPolicy::Forbid),
            suspend: Some(false),
            successful_jobs_history_limit: Some(5),
            failed_jobs_history_limit: Some(2),
            starting_deadline_seconds: Some(120),
            tasks,
            ..Default::default()
        };

        let job = test_job_with_spec(spec);
        let templates =
            BTreeMap::from([("worker".to_string(), test_pod_template("worker:latest"))]);
        let vcjob = compile_vcjob(&job, &templates);
        let cron = compile_vccronjob(&job, vcjob);

        assert_eq!(cron.api_version, "batch.volcano.sh/v1alpha1");
        assert_eq!(cron.kind, "CronJob");
        assert_eq!(cron.metadata.name, "test-job");
        assert_eq!(cron.spec.schedule, "*/10 * * * *");
        assert_eq!(cron.spec.concurrency_policy, Some("Forbid".to_string()));
        assert_eq!(cron.spec.suspend, Some(false));
        assert_eq!(cron.spec.successful_jobs_history_limit, Some(5));
        assert_eq!(cron.spec.failed_jobs_history_limit, Some(2));
        assert_eq!(cron.spec.starting_deadline_seconds, Some(120));
        assert_eq!(cron.spec.job_template.spec.tasks.len(), 1);
        assert_eq!(cron.spec.job_template.spec.scheduler_name, "volcano");
    }

    #[test]
    fn compile_vccronjob_defaults() {
        let spec = LatticeJobSpec {
            schedule: Some("0 0 * * *".to_string()),
            ..Default::default()
        };

        let job = test_job_with_spec(spec);
        let vcjob = compile_vcjob(&job, &BTreeMap::new());
        let cron = compile_vccronjob(&job, vcjob);

        assert_eq!(cron.spec.schedule, "0 0 * * *");
        assert_eq!(cron.spec.concurrency_policy, None);
        assert_eq!(cron.spec.suspend, None);
        assert_eq!(cron.spec.successful_jobs_history_limit, None);
        assert_eq!(cron.spec.failed_jobs_history_limit, None);
        assert_eq!(cron.spec.starting_deadline_seconds, None);
    }

    fn test_job_with_spec(spec: LatticeJobSpec) -> LatticeJob {
        let mut job = LatticeJob::new("test-job", spec);
        job.metadata.namespace = Some("default".to_string());
        job.metadata.uid = Some("test-uid-123".to_string());
        job
    }

    #[test]
    fn explicit_job_policies_override_defaults() {
        let spec = LatticeJobSpec {
            policies: Some(vec![VolcanoPolicy {
                event: VolcanoPolicyEvent::PodFailed,
                action: VolcanoPolicyAction::AbortJob,
            }]),
            ..Default::default()
        };

        let job = test_job_with_spec(spec);
        let vcjob = compile_vcjob(&job, &BTreeMap::new());

        assert_eq!(vcjob.spec.policies.len(), 1);
        assert_eq!(vcjob.spec.policies[0].event, "PodFailed");
        assert_eq!(vcjob.spec.policies[0].action, "AbortJob");
    }

    #[test]
    fn task_level_policies_on_vcjob_task() {
        let mut tasks = BTreeMap::new();
        tasks.insert(
            "coordinator".to_string(),
            JobTaskSpec {
                replicas: 1,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
                restart_policy: None,
                policies: Some(vec![VolcanoPolicy {
                    event: VolcanoPolicyEvent::TaskCompleted,
                    action: VolcanoPolicyAction::CompleteJob,
                }]),
            },
        );

        let job = test_job(tasks);
        let templates = BTreeMap::from([(
            "coordinator".to_string(),
            test_pod_template("coord:latest"),
        )]);

        let vcjob = compile_vcjob(&job, &templates);

        assert_eq!(vcjob.spec.tasks.len(), 1);
        assert_eq!(vcjob.spec.tasks[0].policies.len(), 1);
        assert_eq!(vcjob.spec.tasks[0].policies[0].event, "TaskCompleted");
        assert_eq!(vcjob.spec.tasks[0].policies[0].action, "CompleteJob");
    }

    #[test]
    fn no_task_policies_yields_empty_vec() {
        let mut tasks = BTreeMap::new();
        tasks.insert(
            "worker".to_string(),
            JobTaskSpec {
                replicas: 1,
                workload: WorkloadSpec::default(),
                runtime: RuntimeSpec::default(),
                restart_policy: None,
                policies: None,
            },
        );

        let job = test_job(tasks);
        let templates =
            BTreeMap::from([("worker".to_string(), test_pod_template("worker:latest"))]);

        let vcjob = compile_vcjob(&job, &templates);

        assert!(vcjob.spec.tasks[0].policies.is_empty());
    }
}
