//! LatticeJob integration tests
//!
//! Verifies that deploying a LatticeJob creates the expected Volcano VCJob,
//! mesh members, and tracing policies.
//!
//! Run standalone:
//! ```
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_job_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::helpers::{
    apply_yaml, delete_namespace, ensure_fresh_namespace, load_fixture_config, run_kubectl,
    setup_regcreds_infrastructure, wait_for_condition, wait_for_resource_phase, with_diagnostics,
    DiagnosticContext, DEFAULT_TIMEOUT, POLL_INTERVAL,
};

const JOB_NAMESPACE: &str = "batch";
const JOB_NAME: &str = "data-pipeline";
const CRON_JOB_NAME: &str = "scheduled-pipeline";

/// Deploy a LatticeJob and verify the controller creates the expected resources
async fn test_job_deployment(kubeconfig: &str) -> Result<(), String> {
    info!("[Job] Deploying LatticeJob from fixture...");

    // Ensure namespace exists before applying the job
    ensure_fresh_namespace(kubeconfig, JOB_NAMESPACE).await?;

    let job: lattice_common::crd::LatticeJob = load_fixture_config("batch-job.yaml")?;
    let yaml =
        serde_json::to_string(&job).map_err(|e| format!("Failed to serialize job fixture: {e}"))?;
    apply_yaml(kubeconfig, &yaml).await?;

    // Wait for controller to pick up and start reconciling.
    // Gang scheduling (minAvailable = sum of all replicas) can be slow
    // under cluster resource pressure from concurrent tests.
    wait_for_resource_phase(
        kubeconfig,
        "latticejob",
        JOB_NAMESPACE,
        JOB_NAME,
        "Running",
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!("[Job] LatticeJob reached Running phase");
    Ok(())
}

/// Verify Volcano VCJob was created with expected task structure
async fn test_vcjob_created(kubeconfig: &str) -> Result<(), String> {
    info!("[Job] Verifying VCJob creation...");

    // Fetch the full VCJob JSON with retry — during chaos the API server may
    // transiently return NotFound or connection errors.
    let kc = kubeconfig.to_string();
    let vcjob_json = wait_for_condition(
        "VCJob to be readable",
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                match run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "jobs.batch.volcano.sh",
                    JOB_NAME,
                    "-n",
                    JOB_NAMESPACE,
                    "-o",
                    "json",
                ])
                .await
                {
                    Ok(output) if !output.trim().is_empty() => Ok(Some(output)),
                    _ => Ok(None),
                }
            }
        },
    )
    .await?;

    let vcjob: serde_json::Value = serde_json::from_str(&vcjob_json)
        .map_err(|e| format!("Failed to parse VCJob JSON: {e}"))?;

    // Verify tasks
    let tasks = vcjob["spec"]["tasks"]
        .as_array()
        .ok_or("VCJob spec.tasks is not an array")?;
    let task_names: Vec<&str> = tasks
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    if !task_names.contains(&"master") || !task_names.contains(&"worker") {
        return Err(format!(
            "Expected VCJob tasks 'master' and 'worker', got: {:?}",
            task_names
        ));
    }

    // Verify scheduler is volcano
    let scheduler = vcjob["spec"]["schedulerName"]
        .as_str()
        .unwrap_or("unset");
    if scheduler != "volcano" {
        return Err(format!(
            "Expected schedulerName 'volcano', got: '{scheduler}'"
        ));
    }

    // Verify owner reference points to LatticeJob
    let owner_kind = vcjob["metadata"]["ownerReferences"][0]["kind"]
        .as_str()
        .unwrap_or("unset");
    if owner_kind != "LatticeJob" {
        return Err(format!(
            "Expected ownerReference kind 'LatticeJob', got: '{owner_kind}'"
        ));
    }

    info!("[Job] VCJob verified: 2 tasks, volcano scheduler, correct owner reference");
    Ok(())
}

/// Verify TracingPolicyNamespaced resources were created for each task.
///
/// Polls with a timeout because Tetragon CRD installation may still be
/// in progress when the job test starts (race between infra setup and
/// test execution).
async fn test_tracing_policies_created(kubeconfig: &str) -> Result<(), String> {
    info!("[Job] Verifying TracingPolicyNamespaced resources...");

    let expected = [
        format!("allow-binaries-{}-master", JOB_NAME),
        format!("allow-binaries-{}-worker", JOB_NAME),
    ];

    let kc = kubeconfig.to_string();
    let expected_clone = expected.clone();
    wait_for_condition(
        "TracingPolicyNamespaced resources to exist",
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            let expected = expected_clone.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "tracingpolicynamespaced",
                    "-n",
                    JOB_NAMESPACE,
                    "-o",
                    "jsonpath={.items[*].metadata.name}",
                ])
                .await?;

                let policies: Vec<&str> = output.split_whitespace().collect();
                for expected_name in &expected {
                    if !policies.contains(&expected_name.as_str()) {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        },
    )
    .await?;

    info!("[Job] TracingPolicyNamespaced resources verified (master + worker)");
    Ok(())
}

/// Verify the VCJob pod template contains expected container configuration
async fn test_vcjob_pod_template(kubeconfig: &str) -> Result<(), String> {
    info!("[Job] Verifying VCJob pod template...");

    // Fetch with retry — during chaos the API server may transiently fail
    let kc = kubeconfig.to_string();
    let output = wait_for_condition(
        "VCJob pod template to be readable",
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                match run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "jobs.batch.volcano.sh",
                    JOB_NAME,
                    "-n",
                    JOB_NAMESPACE,
                    "-o",
                    "json",
                ])
                .await
                {
                    Ok(output) if !output.trim().is_empty() => Ok(Some(output)),
                    _ => Ok(None),
                }
            }
        },
    )
    .await?;

    let vcjob: serde_json::Value =
        serde_json::from_str(&output).map_err(|e| format!("Failed to parse VCJob JSON: {e}"))?;

    let tasks = vcjob["spec"]["tasks"]
        .as_array()
        .ok_or("VCJob spec.tasks is not an array")?;

    for task in tasks {
        let name = task["name"].as_str().unwrap_or_default();
        let containers = &task["template"]["spec"]["containers"];

        if !containers.is_array() || containers.as_array().unwrap().is_empty() {
            return Err(format!("Task '{name}' has no containers in pod template"));
        }

        let image = containers[0]["image"]
            .as_str()
            .ok_or(format!("Task '{name}' container has no image"))?;

        if !image.contains("busybox") {
            return Err(format!(
                "Task '{name}' expected busybox image, got: {image}"
            ));
        }

        // Verify restart policy was set
        let restart = task["template"]["spec"]["restartPolicy"]
            .as_str()
            .unwrap_or("unset");

        info!("[Job] Task '{name}': image={image}, restartPolicy={restart}");
    }

    // Verify worker has OnFailure restart policy
    let worker = tasks
        .iter()
        .find(|t| t["name"].as_str() == Some("worker"))
        .ok_or("Worker task not found in VCJob")?;

    let worker_restart = worker["template"]["spec"]["restartPolicy"]
        .as_str()
        .unwrap_or("unset");

    if worker_restart != "OnFailure" {
        return Err(format!(
            "Worker task expected restartPolicy 'OnFailure', got: '{worker_restart}'"
        ));
    }

    info!("[Job] VCJob pod templates verified");
    Ok(())
}

/// Verify the job completes successfully (exercises full lifecycle including graph cleanup)
async fn test_job_completion(kubeconfig: &str) -> Result<(), String> {
    info!("[Job] Waiting for job to complete (tasks sleep 10s)...");

    wait_for_resource_phase(
        kubeconfig,
        "latticejob",
        JOB_NAMESPACE,
        JOB_NAME,
        "Succeeded",
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Verify observedGeneration was set
    let observed = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticejob",
        JOB_NAME,
        "-n",
        JOB_NAMESPACE,
        "-o",
        "jsonpath={.status.observedGeneration}",
    ])
    .await?;

    let gen = observed.trim();
    if gen.is_empty() || gen == "0" {
        return Err(format!("Expected observedGeneration > 0, got: '{gen}'"));
    }

    info!("[Job] Job completed successfully (observedGeneration={gen})");
    Ok(())
}

/// Deploy a cron LatticeJob and verify the controller creates a VCCronJob
async fn test_cron_job_deployment(kubeconfig: &str) -> Result<(), String> {
    info!("[CronJob] Deploying cron LatticeJob from fixture...");

    let job: lattice_common::crd::LatticeJob = load_fixture_config("cron-job.yaml")?;
    let yaml = serde_json::to_string(&job)
        .map_err(|e| format!("Failed to serialize cron job fixture: {e}"))?;
    apply_yaml(kubeconfig, &yaml).await?;

    // Cron jobs stay in Running (perpetual) — never transition to Succeeded
    wait_for_resource_phase(
        kubeconfig,
        "latticejob",
        JOB_NAMESPACE,
        CRON_JOB_NAME,
        "Running",
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!("[CronJob] Cron LatticeJob reached Running phase");
    Ok(())
}

/// Verify VCCronJob was created with expected schedule and task structure
async fn test_vccronjob_created(kubeconfig: &str) -> Result<(), String> {
    info!("[CronJob] Verifying VCCronJob creation...");

    // Fetch full VCCronJob JSON with retry for chaos resilience
    let kc = kubeconfig.to_string();
    let cronjob_json = wait_for_condition(
        "VCCronJob to be readable",
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                match run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "cronjobs.batch.volcano.sh",
                    CRON_JOB_NAME,
                    "-n",
                    JOB_NAMESPACE,
                    "-o",
                    "json",
                ])
                .await
                {
                    Ok(output) if !output.trim().is_empty() => Ok(Some(output)),
                    _ => Ok(None),
                }
            }
        },
    )
    .await?;

    let cronjob: serde_json::Value = serde_json::from_str(&cronjob_json)
        .map_err(|e| format!("Failed to parse VCCronJob JSON: {e}"))?;

    let schedule = cronjob["spec"]["schedule"]
        .as_str()
        .unwrap_or("unset");
    if schedule != "*/5 * * * *" {
        return Err(format!(
            "Expected schedule '*/5 * * * *', got: '{schedule}'"
        ));
    }

    let concurrency = cronjob["spec"]["concurrencyPolicy"]
        .as_str()
        .unwrap_or("unset");
    if concurrency != "Forbid" {
        return Err(format!(
            "Expected concurrencyPolicy 'Forbid', got: '{concurrency}'"
        ));
    }

    // Verify jobTemplate has tasks
    let tasks = cronjob["spec"]["jobTemplate"]["spec"]["tasks"]
        .as_array()
        .ok_or("VCCronJob jobTemplate.spec.tasks is not an array")?;
    let task_names: Vec<&str> = tasks
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    if !task_names.contains(&"worker") {
        return Err(format!(
            "Expected VCCronJob jobTemplate task 'worker', got: {task_names:?}"
        ));
    }

    // Verify owner reference
    let owner_kind = cronjob["metadata"]["ownerReferences"][0]["kind"]
        .as_str()
        .unwrap_or("unset");
    if owner_kind != "LatticeJob" {
        return Err(format!(
            "Expected ownerReference kind 'LatticeJob', got: '{owner_kind}'"
        ));
    }

    info!("[CronJob] VCCronJob verified: schedule, concurrencyPolicy, tasks, owner reference");
    Ok(())
}

/// Run all job integration tests
pub async fn run_job_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[Job] Running LatticeJob integration tests on {kubeconfig}");

    let diag = DiagnosticContext::new(kubeconfig, JOB_NAMESPACE);
    with_diagnostics(&diag, "Job", || async {
        run_job_test_sequence(kubeconfig).await?;
        delete_namespace(kubeconfig, JOB_NAMESPACE).await;
        Ok(())
    })
    .await
}

async fn run_job_test_sequence(kubeconfig: &str) -> Result<(), String> {
    // Deploy the one-shot job
    test_job_deployment(kubeconfig).await?;

    // Verify resources were created
    test_vcjob_created(kubeconfig).await?;
    test_vcjob_pod_template(kubeconfig).await?;
    test_tracing_policies_created(kubeconfig).await?;

    // Wait for full lifecycle completion
    test_job_completion(kubeconfig).await?;

    // Cron job tests (reuses the same namespace)
    test_cron_job_deployment(kubeconfig).await?;
    test_vccronjob_created(kubeconfig).await?;

    info!("[Job] All LatticeJob integration tests passed!");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_job_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    setup_regcreds_infrastructure(&resolved.kubeconfig)
        .await
        .unwrap();
    run_job_tests(&resolved.kubeconfig).await.unwrap();
}
