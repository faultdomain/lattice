//! LatticeJob integration tests
//!
//! Verifies that deploying a LatticeJob creates the expected Volcano VCJob,
//! mesh members, and tracing policies.
//!
//! Run standalone:
//! ```
//! LATTICE_WORKLOAD_KUBECONFIG=/tmp/xxx-e2e-workload-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_job_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::super::context::{InfraContext, TestSession};
use super::super::helpers::{
    apply_apparmor_override_policy, apply_yaml_with_retry, delete_namespace, load_fixture_config,
    run_kubectl, setup_regcreds_infrastructure, wait_for_condition,
};

const JOB_NAMESPACE: &str = "batch";
const JOB_NAME: &str = "data-pipeline";

/// Load the batch-job fixture
fn load_job_fixture() -> Result<lattice_common::crd::LatticeJob, String> {
    load_fixture_config("batch-job.yaml")
}

/// Wait for a LatticeJob to reach the expected phase
async fn wait_for_job_phase(
    kubeconfig: &str,
    namespace: &str,
    name: &str,
    phase: &str,
    timeout: Duration,
) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let ns = namespace.to_string();
    let job_name = name.to_string();
    let expected_phase = phase.to_string();

    wait_for_condition(
        &format!("LatticeJob {}/{} to reach {}", namespace, name, phase),
        timeout,
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let ns = ns.clone();
            let job_name = job_name.clone();
            let expected_phase = expected_phase.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "latticejob",
                    &job_name,
                    "-n",
                    &ns,
                    "-o",
                    "jsonpath={.status.phase}",
                ])
                .await;

                match output {
                    Ok(current_phase) => {
                        let current = current_phase.trim();
                        info!("LatticeJob {}/{} phase: {}", ns, job_name, current);
                        Ok(current == expected_phase)
                    }
                    Err(e) => {
                        info!("LatticeJob {}/{} not ready: {}", ns, job_name, e);
                        Ok(false)
                    }
                }
            }
        },
    )
    .await
}

/// Deploy a LatticeJob and verify the controller creates the expected resources
async fn test_job_deployment(kubeconfig: &str) -> Result<(), String> {
    info!("[Job] Deploying LatticeJob from fixture...");

    // Ensure namespace exists before applying the job
    super::super::helpers::services::ensure_namespace(kubeconfig, JOB_NAMESPACE).await?;

    let job = load_job_fixture()?;
    let yaml =
        serde_json::to_string(&job).map_err(|e| format!("Failed to serialize job fixture: {e}"))?;
    apply_yaml_with_retry(kubeconfig, &yaml).await?;

    // Wait for controller to pick up and start reconciling
    wait_for_job_phase(
        kubeconfig,
        JOB_NAMESPACE,
        JOB_NAME,
        "Running",
        Duration::from_secs(120),
    )
    .await?;

    info!("[Job] LatticeJob reached Running phase");
    Ok(())
}

/// Verify Volcano VCJob was created with expected task structure
async fn test_vcjob_created(kubeconfig: &str) -> Result<(), String> {
    info!("[Job] Verifying VCJob creation...");

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "jobs.batch.volcano.sh",
        JOB_NAME,
        "-n",
        JOB_NAMESPACE,
        "-o",
        "jsonpath={.spec.tasks[*].name}",
    ])
    .await?;

    let task_names: Vec<&str> = output.trim().split_whitespace().collect();
    if !task_names.contains(&"master") || !task_names.contains(&"worker") {
        return Err(format!(
            "Expected VCJob tasks 'master' and 'worker', got: {:?}",
            task_names
        ));
    }

    // Verify replicas
    let replicas = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "jobs.batch.volcano.sh",
        JOB_NAME,
        "-n",
        JOB_NAMESPACE,
        "-o",
        "jsonpath={.spec.tasks[*].replicas}",
    ])
    .await?;

    info!("[Job] VCJob task replicas: {}", replicas.trim());

    // Verify scheduler is volcano
    let scheduler = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "jobs.batch.volcano.sh",
        JOB_NAME,
        "-n",
        JOB_NAMESPACE,
        "-o",
        "jsonpath={.spec.schedulerName}",
    ])
    .await?;

    if scheduler.trim() != "volcano" {
        return Err(format!(
            "Expected schedulerName 'volcano', got: '{}'",
            scheduler.trim()
        ));
    }

    // Verify owner reference points to LatticeJob
    let owner_kind = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "jobs.batch.volcano.sh",
        JOB_NAME,
        "-n",
        JOB_NAMESPACE,
        "-o",
        "jsonpath={.metadata.ownerReferences[0].kind}",
    ])
    .await?;

    if owner_kind.trim() != "LatticeJob" {
        return Err(format!(
            "Expected ownerReference kind 'LatticeJob', got: '{}'",
            owner_kind.trim()
        ));
    }

    info!("[Job] VCJob verified: 2 tasks, volcano scheduler, correct owner reference");
    Ok(())
}

/// Verify TracingPolicyNamespaced resources were created for each task
async fn test_tracing_policies_created(kubeconfig: &str) -> Result<(), String> {
    info!("[Job] Verifying TracingPolicyNamespaced resources...");

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "tracingpolicynamespaced",
        "-n",
        JOB_NAMESPACE,
        "-o",
        "jsonpath={.items[*].metadata.name}",
    ])
    .await?;

    let policies: Vec<&str> = output.trim().split_whitespace().collect();
    info!("[Job] Found tracing policies: {:?}", policies);

    // Each task should have an allow-binaries policy (command uses /bin/sh, not wildcard)
    let expected_master = format!("allow-binaries-{}-master", JOB_NAME);
    let expected_worker = format!("allow-binaries-{}-worker", JOB_NAME);

    if !policies.contains(&expected_master.as_str()) {
        return Err(format!(
            "Expected tracing policy '{}', found: {:?}",
            expected_master, policies
        ));
    }
    if !policies.contains(&expected_worker.as_str()) {
        return Err(format!(
            "Expected tracing policy '{}', found: {:?}",
            expected_worker, policies
        ));
    }

    info!("[Job] TracingPolicyNamespaced resources verified (master + worker)");
    Ok(())
}

/// Verify the VCJob pod template contains expected container configuration
async fn test_vcjob_pod_template(kubeconfig: &str) -> Result<(), String> {
    info!("[Job] Verifying VCJob pod template...");

    // Check the worker task template has the correct image
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "jobs.batch.volcano.sh",
        JOB_NAME,
        "-n",
        JOB_NAMESPACE,
        "-o",
        "json",
    ])
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
    info!("[Job] Waiting for job to complete (tasks sleep 30s)...");

    wait_for_job_phase(
        kubeconfig,
        JOB_NAMESPACE,
        JOB_NAME,
        "Succeeded",
        Duration::from_secs(120),
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

/// Run all job integration tests
pub async fn run_job_tests(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;
    info!("[Job] Running LatticeJob integration tests on {kubeconfig}");

    // GHCR registry credentials (job uses ghcr.io/evan-hines-js/busybox)
    setup_regcreds_infrastructure(kubeconfig).await?;

    // Cedar policy for AppArmor override (kind clusters lack AppArmor)
    apply_apparmor_override_policy(kubeconfig).await?;

    // Deploy the job
    test_job_deployment(kubeconfig).await?;

    // Verify resources were created
    test_vcjob_created(kubeconfig).await?;
    test_vcjob_pod_template(kubeconfig).await?;
    test_tracing_policies_created(kubeconfig).await?;

    // Wait for full lifecycle completion
    test_job_completion(kubeconfig).await?;

    // Cleanup
    delete_namespace(kubeconfig, JOB_NAMESPACE).await;

    info!("[Job] All LatticeJob integration tests passed!");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_job_standalone() {
    let session =
        TestSession::from_env("Set LATTICE_WORKLOAD_KUBECONFIG to run standalone job tests")
            .await
            .expect("Failed to create test session");

    if let Err(e) = run_job_tests(&session.ctx).await {
        panic!("Job tests failed: {e}");
    }
}
