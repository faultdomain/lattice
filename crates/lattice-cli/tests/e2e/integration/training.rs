//! Training integration tests
//!
//! Two test suites:
//!
//! **Compilation tests** — verify the Lattice job compiler produces the correct
//! Kubernetes resources (ConfigMaps, headless Service, PVCs) for checkpoint
//! training jobs.
//!
//! **PyTorch distributed tests** — deploy a real 2-node DDP job (master x1 +
//! worker x1) and verify that globally unique RANK values are computed
//! correctly, `init_process_group` succeeds, and gradient sync works.
//!
//! Run standalone:
//! ```
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_training_standalone -- --ignored --nocapture
//!
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_pytorch_training_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::collections::HashSet;
use std::time::Duration;

use tracing::info;

use super::super::helpers::{
    apply_yaml, delete_namespace, ensure_fresh_namespace, load_fixture_config, run_kubectl,
    setup_regcreds_infrastructure, wait_for_resource_phase, DEFAULT_TIMEOUT,
};

// =============================================================================
// Shared helpers
// =============================================================================

/// Get pod names for a Volcano job
async fn get_job_pod_names(
    kubeconfig: &str,
    namespace: &str,
    job_name: &str,
) -> Result<Vec<String>, String> {
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pods",
        "-n",
        namespace,
        "-l",
        &format!("volcano.sh/job-name={}", job_name),
        "-o",
        "jsonpath={.items[*].metadata.name}",
    ])
    .await?;

    Ok(output.split_whitespace().map(String::from).collect())
}

/// Get logs from a specific pod container
async fn get_pod_logs(
    kubeconfig: &str,
    namespace: &str,
    pod_name: &str,
    container: &str,
) -> Result<String, String> {
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "logs",
        pod_name,
        "-n",
        namespace,
        "-c",
        container,
    ])
    .await
    .map_err(|e| format!("Failed to get logs for pod {pod_name}: {e}"))
}

/// Deploy a job fixture and wait for a target phase
async fn deploy_and_wait(
    kubeconfig: &str,
    namespace: &str,
    fixture: &str,
    job_name: &str,
    phase: &str,
    timeout: Duration,
) -> Result<(), String> {
    ensure_fresh_namespace(kubeconfig, namespace).await?;

    let job: lattice_common::crd::LatticeJob = load_fixture_config(fixture)?;
    let yaml =
        serde_json::to_string(&job).map_err(|e| format!("Failed to serialize fixture: {e}"))?;
    apply_yaml(kubeconfig, &yaml).await?;

    wait_for_resource_phase(
        kubeconfig,
        "latticejob",
        namespace,
        job_name,
        phase,
        timeout,
    )
    .await
}

// =============================================================================
// Checkpoint compilation tests
// =============================================================================

const TRAINING_NAMESPACE: &str = "training-test";
const CKPT_JOB_NAME: &str = "training-ckpt";

async fn test_training_deployment(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Deploying training checkpoint job...");

    deploy_and_wait(
        kubeconfig,
        TRAINING_NAMESPACE,
        "training-checkpoint-job.yaml",
        CKPT_JOB_NAME,
        "Running",
        Duration::from_secs(180),
    )
    .await?;

    info!("[Training] Job reached Running phase");
    Ok(())
}

async fn test_headless_service(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Verifying headless Service...");

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "service",
        CKPT_JOB_NAME,
        "-n",
        TRAINING_NAMESPACE,
        "-o",
        "json",
    ])
    .await?;

    let svc: serde_json::Value =
        serde_json::from_str(&output).map_err(|e| format!("Failed to parse Service JSON: {e}"))?;

    let cluster_ip = svc["spec"]["clusterIP"].as_str().unwrap_or("");
    if cluster_ip != "None" {
        return Err(format!(
            "Expected headless Service (clusterIP=None), got: '{cluster_ip}'"
        ));
    }

    let selector = svc["spec"]["selector"]["volcano.sh/job-name"]
        .as_str()
        .unwrap_or("");
    if selector != CKPT_JOB_NAME {
        return Err(format!(
            "Expected selector volcano.sh/job-name={CKPT_JOB_NAME}, got: '{selector}'"
        ));
    }

    let publish = svc["spec"]["publishNotReadyAddresses"]
        .as_bool()
        .unwrap_or(false);
    if !publish {
        return Err("Expected publishNotReadyAddresses=true".to_string());
    }

    info!("[Training] Headless Service verified");
    Ok(())
}

async fn test_training_env_vars(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Verifying training env vars...");

    for task_name in ["master", "worker"] {
        let cm_name = format!("{}-{}-main-env", CKPT_JOB_NAME, task_name);

        let output = run_kubectl(&[
            "--kubeconfig",
            kubeconfig,
            "get",
            "configmap",
            &cm_name,
            "-n",
            TRAINING_NAMESPACE,
            "-o",
            "json",
        ])
        .await
        .map_err(|e| format!("ConfigMap '{cm_name}' not found: {e}"))?;

        let cm: serde_json::Value = serde_json::from_str(&output)
            .map_err(|e| format!("Failed to parse ConfigMap JSON: {e}"))?;

        let data = cm["data"]
            .as_object()
            .ok_or(format!("ConfigMap '{cm_name}' has no data"))?;

        // PyTorch distributed env vars (shared across all pods in the task).
        // RANK/NODE_RANK are NOT in the ConfigMap — they're computed at pod
        // startup by the lattice-rank init container.
        for required in ["MASTER_ADDR", "MASTER_PORT", "WORLD_SIZE", "NNODES"] {
            if !data.contains_key(required) {
                return Err(format!(
                    "Task '{task_name}' ConfigMap missing training env var: {required}"
                ));
            }
        }

        let ckpt_dir = data
            .get("CHECKPOINT_DIR")
            .and_then(|v| v.as_str())
            .ok_or(format!(
                "Task '{task_name}' ConfigMap missing CHECKPOINT_DIR"
            ))?;

        if ckpt_dir != "/checkpoints" {
            return Err(format!(
                "Task '{task_name}' CHECKPOINT_DIR expected '/checkpoints', got: '{ckpt_dir}'"
            ));
        }

        info!("[Training] Task '{task_name}': ConfigMap '{cm_name}' has training env vars");
    }

    Ok(())
}

async fn test_checkpoint_pvcs(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Verifying checkpoint PVCs...");

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pvc",
        "-n",
        TRAINING_NAMESPACE,
        "-l",
        &format!("lattice.dev/training-job={}", CKPT_JOB_NAME),
        "-o",
        "jsonpath={.items[*].metadata.name}",
    ])
    .await?;

    let pvcs: Vec<&str> = output.split_whitespace().collect();
    if pvcs.is_empty() {
        return Err("No PVCs found with lattice.dev/training-job label".to_string());
    }

    info!("[Training] Found {} labeled PVCs: {:?}", pvcs.len(), pvcs);
    Ok(())
}

/// Run checkpoint compilation integration tests
pub async fn run_training_tests(kubeconfig: &str) -> Result<(), String> {
    info!("\n========================================");
    info!("Training Compilation Tests");
    info!("========================================\n");

    setup_regcreds_infrastructure(kubeconfig).await?;

    let result = async {
        test_training_deployment(kubeconfig).await?;
        test_headless_service(kubeconfig).await?;
        test_training_env_vars(kubeconfig).await?;
        test_checkpoint_pvcs(kubeconfig).await?;

        info!("\n========================================");
        info!("Training Compilation Tests: PASSED");
        info!("========================================\n");

        Ok(())
    }
    .await;

    delete_namespace(kubeconfig, TRAINING_NAMESPACE).await;
    result
}

#[tokio::test]
#[ignore]
async fn test_training_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_training_tests(&resolved.kubeconfig).await.unwrap();
}

// =============================================================================
// PyTorch distributed training tests
// =============================================================================

const PYTORCH_NAMESPACE: &str = "training-pytorch-test";
const PYTORCH_JOB_NAME: &str = "pytorch-ddp";

/// Deploy the PyTorch DDP job, wait for it to succeed, then verify logs.
///
/// The job has master x1 + worker x1 running a real PyTorch DDP training
/// iteration with `init_process_group(backend='gloo')`. If the RANK env
/// vars are wrong (the bug this test catches), `init_process_group` hangs
/// or crashes and the job never reaches Succeeded.
async fn test_pytorch_distributed_training(kubeconfig: &str) -> Result<(), String> {
    info!("[PyTorch] Deploying PyTorch DDP job...");

    deploy_and_wait(
        kubeconfig,
        PYTORCH_NAMESPACE,
        "training-pytorch-distributed.yaml",
        PYTORCH_JOB_NAME,
        "Succeeded",
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!("[PyTorch] Job succeeded — verifying logs...");

    let pod_names = get_job_pod_names(kubeconfig, PYTORCH_NAMESPACE, PYTORCH_JOB_NAME).await?;
    if pod_names.len() != 2 {
        return Err(format!(
            "Expected 2 pods (master + worker), found {}: {:?}",
            pod_names.len(),
            pod_names
        ));
    }

    let mut all_ranks: HashSet<String> = HashSet::new();

    for pod_name in &pod_names {
        let logs = get_pod_logs(kubeconfig, PYTORCH_NAMESPACE, pod_name, "main").await?;

        if !logs.contains("PYTORCH_DISTRIBUTED_SUCCESS") {
            return Err(format!(
                "Pod {pod_name} missing PYTORCH_DISTRIBUTED_SUCCESS marker.\nLogs:\n{}",
                &logs[..logs.len().min(2000)]
            ));
        }

        // Extract rank from "initialized rank=N" to verify uniqueness
        for line in logs.lines() {
            if let Some(rest) = line.strip_prefix("STEP: initialized rank=") {
                if let Some(rank_str) = rest.split_whitespace().next() {
                    all_ranks.insert(rank_str.to_string());
                }
            }
        }

        info!("[PyTorch] Pod {pod_name}: PYTORCH_DISTRIBUTED_SUCCESS confirmed");
    }

    if all_ranks.len() != 2 {
        return Err(format!(
            "RANK collision detected! Expected 2 unique ranks, got {:?}",
            all_ranks
        ));
    }

    info!("[PyTorch] Verified 2 unique ranks: {:?}", all_ranks);
    Ok(())
}

/// Run all PyTorch distributed training tests
pub async fn run_pytorch_training_tests(kubeconfig: &str) -> Result<(), String> {
    info!("\n========================================");
    info!("PyTorch Distributed Training Tests");
    info!("========================================\n");

    setup_regcreds_infrastructure(kubeconfig).await?;

    let result = async {
        test_pytorch_distributed_training(kubeconfig).await?;

        info!("\n========================================");
        info!("PyTorch Distributed Training Tests: PASSED");
        info!("========================================\n");

        Ok(())
    }
    .await;

    delete_namespace(kubeconfig, PYTORCH_NAMESPACE).await;
    result
}

#[tokio::test]
#[ignore]
async fn test_pytorch_training_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_pytorch_training_tests(&resolved.kubeconfig)
        .await
        .unwrap();
}
