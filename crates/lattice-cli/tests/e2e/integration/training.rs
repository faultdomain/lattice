//! Training compilation integration tests
//!
//! Verifies that the Lattice job compiler produces the correct Kubernetes
//! resources for distributed training jobs:
//! - Training env var injection (MASTER_ADDR, WORLD_SIZE, CHECKPOINT_DIR)
//! - Headless Service creation for pod DNS resolution
//! - Checkpoint PVCs with training-job labels
//! - Velero Schedule for periodic PVC snapshots (disaster recovery)
//! - Velero Schedule cleanup via finalizer on job deletion
//!
//! Run standalone:
//! ```
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_training_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::super::helpers::{
    apply_yaml, cleanup_minio_backup_storage, delete_namespace, ensure_fresh_namespace,
    load_fixture_config, run_kubectl, setup_minio_backup_storage, setup_regcreds_infrastructure,
    wait_for_condition, wait_for_resource_phase, VELERO_NAMESPACE,
};

const TRAINING_NAMESPACE: &str = "training-test";
const JOB_NAME: &str = "training-ckpt";

// =============================================================================
// Compilation verification
// =============================================================================

/// Deploy the training job and wait for Running phase
async fn test_training_deployment(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Deploying training checkpoint job...");

    ensure_fresh_namespace(kubeconfig, TRAINING_NAMESPACE).await?;

    let job: lattice_common::crd::LatticeJob =
        load_fixture_config("training-checkpoint-job.yaml")?;
    let yaml =
        serde_json::to_string(&job).map_err(|e| format!("Failed to serialize fixture: {e}"))?;
    apply_yaml(kubeconfig, &yaml).await?;

    wait_for_resource_phase(
        kubeconfig,
        "latticejob",
        TRAINING_NAMESPACE,
        JOB_NAME,
        "Running",
        Duration::from_secs(180),
    )
    .await?;

    info!("[Training] Job reached Running phase");
    Ok(())
}

/// Verify the headless Service was created for pod DNS resolution
async fn test_headless_service(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Verifying headless Service...");

    let cluster_ip = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "service",
        JOB_NAME,
        "-n",
        TRAINING_NAMESPACE,
        "-o",
        "jsonpath={.spec.clusterIP}",
    ])
    .await?;

    if cluster_ip.trim() != "None" {
        return Err(format!(
            "Expected headless Service (clusterIP=None), got: '{}'",
            cluster_ip.trim()
        ));
    }

    let selector = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "service",
        JOB_NAME,
        "-n",
        TRAINING_NAMESPACE,
        "-o",
        "jsonpath={.spec.selector.volcano\\.sh/job-name}",
    ])
    .await?;

    if selector.trim() != JOB_NAME {
        return Err(format!(
            "Expected Service selector volcano.sh/job-name={}, got: '{}'",
            JOB_NAME,
            selector.trim()
        ));
    }

    let publish = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "service",
        JOB_NAME,
        "-n",
        TRAINING_NAMESPACE,
        "-o",
        "jsonpath={.spec.publishNotReadyAddresses}",
    ])
    .await?;

    if publish.trim() != "true" {
        return Err(format!(
            "Expected publishNotReadyAddresses=true, got: '{}'",
            publish.trim()
        ));
    }

    info!("[Training] Headless Service verified");
    Ok(())
}

/// Verify training env vars were injected into ConfigMaps.
///
/// Training env vars are injected into `container.variables` by the job compiler,
/// which the workload compiler renders into ConfigMaps (referenced via `envFrom`).
/// The ConfigMap name follows the pattern: `{job}-{task}-{container}-env`.
async fn test_training_env_vars(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Verifying training env vars...");

    for task_name in ["master", "worker"] {
        let cm_name = format!("{}-{}-main-env", JOB_NAME, task_name);

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
        // RANK/NODE_RANK are NOT in the ConfigMap — they're injected at the
        // pod spec level via $(VC_TASK_INDEX) from the Volcano env plugin.
        for required in ["MASTER_ADDR", "MASTER_PORT", "WORLD_SIZE", "NNODES"] {
            if !data.contains_key(required) {
                return Err(format!(
                    "Task '{task_name}' ConfigMap missing training env var: {required}"
                ));
            }
        }

        // Checkpoint env var
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

/// Verify PVCs exist with the training-job label
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
        &format!("lattice.dev/training-job={}", JOB_NAME),
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

/// Verify the Velero Schedule was created for periodic snapshots
async fn test_velero_schedule(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Verifying Velero Schedule...");

    let schedule_name = format!("lattice-training-{}", JOB_NAME);

    let schedule = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "schedule.velero.io",
        &schedule_name,
        "-n",
        VELERO_NAMESPACE,
        "-o",
        "jsonpath={.spec.schedule}",
    ])
    .await?;

    if schedule.trim() != "*/1 * * * *" {
        return Err(format!(
            "Expected Velero Schedule '*/1 * * * *', got: '{}'",
            schedule.trim()
        ));
    }

    // Verify label selector targets our training job's PVCs
    let label_selector = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "schedule.velero.io",
        &schedule_name,
        "-n",
        VELERO_NAMESPACE,
        "-o",
        "jsonpath={.spec.template.labelSelector.matchLabels.lattice\\.dev/training-job}",
    ])
    .await?;

    if label_selector.trim() != JOB_NAME {
        return Err(format!(
            "Expected Schedule labelSelector lattice.dev/training-job={}, got: '{}'",
            JOB_NAME,
            label_selector.trim()
        ));
    }

    info!("[Training] Velero Schedule verified: schedule=*/1 * * * *, correct label selector");
    Ok(())
}

// =============================================================================
// Cleanup verification
// =============================================================================

/// Delete the job and verify Velero Schedule is cleaned up via finalizer
async fn test_velero_schedule_cleanup(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Deleting job to verify Velero Schedule cleanup...");

    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "latticejob",
        JOB_NAME,
        "-n",
        TRAINING_NAMESPACE,
    ])
    .await?;

    let schedule_name = format!("lattice-training-{}", JOB_NAME);
    let kc = kubeconfig.to_string();
    wait_for_condition(
        "Velero Schedule to be cleaned up",
        Duration::from_secs(60),
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let schedule_name = schedule_name.clone();
            async move {
                let result = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "schedule.velero.io",
                    &schedule_name,
                    "-n",
                    VELERO_NAMESPACE,
                ])
                .await;

                match result {
                    Err(e) if e.contains("NotFound") || e.contains("not found") => Ok(true),
                    Ok(_) => {
                        info!("[Training] Velero Schedule still exists, waiting...");
                        Ok(false)
                    }
                    Err(e) => {
                        info!("[Training] Unexpected error checking schedule: {}", e);
                        Ok(false)
                    }
                }
            }
        },
    )
    .await?;

    info!("[Training] Velero Schedule cleaned up after job deletion");
    Ok(())
}

// =============================================================================
// Public API
// =============================================================================

/// Run all training compilation integration tests
pub async fn run_training_tests(kubeconfig: &str) -> Result<(), String> {
    info!("\n========================================");
    info!("Training Compilation Tests");
    info!("========================================\n");

    setup_regcreds_infrastructure(kubeconfig).await?;
    setup_minio_backup_storage(kubeconfig).await?;

    let result = run_training_test_sequence(kubeconfig).await;

    cleanup_training_tests(kubeconfig).await;

    result
}

async fn run_training_test_sequence(kubeconfig: &str) -> Result<(), String> {
    // Verify compilation produces the correct resources
    test_training_deployment(kubeconfig).await?;
    test_headless_service(kubeconfig).await?;
    test_training_env_vars(kubeconfig).await?;
    test_checkpoint_pvcs(kubeconfig).await?;
    test_velero_schedule(kubeconfig).await?;

    // Verify finalizer cleans up cross-namespace Velero Schedule
    test_velero_schedule_cleanup(kubeconfig).await?;

    info!("\n========================================");
    info!("Training Compilation Tests: PASSED");
    info!("========================================\n");

    Ok(())
}

async fn cleanup_training_tests(kubeconfig: &str) {
    let schedule_name = format!("lattice-training-{}", JOB_NAME);

    for (kind, selector_flag, selector) in [
        (
            "schedule.velero.io",
            "--field-selector",
            &format!("metadata.name={}", schedule_name) as &str,
        ),
        (
            "backup",
            "-l",
            &format!("velero.io/schedule-name={}", schedule_name),
        ),
    ] {
        let _ = run_kubectl(&[
            "--kubeconfig",
            kubeconfig,
            "delete",
            kind,
            "-n",
            VELERO_NAMESPACE,
            selector_flag,
            selector,
            "--ignore-not-found",
        ])
        .await;
    }

    cleanup_minio_backup_storage(kubeconfig).await;
    delete_namespace(kubeconfig, TRAINING_NAMESPACE).await;
}

#[tokio::test]
#[ignore]
async fn test_training_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_training_tests(&resolved.kubeconfig).await.unwrap();
}
