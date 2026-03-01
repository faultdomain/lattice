//! Training checkpoint/recovery integration tests
//!
//! Exercises the full training lifecycle:
//! - Training env var injection (MASTER_ADDR, WORLD_SIZE, CHECKPOINT_DIR)
//! - Headless Service creation for pod DNS
//! - Velero Schedule creation for PVC snapshots
//! - PVC labeling with `lattice.dev/training-job`
//! - Gang failure and Volcano restart (kill one pod → gang restarts with PVCs intact)
//! - Checkpoint data persistence through Volcano restart
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
// Phase 1: Verify training compilation
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
// Phase 2: Trigger failure and verify recovery
// =============================================================================

/// Verify containers wrote checkpoint data (FRESH start logs)
async fn test_checkpoint_data_written(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Waiting for containers to write checkpoint data...");

    let kc = kubeconfig.to_string();
    wait_for_condition(
        "training pods to emit CHECKPOINT_READY",
        Duration::from_secs(120),
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "logs",
                    "-n",
                    TRAINING_NAMESPACE,
                    "-l",
                    &format!("volcano.sh/job-name={}", JOB_NAME),
                    "--tail=20",
                ])
                .await
                .unwrap_or_default();

                Ok(output.contains("CHECKPOINT_READY"))
            }
        },
    )
    .await?;

    info!("[Training] Containers wrote checkpoint data");
    Ok(())
}

/// Wait for a Velero backup to complete for this training job (hard assertion)
async fn wait_for_velero_backup(kubeconfig: &str) -> Result<String, String> {
    info!("[Training] Waiting for Velero backup to complete (up to 3 minutes)...");

    let schedule_name = format!("lattice-training-{}", JOB_NAME);
    let kc = kubeconfig.to_string();
    wait_for_condition(
        "Velero backup to complete",
        Duration::from_secs(180),
        Duration::from_secs(10),
        || {
            let kc = kc.clone();
            let schedule_name = schedule_name.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "backup",
                    "-n",
                    VELERO_NAMESPACE,
                    "-l",
                    &format!("velero.io/schedule-name={}", schedule_name),
                    "-o",
                    "jsonpath={range .items[*]}{.metadata.name}={.status.phase} {end}",
                ])
                .await
                .unwrap_or_default();

                // Find a completed backup
                for entry in output.split_whitespace() {
                    if let Some((name, phase)) = entry.split_once('=') {
                        if phase == "Completed" {
                            return Ok(Some(name.to_string()));
                        }
                    }
                }

                info!("[Training] No completed backup yet: {}", output.trim());
                Ok(None)
            }
        },
    )
    .await
}

/// Kill a pod's main process to trigger a container failure.
///
/// Uses `kubectl exec -- kill 1` to send SIGTERM to PID 1. With
/// `restartPolicy: Never` (set by the compiler for checkpoint training),
/// the pod transitions to Failed. Volcano detects PodFailed and enters
/// Restarting — which the Lattice controller treats as Failed (maxRetry=0),
/// triggering checkpoint recovery.
///
/// We must NOT use `kubectl delete pod` here: Volcano treats pod deletion
/// as a missing pod and just recreates it, keeping the VCJob in Running.
async fn test_kill_gang_member(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Killing a gang member process to trigger failure...");

    // Get a worker pod name
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pods",
        "-n",
        TRAINING_NAMESPACE,
        "-l",
        &format!(
            "volcano.sh/job-name={},volcano.sh/task-spec=worker",
            JOB_NAME
        ),
        "-o",
        "jsonpath={.items[0].metadata.name}",
    ])
    .await?;

    let pod_name = output.trim();
    if pod_name.is_empty() {
        return Err("No worker pod found to kill".to_string());
    }

    info!("[Training] Killing PID 1 in worker pod: {}", pod_name);
    // kill 1 may "fail" because the exec connection drops when PID 1 dies —
    // that's expected, so we ignore the exit code.
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "exec",
        pod_name,
        "-n",
        TRAINING_NAMESPACE,
        "--",
        "kill",
        "1",
    ])
    .await;

    info!("[Training] Worker process killed");
    Ok(())
}

/// Verify Volcano restarts the gang and the job returns to Running.
///
/// PVCs persist across Volcano restarts so checkpoint data survives.
/// Volcano handles retries via its maxRetry mechanism — the Lattice
/// controller just observes the VCJob phase.
async fn test_volcano_restarts_gang(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Waiting for Volcano to restart the gang...");

    wait_for_resource_phase(
        kubeconfig,
        "latticejob",
        TRAINING_NAMESPACE,
        JOB_NAME,
        "Running",
        Duration::from_secs(120),
    )
    .await?;

    info!("[Training] Volcano restarted the gang, job is Running");
    Ok(())
}

// =============================================================================
// Phase 3: Verify checkpoint data persistence
// =============================================================================

/// Verify pods read from the restored checkpoint (RESTORED must appear in logs)
async fn test_checkpoint_restored(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Waiting for restored pods to emit RESTORED...");

    let kc = kubeconfig.to_string();
    wait_for_condition(
        "restarted pods to emit RESTORED",
        Duration::from_secs(120),
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "logs",
                    "-n",
                    TRAINING_NAMESPACE,
                    "-l",
                    &format!("volcano.sh/job-name={}", JOB_NAME),
                    "--tail=20",
                ])
                .await
                .unwrap_or_default();

                if output.contains("RESTORED") {
                    Ok(true)
                } else if output.contains("FRESH") {
                    Err(
                        "Pods started FRESH — checkpoint data was not restored from backup"
                            .to_string(),
                    )
                } else {
                    Ok(false)
                }
            }
        },
    )
    .await?;

    info!("[Training] Checkpoint data restored from Velero backup");
    Ok(())
}

// =============================================================================
// Cleanup: Verify Velero Schedule is cleaned up on terminal state
// =============================================================================

/// Delete the job and verify Velero Schedule is cleaned up
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

                // Schedule should be gone (NotFound)
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

/// Run all training checkpoint/recovery integration tests
pub async fn run_training_tests(kubeconfig: &str) -> Result<(), String> {
    info!("\n========================================");
    info!("Training Checkpoint/Recovery Tests");
    info!("========================================\n");

    setup_regcreds_infrastructure(kubeconfig).await?;
    setup_minio_backup_storage(kubeconfig).await?;

    let result = run_training_test_sequence(kubeconfig).await;

    // Cleanup regardless of test result
    cleanup_training_tests(kubeconfig).await;

    result
}

async fn run_training_test_sequence(kubeconfig: &str) -> Result<(), String> {
    // Phase 1: Deploy and verify compilation
    test_training_deployment(kubeconfig).await?;
    test_headless_service(kubeconfig).await?;
    test_training_env_vars(kubeconfig).await?;
    test_checkpoint_pvcs(kubeconfig).await?;
    test_velero_schedule(kubeconfig).await?;

    // Phase 2: Write data, wait for backup, trigger failure, verify recovery
    test_checkpoint_data_written(kubeconfig).await?;

    let backup_name = wait_for_velero_backup(kubeconfig).await?;
    info!("[Training] Backup completed: {}", backup_name);

    test_kill_gang_member(kubeconfig).await?;
    test_volcano_restarts_gang(kubeconfig).await?;

    // Phase 3: Verify checkpoint data was actually restored
    test_checkpoint_restored(kubeconfig).await?;

    // Verify cleanup
    test_velero_schedule_cleanup(kubeconfig).await?;

    info!("\n========================================");
    info!("Training Checkpoint/Recovery Tests: PASSED");
    info!("========================================\n");

    Ok(())
}

async fn cleanup_training_tests(kubeconfig: &str) {
    let schedule_name = format!("lattice-training-{}", JOB_NAME);

    // Delete leftover Velero resources (schedule, backups, restores)
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
        (
            "restore",
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
