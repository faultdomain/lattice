//! Training checkpoint/recovery integration tests
//!
//! Exercises the full training lifecycle:
//! - Training env var injection (MASTER_ADDR, WORLD_SIZE, CHECKPOINT_DIR)
//! - Headless Service creation for pod DNS
//! - Velero Schedule creation for PVC snapshots
//! - PVC labeling with `lattice.dev/training-job`
//! - Gang failure (kill one pod → all die)
//! - Recovery state machine (Recovering → DeletingResources → WaitingForRestore → Restarting)
//! - Checkpoint data persistence through recovery
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

/// Load the training checkpoint job fixture
fn load_training_fixture() -> Result<lattice_common::crd::LatticeJob, String> {
    load_fixture_config("training-checkpoint-job.yaml")
}

// =============================================================================
// Phase 1: Verify training compilation
// =============================================================================

/// Deploy the training job and wait for Running phase
async fn test_training_deployment(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Deploying training checkpoint job...");

    ensure_fresh_namespace(kubeconfig, TRAINING_NAMESPACE).await?;

    let job = load_training_fixture()?;
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

        // PyTorch distributed env vars
        for required in ["MASTER_ADDR", "MASTER_PORT", "WORLD_SIZE", "RANK"] {
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

/// Verify the Velero Backup contains PodVolumeBackup data (fs-backup ran)
async fn test_velero_backup_data_exists(kubeconfig: &str, backup_name: &str) -> Result<(), String> {
    info!(
        "[Training] Verifying PodVolumeBackup data for backup '{}'...",
        backup_name
    );

    let kc = kubeconfig.to_string();
    let bk = backup_name.to_string();
    wait_for_condition(
        "PodVolumeBackup to exist for backup",
        Duration::from_secs(60),
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let bk = bk.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "podvolumebackup",
                    "-n",
                    VELERO_NAMESPACE,
                    "-l",
                    &format!("velero.io/backup-name={}", bk),
                    "-o",
                    "jsonpath={.items[*].status.phase}",
                ])
                .await
                .unwrap_or_default();

                let phases: Vec<&str> = output.split_whitespace().collect();
                if phases.is_empty() {
                    info!("[Training] No PodVolumeBackup found yet");
                    return Ok(false);
                }

                let all_completed = phases.iter().all(|p| *p == "Completed");
                if all_completed {
                    info!(
                        "[Training] {} PodVolumeBackup(s) completed",
                        phases.len()
                    );
                } else {
                    info!(
                        "[Training] PodVolumeBackup phases: {:?}",
                        phases
                    );
                }
                Ok(all_completed)
            }
        },
    )
    .await?;

    info!(
        "[Training] PodVolumeBackup data verified for backup '{}'",
        backup_name
    );
    Ok(())
}

/// Kill a pod from the training gang to trigger VCJob failure
async fn test_kill_gang_member(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Killing a gang member pod to trigger failure...");

    // Get a worker pod name
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pods",
        "-n",
        TRAINING_NAMESPACE,
        "-l",
        &format!("volcano.sh/job-name={},volcano.sh/task-spec=worker", JOB_NAME),
        "-o",
        "jsonpath={.items[0].metadata.name}",
    ])
    .await?;

    let pod_name = output.trim();
    if pod_name.is_empty() {
        return Err("No worker pod found to kill".to_string());
    }

    info!("[Training] Deleting worker pod: {}", pod_name);
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "pod",
        pod_name,
        "-n",
        TRAINING_NAMESPACE,
        "--grace-period=0",
        "--force",
    ])
    .await?;

    info!("[Training] Worker pod deleted");
    Ok(())
}

/// Verify the job transitions to Recovering phase after gang failure
async fn test_recovery_triggered(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Waiting for Recovering phase...");

    wait_for_resource_phase(
        kubeconfig,
        "latticejob",
        TRAINING_NAMESPACE,
        JOB_NAME,
        "Recovering",
        Duration::from_secs(120),
    )
    .await?;

    info!("[Training] Job entered Recovering phase");

    // Verify retry_count was incremented
    let retry_count = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticejob",
        JOB_NAME,
        "-n",
        TRAINING_NAMESPACE,
        "-o",
        "jsonpath={.status.retryCount}",
    ])
    .await?;

    let count: u32 = retry_count
        .trim()
        .parse()
        .map_err(|e| format!("Failed to parse retryCount: {e}"))?;

    if count == 0 {
        return Err("Expected retryCount > 0 during recovery".to_string());
    }

    info!("[Training] Recovery triggered: retryCount={}", count);
    Ok(())
}

/// Verify all pods from the gang were terminated
async fn test_all_pods_terminated(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Verifying all gang pods terminated...");

    let kc = kubeconfig.to_string();
    wait_for_condition(
        "all training pods to terminate",
        Duration::from_secs(60),
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "pods",
                    "-n",
                    TRAINING_NAMESPACE,
                    "-l",
                    &format!("volcano.sh/job-name={}", JOB_NAME),
                    "--field-selector=status.phase=Running",
                    "-o",
                    "jsonpath={.items[*].metadata.name}",
                ])
                .await
                .unwrap_or_default();

                let running_pods: Vec<&str> = output.split_whitespace().collect();
                if running_pods.is_empty() {
                    Ok(true)
                } else {
                    info!(
                        "[Training] {} pods still running: {:?}",
                        running_pods.len(),
                        running_pods
                    );
                    Ok(false)
                }
            }
        },
    )
    .await?;

    info!("[Training] All gang pods terminated");
    Ok(())
}

/// Verify the job recovers and returns to Running phase
async fn test_recovery_completes(kubeconfig: &str) -> Result<(), String> {
    info!("[Training] Waiting for job to recover and return to Running...");

    wait_for_resource_phase(
        kubeconfig,
        "latticejob",
        TRAINING_NAMESPACE,
        JOB_NAME,
        "Running",
        Duration::from_secs(300),
    )
    .await?;

    // Verify recovery_phase is cleared
    let recovery_phase = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticejob",
        JOB_NAME,
        "-n",
        TRAINING_NAMESPACE,
        "-o",
        "jsonpath={.status.recoveryPhase}",
    ])
    .await?;

    if !recovery_phase.trim().is_empty() {
        return Err(format!(
            "Expected recovery_phase cleared after recovery, got: '{}'",
            recovery_phase.trim()
        ));
    }

    let message = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticejob",
        JOB_NAME,
        "-n",
        TRAINING_NAMESPACE,
        "-o",
        "jsonpath={.status.message}",
    ])
    .await?;

    info!("[Training] Recovery complete: message='{}'", message.trim());
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
                    Err("Pods started FRESH — checkpoint data was not restored from backup".to_string())
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

    test_velero_backup_data_exists(kubeconfig, &backup_name).await?;

    test_kill_gang_member(kubeconfig).await?;
    test_all_pods_terminated(kubeconfig).await?;
    test_recovery_triggered(kubeconfig).await?;
    test_recovery_completes(kubeconfig).await?;

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
        ("schedule.velero.io", "--field-selector", &format!("metadata.name={}", schedule_name) as &str),
        ("backup", "-l", &format!("velero.io/schedule-name={}", schedule_name)),
        ("restore", "-l", &format!("velero.io/schedule-name={}", schedule_name)),
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
