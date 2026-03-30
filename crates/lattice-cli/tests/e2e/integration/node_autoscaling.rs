//! CAPI node autoscaling integration tests
//!
//! Tests cluster-autoscaler scale-from-zero: adds an autoscaling worker pool
//! with min=0, deploys an unschedulable pod, and verifies the autoscaler
//! provisions a new node via CAPI MachineDeployment.
//!
//! # Prerequisites
//!
//! - Workload cluster running on real CAPI infrastructure (Proxmox/AWS)
//! - Cluster-autoscaler deployed (automatic when any pool has min/max)
//!
//! # Running
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_node_autoscaling_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::super::helpers::{
    delete_namespace, ensure_fresh_namespace, get_workload_cluster_name, run_kubectl,
    wait_for_condition, DEFAULT_TIMEOUT,
};

// =============================================================================
// Constants
// =============================================================================

const TEST_NAMESPACE: &str = "node-autoscaling-test";
const AUTOSCALE_POOL: &str = "autoscale";

/// Timeout for node provisioning (CAPI + VM boot + kubelet join)
const NODE_PROVISION_TIMEOUT: Duration = Duration::from_secs(900); // 15 min

const POLL_INTERVAL: Duration = Duration::from_secs(15);

// =============================================================================
// Main Test Runner
// =============================================================================

/// Run the full CAPI node autoscaling test suite.
pub async fn run_node_autoscaling_tests(kubeconfig: &str) -> Result<(), String> {
    info!("========================================");
    info!("CAPI NODE AUTOSCALING TESTS");
    info!("========================================");

    ensure_fresh_namespace(kubeconfig, TEST_NAMESPACE).await?;

    test_add_autoscaling_pool(kubeconfig).await?;
    test_verify_md_annotations(kubeconfig).await?;
    test_scale_from_zero(kubeconfig).await?;
    // Scale-down is not tested — it exercises CAPI/autoscaler behavior
    // (5-10 min drain timers) rather than Lattice code.

    cleanup(kubeconfig).await;
    Ok(())
}

// =============================================================================
// Test: Add autoscaling pool to cluster
// =============================================================================

async fn test_add_autoscaling_pool(kubeconfig: &str) -> Result<(), String> {
    info!("[NodeAutoscaling] Adding autoscaling pool with min=0...");

    let cluster_name = get_workload_cluster_name();

    // Add a small autoscaling pool. Uses resource-based instance type so
    // capacity is derived automatically (no NodeCapacityHint needed).
    let patch = serde_json::json!({
        "spec": {
            "nodes": {
                "workerPools": {
                    AUTOSCALE_POOL: {
                        "replicas": 0,
                        "min": 0,
                        "max": 2,
                        "instanceType": {
                            "cores": 4,
                            "memoryGib": 8,
                            "diskGib": 50
                        },
                        "labels": {
                            "lattice.dev/pool": AUTOSCALE_POOL
                        }
                    }
                }
            }
        }
    });

    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "patch",
        "latticecluster",
        &cluster_name,
        "--type=merge",
        "-p",
        &patch.to_string(),
    ])
    .await
    .map_err(|e| format!("Failed to add autoscaling pool: {e}"))?;

    info!(
        "[NodeAutoscaling] Pool '{}' added (min=0, max=2)",
        AUTOSCALE_POOL
    );

    // Wait for MachineDeployment to be created by the operator
    let kc = kubeconfig.to_string();
    let md_name = format!("{}-pool-{}", cluster_name, AUTOSCALE_POOL);
    wait_for_condition(
        &format!("MachineDeployment '{}' to exist", md_name),
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            let md_name = md_name.clone();
            async move {
                Ok(run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "machinedeployment",
                    &md_name,
                    "-n",
                    &format!("capi-{}", get_workload_cluster_name()),
                    "-o",
                    "name",
                ])
                .await
                .is_ok())
            }
        },
    )
    .await?;

    info!("[NodeAutoscaling] MachineDeployment '{}' created", md_name);
    Ok(())
}

// =============================================================================
// Test: Verify capacity annotations on MachineDeployment
// =============================================================================

async fn test_verify_md_annotations(kubeconfig: &str) -> Result<(), String> {
    info!("[NodeAutoscaling] Verifying MachineDeployment annotations...");

    let cluster_name = get_workload_cluster_name();
    let md_name = format!("{}-pool-{}", cluster_name, AUTOSCALE_POOL);
    let capi_ns = format!("capi-{}", cluster_name);

    let annotations = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "machinedeployment",
        &md_name,
        "-n",
        &capi_ns,
        "-o",
        "jsonpath={.metadata.annotations}",
    ])
    .await?;

    // Verify autoscaler min/max
    if !annotations.contains("autoscaler-node-group-min-size") {
        return Err(format!("MD missing min-size annotation: {annotations}"));
    }
    if !annotations.contains("autoscaler-node-group-max-size") {
        return Err(format!("MD missing max-size annotation: {annotations}"));
    }

    // Verify capacity annotations (CAPI v1.12+ format, derived from resource-based instance type)
    if !annotations.contains("capacity.cluster-autoscaler.kubernetes.io/cpu") {
        return Err(format!("MD missing cpu capacity annotation: {annotations}"));
    }
    if !annotations.contains("capacity.cluster-autoscaler.kubernetes.io/memory") {
        return Err(format!(
            "MD missing memory capacity annotation: {annotations}"
        ));
    }

    // Verify replicas is 0
    let replicas = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "machinedeployment",
        &md_name,
        "-n",
        &capi_ns,
        "-o",
        "jsonpath={.spec.replicas}",
    ])
    .await?;

    if replicas.trim() != "0" {
        return Err(format!("MD replicas should be 0, got: {}", replicas.trim()));
    }

    info!("[NodeAutoscaling] MachineDeployment has correct capacity annotations and 0 replicas");
    Ok(())
}

// =============================================================================
// Test: Scale from zero
// =============================================================================

async fn test_scale_from_zero(kubeconfig: &str) -> Result<(), String> {
    info!("[NodeAutoscaling] Testing scale-from-zero...");

    // Deploy a pod with a nodeSelector that targets the autoscaling pool.
    // The pod requests enough resources that it can't fit on existing nodes.
    // This forces the cluster-autoscaler to scale the pool from 0 to 1.
    let pod_yaml = format!(
        r#"apiVersion: v1
kind: Pod
metadata:
  name: trigger-scaleup
  namespace: {TEST_NAMESPACE}
spec:
  nodeSelector:
    lattice.dev/pool: {AUTOSCALE_POOL}
  containers:
    - name: busybox
      image: busybox:1.36
      command: ["sleep", "3600"]
      resources:
        requests:
          cpu: "1"
          memory: "1Gi""#
    );

    super::super::helpers::cedar::apply_yaml(kubeconfig, &pod_yaml).await?;
    info!("[NodeAutoscaling] Trigger pod deployed, waiting for node scale-up...");

    // The pod should be Pending initially (no nodes in the autoscale pool)
    let kc = kubeconfig.to_string();
    wait_for_condition(
        "trigger pod to become Pending",
        Duration::from_secs(30),
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                let phase = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "pod",
                    "trigger-scaleup",
                    "-n",
                    TEST_NAMESPACE,
                    "-o",
                    "jsonpath={.status.phase}",
                ])
                .await;
                Ok(phase.map(|p| p.trim() == "Pending").unwrap_or(false))
            }
        },
    )
    .await
    .map_err(|e| format!("Trigger pod never reached Pending: {e}"))?;

    info!("[NodeAutoscaling] Trigger pod is Pending (as expected — no nodes in pool)");

    // Now wait for the cluster-autoscaler to scale up the pool and the pod to run.
    // This is the main test: CAPI provisions a VM, kubelet joins, pod gets scheduled.
    let kc = kubeconfig.to_string();
    wait_for_condition(
        "trigger pod to become Running (node scaled up)",
        NODE_PROVISION_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                let phase = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "pod",
                    "trigger-scaleup",
                    "-n",
                    TEST_NAMESPACE,
                    "-o",
                    "jsonpath={.status.phase}",
                ])
                .await;
                let running = phase.map(|p| p.trim() == "Running").unwrap_or(false);
                if !running {
                    // Log current MD replicas for visibility
                    let cluster = get_workload_cluster_name();
                    let md = format!("{}-pool-{}", cluster, AUTOSCALE_POOL);
                    let capi_ns = format!("capi-{}", cluster);
                    if let Ok(r) = run_kubectl(&[
                        "--kubeconfig",
                        &kc,
                        "get",
                        "machinedeployment",
                        &md,
                        "-n",
                        &capi_ns,
                        "-o",
                        "jsonpath={.spec.replicas}/{.status.readyReplicas}",
                    ])
                    .await
                    {
                        info!("[NodeAutoscaling] MD replicas: {}", r.trim());
                    }
                }
                Ok(running)
            }
        },
    )
    .await?;

    info!("[NodeAutoscaling] Scale-from-zero succeeded! Pod is Running on new node.");

    // Verify the node has the pool label
    let node_name = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pod",
        "trigger-scaleup",
        "-n",
        TEST_NAMESPACE,
        "-o",
        "jsonpath={.spec.nodeName}",
    ])
    .await?;

    let pool_label = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "node",
        node_name.trim(),
        "-o",
        "jsonpath={.metadata.labels['lattice\\.dev/pool']}",
    ])
    .await?;

    if pool_label.trim() != AUTOSCALE_POOL {
        return Err(format!(
            "Node '{}' has wrong pool label: expected '{}', got '{}'",
            node_name.trim(),
            AUTOSCALE_POOL,
            pool_label.trim()
        ));
    }

    info!(
        "[NodeAutoscaling] Node '{}' has correct pool label",
        node_name.trim()
    );
    Ok(())
}


// =============================================================================
// Cleanup
// =============================================================================

async fn cleanup(kubeconfig: &str) {
    info!("[NodeAutoscaling] Cleaning up...");

    delete_namespace(kubeconfig, TEST_NAMESPACE).await;

    // Remove the autoscaling pool from the cluster spec
    let cluster_name = get_workload_cluster_name();
    // Use JSON patch to remove the pool key
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "patch",
        "latticecluster",
        &cluster_name,
        "--type=json",
        "-p",
        &format!(r#"[{{"op":"remove","path":"/spec/nodes/workerPools/{AUTOSCALE_POOL}"}}]"#),
    ])
    .await;

    info!("[NodeAutoscaling] Cleanup complete");
}

// =============================================================================
// Standalone Test
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_node_autoscaling_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_node_autoscaling_tests(&resolved.kubeconfig)
        .await
        .unwrap();
}
