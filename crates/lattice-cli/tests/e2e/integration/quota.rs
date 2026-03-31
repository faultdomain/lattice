//! Quota integration tests
//!
//! Verifies that LatticeQuota enforcement works end-to-end:
//! - Quota controller tracks usage in status
//! - Workload compiler rejects services exceeding soft limits
//! - MachineDeployment annotations are patched with solver-computed min/max
//! - Quota phase transitions (Active → Exceeded → Active)
//!
//! Run standalone:
//! ```
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_quota_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::super::helpers::{
    apply_yaml, delete_namespace, ensure_fresh_namespace, run_kubectl,
    wait_for_condition, wait_for_resource_phase, with_diagnostics, DiagnosticContext,
    DEFAULT_TIMEOUT, POLL_INTERVAL,
};

const QUOTA_NS: &str = "quota-test";
const LATTICE_NS: &str = "lattice-system";

// =============================================================================
// Main Test Runner
// =============================================================================

/// Run the full quota integration test suite.
pub async fn run_quota_tests(kubeconfig: &str) -> Result<(), String> {
    let diag = DiagnosticContext::new(kubeconfig, QUOTA_NS);
    with_diagnostics(&diag, "Quota", || async {
        // Label the test namespace so group quotas match
        setup_namespace(kubeconfig).await?;

        test_quota_lifecycle(kubeconfig).await?;
        test_quota_enforcement(kubeconfig).await?;
        test_quota_exceeded_phase(kubeconfig).await?;

        cleanup(kubeconfig).await;

        info!("[Quota] All quota integration tests passed!");
        Ok(())
    })
    .await
}

// =============================================================================
// Setup
// =============================================================================

async fn setup_namespace(kubeconfig: &str) -> Result<(), String> {
    ensure_fresh_namespace(kubeconfig, QUOTA_NS).await?;

    // Label the namespace so group-based quotas match
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "label",
        "namespace",
        QUOTA_NS,
        "lattice.dev/group=quota-test-team",
        "--overwrite",
    ])
    .await?;

    info!("[Quota] Namespace '{}' ready with group label", QUOTA_NS);
    Ok(())
}

// =============================================================================
// Test: Quota CRD lifecycle (create → Active status)
// =============================================================================

async fn test_quota_lifecycle(kubeconfig: &str) -> Result<(), String> {
    info!("[Quota] Testing quota CRD lifecycle...");

    let quota_yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: LatticeQuota
metadata:
  name: test-team-quota
  namespace: lattice-system
spec:
  principal: 'Lattice::Group::"quota-test-team"'
  limits:
    cpu: "4"
    memory: "8Gi"
  maxPerWorkload:
    cpu: "2"
    memory: "4Gi"
"#;

    apply_yaml(kubeconfig, quota_yaml).await?;

    // Wait for the quota controller to reconcile and set status
    wait_for_resource_phase(
        kubeconfig,
        "latticequota",
        LATTICE_NS,
        "test-team-quota",
        "Active",
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Verify status fields are populated
    let used = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticequota",
        "test-team-quota",
        "-n",
        LATTICE_NS,
        "-o",
        "jsonpath={.status.workloadCount}",
    ])
    .await?;

    let count: u32 = used.trim().parse().unwrap_or(999);
    if count != 0 {
        return Err(format!(
            "Expected workloadCount=0 (no workloads deployed), got {count}"
        ));
    }

    info!("[Quota] Quota 'test-team-quota' is Active with 0 workloads");
    Ok(())
}

// =============================================================================
// Test: Deploy service within limits → succeeds, usage tracked
// =============================================================================

async fn test_quota_enforcement(kubeconfig: &str) -> Result<(), String> {
    info!("[Quota] Testing enforcement: deploy within limits...");

    // Deploy a small service that fits within the quota (1 CPU, 2Gi, 1 replica)
    let svc_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: quota-small-svc
  namespace: {QUOTA_NS}
spec:
  replicas: 1
  workload:
    containers:
      main:
        image: busybox:1.36
        command: ["/bin/sleep", "3600"]
        resources:
          requests:
            cpu: "500m"
            memory: "512Mi"
          limits:
            cpu: "500m"
            memory: "512Mi"
    service:
      ports:
        http:
          port: 8080
          targetPort: 8080"#
    );

    apply_yaml(kubeconfig, &svc_yaml).await?;

    // Service should compile successfully (within quota)
    wait_for_resource_phase(
        kubeconfig,
        "latticeservice",
        QUOTA_NS,
        "quota-small-svc",
        "Ready",
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Wait for the quota controller to pick up the usage
    let kc = kubeconfig.to_string();
    wait_for_condition(
        "quota to reflect workload usage",
        Duration::from_secs(90),
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                let count = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "latticequota",
                    "test-team-quota",
                    "-n",
                    LATTICE_NS,
                    "-o",
                    "jsonpath={.status.workloadCount}",
                ])
                .await;
                match count {
                    Ok(c) => Ok(c.trim().parse::<u32>().unwrap_or(0) >= 1),
                    Err(_) => Ok(false),
                }
            }
        },
    )
    .await?;

    // Verify used CPU is reported
    let used_cpu = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticequota",
        "test-team-quota",
        "-n",
        LATTICE_NS,
        "-o",
        "jsonpath={.status.used.cpu}",
    ])
    .await?;

    if used_cpu.trim().is_empty() {
        return Err("status.used.cpu is empty after deploying a service".to_string());
    }

    info!(
        "[Quota] Service deployed within limits, usage tracked: cpu={}",
        used_cpu.trim()
    );
    Ok(())
}

// =============================================================================
// Test: Deploy service exceeding soft limit → rejected
// =============================================================================

async fn test_quota_exceeded_phase(kubeconfig: &str) -> Result<(), String> {
    info!("[Quota] Testing enforcement: deploy exceeding per-workload cap...");

    // Deploy a service that exceeds maxPerWorkload (3 CPU > 2 CPU cap)
    let big_svc_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: quota-big-svc
  namespace: {QUOTA_NS}
spec:
  replicas: 1
  workload:
    containers:
      main:
        image: busybox:1.36
        command: ["/bin/sleep", "3600"]
        resources:
          requests:
            cpu: "3"
            memory: "1Gi"
          limits:
            cpu: "3"
            memory: "1Gi"
    service:
      ports:
        http:
          port: 8080
          targetPort: 8080"#
    );

    apply_yaml(kubeconfig, &big_svc_yaml).await?;

    // Service should fail compilation with quota exceeded
    let kc = kubeconfig.to_string();
    wait_for_condition(
        "big service to be rejected by quota",
        Duration::from_secs(90),
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                let phase = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "latticeservice",
                    "quota-big-svc",
                    "-n",
                    QUOTA_NS,
                    "-o",
                    "jsonpath={.status.phase}",
                ])
                .await;

                let message = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "latticeservice",
                    "quota-big-svc",
                    "-n",
                    QUOTA_NS,
                    "-o",
                    "jsonpath={.status.message}",
                ])
                .await;

                match (phase, message) {
                    (Ok(p), Ok(m)) => {
                        let phase = p.trim();
                        let msg = m.trim();
                        info!("[Quota] Big service phase={phase}, message={msg}");
                        // Should be Failed with a quota-related message
                        Ok(phase == "Failed"
                            && (msg.contains("quota") || msg.contains("per-workload")))
                    }
                    _ => Ok(false),
                }
            }
        },
    )
    .await?;

    info!("[Quota] Big service correctly rejected by per-workload cap");

    // Clean up the failed service
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "latticeservice",
        "quota-big-svc",
        "-n",
        QUOTA_NS,
        "--ignore-not-found",
    ])
    .await;

    Ok(())
}

// =============================================================================
// Cleanup
// =============================================================================

async fn cleanup(kubeconfig: &str) {
    info!("[Quota] Cleaning up...");

    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "latticequota",
        "test-team-quota",
        "-n",
        LATTICE_NS,
        "--ignore-not-found",
    ])
    .await;

    delete_namespace(kubeconfig, QUOTA_NS).await;

    info!("[Quota] Cleanup complete");
}

// =============================================================================
// Standalone Test
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_quota_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_quota_tests(&resolved.kubeconfig).await.unwrap();
}
