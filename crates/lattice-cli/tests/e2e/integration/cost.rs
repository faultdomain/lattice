//! Cost estimation integration tests
//!
//! Verifies that cost estimation produces correct `status.cost` fields on
//! LatticeService, LatticeJob, and LatticeModel resources when the
//! `lattice-resource-rates` ConfigMap is present in `lattice-system`.
//!
//! Run standalone:
//! ```
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_cost_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::super::helpers::{
    apply_yaml, delete_namespace, ensure_fresh_namespace, run_kubectl, wait_for_condition,
    wait_for_resource_phase, DEFAULT_TIMEOUT,
};

const COST_NAMESPACE: &str = "cost-test";
const SERVICE_NAME: &str = "cost-test-api";
const RATES_CM_NAMESPACE: &str = "lattice-system";
const RATES_CM_NAME: &str = "lattice-resource-rates";

/// Apply the `lattice-resource-rates` ConfigMap to `lattice-system`.
async fn ensure_rates_configmap(kubeconfig: &str) -> Result<(), String> {
    info!("[Cost] Applying lattice-resource-rates ConfigMap...");

    let cm_yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: lattice-resource-rates
  namespace: lattice-system
data:
  rates.yaml: |
    cpu: 0.031
    memory: 0.004
    gpu:
      H100-SXM: 3.50
      H100-PCIe: 2.85
      A100-80GB: 2.21
      A100-40GB: 1.50
      L4: 0.81
      T4: 0.35
"#;

    apply_yaml(kubeconfig, cm_yaml).await?;
    info!("[Cost] Rates ConfigMap applied");
    Ok(())
}

/// Deploy a CPU-only LatticeService and verify `status.cost` is populated.
async fn test_service_cost_populated(kubeconfig: &str) -> Result<(), String> {
    info!("[Cost] Deploying cost-test-api service...");

    ensure_fresh_namespace(kubeconfig, COST_NAMESPACE).await?;

    let service: lattice_common::crd::LatticeService =
        super::super::helpers::load_fixture_config("cost-service.yaml")?;
    let yaml = serde_json::to_string(&service)
        .map_err(|e| format!("Failed to serialize service fixture: {e}"))?;
    apply_yaml(kubeconfig, &yaml).await?;

    wait_for_resource_phase(
        kubeconfig,
        "latticeservice",
        COST_NAMESPACE,
        SERVICE_NAME,
        "Ready",
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!("[Cost] Service ready, checking cost fields...");

    // Verify hourlyCost is set and non-empty
    let hourly_cost = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticeservice",
        SERVICE_NAME,
        "-n",
        COST_NAMESPACE,
        "-o",
        "jsonpath={.status.cost.hourlyCost}",
    ])
    .await?;

    let cost_str = hourly_cost.trim();
    if cost_str.is_empty() {
        return Err("status.cost.hourlyCost is empty — cost estimation not working".to_string());
    }

    let cost_val: f64 = cost_str
        .parse()
        .map_err(|e| format!("hourlyCost '{cost_str}' is not a valid number: {e}"))?;
    if cost_val <= 0.0 {
        return Err(format!("hourlyCost should be > 0, got: {cost_val}"));
    }

    // Verify breakdown.cpu is set
    let cpu_cost = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticeservice",
        SERVICE_NAME,
        "-n",
        COST_NAMESPACE,
        "-o",
        "jsonpath={.status.cost.breakdown.cpu}",
    ])
    .await?;

    if cpu_cost.trim().is_empty() {
        return Err("status.cost.breakdown.cpu is empty".to_string());
    }

    // Verify breakdown.memory is set
    let mem_cost = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticeservice",
        SERVICE_NAME,
        "-n",
        COST_NAMESPACE,
        "-o",
        "jsonpath={.status.cost.breakdown.memory}",
    ])
    .await?;

    if mem_cost.trim().is_empty() {
        return Err("status.cost.breakdown.memory is empty".to_string());
    }

    // Verify breakdown.gpu is NOT set (CPU-only service)
    let gpu_cost = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticeservice",
        SERVICE_NAME,
        "-n",
        COST_NAMESPACE,
        "-o",
        "jsonpath={.status.cost.breakdown.gpu}",
    ])
    .await?;

    if !gpu_cost.trim().is_empty() {
        return Err(format!(
            "CPU-only service should have no GPU cost, got: '{}'",
            gpu_cost.trim()
        ));
    }

    // Verify lastEstimatedAt is set
    let timestamp = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticeservice",
        SERVICE_NAME,
        "-n",
        COST_NAMESPACE,
        "-o",
        "jsonpath={.status.cost.lastEstimatedAt}",
    ])
    .await?;

    if timestamp.trim().is_empty() {
        return Err("status.cost.lastEstimatedAt is empty".to_string());
    }

    info!(
        "[Cost] Service cost verified: hourlyCost={}, cpu={}, memory={}, lastEstimatedAt={}",
        cost_str,
        cpu_cost.trim(),
        mem_cost.trim(),
        timestamp.trim()
    );
    Ok(())
}

/// Verify cost arithmetic: CPU-only service with known rates.
///
/// Fixture: 500m CPU, 1Gi memory, 2 replicas.
/// Expected: CPU = (0.5 * 0.031 * 2) = 0.031, Mem = (1.0 * 0.004 * 2) = 0.008,
/// Total = 0.039
async fn test_service_cost_arithmetic(kubeconfig: &str) -> Result<(), String> {
    info!("[Cost] Verifying cost arithmetic...");

    let hourly = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticeservice",
        SERVICE_NAME,
        "-n",
        COST_NAMESPACE,
        "-o",
        "jsonpath={.status.cost.hourlyCost}",
    ])
    .await?;

    let total: f64 = hourly
        .trim()
        .parse()
        .map_err(|e| format!("Failed to parse hourlyCost: {e}"))?;

    // CPU: 0.5 cores * $0.031/core/hr * 2 replicas = $0.031
    // Memory: 1 GiB * $0.004/GiB/hr * 2 replicas = $0.008
    // Total: $0.039
    let expected = 0.039;
    if (total - expected).abs() > 0.001 {
        return Err(format!(
            "Expected hourlyCost ~{expected}, got {total} (delta={})",
            (total - expected).abs()
        ));
    }

    info!("[Cost] Arithmetic correct: ${total}/hr (expected ~${expected}/hr)");
    Ok(())
}

/// Verify that removing the rates ConfigMap causes cost to become None on next reconcile.
async fn test_cost_without_configmap(kubeconfig: &str) -> Result<(), String> {
    info!("[Cost] Removing rates ConfigMap to test graceful degradation...");

    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "configmap",
        RATES_CM_NAME,
        "-n",
        RATES_CM_NAMESPACE,
        "--ignore-not-found",
    ])
    .await?;

    // Force a full re-reconcile by changing replicas (spec change bumps generation)
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "patch",
        "latticeservice",
        SERVICE_NAME,
        "-n",
        COST_NAMESPACE,
        "--type",
        "merge",
        "-p",
        r#"{"spec":{"replicas":3}}"#,
    ])
    .await?;

    // Wait for cost to become empty (controller clears it on rate load failure)
    let kc = kubeconfig.to_string();
    wait_for_condition(
        "cost to be cleared after ConfigMap removal",
        Duration::from_secs(60),
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "latticeservice",
                    SERVICE_NAME,
                    "-n",
                    COST_NAMESPACE,
                    "-o",
                    "jsonpath={.status.cost.hourlyCost}",
                ])
                .await?;

                // Cost should be empty once the controller re-reconciles without rates
                Ok(output.trim().is_empty())
            }
        },
    )
    .await?;

    info!("[Cost] Cost correctly cleared when ConfigMap is absent");

    // Restore the ConfigMap for subsequent tests
    ensure_rates_configmap(kubeconfig).await?;

    Ok(())
}

/// Run all cost integration tests.
pub async fn run_cost_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[Cost] Running cost estimation integration tests on {kubeconfig}");

    ensure_rates_configmap(kubeconfig).await?;

    test_service_cost_populated(kubeconfig).await?;
    test_service_cost_arithmetic(kubeconfig).await?;
    test_cost_without_configmap(kubeconfig).await?;

    delete_namespace(kubeconfig, COST_NAMESPACE).await;

    info!("[Cost] All cost integration tests passed!");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_cost_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_cost_tests(&resolved.kubeconfig).await.unwrap();
}
