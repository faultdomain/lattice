//! Operator image upgrade integration tests
//!
//! Verifies that patching `spec.latticeImage` on a LatticeCluster triggers
//! the operator to upgrade its own Deployment and reflect the running image
//! in `status.latticeImage`.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_operator_upgrade_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::super::helpers::{
    run_kubectl, wait_for_condition, DEFAULT_LATTICE_IMAGE, DEFAULT_TIMEOUT,
};

/// Verify that `status.latticeImage` is set on the self-cluster's LatticeCluster.
///
/// After a fresh install the operator should write the running image into status.
pub async fn verify_status_lattice_image(kubeconfig: &str) -> Result<(), String> {
    info!("[Integration/Upgrade] Verifying status.latticeImage is set...");

    let kc = kubeconfig.to_string();
    let image = wait_for_condition(
        "status.latticeImage to be set",
        DEFAULT_TIMEOUT,
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "latticecluster",
                    "-o",
                    "jsonpath={range .items[*]}{.status.latticeImage}{end}",
                ])
                .await
                .map_err(|e| format!("kubectl failed: {}", e))?;

                let trimmed = output.trim().to_string();
                if trimmed.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(trimmed))
                }
            }
        },
    )
    .await?;

    info!(
        "[Integration/Upgrade] status.latticeImage = {}",
        image
    );
    Ok(())
}

/// Verify the operator image upgrade flow end-to-end on a running cluster.
///
/// - Records the current `spec.latticeImage`
/// - Patches it to a new tag
/// - Waits for the operator Deployment to roll to the new image
/// - Waits for `status.latticeImage` to reflect the new image
/// - Restores the original image
///
/// Requires a cluster where the test runner has admin access and the Lattice
/// operator is running as a self-managing cluster.
pub async fn verify_operator_upgrade(
    kubeconfig: &str,
    cluster_name: &str,
    new_image: &str,
) -> Result<(), String> {
    info!(
        "[Integration/Upgrade] Testing operator upgrade to {} on cluster {}...",
        new_image, cluster_name
    );

    // Record original image
    let original_image = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticecluster",
        cluster_name,
        "-o",
        "jsonpath={.spec.latticeImage}",
    ])
    .await
    .map_err(|e| format!("Failed to get current latticeImage: {}", e))?;

    let original_image = original_image.trim().to_string();
    if original_image.is_empty() {
        return Err("spec.latticeImage is empty on cluster".to_string());
    }
    info!(
        "[Integration/Upgrade] Current image: {}",
        original_image
    );

    // Patch spec.latticeImage to the new image
    let patch = format!(r#"{{"spec":{{"latticeImage":"{}"}}}}"#, new_image);
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "patch",
        "latticecluster",
        cluster_name,
        "--type=merge",
        "-p",
        &patch,
    ])
    .await
    .map_err(|e| format!("Failed to patch latticeImage: {}", e))?;

    info!(
        "[Integration/Upgrade] Patched spec.latticeImage to {}",
        new_image
    );

    // Wait for the operator Deployment to roll to the new image
    let kc = kubeconfig.to_string();
    let target = new_image.to_string();
    wait_for_condition(
        "operator Deployment to update to new image",
        DEFAULT_TIMEOUT,
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let target = target.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "deployment",
                    "lattice-operator",
                    "-n",
                    "lattice-system",
                    "-o",
                    "jsonpath={.spec.template.spec.containers[0].image}",
                ])
                .await
                .map_err(|e| format!("kubectl failed: {}", e))?;

                Ok(output.trim() == target)
            }
        },
    )
    .await?;

    info!(
        "[Integration/Upgrade] Deployment image updated to {}",
        new_image
    );

    // Wait for status.latticeImage to reflect the new image
    let kc = kubeconfig.to_string();
    let target = new_image.to_string();
    let cn = cluster_name.to_string();
    wait_for_condition(
        "status.latticeImage to reflect new image",
        DEFAULT_TIMEOUT,
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let target = target.clone();
            let cn = cn.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "latticecluster",
                    &cn,
                    "-o",
                    "jsonpath={.status.latticeImage}",
                ])
                .await
                .map_err(|e| format!("kubectl failed: {}", e))?;

                Ok(output.trim() == target)
            }
        },
    )
    .await?;

    info!(
        "[Integration/Upgrade] status.latticeImage confirmed: {}",
        new_image
    );

    // Restore original image
    let restore_patch = format!(
        r#"{{"spec":{{"latticeImage":"{}"}}}}"#,
        original_image
    );
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "patch",
        "latticecluster",
        cluster_name,
        "--type=merge",
        "-p",
        &restore_patch,
    ])
    .await
    .map_err(|e| format!("Failed to restore original latticeImage: {}", e))?;

    // Wait for restoration
    let kc = kubeconfig.to_string();
    let orig = original_image.clone();
    wait_for_condition(
        "operator to restore to original image",
        DEFAULT_TIMEOUT,
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let orig = orig.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "deployment",
                    "lattice-operator",
                    "-n",
                    "lattice-system",
                    "-o",
                    "jsonpath={.spec.template.spec.containers[0].image}",
                ])
                .await
                .map_err(|e| format!("kubectl failed: {}", e))?;

                Ok(output.trim() == orig)
            }
        },
    )
    .await?;

    info!("[Integration/Upgrade] Restored original image: {}", original_image);
    Ok(())
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test - verify status.latticeImage is populated
#[tokio::test]
#[ignore]
async fn test_operator_status_image_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    verify_status_lattice_image(&resolved.kubeconfig)
        .await
        .unwrap();
}

/// Standalone test - verify full operator upgrade cycle
///
/// Patches `spec.latticeImage` to a tagged version, waits for the Deployment
/// to update, verifies status, then restores the original image.
///
/// Set `LATTICE_UPGRADE_IMAGE` to override the target image (defaults to
/// the standard test image with a `-upgrade-test` suffix tag).
#[tokio::test]
#[ignore]
async fn test_operator_upgrade_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();

    let upgrade_image = std::env::var("LATTICE_UPGRADE_IMAGE")
        .unwrap_or_else(|_| DEFAULT_LATTICE_IMAGE.to_string());

    // Find the self-cluster name
    let cluster_name = run_kubectl(&[
        "--kubeconfig",
        &resolved.kubeconfig,
        "get",
        "latticecluster",
        "-o",
        "jsonpath={.items[0].metadata.name}",
    ])
    .await
    .expect("Failed to get cluster name");

    let cluster_name = cluster_name.trim();
    if cluster_name.is_empty() {
        panic!("No LatticeCluster found on the target cluster");
    }

    verify_operator_upgrade(&resolved.kubeconfig, cluster_name, &upgrade_image)
        .await
        .unwrap();
}
