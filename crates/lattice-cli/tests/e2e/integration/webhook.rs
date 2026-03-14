//! Admission webhook integration tests
//!
//! Verifies that the ValidatingAdmissionWebhook rejects invalid Lattice CRDs
//! at admission time and allows valid ones through.
//!
//! Run standalone:
//! ```
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_webhook_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::super::helpers::{
    apply_apparmor_override_policy, apply_yaml, ensure_namespace, run_kubectl, wait_for_condition,
    with_diagnostics, DiagnosticContext,
};

const WEBHOOK_TEST_NS: &str = "webhook-test";

/// Sanitize a test description for use in a file path
fn sanitize_desc(desc: &str) -> String {
    desc.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Apply YAML via kubectl and expect it to succeed
async fn apply_should_succeed(kubeconfig: &str, yaml: &str, desc: &str) -> Result<(), String> {
    apply_yaml(kubeconfig, yaml).await?;
    info!("[Webhook] {desc}: accepted (expected)");
    Ok(())
}

/// Apply YAML via kubectl and expect it to be rejected by the admission webhook.
///
/// Returns the error message from the rejection for further assertions.
/// For static YAML that doesn't change between retries. For live resources
/// that may be modified by the operator between attempts, use
/// `try_apply_expecting_rejection` directly with a refresh closure.
async fn apply_should_be_rejected(
    kubeconfig: &str,
    yaml: &str,
    desc: &str,
) -> Result<String, String> {
    let yaml = yaml.to_string();
    try_apply_expecting_rejection(
        kubeconfig,
        || {
            let y = yaml.clone();
            async move { Ok(y) }
        },
        desc,
    )
    .await
}

/// Core retry loop for webhook rejection tests.
///
/// Re-generates YAML via `make_yaml` before each attempt, handling Conflict
/// errors from concurrent operator updates (annotation changes, status patches).
/// Retries up to 10 times on transient errors. Returns once kubectl gets a
/// definitive accept/reject from the admission webhook.
async fn try_apply_expecting_rejection<F, Fut>(
    kubeconfig: &str,
    make_yaml: F,
    desc: &str,
) -> Result<String, String>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    let tmpfile = format!("/tmp/webhook-test-{}.yaml", sanitize_desc(desc));
    let kc = kubeconfig.to_string();
    let desc_owned = desc.to_string();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let yaml = make_yaml().await?;
        tokio::fs::write(&tmpfile, &yaml)
            .await
            .map_err(|e| format!("Failed to write temp file: {e}"))?;

        let result = tokio::process::Command::new("kubectl")
            .args(["--kubeconfig", &kc, "apply", "-f", &tmpfile])
            .output()
            .await
            .map_err(|e| format!("Failed to spawn kubectl: {e}"))?;

        if result.status.success() {
            return Err(format!(
                "[Webhook] {desc_owned}: was accepted but should have been REJECTED"
            ));
        }

        let stderr = String::from_utf8_lossy(&result.stderr).to_string();

        // Admission webhook rejections contain "denied the request" — if we see
        // that, the request reached the webhook and was properly rejected.
        if stderr.contains("denied the request") {
            info!("[Webhook] {desc_owned}: rejected (expected): {stderr}");
            return Ok(stderr);
        }

        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "[Webhook] {desc_owned}: kubectl never reached the admission webhook \
                 within timeout"
            ));
        }

        // Transient error (auth, connectivity, etc.) — retry
        info!(
            "[Webhook] {desc_owned}: transient error: {}",
            stderr.lines().next().unwrap_or(&stderr)
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Wait for the admission webhook to be responsive.
///
/// The webhook server starts on all pods before leader election, but the
/// ValidatingWebhookConfiguration is applied by the leader after CRD installation.
/// This function polls until the webhook is active by checking if the
/// ValidatingWebhookConfiguration exists.
async fn wait_for_webhook_ready(kubeconfig: &str) -> Result<(), String> {
    info!("[Webhook] Waiting for admission webhook to be ready...");

    wait_for_condition(
        "ValidatingWebhookConfiguration to exist",
        Duration::from_secs(120),
        Duration::from_secs(5),
        || {
            let kc = kubeconfig.to_string();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "validatingwebhookconfiguration",
                    "lattice-validating-webhook",
                    "-o",
                    "name",
                ])
                .await;

                match output {
                    Ok(name) if name.contains("lattice-validating-webhook") => Ok(true),
                    _ => Ok(false),
                }
            }
        },
    )
    .await?;

    info!("[Webhook] Admission webhook is ready");
    Ok(())
}

/// Test: valid LatticeService is accepted
async fn test_valid_service_accepted(kubeconfig: &str) -> Result<(), String> {
    let yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: webhook-test-svc
  namespace: {WEBHOOK_TEST_NS}
spec:
  workload:
    containers:
      main:
        image: nginx:latest
        resources:
          limits:
            cpu: "100m"
            memory: "64Mi"
        security:
          apparmorProfile: Unconfined
"#
    );
    apply_should_succeed(kubeconfig, &yaml, "valid LatticeService").await
}

/// Test: LatticeService with replicas > autoscaling.max is rejected
async fn test_invalid_service_rejected(kubeconfig: &str) -> Result<(), String> {
    let yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: webhook-test-bad-svc
  namespace: {WEBHOOK_TEST_NS}
spec:
  replicas: 10
  autoscaling:
    max: 5
  workload:
    containers:
      main:
        image: nginx:latest
        resources:
          limits:
            cpu: "100m"
            memory: "64Mi"
"#
    );
    let err =
        apply_should_be_rejected(kubeconfig, &yaml, "service replicas > autoscaling max").await?;
    if !err.contains("replicas") || !err.contains("autoscaling") {
        return Err(format!(
            "Expected rejection to mention replicas/autoscaling, got: {err}"
        ));
    }
    Ok(())
}

/// Test: valid LatticeModel is accepted
async fn test_valid_model_accepted(kubeconfig: &str) -> Result<(), String> {
    let yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeModel
metadata:
  name: webhook-test-model
  namespace: {WEBHOOK_TEST_NS}
spec:
  roles:
    prefill:
      replicas: 1
      entryWorkload:
        containers:
          main:
            image: vllm:latest
            resources:
              limits:
                cpu: "100m"
                memory: "64Mi"
            security:
              apparmorProfile: Unconfined
"#
    );
    apply_should_succeed(kubeconfig, &yaml, "valid LatticeModel").await
}

/// Test: LatticeModel with role replicas > autoscaling.max is rejected
async fn test_invalid_model_rejected(kubeconfig: &str) -> Result<(), String> {
    let yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeModel
metadata:
  name: webhook-test-bad-model
  namespace: {WEBHOOK_TEST_NS}
spec:
  roles:
    decode:
      replicas: 10
      autoscaling:
        max: 5
      entryWorkload:
        containers:
          main:
            image: vllm:latest
"#
    );
    let err = apply_should_be_rejected(kubeconfig, &yaml, "model role replicas > autoscaling max")
        .await?;
    if !err.contains("decode") {
        return Err(format!(
            "Expected rejection to mention the role name 'decode', got: {err}"
        ));
    }
    Ok(())
}

/// Test: valid LatticeMeshMember is accepted
async fn test_valid_mesh_member_accepted(kubeconfig: &str) -> Result<(), String> {
    let yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeMeshMember
metadata:
  name: webhook-test-mesh
  namespace: {WEBHOOK_TEST_NS}
spec:
  target:
    selector:
      app: test
  ports:
    - port: 8080
      name: http
"#
    );
    apply_should_succeed(kubeconfig, &yaml, "valid LatticeMeshMember").await
}

/// Test: LatticeMeshMember with no ports/deps/egress is accepted (empty LMM
/// is valid — gives workload a CNP with DNS access at minimum).
async fn test_empty_mesh_member_accepted(kubeconfig: &str) -> Result<(), String> {
    let yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeMeshMember
metadata:
  name: webhook-test-empty-mesh
  namespace: {WEBHOOK_TEST_NS}
spec:
  target:
    selector:
      app: test
  ports: []
  dependencies: []
  egress: []
"#
    );
    apply_should_succeed(kubeconfig, &yaml, "empty LatticeMeshMember").await
}

// =============================================================================
// LatticeCluster parent_config validation tests
// =============================================================================
//
// These tests use the real clusters from the E2E hierarchy instead of creating
// throwaway clusters, to avoid straining test infrastructure:
//
// - Management cluster: has parent_config (it's a parent) → test removal/modification blocked
// - Workload cluster: no parent_config (leaf) → test promotion allowed, then removal blocked
//
// The tests fetch the existing LatticeCluster YAML and re-apply with modifications.
// On the workload cluster, the self-cluster is accessed via the workload kubeconfig.
// On the management cluster, the self-cluster is accessed via the mgmt kubeconfig.

/// Discover the self-cluster name by listing LatticeCluster resources.
///
/// Returns `None` if no LatticeCluster exists on the target cluster.
async fn discover_self_cluster(kubeconfig: &str) -> Result<Option<String>, String> {
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticecluster",
        "-o",
        "jsonpath={.items[0].metadata.name}",
    ])
    .await;

    match output {
        Ok(name) if !name.trim().is_empty() => Ok(Some(name.trim().to_string())),
        _ => Ok(None),
    }
}

/// Fetch the full LatticeCluster YAML for a given cluster name
async fn get_cluster_yaml(kubeconfig: &str, name: &str) -> Result<String, String> {
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "latticecluster",
        name,
        "-o",
        "yaml",
    ])
    .await
}

/// Test: LatticeCluster CREATE with duplicate ports in parentConfig is rejected
async fn test_cluster_duplicate_ports_rejected(kubeconfig: &str) -> Result<(), String> {
    let yaml = r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: webhook-test-dup-ports
spec:
  latticeImage: "test:latest"
  providerRef: webhook-test-fake
  provider:
    kubernetes:
      version: "1.32.0"
      certSANs: ["127.0.0.1"]
    config:
      docker: {}
  nodes:
    controlPlane:
      replicas: 1
    workerPools:
      default:
        replicas: 1
  parentConfig:
    grpcPort: 8443
    bootstrapPort: 8443
    proxyPort: 8081
    service:
      type: LoadBalancer
"#;
    let err = apply_should_be_rejected(kubeconfig, yaml, "cluster with duplicate ports").await?;
    if !err.contains("distinct") {
        return Err(format!(
            "Expected rejection to mention 'distinct', got: {err}"
        ));
    }
    Ok(())
}

/// Test: LatticeCluster CREATE with invalid service type is rejected
async fn test_cluster_invalid_service_type_rejected(kubeconfig: &str) -> Result<(), String> {
    let yaml = r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: webhook-test-bad-svc-type
spec:
  latticeImage: "test:latest"
  providerRef: webhook-test-fake
  provider:
    kubernetes:
      version: "1.32.0"
      certSANs: ["127.0.0.1"]
    config:
      docker: {}
  nodes:
    controlPlane:
      replicas: 1
    workerPools:
      default:
        replicas: 1
  parentConfig:
    grpcPort: 50051
    bootstrapPort: 8443
    proxyPort: 8081
    service:
      type: ExternalName
"#;
    let err =
        apply_should_be_rejected(kubeconfig, yaml, "cluster with invalid service type").await?;
    if !err.contains("LoadBalancer") {
        return Err(format!(
            "Expected rejection to mention 'LoadBalancer', got: {err}"
        ));
    }
    Ok(())
}

/// Test parent_config immutability using the live workload cluster.
///
/// The workload cluster is a leaf (no parent_config). The test:
/// - Promotes it by adding parent_config → allowed
/// - Tries to modify the parent_config → rejected (immutable)
/// - Tries to remove parent_config → rejected (cannot be removed)
///
/// After testing, the parent_config stays on the workload cluster. This is
/// safe because E2E teardown destroys everything, and standalone runs don't
/// rely on the workload being a leaf.
async fn test_parent_config_immutability(kubeconfig: &str) -> Result<(), String> {
    let cluster_name = match discover_self_cluster(kubeconfig).await? {
        Some(name) => name,
        None => {
            info!("[Webhook] No LatticeCluster found on target cluster, skipping parent_config immutability test");
            return Ok(());
        }
    };

    // Fetch the existing workload LatticeCluster YAML
    let original_yaml = get_cluster_yaml(kubeconfig, &cluster_name).await?;

    // Verify the workload cluster doesn't already have parent_config
    if original_yaml.contains("parentConfig") {
        info!("[Webhook] Cluster already has parentConfig, skipping promotion test");
        // Apply the current YAML to establish the last-applied-configuration
        // annotation. Without it, `kubectl apply` does a two-way merge that
        // cannot detect field removal, so the strip test would silently no-op.
        apply_should_succeed(
            kubeconfig,
            &original_yaml,
            "establish last-applied annotation",
        )
        .await?;
    } else {
        // Promotion: add parent_config to the leaf cluster → should be allowed
        let promoted_yaml = inject_parent_config(&original_yaml);
        apply_should_succeed(kubeconfig, &promoted_yaml, "promote workload to parent").await?;
        info!("[Webhook] Workload cluster promoted to parent");
    }

    // Modification: try to change grpc_port → should be rejected
    // Re-fetch before each attempt because operator reconciliation can modify
    // the resource (annotations, status), causing Conflict errors with stale YAML.
    let err = try_apply_expecting_rejection(
        kubeconfig,
        || {
            let kc = kubeconfig.to_string();
            let cn = cluster_name.clone();
            async move {
                let yaml = get_cluster_yaml(&kc, &cn).await?;
                let modified = yaml.replace("grpcPort: 50051", "grpcPort: 9999");
                if modified == yaml {
                    return Err("Failed to inject modified grpcPort into YAML".to_string());
                }
                Ok(modified)
            }
        },
        "modify parent_config ports",
    )
    .await?;
    if !err.contains("immutable") {
        return Err(format!(
            "Expected rejection to mention 'immutable', got: {err}"
        ));
    }

    // Removal: try to null out parent_config → should be rejected
    //
    // Use `kubectl patch --type=merge` to directly send a null parentConfig
    // instead of relying on `kubectl apply` three-way merge with stripped YAML.
    // The apply approach is fragile: if the operator reconciles and removes the
    // test-injected parentConfig between promotion and this test, the strip is
    // a no-op and kubectl accepts unchanged YAML without hitting the webhook.
    let err = try_patch_expecting_rejection(
        kubeconfig,
        &cluster_name,
        r#"{"spec":{"parentConfig":null}}"#,
        "remove parent_config",
    )
    .await?;
    if !err.contains("cannot be removed") {
        return Err(format!(
            "Expected rejection to mention 'cannot be removed', got: {err}"
        ));
    }

    Ok(())
}

/// Patch a LatticeCluster and expect the admission webhook to reject it.
///
/// Uses `kubectl patch --type=merge` which sends a direct merge patch to the
/// API server, bypassing the three-way merge logic of `kubectl apply`. This is
/// more reliable for testing field removal (setting to null) because it doesn't
/// depend on last-applied-configuration annotation state.
async fn try_patch_expecting_rejection(
    kubeconfig: &str,
    cluster_name: &str,
    patch_json: &str,
    desc: &str,
) -> Result<String, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let result = tokio::process::Command::new("kubectl")
            .args([
                "--kubeconfig",
                kubeconfig,
                "patch",
                "latticecluster",
                cluster_name,
                "--type=merge",
                "-p",
                patch_json,
            ])
            .output()
            .await
            .map_err(|e| format!("Failed to spawn kubectl: {e}"))?;

        if result.status.success() {
            return Err(format!(
                "[Webhook] {desc}: was accepted but should have been REJECTED"
            ));
        }

        let stderr = String::from_utf8_lossy(&result.stderr).to_string();

        if stderr.contains("denied the request") {
            info!("[Webhook] {desc}: rejected (expected): {stderr}");
            return Ok(stderr);
        }

        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "[Webhook] {desc}: kubectl never reached the admission webhook \
                 within timeout"
            ));
        }

        info!(
            "[Webhook] {desc}: transient error: {}",
            stderr.lines().next().unwrap_or(&stderr)
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Inject a parentConfig block into a LatticeCluster YAML that doesn't have one.
///
/// Inserts after the `nodes:` section by finding the `nodes:` key at spec level
/// and appending parentConfig at the same indent.
fn inject_parent_config(yaml: &str) -> String {
    let parent_config_block = r#"  parentConfig:
    grpcPort: 50051
    bootstrapPort: 8443
    proxyPort: 8081
    service:
      type: LoadBalancer"#;

    // Insert parentConfig at the end of spec (before status or EOF)
    if let Some(status_pos) = yaml.find("\nstatus:") {
        format!(
            "{}\n{}\n{}",
            &yaml[..status_pos],
            parent_config_block,
            &yaml[status_pos..]
        )
    } else {
        format!("{}\n{}\n", yaml.trim_end(), parent_config_block)
    }
}

// =============================================================================
// Cleanup and main test runner
// =============================================================================

/// Cleanup test resources
async fn cleanup(kubeconfig: &str) {
    info!("[Webhook] Cleaning up test resources...");
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "namespace",
        WEBHOOK_TEST_NS,
    ])
    .await;
}

/// Run all webhook integration tests
pub async fn run_webhook_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[Webhook] Running admission webhook integration tests on {kubeconfig}");

    let diag = DiagnosticContext::new(kubeconfig, WEBHOOK_TEST_NS);
    with_diagnostics(&diag, "Webhook", || async {
        wait_for_webhook_ready(kubeconfig).await?;
        ensure_namespace(kubeconfig, WEBHOOK_TEST_NS).await?;

        apply_apparmor_override_policy(kubeconfig).await?;

        test_valid_service_accepted(kubeconfig).await?;
        test_valid_model_accepted(kubeconfig).await?;
        test_valid_mesh_member_accepted(kubeconfig).await?;

        test_invalid_service_rejected(kubeconfig).await?;
        test_invalid_model_rejected(kubeconfig).await?;
        test_empty_mesh_member_accepted(kubeconfig).await?;

        test_cluster_duplicate_ports_rejected(kubeconfig).await?;
        test_cluster_invalid_service_type_rejected(kubeconfig).await?;

        test_parent_config_immutability(kubeconfig).await?;

        cleanup(kubeconfig).await;

        info!("[Webhook] All admission webhook integration tests passed!");
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore]
async fn test_webhook_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_webhook_tests(&resolved.kubeconfig).await.unwrap();
}
