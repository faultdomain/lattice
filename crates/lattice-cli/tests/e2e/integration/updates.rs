//! CRD update integration tests
//!
//! Verifies that controllers handle spec updates correctly:
//!
//! LatticeService:
//! - Ready → spec change → recompile → Ready
//! - Failed → spec fix → recover → Ready
//! - Failed (persistent) → no spec change → observed_generation set, no tight loop
//!
//! LatticeModel:
//! - Serving → spec change → recompile → Serving
//! - Loading → spec change → detect and recompile (not stamp stale generation)
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_updates_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::super::helpers::{
    apply_cedar_policy_crd, apply_yaml_with_retry, create_service_with_secrets,
    delete_cedar_policies_by_label, delete_namespace, deploy_and_wait_for_phase,
    ensure_fresh_namespace, load_fixture_config, run_kubectl, setup_regcreds_infrastructure,
    wait_for_condition, wait_for_resource_phase, wait_for_service_phase, TestHarness,
    BUSYBOX_IMAGE, DEFAULT_TIMEOUT,
};

// =============================================================================
// Constants
// =============================================================================

const NS_READY_UPDATE: &str = "update-t1";
const NS_FAILED_RECOVER: &str = "update-t2";
const NS_FAILED_STABLE: &str = "update-t3";

/// Dummy secret provider name (Cedar denies access → immediate compile failure)
const DENIED_PROVIDER: &str = "nonexistent-provider";

// =============================================================================
// Test 1: Ready → spec change → recompile → Ready
// =============================================================================

/// Deploy a service to Ready, update its spec, verify the controller recompiles
/// and the new generation is reflected in observed_generation.
async fn test_ready_spec_update(kubeconfig: &str) -> Result<(), String> {
    info!("[Updates] Test 1: Ready → spec change → recompile → Ready");
    ensure_fresh_namespace(kubeconfig, NS_READY_UPDATE).await?;

    // Deploy a simple service (no secrets, no deps) → should reach Ready
    let svc = build_simple_service("svc-update-test", NS_READY_UPDATE);
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_READY_UPDATE,
        svc,
        "Ready",
        None,
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Record the current observed_generation
    let gen_before =
        get_observed_generation(kubeconfig, NS_READY_UPDATE, "svc-update-test").await?;
    info!("[Updates] Before update: observed_generation = {gen_before}");

    // Update the service spec (change the command) — this bumps metadata.generation
    let patch_json = serde_json::json!({
        "spec": {
            "workload": {
                "containers": {
                    "main": {
                        "command": ["/bin/sleep", "999999"]
                    }
                }
            }
        }
    });
    patch_resource(
        kubeconfig,
        "latticeservice",
        NS_READY_UPDATE,
        "svc-update-test",
        &patch_json,
    )
    .await?;

    // Wait for the controller to reconcile with the new generation
    let gen_before_i64: i64 = gen_before.parse().unwrap_or(0);
    wait_for_generation_advance(
        kubeconfig,
        NS_READY_UPDATE,
        "svc-update-test",
        gen_before_i64,
    )
    .await?;

    // Verify still Ready (not stuck in Compiling or Failed)
    wait_for_service_phase(
        kubeconfig,
        NS_READY_UPDATE,
        "svc-update-test",
        "Ready",
        None,
        Duration::from_secs(120),
    )
    .await?;

    let gen_after = get_observed_generation(kubeconfig, NS_READY_UPDATE, "svc-update-test").await?;
    info!("[Updates] After update: observed_generation = {gen_after}");

    if gen_after == gen_before {
        return Err(format!(
            "observed_generation did not advance after spec change ({gen_before} → {gen_after})"
        ));
    }

    delete_namespace(kubeconfig, NS_READY_UPDATE).await;
    info!("[Updates] Test 1 passed: Ready → spec change → Ready");
    Ok(())
}

// =============================================================================
// Test 2: Failed → spec fix → recover → Ready
// =============================================================================

/// Deploy a service that fails (Cedar denies secret access), then fix it
/// by adding a permit policy, and verify recovery to Ready.
async fn test_failed_spec_recovery(kubeconfig: &str) -> Result<(), String> {
    info!("[Updates] Test 2: Failed → fix → Ready");

    // Clean up Cedar policies from previous runs. The permit policy lives in
    // lattice-system (not the test namespace), so ensure_fresh_namespace won't
    // delete it. A stale permit would cause the service to reach Ready instead
    // of Failed, breaking the test.
    delete_cedar_policies_by_label(kubeconfig, "lattice.dev/test=update-test").await;

    ensure_fresh_namespace(kubeconfig, NS_FAILED_RECOVER).await?;

    // Deploy a service with a secret that's denied by Cedar → should reach Failed
    let svc = create_service_with_secrets(
        "svc-recover",
        NS_FAILED_RECOVER,
        vec![("my-secret", "some/path", DENIED_PROVIDER, None)],
    );
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_FAILED_RECOVER,
        svc,
        "Failed",
        Some("secret access denied"),
        Duration::from_secs(60),
    )
    .await?;

    info!("[Updates] Service failed as expected, applying Cedar permit policy...");

    // Apply a Cedar policy that permits access to the secret
    apply_cedar_policy_crd(
        kubeconfig,
        "permit-update-t2",
        "update-test",
        100,
        &format!(
            r#"permit(
  principal,
  action == Lattice::Action::"AccessSecret",
  resource
) when {{
  principal.namespace == "{NS_FAILED_RECOVER}"
}};"#
        ),
    )
    .await?;

    // Wait for recovery to Ready
    wait_for_service_phase(
        kubeconfig,
        NS_FAILED_RECOVER,
        "svc-recover",
        "Ready",
        None,
        Duration::from_secs(180),
    )
    .await?;

    delete_cedar_policies_by_label(kubeconfig, "lattice.dev/test=update-test").await;
    delete_namespace(kubeconfig, NS_FAILED_RECOVER).await;
    info!("[Updates] Test 2 passed: Failed → permit policy → Ready");
    Ok(())
}

// =============================================================================
// Test 3: Failed (persistent) → no change → observed_generation set
// =============================================================================

/// Deploy a service that fails persistently (invalid secret provider, no Cedar
/// policy will fix it). Verify that:
/// - observed_generation IS set on the Failed status
/// - The controller does NOT tight-loop recompiling (status stabilizes)
///
/// This test exposes Gap 1: LatticeService Failed currently sets
/// observed_generation to None, causing 30s retry loops with no input changes.
async fn test_failed_sets_observed_generation(kubeconfig: &str) -> Result<(), String> {
    info!("[Updates] Test 3: Failed sets observed_generation (no tight loop)");
    ensure_fresh_namespace(kubeconfig, NS_FAILED_STABLE).await?;

    // Deploy a service with a secret that's denied — will fail on compilation
    let svc = create_service_with_secrets(
        "svc-stable-fail",
        NS_FAILED_STABLE,
        vec![("my-secret", "denied/path", DENIED_PROVIDER, None)],
    );
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_FAILED_STABLE,
        svc,
        "Failed",
        Some("secret access denied"),
        Duration::from_secs(60),
    )
    .await?;

    // Give the controller time to stabilize (2 requeue cycles)
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Verify observed_generation is set (not empty/missing)
    let observed = get_observed_generation(kubeconfig, NS_FAILED_STABLE, "svc-stable-fail").await?;
    if observed.is_empty() {
        return Err(
            "observed_generation is empty on Failed service — controller will tight-loop \
             recompiling every 30s even when nothing changed. \
             Failed status must include observed_generation."
                .to_string(),
        );
    }

    let gen = get_generation(kubeconfig, NS_FAILED_STABLE, "svc-stable-fail").await?;
    if observed != gen {
        return Err(format!(
            "observed_generation ({observed}) != metadata.generation ({gen}) — \
             controller hasn't acknowledged the current spec"
        ));
    }

    info!("[Updates] observed_generation = {observed} (matches generation = {gen})");

    delete_namespace(kubeconfig, NS_FAILED_STABLE).await;
    info!("[Updates] Test 3 passed: Failed service has observed_generation set");
    Ok(())
}

// =============================================================================
// Test 4: LatticeModel Serving → spec change → recompile → Serving
// =============================================================================

const NS_MODEL_SPEC_UPDATE: &str = "update-t4";

/// Deploy a model to Serving, update its spec (replicas), verify the controller
/// recompiles and observed_generation advances.
async fn test_model_serving_spec_update(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    info!("[Updates] Test 4: Model Serving → spec change → Serving");
    ensure_fresh_namespace(kubeconfig, namespace).await?;

    // Deploy from fixture with overridden namespace
    let yaml = load_model_fixture_for_namespace(namespace)?;
    apply_yaml_with_retry(kubeconfig, &yaml).await?;

    // Wait for Serving
    wait_for_resource_phase(
        kubeconfig,
        "latticemodel",
        namespace,
        "llm-serving",
        "Serving",
        DEFAULT_TIMEOUT,
    )
    .await?;

    let gen_before = get_model_observed_generation(kubeconfig, namespace, "llm-serving").await?;
    info!("[Updates] Model before update: observed_generation = {gen_before}");

    // Patch decode replicas from 2 → 3
    let patch_json = serde_json::json!({
        "spec": {
            "roles": {
                "decode": {
                    "replicas": 3
                }
            }
        }
    });
    patch_resource(
        kubeconfig,
        "latticemodel",
        namespace,
        "llm-serving",
        &patch_json,
    )
    .await?;

    // Wait for generation to advance
    let gen_before_i64: i64 = gen_before.parse().unwrap_or(0);
    wait_for_model_generation_advance(kubeconfig, namespace, "llm-serving", gen_before_i64).await?;

    // Verify still Serving
    wait_for_resource_phase(
        kubeconfig,
        "latticemodel",
        namespace,
        "llm-serving",
        "Serving",
        Duration::from_secs(180),
    )
    .await?;

    // Verify ModelServing reflects new replicas
    let decode_replicas =
        get_model_serving_role_replicas(kubeconfig, namespace, "llm-serving", "decode").await?;
    if decode_replicas != 3 {
        return Err(format!(
            "ModelServing decode replicas should be 3 after update, got: {decode_replicas}"
        ));
    }

    let gen_after = get_model_observed_generation(kubeconfig, namespace, "llm-serving").await?;
    info!("[Updates] Model after update: observed_generation = {gen_after}");

    if gen_after == gen_before {
        return Err(format!(
            "Model observed_generation did not advance ({gen_before} → {gen_after})"
        ));
    }

    delete_namespace(kubeconfig, namespace).await;
    info!("[Updates] Test 4 passed: Model Serving → spec change → Serving");
    Ok(())
}

// =============================================================================
// Test 5: LatticeModel Loading → spec change → detect and recompile
// =============================================================================

const NS_MODEL_LOADING_GAP: &str = "update-t5";

/// Deploy a model, wait for Loading, then patch the spec (change replicas).
/// Verify that the controller detects the spec change and recompiles before
/// reaching Serving — the compiled resources must reflect the NEW spec.
///
/// This test exposes Gap 2: the Loading phase currently does not check
/// `spec_changed_since_compilation`. When the user updates the spec while
/// Loading, the old compiled resources keep running. On Loading→Serving
/// transition, the NEW generation is stamped — making Serving think it's
/// up-to-date when it's actually running stale config.
async fn test_model_loading_detects_spec_change(
    kubeconfig: &str,
    namespace: &str,
) -> Result<(), String> {
    info!("[Updates] Test 5: Model Loading → spec change → detect and recompile");
    ensure_fresh_namespace(kubeconfig, namespace).await?;

    // Deploy from fixture (decode.replicas=2 in fixture)
    let yaml = load_model_fixture_for_namespace(namespace)?;
    apply_yaml_with_retry(kubeconfig, &yaml).await?;

    // Wait for Loading (compilation done, resources applied, waiting for readiness)
    wait_for_resource_phase(
        kubeconfig,
        "latticemodel",
        namespace,
        "llm-serving",
        "Loading",
        Duration::from_secs(120),
    )
    .await?;

    let gen_at_loading =
        get_model_observed_generation(kubeconfig, namespace, "llm-serving").await?;
    info!("[Updates] Model at Loading: observed_generation = {gen_at_loading}");

    // Patch decode replicas from 2 → 3 while still Loading
    // This bumps metadata.generation but the Loading phase won't notice (the gap)
    let patch_json = serde_json::json!({
        "spec": {
            "roles": {
                "decode": {
                    "replicas": 3
                }
            }
        }
    });
    patch_resource(
        kubeconfig,
        "latticemodel",
        namespace,
        "llm-serving",
        &patch_json,
    )
    .await?;
    info!("[Updates] Patched decode replicas to 3 while Loading");

    // Wait for the model to reach Serving (whether or not it recompiled)
    wait_for_resource_phase(
        kubeconfig,
        "latticemodel",
        namespace,
        "llm-serving",
        "Serving",
        DEFAULT_TIMEOUT,
    )
    .await?;

    // The critical check: does the ModelServing have 3 decode replicas (new spec)
    // or 2 (old spec, stale config)?
    let decode_replicas =
        get_model_serving_role_replicas(kubeconfig, namespace, "llm-serving", "decode").await?;

    if decode_replicas != 3 {
        return Err(format!(
            "ModelServing decode replicas = {decode_replicas}, expected 3. \
             The Loading phase did not detect the spec change — compiled resources \
             are stale but observed_generation was stamped with the new generation. \
             Loading must check spec_changed_since_compilation and go back to Pending \
             when the generation doesn't match."
        ));
    }

    // Also verify observed_generation matches the final generation
    let observed = get_model_observed_generation(kubeconfig, namespace, "llm-serving").await?;
    let gen = get_model_generation(kubeconfig, namespace, "llm-serving").await?;
    if observed != gen {
        return Err(format!(
            "Model observed_generation ({observed}) != generation ({gen}) after Serving"
        ));
    }

    delete_namespace(kubeconfig, namespace).await;
    info!("[Updates] Test 5 passed: Model Loading detected spec change and recompiled");
    Ok(())
}

// =============================================================================
// Helpers (Service)
// =============================================================================

/// Build a minimal LatticeService with no secrets or dependencies.
fn build_simple_service(name: &str, namespace: &str) -> lattice_common::crd::LatticeService {
    use lattice_common::crd::{ContainerSpec, ResourceQuantity, ResourceRequirements};
    use std::collections::BTreeMap;

    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: BUSYBOX_IMAGE.to_string(),
            command: Some(vec!["/bin/sleep".to_string(), "infinity".to_string()]),
            resources: Some(ResourceRequirements {
                requests: Some(ResourceQuantity {
                    cpu: Some("50m".to_string()),
                    memory: Some("64Mi".to_string()),
                }),
                limits: Some(ResourceQuantity {
                    cpu: Some("200m".to_string()),
                    memory: Some("128Mi".to_string()),
                }),
            }),
            security: Some(lattice_common::crd::SecurityContext {
                apparmor_profile: Some("Unconfined".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    super::super::helpers::build_busybox_service(name, namespace, containers, BTreeMap::new())
}

// =============================================================================
// Helpers (Generic)
// =============================================================================

/// Patch any CRD resource via `kubectl patch --type=merge`.
async fn patch_resource(
    kubeconfig: &str,
    kind: &str,
    namespace: &str,
    name: &str,
    patch: &serde_json::Value,
) -> Result<(), String> {
    let patch_str =
        serde_json::to_string(patch).map_err(|e| format!("Failed to serialize patch: {e}"))?;

    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "patch",
        kind,
        name,
        "-n",
        namespace,
        "--type=merge",
        "-p",
        &patch_str,
    ])
    .await?;

    Ok(())
}

/// Get `.status.observedGeneration` from any resource via kubectl.
async fn get_resource_observed_generation(
    kubeconfig: &str,
    kind: &str,
    namespace: &str,
    name: &str,
) -> Result<String, String> {
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        kind,
        name,
        "-n",
        namespace,
        "-o",
        "jsonpath={.status.observedGeneration}",
    ])
    .await
    .map(|s| s.trim().to_string())
}

/// Get `.metadata.generation` from any resource via kubectl.
async fn get_resource_generation(
    kubeconfig: &str,
    kind: &str,
    namespace: &str,
    name: &str,
) -> Result<String, String> {
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        kind,
        name,
        "-n",
        namespace,
        "-o",
        "jsonpath={.metadata.generation}",
    ])
    .await
    .map(|s| s.trim().to_string())
}

/// Wait for `.status.observedGeneration` to advance past `previous_gen`.
async fn wait_for_generation_advance_generic(
    kubeconfig: &str,
    kind: &str,
    namespace: &str,
    name: &str,
    previous_gen: i64,
) -> Result<(), String> {
    let kind_owned = kind.to_string();
    wait_for_condition(
        &format!("{kind} {namespace}/{name} observed_generation > {previous_gen}"),
        Duration::from_secs(180),
        Duration::from_secs(5),
        || {
            let kind_ref = kind_owned.clone();
            async move {
                let obs = get_resource_observed_generation(kubeconfig, &kind_ref, namespace, name)
                    .await
                    .unwrap_or_default();
                let current: i64 = obs.parse().unwrap_or(0);
                Ok(current > previous_gen)
            }
        },
    )
    .await
}

// =============================================================================
// Helpers (Service — delegate to generic)
// =============================================================================

/// Get `.status.observedGeneration` from a LatticeService.
async fn get_observed_generation(
    kubeconfig: &str,
    namespace: &str,
    name: &str,
) -> Result<String, String> {
    get_resource_observed_generation(kubeconfig, "latticeservice", namespace, name).await
}

/// Get `.metadata.generation` from a LatticeService.
async fn get_generation(kubeconfig: &str, namespace: &str, name: &str) -> Result<String, String> {
    get_resource_generation(kubeconfig, "latticeservice", namespace, name).await
}

/// Wait for LatticeService `.status.observedGeneration` to advance.
async fn wait_for_generation_advance(
    kubeconfig: &str,
    namespace: &str,
    name: &str,
    previous_gen: i64,
) -> Result<(), String> {
    wait_for_generation_advance_generic(kubeconfig, "latticeservice", namespace, name, previous_gen)
        .await
}

// =============================================================================
// Helpers (Model)
// =============================================================================

/// Load the model-serving fixture with an overridden namespace.
fn load_model_fixture_for_namespace(namespace: &str) -> Result<String, String> {
    let mut model: lattice_common::crd::LatticeModel = load_fixture_config("model-serving.yaml")?;
    model.metadata.namespace = Some(namespace.to_string());
    serde_json::to_string(&model).map_err(|e| format!("Failed to serialize model fixture: {e}"))
}

/// Get `.status.observedGeneration` from a LatticeModel.
async fn get_model_observed_generation(
    kubeconfig: &str,
    namespace: &str,
    name: &str,
) -> Result<String, String> {
    get_resource_observed_generation(kubeconfig, "latticemodel", namespace, name).await
}

/// Get `.metadata.generation` from a LatticeModel.
async fn get_model_generation(
    kubeconfig: &str,
    namespace: &str,
    name: &str,
) -> Result<String, String> {
    get_resource_generation(kubeconfig, "latticemodel", namespace, name).await
}

/// Wait for LatticeModel `.status.observedGeneration` to advance.
async fn wait_for_model_generation_advance(
    kubeconfig: &str,
    namespace: &str,
    name: &str,
    previous_gen: i64,
) -> Result<(), String> {
    wait_for_generation_advance_generic(kubeconfig, "latticemodel", namespace, name, previous_gen)
        .await
}

/// Get the `replicas` field for a specific role from the ModelServing resource.
async fn get_model_serving_role_replicas(
    kubeconfig: &str,
    namespace: &str,
    model_name: &str,
    role_name: &str,
) -> Result<u64, String> {
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "modelservings.workload.serving.volcano.sh",
        model_name,
        "-n",
        namespace,
        "-o",
        "json",
    ])
    .await?;

    let ms: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| format!("Failed to parse ModelServing JSON: {e}"))?;

    let roles = ms["spec"]["template"]["roles"]
        .as_array()
        .ok_or("ModelServing roles is not an array")?;

    let role = roles
        .iter()
        .find(|r| r["name"].as_str() == Some(role_name))
        .ok_or(format!("Role '{role_name}' not found in ModelServing"))?;

    role["replicas"]
        .as_u64()
        .ok_or(format!("Role '{role_name}' replicas is not a number"))
}

// =============================================================================
// Orchestrators
// =============================================================================

/// Run LatticeService CRD update integration tests.
pub async fn run_service_update_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[Updates] Running LatticeService update tests on {kubeconfig}");

    let harness = TestHarness::new("Service Updates");
    tokio::join!(
        harness.run("Ready spec update", || test_ready_spec_update(kubeconfig)),
        harness.run("Failed recovery", || test_failed_spec_recovery(kubeconfig)),
        harness.run("Failed observed_generation", || {
            test_failed_sets_observed_generation(kubeconfig)
        }),
    );

    harness.finish()
}

/// Run LatticeModel CRD update integration tests.
pub async fn run_model_update_tests(kubeconfig: &str) -> Result<(), String> {
    run_model_update_tests_in(kubeconfig, NS_MODEL_SPEC_UPDATE, NS_MODEL_LOADING_GAP).await
}

/// Run LatticeModel CRD update integration tests with explicit namespaces.
/// Callers must provide distinct namespaces to avoid collisions when running
/// concurrently with other tests that use the default namespaces.
pub async fn run_model_update_tests_in(
    kubeconfig: &str,
    ns_spec_update: &str,
    ns_loading_gap: &str,
) -> Result<(), String> {
    info!("[Updates] Running LatticeModel update tests on {kubeconfig}");

    // Model tests run sequentially: test 5 needs Loading phase which is brief,
    // and we can't have two models with the same name in different namespaces
    // competing for CRD discovery.
    let harness = TestHarness::new("Model Updates");
    harness
        .run("Model Serving spec update", || {
            test_model_serving_spec_update(kubeconfig, ns_spec_update)
        })
        .await;
    harness
        .run("Model Loading detects spec change", || {
            test_model_loading_detects_spec_change(kubeconfig, ns_loading_gap)
        })
        .await;

    harness.finish()
}

/// Run all CRD update integration tests (Service + Model).
pub async fn run_update_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[Updates] Running CRD update integration tests on {kubeconfig}");

    setup_regcreds_infrastructure(kubeconfig).await?;

    run_service_update_tests(kubeconfig).await?;
    run_model_update_tests(kubeconfig).await?;

    info!("[Updates] All CRD update integration tests passed!");
    Ok(())
}

// =============================================================================
// Standalone Tests
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_updates_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_update_tests(&resolved.kubeconfig).await.unwrap();
}

#[tokio::test]
#[ignore]
async fn test_model_updates_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    setup_regcreds_infrastructure(&resolved.kubeconfig)
        .await
        .unwrap();
    // Use distinct namespaces to avoid collisions with test_updates_standalone
    // which runs concurrently and uses update-t4/update-t5.
    run_model_update_tests_in(&resolved.kubeconfig, "model-update-t4", "model-update-t5")
        .await
        .unwrap();
}
