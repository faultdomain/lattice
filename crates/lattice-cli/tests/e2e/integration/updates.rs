//! CRD update integration tests
//!
//! Verifies that controllers handle spec updates correctly:
//!
//! LatticeService:
//! - Ready → spec change → recompile → Ready
//! - Failed → spec fix → recover → Ready
//! - Failed (persistent) → no spec change → observed_generation set, no tight loop
//! - replicas 2→1 → PDB orphan cleanup (PodDisruptionBudget deleted)
//!
//! LatticeModel:
//! - Serving → spec change → recompile → Serving
//! - Loading → spec change → detect and recompile (not stamp stale generation)
//! - Role removal → orphan cleanup (removed role's MeshMember deleted)
//!
//! LatticeJob:
//! - Failed sets observed_generation (no tight loop, jobs are immutable)
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
    ensure_fresh_namespace, load_fixture_config, resolve_model_serving_name, run_kubectl,
    setup_regcreds_infrastructure, wait_for_condition, wait_for_resource_phase,
    wait_for_service_phase, TestHarness, BUSYBOX_IMAGE, DEFAULT_TIMEOUT,
};

// =============================================================================
// Constants
// =============================================================================

const NS_READY_UPDATE: &str = "update-t1";
const NS_FAILED_RECOVER: &str = "update-t2";
const NS_FAILED_STABLE: &str = "update-t3";
const NS_MODEL_SPEC_UPDATE: &str = "update-t4";
const NS_MODEL_LOADING_GAP: &str = "update-t5";
const NS_PDB_ORPHAN: &str = "update-t6";
const NS_MODEL_ROLE_ORPHAN: &str = "update-t7";
const NS_JOB_FAILED_STABLE: &str = "update-t8";
/// Separate namespace for `test_job_updates_standalone` so it doesn't collide
/// with `test_updates_standalone` when both run concurrently.
const NS_JOB_FAILED_STANDALONE: &str = "update-t8-sa";

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
        "merge",
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
        Duration::from_secs(300),
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
        DEFAULT_TIMEOUT,
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

    // Patch decode replicas from 1 → 2
    let patch_json = serde_json::json!({
        "spec": {
            "roles": {
                "decode": {
                    "replicas": 2
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
        "merge",
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
    if decode_replicas != 2 {
        return Err(format!(
            "ModelServing decode replicas should be 2 after update, got: {decode_replicas}"
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

    // Deploy from fixture (decode.replicas=1 in fixture)
    let yaml = load_model_fixture_for_namespace(namespace)?;
    apply_yaml_with_retry(kubeconfig, &yaml).await?;

    // Wait for Loading (compilation done, resources applied, waiting for readiness)
    wait_for_resource_phase(
        kubeconfig,
        "latticemodel",
        namespace,
        "llm-serving",
        "Loading",
        Duration::from_secs(300),
    )
    .await?;

    let gen_at_loading =
        get_model_observed_generation(kubeconfig, namespace, "llm-serving").await?;
    info!("[Updates] Model at Loading: observed_generation = {gen_at_loading}");

    // Patch decode replicas from 1 → 2 while still Loading
    // This bumps metadata.generation but the Loading phase won't notice (the gap)
    let patch_json = serde_json::json!({
        "spec": {
            "roles": {
                "decode": {
                    "replicas": 2
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
        "merge",
    )
    .await?;
    info!("[Updates] Patched decode replicas to 2 while Loading");

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

    // The critical check: does the ModelServing have 2 decode replicas (new spec)
    // or 1 (old spec, stale config)?
    let decode_replicas =
        get_model_serving_role_replicas(kubeconfig, namespace, "llm-serving", "decode").await?;

    if decode_replicas != 2 {
        return Err(format!(
            "ModelServing decode replicas = {decode_replicas}, expected 2. \
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
    build_service_with_replicas(name, namespace, 1)
}

// =============================================================================
// Helpers (Generic)
// =============================================================================

/// Patch any CRD resource via `kubectl patch`.
/// `patch_type` is one of: "merge", "json", "strategic".
async fn patch_resource(
    kubeconfig: &str,
    kind: &str,
    namespace: &str,
    name: &str,
    patch: &serde_json::Value,
    patch_type: &str,
) -> Result<(), String> {
    let patch_str =
        serde_json::to_string(patch).map_err(|e| format!("Failed to serialize patch: {e}"))?;
    let type_flag = format!("--type={patch_type}");

    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "patch",
        kind,
        name,
        "-n",
        namespace,
        &type_flag,
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
    let serving_name = resolve_model_serving_name(kubeconfig, namespace, model_name).await?;
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "modelservings.workload.serving.volcano.sh",
        &serving_name,
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
// Test 6: Service PDB orphan cleanup (replicas 2→1)
// =============================================================================

/// Deploy a service with replicas=2 (produces PDB), then update to replicas=1.
/// Verify the PodDisruptionBudget is deleted after the spec update.
async fn test_service_pdb_orphan_cleanup(kubeconfig: &str) -> Result<(), String> {
    info!("[Updates] Test 6: Service PDB orphan cleanup (replicas 2→1)");
    ensure_fresh_namespace(kubeconfig, NS_PDB_ORPHAN).await?;

    // Deploy a service with replicas=2 → produces PDB
    let svc = build_service_with_replicas("svc-pdb-test", NS_PDB_ORPHAN, 2);
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_PDB_ORPHAN,
        svc,
        "Ready",
        None,
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Verify PDB exists
    wait_for_resource_exists(kubeconfig, "pdb", NS_PDB_ORPHAN, "svc-pdb-test", true).await?;
    info!("[Updates] PDB exists with replicas=2 (expected)");

    let gen_before = get_observed_generation(kubeconfig, NS_PDB_ORPHAN, "svc-pdb-test").await?;

    // Patch replicas to 1 → PDB should be removed
    let patch_json = serde_json::json!({
        "spec": { "replicas": 1 }
    });
    patch_resource(
        kubeconfig,
        "latticeservice",
        NS_PDB_ORPHAN,
        "svc-pdb-test",
        &patch_json,
        "merge",
    )
    .await?;

    // Wait for the controller to reconcile with the new generation
    let gen_before_i64: i64 = gen_before.parse().unwrap_or(0);
    wait_for_generation_advance(kubeconfig, NS_PDB_ORPHAN, "svc-pdb-test", gen_before_i64).await?;

    // Verify still Ready
    wait_for_service_phase(
        kubeconfig,
        NS_PDB_ORPHAN,
        "svc-pdb-test",
        "Ready",
        None,
        Duration::from_secs(300),
    )
    .await?;

    // Verify PDB is gone
    wait_for_resource_exists(kubeconfig, "pdb", NS_PDB_ORPHAN, "svc-pdb-test", false).await?;
    info!("[Updates] PDB deleted after replicas=1 (expected)");

    delete_namespace(kubeconfig, NS_PDB_ORPHAN).await;
    info!("[Updates] Test 6 passed: PDB orphan cleanup works");
    Ok(())
}

// =============================================================================
// Test 7: Model role removal orphan cleanup
// =============================================================================

/// Deploy a model with two roles (prefill + decode), then remove prefill.
/// Verify the removed role's LatticeMeshMember is deleted.
async fn test_model_role_removal_orphan_cleanup(
    kubeconfig: &str,
    namespace: &str,
) -> Result<(), String> {
    info!("[Updates] Test 7: Model role removal orphan cleanup");
    ensure_fresh_namespace(kubeconfig, namespace).await?;

    // Deploy model fixture (has prefill + decode roles)
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

    // Verify MeshMembers for both roles exist
    wait_for_resource_exists(
        kubeconfig,
        "latticemeshmember",
        namespace,
        "llm-serving-prefill",
        true,
    )
    .await?;
    wait_for_resource_exists(
        kubeconfig,
        "latticemeshmember",
        namespace,
        "llm-serving-decode",
        true,
    )
    .await?;
    info!("[Updates] Both role MeshMembers exist (expected)");

    let gen_before = get_model_observed_generation(kubeconfig, namespace, "llm-serving").await?;

    // Remove the prefill role, keeping only decode.
    // Must use JSON patch (not merge patch) because merge patch can't remove map keys.
    let patch_json = serde_json::json!([
        {
            "op": "remove",
            "path": "/spec/roles/prefill"
        }
    ]);
    patch_resource(
        kubeconfig,
        "latticemodel",
        namespace,
        "llm-serving",
        &patch_json,
        "json",
    )
    .await?;
    info!("[Updates] Patched model to remove prefill role");

    // Verify removed role's MeshMember is cleaned up.
    // The controller runs cleanup_removed_roles before re-applying the
    // ModelServing, so the MeshMember deletion is the earliest observable
    // side effect of the spec change.
    wait_for_resource_exists(
        kubeconfig,
        "latticemeshmember",
        namespace,
        "llm-serving-prefill",
        false,
    )
    .await?;
    info!("[Updates] Prefill MeshMember deleted (expected)");

    // Wait for generation to advance (ModelServing is deleted and recreated
    // because the gang policy's minRoleReplicas key set changed)
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

    // Verify remaining role's MeshMember still exists
    wait_for_resource_exists(
        kubeconfig,
        "latticemeshmember",
        namespace,
        "llm-serving-decode",
        true,
    )
    .await?;
    info!("[Updates] Decode MeshMember still exists (expected)");

    delete_namespace(kubeconfig, namespace).await;
    info!("[Updates] Test 7 passed: Model role removal orphan cleanup works");
    Ok(())
}

// =============================================================================
// Helpers (Resource existence)
// =============================================================================

/// Wait for a resource to exist or not exist.
/// If `should_exist` is true, waits until the resource is found.
/// If `should_exist` is false, waits until the resource returns 404.
async fn wait_for_resource_exists(
    kubeconfig: &str,
    kind: &str,
    namespace: &str,
    name: &str,
    should_exist: bool,
) -> Result<(), String> {
    let desc = if should_exist {
        format!("{kind} {namespace}/{name} to exist")
    } else {
        format!("{kind} {namespace}/{name} to be deleted")
    };

    let kc = kubeconfig.to_string();
    let kind = kind.to_string();
    let ns = namespace.to_string();
    let rname = name.to_string();

    wait_for_condition(
        &desc,
        Duration::from_secs(300),
        Duration::from_secs(3),
        || {
            let kc = kc.clone();
            let kind = kind.clone();
            let ns = ns.clone();
            let rname = rname.clone();
            async move {
                let result = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    &kind,
                    &rname,
                    "-n",
                    &ns,
                    "-o",
                    "name",
                ])
                .await;

                match result {
                    Ok(_) => Ok(should_exist), // resource exists
                    Err(e) if e.contains("NotFound") || e.contains("not found") => {
                        Ok(!should_exist) // resource doesn't exist
                    }
                    Err(e) => Err(format!("error checking {kind} {ns}/{rname}: {e}")),
                }
            }
        },
    )
    .await
}

// =============================================================================
// Helpers (Service with replicas)
// =============================================================================

/// Build a LatticeService with a specific replica count.
fn build_service_with_replicas(
    name: &str,
    namespace: &str,
    replicas: u32,
) -> lattice_common::crd::LatticeService {
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
                run_as_user: Some(65534),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    let mut svc =
        super::super::helpers::build_busybox_service(name, namespace, containers, BTreeMap::new());
    svc.spec.replicas = replicas;
    svc
}

// =============================================================================
// Test 8: LatticeJob Failed sets observed_generation (no tight loop)
// =============================================================================

/// Deploy a job that fails permanently. Verify that observed_generation is set
/// on the Failed status so the controller doesn't tight-loop retrying.
async fn test_job_failed_sets_observed_generation(
    kubeconfig: &str,
    namespace: &str,
) -> Result<(), String> {
    info!("[Updates] Test 8: LatticeJob Failed sets observed_generation");
    ensure_fresh_namespace(kubeconfig, namespace).await?;

    // Deploy a job that fails permanently
    let job = build_simple_job("job-stable-fail", namespace, &["/bin/sh", "-c", "exit 1"]);
    let yaml = serde_json::to_string(&job).map_err(|e| format!("Failed to serialize job: {e}"))?;
    apply_yaml_with_retry(kubeconfig, &yaml).await?;

    // Wait for Failed
    wait_for_resource_phase(
        kubeconfig,
        "latticejob",
        namespace,
        "job-stable-fail",
        "Failed",
        Duration::from_secs(300),
    )
    .await?;

    // Give the controller time to stabilize
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Verify observed_generation is set (not empty/missing)
    let observed =
        get_resource_observed_generation(kubeconfig, "latticejob", namespace, "job-stable-fail")
            .await?;
    if observed.is_empty() {
        return Err(
            "observed_generation is empty on Failed job — controller will tight-loop \
             retrying every 30s even when nothing changed. \
             Failed status must include observed_generation."
                .to_string(),
        );
    }

    let gen =
        get_resource_generation(kubeconfig, "latticejob", namespace, "job-stable-fail").await?;
    if observed != gen {
        return Err(format!(
            "observed_generation ({observed}) != metadata.generation ({gen}) — \
             controller hasn't acknowledged the current spec"
        ));
    }

    info!("[Updates] observed_generation = {observed} (matches generation = {gen})");

    delete_namespace(kubeconfig, namespace).await;
    info!("[Updates] Test 8 passed: Failed job has observed_generation set");
    Ok(())
}

// =============================================================================
// Helpers (Job)
// =============================================================================

/// Build a minimal LatticeJob with a single "worker" task.
fn build_simple_job(
    name: &str,
    namespace: &str,
    command: &[&str],
) -> lattice_common::crd::LatticeJob {
    use lattice_common::crd::{
        ContainerSpec, JobTaskSpec, LatticeJobSpec, ResourceQuantity, ResourceRequirements,
        RestartPolicy,
    };
    use std::collections::BTreeMap;

    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: BUSYBOX_IMAGE.to_string(),
            command: Some(command.iter().map(|s| s.to_string()).collect()),
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
                run_as_user: Some(65534),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    let mut tasks = BTreeMap::new();
    tasks.insert(
        "worker".to_string(),
        JobTaskSpec {
            replicas: 1,
            workload: lattice_common::crd::WorkloadSpec {
                containers,
                ..Default::default()
            },
            runtime: lattice_common::crd::RuntimeSpec::default(),
            restart_policy: Some(RestartPolicy::Never),
        },
    );

    let spec = LatticeJobSpec {
        max_retry: Some(0),
        tasks,
        ..Default::default()
    };
    let mut job = lattice_common::crd::LatticeJob::new(name, spec);
    job.metadata.namespace = Some(namespace.to_string());
    job
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
        harness.run("PDB orphan cleanup", || {
            test_service_pdb_orphan_cleanup(kubeconfig)
        }),
    );

    harness.finish()
}

/// Run LatticeModel CRD update integration tests.
pub async fn run_model_update_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[Updates] Running LatticeModel update tests on {kubeconfig}");

    // Each test uses its own namespace so they can run concurrently
    let harness = TestHarness::new("Model Updates");
    tokio::join!(
        harness.run("Model Serving spec update", || {
            test_model_serving_spec_update(kubeconfig, NS_MODEL_SPEC_UPDATE)
        }),
        harness.run("Model Loading detects spec change", || {
            test_model_loading_detects_spec_change(kubeconfig, NS_MODEL_LOADING_GAP)
        }),
        harness.run("Model role removal orphan cleanup", || {
            test_model_role_removal_orphan_cleanup(kubeconfig, NS_MODEL_ROLE_ORPHAN)
        }),
    );

    harness.finish()
}

/// Run LatticeJob CRD update integration tests.
pub async fn run_job_update_tests(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    info!("[Updates] Running LatticeJob update tests on {kubeconfig}");

    let harness = TestHarness::new("Job Updates");
    harness
        .run("Job Failed observed_generation", || {
            test_job_failed_sets_observed_generation(kubeconfig, namespace)
        })
        .await;

    harness.finish()
}

/// Run all CRD update integration tests (Service + Model + Job).
pub async fn run_update_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[Updates] Running CRD update integration tests on {kubeconfig}");

    setup_regcreds_infrastructure(kubeconfig).await?;

    // All suites use independent namespaces, run concurrently
    let (svc_result, model_result, job_result) = tokio::join!(
        run_service_update_tests(kubeconfig),
        run_model_update_tests(kubeconfig),
        run_job_update_tests(kubeconfig, NS_JOB_FAILED_STABLE),
    );
    svc_result?;
    model_result?;
    job_result?;

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
async fn test_job_updates_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    setup_regcreds_infrastructure(&resolved.kubeconfig)
        .await
        .unwrap();
    run_job_update_tests(&resolved.kubeconfig, NS_JOB_FAILED_STANDALONE)
        .await
        .unwrap();
}
