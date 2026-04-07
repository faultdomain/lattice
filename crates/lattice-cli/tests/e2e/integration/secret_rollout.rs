//! Secret rollout integration tests
//!
//! Verifies that pods roll when ESO-managed secret content changes, and do NOT
//! roll when the content is re-synced identically (content-addressable hashing).
//!
//! The controller hashes the `.data` field of all K8s Secrets labeled
//! `lattice.dev/service={name}`. When the hash changes, the inputs hash changes,
//! the config hash annotation on the Deployment pod template changes, and K8s
//! triggers a rolling update.
//!
//! # Running
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_secret_rollout_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use kube::Api;
use lattice_common::crd::LatticeService;
use lattice_common::LOCAL_WEBHOOK_STORE_NAME;
use tracing::info;

use super::super::helpers::{
    apply_cedar_secret_policy_for_service, apply_run_as_root_override_policy,
    client_from_kubeconfig, create_service_with_secrets, create_with_retry,
    delete_cedar_policies_by_label, delete_namespace, ensure_fresh_namespace, run_kubectl,
    seed_local_secret, setup_regcreds_infrastructure, wait_for_condition, wait_for_service_phase,
    with_diagnostics, with_run_as_root, DiagnosticContext, DEFAULT_TIMEOUT, POLL_INTERVAL,
};

const TEST_NAMESPACE: &str = "secret-rollout-test";

/// Run secret rollout integration tests.
///
/// Deploys a service with an ESO-managed secret, verifies pods roll on secret
/// change, and verifies pods do NOT roll on identical re-sync.
pub async fn run_secret_rollout_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[SecretRollout] Running secret rollout integration tests...");

    let diag = DiagnosticContext::new(kubeconfig, TEST_NAMESPACE);
    with_diagnostics(&diag, "SecretRollout", || async {
        // Seed initial secret
        let mut initial_data = std::collections::BTreeMap::new();
        initial_data.insert("vpn-user".to_string(), "alice".to_string());
        initial_data.insert("vpn-pass".to_string(), "original-password".to_string());
        seed_local_secret(kubeconfig, "local-rollout-vpn-creds", &initial_data).await?;

        // Cedar: permit this namespace to access the secret
        apply_cedar_secret_policy_for_service(
            kubeconfig,
            "permit-rollout-secrets",
            "secret-rollout",
            TEST_NAMESPACE,
            &["local-rollout-vpn-creds"],
        )
        .await?;

        apply_run_as_root_override_policy(kubeconfig, TEST_NAMESPACE, "rollout-svc").await?;

        async {
            ensure_fresh_namespace(kubeconfig, TEST_NAMESPACE).await?;

            // Deploy a service with the ESO secret
            let service = with_run_as_root(create_service_with_secrets(
                "rollout-svc",
                TEST_NAMESPACE,
                vec![(
                    "vpn-creds",
                    "local-rollout-vpn-creds",
                    LOCAL_WEBHOOK_STORE_NAME,
                    Some(vec!["vpn-user", "vpn-pass"]),
                )],
            ));

            let client = client_from_kubeconfig(kubeconfig).await?;
            let api: Api<LatticeService> = Api::namespaced(client, TEST_NAMESPACE);
            create_with_retry(&api, &service, "rollout-svc").await?;

            wait_for_service_phase(
                kubeconfig,
                TEST_NAMESPACE,
                "rollout-svc",
                "Ready",
                None,
                DEFAULT_TIMEOUT,
            )
            .await?;

            // Wait for ESO to sync the secret and the deployment to be ready
            wait_for_synced_secret(kubeconfig, TEST_NAMESPACE, "rollout-svc-vpn-creds").await?;
            wait_for_deployment_ready(kubeconfig, TEST_NAMESPACE, "rollout-svc").await?;

            // Capture initial pod UIDs
            let initial_pods = get_pod_uids(kubeconfig, TEST_NAMESPACE, "rollout-svc").await?;
            assert!(!initial_pods.is_empty(), "Service should have running pods");
            info!("[SecretRollout] Initial pods: {:?}", initial_pods);

            // Capture initial config-hash annotation
            let initial_hash =
                get_config_hash_annotation(kubeconfig, TEST_NAMESPACE, "rollout-svc").await?;
            info!("[SecretRollout] Initial config-hash: {}", initial_hash);

            // ── Test 1: Changing secret content triggers rollout ──
            info!("[SecretRollout] Mutating secret content...");
            let mut rotated_data = std::collections::BTreeMap::new();
            rotated_data.insert("vpn-user".to_string(), "alice".to_string());
            rotated_data.insert("vpn-pass".to_string(), "rotated-password-new".to_string());
            seed_local_secret(kubeconfig, "local-rollout-vpn-creds", &rotated_data).await?;

            // Force ESO to re-sync immediately (default refreshInterval is 1h)
            force_eso_resync(kubeconfig, TEST_NAMESPACE, "rollout-svc-vpn-creds").await?;

            // Wait for ESO to re-sync the K8s Secret with new content
            wait_for_secret_content(
                kubeconfig,
                TEST_NAMESPACE,
                "rollout-svc-vpn-creds",
                "vpn-pass",
                "rotated-password-new",
            )
            .await?;

            // Wait for the config-hash annotation to change (controller detected the rotation)
            info!("[SecretRollout] Waiting for config-hash to change...");
            let new_hash = wait_for_condition(
                "config-hash annotation to change after secret rotation",
                DEFAULT_TIMEOUT,
                POLL_INTERVAL,
                || {
                    let kc = kubeconfig.to_string();
                    let prev = initial_hash.clone();
                    async move {
                        let hash = get_config_hash_annotation(&kc, TEST_NAMESPACE, "rollout-svc")
                            .await
                            .map_err(|e| format!("get config-hash: {e}"))?;
                        if hash != prev {
                            Ok(Some(hash))
                        } else {
                            Ok(None)
                        }
                    }
                },
            )
            .await?;

            info!(
                "[SecretRollout] Config-hash changed: {} -> {}",
                initial_hash, new_hash
            );

            // Wait for new pods to come up (rollout in progress)
            info!("[SecretRollout] Waiting for pods to roll...");
            wait_for_new_pods(kubeconfig, TEST_NAMESPACE, "rollout-svc", &initial_pods).await?;

            // Wait for the rollout to fully complete before capturing baseline for Test 2
            wait_for_deployment_ready(kubeconfig, TEST_NAMESPACE, "rollout-svc").await?;

            info!("[SecretRollout] Test 1 PASSED: Secret rotation triggered pod rollout");

            // ── Test 2: Re-syncing same content does NOT trigger rollout ──
            info!(
                "[SecretRollout] Re-applying same secret content (should not trigger rollout)..."
            );
            let stable_hash =
                get_config_hash_annotation(kubeconfig, TEST_NAMESPACE, "rollout-svc").await?;
            let stable_pods = get_pod_uids(kubeconfig, TEST_NAMESPACE, "rollout-svc").await?;

            // Re-seed with identical content
            seed_local_secret(kubeconfig, "local-rollout-vpn-creds", &rotated_data).await?;

            // Force ESO to re-sync so the controller sees the (identical) secret data
            force_eso_resync(kubeconfig, TEST_NAMESPACE, "rollout-svc-vpn-creds").await?;

            // Patch a no-op annotation to bump .metadata.generation, forcing a reconcile
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string();
            run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "annotate",
                "latticeservice",
                "rollout-svc",
                "-n",
                TEST_NAMESPACE,
                &format!("lattice.dev/test-touch={}", timestamp),
                "--overwrite",
            ])
            .await?;

            // Read the current generation after the annotation patch
            let generation = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "get",
                "latticeservice",
                "rollout-svc",
                "-n",
                TEST_NAMESPACE,
                "-o",
                "jsonpath={.metadata.generation}",
            ])
            .await?;
            let generation: i64 = generation
                .trim()
                .parse()
                .map_err(|e| format!("parse generation: {e}"))?;

            info!(
                "[SecretRollout] Patched annotation, generation={}. Waiting for controller to reconcile...",
                generation
            );

            // Wait for observedGeneration >= generation, proving the controller processed this version
            let kc_owned = kubeconfig.to_string();
            let gen = generation;
            wait_for_condition(
                "observedGeneration to catch up after annotation patch",
                DEFAULT_TIMEOUT,
                POLL_INTERVAL,
                move || {
                    let kc = kc_owned.clone();
                    async move {
                        let observed = run_kubectl(&[
                            "--kubeconfig",
                            &kc,
                            "get",
                            "latticeservice",
                            "rollout-svc",
                            "-n",
                            TEST_NAMESPACE,
                            "-o",
                            "jsonpath={.status.observedGeneration}",
                        ])
                        .await
                        .map_err(|e| format!("get observedGeneration: {e}"))?;
                        let observed: i64 = observed
                            .trim()
                            .parse()
                            .unwrap_or(0);
                        Ok(observed >= gen)
                    }
                },
            )
            .await?;

            info!("[SecretRollout] Controller reconciled. Verifying no spurious rollout...");

            let hash_after =
                get_config_hash_annotation(kubeconfig, TEST_NAMESPACE, "rollout-svc").await?;
            assert_eq!(
                stable_hash, hash_after,
                "Config-hash should NOT change when secret content is identical"
            );

            let pods_after = get_pod_uids(kubeconfig, TEST_NAMESPACE, "rollout-svc").await?;
            assert_eq!(
                stable_pods, pods_after,
                "Pods should NOT roll when secret content is identical (content-addressable)"
            );

            info!("[SecretRollout] Test 2 PASSED: Identical re-sync did NOT trigger rollout");

            Ok::<(), String>(())
        }
        .await?;

        delete_namespace(kubeconfig, TEST_NAMESPACE).await;
        delete_cedar_policies_by_label(kubeconfig, "lattice.dev/test=secret-rollout").await;

        info!("[SecretRollout] All secret rollout tests passed!");
        Ok(())
    })
    .await
}

// =============================================================================
// Helpers
// =============================================================================

/// Get the `lattice.dev/config-hash` annotation from a Deployment's pod template.
async fn get_config_hash_annotation(
    kubeconfig: &str,
    namespace: &str,
    name: &str,
) -> Result<String, String> {
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "deployment",
        name,
        "-n",
        namespace,
        "-o",
        "jsonpath={.spec.template.metadata.annotations.lattice\\.dev/config-hash}",
    ])
    .await?;
    let hash = output.trim().to_string();
    if hash.is_empty() {
        return Err(format!(
            "Deployment {}/{} has no lattice.dev/config-hash annotation",
            namespace, name
        ));
    }
    Ok(hash)
}

/// Get UIDs of all running pods matching a service's label selector.
async fn get_pod_uids(
    kubeconfig: &str,
    namespace: &str,
    service_name: &str,
) -> Result<Vec<String>, String> {
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pods",
        "-n",
        namespace,
        "-l",
        &format!("app.kubernetes.io/name={}", service_name),
        "--field-selector=status.phase=Running",
        "-o",
        "jsonpath={.items[*].metadata.uid}",
    ])
    .await?;
    let mut uids: Vec<String> = output
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    uids.sort();
    Ok(uids)
}

/// Wait until all running pods are different from the given initial set.
async fn wait_for_new_pods(
    kubeconfig: &str,
    namespace: &str,
    service_name: &str,
    initial_uids: &[String],
) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let ns = namespace.to_string();
    let svc = service_name.to_string();
    let old = initial_uids.to_vec();

    wait_for_condition(
        "new pods after rollout",
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            let ns = ns.clone();
            let svc = svc.clone();
            let old = old.clone();
            async move {
                let current = get_pod_uids(&kc, &ns, &svc).await?;
                if current.is_empty() {
                    return Ok(false);
                }
                // All current pods must be different from the initial set
                let all_new = current.iter().all(|uid| !old.contains(uid));
                if all_new {
                    info!("[SecretRollout] New pods detected: {:?}", current);
                }
                Ok(all_new)
            }
        },
    )
    .await
}

/// Force ESO to re-sync an ExternalSecret by annotating it with the reconcile trigger.
///
/// ESO watches for `force-sync` annotation changes and immediately re-syncs.
/// Without this, ESO only re-syncs on its `refreshInterval` (default 1h).
async fn force_eso_resync(
    kubeconfig: &str,
    namespace: &str,
    external_secret_name: &str,
) -> Result<(), String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string();

    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "annotate",
        "externalsecret",
        external_secret_name,
        "-n",
        namespace,
        &format!("force-sync={}", timestamp),
        "--overwrite",
    ])
    .await?;

    info!(
        "[SecretRollout] Triggered ESO re-sync for {}/{}",
        namespace, external_secret_name
    );
    Ok(())
}

/// Wait for an ESO-synced K8s Secret to exist.
async fn wait_for_synced_secret(
    kubeconfig: &str,
    namespace: &str,
    secret_name: &str,
) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let ns = namespace.to_string();
    let name = secret_name.to_string();

    wait_for_condition(
        &format!("Secret {}/{} to be synced by ESO", namespace, secret_name),
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            let ns = ns.clone();
            let name = name.clone();
            async move {
                let result = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "secret",
                    &name,
                    "-n",
                    &ns,
                    "-o",
                    "name",
                ])
                .await;
                Ok(result.is_ok())
            }
        },
    )
    .await
}

/// Wait for a specific key in a K8s Secret to have the expected value.
async fn wait_for_secret_content(
    kubeconfig: &str,
    namespace: &str,
    secret_name: &str,
    key: &str,
    expected_value: &str,
) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let ns = namespace.to_string();
    let name = secret_name.to_string();
    let k = key.to_string();
    let expected = expected_value.to_string();

    wait_for_condition(
        &format!(
            "Secret {}/{} key '{}' to equal '{}'",
            namespace, secret_name, key, expected_value
        ),
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            let ns = ns.clone();
            let name = name.clone();
            let k = k.clone();
            let expected = expected.clone();
            async move {
                let jsonpath = format!("jsonpath={{.data.{}}}", k);
                let result = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "secret",
                    &name,
                    "-n",
                    &ns,
                    "-o",
                    &jsonpath,
                ])
                .await;

                match result {
                    Ok(b64) => {
                        // K8s stores secret data as base64
                        let decoded = base64_decode(b64.trim());
                        Ok(decoded.as_deref() == Some(expected.as_str()))
                    }
                    Err(_) => Ok(false),
                }
            }
        },
    )
    .await
}

/// Wait for a Deployment to have all replicas ready.
async fn wait_for_deployment_ready(
    kubeconfig: &str,
    namespace: &str,
    name: &str,
) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let ns = namespace.to_string();
    let deploy_name = name.to_string();

    wait_for_condition(
        &format!("Deployment {}/{} to be ready", namespace, name),
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            let ns = ns.clone();
            let deploy_name = deploy_name.clone();
            async move {
                let result = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "rollout",
                    "status",
                    &format!("deployment/{}", deploy_name),
                    "-n",
                    &ns,
                    "--timeout=5s",
                ])
                .await;
                Ok(result.is_ok())
            }
        },
    )
    .await
}

/// Decode a base64-encoded string to a UTF-8 string.
fn base64_decode(input: &str) -> Option<String> {
    use std::process::Command;
    let output = Command::new("base64")
        .args(["--decode"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(input.as_bytes());
            }
            child.wait_with_output().ok()
        })?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}

// =============================================================================
// Standalone Tests (run with --ignored)
// =============================================================================

/// Standalone test — run secret rollout tests on existing cluster
#[tokio::test]
#[ignore]
async fn test_secret_rollout_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    setup_regcreds_infrastructure(&resolved.kubeconfig)
        .await
        .unwrap();
    run_secret_rollout_tests(&resolved.kubeconfig)
        .await
        .unwrap();
}
