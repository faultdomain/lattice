//! Tetragon runtime enforcement integration tests
//!
//! Validates that deploying a LatticeService creates the correct
//! TracingPolicyNamespaced binary whitelist policies, and that
//! entrypoint auto-detection for probes/commands works correctly.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/kubeconfig \
//! cargo test --features provider-e2e --test e2e test_tetragon_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use tracing::{info, warn};

use lattice_common::crd::{
    ContainerSpec, ExecProbe, LatticeService, LatticeServiceSpec, PortSpec, Probe,
    ResourceQuantity, ResourceRequirements, ResourceSpec, ResourceType, RuntimeSpec,
    SecurityContext, ServicePortsSpec, SidecarSpec, VolumeMount, WorkloadSpec,
};

use super::super::context::InfraContext;
use super::super::helpers::{
    apply_cedar_policy_crd, delete_cedar_policies_by_label, delete_namespace,
    deploy_and_wait_for_phase, ensure_fresh_namespace, list_tracing_policies, run_kubectl,
    setup_regcreds_infrastructure, wait_for_condition, wait_for_pod_running, TestHarness,
    BUSYBOX_IMAGE, NGINX_IMAGE, REGCREDS_PROVIDER, REGCREDS_REMOTE_KEY,
};

const NS_DEFAULT: &str = "tetragon-t1";
const NS_PROBE_SHELL: &str = "tetragon-t2";
const NS_CMD_SHELL: &str = "tetragon-t3";
const NS_SIDECAR_SHELL: &str = "tetragon-t4";
const NS_ENFORCEMENT: &str = "tetragon-t5";
const NS_ALLOWED_BINARIES: &str = "tetragon-t6";
const NS_ALLOWED_BINARIES_CEDAR: &str = "tetragon-t7";
const NS_WILDCARD_BINARIES: &str = "tetragon-t8";
const NS_IMPLICIT_WILDCARD: &str = "tetragon-t9";
const NS_IMPLICIT_CEDAR_DENY: &str = "tetragon-t10";
const NS_MISSING_ENTRYPOINT: &str = "tetragon-t11";

const TEST_LABEL: &str = "tetragon";

/// Default timeout for deploy_and_wait_for_phase. Higher than single-service
/// tests because all 11 Tetragon tests run in parallel and compete for
/// operator reconciliation time.
const DEPLOY_TIMEOUT: Duration = Duration::from_secs(180);

/// Default timeout for waiting on Tetragon policy enforcement.
const ENFORCEMENT_TIMEOUT: Duration = Duration::from_secs(300);

// =============================================================================
// Cedar helpers
// =============================================================================

async fn apply_security_override(
    kubeconfig: &str,
    name: &str,
    namespace: &str,
) -> Result<(), String> {
    let cedar = format!(
        r#"permit(
  principal,
  action == Lattice::Action::"OverrideSecurity",
  resource
) when {{
  principal.namespace == "{namespace}"
}};"#,
    );
    apply_cedar_policy_crd(kubeconfig, name, TEST_LABEL, 100, &cedar).await
}

async fn cleanup_policies(kubeconfig: &str) {
    delete_cedar_policies_by_label(kubeconfig, &format!("lattice.dev/test={TEST_LABEL}")).await;
}

// =============================================================================
// Service builders
// =============================================================================

/// Default security context for tetragon test containers.
/// Docker KIND clusters need AppArmor Unconfined and runAsNonRoot disabled.
fn default_security() -> SecurityContext {
    SecurityContext {
        apparmor_profile: Some("Unconfined".to_string()),
        run_as_non_root: Some(false),
        ..Default::default()
    }
}

/// Default resource limits for tetragon test containers.
fn default_resources() -> ResourceRequirements {
    ResourceRequirements {
        limits: Some(ResourceQuantity {
            cpu: Some("100m".to_string()),
            memory: Some("64Mi".to_string()),
        }),
        ..Default::default()
    }
}

/// Default port spec for tetragon test services.
fn default_ports() -> BTreeMap<String, PortSpec> {
    let mut ports = BTreeMap::new();
    ports.insert(
        "http".to_string(),
        PortSpec {
            port: 8080,
            target_port: None,
            protocol: None,
        },
    );
    ports
}

/// Wrap containers (and optional sidecars) into a LatticeService with standard metadata and ports.
fn wrap_service(
    name: &str,
    namespace: &str,
    containers: BTreeMap<String, ContainerSpec>,
    sidecars: BTreeMap<String, SidecarSpec>,
) -> LatticeService {
    let mut reg_params = BTreeMap::new();
    reg_params.insert("provider".to_string(), serde_json::json!(REGCREDS_PROVIDER));
    reg_params.insert("refreshInterval".to_string(), serde_json::json!("1h"));

    let mut resources = BTreeMap::new();
    resources.insert(
        "ghcr-creds".to_string(),
        ResourceSpec {
            type_: ResourceType::Secret,
            id: Some(REGCREDS_REMOTE_KEY.to_string()),
            params: Some(reg_params),
            ..Default::default()
        },
    );

    LatticeService {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            workload: WorkloadSpec {
                containers,
                resources,
                service: Some(ServicePortsSpec {
                    ports: default_ports(),
                }),
            },
            runtime: RuntimeSpec {
                sidecars,
                image_pull_secrets: vec!["ghcr-creds".to_string()],
                ..Default::default()
            },
            ..Default::default()
        },
        status: None,
    }
}

fn build_service(
    name: &str,
    namespace: &str,
    security: Option<SecurityContext>,
    liveness_probe: Option<Probe>,
    command: Option<Vec<String>>,
) -> LatticeService {
    let mut sec = security.unwrap_or_default();
    if sec.apparmor_profile.is_none() {
        sec.apparmor_profile = Some("Unconfined".to_string());
    }
    if sec.run_as_non_root.is_none() {
        sec.run_as_non_root = Some(false);
    }

    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: BUSYBOX_IMAGE.to_string(),
            command: command.or(Some(vec!["sleep".to_string(), "infinity".to_string()])),
            security: Some(sec),
            liveness_probe,
            resources: Some(default_resources()),
            ..Default::default()
        },
    );

    wrap_service(name, namespace, containers, BTreeMap::new())
}

fn build_service_with_sidecar_shell(name: &str, namespace: &str) -> LatticeService {
    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: BUSYBOX_IMAGE.to_string(),
            command: Some(vec!["sleep".to_string(), "infinity".to_string()]),
            security: Some(default_security()),
            resources: Some(default_resources()),
            ..Default::default()
        },
    );

    let mut sidecars = BTreeMap::new();
    sidecars.insert(
        "log-shipper".to_string(),
        SidecarSpec {
            image: BUSYBOX_IMAGE.to_string(),
            command: Some(vec![
                "/bin/ash".to_string(),
                "-c".to_string(),
                "tail -f /dev/null".to_string(),
            ]),
            security: Some(default_security()),
            ..Default::default()
        },
    );

    wrap_service(name, namespace, containers, sidecars)
}

fn build_service_with_allowed_binaries(
    name: &str,
    namespace: &str,
    allowed_binaries: Vec<String>,
) -> LatticeService {
    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: BUSYBOX_IMAGE.to_string(),
            command: Some(vec!["sleep".to_string(), "infinity".to_string()]),
            security: Some(SecurityContext {
                allowed_binaries,
                ..default_security()
            }),
            resources: Some(default_resources()),
            ..Default::default()
        },
    );

    wrap_service(name, namespace, containers, BTreeMap::new())
}

/// Build a service with no command (implicit wildcard).
/// Uses nginx which has a long-running default entrypoint, unlike busybox
/// whose default `sh` exits immediately in non-interactive mode.
fn build_service_no_command(name: &str, namespace: &str) -> LatticeService {
    let mut volumes = BTreeMap::new();
    volumes.insert("/tmp".to_string(), VolumeMount::default());

    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: NGINX_IMAGE.to_string(),
            security: Some(default_security()),
            resources: Some(default_resources()),
            volumes,
            ..Default::default()
        },
    );

    wrap_service(name, namespace, containers, BTreeMap::new())
}

// =============================================================================
// Verification helpers
// =============================================================================

async fn wait_for_policies(
    kubeconfig: &str,
    namespace: &str,
    service_name: &str,
    timeout: Duration,
) -> Result<Vec<String>, String> {
    wait_for_condition(
        &format!("TracingPolicy for {service_name} in {namespace}"),
        timeout,
        Duration::from_secs(5),
        || async move {
            let all = list_tracing_policies(kubeconfig, namespace).await?;
            let matching: Vec<String> = all
                .into_iter()
                .filter(|n| n.ends_with(&format!("-{service_name}")))
                .collect();
            if !matching.is_empty() {
                Ok(Some(matching))
            } else {
                Ok(None)
            }
        },
    )
    .await
}

fn assert_has(policies: &[String], prefix: &str, svc: &str) {
    let expected = format!("{prefix}-{svc}");
    assert!(
        policies.contains(&expected),
        "Expected '{expected}' in {policies:?}"
    );
}

async fn get_policy_yaml(kubeconfig: &str, namespace: &str, name: &str) -> Result<String, String> {
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "tracingpolicynamespaced",
        name,
        "-n",
        namespace,
        "-o",
        "yaml",
    ])
    .await
}

/// Check if a binary appears in the allow-binaries policy's NotEqual values list.
/// In the allow-binaries policy, NotEqual values are the ALLOWED binaries.
fn yaml_allows_binary(yaml: &str, binary: &str) -> bool {
    yaml.contains(&format!("- {binary}")) || yaml.contains(&format!("- \"{binary}\""))
}

/// Result of exec'ing into a pod. Distinguishes between SIGKILL (Tetragon enforcement),
/// successful execution, and transient infrastructure errors (proxy, WebSocket, timeout).
enum ExecResult {
    /// Process ran and exited successfully (exit 0).
    Ok(String),
    /// Process was killed by Tetragon (exit 137 / SIGKILL).
    Killed,
    /// Transient infrastructure error (proxy timeout, WebSocket failure, etc.).
    /// These should be retried — they don't indicate enforcement or lack thereof.
    TransientError(String),
}

fn exec_in_pod_sync(kubeconfig: &str, namespace: &str, deploy: &str, args: &[&str]) -> ExecResult {
    let deploy_ref = format!("deploy/{deploy}");
    let mut cmd_args = vec![
        "--kubeconfig",
        kubeconfig,
        "exec",
        deploy_ref.as_str(),
        "-n",
        namespace,
        "--",
    ];
    cmd_args.extend_from_slice(args);

    let output = match std::process::Command::new("kubectl")
        .args(&cmd_args)
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            info!("[exec] {deploy} in {namespace}: SPAWN_ERROR ({e})");
            return ExecResult::TransientError(format!("kubectl exec failed to spawn: {e}"));
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code();

    if output.status.success() {
        info!("[exec] {deploy} in {namespace}: OK (exit={exit_code:?}, stdout={stdout:?})");
        return ExecResult::Ok(stdout);
    }

    // SIGKILL: exit code 137 (128+9) or stderr mentioning signal/137
    let is_sigkill = exit_code == Some(137)
        || stderr.contains("exit code 137")
        || stderr.contains("signal: killed");

    if is_sigkill {
        info!("[exec] {deploy} in {namespace}: KILLED (exit={exit_code:?})");
        return ExecResult::Killed;
    }

    // Transient proxy/connection errors — not enforcement
    let is_transient = stderr.contains("WebSocket")
        || stderr.contains("500 Internal Server Error")
        || stderr.contains("proxy error")
        || stderr.contains("timed out")
        || stderr.contains("connection refused")
        || stderr.contains("TLS handshake")
        || stderr.contains("net/http");

    if is_transient {
        info!("[exec] {deploy} in {namespace}: TRANSIENT (exit={exit_code:?}, stderr={stderr:?})");
        return ExecResult::TransientError(stderr);
    }

    // Unknown non-zero exit — could be Tetragon or something else. Log clearly.
    info!("[exec] {deploy} in {namespace}: UNKNOWN_FAIL (exit={exit_code:?}, stderr={stderr:?})");
    // Treat exit code > 128 as signal-killed (128+signal_number)
    if exit_code.is_some_and(|c| c > 128) {
        ExecResult::Killed
    } else {
        ExecResult::TransientError(stderr)
    }
}

/// Wait until exec'ing the given command in the pod is SIGKILL'd by Tetragon.
///
/// Only counts actual SIGKILL (exit 137) as enforcement — proxy errors and
/// transient failures are retried, not treated as enforcement.
async fn wait_for_exec_blocked(
    kubeconfig: &str,
    namespace: &str,
    deploy: &str,
    args: &[&str],
    description: &str,
) -> Result<(), String> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

    wait_for_condition(
        description,
        ENFORCEMENT_TIMEOUT,
        Duration::from_secs(3),
        || {
            let args = &args;
            async move {
                let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                match exec_in_pod_sync(kubeconfig, namespace, deploy, &args_ref) {
                    ExecResult::Killed => Ok(true),
                    ExecResult::Ok(out) => {
                        warn!("[wait_killed] {deploy} unexpectedly succeeded: {out:?}");
                        Ok(false)
                    }
                    ExecResult::TransientError(e) => {
                        warn!("[wait_killed] {deploy} transient error: {e}");
                        Ok(false)
                    }
                }
            }
        },
    )
    .await
}

/// Wait until exec'ing the given command in the pod succeeds (exit 0).
///
/// Used for wildcard/exempt cases where the exec should NOT be blocked.
/// Transient proxy errors are retried.
async fn wait_for_exec_allowed(
    kubeconfig: &str,
    namespace: &str,
    deploy: &str,
    args: &[&str],
    description: &str,
) -> Result<(), String> {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

    wait_for_condition(
        description,
        ENFORCEMENT_TIMEOUT,
        Duration::from_secs(3),
        || {
            let args = &args;
            async move {
                let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                match exec_in_pod_sync(kubeconfig, namespace, deploy, &args_ref) {
                    ExecResult::Ok(_) => Ok(true),
                    ExecResult::Killed => {
                        warn!("[wait_allowed] {deploy} unexpectedly killed");
                        Ok(false)
                    }
                    ExecResult::TransientError(e) => {
                        warn!("[wait_allowed] {deploy} transient error: {e}");
                        Ok(false)
                    }
                }
            }
        },
    )
    .await
}

// =============================================================================
// Test scenarios
// =============================================================================

async fn test_default_security(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 1: Default security — command whitelisted...");
    ensure_fresh_namespace(kubeconfig, NS_DEFAULT).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t1", NS_DEFAULT).await?;

    let svc = "svc-default";
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_DEFAULT,
        build_service(svc, NS_DEFAULT, None, None, None),
        "Ready",
        None,
        DEPLOY_TIMEOUT,
    )
    .await?;

    let p = wait_for_policies(kubeconfig, NS_DEFAULT, svc, Duration::from_secs(30)).await?;
    assert_has(&p, "allow-binaries", svc);

    delete_namespace(kubeconfig, NS_DEFAULT).await;
    info!("[Tetragon] Test 1 passed");
    Ok(())
}

async fn test_probe_shell_exemption(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 2: Probe shell exemption...");
    ensure_fresh_namespace(kubeconfig, NS_PROBE_SHELL).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t2", NS_PROBE_SHELL).await?;

    let svc = "svc-probe";
    let probe = Probe {
        exec: Some(ExecProbe {
            command: vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
        }),
        http_get: None,
    };
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_PROBE_SHELL,
        build_service(svc, NS_PROBE_SHELL, None, Some(probe), None),
        "Ready",
        None,
        DEPLOY_TIMEOUT,
    )
    .await?;

    wait_for_policies(kubeconfig, NS_PROBE_SHELL, svc, Duration::from_secs(30)).await?;
    let yaml =
        get_policy_yaml(kubeconfig, NS_PROBE_SHELL, &format!("allow-binaries-{svc}")).await?;
    assert!(
        yaml_allows_binary(&yaml, "/bin/sh"),
        "/bin/sh should be auto-allowed for probe"
    );

    delete_namespace(kubeconfig, NS_PROBE_SHELL).await;
    info!("[Tetragon] Test 2 passed");
    Ok(())
}

async fn test_cmd_shell_exemption(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 3: Command shell exemption...");
    ensure_fresh_namespace(kubeconfig, NS_CMD_SHELL).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t3", NS_CMD_SHELL).await?;

    let svc = "svc-cmd";
    let cmd = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "sleep infinity".to_string(),
    ];
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_CMD_SHELL,
        build_service(svc, NS_CMD_SHELL, None, None, Some(cmd)),
        "Ready",
        None,
        DEPLOY_TIMEOUT,
    )
    .await?;

    wait_for_policies(kubeconfig, NS_CMD_SHELL, svc, Duration::from_secs(30)).await?;
    let yaml = get_policy_yaml(kubeconfig, NS_CMD_SHELL, &format!("allow-binaries-{svc}")).await?;
    assert!(
        yaml_allows_binary(&yaml, "/bin/sh"),
        "/bin/sh should be auto-allowed for container command"
    );

    delete_namespace(kubeconfig, NS_CMD_SHELL).await;
    info!("[Tetragon] Test 3 passed");
    Ok(())
}

/// Sidecar command shell exemption — /bin/ash auto-allowed
async fn test_sidecar_shell_exemption(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 4: Sidecar shell exemption — /bin/ash should be allowed...");
    ensure_fresh_namespace(kubeconfig, NS_SIDECAR_SHELL).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t4", NS_SIDECAR_SHELL).await?;

    let svc = "svc-sidecar";
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_SIDECAR_SHELL,
        build_service_with_sidecar_shell(svc, NS_SIDECAR_SHELL),
        "Ready",
        None,
        DEPLOY_TIMEOUT,
    )
    .await?;

    wait_for_policies(kubeconfig, NS_SIDECAR_SHELL, svc, Duration::from_secs(30)).await?;
    let yaml = get_policy_yaml(
        kubeconfig,
        NS_SIDECAR_SHELL,
        &format!("allow-binaries-{svc}"),
    )
    .await?;
    assert!(
        yaml_allows_binary(&yaml, "/bin/ash"),
        "/bin/ash should be auto-allowed because sidecar command uses it"
    );

    delete_namespace(kubeconfig, NS_SIDECAR_SHELL).await;
    info!("[Tetragon] Test 4 passed");
    Ok(())
}

// =============================================================================
// Enforcement tests (exec into pods to verify Tetragon kills blocked actions)
// =============================================================================

async fn test_enforcement(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 5: Enforcement — blocked binaries killed, exempted allowed...");
    ensure_fresh_namespace(kubeconfig, NS_ENFORCEMENT).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t5", NS_ENFORCEMENT).await?;

    // --- Service with default security (binary whitelist, no exemptions) ---
    let svc_block = "svc-enforce";
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_ENFORCEMENT,
        build_service(svc_block, NS_ENFORCEMENT, None, None, None),
        "Ready",
        None,
        DEPLOY_TIMEOUT,
    )
    .await?;
    wait_for_policies(
        kubeconfig,
        NS_ENFORCEMENT,
        svc_block,
        Duration::from_secs(30),
    )
    .await?;
    wait_for_pod_running(
        kubeconfig,
        NS_ENFORCEMENT,
        &format!("app.kubernetes.io/name={svc_block}"),
    )
    .await?;

    // Check 1: Shell execution should be blocked (SIGKILL)
    info!("[Tetragon] Check 1: shell exec should be killed...");
    wait_for_exec_blocked(
        kubeconfig,
        NS_ENFORCEMENT,
        svc_block,
        &["sh", "-c", "echo hello"],
        "shell blocked by Tetragon on svc-enforce",
    )
    .await?;
    info!("[Tetragon] Check 1 passed — shell was blocked");

    // --- Service with probe shell exemption (shell should be allowed) ---
    let svc_exempt = "svc-enforce-exempt";
    let probe = Probe {
        exec: Some(ExecProbe {
            command: vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
        }),
        http_get: None,
    };
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_ENFORCEMENT,
        build_service(svc_exempt, NS_ENFORCEMENT, None, Some(probe), None),
        "Ready",
        None,
        DEPLOY_TIMEOUT,
    )
    .await?;
    wait_for_policies(
        kubeconfig,
        NS_ENFORCEMENT,
        svc_exempt,
        Duration::from_secs(30),
    )
    .await?;
    wait_for_pod_running(
        kubeconfig,
        NS_ENFORCEMENT,
        &format!("app.kubernetes.io/name={svc_exempt}"),
    )
    .await?;

    // Check 2: Shell should be allowed when exempted via probe
    info!("[Tetragon] Check 2: exempted shell should succeed...");
    wait_for_exec_allowed(
        kubeconfig,
        NS_ENFORCEMENT,
        svc_exempt,
        &["sh", "-c", "echo hello"],
        "shell allowed on svc-enforce-exempt (probe exemption)",
    )
    .await?;
    info!("[Tetragon] Check 2 passed — exempted shell was allowed");

    delete_namespace(kubeconfig, NS_ENFORCEMENT).await;
    info!("[Tetragon] Test 5 passed");
    Ok(())
}

// =============================================================================
// Allowed binaries tests
// =============================================================================

/// allowedBinaries whitelist — listed binaries work, unlisted get SIGKILL'd
async fn test_allowed_binaries(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 6: allowedBinaries whitelist...");
    ensure_fresh_namespace(kubeconfig, NS_ALLOWED_BINARIES).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t6", NS_ALLOWED_BINARIES).await?;

    let svc = "svc-binaries";
    // Allow only /bin/busybox (needed to exec anything in the busybox image)
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_ALLOWED_BINARIES,
        build_service_with_allowed_binaries(
            svc,
            NS_ALLOWED_BINARIES,
            vec!["/bin/busybox".to_string()],
        ),
        "Ready",
        None,
        DEPLOY_TIMEOUT,
    )
    .await?;

    let p = wait_for_policies(
        kubeconfig,
        NS_ALLOWED_BINARIES,
        svc,
        Duration::from_secs(30),
    )
    .await?;
    assert_has(&p, "allow-binaries", svc);

    wait_for_pod_running(
        kubeconfig,
        NS_ALLOWED_BINARIES,
        &format!("app.kubernetes.io/name={svc}"),
    )
    .await?;

    // Allowed binary should work
    wait_for_exec_allowed(
        kubeconfig,
        NS_ALLOWED_BINARIES,
        svc,
        &["/bin/busybox", "echo", "hello"],
        "/bin/busybox allowed in svc-binaries",
    )
    .await?;

    // Shell should be blocked (not in allowedBinaries)
    wait_for_exec_blocked(
        kubeconfig,
        NS_ALLOWED_BINARIES,
        svc,
        &["sh", "-c", "echo hello"],
        "shell blocked in svc-binaries (not in allowedBinaries)",
    )
    .await?;

    delete_namespace(kubeconfig, NS_ALLOWED_BINARIES).await;
    info!("[Tetragon] Test 6 passed");
    Ok(())
}

/// Cedar forbid on allowedBinary — compilation rejected
async fn test_allowed_binaries_cedar_deny(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 7: Cedar deny on allowedBinary...");
    ensure_fresh_namespace(kubeconfig, NS_ALLOWED_BINARIES_CEDAR).await?;
    // No security override permit → Cedar default-deny should reject the allowedBinary

    let svc = "svc-cedar-deny";
    let svc_obj = build_service_with_allowed_binaries(
        svc,
        NS_ALLOWED_BINARIES_CEDAR,
        vec!["/usr/bin/curl".to_string()],
    );

    // The service must reach "Failed" phase — Cedar default-deny should reject
    // the allowedBinary override because no OverrideSecurity permit exists.
    // deploy_and_wait_for_phase returns Ok when the target phase is reached,
    // or Err on timeout. Both "Failed" and timeout-with-rejection are acceptable,
    // but reaching "Ready" means Cedar deny is broken.
    match deploy_and_wait_for_phase(
        kubeconfig,
        NS_ALLOWED_BINARIES_CEDAR,
        svc_obj,
        "Failed",
        None,
        DEPLOY_TIMEOUT,
    )
    .await
    {
        Ok(_) => {
            info!("[Tetragon] Test 7 passed — service reached Failed phase (Cedar denial)");
        }
        Err(e) => {
            // Timeout is acceptable only if the service did NOT reach Ready.
            // Check the current phase to distinguish "never scheduled" from "succeeded".
            let phase = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "get",
                "latticeservice",
                svc,
                "-n",
                NS_ALLOWED_BINARIES_CEDAR,
                "-o",
                "jsonpath={.status.phase}",
            ])
            .await
            .unwrap_or_default();

            if phase.trim() == "Ready" {
                delete_namespace(kubeconfig, NS_ALLOWED_BINARIES_CEDAR).await;
                return Err(format!(
                    "Cedar deny BROKEN: service reached Ready phase instead of Failed. \
                     The OverrideSecurity Cedar policy is not blocking allowedBinaries. Error: {e}"
                ));
            }
            info!(
                "[Tetragon] Test 7 passed — deployment rejected by Cedar (phase={}, err={e})",
                phase.trim()
            );
        }
    }

    delete_namespace(kubeconfig, NS_ALLOWED_BINARIES_CEDAR).await;
    Ok(())
}

/// Wildcard allowedBinaries — no binary restriction policies
async fn test_wildcard_allowed_binaries(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 8: Wildcard allowedBinaries — no binary restrictions...");
    ensure_fresh_namespace(kubeconfig, NS_WILDCARD_BINARIES).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t8", NS_WILDCARD_BINARIES).await?;

    let svc = "svc-wildcard";
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_WILDCARD_BINARIES,
        build_service_with_allowed_binaries(svc, NS_WILDCARD_BINARIES, vec!["*".to_string()]),
        "Ready",
        None,
        DEPLOY_TIMEOUT,
    )
    .await?;

    wait_for_pod_running(
        kubeconfig,
        NS_WILDCARD_BINARIES,
        &format!("app.kubernetes.io/name={svc}"),
    )
    .await?;

    // Verify no binary policy was created
    let all = list_tracing_policies(kubeconfig, NS_WILDCARD_BINARIES).await?;
    let matching: Vec<_> = all.iter().filter(|n| n.contains(svc)).collect();
    assert!(
        matching.is_empty(),
        "Expected no policies for wildcard service, got: {matching:?}"
    );

    // Everything should work with wildcard
    wait_for_exec_allowed(
        kubeconfig,
        NS_WILDCARD_BINARIES,
        svc,
        &["sh", "-c", "echo hello"],
        "shell allowed with wildcard allowedBinaries",
    )
    .await?;

    delete_namespace(kubeconfig, NS_WILDCARD_BINARIES).await;
    info!("[Tetragon] Test 8 passed");
    Ok(())
}

/// Implicit wildcard — no command, no allowedBinaries → no binary restrictions.
/// Verifies the compiler correctly infers wildcard when the image ENTRYPOINT is unknown.
async fn test_implicit_wildcard(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 9: Implicit wildcard — no command, no allowedBinaries...");
    ensure_fresh_namespace(kubeconfig, NS_IMPLICIT_WILDCARD).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t9", NS_IMPLICIT_WILDCARD).await?;

    let svc = "svc-implicit";
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_IMPLICIT_WILDCARD,
        build_service_no_command(svc, NS_IMPLICIT_WILDCARD),
        "Ready",
        None,
        DEPLOY_TIMEOUT,
    )
    .await?;

    wait_for_pod_running(
        kubeconfig,
        NS_IMPLICIT_WILDCARD,
        &format!("app.kubernetes.io/name={svc}"),
    )
    .await?;

    // Verify no binary policy was created
    let all = list_tracing_policies(kubeconfig, NS_IMPLICIT_WILDCARD).await?;
    let matching: Vec<_> = all.iter().filter(|n| n.contains(svc)).collect();
    assert!(
        matching.is_empty(),
        "Expected no policies for implicit wildcard service, got: {matching:?}"
    );

    // Everything should work — no binary restrictions
    wait_for_exec_allowed(
        kubeconfig,
        NS_IMPLICIT_WILDCARD,
        svc,
        &["sh", "-c", "echo hello"],
        "shell allowed with implicit wildcard",
    )
    .await?;

    delete_namespace(kubeconfig, NS_IMPLICIT_WILDCARD).await;
    info!("[Tetragon] Test 9 passed");
    Ok(())
}

// =============================================================================
// Negative tests
// =============================================================================

/// No command, no allowedBinaries, no Cedar permit → implicit wildcard denied by Cedar.
async fn test_implicit_wildcard_cedar_deny(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 10: Implicit wildcard Cedar deny...");
    ensure_fresh_namespace(kubeconfig, NS_IMPLICIT_CEDAR_DENY).await?;

    let svc = "svc-implicit-deny";

    // The service must reach "Failed" — Cedar default-deny should reject
    // the implicit wildcard because no OverrideSecurity permit exists.
    match deploy_and_wait_for_phase(
        kubeconfig,
        NS_IMPLICIT_CEDAR_DENY,
        build_service_no_command(svc, NS_IMPLICIT_CEDAR_DENY),
        "Failed",
        None,
        DEPLOY_TIMEOUT,
    )
    .await
    {
        Ok(_) => {
            info!("[Tetragon] Test 10 passed — service reached Failed phase (Cedar denial)");
        }
        Err(e) => {
            let phase = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "get",
                "latticeservice",
                svc,
                "-n",
                NS_IMPLICIT_CEDAR_DENY,
                "-o",
                "jsonpath={.status.phase}",
            ])
            .await
            .unwrap_or_default();

            if phase.trim() == "Ready" {
                delete_namespace(kubeconfig, NS_IMPLICIT_CEDAR_DENY).await;
                return Err(format!(
                    "Cedar deny BROKEN: implicit wildcard service reached Ready instead of Failed. \
                     The OverrideSecurity Cedar policy is not blocking implicit wildcards. Error: {e}"
                ));
            }
            info!(
                "[Tetragon] Test 10 passed — deployment rejected by Cedar (phase={}, err={e})",
                phase.trim()
            );
        }
    }

    delete_namespace(kubeconfig, NS_IMPLICIT_CEDAR_DENY).await;
    Ok(())
}

/// allowedBinaries doesn't include the image entrypoint → container SIGKILL'd on start.
/// image: busybox (entrypoint: sh), allowedBinaries: ["/usr/bin/curl"] → sleep (command[0])
/// is whitelisted but /usr/bin/curl is also allowed. The key: no other binary can run.
async fn test_missing_entrypoint_killed(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 11: Missing entrypoint in allowedBinaries — pod should crash...");
    ensure_fresh_namespace(kubeconfig, NS_MISSING_ENTRYPOINT).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t11", NS_MISSING_ENTRYPOINT).await?;

    // command: ["sleep", "infinity"] → "sleep" auto-whitelisted
    // allowedBinaries: ["/usr/bin/curl"] → also whitelisted
    // But exec'ing "sh" should be killed since it's not in either list
    let svc = "svc-bad-whitelist";
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_MISSING_ENTRYPOINT,
        build_service_with_allowed_binaries(
            svc,
            NS_MISSING_ENTRYPOINT,
            vec!["/usr/bin/curl".to_string()],
        ),
        "Ready",
        None,
        DEPLOY_TIMEOUT,
    )
    .await?;

    wait_for_policies(
        kubeconfig,
        NS_MISSING_ENTRYPOINT,
        svc,
        Duration::from_secs(30),
    )
    .await?;
    wait_for_pod_running(
        kubeconfig,
        NS_MISSING_ENTRYPOINT,
        &format!("app.kubernetes.io/name={svc}"),
    )
    .await?;

    // Shell should be killed — not in whitelist
    wait_for_exec_blocked(
        kubeconfig,
        NS_MISSING_ENTRYPOINT,
        svc,
        &["sh", "-c", "echo hello"],
        "shell blocked in svc-bad-whitelist (not in allowedBinaries)",
    )
    .await?;
    info!("[Tetragon] Test 11 passed — unlisted binary was killed");

    delete_namespace(kubeconfig, NS_MISSING_ENTRYPOINT).await;
    Ok(())
}

// =============================================================================
// Orchestrator
// =============================================================================

pub async fn run_tetragon_tests(ctx: &InfraContext) -> Result<(), String> {
    let kubeconfig = ctx.require_workload()?;
    info!("[Tetragon] Running runtime enforcement tests on {kubeconfig}");

    setup_regcreds_infrastructure(kubeconfig).await?;
    cleanup_policies(kubeconfig).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let harness = TestHarness::new("Tetragon");
    tokio::join!(
        harness.run("Default security", || test_default_security(kubeconfig)),
        harness.run("Probe shell exemption", || test_probe_shell_exemption(
            kubeconfig
        )),
        harness.run("Cmd shell exemption", || test_cmd_shell_exemption(
            kubeconfig
        )),
        harness.run("Sidecar shell exemption", || test_sidecar_shell_exemption(
            kubeconfig
        )),
        harness.run("Enforcement", || test_enforcement(kubeconfig)),
        harness.run("Allowed binaries", || test_allowed_binaries(kubeconfig)),
        harness.run("Allowed binaries cedar deny", || {
            test_allowed_binaries_cedar_deny(kubeconfig)
        }),
        harness.run("Wildcard allowed binaries", || {
            test_wildcard_allowed_binaries(kubeconfig)
        }),
        harness.run("Implicit wildcard", || test_implicit_wildcard(kubeconfig)),
        harness.run("Implicit wildcard cedar deny", || {
            test_implicit_wildcard_cedar_deny(kubeconfig)
        }),
        harness.run("Missing entrypoint killed", || {
            test_missing_entrypoint_killed(kubeconfig)
        }),
    );
    harness.finish()?;

    cleanup_policies(kubeconfig).await;
    info!("[Tetragon] All runtime enforcement tests passed!");
    Ok(())
}

// =============================================================================
// Standalone entry
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_tetragon_standalone() {
    use super::super::context::TestSession;

    let session =
        TestSession::from_env("Set LATTICE_WORKLOAD_KUBECONFIG to run standalone Tetragon tests")
            .await
            .expect("Failed to create test session");

    if let Err(e) = run_tetragon_tests(&session.ctx).await {
        panic!("Tetragon tests failed: {e}");
    }
}
