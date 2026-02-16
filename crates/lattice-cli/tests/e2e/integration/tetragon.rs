//! Tetragon runtime enforcement integration tests
//!
//! Validates that deploying a LatticeService creates the correct
//! TracingPolicyNamespaced resources based on security context,
//! and that shell exemptions for probes/commands work correctly.
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
use tracing::info;

use lattice_common::crd::{
    ContainerSpec, ExecProbe, LatticeService, LatticeServiceSpec, PortSpec, Probe,
    ResourceQuantity, ResourceRequirements, RuntimeSpec, SecurityContext, ServicePortsSpec,
    SidecarSpec, WorkloadSpec,
};

use super::super::context::InfraContext;
use super::super::helpers::{
    apply_cedar_policy_crd, delete_cedar_policies_by_label, delete_namespace,
    deploy_and_wait_for_phase, ensure_fresh_namespace, list_tracing_policies,
    setup_regcreds_infrastructure, wait_for_pod_running, BUSYBOX_IMAGE,
};

const NS_DEFAULT: &str = "tetragon-t1";
const NS_WRITABLE_ROOTFS: &str = "tetragon-t2";
const NS_ROOT_ALLOWED: &str = "tetragon-t3";
const NS_CAPS_REQUESTED: &str = "tetragon-t4";
const NS_PROBE_SHELL: &str = "tetragon-t5";
const NS_CMD_SHELL: &str = "tetragon-t6";
const NS_SIDECAR_SHELL: &str = "tetragon-t7";
const NS_ENFORCEMENT: &str = "tetragon-t8";

const TEST_LABEL: &str = "tetragon";

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

    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: BUSYBOX_IMAGE.to_string(),
            command: command.or(Some(vec!["sleep".to_string(), "infinity".to_string()])),
            security: Some(sec),
            liveness_probe,
            resources: Some(ResourceRequirements {
                limits: Some(ResourceQuantity {
                    cpu: Some("100m".to_string()),
                    memory: Some("64Mi".to_string()),
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    let mut ports = BTreeMap::new();
    ports.insert(
        "http".to_string(),
        PortSpec {
            port: 8080,
            target_port: None,
            protocol: None,
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
                service: Some(ServicePortsSpec { ports }),
                ..Default::default()
            },
            runtime: RuntimeSpec::default(),
            ..Default::default()
        },
        status: None,
    }
}

/// Build a service with a sidecar whose command uses a shell
fn build_service_with_sidecar_shell(name: &str, namespace: &str) -> LatticeService {
    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: BUSYBOX_IMAGE.to_string(),
            command: Some(vec!["sleep".to_string(), "infinity".to_string()]),
            security: Some(SecurityContext {
                apparmor_profile: Some("Unconfined".to_string()),
                ..Default::default()
            }),
            resources: Some(ResourceRequirements {
                limits: Some(ResourceQuantity {
                    cpu: Some("100m".to_string()),
                    memory: Some("64Mi".to_string()),
                }),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    let mut ports = BTreeMap::new();
    ports.insert(
        "http".to_string(),
        PortSpec {
            port: 8080,
            target_port: None,
            protocol: None,
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
            security: Some(SecurityContext {
                apparmor_profile: Some("Unconfined".to_string()),
                ..Default::default()
            }),
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
                service: Some(ServicePortsSpec { ports }),
                ..Default::default()
            },
            runtime: RuntimeSpec {
                sidecars,
                ..Default::default()
            },
            ..Default::default()
        },
        status: None,
    }
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
    let start = std::time::Instant::now();
    loop {
        let all = list_tracing_policies(kubeconfig, namespace).await?;
        let matching: Vec<String> = all
            .into_iter()
            .filter(|n| n.ends_with(&format!("-{service_name}")))
            .collect();
        if !matching.is_empty() {
            return Ok(matching);
        }
        if start.elapsed() > timeout {
            return Err(format!(
                "Timeout waiting for TracingPolicyNamespaced for {service_name} in {namespace}"
            ));
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

fn assert_has(policies: &[String], prefix: &str, svc: &str) {
    let expected = format!("{prefix}-{svc}");
    assert!(
        policies.contains(&expected),
        "Expected '{expected}' in {policies:?}"
    );
}

fn assert_missing(policies: &[String], prefix: &str, svc: &str) {
    let unexpected = format!("{prefix}-{svc}");
    assert!(
        !policies.contains(&unexpected),
        "Did NOT expect '{unexpected}' in {policies:?}"
    );
}

async fn get_policy_yaml(kubeconfig: &str, namespace: &str, name: &str) -> Result<String, String> {
    let output = std::process::Command::new("kubectl")
        .args([
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
        .output()
        .map_err(|e| format!("kubectl failed: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn yaml_blocks_shell(yaml: &str, shell: &str) -> bool {
    yaml.contains(&format!("- {shell}")) || yaml.contains(&format!("- \"{shell}\""))
}

// =============================================================================
// Test scenarios
// =============================================================================

async fn test_default_security(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 1: Default security — all 4 policies...");
    ensure_fresh_namespace(kubeconfig, NS_DEFAULT).await?;

    let svc = "svc-default";
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_DEFAULT,
        build_service(svc, NS_DEFAULT, None, None, None),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    let p = wait_for_policies(kubeconfig, NS_DEFAULT, svc, Duration::from_secs(30)).await?;
    assert_has(&p, "block-shells", svc);
    assert_has(&p, "block-rootfs-write", svc);
    assert_has(&p, "block-setuid", svc);
    assert_has(&p, "block-capset", svc);

    delete_namespace(kubeconfig, NS_DEFAULT).await;
    info!("[Tetragon] Test 1 passed");
    Ok(())
}

async fn test_writable_rootfs(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 2: Writable rootfs...");
    ensure_fresh_namespace(kubeconfig, NS_WRITABLE_ROOTFS).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t2", NS_WRITABLE_ROOTFS).await?;

    let svc = "svc-writable";
    let sec = SecurityContext {
        read_only_root_filesystem: Some(false),
        apparmor_profile: Some("Unconfined".to_string()),
        ..Default::default()
    };
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_WRITABLE_ROOTFS,
        build_service(svc, NS_WRITABLE_ROOTFS, Some(sec), None, None),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    let p = wait_for_policies(kubeconfig, NS_WRITABLE_ROOTFS, svc, Duration::from_secs(30)).await?;
    assert_has(&p, "block-shells", svc);
    assert_missing(&p, "block-rootfs-write", svc);

    delete_namespace(kubeconfig, NS_WRITABLE_ROOTFS).await;
    info!("[Tetragon] Test 2 passed");
    Ok(())
}

async fn test_root_allowed(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 3: Root allowed...");
    ensure_fresh_namespace(kubeconfig, NS_ROOT_ALLOWED).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t3", NS_ROOT_ALLOWED).await?;

    let svc = "svc-root";
    let sec = SecurityContext {
        run_as_non_root: Some(false),
        apparmor_profile: Some("Unconfined".to_string()),
        ..Default::default()
    };
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_ROOT_ALLOWED,
        build_service(svc, NS_ROOT_ALLOWED, Some(sec), None, None),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    let p = wait_for_policies(kubeconfig, NS_ROOT_ALLOWED, svc, Duration::from_secs(30)).await?;
    assert_missing(&p, "block-setuid", svc);

    delete_namespace(kubeconfig, NS_ROOT_ALLOWED).await;
    info!("[Tetragon] Test 3 passed");
    Ok(())
}

async fn test_caps_requested(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 4: Capabilities requested...");
    ensure_fresh_namespace(kubeconfig, NS_CAPS_REQUESTED).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t4", NS_CAPS_REQUESTED).await?;

    let svc = "svc-caps";
    let sec = SecurityContext {
        capabilities: vec!["NET_ADMIN".to_string()],
        apparmor_profile: Some("Unconfined".to_string()),
        ..Default::default()
    };
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_CAPS_REQUESTED,
        build_service(svc, NS_CAPS_REQUESTED, Some(sec), None, None),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    let p = wait_for_policies(kubeconfig, NS_CAPS_REQUESTED, svc, Duration::from_secs(30)).await?;
    assert_missing(&p, "block-capset", svc);

    delete_namespace(kubeconfig, NS_CAPS_REQUESTED).await;
    info!("[Tetragon] Test 4 passed");
    Ok(())
}

async fn test_probe_shell_exemption(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 5: Probe shell exemption...");
    ensure_fresh_namespace(kubeconfig, NS_PROBE_SHELL).await?;

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
        Duration::from_secs(90),
    )
    .await?;

    wait_for_policies(kubeconfig, NS_PROBE_SHELL, svc, Duration::from_secs(30)).await?;
    let yaml = get_policy_yaml(kubeconfig, NS_PROBE_SHELL, &format!("block-shells-{svc}")).await?;
    assert!(
        !yaml_blocks_shell(&yaml, "/bin/sh"),
        "/bin/sh should be exempted for probe"
    );

    delete_namespace(kubeconfig, NS_PROBE_SHELL).await;
    info!("[Tetragon] Test 5 passed");
    Ok(())
}

async fn test_cmd_shell_exemption(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 6: Command shell exemption...");
    ensure_fresh_namespace(kubeconfig, NS_CMD_SHELL).await?;

    let svc = "svc-cmd";
    let cmd = vec![
        "/bin/bash".to_string(),
        "-c".to_string(),
        "sleep infinity".to_string(),
    ];
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_CMD_SHELL,
        build_service(svc, NS_CMD_SHELL, None, None, Some(cmd)),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    wait_for_policies(kubeconfig, NS_CMD_SHELL, svc, Duration::from_secs(30)).await?;
    let yaml = get_policy_yaml(kubeconfig, NS_CMD_SHELL, &format!("block-shells-{svc}")).await?;
    assert!(
        !yaml_blocks_shell(&yaml, "/bin/bash"),
        "/bin/bash should be exempted for container command"
    );

    delete_namespace(kubeconfig, NS_CMD_SHELL).await;
    info!("[Tetragon] Test 6 passed");
    Ok(())
}

/// Test 7: Sidecar command shell exemption — /bin/ash NOT in blocked shells
async fn test_sidecar_shell_exemption(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 7: Sidecar shell exemption — /bin/ash should be allowed...");
    ensure_fresh_namespace(kubeconfig, NS_SIDECAR_SHELL).await?;

    let svc = "svc-sidecar";
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_SIDECAR_SHELL,
        build_service_with_sidecar_shell(svc, NS_SIDECAR_SHELL),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    wait_for_policies(kubeconfig, NS_SIDECAR_SHELL, svc, Duration::from_secs(30)).await?;
    let yaml =
        get_policy_yaml(kubeconfig, NS_SIDECAR_SHELL, &format!("block-shells-{svc}")).await?;
    assert!(
        !yaml_blocks_shell(&yaml, "/bin/ash"),
        "/bin/ash should be exempted because sidecar command uses it"
    );

    delete_namespace(kubeconfig, NS_SIDECAR_SHELL).await;
    info!("[Tetragon] Test 7 passed");
    Ok(())
}

// =============================================================================
// Enforcement tests (exec into pods to verify Tetragon kills blocked actions)
// =============================================================================

/// Exec into a deployment's pod and return stdout on success or stderr on failure.
async fn exec_in_pod(
    kubeconfig: &str,
    namespace: &str,
    deploy: &str,
    args: &[&str],
) -> Result<String, String> {
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

    // Don't use run_kubectl (it retries on transient errors); we want raw exit status.
    let output = std::process::Command::new("kubectl")
        .args(&cmd_args)
        .output()
        .map_err(|e| format!("kubectl exec failed to spawn: {e}"))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

async fn test_enforcement(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 8: Enforcement — blocked actions killed, exempted actions allowed...");
    ensure_fresh_namespace(kubeconfig, NS_ENFORCEMENT).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t8", NS_ENFORCEMENT).await?;

    // --- Service with default security (all 4 policies, no exemptions) ---
    let svc_block = "svc-enforce";
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_ENFORCEMENT,
        build_service(svc_block, NS_ENFORCEMENT, None, None, None),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;
    wait_for_policies(kubeconfig, NS_ENFORCEMENT, svc_block, Duration::from_secs(30)).await?;
    wait_for_pod_running(kubeconfig, NS_ENFORCEMENT, &format!("app.kubernetes.io/name={svc_block}"))
        .await?;

    // Give Tetragon a moment to load the policies
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Check 1: Shell execution should be blocked (SIGKILL)
    info!("[Tetragon] Check 1: shell exec should be killed...");
    let shell_result = exec_in_pod(kubeconfig, NS_ENFORCEMENT, svc_block, &["sh", "-c", "echo hello"]).await;
    assert!(
        shell_result.is_err(),
        "Expected shell exec to be killed by Tetragon, but it succeeded: {shell_result:?}"
    );
    info!("[Tetragon] Check 1 passed — shell was blocked");

    // Check 2: Rootfs write should be blocked
    // Use /bin/busybox directly since shells are blocked
    info!("[Tetragon] Check 2: rootfs write should be blocked...");
    let write_result =
        exec_in_pod(kubeconfig, NS_ENFORCEMENT, svc_block, &["/bin/busybox", "touch", "/testfile"]).await;
    assert!(
        write_result.is_err(),
        "Expected rootfs write to be blocked by Tetragon, but it succeeded: {write_result:?}"
    );
    info!("[Tetragon] Check 2 passed — rootfs write was blocked");

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
        Duration::from_secs(90),
    )
    .await?;
    wait_for_policies(kubeconfig, NS_ENFORCEMENT, svc_exempt, Duration::from_secs(30)).await?;
    wait_for_pod_running(kubeconfig, NS_ENFORCEMENT, &format!("app.kubernetes.io/name={svc_exempt}"))
        .await?;

    tokio::time::sleep(Duration::from_secs(5)).await;

    // Check 3: Shell should be allowed when exempted via probe
    info!("[Tetragon] Check 3: exempted shell should succeed...");
    let exempt_result =
        exec_in_pod(kubeconfig, NS_ENFORCEMENT, svc_exempt, &["sh", "-c", "echo hello"]).await;
    assert!(
        exempt_result.is_ok(),
        "Expected shell exec to succeed (probe exemption), but it failed: {exempt_result:?}"
    );
    info!("[Tetragon] Check 3 passed — exempted shell was allowed");

    delete_namespace(kubeconfig, NS_ENFORCEMENT).await;
    info!("[Tetragon] Test 8 passed");
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

    tokio::try_join!(
        test_default_security(kubeconfig),
        test_writable_rootfs(kubeconfig),
        test_root_allowed(kubeconfig),
        test_caps_requested(kubeconfig),
        test_probe_shell_exemption(kubeconfig),
        test_cmd_shell_exemption(kubeconfig),
        test_sidecar_shell_exemption(kubeconfig),
        test_enforcement(kubeconfig),
    )?;

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
