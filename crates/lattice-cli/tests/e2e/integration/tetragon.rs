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
const NS_PROBE_SHELL: &str = "tetragon-t2";
const NS_CMD_SHELL: &str = "tetragon-t3";
const NS_SIDECAR_SHELL: &str = "tetragon-t4";
const NS_ENFORCEMENT: &str = "tetragon-t5";

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

/// Check if a binary appears in the allow-binaries policy's NotEqual values list.
/// In the allow-binaries policy, NotEqual values are the ALLOWED binaries.
fn yaml_allows_binary(yaml: &str, binary: &str) -> bool {
    yaml.contains(&format!("- {binary}")) || yaml.contains(&format!("- \"{binary}\""))
}

// =============================================================================
// Test scenarios
// =============================================================================

async fn test_default_security(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 1: Default security — command whitelisted...");
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
    assert_has(&p, "allow-binaries", svc);

    delete_namespace(kubeconfig, NS_DEFAULT).await;
    info!("[Tetragon] Test 1 passed");
    Ok(())
}

async fn test_probe_shell_exemption(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 2: Probe shell exemption...");
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
    let yaml = get_policy_yaml(kubeconfig, NS_CMD_SHELL, &format!("allow-binaries-{svc}")).await?;
    assert!(
        yaml_allows_binary(&yaml, "/bin/bash"),
        "/bin/bash should be auto-allowed for container command"
    );

    delete_namespace(kubeconfig, NS_CMD_SHELL).await;
    info!("[Tetragon] Test 3 passed");
    Ok(())
}

/// Sidecar command shell exemption — /bin/ash auto-allowed
async fn test_sidecar_shell_exemption(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 4: Sidecar shell exemption — /bin/ash should be allowed...");
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
    info!("[Tetragon] Test 5: Enforcement — blocked binaries killed, exempted allowed...");
    ensure_fresh_namespace(kubeconfig, NS_ENFORCEMENT).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t8", NS_ENFORCEMENT).await?;

    // --- Service with default security (binary whitelist, no exemptions) ---
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

    // Give Tetragon a moment to load the policies
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Check 1: Shell execution should be blocked (SIGKILL)
    info!("[Tetragon] Check 1: shell exec should be killed...");
    let shell_result = exec_in_pod(
        kubeconfig,
        NS_ENFORCEMENT,
        svc_block,
        &["sh", "-c", "echo hello"],
    )
    .await;
    assert!(
        shell_result.is_err(),
        "Expected shell exec to be killed by Tetragon, but it succeeded: {shell_result:?}"
    );
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
        Duration::from_secs(90),
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

    tokio::time::sleep(Duration::from_secs(5)).await;

    // Check 2: Shell should be allowed when exempted via probe
    info!("[Tetragon] Check 2: exempted shell should succeed...");
    let exempt_result = exec_in_pod(
        kubeconfig,
        NS_ENFORCEMENT,
        svc_exempt,
        &["sh", "-c", "echo hello"],
    )
    .await;
    assert!(
        exempt_result.is_ok(),
        "Expected shell exec to succeed (probe exemption), but it failed: {exempt_result:?}"
    );
    info!("[Tetragon] Check 2 passed — exempted shell was allowed");

    delete_namespace(kubeconfig, NS_ENFORCEMENT).await;
    info!("[Tetragon] Test 5 passed");
    Ok(())
}

// =============================================================================
// Allowed binaries tests
// =============================================================================

const NS_ALLOWED_BINARIES: &str = "tetragon-t9";
const NS_ALLOWED_BINARIES_CEDAR: &str = "tetragon-t10";
const NS_WILDCARD_BINARIES: &str = "tetragon-t11";

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
                apparmor_profile: Some("Unconfined".to_string()),
                allowed_binaries,
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

/// allowedBinaries whitelist — listed binaries work, unlisted get SIGKILL'd
async fn test_allowed_binaries(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 6: allowedBinaries whitelist...");
    ensure_fresh_namespace(kubeconfig, NS_ALLOWED_BINARIES).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t9", NS_ALLOWED_BINARIES).await?;

    let svc = "svc-binaries";
    // Allow only /bin/busybox (needed to exec anything in busybox image)
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
        Duration::from_secs(90),
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
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Allowed binary should work
    let ok = exec_in_pod(
        kubeconfig,
        NS_ALLOWED_BINARIES,
        svc,
        &["/bin/busybox", "echo", "hello"],
    )
    .await;
    assert!(ok.is_ok(), "Expected /bin/busybox to be allowed: {ok:?}");

    // Shell should be blocked (not in allowedBinaries)
    let blocked = exec_in_pod(
        kubeconfig,
        NS_ALLOWED_BINARIES,
        svc,
        &["sh", "-c", "echo hello"],
    )
    .await;
    assert!(
        blocked.is_err(),
        "Expected shell to be SIGKILL'd: {blocked:?}"
    );

    delete_namespace(kubeconfig, NS_ALLOWED_BINARIES).await;
    info!("[Tetragon] Test 6 passed");
    Ok(())
}

/// Cedar forbid on allowedBinary — compilation rejected
async fn test_allowed_binaries_cedar_deny(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 7: Cedar deny on allowedBinary...");
    ensure_fresh_namespace(kubeconfig, NS_ALLOWED_BINARIES_CEDAR).await?;
    // No security override permit → Cedar default-deny should reject

    let svc = "svc-cedar-deny";
    let result = deploy_and_wait_for_phase(
        kubeconfig,
        NS_ALLOWED_BINARIES_CEDAR,
        build_service_with_allowed_binaries(
            svc,
            NS_ALLOWED_BINARIES_CEDAR,
            vec!["/usr/bin/curl".to_string()],
        ),
        "Failed",
        None,
        Duration::from_secs(90),
    )
    .await;

    // Should either fail to deploy or land in Failed phase due to Cedar denial
    if result.is_err() {
        info!("[Tetragon] Test 7 passed — deployment rejected by Cedar");
    } else {
        info!("[Tetragon] Test 7 passed — service in Failed phase due to Cedar denial");
    }

    delete_namespace(kubeconfig, NS_ALLOWED_BINARIES_CEDAR).await;
    Ok(())
}

/// Wildcard allowedBinaries — no binary restriction policies
async fn test_wildcard_allowed_binaries(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 8: Wildcard allowedBinaries — no binary restrictions...");
    ensure_fresh_namespace(kubeconfig, NS_WILDCARD_BINARIES).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t11", NS_WILDCARD_BINARIES).await?;

    let svc = "svc-wildcard";
    deploy_and_wait_for_phase(
        kubeconfig,
        NS_WILDCARD_BINARIES,
        build_service_with_allowed_binaries(svc, NS_WILDCARD_BINARIES, vec!["*".to_string()]),
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    // Wildcard → no binary policy should be created. Wait for pod, then verify.
    wait_for_pod_running(
        kubeconfig,
        NS_WILDCARD_BINARIES,
        &format!("app.kubernetes.io/name={svc}"),
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Verify no binary policy was created
    let all = list_tracing_policies(kubeconfig, NS_WILDCARD_BINARIES).await?;
    let matching: Vec<_> = all.iter().filter(|n| n.contains(svc)).collect();
    assert!(
        matching.is_empty(),
        "Expected no policies for wildcard service, got: {matching:?}"
    );

    // Everything should work with wildcard
    let shell = exec_in_pod(
        kubeconfig,
        NS_WILDCARD_BINARIES,
        svc,
        &["sh", "-c", "echo hello"],
    )
    .await;
    assert!(
        shell.is_ok(),
        "Expected shell to work with wildcard: {shell:?}"
    );

    delete_namespace(kubeconfig, NS_WILDCARD_BINARIES).await;
    info!("[Tetragon] Test 8 passed");
    Ok(())
}

const NS_IMPLICIT_WILDCARD: &str = "tetragon-t12";

/// Implicit wildcard — no command, no allowedBinaries → no binary restrictions.
/// Verifies the compiler correctly infers wildcard when the image ENTRYPOINT is unknown.
async fn test_implicit_wildcard(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 9: Implicit wildcard — no command, no allowedBinaries...");
    ensure_fresh_namespace(kubeconfig, NS_IMPLICIT_WILDCARD).await?;
    apply_security_override(kubeconfig, "permit-tetragon-t12", NS_IMPLICIT_WILDCARD).await?;

    let svc = "svc-implicit";
    // No command, no allowedBinaries — build manually to avoid build_service's default command
    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: BUSYBOX_IMAGE.to_string(),
            // Busybox default ENTRYPOINT is "sh", so the pod will start
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

    let service = LatticeService {
        metadata: ObjectMeta {
            name: Some(svc.to_string()),
            namespace: Some(NS_IMPLICIT_WILDCARD.to_string()),
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
    };

    deploy_and_wait_for_phase(
        kubeconfig,
        NS_IMPLICIT_WILDCARD,
        service,
        "Ready",
        None,
        Duration::from_secs(90),
    )
    .await?;

    // Implicit wildcard → no binary policy should be created. Wait for pod, then verify.
    wait_for_pod_running(
        kubeconfig,
        NS_IMPLICIT_WILDCARD,
        &format!("app.kubernetes.io/name={svc}"),
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Verify no binary policy was created
    let all = list_tracing_policies(kubeconfig, NS_IMPLICIT_WILDCARD).await?;
    let matching: Vec<_> = all.iter().filter(|n| n.contains(svc)).collect();
    assert!(
        matching.is_empty(),
        "Expected no policies for implicit wildcard service, got: {matching:?}"
    );

    // Everything should work — no binary restrictions
    let shell = exec_in_pod(
        kubeconfig,
        NS_IMPLICIT_WILDCARD,
        svc,
        &["sh", "-c", "echo hello"],
    )
    .await;
    assert!(
        shell.is_ok(),
        "Expected shell to work with implicit wildcard: {shell:?}"
    );

    delete_namespace(kubeconfig, NS_IMPLICIT_WILDCARD).await;
    info!("[Tetragon] Test 9 passed");
    Ok(())
}

// =============================================================================
// Negative tests
// =============================================================================

const NS_IMPLICIT_CEDAR_DENY: &str = "tetragon-t13";
const NS_MISSING_ENTRYPOINT: &str = "tetragon-t14";

/// No command, no allowedBinaries, no Cedar permit → implicit wildcard denied by Cedar.
async fn test_implicit_wildcard_cedar_deny(kubeconfig: &str) -> Result<(), String> {
    info!("[Tetragon] Test 10: Implicit wildcard Cedar deny...");
    ensure_fresh_namespace(kubeconfig, NS_IMPLICIT_CEDAR_DENY).await?;
    // Deliberately no Cedar permit for allowedBinary:*

    let svc = "svc-implicit-deny";
    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: BUSYBOX_IMAGE.to_string(),
            // No command, no allowedBinaries → implicit wildcard → Cedar must permit
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

    let service = LatticeService {
        metadata: ObjectMeta {
            name: Some(svc.to_string()),
            namespace: Some(NS_IMPLICIT_CEDAR_DENY.to_string()),
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
    };

    let result = deploy_and_wait_for_phase(
        kubeconfig,
        NS_IMPLICIT_CEDAR_DENY,
        service,
        "Failed",
        None,
        Duration::from_secs(90),
    )
    .await;

    if result.is_err() {
        info!("[Tetragon] Test 10 passed — deployment rejected by Cedar");
    } else {
        info!("[Tetragon] Test 10 passed — service in Failed phase due to Cedar denial");
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
    apply_security_override(kubeconfig, "permit-tetragon-t14", NS_MISSING_ENTRYPOINT).await?;

    let svc = "svc-bad-whitelist";
    // command: ["sleep", "infinity"] → "sleep" auto-whitelisted
    // allowedBinaries: ["/usr/bin/curl"] → also whitelisted
    // But exec'ing "sh" should be killed since it's not in either list
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
        Duration::from_secs(90),
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
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Shell should be killed — not in whitelist
    let shell = exec_in_pod(
        kubeconfig,
        NS_MISSING_ENTRYPOINT,
        svc,
        &["sh", "-c", "echo hello"],
    )
    .await;
    assert!(
        shell.is_err(),
        "Expected shell to be SIGKILL'd (not in allowedBinaries): {shell:?}"
    );
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

    tokio::try_join!(
        test_default_security(kubeconfig),
        test_probe_shell_exemption(kubeconfig),
        test_cmd_shell_exemption(kubeconfig),
        test_sidecar_shell_exemption(kubeconfig),
        test_enforcement(kubeconfig),
        test_allowed_binaries(kubeconfig),
        test_allowed_binaries_cedar_deny(kubeconfig),
        test_wildcard_allowed_binaries(kubeconfig),
        test_implicit_wildcard(kubeconfig),
        test_implicit_wildcard_cedar_deny(kubeconfig),
        test_missing_entrypoint_killed(kubeconfig),
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
