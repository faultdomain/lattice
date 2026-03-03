//! Cedar policy helpers, YAML application, and Tetragon listing.
#![cfg(feature = "provider-e2e")]

use std::sync::Arc;
use std::time::Duration;

use lattice_common::retry::{retry_with_backoff, RetryConfig};
use lattice_common::LATTICE_SYSTEM_NAMESPACE;
use tokio::sync::Semaphore;
use tracing::info;

use super::docker::run_kubectl;

// =============================================================================
// YAML Apply with Retry
// =============================================================================

/// Apply YAML manifest via kubectl with retry for transient failures.
///
/// Handles API server readiness issues by retrying with exponential backoff.
pub async fn apply_yaml(kubeconfig: &str, yaml: &str) -> Result<(), String> {
    let retry_config = RetryConfig {
        max_attempts: 30,
        initial_delay: Duration::from_millis(500),
        max_delay: Duration::from_secs(5),
        backoff_multiplier: 2.0,
    };

    let kubeconfig_owned = kubeconfig.to_string();
    let yaml_owned = yaml.to_string();

    retry_with_backoff(&retry_config, "kubectl_apply", || {
        let kubeconfig = kubeconfig_owned.clone();
        let yaml = yaml_owned.clone();
        async move { apply_yaml_internal(&kubeconfig, &yaml) }
    })
    .await
}

fn apply_yaml_internal(kubeconfig: &str, yaml: &str) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("kubectl")
        .args([
            "--kubeconfig",
            kubeconfig,
            "apply",
            "--server-side",
            "--force-conflicts",
            "--validate=false",
            "-f",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn kubectl: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(yaml.as_bytes())
            .map_err(|e| format!("Failed to write to kubectl stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for kubectl: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Redact secret data from error messages to avoid leaking credentials in logs
        let message = if yaml.contains("kind: Secret") {
            // Strip lines that look like they contain stringData/data payloads
            stderr
                .lines()
                .filter(|line| {
                    let trimmed = line.trim();
                    !trimmed.starts_with("\"stringData\"")
                        && !trimmed.starts_with("\"data\"")
                        && !trimmed.starts_with("{\"auths\"")
                        && !trimmed.starts_with("{\"stringData\"")
                        && !trimmed.starts_with("{\"data\"")
                })
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            stderr.to_string()
        };
        return Err(format!("kubectl apply failed: {}", message));
    }

    Ok(())
}

// =============================================================================
// Cedar Policy Helpers
// =============================================================================

/// Apply a CedarPolicy CRD with standard metadata and wait for the operator to load it.
///
/// Generates the boilerplate YAML wrapper. Callers provide only the variable parts:
/// - `name`: CRD object name
/// - `test_label`: value for `lattice.dev/test` label (used for batch cleanup)
/// - `priority`: Cedar evaluation priority (higher = evaluated first)
/// - `cedar_text`: Raw Cedar policy text (will be indented under `policies: |`)
pub async fn apply_cedar_policy_crd(
    kubeconfig: &str,
    name: &str,
    test_label: &str,
    priority: u32,
    cedar_text: &str,
) -> Result<(), String> {
    let indented: String = cedar_text
        .lines()
        .map(|line| {
            if line.trim().is_empty() {
                String::new()
            } else {
                format!("    {}", line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: CedarPolicy
metadata:
  name: {name}
  namespace: {system_ns}
  labels:
    lattice.dev/test: {test_label}
spec:
  enabled: true
  priority: {priority}
  policies: |
{indented}"#,
        name = name,
        system_ns = LATTICE_SYSTEM_NAMESPACE,
        test_label = test_label,
        priority = priority,
        indented = indented,
    );

    apply_yaml(kubeconfig, &yaml).await?;
    info!(
        "Applied CedarPolicy '{}' (priority={}, label={})",
        name, priority, test_label
    );
    Ok(())
}

/// Specification for a Cedar policy to be batch-applied.
pub struct CedarPolicySpec {
    pub name: String,
    pub test_label: String,
    pub priority: u32,
    pub cedar_text: String,
}

/// Apply multiple Cedar policies concurrently.
///
/// Uses bounded concurrency via a semaphore to avoid overloading the API server.
pub async fn apply_cedar_policies_batch(
    kubeconfig: &str,
    policies: Vec<CedarPolicySpec>,
    max_concurrent: usize,
) -> Result<(), String> {
    let count = policies.len();
    if count == 0 {
        return Ok(());
    }

    info!(
        "Batch-applying {} Cedar policies (max_concurrent={})...",
        count, max_concurrent
    );

    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let kubeconfig = kubeconfig.to_string();

    let mut handles = Vec::with_capacity(count);
    for policy in policies {
        let sem = semaphore.clone();
        let kc = kubeconfig.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem
                .acquire()
                .await
                .map_err(|e| format!("semaphore error: {}", e))?;
            apply_cedar_policy_crd(
                &kc,
                &policy.name,
                &policy.test_label,
                policy.priority,
                &policy.cedar_text,
            )
            .await
        }));
    }

    for handle in handles {
        handle
            .await
            .map_err(|e| format!("task join error: {}", e))??;
    }

    info!("Batch-applied {} Cedar policies", count);
    Ok(())
}

/// Apply a Cedar policy permitting wildcard inbound for a specific service.
pub async fn apply_mesh_wildcard_inbound_policy(
    kubeconfig: &str,
    namespace: &str,
    service_name: &str,
) -> Result<(), String> {
    apply_cedar_policy_crd(
        kubeconfig,
        &format!("permit-wildcard-inbound-{}", service_name),
        "mesh-test",
        50,
        &format!(
            r#"permit(
  principal == Lattice::Service::"{namespace}/{service_name}",
  action == Lattice::Action::"AllowWildcard",
  resource == Lattice::Mesh::"inbound"
);"#
        ),
    )
    .await
}

/// Apply a Cedar policy permitting AppArmor Unconfined for all services.
///
/// Docker KIND clusters don't have AppArmor enabled, so all e2e fixtures
/// set `apparmor_profile: Unconfined`. This policy permits that security
/// override. Uses the "e2e" label so it persists across test phases.
pub async fn apply_apparmor_override_policy(kubeconfig: &str) -> Result<(), String> {
    apply_cedar_policy_crd(
        kubeconfig,
        "permit-apparmor-unconfined",
        "e2e",
        50,
        r#"permit(
  principal,
  action == Lattice::Action::"OverrideSecurity",
  resource == Lattice::SecurityOverride::"unconfined:apparmor"
);"#,
    )
    .await
}

pub async fn apply_run_as_root_override_policy(
    kubeconfig: &str,
    namespace: &str,
    service_name: &str,
) -> Result<(), String> {
    apply_cedar_policy_crd(
        kubeconfig,
        &format!("root-{namespace}-{service_name}"),
        "e2e",
        50,
        &format!(
            r#"permit(
  principal == Lattice::Service::"{namespace}/{service_name}",
  action == Lattice::Action::"OverrideSecurity",
  resource == Lattice::SecurityOverride::"runAsRoot"
);"#
        ),
    )
    .await
}

/// Delete all CedarPolicy CRDs matching a label selector.
pub async fn delete_cedar_policies_by_label(kubeconfig: &str, label_selector: &str) {
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "cedarpolicy",
        "-n",
        LATTICE_SYSTEM_NAMESPACE,
        "-l",
        label_selector,
        "--ignore-not-found",
    ])
    .await;
}

/// Check whether a CedarPolicy with the given name exists in lattice-system.
pub async fn cedar_policy_exists(kubeconfig: &str, name: &str) -> bool {
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "cedarpolicy",
        name,
        "-n",
        LATTICE_SYSTEM_NAMESPACE,
        "-o",
        "name",
    ])
    .await
    .is_ok()
}

/// Count CedarPolicy CRDs matching a label selector.
async fn count_cedar_policies_with_label(kubeconfig: &str, label_selector: &str) -> usize {
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "cedarpolicy",
        "-n",
        LATTICE_SYSTEM_NAMESPACE,
        "-l",
        label_selector,
        "-o",
        "jsonpath={.items[*].metadata.name}",
    ])
    .await;

    match output {
        Ok(stdout) => stdout.split_whitespace().filter(|s| !s.is_empty()).count(),
        Err(_) => 0,
    }
}

/// Wait until no CedarPolicies matching the label selector remain.
///
/// Used after `delete_cedar_policies_by_label` to ensure the operator has
/// processed the deletions before proceeding with tests that rely on
/// default-deny semantics.
pub async fn wait_for_no_cedar_policies_with_label(
    kubeconfig: &str,
    label_selector: &str,
) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let label = label_selector.to_string();
    super::wait_for_condition(
        &format!("no CedarPolicies with label '{}'", label_selector),
        Duration::from_secs(30),
        Duration::from_millis(500),
        || {
            let kc = kc.clone();
            let label = label.clone();
            async move {
                let count = count_cedar_policies_with_label(&kc, &label).await;
                Ok(count == 0)
            }
        },
    )
    .await
}

// =============================================================================
// Fine-Grained Cedar Policy Helpers
// =============================================================================

/// Apply a Cedar policy permitting services in `namespace` to access specific secret IDs.
///
/// Unlike the broad `permit-regcreds` policy (which only covers image pull credentials),
/// this scopes access to exactly the secrets a service needs — validating that the Cedar
/// authorization pipeline works correctly with fine-grained policies.
///
/// The `label` is used for `lattice.dev/test={label}` so callers can clean up with
/// `delete_cedar_policies_by_label`.
pub async fn apply_cedar_secret_policy_for_service(
    kubeconfig: &str,
    policy_name: &str,
    label: &str,
    namespace: &str,
    secret_ids: &[&str],
) -> Result<(), String> {
    let path_conditions: Vec<String> = secret_ids
        .iter()
        .map(|id| format!("resource.path == \"{}\"", id))
        .collect();
    let path_expr = path_conditions.join(" || ");

    let cedar = format!(
        r#"permit(
  principal,
  action == Lattice::Action::"AccessSecret",
  resource
) when {{
  principal.namespace == "{namespace}" &&
  ({path_expr})
}};"#,
    );

    apply_cedar_policy_crd(kubeconfig, policy_name, label, 100, &cedar).await
}

/// List TracingPolicyNamespaced resource names in a namespace
pub async fn list_tracing_policies(
    kubeconfig: &str,
    namespace: &str,
) -> Result<Vec<String>, String> {
    let output = super::docker::run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "tracingpolicynamespaced",
        "-n",
        namespace,
        "-o",
        "jsonpath={.items[*].metadata.name}",
    ])
    .await;

    match output {
        Ok(stdout) => Ok(stdout
            .split_whitespace()
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()),
        Err(e) if e.contains("the server doesn't have a resource type") => Ok(vec![]),
        Err(e) => Err(e),
    }
}
