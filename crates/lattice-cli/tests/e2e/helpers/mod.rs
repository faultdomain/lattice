//! Test helpers for e2e tests
//!
//! Provides utilities for Docker-based cluster testing.
#![cfg(feature = "provider-e2e")]

use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

use lattice_common::LABEL_NAME;
use lattice_common::LOCAL_WEBHOOK_STORE_NAME;
use tokio::time::sleep;

// Submodules
pub mod cedar;
pub mod cluster;
pub mod docker;
pub mod kubernetes;
pub mod services;
pub mod test_harness;

// Re-export everything from submodules so existing imports stay unchanged
pub use cedar::*;
pub use cluster::*;
pub use docker::*;
pub use kubernetes::*;
pub use services::*;
pub use test_harness::*;

// =============================================================================
// Generic Polling Helper
// =============================================================================

/// Trait that abstracts over condition return types for `wait_for_condition`.
///
/// Implemented for `bool` (returns `()`) and `Option<T>` (returns `T`), so the
/// same polling helper works for both fire-and-forget conditions and conditions
/// that produce a value.
pub trait ConditionResult {
    type Value;
    fn is_met(&self) -> bool;
    fn into_value(self) -> Self::Value;
}

impl ConditionResult for bool {
    type Value = ();
    fn is_met(&self) -> bool {
        *self
    }
    fn into_value(self) -> Self::Value {}
}

impl<T> ConditionResult for Option<T> {
    type Value = T;
    fn is_met(&self) -> bool {
        self.is_some()
    }
    fn into_value(self) -> T {
        self.expect("into_value called on None (should only be called when is_met() is true)")
    }
}

/// Poll an async condition until it succeeds or the timeout expires.
///
/// The condition closure returns `Ok(R)` where `R` implements `ConditionResult`:
/// - `bool`: `Ok(true)` = done, `Ok(false)` = keep polling. Returns `()`.
/// - `Option<T>`: `Ok(Some(val))` = done with value, `Ok(None)` = keep polling. Returns `T`.
/// - `Err(String)` aborts immediately in both cases.
pub async fn wait_for_condition<F, Fut, R>(
    description: &str,
    timeout: Duration,
    poll_interval: Duration,
    condition: F,
) -> Result<R::Value, String>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<R, String>>,
    R: ConditionResult,
{
    let start = std::time::Instant::now();
    let mut last_error: Option<String> = None;
    loop {
        if start.elapsed() > timeout {
            let mut msg = format!("Timeout after {:?} waiting for: {}", timeout, description);
            if let Some(e) = &last_error {
                msg.push_str(&format!(" (last error: {e})"));
            }
            return Err(msg);
        }
        match condition().await {
            Ok(r) if r.is_met() => return Ok(r.into_value()),
            Ok(_) => {
                last_error = None;
            }
            Err(e) => {
                tracing::warn!("Transient error while waiting for {}: {}", description, e);
                last_error = Some(e);
            }
        }
        sleep(poll_interval).await;
    }
}

// =============================================================================
// Shared Constants
// =============================================================================

/// Default Lattice container image for E2E tests
pub const DEFAULT_LATTICE_IMAGE: &str = "ghcr.io/evan-hines-js/lattice:latest";

/// When `true`, rewrite all non-lattice test images to the GHCR mirror
/// (`ghcr.io/evan-hines-js/{name}:{tag}`). Flip this single bool to switch.
const USE_GHCR_MIRROR: bool = true;

/// GHCR org where mirrored images live (only used when `USE_GHCR_MIRROR` is true).
const GHCR_MIRROR_PREFIX: &str = "ghcr.io/evan-hines-js";

/// Resolve a test image: returns the canonical docker.io path unchanged, or
/// rewrites it to the GHCR mirror by extracting `name:tag` from the last
/// path segment. e.g. `docker.io/curlimages/curl:latest` → `ghcr.io/evan-hines-js/curl:latest`
pub fn test_image(docker_path: &str) -> String {
    if USE_GHCR_MIRROR {
        let name_tag = docker_path.rsplit('/').next().unwrap_or(docker_path);
        format!("{GHCR_MIRROR_PREFIX}/{name_tag}")
    } else {
        docker_path.to_string()
    }
}

/// Nginx image for mesh server containers
pub static NGINX_IMAGE: LazyLock<String> =
    LazyLock::new(|| test_image("docker.io/nginxinc/nginx-unprivileged:alpine"));

/// Curl image for mesh traffic generator containers
pub static CURL_IMAGE: LazyLock<String> =
    LazyLock::new(|| test_image("docker.io/curlimages/curl:latest"));

/// Busybox image for lightweight test pods
pub static BUSYBOX_IMAGE: LazyLock<String> =
    LazyLock::new(|| test_image("docker.io/library/busybox:latest"));

/// SecretProvider name used for GHCR registry credentials across all tests.
///
/// Points at the operator's built-in `lattice-local` ClusterSecretStore
/// (created by `ensure_local_webhook_infrastructure()` at startup).
pub const REGCREDS_PROVIDER: &str = LOCAL_WEBHOOK_STORE_NAME;

/// Remote key for the GHCR registry credentials secret in the local webhook store.
pub const REGCREDS_REMOTE_KEY: &str = "local-regcreds";

/// Standard cluster names for E2E tests
pub const MGMT_CLUSTER_NAME: &str = "e2e-mgmt";
pub const WORKLOAD_CLUSTER_NAME: &str = "e2e-workload";
pub const WORKLOAD2_CLUSTER_NAME: &str = "e2e-workload2";

/// Get a cluster name from an env var, falling back to a default.
fn cluster_name_from_env(env_var: &str, default: &str) -> String {
    std::env::var(env_var).unwrap_or_else(|_| default.to_string())
}

pub fn get_mgmt_cluster_name() -> String {
    cluster_name_from_env("LATTICE_MGMT_CLUSTER_NAME", MGMT_CLUSTER_NAME)
}

pub fn get_workload_cluster_name() -> String {
    cluster_name_from_env("LATTICE_WORKLOAD_CLUSTER_NAME", WORKLOAD_CLUSTER_NAME)
}

pub fn get_workload2_cluster_name() -> String {
    cluster_name_from_env("LATTICE_WORKLOAD2_CLUSTER_NAME", WORKLOAD2_CLUSTER_NAME)
}

/// Get child cluster name (checks LATTICE_CHILD_CLUSTER_NAME, then falls back to workload name)
pub fn get_child_cluster_name() -> String {
    std::env::var("LATTICE_CHILD_CLUSTER_NAME")
        .or_else(|_| std::env::var("LATTICE_WORKLOAD_CLUSTER_NAME"))
        .unwrap_or_else(|_| WORKLOAD_CLUSTER_NAME.to_string())
}

/// Label selector for lattice-operator pods (helm-managed, not compiler-generated)
pub const OPERATOR_LABEL: &str = "app=lattice-operator";

/// Build a label selector for pods generated by the LatticeService compiler.
///
/// Uses `LABEL_NAME` (`app.kubernetes.io/name`) — the same label the compiler
/// puts on Deployments and pod templates.
pub fn service_pod_selector(name: &str) -> String {
    format!("{}={}", LABEL_NAME, name)
}

// =============================================================================
// Unique Run ID for Parallel Test Execution
// =============================================================================

/// Unique run ID for this test process.
/// Uses LATTICE_RUN_ID env var if set (e.g., commit SHA in CI),
/// otherwise falls back to process ID and timestamp.
static RUN_ID: OnceLock<String> = OnceLock::new();

/// Get the unique run ID for this test process.
///
/// Checks `LATTICE_RUN_ID` environment variable first (useful for CI where
/// you can set it to the commit SHA), then falls back to `{pid}-{timestamp}`.
pub fn run_id() -> &'static str {
    RUN_ID.get_or_init(|| {
        std::env::var("LATTICE_RUN_ID").unwrap_or_else(|_| {
            format!(
                "{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
                    % 1_000_000
            )
        })
    })
}

/// Generate a unique kubeconfig path for a cluster.
///
/// The path includes the run ID as a suffix to allow parallel test execution.
/// Example: `/tmp/e2e-mgmt-kubeconfig-8156-965202`
pub fn kubeconfig_path(cluster_name: &str) -> String {
    format!("/tmp/{}-kubeconfig-{}", cluster_name, run_id())
}

/// Generate a unique localhost-patched kubeconfig path for a cluster.
/// Example: `/tmp/e2e-mgmt-kubeconfig-local-8156-965202`
fn kubeconfig_local_path(cluster_name: &str) -> String {
    format!("/tmp/{}-kubeconfig-local-{}", cluster_name, run_id())
}

// =============================================================================
// Docker Network Constants
// =============================================================================

/// Docker network subnet for kind/CAPD clusters
/// This must be pinned because Cilium LB-IPAM uses IPs from this range (172.18.255.x)
pub const DOCKER_KIND_SUBNET: &str = "172.18.0.0/16";
pub const DOCKER_KIND_GATEWAY: &str = "172.18.0.1";
