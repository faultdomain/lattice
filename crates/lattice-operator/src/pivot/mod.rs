//! Pivot logic for cluster self-management
//!
//! The pivot process transfers CAPI resources from the cell to a workload cluster,
//! making the workload cluster self-managing.
//!
//! # Flow
//!
//! 1. Cell triggers pivot via gRPC control stream
//! 2. Agent enters PIVOTING state
//! 3. Cell executes `clusterctl move --to-kubeconfig <proxy>` through K8s API proxy
//! 4. CAPI resources are created on workload cluster
//! 5. Agent detects resources and confirms pivot complete
//!
//! # Why Pivot Matters
//!
//! - Workload clusters become independent of cell
//! - Each cluster can self-heal and self-manage
//! - Cell failure doesn't affect workload clusters
//! - Enables air-gapped operation after provisioning

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use thiserror::Error;
use tracing::{debug, info};

// Re-export retry utilities for convenience
pub use crate::retry::{retry_with_backoff, RetryConfig};

/// Pivot errors
#[derive(Debug, Error)]
pub enum PivotError {
    /// Clusterctl command failed
    #[error("clusterctl failed: {0}")]
    ClusterctlFailed(String),

    /// Kubeconfig generation failed
    #[error("kubeconfig generation failed: {0}")]
    KubeconfigFailed(String),

    /// Pivot timed out
    #[error("pivot timed out")]
    Timeout,

    /// Agent not connected
    #[error("agent not connected: {0}")]
    AgentNotConnected(String),

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}

/// Command output for testability
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// Whether command succeeded
    pub success: bool,
    /// Standard output
    pub stdout: String,
    /// Standard error
    pub stderr: String,
}

/// Trait for executing external commands (allows mocking in tests)
#[async_trait::async_trait]
pub trait CommandRunner: Send + Sync {
    /// List CAPI resources of a given type
    async fn run_kubectl_get(
        &self,
        resource_type: &str,
        namespace: &str,
    ) -> Result<CommandOutput, PivotError>;
}

/// Real command runner that executes actual system commands
#[derive(Default, Clone)]
pub struct RealCommandRunner;

#[async_trait::async_trait]
impl CommandRunner for RealCommandRunner {
    async fn run_kubectl_get(
        &self,
        resource_type: &str,
        namespace: &str,
    ) -> Result<CommandOutput, PivotError> {
        use kube::api::{Api, DynamicObject, ListParams};
        use kube::discovery::ApiResource;

        let client = Client::try_default()
            .await
            .map_err(|e| PivotError::Internal(format!("k8s client failed: {}", e)))?;

        // Parse resource type to get group/version/kind
        let (group, version, kind, plural) = parse_capi_resource_type(resource_type)?;

        let ar = ApiResource {
            group: group.clone(),
            version,
            kind,
            api_version: if group.is_empty() {
                "v1".to_string()
            } else {
                format!("{}/v1beta1", group)
            },
            plural,
        };

        let api: Api<DynamicObject> = Api::namespaced_with(client, namespace, &ar);
        let list = api.list(&ListParams::default()).await.map_err(|e| {
            // Return empty result for "not found" errors (CRD not installed)
            if e.to_string().contains("not found") || e.to_string().contains("404") {
                return PivotError::Internal("not found".to_string());
            }
            PivotError::Internal(format!("list failed: {}", e))
        })?;

        // Format output similar to kubectl
        let stdout = list
            .items
            .iter()
            .filter_map(|obj| obj.metadata.name.clone())
            .collect::<Vec<_>>()
            .join("\n");

        Ok(CommandOutput {
            stdout,
            stderr: String::new(),
            success: true,
        })
    }
}

/// Parse CAPI resource type string into group/version/kind/plural
fn parse_capi_resource_type(
    resource_type: &str,
) -> Result<(String, String, String, String), PivotError> {
    // Resource types like "clusters.cluster.x-k8s.io"
    let parts: Vec<&str> = resource_type.splitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(PivotError::Internal(format!(
            "invalid resource type: {}",
            resource_type
        )));
    }

    let plural = parts[0].to_string();
    let group = parts[1].to_string();

    // Derive kind from plural (simple heuristic)
    let kind = if plural.ends_with("ies") {
        format!("{}y", &plural[..plural.len() - 3])
    } else if plural.ends_with('s') {
        plural[..plural.len() - 1].to_string()
    } else {
        plural.clone()
    };

    // Capitalize first letter
    let kind = kind
        .chars()
        .enumerate()
        .map(|(i, c)| if i == 0 { c.to_ascii_uppercase() } else { c })
        .collect();

    Ok((group, "v1beta1".to_string(), kind, plural))
}

/// Pivot handler for the agent side
///
/// Used by the agent to detect when CAPI resources have been imported after pivot.
pub struct AgentPivotHandler<R: CommandRunner = RealCommandRunner> {
    /// CAPI namespace to watch
    capi_namespace: String,
    /// Command runner
    runner: R,
}

impl AgentPivotHandler<RealCommandRunner> {
    /// Create a new agent pivot handler
    pub fn new() -> Self {
        Self {
            capi_namespace: "default".to_string(),
            runner: RealCommandRunner,
        }
    }
}

impl<R: CommandRunner> AgentPivotHandler<R> {
    /// Create with a custom runner (for testing)
    pub fn with_runner(runner: R) -> Self {
        Self {
            capi_namespace: "default".to_string(),
            runner,
        }
    }

    /// Set the CAPI namespace
    pub fn with_capi_namespace(mut self, namespace: &str) -> Self {
        self.capi_namespace = namespace.to_string();
        self
    }

    /// Get the configured namespace
    pub fn namespace(&self) -> &str {
        &self.capi_namespace
    }

    /// Check if CAPI resources exist in the cluster
    pub async fn check_capi_resources_present(&self) -> Result<bool, PivotError> {
        let output = self
            .runner
            .run_kubectl_get("clusters.cluster.x-k8s.io", &self.capi_namespace)
            .await?;

        let has_resources =
            !output.stdout.trim().is_empty() && !output.stdout.contains("No resources found");

        debug!(
            has_resources = has_resources,
            output = %output.stdout.trim(),
            "Checked for CAPI resources"
        );

        Ok(has_resources)
    }

    /// Wait for CAPI resources to be imported
    pub async fn wait_for_capi_resources(
        &self,
        timeout_duration: Duration,
        poll_interval: Duration,
    ) -> Result<u32, PivotError> {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout_duration {
            if self.check_capi_resources_present().await? {
                let count = self.count_capi_resources().await?;
                info!(count = count, "CAPI resources detected");
                return Ok(count);
            }

            tokio::time::sleep(poll_interval).await;
        }

        Err(PivotError::Timeout)
    }

    /// Count CAPI resources in the namespace
    async fn count_capi_resources(&self) -> Result<u32, PivotError> {
        let resource_types = [
            "clusters.cluster.x-k8s.io",
            "machines.cluster.x-k8s.io",
            "machinedeployments.cluster.x-k8s.io",
            "kubeadmcontrolplanes.controlplane.cluster.x-k8s.io",
        ];

        let mut total = 0;

        for resource_type in &resource_types {
            let output = self
                .runner
                .run_kubectl_get(resource_type, &self.capi_namespace)
                .await?;
            let count = output
                .stdout
                .lines()
                .filter(|l| !l.trim().is_empty())
                .count();
            total += count as u32;
        }

        Ok(total)
    }
}

impl Default for AgentPivotHandler<RealCommandRunner> {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Kubeconfig Patching for Self-Management
// =============================================================================

/// Patch the kubeconfig secret to use the internal Kubernetes service endpoint.
///
/// After clusterctl move, the kubeconfig secret contains the external network IP
/// (e.g., 172.18.0.3:6443 for Docker, or cloud provider load balancer IP).
/// For self-managing clusters, CAPI needs to reach the API server from within
/// the cluster, which requires using the internal service endpoint
/// (kubernetes.default.svc:443) instead.
///
/// This function patches ALL cluster entries in the kubeconfig, not just the first one,
/// to handle multi-cluster kubeconfigs correctly.
pub async fn patch_kubeconfig_for_self_management(
    cluster_name: &str,
    namespace: &str,
) -> Result<(), PivotError> {
    info!(cluster = %cluster_name, namespace = %namespace, "Patching kubeconfig for self-management");

    // Read the in-cluster CA certificate
    const IN_CLUSTER_CA_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
    let in_cluster_ca = std::fs::read_to_string(IN_CLUSTER_CA_PATH).map_err(|e| {
        PivotError::Internal(format!(
            "failed to read in-cluster CA from {}: {}",
            IN_CLUSTER_CA_PATH, e
        ))
    })?;
    let in_cluster_ca_b64 = STANDARD.encode(in_cluster_ca.as_bytes());

    let client = kube::Client::try_default()
        .await
        .map_err(|e| PivotError::Internal(format!("failed to create k8s client: {}", e)))?;

    let secrets: Api<Secret> = Api::namespaced(client, namespace);
    let secret_name = format!("{}-kubeconfig", cluster_name);

    let secret = secrets.get(&secret_name).await.map_err(|e| {
        PivotError::Internal(format!(
            "failed to get kubeconfig secret '{}': {}",
            secret_name, e
        ))
    })?;

    let data = secret
        .data
        .ok_or_else(|| PivotError::Internal("kubeconfig secret has no data".to_string()))?;
    let kubeconfig_bytes = data
        .get("value")
        .ok_or_else(|| PivotError::Internal("kubeconfig secret missing 'value' key".to_string()))?;

    let kubeconfig_str = String::from_utf8(kubeconfig_bytes.0.clone())
        .map_err(|e| PivotError::Internal(format!("kubeconfig is not valid UTF-8: {}", e)))?;

    let mut kubeconfig: serde_yaml::Value = serde_yaml::from_str(&kubeconfig_str)
        .map_err(|e| PivotError::Internal(format!("failed to parse kubeconfig YAML: {}", e)))?;

    // Update ALL cluster server URLs and CA certs to internal endpoint
    let mut updated_count = 0;
    if let Some(clusters) = kubeconfig
        .get_mut("clusters")
        .and_then(|c| c.as_sequence_mut())
    {
        for cluster in clusters {
            if let Some(cluster_config) = cluster.get_mut("cluster") {
                if let Some(server) = cluster_config.get_mut("server") {
                    let old_server = server.as_str().unwrap_or("unknown").to_string();
                    if !old_server.contains("kubernetes.default.svc") {
                        *server = serde_yaml::Value::String(
                            "https://kubernetes.default.svc:443".to_string(),
                        );

                        if let Some(m) = cluster_config.as_mapping_mut() {
                            m.remove("certificate-authority");
                            m.insert(
                                serde_yaml::Value::String("certificate-authority-data".to_string()),
                                serde_yaml::Value::String(in_cluster_ca_b64.clone()),
                            );
                        }

                        info!(
                            cluster = %cluster_name,
                            old_server = %old_server,
                            new_server = "https://kubernetes.default.svc:443",
                            "Updated kubeconfig server URL and CA"
                        );
                        updated_count += 1;
                    }
                }
            }
        }
    }

    if updated_count == 0 {
        debug!(cluster = %cluster_name, "Kubeconfig already uses internal endpoint, skipping patch");
        return Ok(());
    }

    let updated_kubeconfig = serde_yaml::to_string(&kubeconfig)
        .map_err(|e| PivotError::Internal(format!("failed to serialize kubeconfig: {}", e)))?;

    let encoded = STANDARD.encode(updated_kubeconfig.as_bytes());

    let patch = serde_json::json!({
        "data": {
            "value": encoded
        }
    });

    secrets
        .patch(
            &secret_name,
            &PatchParams::apply("lattice"),
            &Patch::Merge(&patch),
        )
        .await
        .map_err(|e| PivotError::Internal(format!("failed to patch kubeconfig secret: {}", e)))?;

    info!(
        cluster = %cluster_name,
        updated_servers = updated_count,
        "Kubeconfig patched for self-management"
    );
    Ok(())
}

/// Patch a child cluster's kubeconfig to use the central proxy
///
/// Updates the server URL to point to the internal central proxy service
/// with path-based routing: `/cluster/{cluster_name}`. Includes CA cert for TLS.
pub async fn patch_kubeconfig_for_child_cluster(
    cluster_name: &str,
    namespace: &str,
    proxy_url: &str,
    ca_cert_pem: &str,
) -> Result<(), PivotError> {
    let client = Client::try_default()
        .await
        .map_err(|e| PivotError::Internal(format!("failed to create k8s client: {}", e)))?;

    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let secret_name = format!("{}-kubeconfig", cluster_name);

    info!(
        cluster = %cluster_name,
        namespace = %namespace,
        secret = %secret_name,
        "Patching kubeconfig for child cluster to use central proxy"
    );

    let secret = secrets.get(&secret_name).await.map_err(|e| {
        PivotError::Internal(format!(
            "failed to get kubeconfig secret '{}': {}",
            secret_name, e
        ))
    })?;

    let kubeconfig_bytes = secret
        .data
        .as_ref()
        .and_then(|d| d.get("value"))
        .ok_or_else(|| PivotError::Internal("kubeconfig secret missing 'value' key".to_string()))?;

    let kubeconfig_str = String::from_utf8(kubeconfig_bytes.0.clone())
        .map_err(|e| PivotError::Internal(format!("kubeconfig is not valid UTF-8: {}", e)))?;

    let mut kubeconfig: serde_yaml::Value = serde_yaml::from_str(&kubeconfig_str)
        .map_err(|e| PivotError::Internal(format!("failed to parse kubeconfig YAML: {}", e)))?;

    let proxy_server = format!("{}/cluster/{}", proxy_url, cluster_name);

    let mut updated_count = 0;
    if let Some(clusters) = kubeconfig
        .get_mut("clusters")
        .and_then(|c| c.as_sequence_mut())
    {
        for cluster in clusters {
            if let Some(cluster_config) = cluster.get_mut("cluster") {
                if let Some(server) = cluster_config.get_mut("server") {
                    let old_server = server.as_str().unwrap_or("unknown").to_string();
                    if !old_server.contains("/cluster/") {
                        *server = serde_yaml::Value::String(proxy_server.clone());
                        let ca_cert_b64 = STANDARD.encode(ca_cert_pem.as_bytes());
                        cluster_config["certificate-authority-data"] =
                            serde_yaml::Value::String(ca_cert_b64);
                        info!(
                            cluster = %cluster_name,
                            old_server = %old_server,
                            new_server = %proxy_server,
                            "Updated kubeconfig server URL to use central proxy"
                        );
                        updated_count += 1;
                    }
                }
            }
        }
    }

    if updated_count == 0 {
        debug!(
            cluster = %cluster_name,
            "Kubeconfig already uses central proxy, skipping patch"
        );
        return Ok(());
    }

    let updated_kubeconfig = serde_yaml::to_string(&kubeconfig)
        .map_err(|e| PivotError::Internal(format!("failed to serialize kubeconfig: {}", e)))?;

    let encoded = STANDARD.encode(updated_kubeconfig.as_bytes());

    let patch = serde_json::json!({
        "data": {
            "value": encoded
        }
    });

    secrets
        .patch(
            &secret_name,
            &PatchParams::apply("lattice"),
            &Patch::Merge(&patch),
        )
        .await
        .map_err(|e| PivotError::Internal(format!("failed to patch kubeconfig secret: {}", e)))?;

    info!(
        cluster = %cluster_name,
        updated_servers = updated_count,
        "Kubeconfig patched to use central proxy"
    );

    Ok(())
}

/// URL for the internal central proxy service (HTTPS)
pub const CENTRAL_PROXY_SERVICE_URL: &str = "https://lattice-proxy.lattice-system.svc:8081";

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // ==========================================================================
    // Mock Command Runner for Testing AgentPivotHandler
    // ==========================================================================

    type KubectlMockFn = Box<dyn Fn(&str, &str) -> Result<CommandOutput, PivotError> + Send + Sync>;

    #[derive(Clone)]
    pub struct MockCommandRunner {
        kubectl_fn: std::sync::Arc<Mutex<Option<KubectlMockFn>>>,
    }

    impl MockCommandRunner {
        pub fn new() -> Self {
            Self {
                kubectl_fn: std::sync::Arc::new(Mutex::new(None)),
            }
        }

        pub fn with_kubectl<F>(self, f: F) -> Self
        where
            F: Fn(&str, &str) -> Result<CommandOutput, PivotError> + Send + Sync + 'static,
        {
            *self.kubectl_fn.lock().unwrap() = Some(Box::new(f));
            self
        }
    }

    #[async_trait::async_trait]
    impl CommandRunner for MockCommandRunner {
        async fn run_kubectl_get(
            &self,
            resource_type: &str,
            namespace: &str,
        ) -> Result<CommandOutput, PivotError> {
            let guard = self.kubectl_fn.lock().unwrap();
            match &*guard {
                Some(f) => f(resource_type, namespace),
                None => Ok(CommandOutput {
                    success: true,
                    stdout: String::new(),
                    stderr: String::new(),
                }),
            }
        }
    }

    // ==========================================================================
    // AgentPivotHandler Tests
    // ==========================================================================

    #[tokio::test]
    async fn agent_detects_capi_resources() {
        let mock = MockCommandRunner::new().with_kubectl(|_, _| {
            Ok(CommandOutput {
                success: true,
                stdout: "my-cluster   True   v1.28.0   5m\n".to_string(),
                stderr: String::new(),
            })
        });

        let handler = AgentPivotHandler::with_runner(mock);
        let has_resources = handler.check_capi_resources_present().await.unwrap();
        assert!(has_resources);
    }

    #[tokio::test]
    async fn agent_detects_no_capi_resources() {
        let mock = MockCommandRunner::new().with_kubectl(|_, _| {
            Ok(CommandOutput {
                success: true,
                stdout: "No resources found in default namespace.\n".to_string(),
                stderr: String::new(),
            })
        });

        let handler = AgentPivotHandler::with_runner(mock);
        let has_resources = handler.check_capi_resources_present().await.unwrap();
        assert!(!has_resources);
    }

    #[tokio::test]
    async fn agent_counts_all_capi_resource_types() {
        let mock = MockCommandRunner::new().with_kubectl(|resource_type, _| {
            let stdout = match resource_type {
                "clusters.cluster.x-k8s.io" => "my-cluster   True",
                "machines.cluster.x-k8s.io" => "cp-0   Running\ncp-1   Running\nworker-0   Running",
                "machinedeployments.cluster.x-k8s.io" => "md-0   3   3   3",
                "kubeadmcontrolplanes.controlplane.cluster.x-k8s.io" => "cp   Initialized",
                _ => "",
            };
            Ok(CommandOutput {
                success: true,
                stdout: stdout.to_string(),
                stderr: String::new(),
            })
        });

        let handler = AgentPivotHandler::with_runner(mock);
        let count = handler.count_capi_resources().await.unwrap();
        // 1 cluster + 3 machines + 1 machinedeployment + 1 controlplane = 6
        assert_eq!(count, 6);
    }

    #[tokio::test]
    async fn wait_times_out_when_no_resources() {
        let mock = MockCommandRunner::new().with_kubectl(|_, _| {
            Ok(CommandOutput {
                success: true,
                stdout: "No resources found in default namespace.\n".to_string(),
                stderr: String::new(),
            })
        });

        let handler = AgentPivotHandler::with_runner(mock);
        let result = handler
            .wait_for_capi_resources(Duration::from_millis(50), Duration::from_millis(10))
            .await;

        assert!(matches!(result, Err(PivotError::Timeout)));
    }

    #[tokio::test]
    async fn handler_uses_configured_namespace() {
        use std::sync::Arc;

        let captured_namespace = Arc::new(Mutex::new(String::new()));
        let ns_clone = captured_namespace.clone();

        let mock = MockCommandRunner::new().with_kubectl(move |_, namespace| {
            *ns_clone.lock().unwrap() = namespace.to_string();
            Ok(CommandOutput {
                success: true,
                stdout: "cluster-1   True\n".to_string(),
                stderr: String::new(),
            })
        });

        let handler = AgentPivotHandler::with_runner(mock).with_capi_namespace("workload-ns");
        let _ = handler
            .wait_for_capi_resources(Duration::from_secs(1), Duration::from_millis(10))
            .await;

        assert_eq!(*captured_namespace.lock().unwrap(), "workload-ns");
    }

    #[test]
    fn handler_default_namespace() {
        let handler = AgentPivotHandler::default();
        assert_eq!(handler.namespace(), "default");
    }

    // ==========================================================================
    // Error Display Tests
    // ==========================================================================

    #[test]
    fn error_display() {
        assert_eq!(
            PivotError::ClusterctlFailed("cmd error".to_string()).to_string(),
            "clusterctl failed: cmd error"
        );
        assert_eq!(
            PivotError::KubeconfigFailed("io error".to_string()).to_string(),
            "kubeconfig generation failed: io error"
        );
        assert_eq!(PivotError::Timeout.to_string(), "pivot timed out");
        assert_eq!(
            PivotError::AgentNotConnected("cluster-1".to_string()).to_string(),
            "agent not connected: cluster-1"
        );
        assert_eq!(
            PivotError::Internal("panic".to_string()).to_string(),
            "internal error: panic"
        );
    }
}
