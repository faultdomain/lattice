//! Pivot logic for cluster self-management (agent-side)
//!
//! This module handles the agent-side of the pivot process:
//! - Importing CAPI manifests received from the cell
//! - Patching kubeconfig for self-management
//! - Applying distributed resources

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use thiserror::Error;
use tracing::{debug, info};

use lattice_common::crd::{CloudProvider, SecretsProvider};
pub use lattice_common::retry::{retry_with_backoff, RetryConfig};
pub use lattice_common::DistributableResources;
use lattice_common::LATTICE_SYSTEM_NAMESPACE;

/// Default CAPI namespace for pivot handlers
const DEFAULT_CAPI_NAMESPACE: &str = "default";

/// Delay after clusterctl move to allow resources to appear in the API server
const POST_MOVE_STABILIZATION_DELAY: Duration = Duration::from_secs(2);

/// Path to the in-cluster CA certificate
const IN_CLUSTER_CA_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

/// Internal Kubernetes service endpoint for self-management
const INTERNAL_K8S_ENDPOINT: &str = "https://kubernetes.default.svc:443";

/// Pivot errors
#[derive(Debug, Error)]
pub enum PivotError {
    /// Clusterctl command failed
    #[error("clusterctl failed: {0}")]
    ClusterctlFailed(String),

    /// Kubeconfig generation failed
    #[error("kubeconfig generation failed: {0}")]
    KubeconfigFailed(String),

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
    async fn list_resources(
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
    async fn list_resources(
        &self,
        resource_type: &str,
        namespace: &str,
    ) -> Result<CommandOutput, PivotError> {
        use kube::api::{Api, DynamicObject, ListParams};
        use kube::discovery::ApiResource;

        let client = Client::try_default()
            .await
            .map_err(|e| PivotError::Internal(format!("k8s client failed: {}", e)))?;

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
            if e.to_string().contains("not found") || e.to_string().contains("404") {
                return PivotError::Internal("not found".to_string());
            }
            PivotError::Internal(format!("list failed: {}", e))
        })?;

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
    let parts: Vec<&str> = resource_type.splitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(PivotError::Internal(format!(
            "invalid resource type: {}",
            resource_type
        )));
    }

    let plural = parts[0].to_string();
    let group = parts[1].to_string();

    let kind = if plural.ends_with("ies") {
        format!("{}y", &plural[..plural.len() - 3])
    } else if plural.ends_with('s') {
        plural[..plural.len() - 1].to_string()
    } else {
        plural.clone()
    };

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
    capi_namespace: String,
    runner: R,
}

impl AgentPivotHandler<RealCommandRunner> {
    /// Create a new agent pivot handler
    pub fn new() -> Self {
        Self::with_runner(RealCommandRunner)
    }
}

impl<R: CommandRunner> AgentPivotHandler<R> {
    /// Create with a custom runner (for testing)
    pub fn with_runner(runner: R) -> Self {
        Self {
            capi_namespace: DEFAULT_CAPI_NAMESPACE.to_string(),
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
                .list_resources(resource_type, &self.capi_namespace)
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

    /// Import CAPI manifests received via gRPC
    pub async fn import_capi_manifests(
        &self,
        manifests: &[Vec<u8>],
        _cluster_name: &str,
    ) -> Result<usize, PivotError> {
        if manifests.is_empty() {
            return Err(PivotError::Internal("no manifests to import".to_string()));
        }

        let manifest_count = manifests.len();

        lattice_common::clusterctl::import_from_manifests(None, &self.capi_namespace, manifests)
            .await
            .map_err(|e| PivotError::ClusterctlFailed(e.to_string()))?;

        tokio::time::sleep(POST_MOVE_STABILIZATION_DELAY).await;
        let count = self
            .count_capi_resources()
            .await
            .unwrap_or(manifest_count as u32);

        Ok(count as usize)
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

fn read_in_cluster_ca_base64() -> Result<String, PivotError> {
    let in_cluster_ca = std::fs::read_to_string(IN_CLUSTER_CA_PATH).map_err(|e| {
        PivotError::Internal(format!(
            "failed to read in-cluster CA from {}: {}",
            IN_CLUSTER_CA_PATH, e
        ))
    })?;
    Ok(STANDARD.encode(in_cluster_ca.as_bytes()))
}

async fn fetch_kubeconfig_from_secret(
    secrets: &Api<Secret>,
    secret_name: &str,
) -> Result<serde_yaml::Value, PivotError> {
    let secret = secrets.get(secret_name).await.map_err(|e| {
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

    serde_yaml::from_str(&kubeconfig_str)
        .map_err(|e| PivotError::Internal(format!("failed to parse kubeconfig YAML: {}", e)))
}

fn update_cluster_entry(
    cluster_entry: &mut serde_yaml::Value,
    in_cluster_ca_b64: &str,
    cluster_name: &str,
) -> bool {
    let Some(cluster_config) = cluster_entry.get_mut("cluster") else {
        return false;
    };

    let Some(server) = cluster_config.get_mut("server") else {
        return false;
    };

    let old_server = server.as_str().unwrap_or("unknown").to_string();
    if old_server.contains("kubernetes.default.svc") {
        return false;
    }

    *server = serde_yaml::Value::String(INTERNAL_K8S_ENDPOINT.to_string());

    if let Some(m) = cluster_config.as_mapping_mut() {
        m.remove("certificate-authority");
        m.insert(
            serde_yaml::Value::String("certificate-authority-data".to_string()),
            serde_yaml::Value::String(in_cluster_ca_b64.to_string()),
        );
    }

    info!(
        cluster = %cluster_name,
        old_server = %old_server,
        new_server = INTERNAL_K8S_ENDPOINT,
        "Updated kubeconfig server URL and CA"
    );

    true
}

fn update_all_cluster_entries(
    kubeconfig: &mut serde_yaml::Value,
    in_cluster_ca_b64: &str,
    cluster_name: &str,
) -> usize {
    let Some(clusters) = kubeconfig
        .get_mut("clusters")
        .and_then(|c| c.as_sequence_mut())
    else {
        return 0;
    };

    clusters
        .iter_mut()
        .filter_map(|entry| {
            if update_cluster_entry(entry, in_cluster_ca_b64, cluster_name) {
                Some(())
            } else {
                None
            }
        })
        .count()
}

async fn apply_kubeconfig_patch(
    secrets: &Api<Secret>,
    secret_name: &str,
    kubeconfig: &serde_yaml::Value,
) -> Result<(), PivotError> {
    let updated_kubeconfig = serde_yaml::to_string(kubeconfig)
        .map_err(|e| PivotError::Internal(format!("failed to serialize kubeconfig: {}", e)))?;

    let encoded = STANDARD.encode(updated_kubeconfig.as_bytes());

    let patch = serde_json::json!({
        "data": {
            "value": encoded
        }
    });

    secrets
        .patch(
            secret_name,
            &PatchParams::apply("lattice"),
            &Patch::Merge(&patch),
        )
        .await
        .map_err(|e| PivotError::Internal(format!("failed to patch kubeconfig secret: {}", e)))?;

    Ok(())
}

/// Apply distributed resources to the lattice-system namespace.
pub async fn apply_distributed_resources(
    client: &Client,
    resources: &DistributableResources,
) -> Result<(), PivotError> {
    if resources.is_empty() {
        return Ok(());
    }

    let params = PatchParams::apply("lattice-pivot").force();

    // Apply secrets first (credentials needed by providers)
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    for secret_bytes in &resources.secrets {
        let yaml_str = String::from_utf8_lossy(secret_bytes);
        let secret: Secret = serde_yaml::from_str(&yaml_str)
            .map_err(|e| PivotError::Internal(format!("failed to parse secret YAML: {}", e)))?;

        let name = secret
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| PivotError::Internal("secret has no name".to_string()))?;

        secret_api
            .patch(name, &params, &Patch::Apply(&secret))
            .await
            .map_err(|e| PivotError::Internal(format!("failed to apply secret {}: {}", name, e)))?;

        info!(secret = %name, "Applied distributed secret");
    }

    // Apply CloudProviders
    let cp_api: Api<CloudProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    for cp_bytes in &resources.cloud_providers {
        let yaml_str = String::from_utf8_lossy(cp_bytes);
        let cp: CloudProvider = serde_yaml::from_str(&yaml_str).map_err(|e| {
            PivotError::Internal(format!("failed to parse CloudProvider YAML: {}", e))
        })?;

        let name = cp
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| PivotError::Internal("CloudProvider has no name".to_string()))?;

        cp_api
            .patch(name, &params, &Patch::Apply(&cp))
            .await
            .map_err(|e| {
                PivotError::Internal(format!("failed to apply CloudProvider {}: {}", name, e))
            })?;

        info!(cloud_provider = %name, "Applied distributed CloudProvider");
    }

    // Apply SecretsProviders
    let sp_api: Api<SecretsProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    for sp_bytes in &resources.secrets_providers {
        let yaml_str = String::from_utf8_lossy(sp_bytes);
        let sp: SecretsProvider = serde_yaml::from_str(&yaml_str).map_err(|e| {
            PivotError::Internal(format!("failed to parse SecretsProvider YAML: {}", e))
        })?;

        let name = sp
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| PivotError::Internal("SecretsProvider has no name".to_string()))?;

        sp_api
            .patch(name, &params, &Patch::Apply(&sp))
            .await
            .map_err(|e| {
                PivotError::Internal(format!("failed to apply SecretsProvider {}: {}", name, e))
            })?;

        info!(secrets_provider = %name, "Applied distributed SecretsProvider");
    }

    Ok(())
}

/// Patch the kubeconfig secret to use the internal Kubernetes service endpoint.
pub async fn patch_kubeconfig_for_self_management(
    cluster_name: &str,
    namespace: &str,
) -> Result<(), PivotError> {
    info!(cluster = %cluster_name, namespace = %namespace, "Patching kubeconfig for self-management");

    let in_cluster_ca_b64 = read_in_cluster_ca_base64()?;

    let client = kube::Client::try_default()
        .await
        .map_err(|e| PivotError::Internal(format!("failed to create k8s client: {}", e)))?;

    let secrets: Api<Secret> = Api::namespaced(client, namespace);
    let secret_name = format!("{}-kubeconfig", cluster_name);

    let mut kubeconfig = fetch_kubeconfig_from_secret(&secrets, &secret_name).await?;

    let updated_count =
        update_all_cluster_entries(&mut kubeconfig, &in_cluster_ca_b64, cluster_name);

    if updated_count == 0 {
        debug!(cluster = %cluster_name, "Kubeconfig already uses internal endpoint, skipping patch");
        return Ok(());
    }

    apply_kubeconfig_patch(&secrets, &secret_name, &kubeconfig).await?;

    info!(
        cluster = %cluster_name,
        updated_servers = updated_count,
        "Kubeconfig patched for self-management"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    type ListFn = Box<dyn Fn(&str, &str) -> Result<CommandOutput, PivotError> + Send + Sync>;

    #[derive(Clone)]
    pub struct MockCommandRunner {
        list_fn: std::sync::Arc<Mutex<Option<ListFn>>>,
    }

    impl MockCommandRunner {
        pub fn new() -> Self {
            Self {
                list_fn: std::sync::Arc::new(Mutex::new(None)),
            }
        }

        pub fn with_list<F>(self, f: F) -> Self
        where
            F: Fn(&str, &str) -> Result<CommandOutput, PivotError> + Send + Sync + 'static,
        {
            *self.list_fn.lock().unwrap() = Some(Box::new(f));
            self
        }
    }

    #[async_trait::async_trait]
    impl CommandRunner for MockCommandRunner {
        async fn list_resources(
            &self,
            resource_type: &str,
            namespace: &str,
        ) -> Result<CommandOutput, PivotError> {
            let guard = self.list_fn.lock().unwrap();
            if let Some(f) = guard.as_ref() {
                f(resource_type, namespace)
            } else {
                Ok(CommandOutput {
                    success: true,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }
        }
    }

    #[test]
    fn test_parse_capi_resource_type() {
        let (group, version, kind, plural) =
            parse_capi_resource_type("clusters.cluster.x-k8s.io").unwrap();
        assert_eq!(group, "cluster.x-k8s.io");
        assert_eq!(version, "v1beta1");
        assert_eq!(kind, "Cluster");
        assert_eq!(plural, "clusters");
    }

    #[test]
    fn test_parse_invalid_resource_type() {
        let result = parse_capi_resource_type("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_update_cluster_entry_updates_server() {
        let mut entry = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            name: test-cluster
            cluster:
              server: https://172.18.0.3:6443
              certificate-authority: /path/to/ca
            "#,
        )
        .unwrap();

        let updated = update_cluster_entry(&mut entry, "Y2EtZGF0YQ==", "test");
        assert!(updated);

        let server = entry["cluster"]["server"].as_str().unwrap();
        assert_eq!(server, INTERNAL_K8S_ENDPOINT);
    }

    #[test]
    fn test_update_cluster_entry_skips_already_internal() {
        let mut entry = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            name: test-cluster
            cluster:
              server: https://kubernetes.default.svc:443
            "#,
        )
        .unwrap();

        let updated = update_cluster_entry(&mut entry, "Y2EtZGF0YQ==", "test");
        assert!(!updated);
    }

    #[test]
    fn test_distributable_resources_is_empty() {
        let empty = DistributableResources::default();
        assert!(empty.is_empty());

        let with_cp = DistributableResources {
            cloud_providers: vec![vec![1, 2, 3]],
            ..Default::default()
        };
        assert!(!with_cp.is_empty());
    }

    // =========================================================================
    // AgentPivotHandler Tests
    // =========================================================================

    #[tokio::test]
    async fn test_pivot_handler_with_namespace() {
        let runner = MockCommandRunner::new();
        let handler = AgentPivotHandler::with_runner(runner).with_capi_namespace("custom-ns");

        assert_eq!(handler.namespace(), "custom-ns");
    }

    #[tokio::test]
    async fn test_pivot_handler_default_namespace() {
        let runner = MockCommandRunner::new();
        let handler = AgentPivotHandler::with_runner(runner);

        assert_eq!(handler.namespace(), DEFAULT_CAPI_NAMESPACE);
    }

    #[tokio::test]
    async fn test_count_capi_resources_empty() {
        let runner = MockCommandRunner::new().with_list(|_, _| {
            Ok(CommandOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            })
        });

        let handler = AgentPivotHandler::with_runner(runner);
        let count = handler.count_capi_resources().await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_count_capi_resources_with_resources() {
        let runner = MockCommandRunner::new().with_list(|resource_type, _| {
            // Return different counts for different resource types
            let stdout = match resource_type {
                "clusters.cluster.x-k8s.io" => "cluster-1\ncluster-2",
                "machines.cluster.x-k8s.io" => "machine-1\nmachine-2\nmachine-3",
                _ => "",
            };
            Ok(CommandOutput {
                success: true,
                stdout: stdout.to_string(),
                stderr: String::new(),
            })
        });

        let handler = AgentPivotHandler::with_runner(runner);
        let count = handler.count_capi_resources().await.unwrap();
        // 2 clusters + 3 machines = 5 (other types return 0)
        assert_eq!(count, 5);
    }

    #[tokio::test]
    async fn test_count_capi_resources_error_propagates() {
        let runner = MockCommandRunner::new().with_list(|_, _| {
            Err(PivotError::Internal("test error".to_string()))
        });

        let handler = AgentPivotHandler::with_runner(runner);
        let result = handler.count_capi_resources().await;
        assert!(result.is_err());
    }

    // =========================================================================
    // Parse CAPI Resource Type Tests
    // =========================================================================

    #[test]
    fn test_parse_capi_resource_type_machines() {
        let (group, version, kind, plural) =
            parse_capi_resource_type("machines.cluster.x-k8s.io").unwrap();
        assert_eq!(group, "cluster.x-k8s.io");
        assert_eq!(version, "v1beta1");
        assert_eq!(kind, "Machine");
        assert_eq!(plural, "machines");
    }

    #[test]
    fn test_parse_capi_resource_type_machinedeployments() {
        let (group, version, kind, plural) =
            parse_capi_resource_type("machinedeployments.cluster.x-k8s.io").unwrap();
        assert_eq!(group, "cluster.x-k8s.io");
        assert_eq!(version, "v1beta1");
        assert_eq!(kind, "Machinedeployment");
        assert_eq!(plural, "machinedeployments");
    }

    #[test]
    fn test_parse_capi_resource_type_kubeadmcontrolplanes() {
        let (group, version, kind, plural) =
            parse_capi_resource_type("kubeadmcontrolplanes.controlplane.cluster.x-k8s.io").unwrap();
        assert_eq!(group, "controlplane.cluster.x-k8s.io");
        assert_eq!(version, "v1beta1");
        assert_eq!(kind, "Kubeadmcontrolplane");
        assert_eq!(plural, "kubeadmcontrolplanes");
    }

    #[test]
    fn test_parse_capi_resource_type_policies() {
        // Test -ies -> -y conversion
        let (group, version, kind, plural) =
            parse_capi_resource_type("policies.policy.x-k8s.io").unwrap();
        assert_eq!(kind, "Policy");
        assert_eq!(plural, "policies");
    }

    // =========================================================================
    // Update All Cluster Entries Tests
    // =========================================================================

    #[test]
    fn test_update_all_cluster_entries_multiple() {
        let mut kubeconfig = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            clusters:
              - name: cluster-1
                cluster:
                  server: https://172.18.0.2:6443
                  certificate-authority: /path/to/ca
              - name: cluster-2
                cluster:
                  server: https://172.18.0.3:6443
            "#,
        )
        .unwrap();

        let count = update_all_cluster_entries(&mut kubeconfig, "Y2EtZGF0YQ==", "test");
        assert_eq!(count, 2);
    }

    #[test]
    fn test_update_all_cluster_entries_mixed() {
        let mut kubeconfig = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            clusters:
              - name: external
                cluster:
                  server: https://172.18.0.2:6443
              - name: internal
                cluster:
                  server: https://kubernetes.default.svc:443
            "#,
        )
        .unwrap();

        let count = update_all_cluster_entries(&mut kubeconfig, "Y2EtZGF0YQ==", "test");
        // Only the external one should be updated
        assert_eq!(count, 1);
    }

    #[test]
    fn test_update_all_cluster_entries_no_clusters() {
        let mut kubeconfig = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            apiVersion: v1
            kind: Config
            "#,
        )
        .unwrap();

        let count = update_all_cluster_entries(&mut kubeconfig, "Y2EtZGF0YQ==", "test");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_update_cluster_entry_missing_cluster_key() {
        let mut entry = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            name: test-cluster
            "#,
        )
        .unwrap();

        let updated = update_cluster_entry(&mut entry, "Y2EtZGF0YQ==", "test");
        assert!(!updated);
    }

    #[test]
    fn test_update_cluster_entry_missing_server() {
        let mut entry = serde_yaml::from_str::<serde_yaml::Value>(
            r#"
            name: test-cluster
            cluster:
              certificate-authority: /path/to/ca
            "#,
        )
        .unwrap();

        let updated = update_cluster_entry(&mut entry, "Y2EtZGF0YQ==", "test");
        assert!(!updated);
    }

}
