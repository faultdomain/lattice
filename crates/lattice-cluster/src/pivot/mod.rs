//! Pivot logic for cluster self-management
//!
//! The pivot process transfers CAPI resources from the cell to a workload cluster,
//! making the workload cluster self-managing.
//!
//! # Flow
//!
//! 1. Cell exports CAPI manifests via `clusterctl move --to-directory`
//! 2. Cell sends manifests to agent via gRPC PivotManifestsCommand
//! 3. Agent imports manifests via `clusterctl move --from-directory`
//! 4. Agent patches kubeconfig to use internal endpoint
//! 5. Cluster is now self-managing
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
pub use lattice_common::retry::{retry_with_backoff, RetryConfig};

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
    ///
    /// This is the new pivot flow using --to-directory:
    /// 1. Cell exports manifests via `clusterctl move --to-directory`
    /// 2. Cell sends manifests to agent via gRPC PivotManifestsCommand
    /// 3. Agent saves manifests to temp directory
    /// 4. Agent imports via `clusterctl move --from-directory`
    ///
    /// This approach keeps paused resources on the parent, simplifying unpivot.
    pub async fn import_capi_manifests(
        &self,
        manifests: &[Vec<u8>],
        cluster_name: &str,
    ) -> Result<usize, PivotError> {
        use std::io::Write;
        use std::process::Stdio;

        if manifests.is_empty() {
            return Err(PivotError::Internal("no manifests to import".to_string()));
        }

        // Create temp directory for manifests
        let temp_dir = std::env::temp_dir().join(format!(
            "lattice-pivot-{}-{}",
            cluster_name,
            std::process::id()
        ));

        std::fs::create_dir_all(&temp_dir)
            .map_err(|e| PivotError::Internal(format!("failed to create temp dir: {}", e)))?;

        info!(
            manifest_count = manifests.len(),
            temp_dir = %temp_dir.display(),
            "Saving CAPI manifests to temp directory"
        );

        // Write each manifest to a file
        let mut saved_count = 0;
        for (i, manifest) in manifests.iter().enumerate() {
            let filename = temp_dir.join(format!("manifest-{:04}.yaml", i));
            let mut file = std::fs::File::create(&filename).map_err(|e| {
                PivotError::Internal(format!("failed to create manifest file: {}", e))
            })?;
            file.write_all(manifest)
                .map_err(|e| PivotError::Internal(format!("failed to write manifest: {}", e)))?;
            saved_count += 1;
        }

        info!(
            saved_count = saved_count,
            "Manifests saved, running clusterctl move --from-directory"
        );

        // Run clusterctl move --from-directory to import resources
        // The agent is running in-cluster, so clusterctl uses the default in-cluster config
        let output = tokio::process::Command::new("clusterctl")
            .arg("move")
            .arg("--from-directory")
            .arg(&temp_dir)
            .arg("--namespace")
            .arg(&self.capi_namespace)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                PivotError::ClusterctlFailed(format!("failed to run clusterctl: {}", e))
            })?;

        // Clean up temp directory
        if let Err(e) = std::fs::remove_dir_all(&temp_dir) {
            debug!(error = %e, "Failed to clean up temp directory (non-fatal)");
        }

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PivotError::ClusterctlFailed(format!(
                "clusterctl move failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        info!(output = %stdout.trim(), "clusterctl move completed successfully");

        // Wait briefly for resources to appear, then count them
        tokio::time::sleep(POST_MOVE_STABILIZATION_DELAY).await;
        let count = self
            .count_capi_resources()
            .await
            .unwrap_or(saved_count as u32);

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

/// Read and base64-encode the in-cluster CA certificate.
fn read_in_cluster_ca_base64() -> Result<String, PivotError> {
    let in_cluster_ca = std::fs::read_to_string(IN_CLUSTER_CA_PATH).map_err(|e| {
        PivotError::Internal(format!(
            "failed to read in-cluster CA from {}: {}",
            IN_CLUSTER_CA_PATH, e
        ))
    })?;
    Ok(STANDARD.encode(in_cluster_ca.as_bytes()))
}

/// Fetch and decode the kubeconfig from a Kubernetes secret.
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

/// Update a single cluster entry in the kubeconfig to use the internal endpoint.
///
/// Returns `true` if the cluster was updated, `false` if it already uses the internal endpoint.
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

    // Update server URL
    *server = serde_yaml::Value::String(INTERNAL_K8S_ENDPOINT.to_string());

    // Update CA certificate
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

/// Update all cluster entries in the kubeconfig to use the internal endpoint.
///
/// Returns the number of clusters that were updated.
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

/// Apply the updated kubeconfig to the secret.
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

/// Label selector for distributable resources
const DISTRIBUTE_LABEL: &str = "lattice.io/distribute=true";

/// Resources labeled for distribution to child clusters
#[derive(Debug, Default, Clone)]
pub struct DistributableResources {
    /// Secrets (credentials, tokens, keys)
    pub secrets: Vec<Vec<u8>>,
    /// ConfigMaps (configuration, feature flags)
    pub configmaps: Vec<Vec<u8>>,
}

impl DistributableResources {
    /// Check if there are any resources to distribute
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty() && self.configmaps.is_empty()
    }
}

/// Fetch all resources labeled for distribution from lattice-system namespace.
///
/// Resources with label `lattice.io/distribute: "true"` are sent to child clusters
/// during pivot and via periodic sync. Use cases:
/// - Secrets: provider credentials, ESO vault creds, registry pull secrets
/// - ConfigMaps: feature flags, environment config, operator settings
pub async fn fetch_distributable_resources(
    client: &Client,
) -> Result<DistributableResources, PivotError> {
    use k8s_openapi::api::core::v1::ConfigMap;
    use kube::api::ListParams;

    let lp = ListParams::default().labels(DISTRIBUTE_LABEL);

    // Fetch secrets
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), "lattice-system");
    let secrets_list = secret_api
        .list(&lp)
        .await
        .map_err(|e| PivotError::Internal(format!("failed to list secrets: {}", e)))?;

    let mut secrets = Vec::new();
    for secret in secrets_list.items {
        let yaml = serialize_for_distribution(&secret)?;
        secrets.push(yaml);
    }

    // Fetch configmaps
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), "lattice-system");
    let cms_list = cm_api
        .list(&lp)
        .await
        .map_err(|e| PivotError::Internal(format!("failed to list configmaps: {}", e)))?;

    let mut configmaps = Vec::new();
    for cm in cms_list.items {
        let yaml = serialize_for_distribution(&cm)?;
        configmaps.push(yaml);
    }

    debug!(
        secrets = secrets.len(),
        configmaps = configmaps.len(),
        "fetched distributable resources"
    );
    Ok(DistributableResources {
        secrets,
        configmaps,
    })
}

/// Serialize a Kubernetes resource for distribution, stripping cluster-specific metadata
fn serialize_for_distribution<
    T: serde::Serialize
        + Clone
        + k8s_openapi::Metadata<Ty = k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta>,
>(
    resource: &T,
) -> Result<Vec<u8>, PivotError> {
    let mut clean = resource.clone();
    let meta = clean.metadata_mut();
    meta.uid = None;
    meta.resource_version = None;
    meta.creation_timestamp = None;
    meta.managed_fields = None;

    serde_yaml::to_string(&clean)
        .map(|s| s.into_bytes())
        .map_err(|e| PivotError::Internal(format!("failed to serialize resource: {}", e)))
}

/// Apply distributed resources to the lattice-system namespace.
///
/// During pivot and periodic sync, parent clusters send resources labeled
/// `lattice.io/distribute: "true"` to child clusters.
pub async fn apply_distributed_resources(
    resources: &DistributableResources,
) -> Result<(), PivotError> {
    use k8s_openapi::api::core::v1::ConfigMap;
    use kube::api::{Patch, PatchParams};

    if resources.is_empty() {
        return Ok(());
    }

    let client = kube::Client::try_default()
        .await
        .map_err(|e| PivotError::Internal(format!("failed to create k8s client: {}", e)))?;

    let params = PatchParams::apply("lattice-pivot").force();

    // Apply secrets
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), "lattice-system");
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

    // Apply configmaps
    let cm_api: Api<ConfigMap> = Api::namespaced(client, "lattice-system");
    for cm_bytes in &resources.configmaps {
        let yaml_str = String::from_utf8_lossy(cm_bytes);
        let cm: ConfigMap = serde_yaml::from_str(&yaml_str)
            .map_err(|e| PivotError::Internal(format!("failed to parse configmap YAML: {}", e)))?;

        let name = cm
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| PivotError::Internal("configmap has no name".to_string()))?;

        cm_api
            .patch(name, &params, &Patch::Apply(&cm))
            .await
            .map_err(|e| {
                PivotError::Internal(format!("failed to apply configmap {}: {}", name, e))
            })?;

        info!(configmap = %name, "Applied distributed configmap");
    }

    Ok(())
}

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

    // ==========================================================================
    // Mock Command Runner for Testing AgentPivotHandler
    // ==========================================================================

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
            *self
                .list_fn
                .lock()
                .expect("list_fn mutex should not be poisoned") = Some(Box::new(f));
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
            let guard = self
                .list_fn
                .lock()
                .expect("list_fn mutex should not be poisoned");
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
    async fn agent_counts_all_capi_resource_types() {
        let mock = MockCommandRunner::new().with_list(|resource_type, _| {
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
        let count = handler
            .count_capi_resources()
            .await
            .expect("counting CAPI resources should succeed");
        // 1 cluster + 3 machines + 1 machinedeployment + 1 controlplane = 6
        assert_eq!(count, 6);
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
        assert_eq!(
            PivotError::Internal("panic".to_string()).to_string(),
            "internal error: panic"
        );
    }

    // ==========================================================================
    // apply_distributed_resources Tests
    // ==========================================================================

    /// Story: Empty resources should succeed immediately
    #[tokio::test]
    async fn apply_distributed_resources_empty_succeeds() {
        let resources = DistributableResources::default();
        let result = apply_distributed_resources(&resources).await;
        assert!(result.is_ok());
    }

    /// Story: Invalid YAML should return an error
    #[tokio::test]
    async fn apply_distributed_resources_invalid_yaml_fails() {
        // This test runs even without a K8s cluster because parsing happens before API calls
        let invalid_yaml = b"not: valid: yaml: [unclosed".to_vec();
        let resources = DistributableResources {
            secrets: vec![invalid_yaml],
            configmaps: vec![],
        };
        let result = apply_distributed_resources(&resources).await;

        // Without a K8s cluster, it will fail on client creation first
        // With a K8s cluster, it will fail on YAML parsing
        assert!(result.is_err());
    }

    /// Story: Secret without a name should return an error
    #[tokio::test]
    async fn apply_distributed_resources_missing_name_fails() {
        // Skip if no K8s cluster (parsing happens after client creation)
        if kube::Client::try_default().await.is_err() {
            eprintln!("Skipping test: no K8s cluster available");
            return;
        }

        let nameless_secret = r#"
apiVersion: v1
kind: Secret
metadata:
  namespace: lattice-system
data:
  key: dmFsdWU=
"#;
        let resources = DistributableResources {
            secrets: vec![nameless_secret.as_bytes().to_vec()],
            configmaps: vec![],
        };
        let result = apply_distributed_resources(&resources).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("secret has no name"),
            "Expected 'secret has no name' error, got: {}",
            err
        );
    }

    /// Story: Valid secret YAML should be parsed correctly
    #[test]
    fn secret_yaml_parsing_works() {
        let valid_secret = r#"
apiVersion: v1
kind: Secret
metadata:
  name: test-secret
  namespace: lattice-system
  labels:
    lattice.io/distribute: "true"
data:
  key: dmFsdWU=
"#;
        let secret: Secret =
            serde_yaml::from_str(valid_secret).expect("valid secret YAML should parse");
        assert_eq!(secret.metadata.name.as_deref(), Some("test-secret"));
    }

    /// Story: DistributableResources is_empty works correctly
    #[test]
    fn distributable_resources_is_empty() {
        let empty = DistributableResources::default();
        assert!(empty.is_empty());

        let with_secrets = DistributableResources {
            secrets: vec![vec![1, 2, 3]],
            configmaps: vec![],
        };
        assert!(!with_secrets.is_empty());

        let with_configmaps = DistributableResources {
            secrets: vec![],
            configmaps: vec![vec![1, 2, 3]],
        };
        assert!(!with_configmaps.is_empty());
    }
}
