//! Shared Kubernetes utilities using kube-rs
//!
//! Provides kubectl-equivalent operations without shelling out to kubectl.
//! FIPS compliant - no external binaries needed.

use std::future::Future;
use std::path::Path;
use std::time::Duration;

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Namespace, Node, Secret};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, DynamicObject, ListParams, Patch, PatchParams, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::discovery::ApiResource;
use kube::{Client, Config};
use tracing::{debug, info, trace};

use crate::Error;

// Kubernetes condition type constants
/// The "Ready" condition type for nodes
pub const CONDITION_READY: &str = "Ready";
/// The "Available" condition type for deployments
pub const CONDITION_AVAILABLE: &str = "Available";
/// The "True" status value for conditions
pub const STATUS_TRUE: &str = "True";

/// Default polling interval for wait operations
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Strip cluster-specific metadata from a resource for export/distribution.
///
/// Removes fields that would cause server-side apply to fail on a target cluster:
/// - uid: Unique identifier in the source cluster
/// - resourceVersion: Optimistic concurrency version
/// - creationTimestamp: When the source resource was created
/// - managedFields: Server-side apply ownership tracking
/// - generation: Controller-managed generation counter
pub fn strip_export_metadata(
    meta: &mut k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
) {
    meta.uid = None;
    meta.resource_version = None;
    meta.creation_timestamp = None;
    meta.managed_fields = None;
    meta.generation = None;
}

/// Check if a Kubernetes condition of the given type has status "True"
///
/// This is a helper for checking conditions on nodes, deployments, and other
/// resources that use the standard Kubernetes condition format.
///
/// # Arguments
/// * `conditions` - Optional slice of conditions (e.g., from status.conditions)
/// * `condition_type` - The condition type to check (e.g., "Ready", "Available")
///
/// # Returns
/// `true` if a condition with the given type exists and has status "True"
pub fn has_condition<T>(conditions: Option<&[T]>, condition_type: &str) -> bool
where
    T: HasConditionFields,
{
    conditions
        .map(|conds| {
            conds
                .iter()
                .any(|c| c.type_field() == condition_type && c.status_field() == STATUS_TRUE)
        })
        .unwrap_or(false)
}

/// Trait for types that have condition-like fields (type and status)
pub trait HasConditionFields {
    /// Get the condition type field value
    fn type_field(&self) -> &str;
    /// Get the condition status field value
    fn status_field(&self) -> &str;
}

impl HasConditionFields for k8s_openapi::api::core::v1::NodeCondition {
    fn type_field(&self) -> &str {
        &self.type_
    }
    fn status_field(&self) -> &str {
        &self.status
    }
}

impl HasConditionFields for k8s_openapi::api::apps::v1::DeploymentCondition {
    fn type_field(&self) -> &str {
        &self.type_
    }
    fn status_field(&self) -> &str {
        &self.status
    }
}

/// Poll until a condition is met or timeout is reached
///
/// This is a generic polling function that repeatedly calls a check function
/// until it returns `Ok(true)` or the timeout is exceeded.
///
/// # Arguments
/// * `timeout` - Maximum time to wait for the condition
/// * `poll_interval` - Time between polling attempts
/// * `timeout_msg` - Error message to use on timeout
/// * `check_fn` - Async function that returns `Ok(true)` when condition is met,
///   `Ok(false)` to continue polling, or `Err` on failure
///
/// # Returns
/// `Ok(())` if the condition was met, or `Err` on timeout or check failure
pub async fn poll_until<F, Fut>(
    timeout: Duration,
    poll_interval: Duration,
    timeout_msg: impl Into<String>,
    mut check_fn: F,
) -> Result<(), Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool, Error>>,
{
    let start = std::time::Instant::now();
    let timeout_msg = timeout_msg.into();

    loop {
        if start.elapsed() > timeout {
            return Err(Error::internal_with_context("poll_until", timeout_msg));
        }

        match check_fn().await {
            Ok(true) => return Ok(()),
            Ok(false) => {
                // Condition not met, continue polling
                trace!("Polling condition not yet met, retrying...");
            }
            Err(e) => {
                // Log at trace level since polling failures are expected
                trace!("Polling check returned error (retrying): {}", e);
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Default connection timeout for kube clients
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default read timeout for kube clients
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Create a kube client from optional kubeconfig path with default timeouts
pub async fn create_client(kubeconfig: Option<&Path>) -> Result<Client, Error> {
    create_client_with_timeout(kubeconfig, DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT).await
}

/// Create a kube client from optional kubeconfig path with custom timeouts
pub async fn create_client_with_timeout(
    kubeconfig: Option<&Path>,
    connect_timeout: Duration,
    read_timeout: Duration,
) -> Result<Client, Error> {
    match kubeconfig {
        Some(path) => {
            let kubeconfig = Kubeconfig::read_from(path).map_err(|e| {
                Error::internal_with_context(
                    "create_client",
                    format!("failed to read kubeconfig: {}", e),
                )
            })?;
            let mut config =
                Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
                    .await
                    .map_err(|e| {
                        Error::internal_with_context(
                            "create_client",
                            format!("failed to load kubeconfig: {}", e),
                        )
                    })?;
            config.connect_timeout = Some(connect_timeout);
            config.read_timeout = Some(read_timeout);
            Client::try_from(config).map_err(|e| {
                Error::internal_with_context(
                    "create_client",
                    format!("failed to create client: {}", e),
                )
            })
        }
        None => {
            let mut config = Config::infer().await.map_err(|e| {
                Error::internal_with_context(
                    "create_client",
                    format!("failed to infer config: {}", e),
                )
            })?;
            config.connect_timeout = Some(connect_timeout);
            config.read_timeout = Some(read_timeout);
            Client::try_from(config).map_err(|e| {
                Error::internal_with_context(
                    "create_client",
                    format!("failed to create client: {}", e),
                )
            })
        }
    }
}

/// Wait for all nodes to be ready
pub async fn wait_for_nodes_ready(client: &Client, timeout: Duration) -> Result<(), Error> {
    let nodes: Api<Node> = Api::all(client.clone());

    poll_until(
        timeout,
        DEFAULT_POLL_INTERVAL,
        "Timeout waiting for nodes to be ready",
        || async {
            let node_list = nodes.list(&ListParams::default()).await.map_err(|e| {
                Error::internal_with_context(
                    "wait_for_nodes_ready",
                    format!("Failed to list nodes: {}", e),
                )
            })?;

            if node_list.items.is_empty() {
                return Ok(false);
            }

            let all_ready = node_list.items.iter().all(|node| {
                let conditions = node.status.as_ref().and_then(|s| s.conditions.as_ref());
                has_condition(conditions.map(|c| c.as_slice()), CONDITION_READY)
            });

            Ok(all_ready)
        },
    )
    .await
}

/// Wait for a deployment to be available
pub async fn wait_for_deployment(
    client: &Client,
    name: &str,
    namespace: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let name_owned = name.to_string();

    poll_until(
        timeout,
        DEFAULT_POLL_INTERVAL,
        format!("Timeout waiting for deployment {} to be available", name),
        || {
            let deployments = deployments.clone();
            let name = name_owned.clone();
            async move {
                match deployments.get(&name).await {
                    Ok(deployment) => {
                        let conditions = deployment
                            .status
                            .as_ref()
                            .and_then(|s| s.conditions.as_ref());
                        Ok(has_condition(
                            conditions.map(|c| c.as_slice()),
                            CONDITION_AVAILABLE,
                        ))
                    }
                    Err(kube::Error::Api(e)) if e.code == 404 => {
                        // Deployment doesn't exist yet, keep waiting
                        trace!("Deployment {} not found yet", name);
                        Ok(false)
                    }
                    Err(e) => Err(Error::internal_with_context(
                        "wait_for_deployment",
                        format!("Failed to get deployment {}: {}", name, e),
                    )),
                }
            }
        },
    )
    .await
}

/// Wait for all deployments in a namespace to be available
pub async fn wait_for_all_deployments(
    client: &Client,
    namespace: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let namespace_owned = namespace.to_string();

    poll_until(
        timeout,
        DEFAULT_POLL_INTERVAL,
        format!(
            "Timeout waiting for deployments in {} to be available",
            namespace
        ),
        || {
            let deployments = deployments.clone();
            let namespace = namespace_owned.clone();
            async move {
                let deployment_list =
                    deployments
                        .list(&ListParams::default())
                        .await
                        .map_err(|e| {
                            Error::internal_with_context(
                                "wait_for_all_deployments",
                                format!("Failed to list deployments in {}: {}", namespace, e),
                            )
                        })?;

                if deployment_list.items.is_empty() {
                    return Ok(false);
                }

                let all_available = deployment_list.items.iter().all(|deployment| {
                    let conditions = deployment
                        .status
                        .as_ref()
                        .and_then(|s| s.conditions.as_ref());
                    has_condition(conditions.map(|c| c.as_slice()), CONDITION_AVAILABLE)
                });

                Ok(all_available)
            }
        },
    )
    .await
}

/// Check if a CRD exists
pub async fn crd_exists(client: &Client, crd_name: &str) -> Result<bool, Error> {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());

    match crds.get(crd_name).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(false),
        Err(e) => Err(Error::internal_with_context(
            "crd_exists",
            format!("Failed to check CRD {}: {}", crd_name, e),
        )),
    }
}

/// Wait for a CRD to be available
pub async fn wait_for_crd(client: &Client, crd_name: &str, timeout: Duration) -> Result<(), Error> {
    let client_clone = client.clone();
    let crd_name_owned = crd_name.to_string();

    poll_until(
        timeout,
        DEFAULT_POLL_INTERVAL,
        format!("Timeout waiting for CRD: {}", crd_name),
        || {
            let client = client_clone.clone();
            let crd_name = crd_name_owned.clone();
            async move {
                let exists = crd_exists(&client, &crd_name).await?;
                if exists {
                    info!("CRD ready: {}", crd_name);
                }
                Ok(exists)
            }
        },
    )
    .await
}

/// Create a namespace (idempotent)
pub async fn create_namespace(client: &Client, name: &str) -> Result<(), Error> {
    let namespaces: Api<Namespace> = Api::all(client.clone());

    let ns = Namespace {
        metadata: kube::core::ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    match namespaces.create(&PostParams::default(), &ns).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(e)) if e.code == 409 => Ok(()), // Already exists
        Err(e) => Err(Error::internal_with_context(
            "create_namespace",
            format!("Failed to create namespace {}: {}", name, e),
        )),
    }
}

/// Parsed manifest metadata for applying to Kubernetes
#[derive(Debug, Clone)]
pub struct ManifestMetadata {
    /// The parsed JSON value
    pub value: serde_json::Value,
    /// Resource name
    pub name: String,
    /// Optional namespace
    pub namespace: Option<String>,
    /// API resource definition
    pub api_resource: ApiResource,
}

/// Parse a manifest and extract its metadata
pub fn parse_manifest(manifest: &str) -> Result<ManifestMetadata, Error> {
    // Convert YAML octal literals to decimal before parsing
    // serde_yaml treats 0NNN as strings, but Kubernetes expects integers
    let manifest = convert_yaml_octal_to_decimal(manifest);

    // Parse the manifest - try JSON first, then YAML
    let value: serde_json::Value = if manifest.trim().starts_with('{') {
        serde_json::from_str(&manifest).map_err(|e| {
            Error::internal_with_context(
                "parse_manifest",
                format!("Failed to parse manifest as JSON: {}", e),
            )
        })?
    } else {
        serde_yaml::from_str(&manifest).map_err(|e| {
            Error::internal_with_context(
                "parse_manifest",
                format!("Failed to parse manifest as YAML: {}", e),
            )
        })?
    };

    let api_version = value
        .get("apiVersion")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Error::internal_with_context("parse_manifest", "Manifest missing apiVersion")
        })?
        .to_string();

    let kind = value
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::internal_with_context("parse_manifest", "Manifest missing kind"))?
        .to_string();

    let name = value
        .pointer("/metadata/name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Error::internal_with_context("parse_manifest", "Manifest missing metadata.name")
        })?
        .to_string();

    let namespace = value
        .pointer("/metadata/namespace")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Parse apiVersion into group and version
    let (group, version) = parse_api_version(&api_version);

    // Build the plural form
    let plural = pluralize(&kind);

    let api_resource = ApiResource {
        group,
        version,
        kind,
        api_version,
        plural,
    };

    Ok(ManifestMetadata {
        value,
        name,
        namespace,
        api_resource,
    })
}

/// Parse apiVersion into (group, version)
fn parse_api_version(api_version: &str) -> (String, String) {
    if api_version.contains('/') {
        let parts: Vec<&str> = api_version.split('/').collect();
        (parts[0].to_string(), parts[1].to_string())
    } else {
        (String::new(), api_version.to_string())
    }
}

/// Apply a manifest using server-side apply
pub async fn apply_manifest(client: &Client, manifest: &str) -> Result<(), Error> {
    let metadata = parse_manifest(manifest)?;
    let patch_params = PatchParams::apply("lattice").force();

    if let Some(ns) = &metadata.namespace {
        let api: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), ns, &metadata.api_resource);
        api.patch(
            &metadata.name,
            &patch_params,
            &Patch::Apply(&metadata.value),
        )
        .await
        .map_err(|e| {
            Error::internal_with_context(
                "apply_manifest",
                format!(
                    "Failed to apply {}/{}: {}",
                    metadata.api_resource.kind, metadata.name, e
                ),
            )
        })?;
    } else {
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &metadata.api_resource);
        api.patch(
            &metadata.name,
            &patch_params,
            &Patch::Apply(&metadata.value),
        )
        .await
        .map_err(|e| {
            Error::internal_with_context(
                "apply_manifest",
                format!(
                    "Failed to apply {}/{}: {}",
                    metadata.api_resource.kind, metadata.name, e
                ),
            )
        })?;
    }

    Ok(())
}

/// Retry interval for apply operations
const APPLY_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// Apply a multi-document YAML manifest (documents separated by ---)
pub async fn apply_manifests(client: &Client, manifests: &str) -> Result<(), Error> {
    for doc in manifests.split("\n---") {
        let doc = doc.trim();
        // Skip non-manifest documents (empty, comments-only, etc.)
        if !doc.contains("apiVersion") {
            continue;
        }
        apply_manifest(client, doc).await?;
    }
    Ok(())
}

/// Apply a manifest with retry (supports multi-document YAML)
pub async fn apply_manifest_with_retry(
    client: &Client,
    manifest: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let client_clone = client.clone();
    let manifest_owned = manifest.to_string();

    poll_until(
        timeout,
        APPLY_RETRY_INTERVAL,
        "Timeout waiting for apply",
        || {
            let client = client_clone.clone();
            let manifest = manifest_owned.clone();
            async move {
                match apply_manifests(&client, &manifest).await {
                    Ok(()) => Ok(true),
                    Err(e) => {
                        // Use debug! level since retries are expected behavior
                        debug!("Apply failed (retrying): {}", e);
                        Ok(false)
                    }
                }
            }
        },
    )
    .await
}

/// Get a secret data value
pub async fn get_secret_data(
    client: &Client,
    name: &str,
    namespace: &str,
    key: &str,
) -> Result<Vec<u8>, Error> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);

    let secret = secrets.get(name).await.map_err(|e| {
        Error::internal_with_context(
            "get_secret_data",
            format!("Failed to get secret {}/{}: {}", namespace, name, e),
        )
    })?;

    let data = secret
        .data
        .as_ref()
        .and_then(|d| d.get(key))
        .ok_or_else(|| {
            Error::internal_with_context(
                "get_secret_data",
                format!("Secret {}/{} missing key {}", namespace, name, key),
            )
        })?;

    Ok(data.0.clone())
}

/// Check if a secret exists
pub async fn secret_exists(client: &Client, name: &str, namespace: &str) -> Result<bool, Error> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);

    match secrets.get(name).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(false),
        Err(e) => Err(Error::internal_with_context(
            "secret_exists",
            format!("Failed to check secret {}/{}: {}", namespace, name, e),
        )),
    }
}

/// Wait for a secret to exist
pub async fn wait_for_secret(
    client: &Client,
    name: &str,
    namespace: &str,
    timeout: Duration,
) -> Result<(), Error> {
    let client_clone = client.clone();
    let name_owned = name.to_string();
    let namespace_owned = namespace.to_string();

    poll_until(
        timeout,
        DEFAULT_POLL_INTERVAL,
        format!("Timeout waiting for secret {}/{}", namespace, name),
        || {
            let client = client_clone.clone();
            let name = name_owned.clone();
            let namespace = namespace_owned.clone();
            async move { secret_exists(&client, &name, &namespace).await }
        },
    )
    .await
}

/// Get a dynamic resource field value
pub async fn get_dynamic_resource_status_field(
    client: &Client,
    ar: &ApiResource,
    name: &str,
    namespace: Option<&str>,
    field: &str,
) -> Result<Option<String>, Error> {
    let result = if let Some(ns) = namespace {
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), ns, ar);
        api.get(name).await
    } else {
        let api: Api<DynamicObject> = Api::all_with(client.clone(), ar);
        api.get(name).await
    };

    match result {
        Ok(obj) => {
            let value = obj
                .data
                .get("status")
                .and_then(|s| s.get(field))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            Ok(value)
        }
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(None),
        Err(e) => Err(Error::internal_with_context(
            "get_dynamic_resource_status_field",
            format!("Failed to get {}/{}: {}", ar.kind, name, e),
        )),
    }
}

/// Get machine phases in a namespace
pub async fn get_machine_phases(client: &Client, namespace: &str) -> Result<Vec<String>, Error> {
    let ar = ApiResource {
        group: "cluster.x-k8s.io".to_string(),
        version: "v1beta1".to_string(),
        kind: "Machine".to_string(),
        api_version: "cluster.x-k8s.io/v1beta1".to_string(),
        plural: "machines".to_string(),
    };

    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &ar);

    let machines = api.list(&ListParams::default()).await.map_err(|e| {
        Error::internal_with_context(
            "get_machine_phases",
            format!("Failed to list machines: {}", e),
        )
    })?;

    let phases: Vec<String> = machines
        .items
        .iter()
        .filter_map(|m| {
            m.data
                .get("status")
                .and_then(|s| s.get("phase"))
                .and_then(|p| p.as_str())
                .map(|s| s.to_string())
        })
        .collect();

    Ok(phases)
}

/// Get count of ready worker nodes (excludes control-plane)
pub async fn get_ready_worker_count(client: &Client) -> Result<usize, Error> {
    let nodes: Api<Node> = Api::all(client.clone());
    let node_list = nodes.list(&ListParams::default()).await.map_err(|e| {
        Error::internal_with_context(
            "get_ready_worker_count",
            format!("Failed to list nodes: {}", e),
        )
    })?;

    let ready_workers = node_list.items.iter().filter(|node| {
        // Check if it's a worker (no control-plane label)
        let is_worker = node
            .metadata
            .labels
            .as_ref()
            .map(|labels| !labels.contains_key("node-role.kubernetes.io/control-plane"))
            .unwrap_or(true);

        // Check if Ready using the has_condition helper
        let conditions = node.status.as_ref().and_then(|s| s.conditions.as_ref());
        let is_ready = has_condition(conditions.map(|c| c.as_slice()), CONDITION_READY);

        is_worker && is_ready
    });

    Ok(ready_workers.count())
}

/// Convert YAML 1.1 octal literals to decimal
///
/// YAML 1.1 interprets numbers with leading zeros as octal (e.g., 0400 = 256).
/// However, serde_yaml treats these as strings. Kubernetes expects integers.
/// This function converts octal patterns to decimal before parsing.
///
/// Only matches 4-digit octal (0NNN) which is the Unix permission format.
fn convert_yaml_octal_to_decimal(yaml: &str) -> String {
    // Match: colon + space + exactly 4 digits starting with 0 (e.g., 0400, 0755)
    let re = regex::Regex::new(r"(:\s+)0([0-7]{3})\b").unwrap();
    re.replace_all(yaml, |caps: &regex::Captures| {
        let prefix = &caps[1];
        let octal_str = &caps[2];
        match i64::from_str_radix(octal_str, 8) {
            Ok(decimal) => format!("{}{}", prefix, decimal),
            Err(_) => caps[0].to_string(),
        }
    })
    .into_owned()
}

/// Simple pluralization for Kubernetes resource kinds
fn pluralize(kind: &str) -> String {
    let lower = kind.to_lowercase();
    if lower.ends_with("s") {
        format!("{}es", lower)
    } else if lower.ends_with("y") {
        format!("{}ies", &lower[..lower.len() - 1])
    } else {
        format!("{}s", lower)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pluralize() {
        assert_eq!(pluralize("Deployment"), "deployments");
        assert_eq!(pluralize("Pod"), "pods");
        assert_eq!(pluralize("Policy"), "policies");
        assert_eq!(pluralize("ClusterResourceSet"), "clusterresourcesets");
        assert_eq!(pluralize("Ingress"), "ingresses");
        assert_eq!(pluralize("Service"), "services");
        assert_eq!(pluralize("ConfigMap"), "configmaps");
        assert_eq!(pluralize("Secret"), "secrets");
        assert_eq!(pluralize("NetworkPolicy"), "networkpolicies");
    }

    #[test]
    fn test_parse_api_version_with_group() {
        let (group, version) = parse_api_version("apps/v1");
        assert_eq!(group, "apps");
        assert_eq!(version, "v1");
    }

    #[test]
    fn test_parse_api_version_core() {
        let (group, version) = parse_api_version("v1");
        assert_eq!(group, "");
        assert_eq!(version, "v1");
    }

    #[test]
    fn test_parse_api_version_crd() {
        let (group, version) = parse_api_version("lattice.io/v1alpha1");
        assert_eq!(group, "lattice.io");
        assert_eq!(version, "v1alpha1");
    }

    #[test]
    fn test_parse_manifest_yaml_deployment() {
        let manifest = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
spec:
  replicas: 1
"#;
        let meta =
            parse_manifest(manifest).expect("YAML deployment manifest should parse successfully");
        assert_eq!(meta.name, "my-app");
        assert_eq!(meta.namespace, Some("default".to_string()));
        assert_eq!(meta.api_resource.kind, "Deployment");
        assert_eq!(meta.api_resource.group, "apps");
        assert_eq!(meta.api_resource.version, "v1");
        assert_eq!(meta.api_resource.plural, "deployments");
    }

    #[test]
    fn test_parse_manifest_json() {
        let manifest = r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"my-config"}}"#;
        let meta = parse_manifest(manifest).expect("JSON manifest should parse successfully");
        assert_eq!(meta.name, "my-config");
        assert_eq!(meta.namespace, None);
        assert_eq!(meta.api_resource.kind, "ConfigMap");
        assert_eq!(meta.api_resource.group, "");
        assert_eq!(meta.api_resource.version, "v1");
    }

    #[test]
    fn test_parse_manifest_cluster_scoped() {
        let manifest = r#"
apiVersion: v1
kind: Namespace
metadata:
  name: my-namespace
"#;
        let meta =
            parse_manifest(manifest).expect("cluster-scoped manifest should parse successfully");
        assert_eq!(meta.name, "my-namespace");
        assert_eq!(meta.namespace, None);
        assert_eq!(meta.api_resource.kind, "Namespace");
    }

    #[test]
    fn test_parse_manifest_crd() {
        let manifest = r#"
apiVersion: lattice.io/v1alpha1
kind: LatticeCluster
metadata:
  name: my-cluster
spec:
  provider: {}
"#;
        let meta = parse_manifest(manifest).expect("CRD manifest should parse successfully");
        assert_eq!(meta.name, "my-cluster");
        assert_eq!(meta.api_resource.group, "lattice.io");
        assert_eq!(meta.api_resource.version, "v1alpha1");
        assert_eq!(meta.api_resource.plural, "latticeclusters");
    }

    #[test]
    fn test_parse_manifest_missing_api_version() {
        let manifest = r#"
kind: Deployment
metadata:
  name: test
"#;
        let result = parse_manifest(manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("apiVersion"));
    }

    #[test]
    fn test_parse_manifest_missing_kind() {
        let manifest = r#"
apiVersion: v1
metadata:
  name: test
"#;
        let result = parse_manifest(manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("kind"));
    }

    #[test]
    fn test_parse_manifest_missing_name() {
        let manifest = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: default
"#;
        let result = parse_manifest(manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("name"));
    }

    #[test]
    fn test_parse_manifest_invalid_yaml() {
        let manifest = "not: valid: yaml: {{";
        let result = parse_manifest(manifest);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_manifest_invalid_json() {
        let manifest = "{not valid json";
        let result = parse_manifest(manifest);
        assert!(result.is_err());
    }

    #[test]
    fn test_has_condition_with_ready() {
        use k8s_openapi::api::core::v1::NodeCondition;

        let conditions = vec![
            NodeCondition {
                type_: "Ready".to_string(),
                status: "True".to_string(),
                ..Default::default()
            },
            NodeCondition {
                type_: "MemoryPressure".to_string(),
                status: "False".to_string(),
                ..Default::default()
            },
        ];

        assert!(has_condition(Some(conditions.as_slice()), CONDITION_READY));
        assert!(!has_condition(
            Some(conditions.as_slice()),
            CONDITION_AVAILABLE
        ));
    }

    #[test]
    fn test_has_condition_not_ready() {
        use k8s_openapi::api::core::v1::NodeCondition;

        let conditions = vec![NodeCondition {
            type_: "Ready".to_string(),
            status: "False".to_string(),
            ..Default::default()
        }];

        assert!(!has_condition(Some(conditions.as_slice()), CONDITION_READY));
    }

    #[test]
    fn test_has_condition_none() {
        assert!(!has_condition::<k8s_openapi::api::core::v1::NodeCondition>(
            None,
            CONDITION_READY
        ));
    }

    #[test]
    fn test_has_condition_empty() {
        let conditions: Vec<k8s_openapi::api::core::v1::NodeCondition> = vec![];
        assert!(!has_condition(Some(conditions.as_slice()), CONDITION_READY));
    }

    #[test]
    fn test_has_condition_deployment() {
        use k8s_openapi::api::apps::v1::DeploymentCondition;

        let conditions = vec![
            DeploymentCondition {
                type_: "Available".to_string(),
                status: "True".to_string(),
                ..Default::default()
            },
            DeploymentCondition {
                type_: "Progressing".to_string(),
                status: "True".to_string(),
                ..Default::default()
            },
        ];

        assert!(has_condition(
            Some(conditions.as_slice()),
            CONDITION_AVAILABLE
        ));
        assert!(!has_condition(Some(conditions.as_slice()), CONDITION_READY));
    }

    #[test]
    fn test_constants() {
        assert_eq!(CONDITION_READY, "Ready");
        assert_eq!(CONDITION_AVAILABLE, "Available");
        assert_eq!(STATUS_TRUE, "True");
    }

    // =========================================================================
    // strip_export_metadata Tests
    // =========================================================================

    #[test]
    fn test_strip_export_metadata_removes_uid() {
        let mut meta = k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some("test".to_string()),
            uid: Some("abc-123".to_string()),
            ..Default::default()
        };

        strip_export_metadata(&mut meta);

        assert_eq!(meta.name, Some("test".to_string())); // preserved
        assert!(meta.uid.is_none()); // stripped
    }

    #[test]
    fn test_strip_export_metadata_removes_resource_version() {
        let mut meta = k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some("test".to_string()),
            resource_version: Some("12345".to_string()),
            ..Default::default()
        };

        strip_export_metadata(&mut meta);

        assert!(meta.resource_version.is_none());
    }

    #[test]
    fn test_strip_export_metadata_removes_creation_timestamp() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

        let mut meta = k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some("test".to_string()),
            creation_timestamp: Some(Time(chrono::Utc::now())),
            ..Default::default()
        };

        strip_export_metadata(&mut meta);

        assert!(meta.creation_timestamp.is_none());
    }

    #[test]
    fn test_strip_export_metadata_removes_managed_fields() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ManagedFieldsEntry;

        let mut meta = k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some("test".to_string()),
            managed_fields: Some(vec![ManagedFieldsEntry {
                manager: Some("kubectl".to_string()),
                ..Default::default()
            }]),
            ..Default::default()
        };

        strip_export_metadata(&mut meta);

        assert!(meta.managed_fields.is_none());
    }

    #[test]
    fn test_strip_export_metadata_removes_generation() {
        let mut meta = k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some("test".to_string()),
            generation: Some(5),
            ..Default::default()
        };

        strip_export_metadata(&mut meta);

        assert!(meta.generation.is_none());
    }

    #[test]
    fn test_strip_export_metadata_preserves_labels() {
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("app".to_string(), "test".to_string());

        let mut meta = k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some("test".to_string()),
            labels: Some(labels.clone()),
            uid: Some("to-be-stripped".to_string()),
            ..Default::default()
        };

        strip_export_metadata(&mut meta);

        assert_eq!(meta.labels, Some(labels));
        assert!(meta.uid.is_none());
    }

    #[test]
    fn test_strip_export_metadata_preserves_annotations() {
        let mut annotations = std::collections::BTreeMap::new();
        annotations.insert("note".to_string(), "important".to_string());

        let mut meta = k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some("test".to_string()),
            annotations: Some(annotations.clone()),
            resource_version: Some("to-be-stripped".to_string()),
            ..Default::default()
        };

        strip_export_metadata(&mut meta);

        assert_eq!(meta.annotations, Some(annotations));
        assert!(meta.resource_version.is_none());
    }

    #[test]
    fn test_strip_export_metadata_preserves_namespace() {
        let mut meta = k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some("test".to_string()),
            namespace: Some("custom-ns".to_string()),
            uid: Some("strip-me".to_string()),
            ..Default::default()
        };

        strip_export_metadata(&mut meta);

        assert_eq!(meta.namespace, Some("custom-ns".to_string()));
        assert!(meta.uid.is_none());
    }

    #[test]
    fn test_convert_yaml_octal_to_decimal() {
        // Basic scalar value: 0400 octal = 256 decimal
        assert_eq!(
            convert_yaml_octal_to_decimal("defaultMode: 0400"),
            "defaultMode: 256"
        );

        // 0644 octal = 420 decimal
        assert_eq!(
            convert_yaml_octal_to_decimal("mode: 0644"),
            "mode: 420"
        );

        // 0755 octal = 493 decimal
        assert_eq!(
            convert_yaml_octal_to_decimal("mode: 0755"),
            "mode: 493"
        );

        // Multiple octals in one document
        let yaml = "mode: 0644\ndefaultMode: 0400";
        let result = convert_yaml_octal_to_decimal(yaml);
        assert!(result.contains("mode: 420"), "0644 octal = 420 decimal");
        assert!(result.contains("defaultMode: 256"), "0400 octal = 256 decimal");

        // Don't touch regular numbers
        assert_eq!(
            convert_yaml_octal_to_decimal("replicas: 3"),
            "replicas: 3"
        );

        // Don't touch numbers with 8 or 9 (not valid octal)
        assert_eq!(
            convert_yaml_octal_to_decimal("port: 8080"),
            "port: 8080"
        );
    }
}
