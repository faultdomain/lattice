//! Manifest parsing and applying utilities.

use std::time::Duration;

use kube::api::{Api, DynamicObject, Patch, PatchParams};
use kube::discovery::ApiResource;
use kube::Client;
use tracing::{trace, warn};

use super::api_resource::build_api_resource;
use super::waiting::poll_until;
use crate::Error;

/// Retry interval for apply operations
const APPLY_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// Options for applying manifests.
#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    /// Skip manifests for resource types that aren't installed yet (default: false).
    /// A 404 from the API server (resource type not found) is treated as a skip.
    pub skip_missing_crds: bool,
}

/// Parsed manifest metadata for applying to Kubernetes
#[derive(Debug, Clone)]
pub(crate) struct ManifestMetadata {
    /// The parsed JSON value
    pub(crate) value: serde_json::Value,
    /// Resource name
    pub(crate) name: String,
    /// Optional namespace
    pub(crate) namespace: Option<String>,
    /// API resource definition
    pub(crate) api_resource: ApiResource,
}

/// Parse a manifest and extract its metadata
pub(crate) fn parse_manifest(manifest: &str) -> Result<ManifestMetadata, Error> {
    // Parse the manifest - try JSON first, then YAML
    let value: serde_json::Value = if manifest.trim().starts_with('{') {
        serde_json::from_str(manifest).map_err(|e| {
            Error::internal_with_context(
                "parse_manifest",
                format!("Failed to parse manifest as JSON: {}", e),
            )
        })?
    } else {
        crate::yaml::parse_yaml(manifest).map_err(|e| {
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

    let api_resource = build_api_resource(&api_version, &kind);

    Ok(ManifestMetadata {
        value,
        name,
        namespace,
        api_resource,
    })
}

/// Apply manifests with proper ordering via server-side apply.
///
/// Each manifest's declared `apiVersion`/`kind` is used directly to construct
/// the ApiResource — no API discovery is needed. This avoids the problem where
/// a broken APIService (e.g. KEDA returning 503) poisons `Discovery::run()`
/// and blocks unrelated manifests.
///
/// Applies in two phases:
/// - Foundational resources (Namespaces, CRDs) — fail-fast
/// - Everything else sorted by kind priority — best-effort (continues past failures)
pub async fn apply_manifests(
    client: &Client,
    manifests: &[impl AsRef<str>],
    options: &ApplyOptions,
) -> Result<(), Error> {
    if manifests.is_empty() {
        return Ok(());
    }

    // Split into foundational (Namespace, CRD) and rest
    let (mut foundational, mut rest): (Vec<&str>, Vec<&str>) =
        manifests.iter().map(|m| m.as_ref()).partition(|m| {
            let kind = extract_kind(m);
            kind == "Namespace" || kind == "CustomResourceDefinition"
        });

    // Sort each group by priority
    foundational.sort_by_key(|m| kind_priority(extract_kind(m)));
    rest.sort_by_key(|m| kind_priority(extract_kind(m)));

    // Phase 1: Foundational resources — fail-fast.
    for manifest in &foundational {
        apply_one(client, manifest, options).await?;
    }

    // Phase 2: Remaining resources — best-effort, continue past failures.
    let mut first_error: Option<Error> = None;
    let mut failed_count = 0usize;

    for manifest in &rest {
        if let Err(e) = apply_one(client, manifest, options).await {
            failed_count += 1;
            warn!(
                error = %e,
                kind = %extract_kind(manifest),
                "manifest apply failed, continuing with remaining manifests"
            );
            if first_error.is_none() {
                first_error = Some(e);
            }
        }
    }

    if let Some(e) = first_error {
        warn!(
            failed = failed_count,
            total = rest.len(),
            "some manifests failed to apply"
        );
        return Err(e);
    }

    Ok(())
}

/// Apply a multi-document YAML string with retry until timeout.
pub async fn apply_manifest_with_retry(
    client: &Client,
    manifest: &str,
    timeout: Duration,
) -> Result<(), Error> {
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let client_clone = client.clone();
    let docs: Vec<String> = split_multi_doc(manifest);
    let last_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let last_error_clone = last_error.clone();

    let result = poll_until(
        timeout,
        APPLY_RETRY_INTERVAL,
        "Timeout waiting for apply",
        || {
            let client = client_clone.clone();
            let docs = docs.clone();
            let last_error = last_error_clone.clone();
            async move {
                match apply_manifests(&client, &docs, &ApplyOptions::default()).await {
                    Ok(()) => Ok(true),
                    Err(e) => {
                        let error_msg = e.to_string();
                        warn!("Apply failed (will retry): {}", error_msg);
                        *last_error.lock().await = Some(error_msg);
                        Ok(false)
                    }
                }
            }
        },
    )
    .await;

    if result.is_err() {
        if let Some(err) = last_error.lock().await.take() {
            return Err(Error::internal_with_context(
                "apply_manifest_with_retry",
                format!("Timeout applying manifest. Last error: {}", err),
            ));
        }
    }

    result
}

/// Apply a single manifest via SSA, respecting `ApplyOptions`.
async fn apply_one(client: &Client, manifest: &str, options: &ApplyOptions) -> Result<(), Error> {
    let metadata = parse_manifest(manifest)?;
    let params = PatchParams::apply("lattice").force();

    let api: Api<DynamicObject> = match &metadata.namespace {
        Some(ns) => Api::namespaced_with(client.clone(), ns, &metadata.api_resource),
        None => Api::all_with(client.clone(), &metadata.api_resource),
    };

    match api
        .patch(&metadata.name, &params, &Patch::Apply(&metadata.value))
        .await
    {
        Ok(_) => {
            trace!(
                kind = %metadata.api_resource.kind,
                name = %metadata.name,
                namespace = ?metadata.namespace,
                "applied manifest"
            );
            Ok(())
        }
        Err(kube::Error::Api(ref ae)) if ae.code == 404 && options.skip_missing_crds => {
            trace!(
                kind = %metadata.api_resource.kind,
                name = %metadata.name,
                "skipping manifest - resource type not available"
            );
            Ok(())
        }
        Err(e) => Err(Error::internal_with_context(
            "apply_manifest",
            format!(
                "failed to apply {}/{}: {}",
                metadata.api_resource.kind, metadata.name, e
            ),
        )),
    }
}

/// Split a multi-document YAML string into individual documents.
fn split_multi_doc(manifest: &str) -> Vec<String> {
    manifest
        .split("\n---")
        .map(|doc| doc.trim().to_string())
        .filter(|doc| doc.contains("apiVersion"))
        .collect()
}

/// Get priority for a Kubernetes resource kind (lower = apply first)
///
/// Security policies (PeerAuthentication, AuthorizationPolicy) MUST be applied
/// before workloads (Deployment, DaemonSet). Otherwise pods start with STRICT
/// mTLS before PERMISSIVE policies are in place, causing the kube-apiserver
/// (not in the mesh) to get EOF when reaching aggregated API services like
/// KEDA's metrics endpoint.
pub fn kind_priority(kind: &str) -> u8 {
    match kind {
        "Namespace" => 0,
        "CustomResourceDefinition" => 1,
        "ServiceAccount" => 2,
        "ClusterRole" | "Role" => 3,
        "ClusterRoleBinding" | "RoleBinding" => 4,
        "ConfigMap" | "Secret" => 5,
        "PeerAuthentication"
        | "AuthorizationPolicy"
        | "CiliumNetworkPolicy"
        | "CiliumClusterwideNetworkPolicy" => 6,
        "Service" => 7,
        "Deployment" | "DaemonSet" | "StatefulSet" => 8,
        "ScaledObject" => 9,
        _ => 10,
    }
}

/// Extract kind from a YAML or JSON manifest (fast, no full parse)
///
/// Handles both YAML (`kind: Foo`) and pretty-printed JSON (`"kind": "Foo"`).
pub(crate) fn extract_kind(manifest: &str) -> &str {
    for line in manifest.lines() {
        let trimmed = line.trim();

        // YAML: `kind: Foo`
        if let Some(value) = trimmed.strip_prefix("kind:") {
            return value.trim();
        }

        // JSON (pretty-printed): `"kind": "Foo"` or `"kind": "Foo",`
        if let Some(rest) = trimmed.strip_prefix("\"kind\":") {
            let rest = rest.trim().trim_start_matches('"');
            if let Some(end) = rest.find('"') {
                return &rest[..end];
            }
        }
    }

    ""
}

/// Check if a JSON manifest is a Kubernetes Deployment
pub fn is_deployment_json(manifest: &str) -> bool {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(manifest) {
        value.get("kind").and_then(|k| k.as_str()) == Some("Deployment")
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
