//! Agent-side move executor
//!
//! Handles object creation on the target cluster during distributed move.
//! Receives batches from the cell and creates objects with UID remapping.

use std::collections::HashMap;
use std::time::Duration;

use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, DynamicObject, ListParams, PostParams};
use kube::Client;
use lattice_common::kube_utils::build_api_resource;
use lattice_common::retry::{retry_with_backoff_bail, RetryConfig};
use serde_json::Value;
use tracing::{debug, info, instrument, warn};

use crate::cell::{MoveObjectOutput, SourceOwnerRefOutput};
use crate::error::MoveError;

/// Annotation key used to store the source UID on created resources
///
/// This enables crash recovery: on restart, the agent can query resources
/// with this annotation to rebuild the UID map (source UID -> target UID).
pub const SOURCE_UID_ANNOTATION: &str = "lattice.dev/source-uid";

/// Agent-side executor for distributed move operations
pub struct AgentMover {
    /// Kubernetes client for the target cluster
    client: Client,
    /// Mapping from source UIDs to target UIDs
    uid_map: HashMap<String, String>,
    /// Namespace for resources
    namespace: String,
    /// Total resources created
    resources_created: u32,
}

impl AgentMover {
    /// Create a new AgentMover
    pub fn new(client: Client, namespace: &str) -> Self {
        Self {
            client,
            uid_map: HashMap::new(),
            namespace: namespace.to_string(),
            resources_created: 0,
        }
    }

    /// Get the UID map (source UID -> target UID)
    pub fn uid_map(&self) -> &HashMap<String, String> {
        &self.uid_map
    }

    /// Get the total resources created
    pub fn resources_created(&self) -> u32 {
        self.resources_created
    }

    /// Merge existing UID mappings (for resume after crash)
    ///
    /// Call this after rebuilding from resources to preserve any mappings
    /// discovered via annotations.
    pub fn merge_uid_map(&mut self, mappings: HashMap<String, String>) {
        for (source_uid, target_uid) in mappings {
            self.uid_map.entry(source_uid).or_insert(target_uid);
        }
    }

    /// Rebuild UID map by querying existing resources with source-uid annotation
    ///
    /// On crash recovery, this scans all resources in the target namespace
    /// for the SOURCE_UID_ANNOTATION and rebuilds the source -> target UID map.
    pub async fn rebuild_uid_map_from_resources(&mut self) -> Result<usize, MoveError> {
        info!(namespace = %self.namespace, "Rebuilding UID map from existing resources");

        let mut count = 0;

        // Get all CRDs that have the move label (same discovery as ObjectGraph)
        let crd_types = crate::utils::discover_move_crds(&self.client).await?;

        for crd_type in crd_types {
            let api_resource = build_api_resource(&crd_type.api_version, &crd_type.kind);
            let api: Api<DynamicObject> =
                Api::namespaced_with(self.client.clone(), &self.namespace, &api_resource);

            // List all objects
            let list = match api.list(&ListParams::default()).await {
                Ok(l) => l,
                Err(e) => {
                    debug!(kind = %crd_type.kind, error = %e, "Failed to list resources (may not exist)");
                    continue;
                }
            };

            for obj in list.items {
                // Check for source-uid annotation
                if let Some(annotations) = &obj.metadata.annotations {
                    if let Some(source_uid) = annotations.get(SOURCE_UID_ANNOTATION) {
                        if let Some(target_uid) = &obj.metadata.uid {
                            self.uid_map.insert(source_uid.clone(), target_uid.clone());
                            count += 1;
                            debug!(
                                source_uid = %source_uid,
                                target_uid = %target_uid,
                                kind = %crd_type.kind,
                                "Recovered UID mapping"
                            );
                        }
                    }
                }
            }
        }

        // Also check core types: Secrets and ConfigMaps
        count += self
            .rebuild_uid_map_for_core_type::<k8s_openapi::api::core::v1::Secret>("Secret")
            .await?;
        count += self
            .rebuild_uid_map_for_core_type::<k8s_openapi::api::core::v1::ConfigMap>("ConfigMap")
            .await?;

        info!(
            namespace = %self.namespace,
            recovered = count,
            "UID map rebuild complete"
        );

        Ok(count)
    }

    /// Rebuild UID map for a core Kubernetes type
    async fn rebuild_uid_map_for_core_type<T>(
        &mut self,
        type_name: &str,
    ) -> Result<usize, MoveError>
    where
        T: kube::Resource<Scope = kube::core::NamespaceResourceScope>
            + Clone
            + std::fmt::Debug
            + serde::de::DeserializeOwned
            + serde::Serialize,
        <T as kube::Resource>::DynamicType: Default,
    {
        let api: Api<T> = Api::namespaced(self.client.clone(), &self.namespace);
        let mut count = 0;

        let list = match api.list(&ListParams::default()).await {
            Ok(l) => l,
            Err(e) => {
                debug!(type_name = %type_name, error = %e, "Failed to list core resources");
                return Ok(0);
            }
        };

        for obj in list.items {
            let meta = obj.meta();
            if let Some(annotations) = &meta.annotations {
                if let Some(source_uid) = annotations.get(SOURCE_UID_ANNOTATION) {
                    if let Some(target_uid) = &meta.uid {
                        self.uid_map.insert(source_uid.clone(), target_uid.clone());
                        count += 1;
                    }
                }
            }
        }

        Ok(count)
    }

    /// Ensure the target namespace exists
    pub async fn ensure_namespace(&self) -> Result<(), MoveError> {
        let ns_api: Api<Namespace> = Api::all(self.client.clone());

        // Check if namespace exists
        match ns_api.get(&self.namespace).await {
            Ok(_) => {
                debug!(namespace = %self.namespace, "Namespace already exists");
                return Ok(());
            }
            Err(kube::Error::Api(e)) if e.code == 404 => {
                // Create it
            }
            Err(e) => {
                return Err(MoveError::NamespaceCreation {
                    namespace: self.namespace.clone(),
                    message: e.to_string(),
                });
            }
        }

        let ns = Namespace {
            metadata: kube::core::ObjectMeta {
                name: Some(self.namespace.clone()),
                ..Default::default()
            },
            ..Default::default()
        };

        ns_api
            .create(&PostParams::default(), &ns)
            .await
            .map_err(|e| MoveError::NamespaceCreation {
                namespace: self.namespace.clone(),
                message: e.to_string(),
            })?;

        info!(namespace = %self.namespace, "Created namespace");
        Ok(())
    }

    /// Apply a batch of objects
    ///
    /// Returns a list of (source_uid, target_uid) mappings for successfully created objects,
    /// and a list of errors for failed objects.
    #[instrument(
        skip(self, objects),
        fields(
            namespace = %self.namespace,
            batch_size = objects.len(),
            otel.kind = "internal"
        )
    )]
    pub async fn apply_batch(
        &mut self,
        objects: &[MoveObjectOutput],
    ) -> (Vec<(String, String)>, Vec<MoveObjectError>) {
        let mut mappings = Vec::new();
        let mut errors = Vec::new();

        for obj in objects {
            match self.create_object(obj).await {
                Ok(target_uid) => {
                    self.uid_map
                        .insert(obj.source_uid.clone(), target_uid.clone());
                    mappings.push((obj.source_uid.clone(), target_uid));
                    self.resources_created += 1;
                }
                Err(e) => {
                    warn!(
                        source_uid = %obj.source_uid,
                        error = %e,
                        "Failed to create object"
                    );
                    errors.push(MoveObjectError {
                        source_uid: obj.source_uid.clone(),
                        message: e.to_string(),
                        retryable: e.is_retryable(),
                    });
                }
            }
        }

        mappings
            .iter()
            .for_each(|(src, tgt)| debug!(source_uid = %src, target_uid = %tgt, "Created object"));

        (mappings, errors)
    }

    /// Create a single object with owner reference rebuilding
    async fn create_object(&self, input: &MoveObjectOutput) -> Result<String, MoveError> {
        // Parse the manifest
        let mut obj: Value = serde_json::from_slice(&input.manifest)
            .map_err(|e| MoveError::Serialization(format!("failed to parse manifest: {}", e)))?;

        // Extract type information
        let api_version = obj["apiVersion"]
            .as_str()
            .ok_or_else(|| MoveError::Serialization("missing apiVersion".to_string()))?
            .to_string();
        let kind = obj["kind"]
            .as_str()
            .ok_or_else(|| MoveError::Serialization("missing kind".to_string()))?
            .to_string();

        // Validate object kind against allowlist to prevent injection of
        // RBAC or other privileged resources during move operations
        validate_move_object_kind(&api_version, &kind)?;
        let name = obj["metadata"]["name"]
            .as_str()
            .ok_or_else(|| MoveError::Serialization("missing metadata.name".to_string()))?
            .to_string();

        // Strip transient fields that shouldn't be copied
        strip_transient_fields(&mut obj);

        // Ensure namespace is set and add source-uid annotation for crash recovery
        if let Some(metadata) = obj.get_mut("metadata").and_then(|m| m.as_object_mut()) {
            metadata.insert(
                "namespace".to_string(),
                Value::String(self.namespace.clone()),
            );

            // Add source-uid annotation for crash recovery (UID map rebuild)
            let annotations = metadata
                .entry("annotations")
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(ann_map) = annotations.as_object_mut() {
                ann_map.insert(
                    SOURCE_UID_ANNOTATION.to_string(),
                    Value::String(input.source_uid.clone()),
                );
            }
        }

        // Rebuild owner references with new UIDs
        self.rebuild_owner_refs(&mut obj, &input.owners)?;

        // Build ApiResource from type info
        let api_resource = build_api_resource(&api_version, &kind);

        // Create the object
        let dyn_obj: DynamicObject = serde_json::from_value(obj.clone()).map_err(|e| {
            MoveError::Serialization(format!("failed to convert to DynamicObject: {}", e))
        })?;

        let api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), &self.namespace, &api_resource);

        // Try to create with retry for transient errors (webhooks not ready, etc.)
        let retry_config = RetryConfig {
            max_attempts: 6, // 1 initial + 5 retries
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 1.0,
        };

        let created = retry_with_backoff_bail(
            &retry_config,
            &format!("create_{}/{}", kind, name),
            || async {
                match api.create(&PostParams::default(), &dyn_obj).await {
                    Ok(created) => Ok(created),
                    Err(kube::Error::Api(e)) if e.code == 409 => {
                        // Already exists - get it to retrieve UID
                        debug!(kind = %kind, name = %name, "Object already exists, getting existing UID");
                        api.get(&name).await.map_err(MoveError::Kube)
                    }
                    Err(e) => Err(MoveError::Kube(e)),
                }
            },
            |e| {
                // Only 5xx errors are transient; everything else is fatal
                !matches!(e, MoveError::Kube(kube::Error::Api(ref ae)) if ae.code >= 500)
            },
        )
        .await?;

        let target_uid = created
            .metadata
            .uid
            .ok_or_else(|| MoveError::Serialization("created object has no UID".to_string()))?;

        debug!(
            kind = %kind,
            name = %name,
            target_uid = %target_uid,
            "Created object"
        );

        Ok(target_uid)
    }

    /// Rebuild owner references using the UID map
    fn rebuild_owner_refs(
        &self,
        obj: &mut Value,
        source_owners: &[SourceOwnerRefOutput],
    ) -> Result<(), MoveError> {
        if source_owners.is_empty() {
            // Remove any existing owner references
            if let Some(metadata) = obj.get_mut("metadata").and_then(|m| m.as_object_mut()) {
                metadata.remove("ownerReferences");
            }
            return Ok(());
        }

        let mut new_refs = Vec::new();

        for owner in source_owners {
            // Look up the new UID
            let target_uid = self.uid_map.get(&owner.source_uid).ok_or_else(|| {
                MoveError::UidMappingNotFound {
                    source_uid: owner.source_uid.clone(),
                }
            })?;

            let mut ref_obj = serde_json::json!({
                "apiVersion": owner.api_version,
                "kind": owner.kind,
                "name": owner.name,
                "uid": target_uid,
            });

            if owner.controller {
                ref_obj["controller"] = Value::Bool(true);
            }
            if owner.block_owner_deletion {
                ref_obj["blockOwnerDeletion"] = Value::Bool(true);
            }

            new_refs.push(ref_obj);
        }

        if let Some(metadata) = obj.get_mut("metadata").and_then(|m| m.as_object_mut()) {
            metadata.insert("ownerReferences".to_string(), Value::Array(new_refs));
        }

        Ok(())
    }

    /// Unpause Cluster and ClusterClass resources after all objects are created.
    ///
    /// This operation is critical - CAPI won't delete paused clusters, so failure
    /// to unpause can lead to orphaned infrastructure.
    pub async fn unpause_resources(&self) -> Result<(), MoveError> {
        // Unpause Cluster (required)
        self.unpause_resource("cluster.x-k8s.io", "Cluster").await?;

        // Unpause ClusterClass (optional - might not exist)
        if let Err(e) = self
            .unpause_resource("cluster.x-k8s.io", "ClusterClass")
            .await
        {
            // ClusterClass might not exist, that's okay
            debug!(error = %e, "No ClusterClass to unpause (or unpause failed)");
        }

        Ok(())
    }

    /// Unpause a specific resource type using discovery
    async fn unpause_resource(&self, group: &str, kind: &str) -> Result<(), MoveError> {
        let count =
            crate::utils::patch_resources_paused(&self.client, &self.namespace, group, kind, false)
                .await?;
        if count > 0 {
            info!(kind = %kind, count = count, "Unpaused resources");
        }
        Ok(())
    }
}

/// Error for a specific object
#[derive(Debug, Clone)]
pub struct MoveObjectError {
    /// Source UID
    pub source_uid: String,
    /// Error message
    pub message: String,
    /// Whether retryable
    pub retryable: bool,
}

/// API groups explicitly allowed during move operations.
/// Only CAPI provider groups and their dependencies are permitted.
/// Any group not on this list is rejected, preventing a compromised source
/// from injecting privilege-escalation resources (RBAC, webhooks, etc.).
const ALLOWED_MOVE_API_GROUPS: &[&str] = &[
    "cluster.x-k8s.io",
    "infrastructure.cluster.x-k8s.io",
    "bootstrap.cluster.x-k8s.io",
    "controlplane.cluster.x-k8s.io",
    "addon.cluster.x-k8s.io",
    "addons.cluster.x-k8s.io",
    "ipam.cluster.x-k8s.io",
    "runtime.cluster.x-k8s.io",
];

/// Core API kinds (apiVersion "v1", no group) allowed during move.
/// These carry CAPI configuration and kubeconfig data needed post-pivot.
const ALLOWED_CORE_KINDS: &[&str] = &["Secret", "ConfigMap"];

/// Validate that an object is allowed during move operations.
///
/// Uses an allowlist approach: only CAPI groups and specific core types
/// are permitted. All other API groups are rejected regardless of kind.
fn validate_move_object_kind(api_version: &str, kind: &str) -> Result<(), MoveError> {
    if api_version.contains('/') {
        // Grouped resource (e.g., "cluster.x-k8s.io/v1beta1")
        let group = api_version.split('/').next().unwrap_or("");
        if ALLOWED_MOVE_API_GROUPS.contains(&group) {
            return Ok(());
        }
    } else {
        // Core API resource (e.g., "v1")
        if ALLOWED_CORE_KINDS.contains(&kind) {
            return Ok(());
        }
    }

    Err(MoveError::Serialization(format!(
        "object '{}' (apiVersion '{}') is not allowed during move operations — \
         only CAPI groups and core Secret/ConfigMap are permitted",
        kind, api_version
    )))
}

/// Strip transient fields that shouldn't be copied to target
fn strip_transient_fields(obj: &mut Value) {
    if let Some(metadata) = obj.get_mut("metadata").and_then(|m| m.as_object_mut()) {
        // Remove server-assigned fields
        metadata.remove("uid");
        metadata.remove("resourceVersion");
        metadata.remove("creationTimestamp");
        metadata.remove("generation");
        metadata.remove("selfLink");
        metadata.remove("managedFields");

        // Remove owner references (will be rebuilt)
        metadata.remove("ownerReferences");

        // Clean up annotations
        if let Some(annotations) = metadata
            .get_mut("annotations")
            .and_then(|a| a.as_object_mut())
        {
            // Remove kubectl last-applied-configuration
            annotations.remove("kubectl.kubernetes.io/last-applied-configuration");
            // Remove helm annotations
            annotations.retain(|k, _| !k.starts_with("meta.helm.sh/"));
        }
    }

    // Remove status (server-side only)
    if let Some(obj_map) = obj.as_object_mut() {
        obj_map.remove("status");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_transient_fields() {
        let mut obj = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "test-secret",
                "namespace": "default",
                "uid": "old-uid",
                "resourceVersion": "12345",
                "creationTimestamp": "2024-01-01T00:00:00Z",
                "generation": 1,
                "managedFields": [],
                "ownerReferences": [{"uid": "owner-uid"}],
                "annotations": {
                    "kubectl.kubernetes.io/last-applied-configuration": "{}",
                    "meta.helm.sh/release-name": "test",
                    "custom-annotation": "keep"
                }
            },
            "status": {"phase": "Active"}
        });

        strip_transient_fields(&mut obj);

        assert!(obj["metadata"]["uid"].is_null());
        assert!(obj["metadata"]["resourceVersion"].is_null());
        assert!(obj["metadata"]["creationTimestamp"].is_null());
        assert!(obj["metadata"]["ownerReferences"].is_null());
        assert!(obj["status"].is_null());
        assert_eq!(obj["metadata"]["name"], "test-secret");
        assert_eq!(obj["metadata"]["annotations"]["custom-annotation"], "keep");
        assert!(
            obj["metadata"]["annotations"]["kubectl.kubernetes.io/last-applied-configuration"]
                .is_null()
        );
    }

    #[test]
    fn test_build_api_resource() {
        let ar = build_api_resource("cluster.x-k8s.io/v1beta1", "Cluster");
        assert_eq!(ar.group, "cluster.x-k8s.io");
        assert_eq!(ar.version, "v1beta1");
        assert_eq!(ar.kind, "Cluster");
        assert_eq!(ar.plural, "clusters");
    }

    #[test]
    fn test_source_uid_annotation_constant() {
        assert_eq!(SOURCE_UID_ANNOTATION, "lattice.dev/source-uid");
    }

    #[test]
    fn test_validate_move_object_kind_allows_capi_and_core() {
        // CAPI groups
        assert!(validate_move_object_kind("cluster.x-k8s.io/v1beta1", "Cluster").is_ok());
        assert!(
            validate_move_object_kind("infrastructure.cluster.x-k8s.io/v1beta2", "AWSCluster")
                .is_ok()
        );
        assert!(
            validate_move_object_kind("bootstrap.cluster.x-k8s.io/v1beta1", "KubeadmConfig")
                .is_ok()
        );
        assert!(
            validate_move_object_kind(
                "controlplane.cluster.x-k8s.io/v1beta1",
                "KubeadmControlPlane"
            )
            .is_ok()
        );
        assert!(
            validate_move_object_kind("addon.cluster.x-k8s.io/v1alpha1", "ClusterResourceSet")
                .is_ok()
        );
        // Core types needed for CAPI
        assert!(validate_move_object_kind("v1", "Secret").is_ok());
        assert!(validate_move_object_kind("v1", "ConfigMap").is_ok());
    }

    #[test]
    fn test_validate_move_object_kind_rejects_non_capi_groups() {
        // Non-CAPI groups are rejected by allowlist (not just security-sensitive ones)
        assert!(validate_move_object_kind("apps/v1", "Deployment").is_err());
        assert!(validate_move_object_kind("rbac.authorization.k8s.io/v1", "ClusterRole").is_err());
        assert!(
            validate_move_object_kind("rbac.authorization.k8s.io/v1", "ClusterRoleBinding")
                .is_err()
        );
        assert!(validate_move_object_kind("networking.k8s.io/v1", "NetworkPolicy").is_err());
        assert!(validate_move_object_kind(
            "admissionregistration.k8s.io/v1",
            "ValidatingWebhookConfiguration"
        )
        .is_err());
        assert!(validate_move_object_kind("storage.k8s.io/v1", "StorageClass").is_err());
        assert!(validate_move_object_kind("policy/v1", "PodDisruptionBudget").is_err());
        assert!(
            validate_move_object_kind("certificates.k8s.io/v1", "CertificateSigningRequest")
                .is_err()
        );
    }

    #[test]
    fn test_validate_move_object_kind_rejects_non_allowed_core_kinds() {
        // Core API kinds not in the allowlist
        assert!(validate_move_object_kind("v1", "ServiceAccount").is_err());
        assert!(validate_move_object_kind("v1", "Pod").is_err());
        assert!(validate_move_object_kind("v1", "Service").is_err());
    }

    #[test]
    fn test_merge_uid_map() {
        // Test the merge logic: existing keys are NOT overwritten
        let mut uid_map = HashMap::new();
        uid_map.insert("source-1".to_string(), "target-1".to_string());
        uid_map.insert("source-2".to_string(), "target-2".to_string());

        let mut new_map = HashMap::new();
        new_map.insert("source-2".to_string(), "target-2-new".to_string()); // existing
        new_map.insert("source-3".to_string(), "target-3".to_string()); // new

        for (source_uid, target_uid) in new_map {
            uid_map.entry(source_uid).or_insert(target_uid);
        }

        assert_eq!(uid_map.get("source-1"), Some(&"target-1".to_string()));
        assert_eq!(uid_map.get("source-2"), Some(&"target-2".to_string())); // NOT overwritten
        assert_eq!(uid_map.get("source-3"), Some(&"target-3".to_string())); // added
    }
}
