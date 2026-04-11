//! ObjectMeta, OwnerReference, and metadata-stripping utilities.

use std::collections::BTreeMap;

/// Kubernetes owner reference for garbage collection cascading.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OwnerReference {
    /// API version of the referent (e.g. "lattice.dev/v1alpha1")
    pub api_version: String,
    /// Kind of the referent (e.g. "LatticeService", "LatticeJob")
    pub kind: String,
    /// Name of the referent
    pub name: String,
    /// UID of the referent
    pub uid: String,
    /// If true, this reference points to the managing controller
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<bool>,
    /// If true, the owner cannot be deleted until this reference is removed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_owner_deletion: Option<bool>,
}

impl From<&OwnerReference> for k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
    fn from(oref: &OwnerReference) -> Self {
        Self {
            api_version: oref.api_version.clone(),
            kind: oref.kind.clone(),
            name: oref.name.clone(),
            uid: oref.uid.clone(),
            controller: oref.controller,
            block_owner_deletion: oref.block_owner_deletion,
        }
    }
}

impl From<&k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference> for OwnerReference {
    fn from(oref: &k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference) -> Self {
        Self {
            api_version: oref.api_version.clone(),
            kind: oref.kind.clone(),
            name: oref.name.clone(),
            uid: oref.uid.clone(),
            controller: oref.controller,
            block_owner_deletion: oref.block_owner_deletion,
        }
    }
}

/// Standard Kubernetes ObjectMeta for compiled resources.
///
/// Used by all resource types (workloads, policies, ingress, certificates)
/// as the unified metadata representation. Automatically adds Lattice
/// management labels on construction.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ObjectMeta {
    /// Resource name
    pub name: String,
    /// Resource namespace
    pub namespace: String,
    /// Labels
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Annotations
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    /// Owner references for GC cascading
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_references: Vec<OwnerReference>,
}

impl ObjectMeta {
    /// Create new metadata with standard Lattice labels
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        let name = name.into();
        let mut labels = BTreeMap::new();
        labels.insert(crate::LABEL_NAME.to_string(), name.clone());
        labels.insert(
            crate::LABEL_MANAGED_BY.to_string(),
            crate::LABEL_MANAGED_BY_LATTICE.to_string(),
        );
        Self {
            name,
            namespace: namespace.into(),
            labels,
            annotations: BTreeMap::new(),
            owner_references: Vec::new(),
        }
    }

    /// Add a label
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Add an annotation
    pub fn with_annotation(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.annotations.insert(key.into(), value.into());
        self
    }

    /// Set owner references for GC cascading
    pub fn with_owner_references(mut self, refs: Vec<OwnerReference>) -> Self {
        self.owner_references = refs;
        self
    }
}

/// Label selector for Kubernetes resources (topology spread, affinity, etc.)
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    /// Match labels
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub match_labels: BTreeMap<String, String>,
}

/// Topology spread constraint for distributing pods across failure domains.
///
/// Reusable across LatticeService, LatticeJob, and ModelServing.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TopologySpreadConstraint {
    /// Maximum difference in pod count between topology domains
    pub max_skew: i32,
    /// Topology key (e.g., kubernetes.io/hostname, topology.kubernetes.io/zone)
    pub topology_key: String,
    /// What to do when constraint can't be satisfied (DoNotSchedule, ScheduleAnyway)
    pub when_unsatisfiable: String,
    /// Label selector to find pods to spread
    pub label_selector: LabelSelector,
}

/// Strip cluster-specific metadata from a resource for export/distribution.
///
/// Removes fields that would cause server-side apply to fail on a target cluster:
/// - uid: Unique identifier in the source cluster
/// - resourceVersion: Optimistic concurrency version
/// - creationTimestamp: When the source resource was created
/// - managedFields: Server-side apply ownership tracking
/// - generation: Controller-managed generation counter
pub use lattice_core::strip_export_metadata;

#[cfg(test)]
mod tests {
    use super::*;

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
            creation_timestamp: Some(Time(k8s_openapi::jiff::Timestamp::now())),
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
}
