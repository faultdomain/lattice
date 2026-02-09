//! Volume compiler for LatticeService
//!
//! This module handles:
//! - PVC generation for owned volumes (volumes with size)
//! - Pod affinity for RWO volume co-location (references follow owner's node)
//! - Model resources: pod volume references, scheduling gates (PVCs are created
//!   by the ModelCache controller, owned by the ModelArtifact CRD)
//! - Volume mounts in container specs

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::error::CompilationError;
use super::ObjectMeta;
use crate::crd::{LatticeServiceSpec, VolumeAccessMode};

// =============================================================================
// Kubernetes PVC Types
// =============================================================================

/// Kubernetes PersistentVolumeClaim
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PersistentVolumeClaim {
    /// API version (v1)
    pub api_version: String,
    /// Resource kind (PersistentVolumeClaim)
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// PVC spec
    pub spec: PvcSpec,
}

/// PVC spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PvcSpec {
    /// Access modes (ReadWriteOnce, ReadWriteMany, ReadOnlyMany)
    pub access_modes: Vec<String>,
    /// Resource requirements
    pub resources: PvcResources,
    /// Storage class name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class_name: Option<String>,
}

/// PVC resource requirements
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PvcResources {
    /// Storage requests
    pub requests: PvcStorage,
}

/// PVC storage request
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PvcStorage {
    /// Storage size (e.g., "10Gi")
    pub storage: String,
}

// =============================================================================
// Pod Affinity Types (for RWO volume co-location)
// =============================================================================

/// Pod affinity specification
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodAffinity {
    /// Required affinity terms - pods must satisfy these
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_during_scheduling_ignored_during_execution: Vec<PodAffinityTerm>,
}

/// Pod affinity term
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodAffinityTerm {
    /// Label selector for matching pods
    pub label_selector: LabelSelector,
    /// Topology key (e.g., kubernetes.io/hostname for same-node)
    pub topology_key: String,
    /// Namespaces to match pods in
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<Vec<String>>,
}

/// Label selector for affinity
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    /// Labels that must match
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub match_labels: BTreeMap<String, String>,
}

/// Full affinity spec for pod
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Affinity {
    /// Pod affinity rules
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_affinity: Option<PodAffinity>,
}

// =============================================================================
// PVC Volume Source
// =============================================================================

/// PVC volume source for pod volumes
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PvcVolumeSource {
    /// PVC claim name
    pub claim_name: String,
    /// Mount as read-only
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
}

// =============================================================================
// Generated Volumes Container
// =============================================================================

/// Collection of volume-related resources generated for a service
#[derive(Clone, Debug, Default)]
pub struct GeneratedVolumes {
    /// PVCs to create (for owned volumes only; model PVCs are managed by ModelCache controller)
    pub pvcs: Vec<PersistentVolumeClaim>,
    /// Pod labels to add (for volume ownership)
    pub pod_labels: BTreeMap<String, String>,
    /// Pod affinity rules (for RWO volume co-location)
    pub affinity: Option<Affinity>,
    /// Volumes to add to pod spec
    pub volumes: Vec<PodVolume>,
    /// Volume mounts per container (container_name -> mounts)
    pub volume_mounts: BTreeMap<String, Vec<super::VolumeMount>>,
    /// Scheduling gates to add to pod spec (for model cache readiness)
    pub scheduling_gates: Vec<super::SchedulingGate>,
}

/// Volume definition for pod spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodVolume {
    /// Volume name
    pub name: String,
    /// PVC volume source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_volume_claim: Option<PvcVolumeSource>,
    /// EmptyDir volume source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_dir: Option<super::EmptyDirVolumeSource>,
}

impl GeneratedVolumes {
    /// Create empty generated volumes
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if no volumes were generated
    pub fn is_empty(&self) -> bool {
        self.pvcs.is_empty()
            && self.pod_labels.is_empty()
            && self.affinity.is_none()
            && self.volumes.is_empty()
            && self.volume_mounts.is_empty()
            && self.scheduling_gates.is_empty()
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Convert a mount path to a valid K8s volume name.
///
/// E.g., `/var/cache/nginx` → `emptydir-var-cache-nginx`
///
/// K8s volume names must be lowercase alphanumeric + `-`, max 63 chars.
fn sanitize_volume_name(mount_path: &str) -> String {
    let sanitized: String = mount_path
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();
    let trimmed = sanitized.trim_matches('-');
    let name = format!("emptydir-{}", trimmed);
    if name.len() > 63 {
        name[..63].trim_end_matches('-').to_string()
    } else {
        name
    }
}

// =============================================================================
// Volume Compiler
// =============================================================================

/// Label prefix for volume ownership
pub const VOLUME_OWNER_LABEL_PREFIX: &str = "lattice.dev/volume-owner-";

/// Compiler for generating volume-related Kubernetes resources
pub struct VolumeCompiler;

impl VolumeCompiler {
    /// Compile volume and model resources for a LatticeService
    ///
    /// Handles both `type: volume` and `type: model` resources:
    /// - Volumes: PVCs with owner/reference pattern, RWO affinity
    /// - Models: Content-addressable PVCs, read-only mounts, scheduling gates
    ///
    /// # Arguments
    /// * `service_name` - Name of the service
    /// * `namespace` - Target namespace
    /// * `spec` - LatticeService spec
    ///
    /// # Returns
    /// Generated volume resources including PVCs, pod labels, affinity rules,
    /// volume mounts, and scheduling gates.
    pub fn compile(
        service_name: &str,
        namespace: &str,
        spec: &LatticeServiceSpec,
    ) -> Result<GeneratedVolumes, CompilationError> {
        let mut output = GeneratedVolumes::new();

        // -----------------------------------------------------------------
        // Process regular volume resources
        // -----------------------------------------------------------------
        let volume_resources: Vec<_> = spec
            .resources
            .iter()
            .filter(|(_, r)| r.type_.is_volume())
            .collect();

        for (resource_name, resource_spec) in &volume_resources {
            let pvc_name = resource_spec
                .volume_pvc_name(service_name, resource_name)
                .unwrap_or_else(|| format!("{}-{}", service_name, resource_name));

            // Generate PVC for owned volumes (has size)
            if resource_spec.is_volume_owner() {
                let params = resource_spec
                    .volume_params()
                    .map_err(|e| {
                        CompilationError::volume(format!("resource '{}': {}", resource_name, e))
                    })?
                    .unwrap_or_default();
                let pvc = Self::compile_pvc(&pvc_name, namespace, &params);
                output.pvcs.push(pvc);

                // Add owner label for RWO volumes so references can find us
                if let Some(id) = &resource_spec.id {
                    let access_mode = params.access_mode.unwrap_or_default();
                    if access_mode == VolumeAccessMode::ReadWriteOnce {
                        let label_key = format!("{}{}", VOLUME_OWNER_LABEL_PREFIX, id);
                        output.pod_labels.insert(label_key, "true".to_string());
                    }
                }
            }

            // Generate pod affinity for RWO volume references
            if resource_spec.is_volume_reference() {
                if let Some(id) = &resource_spec.id {
                    let label_key = format!("{}{}", VOLUME_OWNER_LABEL_PREFIX, id);

                    let affinity_term = PodAffinityTerm {
                        label_selector: LabelSelector {
                            match_labels: {
                                let mut labels = BTreeMap::new();
                                labels.insert(label_key, "true".to_string());
                                labels
                            },
                        },
                        topology_key: "kubernetes.io/hostname".to_string(),
                        namespaces: Some(vec![namespace.to_string()]),
                    };

                    let affinity = output.affinity.get_or_insert_with(Affinity::default);
                    let pod_affinity = affinity
                        .pod_affinity
                        .get_or_insert_with(PodAffinity::default);
                    pod_affinity
                        .required_during_scheduling_ignored_during_execution
                        .push(affinity_term);
                }
            }

            // Generate pod volume
            output.volumes.push(PodVolume {
                name: resource_name.to_string(),
                persistent_volume_claim: Some(PvcVolumeSource {
                    claim_name: pvc_name,
                    read_only: None,
                }),
                empty_dir: None,
            });
        }

        // -----------------------------------------------------------------
        // Process model resources
        // -----------------------------------------------------------------
        let model_resources: Vec<_> = spec
            .resources
            .iter()
            .filter(|(_, r)| r.type_.is_model())
            .collect();

        for (resource_name, resource_spec) in &model_resources {
            let params = resource_spec
                .model_params()
                .map_err(|e| {
                    CompilationError::volume(format!("resource '{}': {}", resource_name, e))
                })?
                .ok_or_else(|| {
                    CompilationError::volume(format!(
                        "resource '{}': expected model params",
                        resource_name
                    ))
                })?;

            let pvc_name = params.cache_pvc_name();

            // PVC is created by the ModelCache controller (owned by ModelArtifact).
            // We only generate the pod volume reference here.

            // Generate pod volume (read-only — model data is immutable once cached)
            output.volumes.push(PodVolume {
                name: resource_name.to_string(),
                persistent_volume_claim: Some(PvcVolumeSource {
                    claim_name: pvc_name,
                    read_only: Some(true),
                }),
                empty_dir: None,
            });
        }

        // Add scheduling gate if any model resources are present
        if !model_resources.is_empty() {
            output.scheduling_gates.push(super::SchedulingGate {
                name: crate::crd::MODEL_READY_GATE.to_string(),
            });
        }

        // -----------------------------------------------------------------
        // Generate volume mounts (for both volume/model resources and emptyDir)
        // -----------------------------------------------------------------
        let all_mountable: Vec<_> = spec
            .resources
            .iter()
            .filter(|(_, r)| r.type_.is_volume_like())
            .collect();

        // Container volume mounts
        for (container_name, container_spec) in &spec.containers {
            let (mounts, extra_vols) =
                Self::resolve_mounts(&container_spec.volumes, &all_mountable);
            if !mounts.is_empty() {
                output.volume_mounts.insert(container_name.clone(), mounts);
            }
            output.volumes.extend(extra_vols);
        }

        // Sidecar volume mounts
        for (sidecar_name, sidecar_spec) in &spec.sidecars {
            let (mounts, extra_vols) =
                Self::resolve_mounts(&sidecar_spec.volumes, &all_mountable);
            if !mounts.is_empty() {
                output.volume_mounts.insert(sidecar_name.clone(), mounts);
            }
            output.volumes.extend(extra_vols);
        }

        Ok(output)
    }

    /// Compile a PVC from volume params
    fn compile_pvc(
        name: &str,
        namespace: &str,
        params: &crate::crd::VolumeParams,
    ) -> PersistentVolumeClaim {
        let access_mode = match params.access_mode {
            Some(VolumeAccessMode::ReadWriteMany) => "ReadWriteMany",
            Some(VolumeAccessMode::ReadOnlyMany) => "ReadOnlyMany",
            Some(VolumeAccessMode::ReadWriteOnce) | None => "ReadWriteOnce",
        };

        PersistentVolumeClaim {
            api_version: "v1".to_string(),
            kind: "PersistentVolumeClaim".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            spec: PvcSpec {
                access_modes: vec![access_mode.to_string()],
                resources: PvcResources {
                    requests: PvcStorage {
                        storage: params.size.clone().unwrap_or_else(|| "1Gi".to_string()),
                    },
                },
                storage_class_name: params.storage_class.clone(),
            },
        }
    }

    /// Resolve volume mounts from a container's volume declarations
    ///
    /// Handles two cases:
    /// 1. **Source present**: matches `${resources.name}` against mountable resources (PVC-backed)
    /// 2. **Source absent**: generates an emptyDir volume + mount
    ///
    /// Returns (volume_mounts, extra_pod_volumes) where extra_pod_volumes are
    /// emptyDir volumes that need to be added to the pod spec.
    fn resolve_mounts(
        volumes: &BTreeMap<String, crate::crd::VolumeMount>,
        mountable_resources: &[(&String, &crate::crd::ResourceSpec)],
    ) -> (Vec<super::VolumeMount>, Vec<PodVolume>) {
        let mut mounts = Vec::new();
        let mut extra_volumes = Vec::new();

        for (mount_path, volume_mount) in volumes {
            match &volume_mount.source {
                Some(source) => {
                    if let Some(resource_name) = Self::parse_volume_source(&source.to_string()) {
                        if mountable_resources
                            .iter()
                            .any(|(name, _)| name.as_str() == resource_name)
                        {
                            mounts.push(super::VolumeMount {
                                name: resource_name.to_string(),
                                mount_path: mount_path.clone(),
                                sub_path: volume_mount.path.clone(),
                                read_only: volume_mount.read_only,
                            });
                        }
                    }
                }
                None => {
                    let vol_name = sanitize_volume_name(mount_path);
                    extra_volumes.push(PodVolume {
                        name: vol_name.clone(),
                        persistent_volume_claim: None,
                        empty_dir: Some(super::EmptyDirVolumeSource {
                            medium: volume_mount.medium.clone(),
                            size_limit: volume_mount.size_limit.clone(),
                        }),
                    });
                    mounts.push(super::VolumeMount {
                        name: vol_name,
                        mount_path: mount_path.clone(),
                        sub_path: volume_mount.path.clone(),
                        read_only: volume_mount.read_only,
                    });
                }
            }
        }

        (mounts, extra_volumes)
    }

    /// Parse volume source template to extract resource name
    /// e.g., "${resources.config}" -> "config"
    fn parse_volume_source(source: &str) -> Option<String> {
        if source.starts_with("${resources.") && source.ends_with('}') {
            let inner = &source[12..source.len() - 1];
            Some(inner.to_string())
        } else {
            None
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{ContainerSpec, ResourceSpec, ResourceType, MODEL_READY_GATE};
    use lattice_common::template::TemplateString;

    fn make_spec_with_volumes(
        owned: Vec<(&str, Option<&str>, &str, Option<VolumeAccessMode>)>, // (name, id, size, access_mode)
        refs: Vec<(&str, &str)>,                                          // (name, id)
        container_mounts: Vec<(&str, &str)>, // (mount_path, resource_name)
    ) -> LatticeServiceSpec {
        let mut resources = BTreeMap::new();

        // Add owned volumes
        for (name, id, size, access_mode) in owned {
            let mut params = BTreeMap::new();
            params.insert("size".to_string(), serde_json::json!(size));
            if let Some(mode) = access_mode {
                let mode_str = match mode {
                    VolumeAccessMode::ReadWriteOnce => "ReadWriteOnce",
                    VolumeAccessMode::ReadWriteMany => "ReadWriteMany",
                    VolumeAccessMode::ReadOnlyMany => "ReadOnlyMany",
                };
                params.insert("accessMode".to_string(), serde_json::json!(mode_str));
            }
            resources.insert(
                name.to_string(),
                ResourceSpec {
                    type_: ResourceType::Volume,
                    id: id.map(|s: &str| s.to_string()),
                    params: Some(params),
                    ..Default::default()
                },
            );
        }

        // Add volume references
        for (name, id) in refs {
            resources.insert(
                name.to_string(),
                ResourceSpec {
                    type_: ResourceType::Volume,
                    id: Some(id.to_string()),
                    ..Default::default()
                },
            );
        }

        // Build container with volume mounts
        let mut volumes = BTreeMap::new();
        for (mount_path, resource_name) in container_mounts {
            volumes.insert(
                mount_path.to_string(),
                crate::crd::VolumeMount {
                    source: Some(TemplateString::from(format!(
                        "${{resources.{}}}",
                        resource_name
                    ))),
                    path: None,
                    read_only: None,
                    medium: None,
                    size_limit: None,
                },
            );
        }

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "nginx:latest".to_string(),
                volumes,
                ..Default::default()
            },
        );

        LatticeServiceSpec {
            containers,
            resources,
            ..Default::default()
        }
    }

    // =========================================================================
    // Story: Generate PVC for Owned Volumes
    // =========================================================================

    #[test]
    fn story_generates_pvc_for_owned_volume() {
        let spec = make_spec_with_volumes(
            vec![("config", None, "5Gi", None)],
            vec![],
            vec![("/config", "config")],
        );

        let output = VolumeCompiler::compile("myapp", "prod", &spec).unwrap();

        assert_eq!(output.pvcs.len(), 1);
        let pvc = &output.pvcs[0];
        assert_eq!(pvc.metadata.name, "myapp-config"); // No id, so service-resource name
        assert_eq!(pvc.metadata.namespace, "prod");
        assert_eq!(pvc.spec.resources.requests.storage, "5Gi");
        assert_eq!(pvc.spec.access_modes, vec!["ReadWriteOnce"]);
    }

    #[test]
    fn story_pvc_uses_volume_id_for_name() {
        let spec = make_spec_with_volumes(
            vec![("downloads", Some("media-downloads"), "500Gi", None)],
            vec![],
            vec![("/downloads", "downloads")],
        );

        let output = VolumeCompiler::compile("nzbget", "media", &spec).unwrap();

        assert_eq!(output.pvcs.len(), 1);
        let pvc = &output.pvcs[0];
        assert_eq!(pvc.metadata.name, "vol-media-downloads"); // Uses id
    }

    #[test]
    fn story_pvc_respects_storage_class() {
        let mut spec = make_spec_with_volumes(
            vec![("config", None, "5Gi", None)],
            vec![],
            vec![("/config", "config")],
        );

        // Add storage class to volume config via params
        if let Some(resource) = spec.resources.get_mut("config") {
            if let Some(params) = resource.params.as_mut() {
                params.insert("storageClass".to_string(), serde_json::json!("local-path"));
            }
        }

        let output = VolumeCompiler::compile("myapp", "prod", &spec).unwrap();

        let pvc = &output.pvcs[0];
        assert_eq!(pvc.spec.storage_class_name, Some("local-path".to_string()));
    }

    #[test]
    fn story_pvc_respects_access_mode() {
        let spec = make_spec_with_volumes(
            vec![(
                "media",
                Some("media-library"),
                "1Ti",
                Some(VolumeAccessMode::ReadWriteMany),
            )],
            vec![],
            vec![("/media", "media")],
        );

        let output = VolumeCompiler::compile("jellyfin", "media", &spec).unwrap();

        let pvc = &output.pvcs[0];
        assert_eq!(pvc.spec.access_modes, vec!["ReadWriteMany"]);
    }

    // =========================================================================
    // Story: No PVC for Volume References
    // =========================================================================

    #[test]
    fn story_no_pvc_for_volume_reference() {
        let spec = make_spec_with_volumes(
            vec![],
            vec![("downloads", "media-downloads")],
            vec![("/downloads", "downloads")],
        );

        let output = VolumeCompiler::compile("sonarr", "media", &spec).unwrap();

        // No PVCs - this is a reference
        assert!(output.pvcs.is_empty());

        // But should still have pod volume pointing to the PVC
        assert_eq!(output.volumes.len(), 1);
        assert_eq!(output.volumes[0].name, "downloads");
        assert_eq!(
            output.volumes[0]
                .persistent_volume_claim
                .as_ref()
                .expect("PVC volume source should be set")
                .claim_name,
            "vol-media-downloads"
        );
    }

    // =========================================================================
    // Story: Pod Labels for Volume Ownership (RWO)
    // =========================================================================

    #[test]
    fn story_owner_gets_volume_label_for_rwo() {
        let spec = make_spec_with_volumes(
            vec![(
                "downloads",
                Some("media-downloads"),
                "500Gi",
                Some(VolumeAccessMode::ReadWriteOnce),
            )],
            vec![],
            vec![("/downloads", "downloads")],
        );

        let output = VolumeCompiler::compile("nzbget", "media", &spec).unwrap();

        // Should have owner label for RWO volume
        assert_eq!(
            output
                .pod_labels
                .get("lattice.dev/volume-owner-media-downloads"),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn story_owner_no_label_for_rwx() {
        let spec = make_spec_with_volumes(
            vec![(
                "media",
                Some("media-library"),
                "1Ti",
                Some(VolumeAccessMode::ReadWriteMany),
            )],
            vec![],
            vec![("/media", "media")],
        );

        let output = VolumeCompiler::compile("jellyfin", "media", &spec).unwrap();

        // No owner label for RWX - no affinity needed
        assert!(output.pod_labels.is_empty());
    }

    // =========================================================================
    // Story: Pod Affinity for Volume References
    // =========================================================================

    #[test]
    fn story_reference_gets_affinity_to_owner() {
        let spec = make_spec_with_volumes(
            vec![],
            vec![("downloads", "media-downloads")],
            vec![("/downloads", "downloads")],
        );

        let output = VolumeCompiler::compile("sonarr", "media", &spec).unwrap();

        // Should have affinity to owner
        let affinity = output.affinity.expect("should have affinity");
        let pod_affinity = affinity.pod_affinity.expect("should have pod affinity");
        let terms = &pod_affinity.required_during_scheduling_ignored_during_execution;

        assert_eq!(terms.len(), 1);
        assert_eq!(terms[0].topology_key, "kubernetes.io/hostname");
        assert_eq!(
            terms[0]
                .label_selector
                .match_labels
                .get("lattice.dev/volume-owner-media-downloads"),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn story_multiple_references_get_multiple_affinities() {
        let spec = make_spec_with_volumes(
            vec![],
            vec![("downloads", "media-downloads"), ("media", "media-library")],
            vec![("/downloads", "downloads"), ("/media", "media")],
        );

        let output = VolumeCompiler::compile("sonarr", "media", &spec).unwrap();

        let affinity = output.affinity.expect("should have affinity");
        let pod_affinity = affinity.pod_affinity.expect("should have pod affinity");
        let terms = &pod_affinity.required_during_scheduling_ignored_during_execution;

        assert_eq!(terms.len(), 2);
    }

    // =========================================================================
    // Story: Volume Mounts
    // =========================================================================

    #[test]
    fn story_generates_volume_mounts() {
        let spec = make_spec_with_volumes(
            vec![("config", None, "5Gi", None)],
            vec![],
            vec![("/config", "config")],
        );

        let output = VolumeCompiler::compile("myapp", "prod", &spec).unwrap();

        let mounts = output
            .volume_mounts
            .get("main")
            .expect("should have mounts for main");
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].name, "config");
        assert_eq!(mounts[0].mount_path, "/config");
    }

    #[test]
    fn story_generates_pod_volumes() {
        let spec = make_spec_with_volumes(
            vec![("config", None, "5Gi", None)],
            vec![],
            vec![("/config", "config")],
        );

        let output = VolumeCompiler::compile("myapp", "prod", &spec).unwrap();

        assert_eq!(output.volumes.len(), 1);
        assert_eq!(output.volumes[0].name, "config");
        let pvc_source = output.volumes[0]
            .persistent_volume_claim
            .as_ref()
            .expect("PVC volume source should be set");
        assert_eq!(pvc_source.claim_name, "myapp-config");
    }

    // =========================================================================
    // Story: Parse Volume Source Template
    // =========================================================================

    #[test]
    fn story_parse_volume_source() {
        assert_eq!(
            VolumeCompiler::parse_volume_source("${resources.config}"),
            Some("config".to_string())
        );
        assert_eq!(
            VolumeCompiler::parse_volume_source("${resources.media-downloads}"),
            Some("media-downloads".to_string())
        );
        assert_eq!(VolumeCompiler::parse_volume_source("invalid"), None);
        assert_eq!(VolumeCompiler::parse_volume_source("${other.thing}"), None);
    }

    // =========================================================================
    // Story: Empty Input
    // =========================================================================

    #[test]
    fn story_no_volumes_returns_empty() {
        let spec = LatticeServiceSpec::default();

        let output = VolumeCompiler::compile("myapp", "prod", &spec).unwrap();

        assert!(output.is_empty());
    }

    // =========================================================================
    // Story: Model Cache PVC Generation
    // =========================================================================

    fn make_model_spec(
        model_mounts: Vec<(&str, &str)>, // (mount_path, resource_name)
    ) -> LatticeServiceSpec {
        let mut resources = BTreeMap::new();
        let mut params = BTreeMap::new();
        params.insert(
            "uri".to_string(),
            serde_json::json!("huggingface://meta-llama/Llama-3.3-70B-Instruct"),
        );
        params.insert("size".to_string(), serde_json::json!("140Gi"));
        resources.insert(
            "llm".to_string(),
            ResourceSpec {
                type_: ResourceType::Model,
                params: Some(params),
                ..Default::default()
            },
        );

        let mut volumes = BTreeMap::new();
        for (mount_path, resource_name) in model_mounts {
            volumes.insert(
                mount_path.to_string(),
                crate::crd::VolumeMount {
                    source: Some(TemplateString::from(format!(
                        "${{resources.{}}}",
                        resource_name
                    ))),
                    path: None,
                    read_only: None,
                    medium: None,
                    size_limit: None,
                },
            );
        }

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "vllm/vllm-openai:latest".to_string(),
                volumes,
                ..Default::default()
            },
        );

        LatticeServiceSpec {
            containers,
            resources,
            ..Default::default()
        }
    }

    #[test]
    fn story_no_pvc_for_model_resources() {
        // Model PVCs are created by the ModelCache controller, not VolumeCompiler
        let spec = make_model_spec(vec![("/models", "llm")]);
        let output = VolumeCompiler::compile("llm-service", "prod", &spec).unwrap();

        assert!(
            output.pvcs.is_empty(),
            "VolumeCompiler should not create PVCs for model resources"
        );
    }

    #[test]
    fn story_model_volume_is_read_only() {
        let spec = make_model_spec(vec![("/models", "llm")]);
        let output = VolumeCompiler::compile("llm-service", "prod", &spec).unwrap();

        let pod_vol = &output.volumes[0];
        let pvc_source = pod_vol.persistent_volume_claim.as_ref().unwrap();
        assert_eq!(pvc_source.read_only, Some(true));
    }

    #[test]
    fn story_model_adds_scheduling_gate() {
        let spec = make_model_spec(vec![("/models", "llm")]);
        let output = VolumeCompiler::compile("llm-service", "prod", &spec).unwrap();

        assert_eq!(output.scheduling_gates.len(), 1);
        assert_eq!(output.scheduling_gates[0].name, MODEL_READY_GATE);
    }

    #[test]
    fn story_model_generates_volume_mount() {
        let spec = make_model_spec(vec![("/models", "llm")]);
        let output = VolumeCompiler::compile("llm-service", "prod", &spec).unwrap();

        let mounts = output
            .volume_mounts
            .get("main")
            .expect("should have mounts for main");
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].name, "llm");
        assert_eq!(mounts[0].mount_path, "/models");
    }

    #[test]
    fn story_no_scheduling_gate_without_model() {
        let spec = make_spec_with_volumes(
            vec![("config", None, "5Gi", None)],
            vec![],
            vec![("/config", "config")],
        );

        let output = VolumeCompiler::compile("myapp", "prod", &spec).unwrap();
        assert!(output.scheduling_gates.is_empty());
    }

    #[test]
    fn story_model_pod_volume_is_content_addressable() {
        // Same model URI should produce the same PVC claim_name regardless of service name
        let spec1 = make_model_spec(vec![("/models", "llm")]);
        let spec2 = make_model_spec(vec![("/models", "llm")]);

        let out1 = VolumeCompiler::compile("service-a", "prod", &spec1).unwrap();
        let out2 = VolumeCompiler::compile("service-b", "prod", &spec2).unwrap();

        let claim1 = &out1.volumes[0]
            .persistent_volume_claim
            .as_ref()
            .unwrap()
            .claim_name;
        let claim2 = &out2.volumes[0]
            .persistent_volume_claim
            .as_ref()
            .unwrap()
            .claim_name;
        assert_eq!(claim1, claim2);
    }

    // =========================================================================
    // Story: Mixed Volume and Model Resources
    // =========================================================================

    #[test]
    fn story_mixed_volumes_and_models() {
        let mut resources = BTreeMap::new();

        // Regular volume
        let mut vol_params = BTreeMap::new();
        vol_params.insert("size".to_string(), serde_json::json!("10Gi"));
        resources.insert(
            "data".to_string(),
            ResourceSpec {
                type_: ResourceType::Volume,
                params: Some(vol_params),
                ..Default::default()
            },
        );

        // Model resource
        let mut model_params = BTreeMap::new();
        model_params.insert(
            "uri".to_string(),
            serde_json::json!("huggingface://meta-llama/Llama-3.3-70B-Instruct"),
        );
        resources.insert(
            "llm".to_string(),
            ResourceSpec {
                type_: ResourceType::Model,
                params: Some(model_params),
                ..Default::default()
            },
        );

        let mut volumes = BTreeMap::new();
        volumes.insert(
            "/data".to_string(),
            crate::crd::VolumeMount {
                source: Some(TemplateString::from("${resources.data}")),
                path: None,
                read_only: None,
                medium: None,
                size_limit: None,
            },
        );
        volumes.insert(
            "/models".to_string(),
            crate::crd::VolumeMount {
                source: Some(TemplateString::from("${resources.llm}")),
                path: None,
                read_only: None,
                medium: None,
                size_limit: None,
            },
        );

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "myapp:latest".to_string(),
                volumes,
                ..Default::default()
            },
        );

        let spec = LatticeServiceSpec {
            containers,
            resources,
            ..Default::default()
        };

        let output = VolumeCompiler::compile("myapp", "prod", &spec).unwrap();

        // 1 PVC: only the regular volume (model PVC is created by ModelCache controller)
        assert_eq!(output.pvcs.len(), 1);

        // 2 pod volumes
        assert_eq!(output.volumes.len(), 2);

        // Scheduling gate from model
        assert_eq!(output.scheduling_gates.len(), 1);
        assert_eq!(output.scheduling_gates[0].name, MODEL_READY_GATE);

        // Both mounts present
        let mounts = output.volume_mounts.get("main").unwrap();
        assert_eq!(mounts.len(), 2);
    }
}
