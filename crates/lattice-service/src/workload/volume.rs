//! Volume compiler for LatticeService
//!
//! This module handles:
//! - PVC generation for owned volumes (volumes with size)
//! - Pod affinity for RWO volume co-location (references follow owner's node)
//! - Volume mounts in container specs

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::ObjectMeta;
use crate::crd::{LatticeServiceSpec, ResourceType, VolumeAccessMode};

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
    /// Preferred affinity terms - soft preferences for scheduling
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preferred_during_scheduling_ignored_during_execution: Vec<WeightedPodAffinityTerm>,
}

/// Weighted pod affinity term for soft scheduling preferences
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WeightedPodAffinityTerm {
    /// Weight (1-100, higher = stronger preference)
    pub weight: i32,
    /// The affinity term
    pub pod_affinity_term: PodAffinityTerm,
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
    /// PVCs to create (only for owned volumes)
    pub pvcs: Vec<PersistentVolumeClaim>,
    /// Pod labels to add (for volume ownership)
    pub pod_labels: BTreeMap<String, String>,
    /// Pod affinity rules (for RWO volume co-location)
    pub affinity: Option<Affinity>,
    /// Volumes to add to pod spec
    pub volumes: Vec<PodVolume>,
    /// Volume mounts per container (container_name -> mounts)
    pub volume_mounts: BTreeMap<String, Vec<super::VolumeMount>>,
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
    /// Compile volume resources for a LatticeService
    ///
    /// # Arguments
    /// * `service_name` - Name of the service
    /// * `namespace` - Target namespace
    /// * `spec` - LatticeService spec
    /// * `graph` - Optional service graph for cross-owner affinity computation
    ///
    /// # Returns
    /// Generated volume resources including PVCs, pod labels, affinity rules,
    /// and volume mounts
    ///
    /// # Cross-Owner Affinity
    ///
    /// When multiple services own RWO volumes that are referenced by the same
    /// consumer service, those owners need to be on the same node. This method
    /// uses the service graph to compute these relationships and adds preferred
    /// affinity between owners that share a referencer.
    ///
    /// Example: jellyfin owns media-library, nzbget owns media-downloads, and
    /// sonarr references both. jellyfin and nzbget will get preferred affinity
    /// to each other so sonarr can schedule on a node with both.
    pub fn compile(
        service_name: &str,
        namespace: &str,
        spec: &LatticeServiceSpec,
        graph: Option<&crate::graph::ServiceGraph>,
    ) -> GeneratedVolumes {
        let mut output = GeneratedVolumes::new();

        // Collect all volume resources
        let volume_resources: Vec<_> = spec
            .resources
            .iter()
            .filter(|(_, r)| r.type_ == ResourceType::Volume)
            .collect();

        if volume_resources.is_empty() {
            return output;
        }

        // Process each volume resource
        for (resource_name, resource_spec) in &volume_resources {
            let pvc_name = resource_spec
                .volume_pvc_name(service_name, resource_name)
                .unwrap_or_else(|| format!("{}-{}", service_name, resource_name));

            // Generate PVC for owned volumes (has size)
            if resource_spec.is_volume_owner() {
                let params = resource_spec.volume_params().unwrap_or_default();
                let pvc = Self::compile_pvc(&pvc_name, namespace, &params);
                output.pvcs.push(pvc);

                // Add owner label for RWO volumes so references can find us
                if let Some(id) = &resource_spec.id {
                    let access_mode = params.access_mode.unwrap_or_default();
                    if access_mode == VolumeAccessMode::ReadWriteOnce {
                        let label_key = format!("{}{}", VOLUME_OWNER_LABEL_PREFIX, id);
                        output.pod_labels.insert(label_key, "true".to_string());

                        // Use the graph to find other owners we need cross-affinity with
                        if let Some(graph) = graph {
                            let cross_affinity_owners =
                                graph.find_rwo_cross_affinity_owners(namespace, service_name, id);

                            for other_owner in cross_affinity_owners {
                                // Add preferred affinity to other owner's label
                                // Find the volume ID they own by looking it up in the graph
                                if let Some(other_node) = graph.get_service(namespace, &other_owner)
                                {
                                    for other_volume_id in &other_node.owned_rwo_volumes {
                                        let other_label_key = format!(
                                            "{}{}",
                                            VOLUME_OWNER_LABEL_PREFIX, other_volume_id
                                        );

                                        let affinity_term = WeightedPodAffinityTerm {
                                            weight: 100, // Strong preference
                                            pod_affinity_term: PodAffinityTerm {
                                                label_selector: LabelSelector {
                                                    match_labels: {
                                                        let mut labels = BTreeMap::new();
                                                        labels
                                                            .insert(other_label_key, "true".to_string());
                                                        labels
                                                    },
                                                },
                                                topology_key: "kubernetes.io/hostname".to_string(),
                                                namespaces: Some(vec![namespace.to_string()]),
                                            },
                                        };

                                        let affinity =
                                            output.affinity.get_or_insert_with(Affinity::default);
                                        let pod_affinity = affinity
                                            .pod_affinity
                                            .get_or_insert_with(PodAffinity::default);
                                        pod_affinity
                                            .preferred_during_scheduling_ignored_during_execution
                                            .push(affinity_term);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Generate pod affinity for RWO volume references
            if resource_spec.is_volume_reference() {
                if let Some(id) = &resource_spec.id {
                    // For references, we need affinity to the owner pod
                    // Note: We assume RWO for references since we can't know the owner's access mode
                    // In practice, the owner decides and references must comply
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

                    // Add to affinity
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
            });
        }

        // Generate volume mounts from container specs
        for (container_name, container_spec) in &spec.containers {
            let mut mounts = Vec::new();

            for (mount_path, volume_mount) in &container_spec.volumes {
                // Parse the source to find the resource name
                // Source is like "${resources.config}" or "${resources.downloads}"
                if let Some(resource_name) =
                    Self::parse_volume_source(&volume_mount.source.to_string())
                {
                    // Only add mount if we have this volume resource
                    if volume_resources
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

            if !mounts.is_empty() {
                output.volume_mounts.insert(container_name.clone(), mounts);
            }
        }

        output
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
    use crate::crd::{ContainerSpec, DependencyDirection, DeploySpec, ReplicaSpec, ResourceSpec};
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
                    direction: DependencyDirection::default(),
                    id: id.map(|s: &str| s.to_string()),
                    class: None,
                    metadata: None,
                    params: Some(params),
                    namespace: None,
                    inbound: None,
                    outbound: None,
                },
            );
        }

        // Add volume references
        for (name, id) in refs {
            resources.insert(
                name.to_string(),
                ResourceSpec {
                    type_: ResourceType::Volume,
                    direction: DependencyDirection::default(),
                    id: Some(id.to_string()),
                    class: None,
                    metadata: None,
                    params: None, // No params = reference
                    namespace: None,
                    inbound: None,
                    outbound: None,
                },
            );
        }

        // Build container with volume mounts
        let mut volumes = BTreeMap::new();
        for (mount_path, resource_name) in container_mounts {
            volumes.insert(
                mount_path.to_string(),
                crate::crd::VolumeMount {
                    source: TemplateString::from(format!("${{resources.{}}}", resource_name)),
                    path: None,
                    read_only: None,
                },
            );
        }

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "nginx:latest".to_string(),
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files: BTreeMap::new(),
                volumes,
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
            },
        );

        LatticeServiceSpec {
            containers,
            resources,
            service: None,
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
            ingress: None,
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

        let output = VolumeCompiler::compile("myapp", "prod", &spec, None);

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

        let output = VolumeCompiler::compile("nzbget", "media", &spec, None);

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

        let output = VolumeCompiler::compile("myapp", "prod", &spec, None);

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

        let output = VolumeCompiler::compile("jellyfin", "media", &spec, None);

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

        let output = VolumeCompiler::compile("sonarr", "media", &spec, None);

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

        let output = VolumeCompiler::compile("nzbget", "media", &spec, None);

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

        let output = VolumeCompiler::compile("jellyfin", "media", &spec, None);

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

        let output = VolumeCompiler::compile("sonarr", "media", &spec, None);

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

        let output = VolumeCompiler::compile("sonarr", "media", &spec, None);

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

        let output = VolumeCompiler::compile("myapp", "prod", &spec, None);

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

        let output = VolumeCompiler::compile("myapp", "prod", &spec, None);

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
        let spec = LatticeServiceSpec {
            containers: BTreeMap::new(),
            resources: BTreeMap::new(),
            service: None,
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
            ingress: None,
        };

        let output = VolumeCompiler::compile("myapp", "prod", &spec, None);

        assert!(output.is_empty());
    }

    // =========================================================================
    // Story: Cross-Owner Affinity via Graph
    // =========================================================================

    #[test]
    fn story_cross_owner_affinity_via_graph() {
        use crate::graph::ServiceGraph;

        // Scenario: jellyfin owns media-library, nzbget owns media-downloads,
        // sonarr references both. jellyfin and nzbget should get cross-affinity.

        let graph = ServiceGraph::new();

        // 1. Register jellyfin (owns media-library RWO)
        let jellyfin_spec = make_spec_with_volumes(
            vec![(
                "media",
                Some("media-library"),
                "1Ti",
                Some(VolumeAccessMode::ReadWriteOnce),
            )],
            vec![],
            vec![("/media", "media")],
        );
        graph.put_service("media-test", "jellyfin", &jellyfin_spec);

        // 2. Register nzbget (owns media-downloads RWO)
        let nzbget_spec = make_spec_with_volumes(
            vec![(
                "downloads",
                Some("media-downloads"),
                "500Gi",
                Some(VolumeAccessMode::ReadWriteOnce),
            )],
            vec![],
            vec![("/downloads", "downloads")],
        );
        graph.put_service("media-test", "nzbget", &nzbget_spec);

        // 3. Register sonarr (references both volumes)
        let sonarr_spec = make_spec_with_volumes(
            vec![],
            vec![("media", "media-library"), ("downloads", "media-downloads")],
            vec![("/media", "media"), ("/downloads", "downloads")],
        );
        graph.put_service("media-test", "sonarr", &sonarr_spec);

        // 4. Compile jellyfin with graph - should get cross-affinity to nzbget
        let jellyfin_output =
            VolumeCompiler::compile("jellyfin", "media-test", &jellyfin_spec, Some(&graph));

        // jellyfin should have preferred affinity to nzbget's volume label
        let affinity = jellyfin_output
            .affinity
            .expect("jellyfin should have affinity");
        let pod_affinity = affinity.pod_affinity.expect("should have pod affinity");
        let preferred = &pod_affinity.preferred_during_scheduling_ignored_during_execution;

        assert!(!preferred.is_empty(), "jellyfin should have preferred affinity to nzbget");

        // Check that the preferred affinity is to nzbget's volume owner label
        let has_nzbget_affinity = preferred.iter().any(|term| {
            term.pod_affinity_term
                .label_selector
                .match_labels
                .contains_key("lattice.dev/volume-owner-media-downloads")
        });
        assert!(
            has_nzbget_affinity,
            "jellyfin should have affinity to media-downloads owner"
        );

        // 5. Compile nzbget with graph - should get cross-affinity to jellyfin
        let nzbget_output =
            VolumeCompiler::compile("nzbget", "media-test", &nzbget_spec, Some(&graph));

        let affinity = nzbget_output
            .affinity
            .expect("nzbget should have affinity");
        let pod_affinity = affinity.pod_affinity.expect("should have pod affinity");
        let preferred = &pod_affinity.preferred_during_scheduling_ignored_during_execution;

        let has_jellyfin_affinity = preferred.iter().any(|term| {
            term.pod_affinity_term
                .label_selector
                .match_labels
                .contains_key("lattice.dev/volume-owner-media-library")
        });
        assert!(
            has_jellyfin_affinity,
            "nzbget should have affinity to media-library owner"
        );
    }

    #[test]
    fn story_no_cross_affinity_for_unrelated_owners() {
        use crate::graph::ServiceGraph;

        // Scenario: Two unrelated volume owners (no common referencer)
        // should NOT get cross-affinity

        let graph = ServiceGraph::new();

        // serviceA owns volume-a
        let service_a_spec = make_spec_with_volumes(
            vec![(
                "data",
                Some("volume-a"),
                "10Gi",
                Some(VolumeAccessMode::ReadWriteOnce),
            )],
            vec![],
            vec![("/data", "data")],
        );
        graph.put_service("test", "service-a", &service_a_spec);

        // serviceB owns volume-b (no common referencer with volume-a)
        let service_b_spec = make_spec_with_volumes(
            vec![(
                "data",
                Some("volume-b"),
                "10Gi",
                Some(VolumeAccessMode::ReadWriteOnce),
            )],
            vec![],
            vec![("/data", "data")],
        );
        graph.put_service("test", "service-b", &service_b_spec);

        // Compile service-a - should NOT have cross-affinity since no shared referencer
        let output = VolumeCompiler::compile("service-a", "test", &service_a_spec, Some(&graph));

        // Should have owner label but no preferred affinity
        assert!(output
            .pod_labels
            .contains_key("lattice.dev/volume-owner-volume-a"));

        if let Some(affinity) = &output.affinity {
            if let Some(pod_affinity) = &affinity.pod_affinity {
                assert!(
                    pod_affinity
                        .preferred_during_scheduling_ignored_during_execution
                        .is_empty(),
                    "unrelated owners should not have cross-affinity"
                );
            }
        }
    }
}
