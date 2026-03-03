//! Volume compiler for LatticeService
//!
//! This module handles:
//! - PVC generation for owned volumes (volumes with size)
//! - Volume mounts in container specs (PVC-backed and emptyDir)

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::CompilationError;
use lattice_common::crd::{VolumeAccessMode, WorkloadSpec};
use lattice_common::kube_utils::{ObjectMeta, OwnerReference};

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
// Generated Volumes Container
// =============================================================================

/// Collection of volume-related resources generated for a service
#[derive(Clone, Debug, Default)]
pub struct GeneratedVolumes {
    /// PVCs to create (for owned volumes only)
    pub pvcs: Vec<PersistentVolumeClaim>,
    /// Volumes to add to pod spec
    pub volumes: Vec<crate::k8s::Volume>,
    /// Volume mounts per container (container_name -> mounts)
    pub volume_mounts: BTreeMap<String, Vec<crate::k8s::VolumeMount>>,
    /// Scheduling gates to add to pod spec
    pub scheduling_gates: Vec<crate::k8s::SchedulingGate>,
}

#[cfg(test)]
impl GeneratedVolumes {
    pub fn is_empty(&self) -> bool {
        self.pvcs.is_empty()
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
fn sanitize_volume_name(mount_path: &str) -> String {
    let label = crate::helpers::sanitize_dns_label(mount_path);
    let name = format!("emptydir-{}", label);
    if name.len() > 63 {
        name[..63].trim_end_matches('-').to_string()
    } else {
        name
    }
}

// =============================================================================
// Volume Compiler
// =============================================================================

/// Compiler for generating volume-related Kubernetes resources
pub struct VolumeCompiler;

impl VolumeCompiler {
    /// Compile volume resources for a workload.
    ///
    /// Generates PVCs for owned volumes and volume mounts for containers
    /// and sidecars.
    ///
    /// # Arguments
    /// * `service_name` - Name of the service
    /// * `namespace` - Target namespace
    /// * `workload` - WorkloadSpec (containers + resources)
    /// * `sidecars` - Sidecar specs from RuntimeSpec (for sidecar volume mounts)
    /// * `owner_references` - Owner references to set on generated PVCs for GC cascading
    pub fn compile(
        service_name: &str,
        namespace: &str,
        workload: &WorkloadSpec,
        sidecars: &BTreeMap<String, lattice_common::crd::SidecarSpec>,
        owner_references: &[OwnerReference],
    ) -> Result<GeneratedVolumes, CompilationError> {
        let mut output = GeneratedVolumes::default();

        // -----------------------------------------------------------------
        // Process volume resources
        // -----------------------------------------------------------------
        let volume_resources: Vec<_> = workload
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
                    .params
                    .as_volume()
                    .cloned()
                    .unwrap_or_default();
                let pvc = Self::compile_pvc(&pvc_name, namespace, &params, owner_references);
                output.pvcs.push(pvc);
            }

            // Generate pod volume
            output.volumes.push(crate::k8s::Volume::from_pvc(
                resource_name.as_str(),
                pvc_name,
            ));
        }

        // -----------------------------------------------------------------
        // Generate volume mounts (for volume resources and emptyDir)
        // -----------------------------------------------------------------

        // Container volume mounts
        for (container_name, container_spec) in &workload.containers {
            let (mounts, extra_vols) =
                Self::resolve_mounts(&container_spec.volumes, &volume_resources);
            if !mounts.is_empty() {
                output.volume_mounts.insert(container_name.clone(), mounts);
            }
            Self::extend_volumes_dedup(&mut output.volumes, extra_vols);
        }

        // Sidecar volume mounts
        for (sidecar_name, sidecar_spec) in sidecars {
            let (mounts, extra_vols) =
                Self::resolve_mounts(&sidecar_spec.volumes, &volume_resources);
            if !mounts.is_empty() {
                output.volume_mounts.insert(sidecar_name.clone(), mounts);
            }
            Self::extend_volumes_dedup(&mut output.volumes, extra_vols);
        }

        Ok(output)
    }

    /// Compile a PVC from volume params
    fn compile_pvc(
        name: &str,
        namespace: &str,
        params: &lattice_common::crd::VolumeParams,
        owner_references: &[OwnerReference],
    ) -> PersistentVolumeClaim {
        let access_mode = match params.access_mode {
            Some(VolumeAccessMode::ReadWriteMany) => "ReadWriteMany",
            Some(VolumeAccessMode::ReadOnlyMany) => "ReadOnlyMany",
            Some(VolumeAccessMode::ReadWriteOnce) | None => "ReadWriteOnce",
        };

        let metadata =
            ObjectMeta::new(name, namespace).with_owner_references(owner_references.to_vec());

        PersistentVolumeClaim {
            api_version: "v1".to_string(),
            kind: "PersistentVolumeClaim".to_string(),
            metadata,
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
        volumes: &BTreeMap<String, lattice_common::crd::VolumeMount>,
        mountable_resources: &[(&String, &lattice_common::crd::ResourceSpec)],
    ) -> (Vec<crate::k8s::VolumeMount>, Vec<crate::k8s::Volume>) {
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
                            mounts.push(crate::k8s::VolumeMount {
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
                    extra_volumes.push(crate::k8s::Volume::from_empty_dir(
                        &vol_name,
                        volume_mount.medium.clone(),
                        volume_mount.size_limit.clone(),
                    ));
                    mounts.push(crate::k8s::VolumeMount {
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

    /// Extend volumes, skipping entries whose name already exists.
    ///
    /// When multiple containers (main + sidecars) declare the same emptyDir
    /// mount (e.g., `/tmp: {}`), they produce identically-named volumes.
    /// K8s rejects duplicate volume names, so we deduplicate here.
    pub(crate) fn extend_volumes_dedup(
        existing: &mut Vec<crate::k8s::Volume>,
        new: Vec<crate::k8s::Volume>,
    ) {
        for vol in new {
            if !existing.iter().any(|v| v.name == vol.name) {
                existing.push(vol);
            }
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
    use lattice_common::crd::{
        ContainerSpec, ResourceParams, ResourceSpec, ResourceType, VolumeParams, WorkloadSpec,
    };
    use lattice_common::template::TemplateString;

    fn make_spec_with_volumes(
        owned: Vec<(&str, Option<&str>, &str, Option<VolumeAccessMode>)>, // (name, id, size, access_mode)
        refs: Vec<(&str, &str)>,                                          // (name, id)
        container_mounts: Vec<(&str, &str)>, // (mount_path, resource_name)
    ) -> WorkloadSpec {
        let mut resources = BTreeMap::new();

        // Add owned volumes
        for (name, id, size, access_mode) in owned {
            resources.insert(
                name.to_string(),
                ResourceSpec {
                    type_: ResourceType::Volume,
                    id: id.map(|s: &str| s.to_string()),
                    params: ResourceParams::Volume(VolumeParams {
                        size: Some(size.to_string()),
                        access_mode,
                        ..Default::default()
                    }),
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
                    params: ResourceParams::Volume(VolumeParams::default()),
                    ..Default::default()
                },
            );
        }

        // Build container with volume mounts
        let mut volumes = BTreeMap::new();
        for (mount_path, resource_name) in container_mounts {
            volumes.insert(
                mount_path.to_string(),
                lattice_common::crd::VolumeMount {
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

        WorkloadSpec {
            containers,
            resources,
            ..Default::default()
        }
    }

    // =========================================================================
    // Story: Generate PVC for Owned Volumes
    // =========================================================================

    #[test]
    fn generates_pvc_for_owned_volume() {
        let spec = make_spec_with_volumes(
            vec![("config", None, "5Gi", None)],
            vec![],
            vec![("/config", "config")],
        );

        let output =
            VolumeCompiler::compile("myapp", "prod", &spec, &BTreeMap::new(), &[]).unwrap();

        assert_eq!(output.pvcs.len(), 1);
        let pvc = &output.pvcs[0];
        assert_eq!(pvc.metadata.name, "myapp-config"); // No id, so service-resource name
        assert_eq!(pvc.metadata.namespace, "prod");
        assert_eq!(pvc.spec.resources.requests.storage, "5Gi");
        assert_eq!(pvc.spec.access_modes, vec!["ReadWriteOnce"]);
    }

    #[test]
    fn pvc_uses_volume_id_for_name() {
        let spec = make_spec_with_volumes(
            vec![("downloads", Some("media-downloads"), "500Gi", None)],
            vec![],
            vec![("/downloads", "downloads")],
        );

        let output =
            VolumeCompiler::compile("nzbget", "media", &spec, &BTreeMap::new(), &[]).unwrap();

        assert_eq!(output.pvcs.len(), 1);
        let pvc = &output.pvcs[0];
        assert_eq!(pvc.metadata.name, "vol-media-downloads"); // Uses id
    }

    #[test]
    fn pvc_respects_storage_class() {
        let mut spec = make_spec_with_volumes(
            vec![("config", None, "5Gi", None)],
            vec![],
            vec![("/config", "config")],
        );

        // Add storage class to volume config via params
        if let Some(resource) = spec.resources.get_mut("config") {
            if let ResourceParams::Volume(ref mut vp) = resource.params {
                vp.storage_class = Some("local-path".to_string());
            }
        }

        let output =
            VolumeCompiler::compile("myapp", "prod", &spec, &BTreeMap::new(), &[]).unwrap();

        let pvc = &output.pvcs[0];
        assert_eq!(pvc.spec.storage_class_name, Some("local-path".to_string()));
    }

    #[test]
    fn pvc_respects_access_mode() {
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

        let output =
            VolumeCompiler::compile("jellyfin", "media", &spec, &BTreeMap::new(), &[]).unwrap();

        let pvc = &output.pvcs[0];
        assert_eq!(pvc.spec.access_modes, vec!["ReadWriteMany"]);
    }

    // =========================================================================
    // Story: PVC Owner References
    // =========================================================================

    #[test]
    fn pvc_gets_owner_references() {
        let spec = make_spec_with_volumes(
            vec![("data", None, "10Gi", None)],
            vec![],
            vec![("/data", "data")],
        );

        let owner_refs = vec![OwnerReference {
            api_version: "lattice.dev/v1alpha1".to_string(),
            kind: "LatticeService".to_string(),
            name: "my-service".to_string(),
            uid: "abc-123".to_string(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        }];

        let output =
            VolumeCompiler::compile("my-service", "prod", &spec, &BTreeMap::new(), &owner_refs)
                .unwrap();

        let pvc = &output.pvcs[0];
        assert_eq!(pvc.metadata.owner_references.len(), 1);
        let oref = &pvc.metadata.owner_references[0];
        assert_eq!(oref.kind, "LatticeService");
        assert_eq!(oref.name, "my-service");
        assert_eq!(oref.uid, "abc-123");
        assert_eq!(oref.controller, Some(true));
    }

    #[test]
    fn pvc_no_owner_references_when_empty() {
        let spec = make_spec_with_volumes(
            vec![("data", None, "10Gi", None)],
            vec![],
            vec![("/data", "data")],
        );

        let output =
            VolumeCompiler::compile("myapp", "prod", &spec, &BTreeMap::new(), &[]).unwrap();

        let pvc = &output.pvcs[0];
        assert!(pvc.metadata.owner_references.is_empty());
    }

    // =========================================================================
    // Story: No PVC for Volume References
    // =========================================================================

    #[test]
    fn no_pvc_for_volume_reference() {
        let spec = make_spec_with_volumes(
            vec![],
            vec![("downloads", "media-downloads")],
            vec![("/downloads", "downloads")],
        );

        let output =
            VolumeCompiler::compile("sonarr", "media", &spec, &BTreeMap::new(), &[]).unwrap();

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
    fn rwo_owner_has_no_extra_resources() {
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

        let output =
            VolumeCompiler::compile("nzbget", "media", &spec, &BTreeMap::new(), &[]).unwrap();

        // Just PVC + volume + mount — no extra scheduling resources
        assert_eq!(output.pvcs.len(), 1);
        assert_eq!(output.volumes.len(), 1);
    }

    #[test]
    fn volume_reference_has_pod_volume() {
        let spec = make_spec_with_volumes(
            vec![],
            vec![("downloads", "media-downloads")],
            vec![("/downloads", "downloads")],
        );

        let output =
            VolumeCompiler::compile("sonarr", "media", &spec, &BTreeMap::new(), &[]).unwrap();

        // Should have the PVC-backed pod volume
        assert_eq!(output.volumes.len(), 1);
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
    // Story: Volume Mounts
    // =========================================================================

    #[test]
    fn generates_volume_mounts() {
        let spec = make_spec_with_volumes(
            vec![("config", None, "5Gi", None)],
            vec![],
            vec![("/config", "config")],
        );

        let output =
            VolumeCompiler::compile("myapp", "prod", &spec, &BTreeMap::new(), &[]).unwrap();

        let mounts = output
            .volume_mounts
            .get("main")
            .expect("should have mounts for main");
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].name, "config");
        assert_eq!(mounts[0].mount_path, "/config");
    }

    #[test]
    fn generates_pod_volumes() {
        let spec = make_spec_with_volumes(
            vec![("config", None, "5Gi", None)],
            vec![],
            vec![("/config", "config")],
        );

        let output =
            VolumeCompiler::compile("myapp", "prod", &spec, &BTreeMap::new(), &[]).unwrap();

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
    fn parse_volume_source() {
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
    fn no_volumes_returns_empty() {
        let spec = WorkloadSpec::default();

        let output =
            VolumeCompiler::compile("myapp", "prod", &spec, &BTreeMap::new(), &[]).unwrap();

        assert!(output.is_empty());
    }

    #[test]
    fn no_scheduling_gate_without_model() {
        let spec = make_spec_with_volumes(
            vec![("config", None, "5Gi", None)],
            vec![],
            vec![("/config", "config")],
        );

        let output =
            VolumeCompiler::compile("myapp", "prod", &spec, &BTreeMap::new(), &[]).unwrap();
        assert!(output.scheduling_gates.is_empty());
    }

    // =========================================================================
    // Story: EmptyDir Volumes (sourceless mounts)
    // =========================================================================

    fn make_emptydir_spec(
        mounts: Vec<(&str, Option<&str>, Option<&str>)>, // (path, medium, size_limit)
    ) -> WorkloadSpec {
        let mut volumes = BTreeMap::new();
        for (path, medium, size_limit) in mounts {
            volumes.insert(
                path.to_string(),
                lattice_common::crd::VolumeMount {
                    source: None,
                    path: None,
                    read_only: None,
                    medium: medium.map(String::from),
                    size_limit: size_limit.map(String::from),
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

        WorkloadSpec {
            containers,
            ..Default::default()
        }
    }

    #[test]
    fn emptydir_volume_from_sourceless_mount() {
        let spec = make_emptydir_spec(vec![("/tmp", None, None)]);
        let output =
            VolumeCompiler::compile("myapp", "prod", &spec, &BTreeMap::new(), &[]).unwrap();

        // Should generate an emptyDir pod volume
        assert_eq!(output.volumes.len(), 1);
        let vol = &output.volumes[0];
        assert_eq!(vol.name, "emptydir-tmp");
        assert!(vol.persistent_volume_claim.is_none());
        let ed = vol.empty_dir.as_ref().expect("should be emptyDir");
        assert!(ed.medium.is_none());
        assert!(ed.size_limit.is_none());

        // Should generate a volume mount
        let mounts = output.volume_mounts.get("main").unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].name, "emptydir-tmp");
        assert_eq!(mounts[0].mount_path, "/tmp");
    }

    #[test]
    fn emptydir_tmpfs_medium() {
        let spec = make_emptydir_spec(vec![("/dev/shm", Some("Memory"), None)]);
        let output =
            VolumeCompiler::compile("myapp", "prod", &spec, &BTreeMap::new(), &[]).unwrap();

        let vol = &output.volumes[0];
        let ed = vol.empty_dir.as_ref().unwrap();
        assert_eq!(ed.medium, Some("Memory".to_string()));
        assert!(ed.size_limit.is_none());
    }

    #[test]
    fn emptydir_size_limit() {
        let spec = make_emptydir_spec(vec![("/scratch", None, Some("5Gi"))]);
        let output =
            VolumeCompiler::compile("myapp", "prod", &spec, &BTreeMap::new(), &[]).unwrap();

        let vol = &output.volumes[0];
        let ed = vol.empty_dir.as_ref().unwrap();
        assert!(ed.medium.is_none());
        assert_eq!(ed.size_limit, Some("5Gi".to_string()));
    }

    #[test]
    fn mixed_resource_and_emptydir_volumes() {
        let mut spec = make_spec_with_volumes(
            vec![("data", None, "10Gi", None)],
            vec![],
            vec![("/data", "data")],
        );

        // Add emptyDir volumes to the same container
        let container = spec.containers.get_mut("main").unwrap();
        container.volumes.insert(
            "/tmp".to_string(),
            lattice_common::crd::VolumeMount {
                source: None,
                path: None,
                read_only: None,
                medium: None,
                size_limit: None,
            },
        );
        container.volumes.insert(
            "/var/cache/nginx".to_string(),
            lattice_common::crd::VolumeMount {
                source: None,
                path: None,
                read_only: None,
                medium: None,
                size_limit: None,
            },
        );

        let output =
            VolumeCompiler::compile("myapp", "prod", &spec, &BTreeMap::new(), &[]).unwrap();

        // 1 PVC volume + 2 emptyDir volumes = 3 total
        assert_eq!(output.volumes.len(), 3);

        let pvc_vols: Vec<_> = output
            .volumes
            .iter()
            .filter(|v| v.persistent_volume_claim.is_some())
            .collect();
        let empty_vols: Vec<_> = output
            .volumes
            .iter()
            .filter(|v| v.empty_dir.is_some())
            .collect();
        assert_eq!(pvc_vols.len(), 1);
        assert_eq!(empty_vols.len(), 2);

        // All 3 mounts present
        let mounts = output.volume_mounts.get("main").unwrap();
        assert_eq!(mounts.len(), 3);
    }

    #[test]
    fn emptydir_volume_name_sanitization() {
        let spec = make_emptydir_spec(vec![
            ("/var/cache/nginx", None, None),
            ("/tmp", None, None),
            ("/dev/shm", Some("Memory"), None),
        ]);
        let output =
            VolumeCompiler::compile("myapp", "prod", &spec, &BTreeMap::new(), &[]).unwrap();

        let names: Vec<_> = output.volumes.iter().map(|v| v.name.as_str()).collect();
        assert!(names.contains(&"emptydir-dev-shm"));
        assert!(names.contains(&"emptydir-tmp"));
        assert!(names.contains(&"emptydir-var-cache-nginx"));
    }

    #[test]
    fn sidecar_emptydir_volumes() {
        use lattice_common::crd::SidecarSpec;

        let spec = WorkloadSpec {
            containers: {
                let mut c = BTreeMap::new();
                c.insert(
                    "main".to_string(),
                    ContainerSpec {
                        image: "app:latest".to_string(),
                        ..Default::default()
                    },
                );
                c
            },
            ..Default::default()
        };

        let mut sidecar_volumes = BTreeMap::new();
        sidecar_volumes.insert(
            "/tmp".to_string(),
            lattice_common::crd::VolumeMount {
                source: None,
                path: None,
                read_only: None,
                medium: None,
                size_limit: None,
            },
        );

        let mut sidecars = BTreeMap::new();
        sidecars.insert(
            "logger".to_string(),
            SidecarSpec {
                image: "fluentbit:latest".to_string(),
                volumes: sidecar_volumes,
                ..Default::default()
            },
        );

        let output = VolumeCompiler::compile("myapp", "prod", &spec, &sidecars, &[]).unwrap();

        // Sidecar should get emptyDir volume
        assert_eq!(output.volumes.len(), 1);
        assert!(output.volumes[0].empty_dir.is_some());
        assert_eq!(output.volumes[0].name, "emptydir-tmp");

        // Sidecar should get volume mount
        let mounts = output.volume_mounts.get("logger").unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].mount_path, "/tmp");
    }

    #[test]
    fn shared_emptydir_between_main_and_sidecar_deduplicates() {
        use lattice_common::crd::SidecarSpec;

        // Main container declares /tmp and /run
        let mut main_volumes = BTreeMap::new();
        for path in ["/tmp", "/run"] {
            main_volumes.insert(
                path.to_string(),
                lattice_common::crd::VolumeMount {
                    source: None,
                    path: None,
                    read_only: None,
                    medium: None,
                    size_limit: None,
                },
            );
        }

        let spec = WorkloadSpec {
            containers: {
                let mut c = BTreeMap::new();
                c.insert(
                    "main".to_string(),
                    ContainerSpec {
                        image: "app:latest".to_string(),
                        volumes: main_volumes,
                        ..Default::default()
                    },
                );
                c
            },
            ..Default::default()
        };

        // Sidecar also declares /tmp and /run
        let mut sidecar_volumes = BTreeMap::new();
        for path in ["/tmp", "/run"] {
            sidecar_volumes.insert(
                path.to_string(),
                lattice_common::crd::VolumeMount {
                    source: None,
                    path: None,
                    read_only: None,
                    medium: None,
                    size_limit: None,
                },
            );
        }

        let mut sidecars = BTreeMap::new();
        sidecars.insert(
            "vpn".to_string(),
            SidecarSpec {
                image: "wireguard:latest".to_string(),
                volumes: sidecar_volumes,
                ..Default::default()
            },
        );

        let output = VolumeCompiler::compile("nzbget", "media", &spec, &sidecars, &[]).unwrap();

        // Should have exactly 2 volumes (deduplicated), not 4
        let emptydir_volumes: Vec<_> = output
            .volumes
            .iter()
            .filter(|v| v.empty_dir.is_some())
            .collect();
        assert_eq!(emptydir_volumes.len(), 2);

        let names: Vec<_> = emptydir_volumes.iter().map(|v| v.name.as_str()).collect();
        assert!(names.contains(&"emptydir-tmp"));
        assert!(names.contains(&"emptydir-run"));

        // Both containers should have mounts pointing to the shared volumes
        let main_mounts = output.volume_mounts.get("main").unwrap();
        assert_eq!(main_mounts.len(), 2);
        let vpn_mounts = output.volume_mounts.get("vpn").unwrap();
        assert_eq!(vpn_mounts.len(), 2);
    }

    #[test]
    fn emptydir_only_no_resources_needed() {
        // EmptyDir volumes should work even with zero resource declarations
        let spec = make_emptydir_spec(vec![("/tmp", None, None), ("/var/run", None, None)]);
        assert!(spec.resources.is_empty());

        let output =
            VolumeCompiler::compile("myapp", "prod", &spec, &BTreeMap::new(), &[]).unwrap();

        assert_eq!(output.volumes.len(), 2);
        assert_eq!(output.pvcs.len(), 0); // No PVCs needed
        let mounts = output.volume_mounts.get("main").unwrap();
        assert_eq!(mounts.len(), 2);
    }
}
