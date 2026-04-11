//! Shared helper functions for workload compilation

use std::collections::BTreeMap;

use aws_lc_rs::digest::{digest, SHA256};
use lattice_common::crd::GpuParams;
use lattice_common::template::RenderedContainer;

use crate::k8s::{
    ConfigMap, EnvFromSource, ResourceQuantity, ResourceRequirements, Secret, Toleration, Volume,
    VolumeMount,
};
use crate::pipeline::secrets::SecretRef;

// =============================================================================
// Config Hash
// =============================================================================

/// Compute a config hash from ConfigMap and Secret data.
///
/// This hash is added as a pod annotation to trigger rollouts when config changes.
/// Uses SHA-256 for FIPS compliance. The `eso_content_hash` captures the current
/// content of ESO-managed K8s Secrets so that rotated secrets trigger rollouts.
pub(crate) fn compute_config_hash(
    env_config_maps: &[ConfigMap],
    env_secrets: &[Secret],
    files_config_maps: &[ConfigMap],
    files_secrets: &[Secret],
    eso_content_hash: &str,
) -> String {
    let mut data = String::new();

    for cm in env_config_maps {
        for (k, v) in &cm.data {
            data.push_str(k);
            data.push('=');
            data.push_str(v);
            data.push('\n');
        }
    }

    for s in env_secrets {
        for (k, v) in &s.string_data {
            data.push_str(k);
            data.push('=');
            data.push_str(v);
            data.push('\n');
        }
    }

    for cm in files_config_maps {
        for (k, v) in &cm.data {
            data.push_str("file:");
            data.push_str(k);
            data.push('=');
            data.push_str(v);
            data.push('\n');
        }
    }

    for s in files_secrets {
        for (k, v) in &s.string_data {
            data.push_str("file:");
            data.push_str(k);
            data.push('=');
            data.push_str(v);
            data.push('\n');
        }
    }

    if !eso_content_hash.is_empty() {
        data.push_str("eso:");
        data.push_str(eso_content_hash);
        data.push('\n');
    }

    let hash = digest(&SHA256, data.as_bytes());
    hash.as_ref()
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect()
}

// =============================================================================
// ContainerCompilationData
// =============================================================================

/// Groups the five per-container maps that flow from `SecretsCompiler`,
/// `TemplateRenderer`, `env::compile`, and `files::compile` into a single
/// parameter object.
pub struct ContainerCompilationData<'a> {
    /// Secret references from ESO for `${secret.*}` resolution
    pub secret_refs: &'a BTreeMap<String, SecretRef>,
    /// Rendered container data from TemplateRenderer
    pub rendered_containers: &'a BTreeMap<String, RenderedContainer>,
    /// EnvFrom refs from env::compile per container
    pub per_container_env_from: &'a BTreeMap<String, Vec<EnvFromSource>>,
    /// File volumes from files::compile per container
    pub per_container_file_volumes: &'a BTreeMap<String, Vec<Volume>>,
    /// File volume mounts from files::compile per container
    pub per_container_file_mounts: &'a BTreeMap<String, Vec<VolumeMount>>,
}

// =============================================================================
// GPU helpers
// =============================================================================

/// Merge GPU resource requirements into existing resource requirements
pub(crate) fn merge_gpu_resources(
    resources: Option<ResourceRequirements>,
    gpu: Option<&GpuParams>,
) -> Option<ResourceRequirements> {
    let gpu = match gpu {
        Some(g) => g,
        None => return resources,
    };

    let mut reqs = resources.unwrap_or_default();
    let limits = reqs.limits.get_or_insert_with(ResourceQuantity::default);

    limits.gpu = Some(gpu.count.to_string());

    if let Some(Ok(mib)) = gpu.memory_mib() {
        limits.gpu_memory = Some(mib.to_string());
    }

    if let Some(compute) = gpu.compute {
        limits.gpu_cores = Some(compute.to_string());
    }

    Some(reqs)
}

/// Build GPU tolerations for a pod spec.
pub(crate) fn gpu_tolerations(gpu: Option<&GpuParams>) -> Vec<Toleration> {
    match gpu {
        Some(g) if g.tolerations.unwrap_or(true) => vec![Toleration {
            key: Some("nvidia.com/gpu".to_string()),
            operator: Some("Exists".to_string()),
            effect: Some("NoSchedule".to_string()),
            ..Default::default()
        }],
        _ => vec![],
    }
}

/// Build SHM volume and mount for GPU pods.
///
/// GPU workloads (NCCL, PyTorch DataLoader) require a large `/dev/shm` for
/// shared-memory IPC. The default 64MB is insufficient.
pub(crate) fn gpu_shm_volume(gpu: Option<&GpuParams>) -> Option<(Volume, VolumeMount)> {
    gpu.map(|_| {
        (
            Volume::from_empty_dir("dshm", Some("Memory".to_string()), None),
            VolumeMount {
                name: "dshm".to_string(),
                mount_path: "/dev/shm".to_string(),
                sub_path: None,
                read_only: None,
            },
        )
    })
}

/// Determine image pull policy based on image tag
pub(crate) fn image_pull_policy(image: &str) -> String {
    if image.ends_with(":latest") || !image.contains(':') {
        "Always".to_string()
    } else {
        "IfNotPresent".to_string()
    }
}

/// Sanitize a string into a valid K8s DNS label.
///
/// Delegates to `lattice_core::sanitize_dns_label` and converts `None` to
/// a compilation error.
pub(crate) fn sanitize_dns_label(s: &str) -> Result<String, crate::error::CompilationError> {
    lattice_core::sanitize_dns_label(s).ok_or_else(|| {
        crate::error::CompilationError::file_compilation(format!(
            "input '{}' produces empty DNS label after sanitization",
            s
        ))
    })
}
