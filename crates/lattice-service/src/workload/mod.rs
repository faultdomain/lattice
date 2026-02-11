//! Workload types for Lattice services
//!
//! This module defines Kubernetes workload resource types used by the ServiceCompiler:
//! - Deployment: Container orchestration
//! - Service: Network exposure
//! - ServiceAccount: SPIFFE identity for mTLS
//! - ScaledObject: KEDA-based auto-scaling
//! - ConfigMap/Secret: Configuration and secrets
//!
//! For workload generation, use [`crate::compiler::ServiceCompiler`].

pub mod backup;
pub mod env;
pub mod error;
pub mod files;
pub mod pod_template;
pub mod secrets;
pub mod volume;

pub use error::CompilationError;
pub use pod_template::{CompiledPodTemplate, PodTemplateCompiler};
pub use secrets::{GeneratedSecrets, SecretRef, SecretsCompiler};
pub use volume::{
    Affinity, GeneratedVolumes, PersistentVolumeClaim, PodAffinity, PvcVolumeSource,
    VolumeCompiler, VOLUME_OWNER_LABEL_PREFIX,
};

use std::collections::BTreeMap;

use aws_lc_rs::digest::{digest, SHA256};
use lattice_common::kube_utils::HasApiResource;
use serde::{Deserialize, Serialize};

/// Compute a config hash from ConfigMap and Secret data
///
/// This hash is added as a pod annotation to trigger rollouts when config changes.
/// Uses SHA-256 for FIPS compliance.
pub fn compute_config_hash(
    env_config_maps: &[ConfigMap],
    env_secrets: &[Secret],
    files_config_maps: &[ConfigMap],
    files_secrets: &[Secret],
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

    // Compute SHA-256 hash
    let hash = digest(&SHA256, data.as_bytes());
    // Return first 16 hex chars (64 bits) for readability
    hash.as_ref()
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect()
}

// =============================================================================
// Kubernetes Resource Types
// =============================================================================

/// Standard Kubernetes ObjectMeta
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
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
}

impl ObjectMeta {
    /// Create new metadata with standard Lattice labels
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        let name = name.into();
        let mut labels = BTreeMap::new();
        labels.insert(lattice_common::LABEL_NAME.to_string(), name.clone());
        labels.insert(
            lattice_common::LABEL_MANAGED_BY.to_string(),
            lattice_common::LABEL_MANAGED_BY_LATTICE.to_string(),
        );
        Self {
            name,
            namespace: namespace.into(),
            labels,
            annotations: BTreeMap::new(),
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
}

// =============================================================================
// ConfigMap and Secret
// =============================================================================

/// Kubernetes ConfigMap for non-sensitive configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigMap {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// String data
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, String>,
}

impl ConfigMap {
    /// Create a new ConfigMap
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            api_version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            data: BTreeMap::new(),
        }
    }

    /// Add a data entry
    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), value.into());
        self
    }
}

/// Kubernetes Secret for sensitive configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Secret {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// String data (auto-encoded to base64 by K8s)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub string_data: BTreeMap<String, String>,
    /// Secret type
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

impl Secret {
    /// Create a new Secret
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            api_version: "v1".to_string(),
            kind: "Secret".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            string_data: BTreeMap::new(),
            type_: Some("Opaque".to_string()),
        }
    }

    /// Add a data entry
    pub fn with_data(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.string_data.insert(key.into(), value.into());
        self
    }
}

// =============================================================================
// EnvFrom sources for referencing ConfigMap/Secret in containers
// =============================================================================

/// Reference to a ConfigMap or Secret for loading env vars
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvFromSource {
    /// ConfigMap reference
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_map_ref: Option<ConfigMapEnvSource>,
    /// Secret reference
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<SecretEnvSource>,
}

/// Reference to a ConfigMap for env vars
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ConfigMapEnvSource {
    /// ConfigMap name
    pub name: String,
}

/// Reference to a Secret for env vars
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SecretEnvSource {
    /// Secret name
    pub name: String,
}

// =============================================================================
// Deployment
// =============================================================================

/// Kubernetes Deployment
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: DeploymentSpec,
}

/// Deployment spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentSpec {
    /// Number of replicas
    pub replicas: u32,
    /// Label selector
    pub selector: LabelSelector,
    /// Pod template
    pub template: PodTemplateSpec,
    /// Deployment strategy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DeploymentStrategy>,
}

/// Label selector
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    /// Match labels
    pub match_labels: BTreeMap<String, String>,
}

/// Deployment strategy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentStrategy {
    /// Strategy type: RollingUpdate or Recreate
    #[serde(rename = "type")]
    pub type_: String,
    /// Rolling update config
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling_update: Option<RollingUpdateConfig>,
}

/// Rolling update configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RollingUpdateConfig {
    /// Max unavailable pods
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_unavailable: Option<String>,
    /// Max surge pods
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_surge: Option<String>,
}

/// Pod template spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodTemplateSpec {
    /// Pod metadata
    pub metadata: PodMeta,
    /// Pod spec
    pub spec: PodSpec,
}

/// Pod metadata (subset of ObjectMeta)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodMeta {
    /// Labels
    pub labels: BTreeMap<String, String>,
    /// Annotations
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// Pod spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodSpec {
    /// Service account name
    pub service_account_name: String,
    /// Whether to automount the service account token into pods
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automount_service_account_token: Option<bool>,
    /// Containers
    pub containers: Vec<Container>,
    /// Init containers (run before main containers)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub init_containers: Vec<Container>,
    /// Volumes
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<Volume>,
    /// Pod affinity rules (for RWO volume co-location)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affinity: Option<volume::Affinity>,
    /// Pod-level security context
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_context: Option<PodSecurityContext>,
    /// Use host network namespace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_network: Option<bool>,
    /// Share PID namespace between containers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_process_namespace: Option<bool>,
    /// Topology spread constraints for HA
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub topology_spread_constraints: Vec<TopologySpreadConstraint>,
    /// Node selector for scheduling onto specific nodes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_selector: Option<BTreeMap<String, String>>,
    /// Tolerations for scheduling onto tainted nodes
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tolerations: Vec<Toleration>,
    /// Runtime class name (e.g., "nvidia" for GPU workloads)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_class_name: Option<String>,
    /// Scheduling gates — block pod scheduling until gates are removed
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scheduling_gates: Vec<SchedulingGate>,
    /// Image pull secrets for authenticating to private registries
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub image_pull_secrets: Vec<LocalObjectReference>,
}

/// Scheduling gate that blocks pod scheduling until removed
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SchedulingGate {
    /// Gate name
    pub name: String,
}

/// Topology spread constraint for distributing pods across failure domains
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TopologySpreadConstraint {
    /// Maximum difference in pod count between topology domains
    pub max_skew: i32,
    /// Topology key (e.g., topology.kubernetes.io/zone)
    pub topology_key: String,
    /// What to do when constraint can't be satisfied
    pub when_unsatisfiable: String,
    /// Label selector to find pods to spread
    pub label_selector: LabelSelector,
}

/// Kubernetes toleration
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Toleration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
}

/// Container spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Container {
    /// Container name
    pub name: String,
    /// Image
    pub image: String,
    /// Image pull policy (Always, IfNotPresent, Never)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_pull_policy: Option<String>,
    /// Command
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// Args
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    /// Environment variables
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvVar>,
    /// Environment from ConfigMap/Secret references
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_from: Vec<EnvFromSource>,
    /// Ports
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<ContainerPort>,
    /// Resource requirements
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,
    /// Liveness probe - restarts container when it fails
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness_probe: Option<ProbeSpec>,
    /// Readiness probe - removes from service endpoints when it fails
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_probe: Option<ProbeSpec>,
    /// Startup probe - delays liveness/readiness until container is ready
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_probe: Option<ProbeSpec>,
    /// Volume mounts
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volume_mounts: Vec<VolumeMount>,
    /// Security context
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_context: Option<K8sSecurityContext>,
}

/// Environment variable — either a literal value or a reference to a secret key
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvVar {
    /// Variable name
    pub name: String,
    /// Literal value (mutually exclusive with `value_from`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Reference to a secret key (mutually exclusive with `value`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_from: Option<EnvVarSource>,
}

impl EnvVar {
    /// Create an env var with a literal value
    pub fn literal(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: Some(value.into()),
            value_from: None,
        }
    }

    /// Create an env var that references a secret key
    pub fn from_secret(
        name: impl Into<String>,
        secret_name: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: None,
            value_from: Some(EnvVarSource {
                secret_key_ref: Some(SecretKeySelector {
                    name: secret_name.into(),
                    key: key.into(),
                }),
            }),
        }
    }
}

/// Source for an environment variable value
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvVarSource {
    /// Reference to a specific key in a K8s Secret
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_key_ref: Option<SecretKeySelector>,
}

/// Selector for a key within a K8s Secret
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretKeySelector {
    /// Name of the K8s Secret
    pub name: String,
    /// Key within the secret
    pub key: String,
}

/// Reference to a local object by name (e.g., for imagePullSecrets)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocalObjectReference {
    /// Object name
    pub name: String,
}

/// Container port
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ContainerPort {
    /// Port name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Port number
    pub container_port: u16,
    /// Protocol
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// Resource requirements
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceRequirements {
    /// Requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<ResourceQuantity>,
    /// Limits
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<ResourceQuantity>,
}

/// Resource quantity
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ResourceQuantity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    /// GPU count (serializes as `nvidia.com/gpu`)
    #[serde(
        default,
        rename = "nvidia.com/gpu",
        skip_serializing_if = "Option::is_none"
    )]
    pub gpu: Option<String>,
    /// GPU memory in MiB for HAMi (serializes as `nvidia.com/gpumem`)
    #[serde(
        default,
        rename = "nvidia.com/gpumem",
        skip_serializing_if = "Option::is_none"
    )]
    pub gpu_memory: Option<String>,
    /// GPU compute percentage for HAMi (serializes as `nvidia.com/gpucores`)
    #[serde(
        default,
        rename = "nvidia.com/gpucores",
        skip_serializing_if = "Option::is_none"
    )]
    pub gpu_cores: Option<String>,
}

/// Probe specification - maps 1:1 with Kubernetes probe spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProbeSpec {
    /// HTTP GET probe
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_get: Option<HttpGetAction>,
    /// Exec probe
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecAction>,
}

/// HTTP GET action for probe
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpGetAction {
    /// Path
    pub path: String,
    /// Port
    pub port: u16,
    /// Scheme (HTTP or HTTPS)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Host header
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// HTTP headers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_headers: Option<Vec<HttpHeader>>,
}

/// HTTP header for probes
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpHeader {
    /// Header name
    pub name: String,
    /// Header value
    pub value: String,
}

/// Exec action for probe
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExecAction {
    /// Command
    pub command: Vec<String>,
}

/// Kubernetes container security context
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct K8sSecurityContext {
    /// Capabilities to add/drop
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,
    /// Run container in privileged mode
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    /// Mount root filesystem as read-only
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_root_filesystem: Option<bool>,
    /// Require the container to run as a non-root user
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_non_root: Option<bool>,
    /// UID to run the container as
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_user: Option<i64>,
    /// GID to run the container as
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_group: Option<i64>,
    /// Allow privilege escalation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_privilege_escalation: Option<bool>,
    /// Seccomp profile
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seccomp_profile: Option<SeccompProfile>,
    /// AppArmor profile
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_armor_profile: Option<AppArmorProfile>,
}

/// Seccomp profile for container or pod security context
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SeccompProfile {
    /// Profile type: RuntimeDefault, Unconfined, or Localhost
    #[serde(rename = "type")]
    pub type_: String,
    /// Localhost profile path (only for Localhost type)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub localhost_profile: Option<String>,
}

/// AppArmor profile for container security context
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppArmorProfile {
    /// Profile type: RuntimeDefault, Unconfined, or Localhost
    #[serde(rename = "type")]
    pub type_: String,
    /// Localhost profile name (only for Localhost type)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub localhost_profile: Option<String>,
}

/// Linux capabilities for containers
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    /// Capabilities to add
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add: Option<Vec<String>>,
    /// Capabilities to drop
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drop: Option<Vec<String>>,
}

/// Pod-level security context
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodSecurityContext {
    /// Require all containers to run as non-root
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_non_root: Option<bool>,
    /// GID applied to all volumes so files are group-readable
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_group: Option<i64>,
    /// Policy for applying fsGroup to volumes (OnRootMismatch or Always)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_group_change_policy: Option<String>,
    /// Pod-level seccomp profile
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seccomp_profile: Option<SeccompProfile>,
    /// Sysctls for the pod
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sysctls: Option<Vec<Sysctl>>,
}

/// Sysctl setting for pod
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Sysctl {
    /// Sysctl name (e.g., net.ipv4.conf.all.src_valid_mark)
    pub name: String,
    /// Sysctl value
    pub value: String,
}

/// Volume
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Volume {
    /// Volume name
    pub name: String,
    /// ConfigMap source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_map: Option<ConfigMapVolumeSource>,
    /// Secret source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<SecretVolumeSource>,
    /// EmptyDir source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_dir: Option<EmptyDirVolumeSource>,
    /// PVC source
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_volume_claim: Option<volume::PvcVolumeSource>,
}

/// ConfigMap volume source
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigMapVolumeSource {
    /// ConfigMap name
    pub name: String,
}

/// Secret volume source
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretVolumeSource {
    /// Secret name
    pub secret_name: String,
}

/// EmptyDir volume source
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EmptyDirVolumeSource {
    /// Storage medium ("Memory" for tmpfs, empty for default)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub medium: Option<String>,
    /// Size limit for the emptyDir (e.g., "1Gi")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_limit: Option<String>,
}

/// Volume mount
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VolumeMount {
    /// Volume name
    pub name: String,
    /// Mount path
    pub mount_path: String,
    /// Sub path within the volume
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_path: Option<String>,
    /// Read only
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
}

// =============================================================================
// Service
// =============================================================================

/// Kubernetes Service
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: ServiceSpec,
}

/// Service spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSpec {
    /// Selector
    pub selector: BTreeMap<String, String>,
    /// Ports
    pub ports: Vec<ServicePort>,
    /// Service type
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
}

/// Service port
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServicePort {
    /// Port name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Port number
    pub port: u16,
    /// Target port
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,
    /// Protocol
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

// =============================================================================
// ServiceAccount
// =============================================================================

/// Kubernetes ServiceAccount
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccount {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Whether to automount the service account token into pods
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automount_service_account_token: Option<bool>,
}

// =============================================================================
// PodDisruptionBudget
// =============================================================================

/// Kubernetes PodDisruptionBudget for ensuring availability during node drains
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodDisruptionBudget {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: PdbSpec,
}

/// PDB spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PdbSpec {
    /// Minimum number of pods that must remain available
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_available: Option<u32>,
    /// Label selector to match pods
    pub selector: LabelSelector,
}

// =============================================================================
// KEDA ScaledObject
// =============================================================================

/// KEDA ScaledObject — manages pod autoscaling via triggers (cpu, memory, prometheus, etc.)
///
/// KEDA creates and manages an HPA under the hood. All autoscaling goes through
/// ScaledObject triggers, giving a single code path for both resource-based
/// (cpu/memory) and custom Prometheus metrics.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScaledObject {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: ScaledObjectSpec,
}

impl HasApiResource for ScaledObject {
    const API_VERSION: &'static str = "keda.sh/v1alpha1";
    const KIND: &'static str = "ScaledObject";
}

/// ScaledObject spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScaledObjectSpec {
    /// Reference to the target Deployment/StatefulSet to scale
    pub scale_target_ref: ScaleTargetRef,
    /// Minimum replica count
    pub min_replica_count: u32,
    /// Maximum replica count
    pub max_replica_count: u32,
    /// Autoscaling triggers (cpu, memory, prometheus, etc.)
    pub triggers: Vec<ScaledObjectTrigger>,
}

/// Scale target reference
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScaleTargetRef {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Name
    pub name: String,
}

/// A single KEDA trigger (one scaling signal)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScaledObjectTrigger {
    /// Trigger type: "cpu", "memory", or "prometheus"
    #[serde(rename = "type")]
    pub type_: String,
    /// Metric type for resource triggers (e.g. "Utilization")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric_type: Option<String>,
    /// Trigger-specific key-value metadata
    pub metadata: BTreeMap<String, String>,
}

// =============================================================================
// Generated Workloads Container
// =============================================================================

/// Collection of all workload resources generated for a service
#[derive(Clone, Debug, Default)]
pub struct GeneratedWorkloads {
    /// Kubernetes Deployment
    pub deployment: Option<Deployment>,
    /// Kubernetes Service
    pub service: Option<Service>,
    /// Kubernetes ServiceAccount
    pub service_account: Option<ServiceAccount>,
    /// PodDisruptionBudget for HA services
    pub pdb: Option<PodDisruptionBudget>,
    /// KEDA ScaledObject for autoscaling
    pub scaled_object: Option<ScaledObject>,
    /// ConfigMaps for non-sensitive env vars (one per container)
    pub env_config_maps: Vec<ConfigMap>,
    /// Secrets for sensitive env vars (one per container)
    pub env_secrets: Vec<Secret>,
    /// ConfigMaps for file mounts — text content (one per container)
    pub files_config_maps: Vec<ConfigMap>,
    /// Secrets for file mounts — binary content (one per container)
    pub files_secrets: Vec<Secret>,
    /// PersistentVolumeClaims for owned volumes
    pub pvcs: Vec<PersistentVolumeClaim>,
    /// ExternalSecrets for syncing secrets from SecretProvider (Vault)
    pub external_secrets: Vec<lattice_secret_provider::ExternalSecret>,
    /// Secret references for template resolution (resource_name -> SecretRef)
    pub secret_refs: BTreeMap<String, SecretRef>,
}

impl GeneratedWorkloads {
    /// Create empty workload collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any workloads were generated
    pub fn is_empty(&self) -> bool {
        self.deployment.is_none()
            && self.service.is_none()
            && self.service_account.is_none()
            && self.pdb.is_none()
            && self.scaled_object.is_none()
            && self.env_config_maps.is_empty()
            && self.env_secrets.is_empty()
            && self.files_config_maps.is_empty()
            && self.files_secrets.is_empty()
            && self.pvcs.is_empty()
            && self.external_secrets.is_empty()
    }
}

// =============================================================================
// Workload Compiler
// =============================================================================

use crate::crd::{
    AutoscalingMetric, DeployStrategy, GpuParams, LatticeService, LatticeServiceSpec, ProviderType,
    ReplicaSpec, WorkloadSpec,
};
use lattice_common::mesh;
use lattice_common::template::RenderedContainer;

/// Merge GPU resource requests into container limits.
///
/// For full GPU mode (count only), adds `nvidia.com/gpu` to limits.
/// For HAMi fractional mode (memory/compute set), also adds
/// `nvidia.com/gpumem` and/or `nvidia.com/gpucores`.
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
/// shared-memory IPC. The default 64MB is insufficient. This adds an emptyDir
/// volume with `medium: Memory` (tmpfs) mounted at `/dev/shm`.
pub(crate) fn gpu_shm_volume(gpu: Option<&GpuParams>) -> Option<(Volume, VolumeMount)> {
    gpu.map(|_| {
        (
            Volume {
                name: "dshm".to_string(),
                config_map: None,
                secret: None,
                empty_dir: Some(EmptyDirVolumeSource {
                    medium: Some("Memory".to_string()),
                    size_limit: None,
                }),
                persistent_volume_claim: None,
            },
            VolumeMount {
                name: "dshm".to_string(),
                mount_path: "/dev/shm".to_string(),
                sub_path: None,
                read_only: None,
            },
        )
    })
}

/// Compute image pull policy from the image reference.
///
/// Returns `Always` when the tag is `:latest` or absent (bare image name),
/// `IfNotPresent` for any other explicit tag or digest.
pub(crate) fn image_pull_policy(image: &str) -> String {
    if image.ends_with(":latest") || !image.contains(':') {
        "Always".to_string()
    } else {
        "IfNotPresent".to_string()
    }
}

/// Per-container compilation data bundled from earlier pipeline stages.
///
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

/// Compiler for generating LatticeService-specific Kubernetes workload resources.
///
/// Uses `PodTemplateCompiler` for the shared pod template, then wraps it in
/// service-specific resources: Deployment, Service, ServiceAccount, PDB, ScaledObject.
pub struct WorkloadCompiler;

impl WorkloadCompiler {
    /// Compile a LatticeService into workload resources.
    pub fn compile(
        name: &str,
        service: &LatticeService,
        namespace: &str,
        volumes: &GeneratedVolumes,
        provider_type: ProviderType,
        monitoring_enabled: bool,
        container_data: &ContainerCompilationData<'_>,
    ) -> Result<GeneratedWorkloads, CompilationError> {
        let spec = &service.spec;
        let workload = &spec.workload;
        let mut output = GeneratedWorkloads::new();

        // Always generate ServiceAccount for SPIFFE identity
        output.service_account = Some(Self::compile_service_account(name, namespace));

        // Compile shared pod template via PodTemplateCompiler
        let pod_template = PodTemplateCompiler::compile(
            name,
            workload,
            &spec.runtime,
            volumes,
            provider_type,
            container_data,
        )?;

        // Wrap pod template in a Deployment with service-specific fields
        output.deployment = Some(Self::build_deployment(name, namespace, spec, pod_template));

        // Generate Service if ports are defined
        if workload.service.is_some() {
            output.service = Some(Self::compile_service(name, namespace, workload));
        }

        // Generate PDB for HA services (min replicas >= 2)
        if spec.replicas.min >= 2 {
            output.pdb = Some(Self::compile_pdb(name, namespace, &spec.replicas));
        }

        // Generate KEDA ScaledObject if max replicas is set
        if spec.replicas.max.is_some() {
            output.scaled_object = Some(Self::compile_scaled_object(
                name,
                namespace,
                &spec.replicas,
                monitoring_enabled,
            )?);
        }

        Ok(output)
    }

    fn compile_service_account(name: &str, namespace: &str) -> ServiceAccount {
        ServiceAccount {
            api_version: "v1".to_string(),
            kind: "ServiceAccount".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            automount_service_account_token: Some(false),
        }
    }

    /// Build a Deployment from a compiled pod template and service-specific config.
    fn build_deployment(
        name: &str,
        namespace: &str,
        spec: &LatticeServiceSpec,
        pod_template: CompiledPodTemplate,
    ) -> Deployment {
        let strategy = Self::compile_strategy(spec);

        Deployment {
            api_version: "apps/v1".to_string(),
            kind: "Deployment".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            spec: DeploymentSpec {
                replicas: spec.replicas.min,
                selector: LabelSelector {
                    match_labels: {
                        let mut selector = BTreeMap::new();
                        selector.insert(lattice_common::LABEL_NAME.to_string(), name.to_string());
                        selector
                    },
                },
                template: PodTemplateSpec {
                    metadata: PodMeta {
                        labels: pod_template.labels,
                        annotations: BTreeMap::new(),
                    },
                    spec: PodSpec {
                        service_account_name: pod_template.service_account_name,
                        automount_service_account_token: Some(false),
                        containers: pod_template.containers,
                        init_containers: pod_template.init_containers,
                        volumes: pod_template.volumes,
                        affinity: pod_template.affinity,
                        security_context: pod_template.security_context,
                        host_network: pod_template.host_network,
                        share_process_namespace: pod_template.share_process_namespace,
                        topology_spread_constraints: pod_template.topology_spread_constraints,
                        node_selector: pod_template.node_selector,
                        tolerations: pod_template.tolerations,
                        runtime_class_name: pod_template.runtime_class_name,
                        scheduling_gates: pod_template.scheduling_gates,
                        image_pull_secrets: pod_template.image_pull_secrets,
                    },
                },
                strategy,
            },
        }
    }

    /// Compile deployment strategy from deploy config.
    fn compile_strategy(spec: &LatticeServiceSpec) -> Option<DeploymentStrategy> {
        match spec.deploy.strategy {
            DeployStrategy::Rolling => Some(DeploymentStrategy {
                type_: "RollingUpdate".to_string(),
                rolling_update: Some(RollingUpdateConfig {
                    max_unavailable: Some("25%".to_string()),
                    max_surge: Some("25%".to_string()),
                }),
            }),
            DeployStrategy::Canary => Some(DeploymentStrategy {
                type_: "RollingUpdate".to_string(),
                rolling_update: Some(RollingUpdateConfig {
                    max_unavailable: Some("0".to_string()),
                    max_surge: Some("100%".to_string()),
                }),
            }),
        }
    }

    /// Compile a PodDisruptionBudget for HA services.
    fn compile_pdb(name: &str, namespace: &str, replicas: &ReplicaSpec) -> PodDisruptionBudget {
        PodDisruptionBudget {
            api_version: "policy/v1".to_string(),
            kind: "PodDisruptionBudget".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            spec: PdbSpec {
                min_available: Some(replicas.min.saturating_sub(1).max(1)),
                selector: LabelSelector {
                    match_labels: {
                        let mut labels = BTreeMap::new();
                        labels.insert(lattice_common::LABEL_NAME.to_string(), name.to_string());
                        labels
                    },
                },
            },
        }
    }

    fn compile_service(name: &str, namespace: &str, workload: &WorkloadSpec) -> Service {
        let mut selector = BTreeMap::new();
        selector.insert(lattice_common::LABEL_NAME.to_string(), name.to_string());

        let ports: Vec<ServicePort> = workload
            .service
            .as_ref()
            .map(|svc| {
                svc.ports
                    .iter()
                    .map(|(port_name, port_spec)| ServicePort {
                        name: Some(port_name.clone()),
                        port: port_spec.port,
                        target_port: port_spec.target_port,
                        protocol: port_spec.protocol.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Add use-waypoint label to route traffic through namespace waypoint
        let metadata = ObjectMeta::new(name, namespace)
            .with_label(mesh::USE_WAYPOINT_LABEL, mesh::waypoint_name(namespace));

        Service {
            api_version: "v1".to_string(),
            kind: "Service".to_string(),
            metadata,
            spec: ServiceSpec {
                selector,
                ports,
                type_: None,
            },
        }
    }

    /// Compile a KEDA ScaledObject from the service's autoscaling config.
    fn compile_scaled_object(
        name: &str,
        namespace: &str,
        replicas: &ReplicaSpec,
        monitoring_enabled: bool,
    ) -> Result<ScaledObject, CompilationError> {
        use lattice_infra::bootstrap::prometheus::{vmselect_url, VMSELECT_PATH, VMSELECT_PORT};

        let autoscaling = if replicas.autoscaling.is_empty() {
            vec![AutoscalingMetric {
                metric: "cpu".to_string(),
                target: 80,
            }]
        } else {
            replicas.autoscaling.clone()
        };

        let custom_metrics: Vec<String> = autoscaling
            .iter()
            .filter(|m| !matches!(m.metric.as_str(), "cpu" | "memory"))
            .map(|m| m.metric.clone())
            .collect();
        if !custom_metrics.is_empty() && !monitoring_enabled {
            return Err(CompilationError::MonitoringRequired {
                metrics: custom_metrics,
            });
        }

        let server_address = format!("{}:{}{}", vmselect_url(), VMSELECT_PORT, VMSELECT_PATH);

        let triggers = autoscaling
            .iter()
            .map(|m| match m.metric.as_str() {
                "cpu" | "memory" => ScaledObjectTrigger {
                    type_: m.metric.clone(),
                    metric_type: Some("Utilization".to_string()),
                    metadata: [("value".to_string(), m.target.to_string())]
                        .into_iter()
                        .collect(),
                },
                _ => ScaledObjectTrigger {
                    type_: "prometheus".to_string(),
                    metric_type: None,
                    metadata: [
                        ("serverAddress".to_string(), server_address.clone()),
                        (
                            "query".to_string(),
                            format!(
                                "avg({}{{namespace=\"{}\",pod=~\"{}-.*\"}})",
                                m.metric, namespace, name
                            ),
                        ),
                        ("threshold".to_string(), m.target.to_string()),
                    ]
                    .into_iter()
                    .collect(),
                },
            })
            .collect();

        Ok(ScaledObject {
            api_version: ScaledObject::API_VERSION.to_string(),
            kind: ScaledObject::KIND.to_string(),
            metadata: ObjectMeta::new(name, namespace),
            spec: ScaledObjectSpec {
                scale_target_ref: ScaleTargetRef {
                    api_version: "apps/v1".to_string(),
                    kind: "Deployment".to_string(),
                    name: name.to_string(),
                },
                min_replica_count: replicas.min,
                max_replica_count: replicas.max.unwrap_or(replicas.min),
                triggers,
            },
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        AutoscalingMetric, ContainerSpec, PortSpec, ReplicaSpec, ResourceSpec, ResourceType,
        ServicePortsSpec, WorkloadSpec,
    };
    use lattice_common::template::TemplateString;

    /// Build rendered containers from a service spec for testing.
    ///
    /// Simulates what the TemplateRenderer does:
    /// - Non-secret variables are treated as pre-rendered plain values
    /// - `${secret.*}` variables are separated into `secret_variables`
    /// - Image, command, args are copied from the spec
    fn build_test_rendered_containers(
        service: &LatticeService,
    ) -> BTreeMap<String, RenderedContainer> {
        use lattice_common::template::{parse_secret_ref, RenderedVariable};

        service
            .spec
            .workload
            .containers
            .iter()
            .map(|(cname, cspec)| {
                let mut variables = BTreeMap::new();
                let mut secret_variables = BTreeMap::new();

                for (var_name, var_val) in &cspec.variables {
                    if let Some(sref) = parse_secret_ref(var_val.as_str()) {
                        secret_variables.insert(var_name.clone(), sref);
                    } else {
                        variables
                            .insert(var_name.clone(), RenderedVariable::plain(var_val.as_str()));
                    }
                }

                (
                    cname.clone(),
                    RenderedContainer {
                        name: cname.clone(),
                        image: cspec.image.clone(),
                        command: cspec.command.clone(),
                        args: cspec.args.clone(),
                        variables,
                        secret_variables,
                        eso_templated_variables: BTreeMap::new(),
                        files: BTreeMap::new(),
                        volumes: BTreeMap::new(),
                    },
                )
            })
            .collect()
    }

    /// Core test compilation helper.
    ///
    /// Builds rendered containers, runs env::compile for envFrom, and delegates
    /// to WorkloadCompiler. Mirrors the ServiceCompiler pipeline without
    /// requiring a TemplateRenderer or ServiceGraph.
    fn test_compile_with_monitoring(
        service: &LatticeService,
        secret_refs: &BTreeMap<String, SecretRef>,
        monitoring_enabled: bool,
    ) -> Result<GeneratedWorkloads, CompilationError> {
        let name = service
            .metadata
            .name
            .as_deref()
            .expect("test service must have a name");
        let namespace = service
            .metadata
            .namespace
            .as_deref()
            .expect("test service must have a namespace");
        let volumes = VolumeCompiler::compile(
            name,
            namespace,
            &service.spec.workload,
            &service.spec.runtime.sidecars,
        )
        .expect("test volume compilation should succeed");

        let rendered_containers = build_test_rendered_containers(service);

        // Run env::compile per container to get envFrom refs
        let mut per_container_env_from = BTreeMap::new();
        for (cname, rendered) in &rendered_containers {
            let compiled_env = env::compile(name, cname, namespace, &rendered.variables);
            per_container_env_from.insert(cname.clone(), compiled_env.env_from);
        }

        let empty_file_volumes = BTreeMap::new();
        let empty_file_mounts = BTreeMap::new();

        let container_data = ContainerCompilationData {
            secret_refs,
            rendered_containers: &rendered_containers,
            per_container_env_from: &per_container_env_from,
            per_container_file_volumes: &empty_file_volumes,
            per_container_file_mounts: &empty_file_mounts,
        };

        WorkloadCompiler::compile(
            name,
            service,
            namespace,
            &volumes,
            ProviderType::Docker,
            monitoring_enabled,
            &container_data,
        )
    }

    /// Core test compilation helper with monitoring enabled by default.
    fn test_compile(
        service: &LatticeService,
        secret_refs: &BTreeMap<String, SecretRef>,
    ) -> Result<GeneratedWorkloads, CompilationError> {
        test_compile_with_monitoring(service, secret_refs, true)
    }

    /// Helper to compile a service with no secret refs
    fn compile_service(service: &LatticeService) -> GeneratedWorkloads {
        test_compile(service, &BTreeMap::new()).expect("test workload compilation should succeed")
    }

    /// Helper to compile a service with monitoring flag
    fn compile_service_with_monitoring(
        service: &LatticeService,
        monitoring_enabled: bool,
    ) -> GeneratedWorkloads {
        test_compile_with_monitoring(service, &BTreeMap::new(), monitoring_enabled)
            .expect("test workload compilation should succeed")
    }

    /// Helper to compile a service with secret refs
    fn compile_service_with_secret_refs(
        service: &LatticeService,
        secret_refs: &BTreeMap<String, SecretRef>,
    ) -> Result<GeneratedWorkloads, CompilationError> {
        test_compile(service, secret_refs)
    }

    fn make_service(name: &str, namespace: &str) -> LatticeService {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "nginx:latest".to_string(),
                ..Default::default()
            },
        );

        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 80,
                target_port: None,
                protocol: None,
            },
        );

        LatticeService {
            metadata: kube::api::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: crate::crd::LatticeServiceSpec {
                workload: WorkloadSpec {
                    containers,
                    service: Some(ServicePortsSpec { ports }),
                    ..Default::default()
                },
                ..Default::default()
            },
            status: None,
        }
    }

    // =========================================================================
    // Story: Always Generate ServiceAccount
    // =========================================================================

    #[test]
    fn story_always_generates_service_account() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service);

        let sa = output.service_account.expect("should have service account");
        assert_eq!(sa.metadata.name, "my-app");
        assert_eq!(sa.metadata.namespace, "default");
        assert_eq!(sa.api_version, "v1");
        assert_eq!(sa.kind, "ServiceAccount");
        assert_eq!(sa.automount_service_account_token, Some(false));
    }

    // =========================================================================
    // Story: Always Generate Deployment
    // =========================================================================

    #[test]
    fn story_always_generates_deployment() {
        let service = make_service("my-app", "prod");
        let output = compile_service(&service);

        let deployment = output.deployment.expect("should have deployment");
        assert_eq!(deployment.metadata.name, "my-app");
        assert_eq!(deployment.metadata.namespace, "prod");
        assert_eq!(deployment.api_version, "apps/v1");
        assert_eq!(deployment.kind, "Deployment");
        assert_eq!(deployment.spec.replicas, 1);
    }

    #[test]
    fn story_deployment_has_correct_labels() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service);

        let deployment = output.deployment.expect("deployment should be set");
        assert_eq!(
            deployment
                .spec
                .selector
                .match_labels
                .get(lattice_common::LABEL_NAME),
            Some(&"my-app".to_string())
        );
        assert_eq!(
            deployment
                .spec
                .template
                .metadata
                .labels
                .get(lattice_common::LABEL_MANAGED_BY),
            Some(&lattice_common::LABEL_MANAGED_BY_LATTICE.to_string())
        );
    }

    #[test]
    fn story_deployment_has_complete_spec() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service);

        let deployment = output.deployment.expect("deployment should be set");

        // Deployment has containers
        assert!(!deployment.spec.template.spec.containers.is_empty());
        assert_eq!(deployment.spec.template.spec.containers[0].name, "main");
        assert_eq!(
            deployment.spec.template.spec.containers[0].image,
            "nginx:latest"
        );

        // Deployment has service account name matching the service
        assert_eq!(deployment.spec.template.spec.service_account_name, "my-app");

        // Deployment has topology spread constraints for HA
        // Tests use Docker provider which spreads by hostname
        assert_eq!(
            deployment
                .spec
                .template
                .spec
                .topology_spread_constraints
                .len(),
            1
        );
        let constraint = &deployment.spec.template.spec.topology_spread_constraints[0];
        assert_eq!(constraint.max_skew, 1);
        assert_eq!(constraint.topology_key, "kubernetes.io/hostname");
        assert_eq!(constraint.when_unsatisfiable, "ScheduleAnyway");
        assert_eq!(
            constraint
                .label_selector
                .match_labels
                .get(lattice_common::LABEL_NAME),
            Some(&"my-app".to_string())
        );
    }

    // =========================================================================
    // Story: Generate Service When Ports Defined
    // =========================================================================

    #[test]
    fn story_generates_service_with_ports() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service);

        let svc = output.service.expect("should have service");
        assert_eq!(svc.metadata.name, "my-app");
        assert_eq!(svc.api_version, "v1");
        assert_eq!(svc.kind, "Service");
        assert!(!svc.spec.ports.is_empty());
    }

    #[test]
    fn story_no_service_without_ports() {
        let mut service = make_service("my-app", "default");
        service.spec.workload.service = None;

        let output = compile_service(&service);
        assert!(output.service.is_none());
    }

    // =========================================================================
    // Story: Generate KEDA ScaledObject When Max Replicas Set
    // =========================================================================

    #[test]
    fn scaled_object_generated_with_max_replicas() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = ReplicaSpec {
            min: 2,
            max: Some(10),
            autoscaling: vec![],
        };

        let output = compile_service(&service);

        let so = output.scaled_object.expect("should have ScaledObject");
        assert_eq!(so.api_version, "keda.sh/v1alpha1");
        assert_eq!(so.kind, "ScaledObject");
        assert_eq!(so.metadata.name, "my-app");
        assert_eq!(so.spec.min_replica_count, 2);
        assert_eq!(so.spec.max_replica_count, 10);
        assert_eq!(so.spec.scale_target_ref.name, "my-app");
        assert_eq!(so.spec.scale_target_ref.kind, "Deployment");
    }

    #[test]
    fn no_scaled_object_without_max_replicas() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service);
        assert!(output.scaled_object.is_none());
    }

    #[test]
    fn scaled_object_default_cpu_80() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = ReplicaSpec {
            min: 1,
            max: Some(5),
            autoscaling: vec![],
        };
        let output = compile_service(&service);
        let so = output.scaled_object.expect("should have ScaledObject");
        assert_eq!(so.spec.triggers.len(), 1);
        let t = &so.spec.triggers[0];
        assert_eq!(t.type_, "cpu");
        assert_eq!(t.metric_type.as_deref(), Some("Utilization"));
        assert_eq!(t.metadata.get("value").unwrap(), "80");
    }

    #[test]
    fn scaled_object_custom_cpu_threshold() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = ReplicaSpec {
            min: 1,
            max: Some(5),
            autoscaling: vec![AutoscalingMetric {
                metric: "cpu".to_string(),
                target: 60,
            }],
        };
        let output = compile_service(&service);
        let so = output.scaled_object.expect("should have ScaledObject");
        assert_eq!(so.spec.triggers.len(), 1);
        assert_eq!(so.spec.triggers[0].type_, "cpu");
        assert_eq!(so.spec.triggers[0].metadata.get("value").unwrap(), "60");
    }

    #[test]
    fn scaled_object_memory_trigger() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = ReplicaSpec {
            min: 1,
            max: Some(5),
            autoscaling: vec![AutoscalingMetric {
                metric: "memory".to_string(),
                target: 75,
            }],
        };
        let output = compile_service(&service);
        let so = output.scaled_object.expect("should have ScaledObject");
        assert_eq!(so.spec.triggers.len(), 1);
        let t = &so.spec.triggers[0];
        assert_eq!(t.type_, "memory");
        assert_eq!(t.metric_type.as_deref(), Some("Utilization"));
        assert_eq!(t.metadata.get("value").unwrap(), "75");
    }

    #[test]
    fn scaled_object_prometheus_trigger() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = ReplicaSpec {
            min: 1,
            max: Some(10),
            autoscaling: vec![AutoscalingMetric {
                metric: "vllm_num_requests_waiting".to_string(),
                target: 5,
            }],
        };
        let output = compile_service(&service);
        let so = output.scaled_object.expect("should have ScaledObject");
        assert_eq!(so.spec.triggers.len(), 1);
        let t = &so.spec.triggers[0];
        assert_eq!(t.type_, "prometheus");
        assert!(t.metric_type.is_none());
        assert!(t
            .metadata
            .get("serverAddress")
            .unwrap()
            .contains("vmselect"));
        assert!(t
            .metadata
            .get("query")
            .unwrap()
            .contains("vllm_num_requests_waiting"));
        assert!(t
            .metadata
            .get("query")
            .unwrap()
            .contains("namespace=\"default\""));
        assert!(t
            .metadata
            .get("query")
            .unwrap()
            .contains("pod=~\"my-app-.*\""));
        assert_eq!(t.metadata.get("threshold").unwrap(), "5");
    }

    #[test]
    fn scaled_object_multi_signal() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = ReplicaSpec {
            min: 1,
            max: Some(10),
            autoscaling: vec![
                AutoscalingMetric {
                    metric: "cpu".to_string(),
                    target: 70,
                },
                AutoscalingMetric {
                    metric: "vllm_num_requests_waiting".to_string(),
                    target: 5,
                },
            ],
        };
        let output = compile_service(&service);
        let so = output.scaled_object.expect("should have ScaledObject");
        assert_eq!(so.spec.triggers.len(), 2);
        assert_eq!(so.spec.triggers[0].type_, "cpu");
        assert_eq!(so.spec.triggers[1].type_, "prometheus");
    }

    #[test]
    fn scaled_object_defaults_to_cpu_when_no_autoscaling() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = ReplicaSpec {
            min: 2,
            max: Some(8),
            autoscaling: vec![],
        };
        let output = compile_service(&service);
        let so = output.scaled_object.expect("should have ScaledObject");
        assert_eq!(so.spec.min_replica_count, 2);
        assert_eq!(so.spec.max_replica_count, 8);
        assert_eq!(so.spec.triggers.len(), 1);
        assert_eq!(so.spec.triggers[0].type_, "cpu");
    }

    #[test]
    fn scaled_object_custom_metrics_require_monitoring() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = ReplicaSpec {
            min: 1,
            max: Some(10),
            autoscaling: vec![AutoscalingMetric {
                metric: "vllm_num_requests_waiting".to_string(),
                target: 5,
            }],
        };

        // With monitoring disabled, custom metrics should fail
        let result = test_compile_with_monitoring(&service, &BTreeMap::new(), false);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("monitoring"));
        assert!(err.contains("vllm_num_requests_waiting"));
    }

    #[test]
    fn scaled_object_cpu_memory_work_without_monitoring() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = ReplicaSpec {
            min: 1,
            max: Some(5),
            autoscaling: vec![
                AutoscalingMetric {
                    metric: "cpu".to_string(),
                    target: 70,
                },
                AutoscalingMetric {
                    metric: "memory".to_string(),
                    target: 80,
                },
            ],
        };

        // cpu/memory should work even without monitoring
        let output = compile_service_with_monitoring(&service, false);
        let so = output.scaled_object.expect("should have ScaledObject");
        assert_eq!(so.spec.triggers.len(), 2);
        assert_eq!(so.spec.triggers[0].type_, "cpu");
        assert_eq!(so.spec.triggers[1].type_, "memory");
    }

    // =========================================================================
    // Story: PodDisruptionBudget for HA Services
    // =========================================================================

    #[test]
    fn pdb_generated_for_ha_services() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = ReplicaSpec {
            min: 3,
            max: None,
            autoscaling: vec![],
        };

        let output = compile_service(&service);

        let pdb = output.pdb.expect("should have PDB");
        assert_eq!(pdb.api_version, "policy/v1");
        assert_eq!(pdb.kind, "PodDisruptionBudget");
        assert_eq!(pdb.metadata.name, "my-app");
        assert_eq!(pdb.spec.min_available, Some(2));
        assert_eq!(
            pdb.spec
                .selector
                .match_labels
                .get(lattice_common::LABEL_NAME),
            Some(&"my-app".to_string())
        );
    }

    #[test]
    fn no_pdb_for_single_replica() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service);
        assert!(output.pdb.is_none());
    }

    #[test]
    fn pdb_min_available_for_two_replicas() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = ReplicaSpec {
            min: 2,
            max: None,
            autoscaling: vec![],
        };

        let output = compile_service(&service);

        let pdb = output.pdb.expect("should have PDB");
        assert_eq!(pdb.spec.min_available, Some(1));
    }

    // =========================================================================
    // Story: Deployment Strategy
    // =========================================================================

    #[test]
    fn story_rolling_strategy() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service);

        let strategy = output
            .deployment
            .expect("deployment should be generated")
            .spec
            .strategy
            .expect("strategy should be set");
        assert_eq!(strategy.type_, "RollingUpdate");
        let rolling = strategy
            .rolling_update
            .expect("rolling update should be configured");
        assert_eq!(rolling.max_unavailable, Some("25%".to_string()));
        assert_eq!(rolling.max_surge, Some("25%".to_string()));
    }

    #[test]
    fn story_canary_strategy() {
        let mut service = make_service("my-app", "default");
        service.spec.deploy.strategy = DeployStrategy::Canary;

        let output = compile_service(&service);

        let strategy = output
            .deployment
            .expect("deployment should be generated")
            .spec
            .strategy
            .expect("strategy should be set");
        assert_eq!(strategy.type_, "RollingUpdate");
        let rolling = strategy
            .rolling_update
            .expect("rolling update should be configured");
        assert_eq!(rolling.max_unavailable, Some("0".to_string()));
        assert_eq!(rolling.max_surge, Some("100%".to_string()));
    }

    // =========================================================================
    // Story: Container Configuration
    // =========================================================================

    #[test]
    fn story_container_environment_variables_via_env_from() {
        let mut service = make_service("my-app", "default");
        let container = service
            .spec
            .workload
            .containers
            .get_mut("main")
            .expect("main container should exist");
        container
            .variables
            .insert("LOG_LEVEL".to_string(), TemplateString::from("debug"));

        let output = compile_service(&service);
        let deployment = output.deployment.expect("deployment should be set");

        // Non-secret env vars are delivered via envFrom (ConfigMap), not individual env entries
        let main = deployment
            .spec
            .template
            .spec
            .containers
            .iter()
            .find(|c| c.name == "main")
            .expect("main container should exist");

        assert!(
            !main.env_from.is_empty(),
            "should have envFrom for rendered variables"
        );
        assert!(
            main.env_from.iter().any(|ef| ef.config_map_ref.is_some()),
            "envFrom should reference a ConfigMap"
        );
    }

    #[test]
    fn story_container_ports_from_service() {
        let service = make_service("my-app", "default");

        let output = compile_service(&service);
        let deployment = output.deployment.expect("deployment should be set");

        let ports = &deployment
            .spec
            .template
            .spec
            .containers
            .iter()
            .find(|c| c.name == "main")
            .expect("main container should exist")
            .ports;
        assert!(ports.iter().any(|p| p.container_port == 80));
    }

    // =========================================================================
    // Story: GeneratedWorkloads Utility Methods
    // =========================================================================

    #[test]
    fn story_is_empty() {
        let empty = GeneratedWorkloads::new();
        assert!(empty.is_empty());

        let service = make_service("my-app", "default");
        let output = compile_service(&service);
        assert!(!output.is_empty());
    }

    // =========================================================================
    // Story: Config Hash for Rollouts
    // =========================================================================

    #[test]
    fn test_config_hash_empty() {
        let hash = compute_config_hash(&[], &[], &[], &[]);
        // Empty data still produces a hash
        assert_eq!(hash.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_config_hash_with_configmap() {
        let mut cm = ConfigMap::new("test", "default");
        cm.data.insert("KEY".to_string(), "value".to_string());

        let hash1 = compute_config_hash(&[cm.clone()], &[], &[], &[]);
        assert_eq!(hash1.len(), 16);

        // Different value produces different hash
        cm.data.insert("KEY".to_string(), "different".to_string());
        let hash2 = compute_config_hash(&[cm], &[], &[], &[]);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_config_hash_with_secret() {
        let mut secret = Secret::new("test", "default");
        secret
            .string_data
            .insert("PASSWORD".to_string(), "secret123".to_string());

        let hash = compute_config_hash(&[], &[secret], &[], &[]);
        assert_eq!(hash.len(), 16);
    }

    #[test]
    fn test_config_hash_deterministic() {
        let mut cm = ConfigMap::new("test", "default");
        cm.data.insert("KEY".to_string(), "value".to_string());

        // Same input produces same hash
        let hash1 = compute_config_hash(&[cm.clone()], &[], &[], &[]);
        let hash2 = compute_config_hash(&[cm], &[], &[], &[]);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_config_hash_combines_all_sources() {
        let mut env_cm = ConfigMap::new("env", "default");
        env_cm
            .data
            .insert("HOST".to_string(), "localhost".to_string());

        let mut env_secret = Secret::new("env", "default");
        env_secret
            .string_data
            .insert("PASSWORD".to_string(), "secret".to_string());

        let mut files_cm = ConfigMap::new("files", "default");
        files_cm
            .data
            .insert("config-yaml".to_string(), "key: value".to_string());

        let mut files_secret = Secret::new("files", "default");
        files_secret
            .string_data
            .insert("cert-pem".to_string(), "binary".to_string());

        // All four produce a combined hash
        let hash_all = compute_config_hash(
            &[env_cm.clone()],
            &[env_secret.clone()],
            &[files_cm],
            &[files_secret],
        );

        // Subset produces different hash
        let hash_partial = compute_config_hash(&[env_cm], &[env_secret], &[], &[]);

        assert_ne!(hash_all, hash_partial);
    }

    // =========================================================================
    // Story: Security Context — Secure Defaults (PSS Restricted)
    // =========================================================================

    #[test]
    fn story_default_security_context_applied() {
        // No security context specified → full restricted defaults
        let k8s_ctx = PodTemplateCompiler::compile_security_context(None);

        let caps = k8s_ctx.capabilities.expect("should have capabilities");
        assert_eq!(caps.add, None);
        assert_eq!(caps.drop, Some(vec!["ALL".to_string()]));
        assert_eq!(k8s_ctx.privileged, None);
        assert_eq!(k8s_ctx.read_only_root_filesystem, Some(true));
        assert_eq!(k8s_ctx.run_as_non_root, Some(true));
        assert_eq!(k8s_ctx.allow_privilege_escalation, Some(false));
        assert_eq!(
            k8s_ctx.seccomp_profile.as_ref().unwrap().type_,
            "RuntimeDefault"
        );
        assert_eq!(
            k8s_ctx.app_armor_profile.as_ref().unwrap().type_,
            "RuntimeDefault"
        );
    }

    #[test]
    fn story_default_security_context_for_sidecars() {
        use crate::crd::SidecarSpec;

        let mut service = make_service("my-app", "default");
        service.spec.runtime.sidecars.insert(
            "logger".to_string(),
            SidecarSpec {
                image: "fluentbit:latest".to_string(),
                ..Default::default()
            },
        );

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");

        let logger = deployment
            .spec
            .template
            .spec
            .containers
            .iter()
            .find(|c| c.name == "logger")
            .expect("logger sidecar should exist");

        let sec = logger
            .security_context
            .as_ref()
            .expect("should have security context");
        assert_eq!(sec.allow_privilege_escalation, Some(false));
        assert_eq!(sec.read_only_root_filesystem, Some(true));
        assert_eq!(sec.run_as_non_root, Some(true));
        let caps = sec.capabilities.as_ref().expect("should have capabilities");
        assert_eq!(caps.drop, Some(vec!["ALL".to_string()]));
    }

    #[test]
    fn story_security_context_with_user_overrides() {
        use crate::crd::SecurityContext;

        let security = SecurityContext {
            capabilities: vec!["NET_ADMIN".to_string(), "SYS_MODULE".to_string()],
            drop_capabilities: None,
            privileged: Some(false),
            read_only_root_filesystem: Some(true),
            run_as_non_root: Some(true),
            run_as_user: Some(1000),
            run_as_group: Some(1000),
            allow_privilege_escalation: Some(false),
            ..Default::default()
        };

        let k8s_ctx = PodTemplateCompiler::compile_security_context(Some(&security));

        let caps = k8s_ctx.capabilities.expect("should have capabilities");
        assert_eq!(
            caps.add,
            Some(vec!["NET_ADMIN".to_string(), "SYS_MODULE".to_string()])
        );
        assert_eq!(caps.drop, Some(vec!["ALL".to_string()]));
        assert_eq!(k8s_ctx.privileged, Some(false));
        assert_eq!(k8s_ctx.read_only_root_filesystem, Some(true));
        assert_eq!(k8s_ctx.run_as_non_root, Some(true));
        assert_eq!(k8s_ctx.run_as_user, Some(1000));
        assert_eq!(k8s_ctx.run_as_group, Some(1000));
        assert_eq!(k8s_ctx.allow_privilege_escalation, Some(false));
    }

    #[test]
    fn story_privileged_mode_relaxes_defaults() {
        use crate::crd::SecurityContext;

        let security = SecurityContext {
            privileged: Some(true),
            ..Default::default()
        };

        let k8s_ctx = PodTemplateCompiler::compile_security_context(Some(&security));

        assert_eq!(k8s_ctx.privileged, Some(true));
        // Privileged: no drop ALL, no allowPrivilegeEscalation restriction
        assert!(k8s_ctx.capabilities.is_none());
        assert_eq!(k8s_ctx.allow_privilege_escalation, None);
        // Other defaults still apply
        assert_eq!(k8s_ctx.read_only_root_filesystem, Some(true));
        assert_eq!(k8s_ctx.run_as_non_root, Some(true));
    }

    #[test]
    fn story_privileged_with_caps_keeps_add() {
        use crate::crd::SecurityContext;

        let security = SecurityContext {
            privileged: Some(true),
            capabilities: vec!["NET_ADMIN".to_string()],
            ..Default::default()
        };

        let k8s_ctx = PodTemplateCompiler::compile_security_context(Some(&security));

        let caps = k8s_ctx
            .capabilities
            .expect("should have capabilities for add");
        assert_eq!(caps.add, Some(vec!["NET_ADMIN".to_string()]));
        assert_eq!(caps.drop, None); // Privileged: no drop
    }

    #[test]
    fn story_run_as_user_zero_disables_run_as_non_root() {
        use crate::crd::SecurityContext;

        let security = SecurityContext {
            run_as_user: Some(0),
            ..Default::default()
        };

        let k8s_ctx = PodTemplateCompiler::compile_security_context(Some(&security));

        assert_eq!(k8s_ctx.run_as_user, Some(0));
        assert_eq!(k8s_ctx.run_as_non_root, Some(false));
    }

    #[test]
    fn story_user_can_override_readonly_root_fs() {
        use crate::crd::SecurityContext;

        let security = SecurityContext {
            read_only_root_filesystem: Some(false),
            ..Default::default()
        };

        let k8s_ctx = PodTemplateCompiler::compile_security_context(Some(&security));
        assert_eq!(k8s_ctx.read_only_root_filesystem, Some(false));
    }

    #[test]
    fn story_seccomp_profile_defaults() {
        let k8s_ctx = PodTemplateCompiler::compile_security_context(None);
        let seccomp = k8s_ctx
            .seccomp_profile
            .expect("should have seccomp profile");
        assert_eq!(seccomp.type_, "RuntimeDefault");
        assert!(seccomp.localhost_profile.is_none());
    }

    #[test]
    fn story_seccomp_profile_user_override() {
        use crate::crd::SecurityContext;

        let security = SecurityContext {
            seccomp_profile: Some("Unconfined".to_string()),
            ..Default::default()
        };

        let k8s_ctx = PodTemplateCompiler::compile_security_context(Some(&security));
        let seccomp = k8s_ctx
            .seccomp_profile
            .expect("should have seccomp profile");
        assert_eq!(seccomp.type_, "Unconfined");
    }

    #[test]
    fn story_apparmor_profile_defaults() {
        let k8s_ctx = PodTemplateCompiler::compile_security_context(None);
        let apparmor = k8s_ctx
            .app_armor_profile
            .expect("should have apparmor profile");
        assert_eq!(apparmor.type_, "RuntimeDefault");
        assert!(apparmor.localhost_profile.is_none());
    }

    #[test]
    fn story_apparmor_profile_localhost() {
        use crate::crd::SecurityContext;

        let security = SecurityContext {
            apparmor_profile: Some("Localhost".to_string()),
            apparmor_localhost_profile: Some("my-custom-profile".to_string()),
            ..Default::default()
        };

        let k8s_ctx = PodTemplateCompiler::compile_security_context(Some(&security));
        let apparmor = k8s_ctx
            .app_armor_profile
            .expect("should have apparmor profile");
        assert_eq!(apparmor.type_, "Localhost");
        assert_eq!(
            apparmor.localhost_profile,
            Some("my-custom-profile".to_string())
        );
    }

    // =========================================================================
    // Story: Pod Security Context (Sysctls)
    // =========================================================================

    #[test]
    fn story_pod_security_context_sysctls() {
        let mut service = make_service("my-app", "default");
        service.spec.runtime.sysctls.insert(
            "net.ipv4.conf.all.src_valid_mark".to_string(),
            "1".to_string(),
        );
        service
            .spec
            .runtime
            .sysctls
            .insert("net.core.somaxconn".to_string(), "65535".to_string());

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");

        let pod_sec = deployment
            .spec
            .template
            .spec
            .security_context
            .expect("should have pod security context");

        let sysctls = pod_sec.sysctls.expect("should have sysctls");
        assert_eq!(sysctls.len(), 2);
        assert!(sysctls
            .iter()
            .any(|s| s.name == "net.ipv4.conf.all.src_valid_mark" && s.value == "1"));
        assert!(sysctls
            .iter()
            .any(|s| s.name == "net.core.somaxconn" && s.value == "65535"));
    }

    #[test]
    fn story_pod_security_context_has_secure_defaults() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");

        let pod_sec = deployment
            .spec
            .template
            .spec
            .security_context
            .expect("should always have pod security context");

        assert_eq!(pod_sec.run_as_non_root, Some(true));
        assert_eq!(
            pod_sec.seccomp_profile.as_ref().unwrap().type_,
            "RuntimeDefault"
        );
        assert!(pod_sec.sysctls.is_none()); // No sysctls when none specified
    }

    // =========================================================================
    // Story: EmptyDir Writable Paths with Read-Only RootFS
    // =========================================================================

    #[test]
    fn story_emptydir_in_deployment_with_readonly_rootfs() {
        // Simulate nginx pattern: read-only rootfs + emptyDir for writable paths
        let mut service = make_service("nginx-app", "default");
        let container = service.spec.workload.containers.get_mut("main").unwrap();
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
        container.volumes.insert(
            "/var/run".to_string(),
            lattice_common::crd::VolumeMount {
                source: None,
                path: None,
                read_only: None,
                medium: None,
                size_limit: None,
            },
        );
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

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");

        // Container should have read-only rootfs (secure default)
        let main = &deployment.spec.template.spec.containers[0];
        let sec = main
            .security_context
            .as_ref()
            .expect("should have security context");
        assert_eq!(sec.read_only_root_filesystem, Some(true));

        // Container should have 3 emptyDir volume mounts
        let emptydir_mounts: Vec<_> = main
            .volume_mounts
            .iter()
            .filter(|vm| vm.name.starts_with("emptydir-"))
            .collect();
        assert_eq!(emptydir_mounts.len(), 3);

        // Pod should have 3 emptyDir volumes
        let emptydir_vols: Vec<_> = deployment
            .spec
            .template
            .spec
            .volumes
            .iter()
            .filter(|v| v.empty_dir.is_some())
            .collect();
        assert_eq!(emptydir_vols.len(), 3);

        // Verify specific volume names
        let vol_names: Vec<_> = emptydir_vols.iter().map(|v| v.name.as_str()).collect();
        assert!(vol_names.contains(&"emptydir-var-cache-nginx"));
        assert!(vol_names.contains(&"emptydir-var-run"));
        assert!(vol_names.contains(&"emptydir-tmp"));
    }

    #[test]
    fn story_emptydir_tmpfs_flows_to_deployment() {
        let mut service = make_service("my-app", "default");
        let container = service.spec.workload.containers.get_mut("main").unwrap();
        container.volumes.insert(
            "/dev/shm".to_string(),
            lattice_common::crd::VolumeMount {
                source: None,
                path: None,
                read_only: None,
                medium: Some("Memory".to_string()),
                size_limit: Some("256Mi".to_string()),
            },
        );

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");

        let shm_vol = deployment
            .spec
            .template
            .spec
            .volumes
            .iter()
            .find(|v| v.name == "emptydir-dev-shm")
            .expect("should have emptyDir volume for /dev/shm");

        let ed = shm_vol.empty_dir.as_ref().expect("should be emptyDir");
        assert_eq!(ed.medium, Some("Memory".to_string()));
        assert_eq!(ed.size_limit, Some("256Mi".to_string()));
    }

    // =========================================================================
    // Story: Init Containers Separated
    // =========================================================================

    #[test]
    fn story_init_containers_separated() {
        use crate::crd::SidecarSpec;

        let mut service = make_service("my-app", "default");
        service.spec.runtime.sidecars.insert(
            "init-setup".to_string(),
            SidecarSpec {
                image: "busybox:latest".to_string(),
                command: Some(vec!["sh".to_string(), "-c".to_string()]),
                args: Some(vec!["echo hello".to_string()]),
                init: Some(true),
                ..Default::default()
            },
        );
        service.spec.runtime.sidecars.insert(
            "vpn".to_string(),
            SidecarSpec {
                image: "wireguard:latest".to_string(),
                init: Some(false),
                ..Default::default()
            },
        );

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");

        // Check init containers
        assert_eq!(deployment.spec.template.spec.init_containers.len(), 1);
        assert_eq!(
            deployment.spec.template.spec.init_containers[0].name,
            "init-setup"
        );

        // Check regular containers (main + vpn sidecar)
        assert_eq!(deployment.spec.template.spec.containers.len(), 2);
        assert!(deployment
            .spec
            .template
            .spec
            .containers
            .iter()
            .any(|c| c.name == "main"));
        assert!(deployment
            .spec
            .template
            .spec
            .containers
            .iter()
            .any(|c| c.name == "vpn"));
    }

    // =========================================================================
    // Story: Sidecars Included in Deployment
    // =========================================================================

    #[test]
    fn story_sidecars_included_in_deployment() {
        use crate::crd::{SecurityContext, SidecarSpec};

        let mut service = make_service("my-app", "default");
        service.spec.runtime.sidecars.insert(
            "vpn".to_string(),
            SidecarSpec {
                image: "wireguard:latest".to_string(),
                security: Some(SecurityContext {
                    capabilities: vec!["NET_ADMIN".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");

        // Main + VPN sidecar
        assert_eq!(deployment.spec.template.spec.containers.len(), 2);

        let vpn = deployment
            .spec
            .template
            .spec
            .containers
            .iter()
            .find(|c| c.name == "vpn")
            .expect("vpn container should exist");

        assert_eq!(vpn.image, "wireguard:latest");

        // Check security context on sidecar
        let sec = vpn
            .security_context
            .as_ref()
            .expect("should have security context");
        let caps = sec.capabilities.as_ref().expect("should have capabilities");
        assert_eq!(caps.add, Some(vec!["NET_ADMIN".to_string()]));
        assert_eq!(caps.drop, Some(vec!["ALL".to_string()]));
    }

    // =========================================================================
    // Story: Host Network and Share Process Namespace
    // =========================================================================

    #[test]
    fn story_host_network_and_share_process_namespace() {
        let mut service = make_service("my-app", "default");
        service.spec.runtime.host_network = Some(true);
        service.spec.runtime.share_process_namespace = Some(true);

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");

        assert_eq!(deployment.spec.template.spec.host_network, Some(true));
        assert_eq!(
            deployment.spec.template.spec.share_process_namespace,
            Some(true)
        );
    }

    #[test]
    fn story_host_network_none_by_default() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");

        assert!(deployment.spec.template.spec.host_network.is_none());
        assert!(deployment
            .spec
            .template
            .spec
            .share_process_namespace
            .is_none());
    }

    // =========================================================================
    // Story: Container Security Context
    // =========================================================================

    #[test]
    fn story_main_container_security_context() {
        use crate::crd::SecurityContext;

        let mut service = make_service("my-app", "default");
        service
            .spec
            .workload
            .containers
            .get_mut("main")
            .unwrap()
            .security = Some(SecurityContext {
            capabilities: vec!["NET_BIND_SERVICE".to_string()],
            run_as_non_root: Some(true),
            run_as_user: Some(1000),
            ..Default::default()
        });

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");

        let main = deployment
            .spec
            .template
            .spec
            .containers
            .iter()
            .find(|c| c.name == "main")
            .expect("main container should exist");

        let sec = main
            .security_context
            .as_ref()
            .expect("should have security context");
        assert_eq!(sec.run_as_non_root, Some(true));
        assert_eq!(sec.run_as_user, Some(1000));
    }

    // =========================================================================
    // Story: GPU Resource Compilation
    // =========================================================================

    #[test]
    fn gpu_full_gpu_in_limits() {
        let mut service = make_service("gpu-app", "default");
        service.spec.workload.resources.insert(
            "my-gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some({
                    let mut p = std::collections::BTreeMap::new();
                    p.insert("count".to_string(), serde_json::json!(1));
                    p
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");
        let main = &deployment.spec.template.spec.containers[0];
        let limits = main.resources.as_ref().unwrap().limits.as_ref().unwrap();

        assert_eq!(limits.gpu, Some("1".to_string()));
        assert!(limits.gpu_memory.is_none());
        assert!(limits.gpu_cores.is_none());
    }

    #[test]
    fn gpu_multi_gpu() {
        let mut service = make_service("gpu-app", "default");
        service.spec.workload.resources.insert(
            "my-gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some({
                    let mut p = std::collections::BTreeMap::new();
                    p.insert("count".to_string(), serde_json::json!(4));
                    p
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");
        let main = &deployment.spec.template.spec.containers[0];
        let limits = main.resources.as_ref().unwrap().limits.as_ref().unwrap();

        assert_eq!(limits.gpu, Some("4".to_string()));
    }

    #[test]
    fn gpu_hami_fractional() {
        let mut service = make_service("gpu-app", "default");
        service.spec.workload.resources.insert(
            "my-gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some({
                    let mut p = std::collections::BTreeMap::new();
                    p.insert("count".to_string(), serde_json::json!(1));
                    p.insert("memory".to_string(), serde_json::json!("20Gi"));
                    p.insert("compute".to_string(), serde_json::json!(30));
                    p
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");
        let main = &deployment.spec.template.spec.containers[0];
        let limits = main.resources.as_ref().unwrap().limits.as_ref().unwrap();

        assert_eq!(limits.gpu, Some("1".to_string()));
        assert_eq!(limits.gpu_memory, Some("20480".to_string())); // 20Gi = 20480 MiB
        assert_eq!(limits.gpu_cores, Some("30".to_string()));
    }

    #[test]
    fn gpu_memory_only_no_compute() {
        let mut service = make_service("gpu-app", "default");
        service.spec.workload.resources.insert(
            "my-gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some({
                    let mut p = std::collections::BTreeMap::new();
                    p.insert("count".to_string(), serde_json::json!(1));
                    p.insert("memory".to_string(), serde_json::json!("8Gi"));
                    p
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");
        let main = &deployment.spec.template.spec.containers[0];
        let limits = main.resources.as_ref().unwrap().limits.as_ref().unwrap();

        assert_eq!(limits.gpu, Some("1".to_string()));
        assert_eq!(limits.gpu_memory, Some("8192".to_string()));
        assert!(limits.gpu_cores.is_none());
    }

    #[test]
    fn gpu_toleration_added_by_default() {
        let mut service = make_service("gpu-app", "default");
        service.spec.workload.resources.insert(
            "my-gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some({
                    let mut p = std::collections::BTreeMap::new();
                    p.insert("count".to_string(), serde_json::json!(1));
                    p
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");
        let tolerations = &deployment.spec.template.spec.tolerations;

        assert_eq!(tolerations.len(), 1);
        assert_eq!(tolerations[0].key, Some("nvidia.com/gpu".to_string()));
        assert_eq!(tolerations[0].operator, Some("Exists".to_string()));
        assert_eq!(tolerations[0].effect, Some("NoSchedule".to_string()));
    }

    #[test]
    fn gpu_toleration_disabled() {
        let mut service = make_service("gpu-app", "default");
        service.spec.workload.resources.insert(
            "my-gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some({
                    let mut p = std::collections::BTreeMap::new();
                    p.insert("count".to_string(), serde_json::json!(1));
                    p.insert("tolerations".to_string(), serde_json::json!(false));
                    p
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");
        assert!(deployment.spec.template.spec.tolerations.is_empty());
    }

    #[test]
    fn gpu_model_node_selector() {
        let mut service = make_service("gpu-app", "default");
        service.spec.workload.resources.insert(
            "my-gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some({
                    let mut p = std::collections::BTreeMap::new();
                    p.insert("count".to_string(), serde_json::json!(4));
                    p.insert("model".to_string(), serde_json::json!("H100"));
                    p
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");
        let selector = deployment
            .spec
            .template
            .spec
            .node_selector
            .as_ref()
            .expect("should have node selector");

        assert_eq!(
            selector.get("nvidia.com/gpu.product"),
            Some(&"NVIDIA-H100-80GB-HBM3".to_string())
        );
    }

    #[test]
    fn no_gpu_no_tolerations_or_selector() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");

        assert!(deployment.spec.template.spec.tolerations.is_empty());
        assert!(deployment.spec.template.spec.node_selector.is_none());
    }

    #[test]
    fn gpu_first_container_only() {
        let mut service = make_service("gpu-app", "default");
        // Add a second container (BTreeMap sorts alphabetically: "main" < "sidecar")
        // But "gpu-worker" < "main", so gpu-worker gets idx 0
        service.spec.workload.containers.insert(
            "gpu-worker".to_string(),
            ContainerSpec {
                image: "worker:latest".to_string(),
                ..Default::default()
            },
        );
        service.spec.workload.resources.insert(
            "my-gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some({
                    let mut p = std::collections::BTreeMap::new();
                    p.insert("count".to_string(), serde_json::json!(1));
                    p
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");
        let containers = &deployment.spec.template.spec.containers;

        // First container (alphabetically) gets GPU limits
        let first = containers.iter().find(|c| c.name == "gpu-worker").unwrap();
        let first_limits = first.resources.as_ref().unwrap().limits.as_ref().unwrap();
        assert_eq!(first_limits.gpu, Some("1".to_string()));

        // Second container does NOT get GPU limits
        let second = containers.iter().find(|c| c.name == "main").unwrap();
        assert!(
            second.resources.is_none() || {
                let r = second.resources.as_ref().unwrap();
                r.limits.is_none() || r.limits.as_ref().unwrap().gpu.is_none()
            }
        );
    }

    #[test]
    fn gpu_merge_with_existing_resources() {
        let mut service = make_service("gpu-app", "default");
        service
            .spec
            .workload
            .containers
            .get_mut("main")
            .unwrap()
            .resources = Some(crate::crd::ResourceRequirements {
            requests: Some(crate::crd::ResourceQuantity {
                cpu: Some("2".to_string()),
                memory: Some("8Gi".to_string()),
            }),
            limits: Some(crate::crd::ResourceQuantity {
                cpu: Some("4".to_string()),
                memory: Some("16Gi".to_string()),
            }),
        });
        service.spec.workload.resources.insert(
            "my-gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some({
                    let mut p = std::collections::BTreeMap::new();
                    p.insert("count".to_string(), serde_json::json!(1));
                    p
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");
        let main = &deployment.spec.template.spec.containers[0];
        let limits = main.resources.as_ref().unwrap().limits.as_ref().unwrap();

        // CPU and memory preserved
        assert_eq!(limits.cpu, Some("4".to_string()));
        assert_eq!(limits.memory, Some("16Gi".to_string()));
        // GPU merged alongside
        assert_eq!(limits.gpu, Some("1".to_string()));
    }

    #[test]
    fn gpu_resource_quantity_serialization() {
        let limits = ResourceQuantity {
            cpu: Some("4".to_string()),
            memory: Some("16Gi".to_string()),
            gpu: Some("1".to_string()),
            gpu_memory: Some("8192".to_string()),
            gpu_cores: Some("30".to_string()),
        };

        let json = serde_json::to_value(&limits).unwrap();
        assert_eq!(json["cpu"], "4");
        assert_eq!(json["memory"], "16Gi");
        assert_eq!(json["nvidia.com/gpu"], "1");
        assert_eq!(json["nvidia.com/gpumem"], "8192");
        assert_eq!(json["nvidia.com/gpucores"], "30");
    }

    #[test]
    fn gpu_deployment_has_shm_volume() {
        let mut service = make_service("gpu-app", "default");
        service.spec.workload.resources.insert(
            "my-gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some({
                    let mut p = std::collections::BTreeMap::new();
                    p.insert("count".to_string(), serde_json::json!(1));
                    p
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");

        // Verify dshm volume exists with medium: Memory
        let shm_vol = deployment
            .spec
            .template
            .spec
            .volumes
            .iter()
            .find(|v| v.name == "dshm")
            .expect("should have dshm volume");
        let empty_dir = shm_vol.empty_dir.as_ref().expect("should be emptyDir");
        assert_eq!(empty_dir.medium, Some("Memory".to_string()));

        // Verify first container has /dev/shm mount
        let main = &deployment.spec.template.spec.containers[0];
        let shm_mount = main
            .volume_mounts
            .iter()
            .find(|vm| vm.name == "dshm")
            .expect("should have dshm volume mount");
        assert_eq!(shm_mount.mount_path, "/dev/shm");
    }

    #[test]
    fn gpu_deployment_has_runtime_class() {
        let mut service = make_service("gpu-app", "default");
        service.spec.workload.resources.insert(
            "my-gpu".to_string(),
            ResourceSpec {
                type_: ResourceType::Gpu,
                params: Some({
                    let mut p = std::collections::BTreeMap::new();
                    p.insert("count".to_string(), serde_json::json!(1));
                    p
                }),
                ..Default::default()
            },
        );

        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");

        assert_eq!(
            deployment.spec.template.spec.runtime_class_name,
            Some("nvidia".to_string())
        );
    }

    #[test]
    fn no_gpu_no_shm_or_runtime_class() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");

        // No dshm volume
        assert!(
            !deployment
                .spec
                .template
                .spec
                .volumes
                .iter()
                .any(|v| v.name == "dshm"),
            "non-GPU deployment should not have dshm volume"
        );

        // No runtimeClassName
        assert!(
            deployment.spec.template.spec.runtime_class_name.is_none(),
            "non-GPU deployment should not have runtimeClassName"
        );
    }

    // =========================================================================
    // Story: EnvVar Serialization (literal vs secretKeyRef)
    // =========================================================================

    #[test]
    fn envvar_literal_serializes_with_value() {
        let env = EnvVar::literal("DB_HOST", "postgres.svc");
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json["name"], "DB_HOST");
        assert_eq!(json["value"], "postgres.svc");
        assert!(json.get("valueFrom").is_none());
    }

    #[test]
    fn envvar_secret_ref_serializes_with_value_from() {
        let env = EnvVar::from_secret("DB_PASSWORD", "myapp-db-creds", "password");
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json["name"], "DB_PASSWORD");
        assert!(json.get("value").is_none());
        assert_eq!(json["valueFrom"]["secretKeyRef"]["name"], "myapp-db-creds");
        assert_eq!(json["valueFrom"]["secretKeyRef"]["key"], "password");
    }

    #[test]
    fn envvar_roundtrip() {
        let literal = EnvVar::literal("KEY", "val");
        let json = serde_json::to_string(&literal).unwrap();
        let back: EnvVar = serde_json::from_str(&json).unwrap();
        assert_eq!(back, literal);

        let secret = EnvVar::from_secret("KEY", "secret-name", "key");
        let json = serde_json::to_string(&secret).unwrap();
        let back: EnvVar = serde_json::from_str(&json).unwrap();
        assert_eq!(back, secret);
    }

    // =========================================================================
    // Story: Secret Variable Resolution in Env Vars
    // =========================================================================

    fn make_service_with_secret_vars(
        vars: Vec<(&str, &str)>,
        secret_resource_name: &str,
    ) -> LatticeService {
        let mut variables = BTreeMap::new();
        for (k, v) in vars {
            variables.insert(
                k.to_string(),
                lattice_common::template::TemplateString::from(v),
            );
        }

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "nginx:latest".to_string(),
                variables,
                ..Default::default()
            },
        );

        let mut resources = BTreeMap::new();
        resources.insert(
            secret_resource_name.to_string(),
            crate::crd::ResourceSpec {
                type_: crate::crd::ResourceType::Secret,
                id: Some("vault/path".to_string()),
                ..Default::default()
            },
        );

        LatticeService {
            metadata: kube::api::ObjectMeta {
                name: Some("myapp".to_string()),
                namespace: Some("prod".to_string()),
                ..Default::default()
            },
            spec: crate::crd::LatticeServiceSpec {
                workload: WorkloadSpec {
                    containers,
                    resources,
                    ..Default::default()
                },
                ..Default::default()
            },
            status: None,
        }
    }

    #[test]
    fn story_secret_var_compiles_to_secret_key_ref() {
        let service = make_service_with_secret_vars(
            vec![("DB_PASSWORD", "${secret.db-creds.password}")],
            "db-creds",
        );
        let mut secret_refs = BTreeMap::new();
        secret_refs.insert(
            "db-creds".to_string(),
            SecretRef {
                secret_name: "myapp-db-creds".to_string(),
                remote_key: "database/prod/credentials".to_string(),
                keys: Some(vec!["password".to_string()]),
                store_name: "vault".to_string(),
            },
        );

        let output =
            compile_service_with_secret_refs(&service, &secret_refs).expect("should compile");

        let deployment = output.deployment.expect("should have deployment");
        let env = &deployment.spec.template.spec.containers[0].env;
        let db_pass = env
            .iter()
            .find(|e| e.name == "DB_PASSWORD")
            .expect("should have DB_PASSWORD");
        assert!(db_pass.value.is_none());
        let vf = db_pass.value_from.as_ref().expect("should have valueFrom");
        let skr = vf
            .secret_key_ref
            .as_ref()
            .expect("should have secretKeyRef");
        assert_eq!(skr.name, "myapp-db-creds");
        assert_eq!(skr.key, "password");
    }

    #[test]
    fn story_secret_var_and_secret_key_ref_coexist() {
        let service = make_service_with_secret_vars(
            vec![
                ("DB_HOST", "postgres.svc"),
                ("DB_PASSWORD", "${secret.db-creds.password}"),
            ],
            "db-creds",
        );
        let mut secret_refs = BTreeMap::new();
        secret_refs.insert(
            "db-creds".to_string(),
            SecretRef {
                secret_name: "myapp-db-creds".to_string(),
                remote_key: "database/prod/credentials".to_string(),
                keys: Some(vec!["password".to_string()]),
                store_name: "vault".to_string(),
            },
        );

        let output =
            compile_service_with_secret_refs(&service, &secret_refs).expect("should compile");

        let env = &output.deployment.unwrap().spec.template.spec.containers[0].env;

        // Secret var should be a secretKeyRef
        let pass = env
            .iter()
            .find(|e| e.name == "DB_PASSWORD")
            .expect("DB_PASSWORD");
        assert!(pass.value.is_none());
        assert!(pass.value_from.is_some());
    }

    #[test]
    fn story_secret_var_error_missing_resource() {
        let mut service = make_service_with_secret_vars(
            vec![("SECRET", "${secret.nonexistent.key}")],
            "db-creds",
        );
        service.spec.workload.resources.remove("nonexistent");

        let secret_refs = BTreeMap::new();
        let result = compile_service_with_secret_refs(&service, &secret_refs);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nonexistent"),
            "error should mention the missing resource: {}",
            err
        );
        assert!(
            err.contains("does not exist"),
            "error should say resource doesn't exist: {}",
            err
        );
    }

    #[test]
    fn story_secret_var_error_wrong_type() {
        let mut service = make_service_with_secret_vars(vec![("VAR", "${secret.db.host}")], "db");
        service.spec.workload.resources.get_mut("db").unwrap().type_ =
            crate::crd::ResourceType::Service;

        let secret_refs = BTreeMap::new();
        let result = compile_service_with_secret_refs(&service, &secret_refs);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("service"),
            "error should mention actual type: {}",
            err
        );
        assert!(
            err.contains("not 'secret'"),
            "error should say not secret: {}",
            err
        );
    }

    #[test]
    fn story_secret_var_error_invalid_key() {
        let service = make_service_with_secret_vars(
            vec![("VAR", "${secret.db-creds.nonexistent}")],
            "db-creds",
        );
        let mut secret_refs = BTreeMap::new();
        secret_refs.insert(
            "db-creds".to_string(),
            SecretRef {
                secret_name: "myapp-db-creds".to_string(),
                remote_key: "database/prod/credentials".to_string(),
                keys: Some(vec!["username".to_string(), "password".to_string()]),
                store_name: "vault".to_string(),
            },
        );

        let result = compile_service_with_secret_refs(&service, &secret_refs);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nonexistent"),
            "error should mention the bad key: {}",
            err
        );
    }

    #[test]
    fn story_secret_var_no_explicit_keys_allows_any_key() {
        let service =
            make_service_with_secret_vars(vec![("VAR", "${secret.db-creds.anything}")], "db-creds");
        let mut secret_refs = BTreeMap::new();
        secret_refs.insert(
            "db-creds".to_string(),
            SecretRef {
                secret_name: "myapp-db-creds".to_string(),
                remote_key: "database/prod/credentials".to_string(),
                keys: None,
                store_name: "vault".to_string(),
            },
        );

        let result = compile_service_with_secret_refs(&service, &secret_refs);
        assert!(result.is_ok());
    }

    // =========================================================================
    // Story: imagePullSecrets Resolution
    // =========================================================================

    #[test]
    fn story_image_pull_secrets_resolved_from_secret_refs() {
        let mut service = make_service("myapp", "prod");
        service.spec.runtime.image_pull_secrets = vec!["ghcr-creds".to_string()];
        service.spec.workload.resources.insert(
            "ghcr-creds".to_string(),
            crate::crd::ResourceSpec {
                type_: crate::crd::ResourceType::Secret,
                id: Some("registry/ghcr".to_string()),
                ..Default::default()
            },
        );

        let mut secret_refs = BTreeMap::new();
        secret_refs.insert(
            "ghcr-creds".to_string(),
            SecretRef {
                secret_name: "myapp-ghcr-creds".to_string(),
                remote_key: "registry/ghcr".to_string(),
                keys: None,
                store_name: "vault".to_string(),
            },
        );

        let output =
            compile_service_with_secret_refs(&service, &secret_refs).expect("should compile");

        let ips = &output
            .deployment
            .unwrap()
            .spec
            .template
            .spec
            .image_pull_secrets;
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].name, "myapp-ghcr-creds");
    }

    #[test]
    fn story_image_pull_secrets_error_missing_resource() {
        let mut service = make_service("myapp", "prod");
        service.spec.runtime.image_pull_secrets = vec!["nonexistent".to_string()];

        let secret_refs = BTreeMap::new();
        let result = compile_service_with_secret_refs(&service, &secret_refs);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonexistent"));
    }

    #[test]
    fn story_image_pull_secrets_error_wrong_type() {
        let mut service = make_service("myapp", "prod");
        service.spec.runtime.image_pull_secrets = vec!["db".to_string()];
        service.spec.workload.resources.insert(
            "db".to_string(),
            crate::crd::ResourceSpec {
                type_: crate::crd::ResourceType::Service,
                ..Default::default()
            },
        );

        let secret_refs = BTreeMap::new();
        let result = compile_service_with_secret_refs(&service, &secret_refs);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("service"),
            "should mention actual type: {}",
            err
        );
        assert!(
            err.contains("not 'secret'"),
            "should say not secret: {}",
            err
        );
    }

    #[test]
    fn story_no_image_pull_secrets_by_default() {
        let service = make_service("myapp", "prod");
        let output = compile_service(&service);
        let deployment = output.deployment.unwrap();
        assert!(deployment.spec.template.spec.image_pull_secrets.is_empty());
    }

    #[test]
    fn gpu_resource_quantity_empty_omits_gpu_fields() {
        let limits = ResourceQuantity {
            cpu: Some("1".to_string()),
            memory: Some("1Gi".to_string()),
            ..Default::default()
        };

        let json = serde_json::to_value(&limits).unwrap();
        assert_eq!(json["cpu"], "1");
        assert!(json.get("nvidia.com/gpu").is_none());
        assert!(json.get("nvidia.com/gpumem").is_none());
        assert!(json.get("nvidia.com/gpucores").is_none());
    }
}
