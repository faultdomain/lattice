//! Kubernetes resource types for workload compilation

use std::collections::BTreeMap;

pub use lattice_common::kube_utils::ObjectMeta;
use serde::{Deserialize, Serialize};

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
// Container
// =============================================================================

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
    /// Working directory
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
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

/// Environment variable -- either a literal value or a reference to a secret key
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

// =============================================================================
// Resource requirements
// =============================================================================

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
    /// GPU count (serializes as `volcano.sh/vgpu-number` for Volcano vGPU scheduling)
    #[serde(
        default,
        rename = "volcano.sh/vgpu-number",
        skip_serializing_if = "Option::is_none"
    )]
    pub gpu: Option<String>,
    /// GPU memory in MiB for Volcano vGPU fractional sharing (serializes as `volcano.sh/vgpu-memory`)
    #[serde(
        default,
        rename = "volcano.sh/vgpu-memory",
        skip_serializing_if = "Option::is_none"
    )]
    pub gpu_memory: Option<String>,
    /// GPU compute percentage for Volcano vGPU fractional sharing (serializes as `volcano.sh/vgpu-cores`)
    #[serde(
        default,
        rename = "volcano.sh/vgpu-cores",
        skip_serializing_if = "Option::is_none"
    )]
    pub gpu_cores: Option<String>,
}

impl From<&lattice_common::crd::ResourceQuantity> for ResourceQuantity {
    fn from(rq: &lattice_common::crd::ResourceQuantity) -> Self {
        Self {
            cpu: rq.cpu.clone(),
            memory: rq.memory.clone(),
            ..Default::default()
        }
    }
}

impl From<&lattice_common::crd::ResourceRequirements> for ResourceRequirements {
    fn from(rr: &lattice_common::crd::ResourceRequirements) -> Self {
        Self {
            requests: rr.requests.as_ref().map(ResourceQuantity::from),
            limits: rr.limits.as_ref().map(ResourceQuantity::from),
        }
    }
}

// =============================================================================
// Probes
// =============================================================================

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
    /// Seconds after container start before probes begin
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_delay_seconds: Option<i32>,
    /// Seconds between probe attempts
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period_seconds: Option<i32>,
    /// Seconds before the probe times out
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<i32>,
    /// Consecutive failures before marking unhealthy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_threshold: Option<i32>,
    /// Consecutive successes before marking healthy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success_threshold: Option<i32>,
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

// =============================================================================
// Security context
// =============================================================================

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

// =============================================================================
// Volumes
// =============================================================================

/// PVC volume source (inline definition pending volume module migration)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PvcVolumeSource {
    /// PVC claim name
    pub claim_name: String,
    /// Read only
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
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
    pub persistent_volume_claim: Option<PvcVolumeSource>,
}

impl Volume {
    /// Create a Volume backed by a ConfigMap.
    pub fn from_config_map(name: impl Into<String>, cm_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            config_map: Some(ConfigMapVolumeSource {
                name: cm_name.into(),
            }),
            secret: None,
            empty_dir: None,
            persistent_volume_claim: None,
        }
    }

    /// Create a Volume backed by a Secret.
    pub fn from_secret(name: impl Into<String>, secret_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            config_map: None,
            secret: Some(SecretVolumeSource {
                secret_name: secret_name.into(),
            }),
            empty_dir: None,
            persistent_volume_claim: None,
        }
    }

    /// Create a Volume backed by an emptyDir.
    pub fn from_empty_dir(
        name: impl Into<String>,
        medium: Option<String>,
        size_limit: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            config_map: None,
            secret: None,
            empty_dir: Some(EmptyDirVolumeSource { medium, size_limit }),
            persistent_volume_claim: None,
        }
    }

    /// Create a Volume backed by a PVC.
    pub fn from_pvc(name: impl Into<String>, claim_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            config_map: None,
            secret: None,
            empty_dir: None,
            persistent_volume_claim: Some(PvcVolumeSource {
                claim_name: claim_name.into(),
                read_only: None,
            }),
        }
    }
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

impl VolumeMount {
    /// Create a readonly file mount with a sub_path key
    pub fn readonly_file(
        name: impl Into<String>,
        mount_path: impl Into<String>,
        sub_path: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            mount_path: mount_path.into(),
            sub_path: Some(sub_path.into()),
            read_only: Some(true),
        }
    }
}

// =============================================================================
// Scheduling
// =============================================================================

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

/// Label selector for topology spread constraints
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    /// Match labels
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub match_labels: BTreeMap<String, String>,
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
