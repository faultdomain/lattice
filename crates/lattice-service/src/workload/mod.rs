//! Workload types for Lattice services
//!
//! This module defines Kubernetes workload resource types used by the ServiceCompiler:
//! - Deployment: Container orchestration
//! - Service: Network exposure
//! - ServiceAccount: SPIFFE identity for mTLS
//! - HorizontalPodAutoscaler: Auto-scaling
//! - ConfigMap/Secret: Configuration and secrets
//!
//! For workload generation, use [`crate::compiler::ServiceCompiler`].

pub mod env;
pub mod error;
pub mod files;
pub mod volume;

pub use error::CompilationError;
pub use volume::{
    Affinity, GeneratedVolumes, PersistentVolumeClaim, PodAffinity, PodVolume, PvcVolumeSource,
    VolumeCompiler, VOLUME_OWNER_LABEL_PREFIX,
};

use std::collections::BTreeMap;

use aws_lc_rs::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};

/// Compute a config hash from ConfigMap and Secret data
///
/// This hash is added as a pod annotation to trigger rollouts when config changes.
/// Uses SHA-256 for FIPS compliance.
pub fn compute_config_hash(
    config_map: Option<&ConfigMap>,
    secret: Option<&Secret>,
    files_cm: Option<&ConfigMap>,
    files_secret: Option<&Secret>,
) -> String {
    let mut data = String::new();

    // Hash ConfigMap data
    if let Some(cm) = config_map {
        for (k, v) in &cm.data {
            data.push_str(k);
            data.push('=');
            data.push_str(v);
            data.push('\n');
        }
    }

    // Hash Secret data
    if let Some(s) = secret {
        for (k, v) in &s.string_data {
            data.push_str(k);
            data.push('=');
            data.push_str(v);
            data.push('\n');
        }
    }

    // Hash files ConfigMap
    if let Some(cm) = files_cm {
        for (k, v) in &cm.data {
            data.push_str("file:");
            data.push_str(k);
            data.push('=');
            data.push_str(v);
            data.push('\n');
        }
    }

    // Hash files Secret
    if let Some(s) = files_secret {
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

/// Container spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Container {
    /// Container name
    pub name: String,
    /// Image
    pub image: String,
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

/// Environment variable
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvVar {
    /// Variable name
    pub name: String,
    /// Variable value
    pub value: String,
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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
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
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceQuantity {
    /// CPU
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
    /// Memory
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
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
pub struct EmptyDirVolumeSource {}

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
}

// =============================================================================
// HorizontalPodAutoscaler
// =============================================================================

/// Kubernetes HorizontalPodAutoscaler (v2)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HorizontalPodAutoscaler {
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Metadata
    pub metadata: ObjectMeta,
    /// Spec
    pub spec: HpaSpec,
}

/// HPA spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HpaSpec {
    /// Scale target ref
    pub scale_target_ref: ScaleTargetRef,
    /// Min replicas
    pub min_replicas: u32,
    /// Max replicas
    pub max_replicas: u32,
    /// Metrics
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<MetricSpec>,
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

/// Metric specification
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MetricSpec {
    /// Metric type
    #[serde(rename = "type")]
    pub type_: String,
    /// Resource metric
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceMetricSource>,
}

/// Resource metric source
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceMetricSource {
    /// Resource name (cpu, memory)
    pub name: String,
    /// Target
    pub target: MetricTarget,
}

/// Metric target
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MetricTarget {
    /// Target type
    #[serde(rename = "type")]
    pub type_: String,
    /// Average utilization percentage
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub average_utilization: Option<u32>,
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
    /// Kubernetes HorizontalPodAutoscaler
    pub hpa: Option<HorizontalPodAutoscaler>,
    /// ConfigMap for non-sensitive env vars
    pub env_config_map: Option<ConfigMap>,
    /// Secret for sensitive env vars
    pub env_secret: Option<Secret>,
    /// ConfigMap for file mounts (text content)
    pub files_config_map: Option<ConfigMap>,
    /// Secret for file mounts (binary content)
    pub files_secret: Option<Secret>,
    /// PersistentVolumeClaims for owned volumes
    pub pvcs: Vec<PersistentVolumeClaim>,
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
            && self.hpa.is_none()
            && self.env_config_map.is_none()
            && self.env_secret.is_none()
            && self.files_config_map.is_none()
            && self.files_secret.is_none()
            && self.pvcs.is_empty()
    }
}

// =============================================================================
// Workload Compiler
// =============================================================================

use crate::crd::{DeployStrategy, LatticeService, LatticeServiceSpec, ProviderType};
use crate::mesh;

/// Compiler for generating Kubernetes workload resources from LatticeService
///
/// This compiler generates:
/// - ServiceAccount: For SPIFFE identity (always)
/// - Deployment: Container orchestration (always)
/// - Service: Network exposure (if ports defined)
/// - HPA: Auto-scaling (if max replicas set)
///
/// For webhook-based injection, use [`compile_pod_spec`] to get just the
/// container and volume specifications.
pub struct WorkloadCompiler;

impl WorkloadCompiler {
    /// Compile a LatticeService into workload resources
    ///
    /// # Arguments
    /// * `name` - Service name
    /// * `service` - The LatticeService to compile
    /// * `namespace` - Target namespace (from CRD metadata)
    /// * `volumes` - Pre-compiled volume resources (affinity, labels, etc.)
    /// * `provider_type` - Infrastructure provider for topology-aware scheduling
    pub fn compile(
        name: &str,
        service: &LatticeService,
        namespace: &str,
        volumes: &GeneratedVolumes,
        provider_type: ProviderType,
    ) -> GeneratedWorkloads {
        let mut output = GeneratedWorkloads::new();

        // Always generate ServiceAccount for SPIFFE identity
        output.service_account = Some(Self::compile_service_account(name, namespace));

        // Always generate Deployment (skeleton - webhook fills containers)
        output.deployment = Some(Self::compile_deployment(
            name,
            namespace,
            &service.spec,
            volumes,
            provider_type,
        ));

        // Generate Service if ports are defined
        if service.spec.service.is_some() {
            output.service = Some(Self::compile_service(name, namespace, &service.spec));
        }

        // Generate HPA if max replicas is set
        if service.spec.replicas.max.is_some() {
            output.hpa = Some(Self::compile_hpa(name, namespace, &service.spec));
        }

        output
    }

    /// Compile containers from a LatticeServiceSpec with volume mounts
    fn compile_containers_with_volumes(
        spec: &LatticeServiceSpec,
        volumes: &GeneratedVolumes,
    ) -> Vec<Container> {
        spec.containers
            .iter()
            .map(|(container_name, container_spec)| {
                // NOTE: Template rendering happens before this stage.
                // At compile time, variables still contain unrendered templates.
                // The workload compiler should render these before generating K8s resources.
                let env: Vec<EnvVar> = container_spec
                    .variables
                    .iter()
                    .map(|(k, v)| EnvVar {
                        name: k.clone(),
                        value: v.to_string(),
                    })
                    .collect();

                // Get ports from service spec
                let ports: Vec<ContainerPort> = spec
                    .service
                    .as_ref()
                    .map(|svc| {
                        svc.ports
                            .iter()
                            .map(|(port_name, port_spec)| ContainerPort {
                                name: Some(port_name.clone()),
                                container_port: port_spec.target_port.unwrap_or(port_spec.port),
                                protocol: port_spec.protocol.clone(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // Convert resources
                let resources = container_spec
                    .resources
                    .as_ref()
                    .map(|r| ResourceRequirements {
                        requests: r.requests.as_ref().map(|req| ResourceQuantity {
                            cpu: req.cpu.clone(),
                            memory: req.memory.clone(),
                        }),
                        limits: r.limits.as_ref().map(|lim| ResourceQuantity {
                            cpu: lim.cpu.clone(),
                            memory: lim.memory.clone(),
                        }),
                    });

                // Convert probes using helper
                let liveness_probe = container_spec
                    .liveness_probe
                    .as_ref()
                    .map(Self::compile_probe);
                let readiness_probe = container_spec
                    .readiness_probe
                    .as_ref()
                    .map(Self::compile_probe);
                let startup_probe = container_spec
                    .startup_probe
                    .as_ref()
                    .map(Self::compile_probe);

                // Get volume mounts for this container
                let volume_mounts = volumes
                    .volume_mounts
                    .get(container_name)
                    .cloned()
                    .unwrap_or_default();

                // Compile security context
                let security_context = container_spec
                    .security
                    .as_ref()
                    .and_then(Self::compile_security_context);

                Container {
                    name: container_name.clone(),
                    image: container_spec.image.clone(),
                    command: container_spec.command.clone(),
                    args: container_spec.args.clone(),
                    env,
                    env_from: vec![],
                    ports,
                    resources,
                    liveness_probe,
                    readiness_probe,
                    startup_probe,
                    volume_mounts,
                    security_context,
                }
            })
            .collect()
    }

    /// Compile a Score-compliant Probe to a K8s ProbeSpec
    fn compile_probe(p: &crate::crd::Probe) -> ProbeSpec {
        ProbeSpec {
            http_get: p.http_get.as_ref().map(|h| HttpGetAction {
                path: h.path.clone(),
                port: h.port,
                scheme: h.scheme.clone(),
                host: h.host.clone(),
                http_headers: h.http_headers.as_ref().map(|headers| {
                    headers
                        .iter()
                        .map(|hdr| HttpHeader {
                            name: hdr.name.clone(),
                            value: hdr.value.clone(),
                        })
                        .collect()
                }),
            }),
            exec: p.exec.as_ref().map(|e| ExecAction {
                command: e.command.clone(),
            }),
        }
    }

    /// Compile deployment strategy
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

    /// Compile a CRD SecurityContext to a K8s SecurityContext
    fn compile_security_context(
        security: &crate::crd::SecurityContext,
    ) -> Option<K8sSecurityContext> {
        // Only generate security context if any field is set
        let has_caps = !security.capabilities.is_empty() || security.drop_capabilities.is_some();
        let has_other = security.privileged.is_some()
            || security.read_only_root_filesystem.is_some()
            || security.run_as_non_root.is_some()
            || security.run_as_user.is_some()
            || security.run_as_group.is_some()
            || security.allow_privilege_escalation.is_some();

        if !has_caps && !has_other {
            return None;
        }

        let capabilities = if has_caps {
            Some(Capabilities {
                add: if security.capabilities.is_empty() {
                    None
                } else {
                    Some(security.capabilities.clone())
                },
                // Default: drop ALL capabilities for security when any capability setting is used
                drop: Some(
                    security
                        .drop_capabilities
                        .clone()
                        .unwrap_or_else(|| vec!["ALL".to_string()]),
                ),
            })
        } else {
            None
        };

        Some(K8sSecurityContext {
            capabilities,
            privileged: security.privileged,
            read_only_root_filesystem: security.read_only_root_filesystem,
            run_as_non_root: security.run_as_non_root,
            run_as_user: security.run_as_user,
            run_as_group: security.run_as_group,
            allow_privilege_escalation: security.allow_privilege_escalation,
        })
    }

    /// Compile pod-level security context from sysctls
    fn compile_pod_security_context(spec: &LatticeServiceSpec) -> Option<PodSecurityContext> {
        if spec.sysctls.is_empty() {
            return None;
        }

        Some(PodSecurityContext {
            sysctls: Some(
                spec.sysctls
                    .iter()
                    .map(|(name, value)| Sysctl {
                        name: name.clone(),
                        value: value.clone(),
                    })
                    .collect(),
            ),
        })
    }

    /// Compile sidecars into init containers and regular sidecar containers
    ///
    /// Returns (init_containers, sidecar_containers)
    fn compile_sidecars(
        spec: &LatticeServiceSpec,
        volumes: &GeneratedVolumes,
    ) -> (Vec<Container>, Vec<Container>) {
        let mut init_containers = Vec::new();
        let mut sidecar_containers = Vec::new();

        for (sidecar_name, sidecar_spec) in &spec.sidecars {
            // Build env vars
            let env: Vec<EnvVar> = sidecar_spec
                .variables
                .iter()
                .map(|(k, v)| EnvVar {
                    name: k.clone(),
                    value: v.to_string(),
                })
                .collect();

            // Convert resources
            let resources = sidecar_spec
                .resources
                .as_ref()
                .map(|r| ResourceRequirements {
                    requests: r.requests.as_ref().map(|req| ResourceQuantity {
                        cpu: req.cpu.clone(),
                        memory: req.memory.clone(),
                    }),
                    limits: r.limits.as_ref().map(|lim| ResourceQuantity {
                        cpu: lim.cpu.clone(),
                        memory: lim.memory.clone(),
                    }),
                });

            // Convert probes (only for non-init containers)
            let is_init = sidecar_spec.init.unwrap_or(false);
            let (liveness_probe, readiness_probe, startup_probe) = if is_init {
                (None, None, None)
            } else {
                (
                    sidecar_spec
                        .liveness_probe
                        .as_ref()
                        .map(Self::compile_probe),
                    sidecar_spec
                        .readiness_probe
                        .as_ref()
                        .map(Self::compile_probe),
                    sidecar_spec.startup_probe.as_ref().map(Self::compile_probe),
                )
            };

            // Get volume mounts for this sidecar
            let volume_mounts = volumes
                .volume_mounts
                .get(sidecar_name)
                .cloned()
                .unwrap_or_default();

            // Compile security context
            let security_context = sidecar_spec
                .security
                .as_ref()
                .and_then(Self::compile_security_context);

            let container = Container {
                name: sidecar_name.clone(),
                image: sidecar_spec.image.clone(),
                command: sidecar_spec.command.clone(),
                args: sidecar_spec.args.clone(),
                env,
                env_from: vec![],
                ports: vec![], // Sidecars typically don't expose ports
                resources,
                liveness_probe,
                readiness_probe,
                startup_probe,
                volume_mounts,
                security_context,
            };

            if is_init {
                init_containers.push(container);
            } else {
                sidecar_containers.push(container);
            }
        }

        (init_containers, sidecar_containers)
    }

    fn compile_service_account(name: &str, namespace: &str) -> ServiceAccount {
        ServiceAccount {
            api_version: "v1".to_string(),
            kind: "ServiceAccount".to_string(),
            metadata: ObjectMeta::new(name, namespace),
        }
    }

    /// Compile a complete Deployment from the LatticeService spec.
    ///
    /// Generates a fully-specified Deployment with:
    /// - Containers with image, env vars, ports, probes, volume mounts
    /// - Init containers and sidecars
    /// - Volumes for PVCs
    /// - Pod affinity for RWO volume co-location
    /// - Volume ownership labels
    /// - Pod-level security context (sysctls)
    /// - Topology spread constraints for HA distribution
    fn compile_deployment(
        name: &str,
        namespace: &str,
        spec: &LatticeServiceSpec,
        volumes: &GeneratedVolumes,
        provider_type: ProviderType,
    ) -> Deployment {
        // Compile main containers with volume mounts
        let mut containers = Self::compile_containers_with_volumes(spec, volumes);

        // Compile sidecars (init + regular)
        let (init_containers, sidecar_containers) = Self::compile_sidecars(spec, volumes);

        // Merge sidecar containers with main containers
        containers.extend(sidecar_containers);

        // Build pod labels
        let mut labels = BTreeMap::new();
        labels.insert(lattice_common::LABEL_NAME.to_string(), name.to_string());
        labels.insert(
            lattice_common::LABEL_MANAGED_BY.to_string(),
            lattice_common::LABEL_MANAGED_BY_LATTICE.to_string(),
        );

        // Add volume ownership labels (for RWO affinity)
        for (k, v) in &volumes.pod_labels {
            labels.insert(k.clone(), v.clone());
        }

        // Build pod volumes from PVCs
        let pod_volumes: Vec<Volume> = volumes
            .volumes
            .iter()
            .map(|pv| Volume {
                name: pv.name.clone(),
                config_map: None,
                secret: None,
                empty_dir: None,
                persistent_volume_claim: pv.persistent_volume_claim.clone(),
            })
            .collect();

        let strategy = Self::compile_strategy(spec);

        // Compile pod-level security context
        let security_context = Self::compile_pod_security_context(spec);

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
                        labels,
                        annotations: BTreeMap::new(),
                    },
                    spec: PodSpec {
                        service_account_name: name.to_string(),
                        containers,
                        init_containers,
                        volumes: pod_volumes,
                        affinity: volumes.affinity.clone(),
                        security_context,
                        host_network: spec.host_network,
                        share_process_namespace: spec.share_process_namespace,
                        topology_spread_constraints: vec![TopologySpreadConstraint {
                            max_skew: 1,
                            topology_key: provider_type.topology_spread_key().to_string(),
                            when_unsatisfiable: "ScheduleAnyway".to_string(),
                            label_selector: LabelSelector {
                                match_labels: {
                                    let mut labels = BTreeMap::new();
                                    labels.insert(
                                        lattice_common::LABEL_NAME.to_string(),
                                        name.to_string(),
                                    );
                                    labels
                                },
                            },
                        }],
                    },
                },
                strategy,
            },
        }
    }

    fn compile_service(name: &str, namespace: &str, spec: &LatticeServiceSpec) -> Service {
        let mut selector = BTreeMap::new();
        selector.insert(lattice_common::LABEL_NAME.to_string(), name.to_string());

        let ports: Vec<ServicePort> = spec
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
        let waypoint_name = format!("{}-waypoint", namespace);
        let metadata =
            ObjectMeta::new(name, namespace).with_label(mesh::USE_WAYPOINT_LABEL, waypoint_name);

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

    fn compile_hpa(
        name: &str,
        namespace: &str,
        spec: &LatticeServiceSpec,
    ) -> HorizontalPodAutoscaler {
        HorizontalPodAutoscaler {
            api_version: "autoscaling/v2".to_string(),
            kind: "HorizontalPodAutoscaler".to_string(),
            metadata: ObjectMeta::new(name, namespace),
            spec: HpaSpec {
                scale_target_ref: ScaleTargetRef {
                    api_version: "apps/v1".to_string(),
                    kind: "Deployment".to_string(),
                    name: name.to_string(),
                },
                min_replicas: spec.replicas.min,
                max_replicas: spec.replicas.max.unwrap_or(spec.replicas.min),
                metrics: vec![MetricSpec {
                    type_: "Resource".to_string(),
                    resource: Some(ResourceMetricSource {
                        name: "cpu".to_string(),
                        target: MetricTarget {
                            type_: "Utilization".to_string(),
                            average_utilization: Some(80),
                        },
                    }),
                }],
            },
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{ContainerSpec, DeploySpec, PortSpec, ReplicaSpec, ServicePortsSpec};
    use lattice_common::template::TemplateString;

    /// Helper to compile a service with empty volumes (for basic tests)
    fn compile_service(service: &LatticeService) -> GeneratedWorkloads {
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
        let volumes = VolumeCompiler::compile(name, namespace, &service.spec)
            .expect("test volume compilation should succeed");
        // Use Docker provider for tests (uses hostname-based spreading)
        WorkloadCompiler::compile(name, service, namespace, &volumes, ProviderType::Docker)
    }

    fn make_service(name: &str, namespace: &str) -> LatticeService {
        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "nginx:latest".to_string(),
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
                security: None,
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
                containers,
                resources: BTreeMap::new(),
                service: Some(ServicePortsSpec { ports }),
                replicas: ReplicaSpec { min: 1, max: None },
                deploy: DeploySpec::default(),
                ingress: None,
                sidecars: BTreeMap::new(),
                sysctls: BTreeMap::new(),
                host_network: None,
                share_process_namespace: None,
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
        service.spec.service = None;

        let output = compile_service(&service);
        assert!(output.service.is_none());
    }

    // =========================================================================
    // Story: Generate HPA When Max Replicas Set
    // =========================================================================

    #[test]
    fn story_generates_hpa_with_max_replicas() {
        let mut service = make_service("my-app", "default");
        service.spec.replicas = ReplicaSpec {
            min: 2,
            max: Some(10),
        };

        let output = compile_service(&service);

        let hpa = output.hpa.expect("should have HPA");
        assert_eq!(hpa.metadata.name, "my-app");
        assert_eq!(hpa.api_version, "autoscaling/v2");
        assert_eq!(hpa.spec.min_replicas, 2);
        assert_eq!(hpa.spec.max_replicas, 10);
        assert_eq!(hpa.spec.scale_target_ref.name, "my-app");
        assert_eq!(hpa.spec.scale_target_ref.kind, "Deployment");
    }

    #[test]
    fn story_no_hpa_without_max_replicas() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service);
        assert!(output.hpa.is_none());
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
    fn story_container_environment_variables() {
        let mut service = make_service("my-app", "default");
        let container = service
            .spec
            .containers
            .get_mut("main")
            .expect("main container should exist");
        container
            .variables
            .insert("LOG_LEVEL".to_string(), TemplateString::from("debug"));

        let output = compile_service(&service);
        let deployment = output.deployment.expect("deployment should be set");

        let env = &deployment
            .spec
            .template
            .spec
            .containers
            .iter()
            .find(|c| c.name == "main")
            .expect("main container should exist")
            .env;
        assert!(env
            .iter()
            .any(|e| e.name == "LOG_LEVEL" && e.value == "debug"));
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
        let hash = compute_config_hash(None, None, None, None);
        // Empty data still produces a hash
        assert_eq!(hash.len(), 16); // 8 bytes = 16 hex chars
    }

    #[test]
    fn test_config_hash_with_configmap() {
        let mut cm = ConfigMap::new("test", "default");
        cm.data.insert("KEY".to_string(), "value".to_string());

        let hash1 = compute_config_hash(Some(&cm), None, None, None);
        assert_eq!(hash1.len(), 16);

        // Different value produces different hash
        cm.data.insert("KEY".to_string(), "different".to_string());
        let hash2 = compute_config_hash(Some(&cm), None, None, None);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_config_hash_with_secret() {
        let mut secret = Secret::new("test", "default");
        secret
            .string_data
            .insert("PASSWORD".to_string(), "secret123".to_string());

        let hash = compute_config_hash(None, Some(&secret), None, None);
        assert_eq!(hash.len(), 16);
    }

    #[test]
    fn test_config_hash_deterministic() {
        let mut cm = ConfigMap::new("test", "default");
        cm.data.insert("KEY".to_string(), "value".to_string());

        // Same input produces same hash
        let hash1 = compute_config_hash(Some(&cm), None, None, None);
        let hash2 = compute_config_hash(Some(&cm), None, None, None);
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
            Some(&env_cm),
            Some(&env_secret),
            Some(&files_cm),
            Some(&files_secret),
        );

        // Subset produces different hash
        let hash_partial = compute_config_hash(Some(&env_cm), Some(&env_secret), None, None);

        assert_ne!(hash_all, hash_partial);
    }

    // =========================================================================
    // Story: Security Context Compilation
    // =========================================================================

    #[test]
    fn story_security_context_compilation() {
        use crate::crd::SecurityContext;

        let security = SecurityContext {
            capabilities: vec!["NET_ADMIN".to_string(), "SYS_MODULE".to_string()],
            drop_capabilities: None, // Should default to [ALL]
            privileged: Some(false),
            read_only_root_filesystem: Some(true),
            run_as_non_root: Some(true),
            run_as_user: Some(1000),
            run_as_group: Some(1000),
            allow_privilege_escalation: Some(false),
        };

        let k8s_ctx = WorkloadCompiler::compile_security_context(&security)
            .expect("should produce security context");

        // Check capabilities
        let caps = k8s_ctx.capabilities.expect("should have capabilities");
        assert_eq!(
            caps.add,
            Some(vec!["NET_ADMIN".to_string(), "SYS_MODULE".to_string()])
        );
        assert_eq!(caps.drop, Some(vec!["ALL".to_string()])); // Default drop ALL

        // Check other fields
        assert_eq!(k8s_ctx.privileged, Some(false));
        assert_eq!(k8s_ctx.read_only_root_filesystem, Some(true));
        assert_eq!(k8s_ctx.run_as_non_root, Some(true));
        assert_eq!(k8s_ctx.run_as_user, Some(1000));
        assert_eq!(k8s_ctx.run_as_group, Some(1000));
        assert_eq!(k8s_ctx.allow_privilege_escalation, Some(false));
    }

    #[test]
    fn story_security_context_empty_returns_none() {
        use crate::crd::SecurityContext;

        let security = SecurityContext::default();
        let k8s_ctx = WorkloadCompiler::compile_security_context(&security);
        assert!(k8s_ctx.is_none());
    }

    // =========================================================================
    // Story: Pod Security Context (Sysctls)
    // =========================================================================

    #[test]
    fn story_pod_security_context_sysctls() {
        let mut service = make_service("my-app", "default");
        service.spec.sysctls.insert(
            "net.ipv4.conf.all.src_valid_mark".to_string(),
            "1".to_string(),
        );
        service
            .spec
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
    fn story_empty_sysctls_no_security_context() {
        let service = make_service("my-app", "default");
        let output = compile_service(&service);
        let deployment = output.deployment.expect("should have deployment");

        assert!(deployment.spec.template.spec.security_context.is_none());
    }

    // =========================================================================
    // Story: Init Containers Separated
    // =========================================================================

    #[test]
    fn story_init_containers_separated() {
        use crate::crd::SidecarSpec;

        let mut service = make_service("my-app", "default");
        service.spec.sidecars.insert(
            "init-setup".to_string(),
            SidecarSpec {
                image: "busybox:latest".to_string(),
                command: Some(vec!["sh".to_string(), "-c".to_string()]),
                args: Some(vec!["echo hello".to_string()]),
                variables: BTreeMap::new(),
                resources: None,
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
                init: Some(true),
                security: None,
            },
        );
        service.spec.sidecars.insert(
            "vpn".to_string(),
            SidecarSpec {
                image: "wireguard:latest".to_string(),
                command: None,
                args: None,
                variables: BTreeMap::new(),
                resources: None,
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
                init: Some(false),
                security: None,
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
        service.spec.sidecars.insert(
            "vpn".to_string(),
            SidecarSpec {
                image: "wireguard:latest".to_string(),
                command: None,
                args: None,
                variables: BTreeMap::new(),
                resources: None,
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
                init: None,
                security: Some(SecurityContext {
                    capabilities: vec!["NET_ADMIN".to_string()],
                    ..Default::default()
                }),
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
        service.spec.host_network = Some(true);
        service.spec.share_process_namespace = Some(true);

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
        service.spec.containers.get_mut("main").unwrap().security = Some(SecurityContext {
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
}
