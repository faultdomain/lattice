//! LatticeService Custom Resource Definition
//!
//! The LatticeService CRD represents a workload deployed by Lattice.
//! Services declare their dependencies and allowed callers for automatic
//! network policy generation.
//!
//! ## Score-Compatible Templating
//!
//! The following fields support `${...}` placeholder syntax per the Score spec:
//! - `containers.*.variables.*` - Environment variable values
//! - `containers.*.files.*.content` - Inline file content
//! - `containers.*.files.*.source` - File source path
//! - `containers.*.volumes.*.source` - Volume source reference
//!
//! Use `$${...}` to escape and produce literal `${...}` in output.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::types::{Condition, ServiceRef};
use crate::template::TemplateString;

/// Direction of a service dependency
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DependencyDirection {
    /// This service calls the target (outbound traffic)
    #[default]
    Outbound,
    /// The target calls this service (inbound traffic)
    Inbound,
    /// Bidirectional communication
    Both,
}

impl DependencyDirection {
    /// Returns true if this direction includes outbound traffic
    pub fn is_outbound(&self) -> bool {
        matches!(self, Self::Outbound | Self::Both)
    }

    /// Returns true if this direction includes inbound traffic
    pub fn is_inbound(&self) -> bool {
        matches!(self, Self::Inbound | Self::Both)
    }
}

/// Type of resource dependency
///
/// Built-in types have strong typing; custom types use `Custom(String)` for extensibility.
/// Built-ins always win during deserialization - explicit match before Custom.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum ResourceType {
    /// Internal service (another LatticeService)
    #[default]
    Service,
    /// External service (LatticeExternalService)
    ExternalService,
    /// Persistent volume (Score-compatible)
    Volume,
    /// Secret from SecretsProvider (ESO ExternalSecret)
    Secret,
    /// Custom resource type (escape hatch for extensibility)
    /// Validated at parse time: lowercase alphanumeric with hyphens, starts with letter
    Custom(String),
}

impl JsonSchema for ResourceType {
    fn schema_name() -> String {
        "ResourceType".to_string()
    }

    fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        // Accept any string - built-in values are "service", "external-service", "volume", "secret"
        // Custom types are validated at parse time
        schemars::schema::Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            metadata: Some(Box::new(schemars::schema::Metadata {
                description: Some(
                    "Resource type: 'service', 'external-service', 'volume', 'secret', or custom type"
                        .to_string(),
                ),
                ..Default::default()
            })),
            ..Default::default()
        })
    }
}

impl Serialize for ResourceType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl ResourceType {
    /// Get the string representation of this resource type
    pub fn as_str(&self) -> &str {
        match self {
            Self::Service => "service",
            Self::ExternalService => "external-service",
            Self::Volume => "volume",
            Self::Secret => "secret",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Returns true if this is a service-like resource type (handles network traffic)
    pub fn is_service_like(&self) -> bool {
        matches!(self, Self::Service | Self::ExternalService)
    }

    /// Returns true if this is a volume resource
    pub fn is_volume(&self) -> bool {
        matches!(self, Self::Volume)
    }

    /// Returns true if this is a secret resource
    pub fn is_secret(&self) -> bool {
        matches!(self, Self::Secret)
    }

    /// Returns true if this is a custom resource type
    pub fn is_custom(&self) -> bool {
        matches!(self, Self::Custom(_))
    }
}

/// Validate custom type: lowercase alphanumeric with hyphens, starts with letter
fn validate_custom_type(s: &str) -> Result<(), String> {
    super::validate_dns_identifier(s, true).map_err(|e| e.replace("identifier", "resource type"))
}

impl<'de> Deserialize<'de> for ResourceType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        // Built-ins always win - explicit match before Custom
        match s.as_str() {
            "service" => Ok(Self::Service),
            "external-service" => Ok(Self::ExternalService),
            "volume" => Ok(Self::Volume),
            "secret" => Ok(Self::Secret),
            _ => {
                validate_custom_type(&s).map_err(serde::de::Error::custom)?;
                Ok(Self::Custom(s))
            }
        }
    }
}

/// Resource metadata (Score-compatible)
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ResourceMetadata {
    /// Annotations for the resource
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// Resource dependency specification (Score-compatible with Lattice extensions)
///
/// ## Score Standard Fields
/// - `type`: Resource type (volume, service, etc.)
/// - `class`: Optional specialization
/// - `id`: Resource identifier for sharing across workloads
/// - `metadata`: Annotations and other metadata
/// - `params`: Provisioner-interpreted parameters (generic object)
///
/// ## Lattice Extensions
/// - `direction`: Bilateral agreement direction (inbound/outbound/both)
/// - `inbound`: L7 policies for inbound traffic (rate limiting)
/// - `outbound`: L7 policies for outbound traffic (retries, timeouts)
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceSpec {
    // =========================================================================
    // Score Standard Fields
    // =========================================================================
    /// Type of resource (Score: type)
    #[serde(rename = "type")]
    pub type_: ResourceType,

    /// Optional specialization class (Score: class)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,

    /// Optional identifier for resource sharing (Score: id)
    ///
    /// When two resources share the same type, class, and id, they are
    /// considered the same resource when used across related Workloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Resource metadata (Score: metadata)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ResourceMetadata>,

    /// Provisioner-interpreted parameters (Score: params)
    ///
    /// Generic parameters that Lattice interprets based on resource type:
    /// - volume: size, storageClass, accessMode
    /// - service: (none - uses Lattice extensions)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<BTreeMap<String, serde_json::Value>>,

    // =========================================================================
    // Lattice Extensions (additions to Score, not replacements)
    // =========================================================================
    /// Direction of the dependency (Lattice extension)
    ///
    /// Used for bilateral service mesh agreements:
    /// - outbound: This service calls the target
    /// - inbound: The target calls this service
    /// - both: Bidirectional communication
    #[serde(default)]
    pub direction: DependencyDirection,

    /// Target namespace for cross-namespace dependencies (Lattice extension)
    ///
    /// When omitted, defaults to the same namespace as the owning service.
    /// Use this to reference services in other namespaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// L7 policies for inbound traffic (Lattice extension)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound: Option<InboundPolicy>,

    /// L7 policies for outbound traffic (Lattice extension)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<OutboundPolicy>,
}

/// L7 policies for inbound traffic (Lattice extension)
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InboundPolicy {
    /// Rate limiting configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitConfig>,
}

/// L7 policies for outbound traffic (Lattice extension)
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OutboundPolicy {
    /// Retry configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<RetryConfig>,
    /// Timeout configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<TimeoutConfig>,
}

/// Rate limiting configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitConfig {
    /// Maximum requests per interval
    pub requests_per_interval: u32,
    /// Interval in seconds (default: 60)
    #[serde(default = "default_rate_limit_interval_config")]
    pub interval_seconds: u32,
}

fn default_rate_limit_interval_config() -> u32 {
    60
}

/// Retry configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RetryConfig {
    /// Number of retry attempts
    pub attempts: u32,
    /// Timeout per attempt
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_try_timeout: Option<String>,
    /// Conditions that trigger a retry
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retry_on: Vec<String>,
}

/// Timeout configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TimeoutConfig {
    /// Request timeout
    pub request: String,
}

// =============================================================================
// Volume Resource Configuration (parsed from Score params)
// =============================================================================

/// Parsed volume parameters from Score's generic `params` field
///
/// Volume ownership is determined by the presence of `size`:
/// - With `size`: This service OWNS the volume (creates the PVC)
/// - Without `size`: This service REFERENCES a shared volume
///
/// ```yaml
/// # Owner (has size in params)
/// resources:
///   downloads:
///     type: volume
///     id: media-downloads
///     params:
///       size: 500Gi
///       storageClass: local-path
///
/// # Reference (no params or no size)
/// resources:
///   downloads:
///     type: volume
///     id: media-downloads
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VolumeParams {
    /// Storage size (e.g., "10Gi", "500Gi")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,

    /// Kubernetes storage class name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,

    /// Access mode: ReadWriteOnce (default), ReadWriteMany, ReadOnlyMany
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_mode: Option<VolumeAccessMode>,
}

/// Volume access mode
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum VolumeAccessMode {
    /// Single node read-write (default)
    #[default]
    ReadWriteOnce,
    /// Multi-node read-write (requires RWX-capable storage)
    ReadWriteMany,
    /// Multi-node read-only
    ReadOnlyMany,
}

// =============================================================================
// Secret Resource Configuration (parsed from Score params)
// =============================================================================

/// Parsed secret parameters from Score's generic `params` field
///
/// Secrets are synced from a SecretsProvider (Vault) via ESO ExternalSecret.
/// The `id` field on ResourceSpec specifies the Vault path.
///
/// ```yaml
/// resources:
///   db-creds:
///     type: secret
///     id: database/prod/credentials  # Vault path
///     params:
///       provider: vault-prod         # SecretsProvider name
///       keys:
///         - username
///         - password
///       refreshInterval: 1h
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretParams {
    /// SecretsProvider name (references a ClusterSecretStore)
    pub provider: String,

    /// Specific keys to sync from the secret (optional, syncs all if omitted)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<String>>,

    /// Refresh interval for syncing the secret (e.g., "1h", "30m")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_interval: Option<String>,
}

impl ResourceSpec {
    /// Parse volume params from the generic Score `params` field
    ///
    /// Returns:
    /// - `Ok(None)` if this is not a volume resource
    /// - `Ok(Some(params))` if params parsed successfully (or defaults if missing)
    /// - `Err(msg)` if JSON conversion failed (invalid params structure)
    pub fn volume_params(&self) -> Result<Option<VolumeParams>, String> {
        if !self.type_.is_volume() {
            return Ok(None);
        }
        match &self.params {
            Some(params) => {
                let value = serde_json::to_value(params)
                    .map_err(|e| format!("failed to serialize volume params: {}", e))?;
                let volume_params = serde_json::from_value(value)
                    .map_err(|e| format!("invalid volume params: {}", e))?;
                Ok(Some(volume_params))
            }
            None => Ok(Some(VolumeParams::default())),
        }
    }

    /// Returns true if this is a volume resource that owns (creates) the PVC
    pub fn is_volume_owner(&self) -> bool {
        self.volume_params()
            .ok()
            .flatten()
            .map(|p| p.size.is_some())
            .unwrap_or(false)
    }

    /// Returns true if this is a volume resource that references a shared PVC
    pub fn is_volume_reference(&self) -> bool {
        self.type_.is_volume()
            && self.id.is_some()
            && self
                .volume_params()
                .ok()
                .flatten()
                .map(|p| p.size.is_none())
                .unwrap_or(true)
    }

    /// Get the PVC name for this volume resource
    pub fn volume_pvc_name(&self, service_name: &str, resource_name: &str) -> Option<String> {
        if !self.type_.is_volume() {
            return None;
        }
        Some(match &self.id {
            Some(id) => format!("vol-{id}"),
            None => format!("{service_name}-{resource_name}"),
        })
    }

    /// Returns true if this is a secret resource
    pub fn is_secret(&self) -> bool {
        self.type_.is_secret()
    }

    /// Parse secret params from the generic Score `params` field
    ///
    /// Returns:
    /// - `Ok(None)` if this is not a secret resource
    /// - `Ok(Some(params))` if params parsed successfully
    /// - `Err(msg)` if JSON conversion failed or required fields missing
    pub fn secret_params(&self) -> Result<Option<SecretParams>, String> {
        if !self.type_.is_secret() {
            return Ok(None);
        }
        match &self.params {
            Some(params) => {
                let value = serde_json::to_value(params)
                    .map_err(|e| format!("failed to serialize secret params: {}", e))?;
                let secret_params: SecretParams = serde_json::from_value(value)
                    .map_err(|e| format!("invalid secret params: {}", e))?;

                // Validate provider is specified
                if secret_params.provider.is_empty() {
                    return Err("secret resource requires 'provider' in params".to_string());
                }

                Ok(Some(secret_params))
            }
            None => Err("secret resource requires 'params' with 'provider'".to_string()),
        }
    }

    /// Get the Vault path for this secret resource (from the id field)
    pub fn secret_vault_path(&self) -> Option<&str> {
        if !self.type_.is_secret() {
            return None;
        }
        self.id.as_deref()
    }

    /// Get the K8s Secret name that will be created by ESO for this secret resource
    pub fn secret_k8s_name(&self, service_name: &str, resource_name: &str) -> Option<String> {
        if !self.type_.is_secret() {
            return None;
        }
        Some(format!("{}-{}", service_name, resource_name))
    }
}

/// Container resource limits and requests
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ResourceRequirements {
    /// Resource requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<ResourceQuantity>,

    /// Resource limits
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<ResourceQuantity>,
}

/// Resource quantity for CPU and memory
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ResourceQuantity {
    /// CPU quantity (e.g., "100m", "1")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,

    /// Memory quantity (e.g., "128Mi", "1Gi")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
}

/// HTTP probe configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HttpGetProbe {
    /// Path to probe
    pub path: String,

    /// Port to probe
    pub port: u16,

    /// HTTP scheme (HTTP or HTTPS)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,

    /// Optional host header
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// Optional HTTP headers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_headers: Option<Vec<HttpHeader>>,
}

/// HTTP header for probes
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct HttpHeader {
    /// Header name
    pub name: String,
    /// Header value
    pub value: String,
}

/// Exec probe configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ExecProbe {
    /// Command to execute
    pub command: Vec<String>,
}

/// Probe configuration (liveness or readiness)
///
/// Score-compliant probe specification. Supports HTTP GET and exec probe types.
/// Timing parameters use platform defaults (initialDelaySeconds: 0, periodSeconds: 10).
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Probe {
    /// HTTP GET probe - performs an HTTP GET request
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_get: Option<HttpGetProbe>,

    /// Exec probe - executes a command inside the container
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecProbe>,
}

/// File mount specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FileMount {
    /// Inline file content (UTF-8, supports `${...}` placeholders)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<TemplateString>,

    /// Base64-encoded binary content
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary_content: Option<String>,

    /// Path to content file (supports `${...}` placeholders)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<TemplateString>,

    /// File mode in octal
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// Disable placeholder expansion entirely
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_expand: bool,

    /// Reverse expansion mode for bash scripts: `${...}` stays literal,
    /// `$${...}` expands. Useful when shell variables are more common
    /// than Lattice templates.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reverse_expand: bool,
}

/// Volume mount specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VolumeMount {
    /// External volume reference (supports `${...}` placeholders)
    pub source: TemplateString,

    /// Sub path in the volume
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Mount as read-only
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
}

/// Container security context
///
/// Controls Linux security settings for a container. All fields are optional
/// with secure defaults. Most services never need to set these.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecurityContext {
    /// Linux capabilities to add (e.g., NET_ADMIN, SYS_MODULE)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,

    /// Capabilities to drop (default: [ALL] for security)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drop_capabilities: Option<Vec<String>>,

    /// Run container in privileged mode (strongly discouraged)
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

    /// Allow privilege escalation (setuid binaries)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_privilege_escalation: Option<bool>,
}

/// Sidecar container specification
///
/// Identical to ContainerSpec but with additional sidecar-specific options.
/// Sidecars are infrastructure containers (VPN, logging, metrics) that support
/// the main application containers.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SidecarSpec {
    /// Container image
    pub image: String,

    /// Override container entrypoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,

    /// Override container arguments
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,

    /// Environment variables (values support `${...}` placeholders)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub variables: BTreeMap<String, TemplateString>,

    /// Resource requirements
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,

    /// Files to mount in the container
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, FileMount>,

    /// Volumes to mount
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub volumes: BTreeMap<String, VolumeMount>,

    /// Liveness probe - restarts container when it fails
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness_probe: Option<Probe>,

    /// Readiness probe - removes container from service endpoints when it fails
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_probe: Option<Probe>,

    /// Startup probe - delays liveness/readiness checks until container is ready
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_probe: Option<Probe>,

    /// Run as init container (runs once before main containers)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init: Option<bool>,

    /// Security context for the container
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityContext>,
}

/// Container specification (Score-compatible)
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ContainerSpec {
    /// Container image (use "." for runtime-supplied image via config)
    pub image: String,

    /// Override container entrypoint
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,

    /// Override container arguments
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,

    /// Environment variables (values support `${...}` placeholders)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub variables: BTreeMap<String, TemplateString>,

    /// Resource requirements
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,

    /// Files to mount in the container
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub files: BTreeMap<String, FileMount>,

    /// Volumes to mount
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub volumes: BTreeMap<String, VolumeMount>,

    /// Liveness probe - restarts container when it fails
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness_probe: Option<Probe>,

    /// Readiness probe - removes container from service endpoints when it fails
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness_probe: Option<Probe>,

    /// Startup probe - delays liveness/readiness checks until container is ready
    ///
    /// Useful for slow-starting containers. Liveness and readiness probes
    /// will not run until the startup probe succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_probe: Option<Probe>,

    /// Security context for the container
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityContext>,
}

/// Service port specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PortSpec {
    /// Service port
    pub port: u16,

    /// Target port (defaults to port)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,

    /// Protocol (TCP or UDP)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// Service exposure specification
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ServicePortsSpec {
    /// Named network ports
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ports: BTreeMap<String, PortSpec>,
}

/// Replica scaling specification
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ReplicaSpec {
    /// Minimum replicas
    #[serde(default)]
    pub min: u32,

    /// Maximum replicas
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,
}

impl Default for ReplicaSpec {
    fn default() -> Self {
        Self { min: 1, max: None }
    }
}

/// Deployment strategy
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeployStrategy {
    /// Rolling update strategy
    #[default]
    Rolling,
    /// Canary deployment with progressive traffic shifting
    Canary,
}

/// Canary deployment configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CanarySpec {
    /// Interval between steps
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,

    /// Error threshold before rollback
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u32>,

    /// Maximum traffic weight
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_weight: Option<u32>,

    /// Weight increment per step
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_weight: Option<u32>,
}

/// Deployment specification
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct DeploySpec {
    /// Deployment strategy
    #[serde(default)]
    pub strategy: DeployStrategy,

    /// Canary configuration (only if strategy is canary)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary: Option<CanarySpec>,
}

// =============================================================================
// Ingress Specification (Gateway API)
// =============================================================================

/// Ingress specification for exposing services externally via Gateway API
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IngressSpec {
    /// Hostnames for the ingress (e.g., "api.example.com")
    pub hosts: Vec<String>,

    /// URL paths to route (defaults to ["/"])
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<IngressPath>>,

    /// TLS configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<IngressTls>,

    /// Rate limiting configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitSpec>,

    /// GatewayClass name (default: "eg" for Envoy Gateway)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_class: Option<String>,
}

/// Rate limiting configuration using token bucket algorithm
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitSpec {
    /// Maximum requests per interval
    pub requests_per_interval: u32,

    /// Interval in seconds (default: 60)
    #[serde(default = "default_rate_limit_interval")]
    pub interval_seconds: u32,

    /// Burst capacity (default: same as requests_per_interval)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
}

fn default_rate_limit_interval() -> u32 {
    60
}

/// Path configuration for ingress routing
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IngressPath {
    /// The URL path to match
    pub path: String,

    /// Path match type (PathPrefix or Exact)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_type: Option<PathMatchType>,
}

/// Path match type for Gateway API HTTPRoute
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum PathMatchType {
    /// Exact path match
    Exact,
    /// Prefix-based path match (default)
    #[default]
    PathPrefix,
}

/// TLS configuration for ingress
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IngressTls {
    /// TLS mode: auto (cert-manager) or manual (pre-existing secret)
    #[serde(default)]
    pub mode: TlsMode,

    /// Secret name containing TLS certificate (for manual mode)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,

    /// Cert-manager issuer reference (for auto mode)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_ref: Option<CertIssuerRef>,
}

/// TLS provisioning mode
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Automatic certificate provisioning via cert-manager
    #[default]
    Auto,
    /// Manual certificate management (use pre-existing secret)
    Manual,
}

/// Reference to a cert-manager issuer
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CertIssuerRef {
    /// Name of the issuer
    pub name: String,

    /// Kind of issuer (default: ClusterIssuer)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

// =============================================================================
// Backup Configuration
// =============================================================================

/// Error action for backup hooks
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum HookErrorAction {
    /// Continue backup even if hook fails (default)
    #[default]
    Continue,
    /// Fail the backup if hook fails
    Fail,
}

/// A single backup hook (pre or post)
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupHook {
    /// Hook name (used in Velero annotation suffix)
    pub name: String,

    /// Target container name
    pub container: String,

    /// Command to execute
    pub command: Vec<String>,

    /// Timeout for hook execution (e.g., "600s", "10m")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,

    /// Action on hook failure
    #[serde(default)]
    pub on_error: HookErrorAction,
}

/// Pre and post backup hooks
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct BackupHooksSpec {
    /// Hooks to run before backup
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pre: Vec<BackupHook>,

    /// Hooks to run after backup
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post: Vec<BackupHook>,
}

/// Default volume backup behavior
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum VolumeBackupDefault {
    /// All volumes are backed up unless explicitly excluded (default)
    #[default]
    OptOut,
    /// Only explicitly included volumes are backed up
    OptIn,
}

/// Volume backup configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VolumeBackupSpec {
    /// Volumes to explicitly include in backup
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,

    /// Volumes to explicitly exclude from backup
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,

    /// Default backup policy for volumes not in include/exclude lists
    #[serde(default)]
    pub default_policy: VolumeBackupDefault,
}

/// Service-level backup configuration
///
/// Defines Velero backup hooks and volume backup policies for a service.
/// This spec is shared between `LatticeService.spec.backup` (inline) and
/// `LatticeServicePolicy.spec.backup` (policy overlay).
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ServiceBackupSpec {
    /// Pre/post backup hooks for application-aware backups
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hooks: Option<BackupHooksSpec>,

    /// Volume backup configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<VolumeBackupSpec>,
}

/// Service lifecycle phase
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum ServicePhase {
    /// Service is waiting for configuration
    #[default]
    Pending,
    /// Service manifests are being compiled
    Compiling,
    /// Service is fully operational
    Ready,
    /// Service has encountered an error
    Failed,
}

impl std::fmt::Display for ServicePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Compiling => write!(f, "Compiling"),
            Self::Ready => write!(f, "Ready"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Specification for a LatticeService
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeService",
    plural = "latticeservices",
    shortname = "ls",
    namespaced,
    status = "LatticeServiceStatus",
    printcolumn = r#"{"name":"Strategy","type":"string","jsonPath":".spec.deploy.strategy"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeServiceSpec {
    /// Named container specifications (Score-compatible)
    pub containers: BTreeMap<String, ContainerSpec>,

    /// External dependencies (service, route, postgres, redis, etc.)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resources: BTreeMap<String, ResourceSpec>,

    /// Service port configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<ServicePortsSpec>,

    /// Replica scaling configuration
    #[serde(default)]
    pub replicas: ReplicaSpec,

    /// Deployment strategy configuration
    #[serde(default)]
    pub deploy: DeploySpec,

    /// Ingress configuration for external access via Gateway API
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<IngressSpec>,

    /// Sidecar containers (VPN, logging, metrics, etc.)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sidecars: BTreeMap<String, SidecarSpec>,

    /// Pod-level sysctls (e.g., net.ipv4.conf.all.src_valid_mark)
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sysctls: BTreeMap<String, String>,

    /// Use host network namespace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_network: Option<bool>,

    /// Share PID namespace between containers
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_process_namespace: Option<bool>,

    /// Backup configuration (Velero hooks and volume policies)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<ServiceBackupSpec>,
}

impl LatticeServiceSpec {
    /// Extract all service dependencies (outbound) with namespace resolution
    ///
    /// Returns ServiceRefs for both internal and external services.
    /// If a resource doesn't specify a namespace, it defaults to `own_namespace`.
    pub fn dependencies(&self, own_namespace: &str) -> Vec<ServiceRef> {
        self.resources
            .iter()
            .filter(|(_, spec)| spec.direction.is_outbound() && spec.type_.is_service_like())
            .map(|(name, spec)| {
                let ns = spec.namespace.as_deref().unwrap_or(own_namespace);
                let svc_name = spec.id.as_deref().unwrap_or(name);
                ServiceRef::new(ns, svc_name)
            })
            .collect()
    }

    /// Extract services allowed to call this service (inbound) with namespace resolution
    ///
    /// Returns ServiceRefs for callers. If a resource doesn't specify a namespace,
    /// it defaults to `own_namespace`.
    pub fn allowed_callers(&self, own_namespace: &str) -> Vec<ServiceRef> {
        self.resources
            .iter()
            .filter(|(_, spec)| {
                spec.direction.is_inbound() && matches!(spec.type_, ResourceType::Service)
            })
            .map(|(name, spec)| {
                let ns = spec.namespace.as_deref().unwrap_or(own_namespace);
                let svc_name = spec.id.as_deref().unwrap_or(name);
                ServiceRef::new(ns, svc_name)
            })
            .collect()
    }

    /// Extract external service dependencies with namespace resolution
    pub fn external_dependencies(&self, own_namespace: &str) -> Vec<ServiceRef> {
        self.resources
            .iter()
            .filter(|(_, spec)| {
                spec.direction.is_outbound() && matches!(spec.type_, ResourceType::ExternalService)
            })
            .map(|(name, spec)| {
                let ns = spec.namespace.as_deref().unwrap_or(own_namespace);
                let svc_name = spec.id.as_deref().unwrap_or(name);
                ServiceRef::new(ns, svc_name)
            })
            .collect()
    }

    /// Extract internal service dependencies with namespace resolution
    pub fn internal_dependencies(&self, own_namespace: &str) -> Vec<ServiceRef> {
        self.resources
            .iter()
            .filter(|(_, spec)| {
                spec.direction.is_outbound() && matches!(spec.type_, ResourceType::Service)
            })
            .map(|(name, spec)| {
                let ns = spec.namespace.as_deref().unwrap_or(own_namespace);
                let svc_name = spec.id.as_deref().unwrap_or(name);
                ServiceRef::new(ns, svc_name)
            })
            .collect()
    }

    /// Get shared volume IDs that this service owns (has size defined)
    /// Returns: Vec<(resource_name, volume_id)>
    pub fn owned_volume_ids(&self) -> Vec<(&str, &str)> {
        self.resources
            .iter()
            .filter(|(_, spec)| spec.is_volume_owner() && spec.id.is_some())
            .filter_map(|(name, spec)| spec.id.as_ref().map(|id| (name.as_str(), id.as_str())))
            .collect()
    }

    /// Get shared volume IDs that this service references (no size, just id)
    /// Returns: Vec<(resource_name, volume_id)>
    pub fn referenced_volume_ids(&self) -> Vec<(&str, &str)> {
        self.resources
            .iter()
            .filter(|(_, spec)| spec.is_volume_reference())
            .filter_map(|(name, spec)| spec.id.as_ref().map(|id| (name.as_str(), id.as_str())))
            .collect()
    }

    /// Get the ports this service exposes
    pub fn ports(&self) -> BTreeMap<&str, u16> {
        self.service
            .as_ref()
            .map(|s| {
                s.ports
                    .iter()
                    .map(|(name, spec)| (name.as_str(), spec.port))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the primary container image
    pub fn primary_image(&self) -> Option<&str> {
        self.containers
            .get("main")
            .or_else(|| self.containers.values().next())
            .map(|c| c.image.as_str())
    }

    /// Validate the service specification
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.containers.is_empty() {
            return Err(crate::Error::validation(
                "service must have at least one container",
            ));
        }

        // Validate replica counts
        if let Some(max) = self.replicas.max {
            if self.replicas.min > max {
                return Err(crate::Error::validation(
                    "min replicas cannot exceed max replicas",
                ));
            }
        }

        // Validate containers
        for (name, container) in &self.containers {
            container.validate(name)?;
        }

        // Validate service ports
        if let Some(ref svc) = self.service {
            svc.validate()?;
        }

        Ok(())
    }
}

impl ContainerSpec {
    /// Validate container specification
    pub fn validate(&self, container_name: &str) -> Result<(), crate::Error> {
        // Validate image format
        validate_image(&self.image, container_name)?;

        // Validate resource quantities
        if let Some(ref resources) = self.resources {
            resources.validate(container_name)?;
        }

        // Validate file mount modes
        for (path, file_mount) in &self.files {
            file_mount.validate(container_name, path)?;
        }

        Ok(())
    }
}

impl ResourceRequirements {
    /// Validate resource requirements
    pub fn validate(&self, container_name: &str) -> Result<(), crate::Error> {
        if let Some(ref requests) = self.requests {
            requests.validate(container_name, "requests")?;
        }
        if let Some(ref limits) = self.limits {
            limits.validate(container_name, "limits")?;
        }
        Ok(())
    }
}

impl ResourceQuantity {
    /// Validate resource quantity values
    pub fn validate(&self, container_name: &str, field: &str) -> Result<(), crate::Error> {
        if let Some(ref cpu) = self.cpu {
            validate_cpu_quantity(cpu, container_name, field)?;
        }
        if let Some(ref memory) = self.memory {
            validate_memory_quantity(memory, container_name, field)?;
        }
        Ok(())
    }
}

impl FileMount {
    /// Validate file mount specification
    pub fn validate(&self, container_name: &str, path: &str) -> Result<(), crate::Error> {
        // Validate mode is valid octal
        if let Some(ref mode) = self.mode {
            validate_file_mode(mode, container_name, path)?;
        }

        // Ensure at least one content source is specified
        let has_content =
            self.content.is_some() || self.binary_content.is_some() || self.source.is_some();
        if !has_content {
            return Err(crate::Error::validation(format!(
                "container '{}' file '{}': must specify content, binary_content, or source",
                container_name, path
            )));
        }

        Ok(())
    }
}

impl ServicePortsSpec {
    /// Validate service port specification
    pub fn validate(&self) -> Result<(), crate::Error> {
        let mut seen_ports: std::collections::HashSet<u16> = std::collections::HashSet::new();

        for (name, port_spec) in &self.ports {
            // Validate port is not zero
            if port_spec.port == 0 {
                return Err(crate::Error::validation(format!(
                    "service port '{}': port cannot be 0",
                    name
                )));
            }

            // Validate target_port is not zero
            if let Some(target_port) = port_spec.target_port {
                if target_port == 0 {
                    return Err(crate::Error::validation(format!(
                        "service port '{}': target_port cannot be 0",
                        name
                    )));
                }
            }

            // Check for duplicate port numbers
            if !seen_ports.insert(port_spec.port) {
                return Err(crate::Error::validation(format!(
                    "duplicate service port number: {}",
                    port_spec.port
                )));
            }
        }

        Ok(())
    }
}

/// Validate container image format
///
/// Accepts:
/// - Standard image references: "nginx:latest", "gcr.io/project/image:v1"
/// - Runtime placeholder: "." (Score spec - image supplied via config at render time)
///
/// Note: Per Score spec, `${...}` placeholders are NOT supported in image field.
/// Use "." for runtime-supplied images instead.
fn validate_image(image: &str, container_name: &str) -> Result<(), crate::Error> {
    if image.is_empty() {
        return Err(crate::Error::validation(format!(
            "container '{}': image cannot be empty",
            container_name
        )));
    }

    // "." is the Score placeholder for runtime-supplied image
    if image == "." {
        return Ok(());
    }

    // Basic validation: image must not contain whitespace or control characters
    if image.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(crate::Error::validation(format!(
            "container '{}': image '{}' contains invalid characters",
            container_name, image
        )));
    }

    Ok(())
}

/// Validate CPU quantity format (e.g., "100m", "1", "0.5")
fn validate_cpu_quantity(qty: &str, container_name: &str, field: &str) -> Result<(), crate::Error> {
    // CPU can be: integer, decimal, or integer with 'm' suffix
    let is_valid = if let Some(stripped) = qty.strip_suffix('m') {
        // Millicores: must be integer
        stripped.parse::<u64>().is_ok()
    } else {
        // Cores: can be integer or decimal
        qty.parse::<f64>().is_ok()
    };

    if !is_valid {
        return Err(crate::Error::validation(format!(
            "container '{}' {}.cpu: invalid quantity '{}' (expected e.g., '100m', '1', '0.5')",
            container_name, field, qty
        )));
    }

    Ok(())
}

/// Validate memory quantity format (e.g., "128Mi", "1Gi", "1000000")
fn validate_memory_quantity(
    qty: &str,
    container_name: &str,
    field: &str,
) -> Result<(), crate::Error> {
    // Memory can have these suffixes: Ki, Mi, Gi, Ti, Pi, Ei, k, M, G, T, P, E
    let suffixes = [
        "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "k", "M", "G", "T", "P", "E",
    ];

    let is_valid = if let Some(suffix) = suffixes.iter().find(|s| qty.ends_with(*s)) {
        // Has suffix: prefix must be a number
        let prefix = &qty[..qty.len() - suffix.len()];
        prefix.parse::<u64>().is_ok() || prefix.parse::<f64>().is_ok()
    } else {
        // No suffix: must be integer (bytes)
        qty.parse::<u64>().is_ok()
    };

    if !is_valid {
        return Err(crate::Error::validation(format!(
            "container '{}' {}.memory: invalid quantity '{}' (expected e.g., '128Mi', '1Gi')",
            container_name, field, qty
        )));
    }

    Ok(())
}

/// Validate file mode is valid octal (e.g., "0644", "0755")
fn validate_file_mode(mode: &str, container_name: &str, path: &str) -> Result<(), crate::Error> {
    // Mode should be 3-4 octal digits, optionally prefixed with 0
    let mode_str = mode.strip_prefix('0').unwrap_or(mode);

    if mode_str.len() < 3 || mode_str.len() > 4 {
        return Err(crate::Error::validation(format!(
            "container '{}' file '{}': mode '{}' must be 3-4 octal digits (e.g., '0644')",
            container_name, path, mode
        )));
    }

    if !mode_str.chars().all(|c| ('0'..='7').contains(&c)) {
        return Err(crate::Error::validation(format!(
            "container '{}' file '{}': mode '{}' contains non-octal digits",
            container_name, path, mode
        )));
    }

    Ok(())
}

/// Status for a LatticeService
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeServiceStatus {
    /// Current phase of the service lifecycle
    #[serde(default)]
    pub phase: ServicePhase,

    /// Human-readable message about current state
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Conditions representing the service state
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    /// Last time manifests were compiled
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_compiled_at: Option<DateTime<Utc>>,

    /// Observed generation for optimistic concurrency
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Resolved dependency URLs
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resolved_dependencies: BTreeMap<String, String>,
}

impl LatticeServiceStatus {
    /// Create a new status with the given phase
    pub fn with_phase(phase: ServicePhase) -> Self {
        Self {
            phase,
            ..Default::default()
        }
    }

    /// Set the phase and return self for chaining
    pub fn phase(mut self, phase: ServicePhase) -> Self {
        self.phase = phase;
        self
    }

    /// Set the message and return self for chaining
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    /// Add a condition and return self for chaining
    pub fn condition(mut self, condition: Condition) -> Self {
        self.conditions.retain(|c| c.type_ != condition.type_);
        self.conditions.push(condition);
        self
    }

    /// Set the last compiled timestamp
    pub fn compiled_at(mut self, time: DateTime<Utc>) -> Self {
        self.last_compiled_at = Some(time);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::types::ConditionStatus;

    // =========================================================================
    // Test Fixtures
    // =========================================================================

    fn simple_container() -> ContainerSpec {
        ContainerSpec {
            image: "nginx:latest".to_string(),
            command: None,
            args: None,
            variables: BTreeMap::new(),
            resources: None,
            files: BTreeMap::new(),
            volumes: BTreeMap::new(),
            liveness_probe: None,
            readiness_probe: None,
            startup_probe: None,
            security: None,
        }
    }

    fn sample_service_spec() -> LatticeServiceSpec {
        let mut containers = BTreeMap::new();
        containers.insert("main".to_string(), simple_container());

        LatticeServiceSpec {
            containers,
            resources: BTreeMap::new(),
            service: None,
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
            ingress: None,
            sidecars: BTreeMap::new(),
            sysctls: BTreeMap::new(),
            host_network: None,
            share_process_namespace: None,
            backup: None,
        }
    }

    // =========================================================================
    // Dependency Direction Tests
    // =========================================================================

    #[test]
    fn test_dependency_direction_outbound() {
        let dir = DependencyDirection::Outbound;
        assert!(dir.is_outbound());
        assert!(!dir.is_inbound());
    }

    #[test]
    fn test_dependency_direction_inbound() {
        let dir = DependencyDirection::Inbound;
        assert!(!dir.is_outbound());
        assert!(dir.is_inbound());
    }

    #[test]
    fn test_dependency_direction_both() {
        let dir = DependencyDirection::Both;
        assert!(dir.is_outbound());
        assert!(dir.is_inbound());
    }

    // =========================================================================
    // Dependency Extraction Stories
    // =========================================================================

    /// Story: Service declares outbound dependencies on other services
    #[test]
    fn story_service_declares_outbound_dependencies() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "redis".to_string(),
            ResourceSpec {
                type_: ResourceType::ExternalService,
                direction: DependencyDirection::Outbound,
                id: None,
                class: None,
                metadata: None,
                params: None,
                namespace: None,
                inbound: None,
                outbound: None,
            },
        );
        resources.insert(
            "api-gateway".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                id: None,
                class: None,
                metadata: None,
                params: None,
                namespace: None,
                inbound: None,
                outbound: None,
            },
        );

        let mut spec = sample_service_spec();
        spec.resources = resources;

        let deps = spec.dependencies("test");
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|r| r.name == "redis"));
        assert!(deps.iter().any(|r| r.name == "api-gateway"));
    }

    /// Story: Service declares which callers are allowed
    #[test]
    fn story_service_declares_allowed_callers() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "curl-tester".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Inbound,
                id: None,
                class: None,
                metadata: None,
                params: None,
                namespace: None,
                inbound: None,
                outbound: None,
            },
        );
        resources.insert(
            "frontend".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Inbound,
                id: None,
                class: None,
                metadata: None,
                params: None,
                namespace: None,
                inbound: None,
                outbound: None,
            },
        );

        let mut spec = sample_service_spec();
        spec.resources = resources;

        let callers = spec.allowed_callers("test");
        assert_eq!(callers.len(), 2);
        assert!(callers.iter().any(|r| r.name == "curl-tester"));
        assert!(callers.iter().any(|r| r.name == "frontend"));
    }

    /// Story: Bidirectional relationships are counted in both directions
    #[test]
    fn story_bidirectional_relationships() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "cache".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Both,
                id: None,
                class: None,
                metadata: None,
                params: None,
                namespace: None,
                inbound: None,
                outbound: None,
            },
        );

        let mut spec = sample_service_spec();
        spec.resources = resources;

        // Should appear in both dependencies and allowed_callers
        assert!(spec.dependencies("test").iter().any(|r| r.name == "cache"));
        assert!(spec
            .allowed_callers("test")
            .iter()
            .any(|r| r.name == "cache"));
    }

    /// Story: External services are separated from internal
    #[test]
    fn story_external_vs_internal_dependencies() {
        let mut resources = BTreeMap::new();
        resources.insert(
            "google".to_string(),
            ResourceSpec {
                type_: ResourceType::ExternalService,
                direction: DependencyDirection::Outbound,
                id: None,
                class: None,
                metadata: None,
                params: None,
                namespace: None,
                inbound: None,
                outbound: None,
            },
        );
        resources.insert(
            "backend".to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                id: None,
                class: None,
                metadata: None,
                params: None,
                namespace: None,
                inbound: None,
                outbound: None,
            },
        );

        let mut spec = sample_service_spec();
        spec.resources = resources;

        let external = spec.external_dependencies("test");
        let internal = spec.internal_dependencies("test");

        assert_eq!(external.len(), 1);
        assert_eq!(external[0].name, "google");
        assert_eq!(internal.len(), 1);
        assert_eq!(internal[0].name, "backend");
    }

    // =========================================================================
    // Validation Stories
    // =========================================================================

    /// Story: Valid service passes validation
    #[test]
    fn story_valid_service_passes_validation() {
        let spec = sample_service_spec();
        assert!(spec.validate().is_ok());
    }

    /// Story: Service without containers fails validation
    #[test]
    fn story_service_without_containers_fails() {
        let spec = LatticeServiceSpec {
            containers: BTreeMap::new(),
            resources: BTreeMap::new(),
            service: None,
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
            ingress: None,
            sidecars: BTreeMap::new(),
            sysctls: BTreeMap::new(),
            host_network: None,
            share_process_namespace: None,
            backup: None,
        };

        let result = spec.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least one container"));
    }

    /// Story: Invalid replica configuration fails validation
    #[test]
    fn story_invalid_replicas_fails() {
        let mut spec = sample_service_spec();
        spec.replicas = ReplicaSpec {
            min: 5,
            max: Some(3),
        };

        let result = spec.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("min replicas"));
    }

    // =========================================================================
    // YAML Serialization Stories
    // =========================================================================

    /// Story: User defines simple nginx service
    #[test]
    fn story_yaml_simple_service() {
        let yaml = r#"
containers:
  main:
    image: nginx:latest
service:
  ports:
    http:
      port: 80
replicas:
  min: 1
  max: 3
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("simple service YAML should parse successfully");

        assert_eq!(spec.containers.len(), 1);
        assert_eq!(spec.containers["main"].image, "nginx:latest");
        assert_eq!(spec.replicas.min, 1);
        assert_eq!(spec.replicas.max, Some(3));

        let ports = spec.ports();
        assert_eq!(ports.get("http"), Some(&80));
    }

    /// Story: User defines service with dependencies and callers
    #[test]
    fn story_yaml_service_with_dependencies() {
        let yaml = r#"
containers:
  main:
    image: my-api:v1.0
    variables:
      LOG_LEVEL: info
resources:
  curl-tester:
    type: service
    direction: inbound
  google:
    type: external-service
    direction: outbound
  cache:
    type: service
    direction: both
service:
  ports:
    http:
      port: 8080
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec = serde_json::from_value(value)
            .expect("service with dependencies YAML should parse successfully");

        // Check dependencies
        let deps = spec.dependencies("test");
        assert!(deps.iter().any(|r| r.name == "google"));
        assert!(deps.iter().any(|r| r.name == "cache"));

        // Check allowed callers
        let callers = spec.allowed_callers("test");
        assert!(callers.iter().any(|r| r.name == "curl-tester"));
        assert!(callers.iter().any(|r| r.name == "cache"));

        // Check variables
        assert_eq!(
            spec.containers["main"]
                .variables
                .get("LOG_LEVEL")
                .map(|v| v.as_str()),
            Some("info")
        );
    }

    /// Story: Service with canary deployment
    #[test]
    fn story_yaml_canary_deployment() {
        let yaml = r#"
containers:
  main:
    image: app:v2.0
deploy:
  strategy: canary
  canary:
    interval: "1m"
    threshold: 5
    maxWeight: 50
    stepWeight: 10
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec = serde_json::from_value(value)
            .expect("canary deployment YAML should parse successfully");

        assert_eq!(spec.deploy.strategy, DeployStrategy::Canary);
        let canary = spec.deploy.canary.expect("canary config should be present");
        assert_eq!(canary.interval, Some("1m".to_string()));
        assert_eq!(canary.threshold, Some(5));
        assert_eq!(canary.max_weight, Some(50));
        assert_eq!(canary.step_weight, Some(10));
    }

    /// Story: Spec survives serialization roundtrip
    #[test]
    fn story_spec_survives_yaml_roundtrip() {
        let spec = sample_service_spec();
        let yaml =
            serde_json::to_string(&spec).expect("LatticeServiceSpec serialization should succeed");
        let value = crate::yaml::parse_yaml(&yaml).expect("parse yaml");
        let parsed: LatticeServiceSpec = serde_json::from_value(value)
            .expect("LatticeServiceSpec deserialization should succeed");
        assert_eq!(spec, parsed);
    }

    // =========================================================================
    // Status Builder Stories
    // =========================================================================

    /// Story: Controller builds status fluently
    #[test]
    fn story_controller_builds_status_fluently() {
        let condition = Condition::new(
            "Ready",
            ConditionStatus::True,
            "ServiceReady",
            "All replicas are healthy",
        );

        let status = LatticeServiceStatus::default()
            .phase(ServicePhase::Ready)
            .message("Service is operational")
            .condition(condition)
            .compiled_at(Utc::now());

        assert_eq!(status.phase, ServicePhase::Ready);
        assert_eq!(status.message.as_deref(), Some("Service is operational"));
        assert_eq!(status.conditions.len(), 1);
        assert!(status.last_compiled_at.is_some());
    }

    // =========================================================================
    // Helper Method Tests
    // =========================================================================

    #[test]
    fn test_primary_image() {
        let spec = sample_service_spec();
        assert_eq!(spec.primary_image(), Some("nginx:latest"));
    }

    #[test]
    fn test_primary_image_without_main() {
        let mut containers = BTreeMap::new();
        containers.insert("worker".to_string(), simple_container());

        let spec = LatticeServiceSpec {
            containers,
            resources: BTreeMap::new(),
            service: None,
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
            ingress: None,
            sidecars: BTreeMap::new(),
            sysctls: BTreeMap::new(),
            host_network: None,
            share_process_namespace: None,
            backup: None,
        };

        assert_eq!(spec.primary_image(), Some("nginx:latest"));
    }

    #[test]
    fn test_service_phase_display() {
        assert_eq!(ServicePhase::Pending.to_string(), "Pending");
        assert_eq!(ServicePhase::Compiling.to_string(), "Compiling");
        assert_eq!(ServicePhase::Ready.to_string(), "Ready");
        assert_eq!(ServicePhase::Failed.to_string(), "Failed");
    }

    // =========================================================================
    // Field Validation Tests
    // =========================================================================

    /// Story: Valid CPU quantities pass validation
    #[test]
    fn test_valid_cpu_quantities() {
        assert!(validate_cpu_quantity("100m", "main", "requests").is_ok());
        assert!(validate_cpu_quantity("1", "main", "limits").is_ok());
        assert!(validate_cpu_quantity("0.5", "main", "requests").is_ok());
        assert!(validate_cpu_quantity("2000m", "main", "limits").is_ok());
    }

    /// Story: Invalid CPU quantities fail validation
    #[test]
    fn test_invalid_cpu_quantities() {
        assert!(validate_cpu_quantity("", "main", "requests").is_err());
        assert!(validate_cpu_quantity("abc", "main", "limits").is_err());
        assert!(validate_cpu_quantity("100x", "main", "requests").is_err());
        assert!(validate_cpu_quantity("1.5m", "main", "limits").is_err()); // millicores must be int
    }

    /// Story: Valid memory quantities pass validation
    #[test]
    fn test_valid_memory_quantities() {
        assert!(validate_memory_quantity("128Mi", "main", "requests").is_ok());
        assert!(validate_memory_quantity("1Gi", "main", "limits").is_ok());
        assert!(validate_memory_quantity("1000000", "main", "requests").is_ok()); // bytes
        assert!(validate_memory_quantity("512Ki", "main", "limits").is_ok());
        assert!(validate_memory_quantity("1M", "main", "requests").is_ok());
    }

    /// Story: Invalid memory quantities fail validation
    #[test]
    fn test_invalid_memory_quantities() {
        assert!(validate_memory_quantity("", "main", "requests").is_err());
        assert!(validate_memory_quantity("abc", "main", "limits").is_err());
        assert!(validate_memory_quantity("128Xi", "main", "requests").is_err());
        // invalid suffix
    }

    /// Story: Valid file modes pass validation
    #[test]
    fn test_valid_file_modes() {
        assert!(validate_file_mode("0644", "main", "/etc/config").is_ok());
        assert!(validate_file_mode("0755", "main", "/usr/bin/script").is_ok());
        assert!(validate_file_mode("644", "main", "/etc/config").is_ok()); // without leading 0
        assert!(validate_file_mode("0777", "main", "/tmp/file").is_ok());
    }

    /// Story: Invalid file modes fail validation
    #[test]
    fn test_invalid_file_modes() {
        assert!(validate_file_mode("0999", "main", "/etc/config").is_err()); // 9 is not octal
        assert!(validate_file_mode("abc", "main", "/etc/config").is_err());
        assert!(validate_file_mode("12", "main", "/etc/config").is_err()); // too short
        assert!(validate_file_mode("12345", "main", "/etc/config").is_err()); // too long
    }

    /// Story: Empty image fails validation
    #[test]
    fn test_empty_image_fails() {
        assert!(validate_image("", "main").is_err());
    }

    /// Story: Image with whitespace fails validation
    #[test]
    fn test_image_with_whitespace_fails() {
        assert!(validate_image("nginx latest", "main").is_err());
        assert!(validate_image("nginx\tlatest", "main").is_err());
    }

    /// Story: Valid images pass validation
    #[test]
    fn test_valid_images() {
        assert!(validate_image("nginx:latest", "main").is_ok());
        assert!(validate_image("registry.example.com/app:v1.2.3", "main").is_ok());
        assert!(validate_image("gcr.io/project/image@sha256:abc123", "main").is_ok());
    }

    /// Story: Score "." image placeholder is valid
    #[test]
    fn test_dot_image_placeholder_valid() {
        assert!(validate_image(".", "main").is_ok());
    }

    /// Story: Duplicate service ports fail validation
    #[test]
    fn test_duplicate_service_ports_fail() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 80,
                target_port: None,
                protocol: None,
            },
        );
        ports.insert(
            "http2".to_string(),
            PortSpec {
                port: 80, // duplicate!
                target_port: None,
                protocol: None,
            },
        );

        let svc = ServicePortsSpec { ports };
        assert!(svc.validate().is_err());
    }

    /// Story: Port zero fails validation
    #[test]
    fn test_port_zero_fails() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "http".to_string(),
            PortSpec {
                port: 0,
                target_port: None,
                protocol: None,
            },
        );

        let svc = ServicePortsSpec { ports };
        assert!(svc.validate().is_err());
    }

    /// Story: File mount must have content source
    #[test]
    fn test_file_mount_requires_content() {
        let file = FileMount {
            content: None,
            binary_content: None,
            source: None,
            mode: None,
            no_expand: false,
            reverse_expand: false,
        };
        assert!(file.validate("main", "/etc/config").is_err());

        // With content, it passes
        let file_with_content = FileMount {
            content: Some(TemplateString::from("data")),
            binary_content: None,
            source: None,
            mode: None,
            no_expand: false,
            reverse_expand: false,
        };
        assert!(file_with_content.validate("main", "/etc/config").is_ok());
    }

    // =========================================================================
    // Template String Tests
    // =========================================================================

    /// Story: Environment variables support Score placeholders
    #[test]
    fn test_variables_support_templates() {
        let yaml = r#"
containers:
  main:
    image: app:latest
    variables:
      DB_HOST: "${resources.postgres.host}"
      DB_PORT: "${resources.postgres.port}"
      STATIC: "plain-value"
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec = serde_json::from_value(value)
            .expect("template variables YAML should parse successfully");
        let vars = &spec.containers["main"].variables;

        assert!(vars["DB_HOST"].has_placeholders());
        assert!(vars["DB_PORT"].has_placeholders());
        assert!(!vars["STATIC"].has_placeholders());
    }

    /// Story: File content supports Score placeholders
    #[test]
    fn test_file_content_supports_templates() {
        let yaml = r#"
containers:
  main:
    image: app:latest
    files:
      /etc/config.yaml:
        content: |
          database:
            host: ${resources.db.host}
            port: ${resources.db.port}
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("file content YAML should parse successfully");
        let file = &spec.containers["main"].files["/etc/config.yaml"];

        assert!(file
            .content
            .as_ref()
            .expect("file content should be present")
            .has_placeholders());
    }

    /// Story: Volume source supports Score placeholders
    #[test]
    fn test_volume_source_supports_templates() {
        let yaml = r#"
containers:
  main:
    image: app:latest
    volumes:
      /data:
        source: "${resources.volume.name}"
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("volume source YAML should parse successfully");
        let volume = &spec.containers["main"].volumes["/data"];

        assert!(volume.source.has_placeholders());
    }

    // =========================================================================
    // Probe Tests (Score/K8s compatible)
    // =========================================================================

    /// Story: Full probe configuration with all timing parameters
    #[test]
    fn test_probe_with_timing_parameters() {
        // Score-compliant probe: only httpGet, no timing fields
        let yaml = r#"
containers:
  main:
    image: app:latest
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("probe YAML should parse successfully");
        let probe = spec.containers["main"]
            .liveness_probe
            .as_ref()
            .expect("liveness probe should be present");

        let http = probe
            .http_get
            .as_ref()
            .expect("HTTP probe should be configured");
        assert_eq!(http.path, "/healthz");
        assert_eq!(http.port, 8080);
    }

    /// Story: HTTP probe with all Score options (scheme, host, headers)
    #[test]
    fn test_http_probe_full() {
        let yaml = r#"
containers:
  main:
    image: app:latest
    readinessProbe:
      httpGet:
        path: /ready
        port: 8080
        scheme: HTTPS
        host: localhost
        httpHeaders:
          - name: X-Custom-Header
            value: test-value
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("probe YAML should parse successfully");
        let probe = spec.containers["main"]
            .readiness_probe
            .as_ref()
            .expect("readiness probe should be present");

        let http = probe
            .http_get
            .as_ref()
            .expect("HTTP probe should be configured");
        assert_eq!(http.path, "/ready");
        assert_eq!(http.port, 8080);
        assert_eq!(http.scheme, Some("HTTPS".to_string()));
        assert_eq!(http.host, Some("localhost".to_string()));
        assert!(http.http_headers.is_some());
    }

    /// Story: Exec probe with command (Score-compliant)
    #[test]
    fn test_exec_probe() {
        let yaml = r#"
containers:
  main:
    image: app:latest
    livenessProbe:
      exec:
        command:
          - cat
          - /tmp/healthy
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("exec probe YAML should parse successfully");
        let probe = spec.containers["main"]
            .liveness_probe
            .as_ref()
            .expect("liveness probe should be present");

        let exec = probe
            .exec
            .as_ref()
            .expect("exec probe should be configured");
        assert_eq!(exec.command, vec!["cat", "/tmp/healthy"]);
    }

    /// Story: Image "." placeholder parses correctly
    #[test]
    fn test_image_dot_placeholder_yaml() {
        let yaml = r#"
containers:
  main:
    image: "."
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec = serde_json::from_value(value)
            .expect("image dot placeholder YAML should parse successfully");
        assert_eq!(spec.containers["main"].image, ".");
        assert!(spec.validate().is_ok());
    }

    // =========================================================================
    // Volume Ownership Tests
    // =========================================================================

    fn service_with_owned_volume(id: &str, size: &str) -> LatticeServiceSpec {
        let mut spec = sample_service_spec();
        spec.resources.insert(
            "data".to_string(),
            ResourceSpec {
                type_: ResourceType::Volume,
                direction: DependencyDirection::default(),
                id: Some(id.to_string()),
                class: None,
                metadata: None,
                params: Some(BTreeMap::from([(
                    "size".to_string(),
                    serde_json::json!(size),
                )])),
                namespace: None,
                inbound: None,
                outbound: None,
            },
        );
        spec
    }

    fn service_with_volume_reference(id: &str) -> LatticeServiceSpec {
        let mut spec = sample_service_spec();
        spec.resources.insert(
            "data".to_string(),
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
        spec
    }

    #[test]
    fn test_volume_owner_detection() {
        let spec = service_with_owned_volume("shared-data", "10Gi");
        let owned = spec.owned_volume_ids();
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0], ("data", "shared-data"));
    }

    #[test]
    fn test_volume_reference_detection() {
        let spec = service_with_volume_reference("shared-data");
        let refs = spec.referenced_volume_ids();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], ("data", "shared-data"));
    }

    // =========================================================================
    // Score Compatibility Tests
    // =========================================================================

    /// Story: Score-compatible params field parses for volumes
    #[test]
    fn test_score_compatible_volume_params() {
        let yaml = r#"
containers:
  main:
    image: jellyfin/jellyfin:latest
resources:
  config:
    type: volume
    params:
      size: 10Gi
      storageClass: local-path
  media:
    type: volume
    id: media-library
    params:
      size: 1Ti
      storageClass: local-path
      accessMode: ReadWriteOnce
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Score-compatible YAML should parse");

        // Verify config volume
        let config = spec.resources.get("config").expect("config should exist");
        assert!(config.is_volume_owner());
        let config_params = config
            .volume_params()
            .expect("config volume params")
            .expect("should have params");
        assert_eq!(config_params.size, Some("10Gi".to_string()));
        assert_eq!(config_params.storage_class, Some("local-path".to_string()));

        // Verify media volume with id
        let media = spec.resources.get("media").expect("media should exist");
        assert!(media.is_volume_owner());
        assert_eq!(media.id, Some("media-library".to_string()));
        let media_params = media
            .volume_params()
            .expect("media volume params")
            .expect("should have params");
        assert_eq!(media_params.size, Some("1Ti".to_string()));
        assert_eq!(
            media_params.access_mode,
            Some(VolumeAccessMode::ReadWriteOnce)
        );
    }

    /// Story: Score-compatible volume reference (no params)
    #[test]
    fn test_score_compatible_volume_reference() {
        let yaml = r#"
containers:
  main:
    image: sonarr:latest
resources:
  media:
    type: volume
    id: media-library
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Volume reference YAML should parse");

        let media = spec.resources.get("media").expect("media should exist");
        assert!(!media.is_volume_owner()); // No params means not an owner
        assert!(media.is_volume_reference()); // Has id but no size
        assert_eq!(media.id, Some("media-library".to_string()));
    }

    /// Story: Lattice extensions for bilateral agreements with L7 policies
    #[test]
    fn test_lattice_bilateral_agreement_extensions() {
        let yaml = r#"
containers:
  main:
    image: jellyfin/jellyfin:latest
resources:
  sonarr:
    type: service
    direction: inbound
    inbound:
      rateLimit:
        requestsPerInterval: 100
        intervalSeconds: 60
  nzbget:
    type: service
    direction: outbound
    outbound:
      retries:
        attempts: 3
        perTryTimeout: 5s
        retryOn:
          - 5xx
          - connect-failure
      timeout:
        request: 30s
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Bilateral agreement YAML should parse");

        // Verify inbound policy
        let sonarr = spec.resources.get("sonarr").expect("sonarr should exist");
        assert_eq!(sonarr.direction, DependencyDirection::Inbound);
        let inbound = sonarr
            .inbound
            .as_ref()
            .expect("inbound policy should exist");
        let rate_limit = inbound
            .rate_limit
            .as_ref()
            .expect("rate limit should exist");
        assert_eq!(rate_limit.requests_per_interval, 100);
        assert_eq!(rate_limit.interval_seconds, 60);

        // Verify outbound policy
        let nzbget = spec.resources.get("nzbget").expect("nzbget should exist");
        assert_eq!(nzbget.direction, DependencyDirection::Outbound);
        let outbound = nzbget
            .outbound
            .as_ref()
            .expect("outbound policy should exist");
        let retries = outbound.retries.as_ref().expect("retries should exist");
        assert_eq!(retries.attempts, 3);
        assert_eq!(retries.per_try_timeout, Some("5s".to_string()));
        assert_eq!(retries.retry_on, vec!["5xx", "connect-failure"]);
        let timeout = outbound.timeout.as_ref().expect("timeout should exist");
        assert_eq!(timeout.request, "30s");
    }

    /// Story: Full media-server jellyfin-style spec parses correctly
    #[test]
    fn test_media_server_style_spec() {
        let yaml = r#"
containers:
  main:
    image: jellyfin/jellyfin:latest
    variables:
      JELLYFIN_PublishedServerUrl: "http://jellyfin.media.svc.cluster.local:8096"
    volumes:
      /config:
        source: ${resources.config}
      /media:
        source: ${resources.media}
    resources:
      requests:
        cpu: 500m
        memory: 1Gi
      limits:
        cpu: 4000m
        memory: 8Gi
    readinessProbe:
      httpGet:
        path: /health
        port: 8096
      initialDelaySeconds: 30
service:
  ports:
    http:
      port: 8096
      protocol: TCP
resources:
  config:
    type: volume
    params:
      size: 10Gi
      storageClass: local-path
  media:
    type: volume
    id: media-library
    params:
      size: 1Ti
      storageClass: local-path
      accessMode: ReadWriteOnce
  sonarr:
    type: service
    direction: inbound
    inbound:
      rateLimit:
        requestsPerInterval: 100
        intervalSeconds: 60
ingress:
  hosts:
    - jellyfin.home.local
  tls:
    mode: auto
    issuerRef:
      name: letsencrypt-prod
replicas:
  min: 1
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Media server YAML should parse");

        // Verify containers
        assert_eq!(spec.containers.len(), 1);
        let main = spec.containers.get("main").expect("main container");
        assert_eq!(main.image, "jellyfin/jellyfin:latest");
        assert!(!main.volumes.is_empty());

        // Verify resources
        assert_eq!(spec.resources.len(), 3);
        assert!(spec
            .resources
            .get("config")
            .expect("config")
            .is_volume_owner());
        assert!(spec
            .resources
            .get("media")
            .expect("media")
            .is_volume_owner());

        // Verify service
        let service = spec.service.as_ref().expect("service should exist");
        assert!(service.ports.contains_key("http"));

        // Verify ingress
        let ingress = spec.ingress.as_ref().expect("ingress should exist");
        assert_eq!(ingress.hosts, vec!["jellyfin.home.local"]);

        // Validate the spec
        spec.validate().expect("spec should be valid");
    }

    // =========================================================================
    // ResourceType Custom Variant Tests
    // =========================================================================

    /// Story: Built-in types always win during deserialization
    #[test]
    fn test_builtin_type_not_custom() {
        let t: ResourceType = serde_json::from_str("\"service\"").unwrap();
        assert!(matches!(t, ResourceType::Service));
        assert!(!t.is_custom());

        let t: ResourceType = serde_json::from_str("\"external-service\"").unwrap();
        assert!(matches!(t, ResourceType::ExternalService));
        assert!(!t.is_custom());

        let t: ResourceType = serde_json::from_str("\"volume\"").unwrap();
        assert!(matches!(t, ResourceType::Volume));
        assert!(!t.is_custom());
    }

    /// Story: Valid custom types are accepted
    #[test]
    fn test_valid_custom_accepted() {
        let t: ResourceType = serde_json::from_str("\"postgres\"").unwrap();
        assert!(matches!(t, ResourceType::Custom(ref s) if s == "postgres"));
        assert!(t.is_custom());

        let t: ResourceType = serde_json::from_str("\"my-custom-db\"").unwrap();
        assert!(matches!(t, ResourceType::Custom(ref s) if s == "my-custom-db"));

        let t: ResourceType = serde_json::from_str("\"redis123\"").unwrap();
        assert!(matches!(t, ResourceType::Custom(ref s) if s == "redis123"));
    }

    /// Story: Invalid custom types are rejected
    #[test]
    fn test_invalid_custom_rejected() {
        // Uppercase - rejected
        assert!(serde_json::from_str::<ResourceType>("\"Postgres\"").is_err());

        // Special chars - rejected
        assert!(serde_json::from_str::<ResourceType>("\"postgres!\"").is_err());

        // Starts with number - rejected
        assert!(serde_json::from_str::<ResourceType>("\"123db\"").is_err());

        // Empty - rejected
        assert!(serde_json::from_str::<ResourceType>("\"\"").is_err());

        // Underscore - rejected (only hyphens allowed)
        assert!(serde_json::from_str::<ResourceType>("\"my_db\"").is_err());
    }

    /// Story: ResourceType helper methods work correctly
    #[test]
    fn test_resource_type_helper_methods() {
        // is_service_like
        assert!(ResourceType::Service.is_service_like());
        assert!(ResourceType::ExternalService.is_service_like());
        assert!(!ResourceType::Volume.is_service_like());
        assert!(!ResourceType::Custom("postgres".to_string()).is_service_like());

        // is_volume
        assert!(ResourceType::Volume.is_volume());
        assert!(!ResourceType::Service.is_volume());
        assert!(!ResourceType::Custom("postgres".to_string()).is_volume());

        // is_custom
        assert!(!ResourceType::Service.is_custom());
        assert!(!ResourceType::Volume.is_custom());
        assert!(ResourceType::Custom("redis".to_string()).is_custom());
    }

    /// Story: ResourceType as_str returns correct values
    #[test]
    fn test_resource_type_as_str() {
        assert_eq!(ResourceType::Service.as_str(), "service");
        assert_eq!(ResourceType::ExternalService.as_str(), "external-service");
        assert_eq!(ResourceType::Volume.as_str(), "volume");
        assert_eq!(
            ResourceType::Custom("postgres".to_string()).as_str(),
            "postgres"
        );
    }

    /// Story: Custom types serialize correctly
    #[test]
    fn test_custom_type_serialization() {
        let custom = ResourceType::Custom("postgres".to_string());
        let serialized = serde_json::to_string(&custom).unwrap();
        assert_eq!(serialized, "\"postgres\"");

        // Round-trip
        let deserialized: ResourceType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, custom);
    }

    /// Story: Custom type in YAML spec parses correctly
    #[test]
    fn test_custom_type_in_yaml_spec() {
        let yaml = r#"
containers:
  main:
    image: myapp:latest
resources:
  my-postgres:
    type: postgres
    params:
      size: 10Gi
      version: "15"
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Custom resource type in YAML should parse");

        let resource = spec
            .resources
            .get("my-postgres")
            .expect("my-postgres should exist");
        assert!(matches!(resource.type_, ResourceType::Custom(ref s) if s == "postgres"));
    }

    // =========================================================================
    // Security Context Tests
    // =========================================================================

    /// Story: SecurityContext parses from YAML with all fields
    #[test]
    fn story_security_context_parses() {
        let yaml = r#"
containers:
  main:
    image: myapp:latest
    security:
      capabilities: [NET_ADMIN, SYS_MODULE]
      dropCapabilities: [ALL]
      privileged: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
      runAsGroup: 1000
      allowPrivilegeEscalation: false
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Security context YAML should parse");

        let security = spec.containers["main"]
            .security
            .as_ref()
            .expect("security should be present");
        assert_eq!(security.capabilities, vec!["NET_ADMIN", "SYS_MODULE"]);
        assert_eq!(security.drop_capabilities, Some(vec!["ALL".to_string()]));
        assert_eq!(security.privileged, Some(false));
        assert_eq!(security.read_only_root_filesystem, Some(true));
        assert_eq!(security.run_as_non_root, Some(true));
        assert_eq!(security.run_as_user, Some(1000));
        assert_eq!(security.run_as_group, Some(1000));
        assert_eq!(security.allow_privilege_escalation, Some(false));
    }

    /// Story: SecurityContext with only capabilities
    #[test]
    fn story_security_context_minimal() {
        let yaml = r#"
containers:
  main:
    image: myapp:latest
    security:
      capabilities: [NET_BIND_SERVICE]
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Minimal security context should parse");

        let security = spec.containers["main"]
            .security
            .as_ref()
            .expect("security should be present");
        assert_eq!(security.capabilities, vec!["NET_BIND_SERVICE"]);
        assert!(security.drop_capabilities.is_none());
        assert!(security.privileged.is_none());
    }

    // =========================================================================
    // Sidecar Tests
    // =========================================================================

    /// Story: Sidecars parse with init flag
    #[test]
    fn story_sidecars_parse_with_init_flag() {
        let yaml = r#"
containers:
  main:
    image: myapp:latest
sidecars:
  setup:
    image: busybox:latest
    init: true
    command: ["sh", "-c"]
    args: ["chown -R 1000:1000 /data"]
    security:
      runAsUser: 0
  vpn:
    image: wireguard:latest
    init: false
    security:
      capabilities: [NET_ADMIN]
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Sidecar YAML should parse");

        assert_eq!(spec.sidecars.len(), 2);

        let setup = spec.sidecars.get("setup").expect("setup should exist");
        assert_eq!(setup.image, "busybox:latest");
        assert_eq!(setup.init, Some(true));
        assert_eq!(
            setup.security.as_ref().map(|s| s.run_as_user),
            Some(Some(0))
        );

        let vpn = spec.sidecars.get("vpn").expect("vpn should exist");
        assert_eq!(vpn.image, "wireguard:latest");
        assert_eq!(vpn.init, Some(false));
        assert_eq!(
            vpn.security.as_ref().map(|s| s.capabilities.clone()),
            Some(vec!["NET_ADMIN".to_string()])
        );
    }

    /// Story: Sidecar with all fields parses
    #[test]
    fn story_sidecar_full_spec() {
        let yaml = r#"
containers:
  main:
    image: myapp:latest
sidecars:
  logging:
    image: fluent-bit:latest
    command: ["/fluent-bit/bin/fluent-bit"]
    args: ["-c", "/config/fluent-bit.conf"]
    variables:
      LOG_LEVEL: info
    resources:
      requests:
        cpu: 50m
        memory: 64Mi
    readinessProbe:
      httpGet:
        path: /health
        port: 2020
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Full sidecar spec should parse");

        let logging = spec.sidecars.get("logging").expect("logging should exist");
        assert_eq!(logging.image, "fluent-bit:latest");
        assert!(logging.command.is_some());
        assert!(logging.args.is_some());
        assert!(!logging.variables.is_empty());
        assert!(logging.resources.is_some());
        assert!(logging.readiness_probe.is_some());
    }

    // =========================================================================
    // Pod-Level Settings Tests
    // =========================================================================

    /// Story: Sysctls parse correctly
    #[test]
    fn story_pod_level_settings_parse() {
        let yaml = r#"
containers:
  main:
    image: myapp:latest
sysctls:
  net.ipv4.conf.all.src_valid_mark: "1"
  net.core.somaxconn: "65535"
hostNetwork: true
shareProcessNamespace: true
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Pod-level settings should parse");

        assert_eq!(spec.sysctls.len(), 2);
        assert_eq!(
            spec.sysctls.get("net.ipv4.conf.all.src_valid_mark"),
            Some(&"1".to_string())
        );
        assert_eq!(
            spec.sysctls.get("net.core.somaxconn"),
            Some(&"65535".to_string())
        );
        assert_eq!(spec.host_network, Some(true));
        assert_eq!(spec.share_process_namespace, Some(true));
    }

    /// Story: VPN killswitch example parses (full nzbget spec)
    #[test]
    fn story_vpn_killswitch_example() {
        let yaml = r#"
containers:
  main:
    image: linuxserver/nzbget:latest
    variables:
      PUID: "1000"
sysctls:
  net.ipv4.conf.all.src_valid_mark: "1"
sidecars:
  vpn:
    image: linuxserver/wireguard:latest
    security:
      capabilities: [NET_ADMIN, SYS_MODULE]
service:
  ports:
    http:
      port: 6789
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("VPN killswitch example should parse");

        // Verify main container
        assert!(spec.containers.contains_key("main"));

        // Verify sysctl
        assert!(spec
            .sysctls
            .contains_key("net.ipv4.conf.all.src_valid_mark"));

        // Verify VPN sidecar
        let vpn = spec.sidecars.get("vpn").expect("vpn sidecar should exist");
        let caps = &vpn
            .security
            .as_ref()
            .expect("security should be set")
            .capabilities;
        assert!(caps.contains(&"NET_ADMIN".to_string()));
        assert!(caps.contains(&"SYS_MODULE".to_string()));
    }

    /// Story: Empty sidecars and sysctls are allowed
    #[test]
    fn story_empty_sidecars_and_sysctls() {
        let yaml = r#"
containers:
  main:
    image: myapp:latest
"#;
        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("Spec without sidecars should parse");

        assert!(spec.sidecars.is_empty());
        assert!(spec.sysctls.is_empty());
        assert!(spec.host_network.is_none());
        assert!(spec.share_process_namespace.is_none());
    }

    // =========================================================================
    // Backup Configuration Tests
    // =========================================================================

    #[test]
    fn test_service_backup_spec_roundtrip() {
        let yaml = r#"
containers:
  main:
    image: postgres:16
backup:
  hooks:
    pre:
      - name: freeze-db
        container: main
        command: ["/bin/sh", "-c", "pg_dump -U postgres mydb -Fc -f /backup/dump.sql"]
        timeout: "600s"
        onError: Fail
    post:
      - name: cleanup
        container: main
        command: ["/bin/sh", "-c", "rm -f /backup/dump.sql"]
  volumes:
    include: [data, wal]
    exclude: [tmp]
    defaultPolicy: opt-in
"#;

        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec =
            serde_json::from_value(value).expect("should parse spec with backup");
        let backup = spec.backup.expect("should have backup spec");

        let hooks = backup.hooks.expect("should have hooks");
        assert_eq!(hooks.pre.len(), 1);
        assert_eq!(hooks.pre[0].name, "freeze-db");
        assert_eq!(hooks.pre[0].container, "main");
        assert_eq!(hooks.pre[0].timeout, Some("600s".to_string()));
        assert!(matches!(hooks.pre[0].on_error, HookErrorAction::Fail));

        assert_eq!(hooks.post.len(), 1);
        assert_eq!(hooks.post[0].name, "cleanup");

        let volumes = backup.volumes.expect("should have volume spec");
        assert_eq!(volumes.include, vec!["data", "wal"]);
        assert_eq!(volumes.exclude, vec!["tmp"]);
        assert!(matches!(volumes.default_policy, VolumeBackupDefault::OptIn));
    }

    #[test]
    fn test_service_backup_defaults() {
        let yaml = r#"
containers:
  main:
    image: nginx:latest
backup:
  hooks:
    pre:
      - name: sync
        container: main
        command: ["/bin/sh", "-c", "sync"]
"#;

        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec = serde_json::from_value(value).expect("should parse spec");
        let backup = spec.backup.expect("should have backup");
        let hooks = backup.hooks.expect("should have hooks");

        // Default onError is Continue
        assert!(matches!(hooks.pre[0].on_error, HookErrorAction::Continue));
        assert!(hooks.pre[0].timeout.is_none());
        assert!(hooks.post.is_empty());

        // Default volume policy is opt-out
        assert!(backup.volumes.is_none());
    }

    #[test]
    fn test_service_without_backup() {
        let yaml = r#"
containers:
  main:
    image: nginx:latest
"#;

        let value = crate::yaml::parse_yaml(yaml).expect("parse yaml");
        let spec: LatticeServiceSpec = serde_json::from_value(value).expect("should parse spec");
        assert!(spec.backup.is_none());
    }

    #[test]
    fn test_hook_error_action_serde() {
        assert_eq!(
            serde_json::to_string(&HookErrorAction::Continue).unwrap(),
            r#""Continue""#
        );
        assert_eq!(
            serde_json::to_string(&HookErrorAction::Fail).unwrap(),
            r#""Fail""#
        );
    }

    #[test]
    fn test_volume_backup_default_serde() {
        assert_eq!(
            serde_json::to_string(&VolumeBackupDefault::OptOut).unwrap(),
            r#""opt-out""#
        );
        assert_eq!(
            serde_json::to_string(&VolumeBackupDefault::OptIn).unwrap(),
            r#""opt-in""#
        );
    }
}
