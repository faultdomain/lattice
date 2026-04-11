//! Resource dependency types shared across all Lattice workload CRDs.
//!
//! Contains the resource system: `ResourceType`, `ResourceSpec`, `DependencyDirection`,
//! and parameter types for volumes and secrets.

use std::borrow::Cow;
use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// =============================================================================
// Dependency Direction
// =============================================================================

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

// =============================================================================
// Resource Type
// =============================================================================

/// Type of resource dependency
///
/// Built-in types have strong typing; custom types use `Custom(String)` for extensibility.
/// Built-ins always win during deserialization - explicit match before Custom.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum ResourceType {
    /// Internal service (another LatticeService)
    #[default]
    Service,
    /// External service (inline endpoint declaration)
    ExternalService,
    /// Persistent volume (Score-compatible)
    Volume,
    /// Secret from SecretProvider (ESO ExternalSecret)
    Secret,
    /// GPU resource (fractional via Volcano vGPU or full allocation)
    Gpu,
    /// Custom resource type (escape hatch for extensibility)
    /// Validated at parse time: lowercase alphanumeric with hyphens, starts with letter
    Custom(String),
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl JsonSchema for ResourceType {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("ResourceType")
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Resource type: 'service', 'external-service', 'volume', 'secret', 'gpu', or custom type"
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
            Self::Gpu => "gpu",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Returns true if this is an internal service (LatticeService)
    pub fn is_service(&self) -> bool {
        matches!(self, Self::Service)
    }

    /// Returns true if this is an external service
    pub fn is_external_service(&self) -> bool {
        matches!(self, Self::ExternalService)
    }

    /// Returns true if this is a service-like resource type (handles network traffic)
    pub fn is_service_like(&self) -> bool {
        self.is_service() || self.is_external_service()
    }

    /// Returns true if this is a volume resource
    pub fn is_volume(&self) -> bool {
        matches!(self, Self::Volume)
    }

    /// Returns true if this is a secret resource
    pub fn is_secret(&self) -> bool {
        matches!(self, Self::Secret)
    }

    /// Returns true if this is a GPU resource
    pub fn is_gpu(&self) -> bool {
        matches!(self, Self::Gpu)
    }

    /// Returns true if this is a custom resource type
    pub fn is_custom(&self) -> bool {
        matches!(self, Self::Custom(_))
    }
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
            "gpu" => Ok(Self::Gpu),
            _ => {
                crate::crd::validate_dns_label(&s, "resource type")
                    .map_err(serde::de::Error::custom)?;
                Ok(Self::Custom(s))
            }
        }
    }
}

// =============================================================================
// Resource Metadata
// =============================================================================

/// Resource metadata (Score-compatible)
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
pub struct ResourceMetadata {
    /// Annotations for the resource
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

// =============================================================================
// Resource Params (typed per resource type)
// =============================================================================

/// Typed resource parameters, discriminated by `ResourceType`.
///
/// Deserialized from the Score `params` field based on the sibling `type` field
/// in `ResourceSpec`. Each variant carries the strongly-typed parameter struct.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ResourceParams {
    /// No params (service type, inbound-only declarations, etc.)
    #[default]
    None,
    /// Volume provisioning parameters
    Volume(VolumeParams),
    /// Secret store parameters
    Secret(SecretParams),
    /// External service endpoint parameters
    ExternalService(ExternalServiceParams),
    /// GPU allocation parameters
    Gpu(GpuParams),
    /// Custom type parameters (pass-through)
    Custom(BTreeMap<String, serde_json::Value>),
}

impl ResourceParams {
    /// Get typed volume params, if this is a `Volume` variant.
    pub fn as_volume(&self) -> Option<&VolumeParams> {
        match self {
            Self::Volume(p) => Some(p),
            _ => None,
        }
    }

    /// Get typed secret params, if this is a `Secret` variant.
    pub fn as_secret(&self) -> Option<&SecretParams> {
        match self {
            Self::Secret(p) => Some(p),
            _ => None,
        }
    }

    /// Get typed external service params, if this is an `ExternalService` variant.
    pub fn as_external_service(&self) -> Option<&ExternalServiceParams> {
        match self {
            Self::ExternalService(p) => Some(p),
            _ => None,
        }
    }

    /// Get typed GPU params, if this is a `Gpu` variant.
    pub fn as_gpu(&self) -> Option<&GpuParams> {
        match self {
            Self::Gpu(p) => Some(p),
            _ => None,
        }
    }

    /// Returns true if this is `None` (no parameters).
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

impl JsonSchema for ResourceParams {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("ResourceParams")
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "object",
            "description": "Resource parameters, interpreted based on the sibling 'type' field",
            "x-kubernetes-preserve-unknown-fields": true
        })
    }
}

// =============================================================================
// Resource Spec
// =============================================================================

/// Resource dependency specification (Score-compatible with Lattice extensions)
///
/// ## Score Standard Fields
/// - `type`: Resource type (volume, service, etc.)
/// - `class`: Optional specialization
/// - `id`: Resource identifier for sharing across workloads
/// - `metadata`: Annotations and other metadata
/// - `params`: Provisioner-interpreted parameters (typed per resource type)
///
/// ## Lattice Extensions
/// - `direction`: Bilateral agreement direction (inbound/outbound/both)
#[derive(Clone, Debug, Default, Serialize, JsonSchema, PartialEq)]
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

    /// Typed resource parameters, parsed based on `type`.
    ///
    /// Uses `x-kubernetes-preserve-unknown-fields` so Kubernetes won't prune
    /// nested objects (e.g., external service endpoint maps).
    #[serde(default, skip_serializing_if = "ResourceParams::is_none")]
    pub params: ResourceParams,

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
}

/// Custom deserialization for ResourceSpec: reads `type` first, then parses
/// `params` into the correct `ResourceParams` variant with inline validation.
impl<'de> Deserialize<'de> for ResourceSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        /// Raw helper that deserializes params as an untyped Value.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RawResourceSpec {
            #[serde(rename = "type", default)]
            type_: ResourceType,
            #[serde(default)]
            class: Option<String>,
            #[serde(default)]
            id: Option<String>,
            #[serde(default)]
            metadata: Option<ResourceMetadata>,
            #[serde(default)]
            params: Option<serde_json::Value>,
            #[serde(default)]
            direction: DependencyDirection,
            #[serde(default)]
            namespace: Option<String>,
        }

        let raw = RawResourceSpec::deserialize(deserializer)?;

        let params = match raw.params {
            None => match &raw.type_ {
                ResourceType::Volume => ResourceParams::Volume(VolumeParams::default()),
                ResourceType::Gpu => {
                    return Err(serde::de::Error::custom(
                        "gpu resource requires 'params' with 'count'",
                    ));
                }
                ResourceType::Secret => {
                    return Err(serde::de::Error::custom(
                        "secret resource requires 'params' with 'provider'",
                    ));
                }
                ResourceType::ExternalService => ResourceParams::None,
                _ => ResourceParams::None,
            },
            Some(value) => match &raw.type_ {
                ResourceType::Volume => {
                    let p: VolumeParams = serde_json::from_value(value).map_err(|e| {
                        serde::de::Error::custom(format!("invalid volume params: {e}"))
                    })?;
                    ResourceParams::Volume(p)
                }
                ResourceType::Secret => {
                    let p: SecretParams = serde_json::from_value(value).map_err(|e| {
                        serde::de::Error::custom(format!("invalid secret params: {e}"))
                    })?;
                    if p.provider.is_empty() {
                        return Err(serde::de::Error::custom(
                            "secret resource requires 'provider' in params",
                        ));
                    }
                    if let Some(ref interval) = p.refresh_interval {
                        validate_duration_string(interval).map_err(|e| {
                            serde::de::Error::custom(format!(
                                "secret resource refresh_interval '{}': {}",
                                interval, e
                            ))
                        })?;
                    }
                    if let Some(ref secret_type) = p.secret_type {
                        const VALID_SECRET_TYPES: &[&str] = &[
                            "Opaque",
                            crate::SECRET_TYPE_TLS,
                            crate::SECRET_TYPE_DOCKERCONFIG,
                            "kubernetes.io/dockercfg",
                            "kubernetes.io/basic-auth",
                            "kubernetes.io/ssh-auth",
                            crate::SECRET_TYPE_SA_TOKEN,
                            "bootstrap.kubernetes.io/token",
                        ];
                        if !VALID_SECRET_TYPES.contains(&secret_type.as_str()) {
                            return Err(serde::de::Error::custom(format!(
                                "secret resource secret_type '{}' is not a recognized K8s secret type \
                                 (valid: {})",
                                secret_type,
                                VALID_SECRET_TYPES.join(", ")
                            )));
                        }
                    }
                    ResourceParams::Secret(p)
                }
                ResourceType::ExternalService => {
                    let p: ExternalServiceParams = serde_json::from_value(value).map_err(|e| {
                        serde::de::Error::custom(format!("invalid external service params: {e}"))
                    })?;
                    if p.endpoints.is_empty() {
                        return Err(serde::de::Error::custom(
                            "external service resource requires at least one endpoint in params",
                        ));
                    }
                    for (name, url) in &p.endpoints {
                        if crate::crd::ParsedEndpoint::parse(url).is_none() {
                            return Err(serde::de::Error::custom(format!(
                                "invalid endpoint URL for '{}': {}",
                                name, url
                            )));
                        }
                    }
                    ResourceParams::ExternalService(p)
                }
                ResourceType::Gpu => {
                    let p: GpuParams = serde_json::from_value(value).map_err(|e| {
                        serde::de::Error::custom(format!("invalid gpu params: {e}"))
                    })?;
                    p.validate().map_err(serde::de::Error::custom)?;
                    ResourceParams::Gpu(p)
                }
                ResourceType::Service => ResourceParams::None,
                ResourceType::Custom(_) => {
                    let map: BTreeMap<String, serde_json::Value> = serde_json::from_value(value)
                        .map_err(|e| {
                            serde::de::Error::custom(format!("invalid custom params: {e}"))
                        })?;
                    ResourceParams::Custom(map)
                }
            },
        };

        Ok(ResourceSpec {
            type_: raw.type_,
            class: raw.class,
            id: raw.id,
            metadata: raw.metadata,
            params,
            direction: raw.direction,
            namespace: raw.namespace,
        })
    }
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

    /// Services allowed to reference this shared volume (owner consent).
    ///
    /// Only meaningful on owned volumes (those with `size`). Format:
    /// - `"service-name"` for same-namespace consumers
    /// - `"namespace/service-name"` for cross-namespace consumers
    ///
    /// Default-deny: if omitted on a shared volume (one with `id`), no consumers
    /// are allowed. Private volumes (no `id`) don't need this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_consumers: Option<Vec<String>>,
}

/// Volume access mode
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
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
/// Secrets are synced from a SecretProvider (Vault) via ESO ExternalSecret.
/// The `id` field on ResourceSpec specifies the Vault path.
///
/// ```yaml
/// resources:
///   db-creds:
///     type: secret
///     id: database/prod/credentials  # Vault path
///     params:
///       provider: vault-prod         # SecretProvider name
///       keys:
///         - username
///         - password
///       refreshInterval: 1h
///   tls-cert:
///     type: secret
///     id: certs/my-service
///     params:
///       provider: vault-prod
///       keys: [tls.crt, tls.key]
///       secretType: kubernetes.io/tls
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretParams {
    /// SecretProvider name (references a ClusterSecretStore)
    pub provider: String,

    /// Specific keys to sync from the secret (optional, syncs all if omitted)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<String>>,

    /// Refresh interval for syncing the secret (e.g., "1h", "30m")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_interval: Option<String>,

    /// K8s Secret type for the synced secret (defaults to Opaque)
    ///
    /// Common values: `kubernetes.io/tls`, `kubernetes.io/dockerconfigjson`,
    /// `kubernetes.io/basic-auth`, `kubernetes.io/ssh-auth`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_type: Option<String>,
}

// =============================================================================
// External Service Resource Configuration (parsed from Score params)
// =============================================================================

/// Parsed external service parameters from Score's generic `params` field
///
/// External services declare their endpoints and resolution strategy inline:
///
/// ```yaml
/// resources:
///   stripe:
///     type: external-service
///     direction: outbound
///     params:
///       endpoints:
///         api: https://api.stripe.com
///       resolution: dns
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalServiceParams {
    /// Named endpoints as URLs (e.g., api: https://api.stripe.com)
    pub endpoints: BTreeMap<String, String>,

    /// How to resolve the external service endpoints (default: dns)
    #[serde(default)]
    pub resolution: crate::crd::Resolution,
}

impl ExternalServiceParams {
    /// Parse all endpoint URLs into named `ParsedEndpoint` values.
    ///
    /// Returns a map of endpoint name → parsed endpoint. URLs are validated
    /// during `external_service_params()`, so this should not drop any entries
    /// for valid specs. Uses `filter_map` defensively.
    pub fn parsed_endpoints(&self) -> BTreeMap<String, crate::crd::ParsedEndpoint> {
        self.endpoints
            .iter()
            .filter_map(|(name, url)| {
                crate::crd::ParsedEndpoint::parse(url).map(|ep| (name.clone(), ep))
            })
            .collect()
    }
}

// =============================================================================
// GPU Resource Configuration (parsed from Score params)
// =============================================================================

/// Parsed GPU parameters from Score's generic `params` field
///
/// GPU becomes a resource type (`type: gpu`) instead of a top-level field.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GpuParams {
    /// Number of GPUs requested (must be > 0)
    pub count: u32,

    /// GPU memory limit (e.g., "20Gi", "512Mi"). Enables Volcano vGPU fractional sharing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,

    /// GPU compute percentage (1-100). Enables Volcano vGPU fractional sharing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute: Option<u32>,

    /// GPU model selector (e.g., "H100", "A100", "L4"). Maps to node selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// Whether to add nvidia.com/gpu toleration (default: true at compile time)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tolerations: Option<bool>,
}

impl GpuParams {
    /// Validate the GPU specification
    pub fn validate(&self) -> Result<(), String> {
        if self.count == 0 {
            return Err("gpu count must be greater than 0".to_string());
        }
        if let Some(compute) = self.compute {
            if compute == 0 || compute > 100 {
                return Err("gpu compute must be between 1 and 100".to_string());
            }
        }
        if let Some(ref memory) = self.memory {
            parse_gpu_memory_mib(memory)?;
        }
        Ok(())
    }

    /// Returns true if Volcano vGPU fractional sharing is needed (memory or compute set)
    pub fn is_fractional(&self) -> bool {
        self.memory.is_some() || self.compute.is_some()
    }

    /// Returns true if this is a dedicated GPU allocation (no fractional fields)
    pub fn is_dedicated(&self) -> bool {
        !self.is_fractional()
    }

    /// Parse the memory field into MiB, if present.
    pub fn memory_mib(&self) -> Option<Result<u64, String>> {
        self.memory.as_ref().map(|m| parse_gpu_memory_mib(m))
    }

    /// Map a short GPU model name to the `nvidia.com/gpu.product` NFD label value.
    pub fn product_label(&self) -> Option<String> {
        self.model
            .as_ref()
            .map(|model| match model.to_uppercase().as_str() {
                "H100" => "NVIDIA-H100-80GB-HBM3".to_string(),
                "H100SXM" => "NVIDIA-H100-80GB-HBM3".to_string(),
                "H100PCIE" => "NVIDIA-H100-PCIe".to_string(),
                "A100" => "NVIDIA-A100-SXM4-80GB".to_string(),
                "A100-80G" => "NVIDIA-A100-SXM4-80GB".to_string(),
                "A100-40G" => "NVIDIA-A100-SXM4-40GB".to_string(),
                "A10G" => "NVIDIA-A10G".to_string(),
                "L40S" => "NVIDIA-L40S".to_string(),
                "L40" => "NVIDIA-L40".to_string(),
                "L4" => "NVIDIA-L4".to_string(),
                "T4" => "NVIDIA-Tesla-T4".to_string(),
                "V100" => "NVIDIA-Tesla-V100-SXM2-16GB".to_string(),
                _ => model.to_string(),
            })
    }

    /// Build a node selector map for GPU model selection.
    pub fn node_selector(&self) -> Option<std::collections::BTreeMap<String, String>> {
        self.product_label().map(|label| {
            let mut selector = std::collections::BTreeMap::new();
            selector.insert("nvidia.com/gpu.product".to_string(), label);
            selector
        })
    }
}

/// Validate a duration string (e.g., "1h", "30m", "15s", "1h30m").
///
/// Accepts Go-style durations used by ESO: combinations of hours (h),
/// minutes (m), and seconds (s) with positive integer values.
fn validate_duration_string(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("duration cannot be empty".to_string());
    }

    let mut remaining = s;
    let mut found_unit = false;

    while !remaining.is_empty() {
        // Parse numeric part
        let num_end = remaining
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(remaining.len());
        if num_end == 0 {
            return Err(format!(
                "expected a number at position {} in '{}'",
                s.len() - remaining.len(),
                s
            ));
        }
        let _num: u64 = remaining[..num_end]
            .parse()
            .map_err(|_| format!("invalid number in duration '{}'", s))?;

        remaining = &remaining[num_end..];

        // Parse unit
        if remaining.is_empty() {
            return Err(format!("missing unit suffix (h/m/s) in duration '{}'", s));
        }
        let unit = remaining.chars().next().expect("checked non-empty above");
        if !matches!(unit, 'h' | 'm' | 's') {
            return Err(format!(
                "invalid duration unit '{}' in '{}' (expected h, m, or s)",
                unit, s
            ));
        }
        remaining = &remaining[1..];
        found_unit = true;
    }

    if !found_unit {
        return Err(format!("no duration units found in '{}'", s));
    }

    Ok(())
}

/// Maximum GPU memory in MiB (1 PiB — no real GPU exceeds this).
const MAX_GPU_MEMORY_MIB: u64 = 1024 * 1024 * 1024; // 1 PiB

/// Parse a GPU memory string into MiB.
///
/// Accepts "20Gi" -> 20480, "512Mi" -> 512, bare number -> MiB.
fn parse_gpu_memory_mib(memory: &str) -> Result<u64, String> {
    let memory = memory.trim();
    let mib = if memory.ends_with("Gi") {
        let num = memory
            .trim_end_matches("Gi")
            .parse::<u64>()
            .map_err(|_| format!("invalid gpu memory: {memory}, use Gi or Mi suffix"))?;
        num.checked_mul(1024).ok_or_else(|| {
            format!("gpu memory overflow: {memory} exceeds maximum representable value")
        })?
    } else if memory.ends_with("Mi") {
        memory
            .trim_end_matches("Mi")
            .parse::<u64>()
            .map_err(|_| format!("invalid gpu memory: {memory}, use Gi or Mi suffix"))?
    } else {
        // Bare number treated as MiB
        memory
            .parse::<u64>()
            .map_err(|_| format!("invalid gpu memory: {memory}, use Gi or Mi suffix"))?
    };

    if mib > MAX_GPU_MEMORY_MIB {
        return Err(format!(
            "gpu memory {memory} ({mib} MiB) exceeds maximum ({MAX_GPU_MEMORY_MIB} MiB)"
        ));
    }

    Ok(mib)
}

// =============================================================================
// ResourceSpec Implementation
// =============================================================================

impl ResourceSpec {
    /// Returns true if this is a volume resource that owns (creates) the PVC
    pub fn is_volume_owner(&self) -> bool {
        self.params
            .as_volume()
            .map(|p| p.size.is_some())
            .unwrap_or(false)
    }

    /// Returns true if this is a volume resource that references a shared PVC
    pub fn is_volume_reference(&self) -> bool {
        self.type_.is_volume()
            && self.id.is_some()
            && self
                .params
                .as_volume()
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

    /// Returns true if this is an inbound resource (policy declaration, not a dependency).
    pub fn is_inbound(&self) -> bool {
        self.direction == DependencyDirection::Inbound
    }

    /// Returns true if this is a wildcard mesh resource (`id: "*"`).
    ///
    /// Wildcard resources are policy declarations meaning "accept from any caller"
    /// and cannot be resolved to template outputs (no service to look up in the graph).
    pub fn is_mesh_wildcard(&self) -> bool {
        self.type_.is_service_like() && self.id.as_deref() == Some("*")
    }

    /// Get the remote key for this secret resource (from the `id` field).
    ///
    /// This is the key/path used to look up the secret in the external store
    /// (e.g., a Vault path, AWS Secrets Manager ARN, GCP secret name).
    pub fn secret_remote_key(&self) -> Option<&str> {
        if !self.type_.is_secret() {
            return None;
        }
        self.id.as_deref()
    }

    /// Create a secret ResourceSpec for testing.
    ///
    /// Shorthand for building a `type: secret` ResourceSpec with the given
    /// remote key and provider. Use in tests only.
    pub fn test_secret(remote_key: &str, provider: &str) -> Self {
        Self {
            type_: ResourceType::Secret,
            id: Some(remote_key.to_string()),
            params: ResourceParams::Secret(SecretParams {
                provider: provider.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Create a secret ResourceSpec for testing with explicit keys.
    pub fn test_secret_with_keys(remote_key: &str, provider: &str, keys: &[&str]) -> Self {
        Self {
            type_: ResourceType::Secret,
            id: Some(remote_key.to_string()),
            params: ResourceParams::Secret(SecretParams {
                provider: provider.to_string(),
                keys: Some(keys.iter().map(|k| k.to_string()).collect()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Get the K8s Secret name that will be created by ESO for this secret resource
    pub fn secret_k8s_name(&self, service_name: &str, resource_name: &str) -> Option<String> {
        if !self.type_.is_secret() {
            return None;
        }
        Some(format!("{}-{}", service_name, resource_name))
    }
}

// =============================================================================
// Container Resource Requirements
// =============================================================================

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

impl ResourceRequirements {
    /// Validate resource requirements
    pub fn validate(&self, container_name: &str) -> Result<(), crate::ValidationError> {
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
    pub fn validate(&self, container_name: &str, field: &str) -> Result<(), crate::ValidationError> {
        if let Some(ref cpu) = self.cpu {
            validate_cpu_quantity(cpu, container_name, field)?;
        }
        if let Some(ref memory) = self.memory {
            validate_memory_quantity(memory, container_name, field)?;
        }
        Ok(())
    }
}

/// Validate CPU quantity format (e.g., "100m", "1", "0.5")
pub(crate) fn validate_cpu_quantity(
    qty: &str,
    container_name: &str,
    field: &str,
) -> Result<(), crate::ValidationError> {
    let is_valid = if let Some(stripped) = qty.strip_suffix('m') {
        stripped.parse::<u64>().is_ok()
    } else {
        qty.parse::<f64>().is_ok()
    };

    if !is_valid {
        return Err(crate::ValidationError::new(format!(
            "container '{}' {}.cpu: invalid quantity '{}' (expected e.g., '100m', '1', '0.5')",
            container_name, field, qty
        )));
    }

    Ok(())
}

/// Validate memory quantity format (e.g., "128Mi", "1Gi", "1000000")
pub(crate) fn validate_memory_quantity(
    qty: &str,
    container_name: &str,
    field: &str,
) -> Result<(), crate::ValidationError> {
    let suffixes = [
        "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "k", "M", "G", "T", "P", "E",
    ];

    let is_valid = if let Some(suffix) = suffixes.iter().find(|s| qty.ends_with(*s)) {
        let prefix = &qty[..qty.len() - suffix.len()];
        prefix.parse::<u64>().is_ok() || prefix.parse::<f64>().is_ok()
    } else {
        qty.parse::<u64>().is_ok()
    };

    if !is_valid {
        return Err(crate::ValidationError::new(format!(
            "container '{}' {}.memory: invalid quantity '{}' (expected e.g., '128Mi', '1Gi')",
            container_name, field, qty
        )));
    }

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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

        let t: ResourceType = serde_json::from_str("\"gpu\"").unwrap();
        assert!(matches!(t, ResourceType::Gpu));
        assert!(!t.is_custom());
    }

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

    #[test]
    fn test_invalid_custom_rejected() {
        assert!(serde_json::from_str::<ResourceType>("\"Postgres\"").is_err());
        assert!(serde_json::from_str::<ResourceType>("\"postgres!\"").is_err());
        assert!(serde_json::from_str::<ResourceType>("\"123db\"").is_err());
        assert!(serde_json::from_str::<ResourceType>("\"\"").is_err());
        assert!(serde_json::from_str::<ResourceType>("\"my_db\"").is_err());
    }

    #[test]
    fn test_resource_type_helper_methods() {
        assert!(ResourceType::Service.is_service_like());
        assert!(ResourceType::ExternalService.is_service_like());
        assert!(!ResourceType::Volume.is_service_like());
        assert!(!ResourceType::Custom("postgres".to_string()).is_service_like());

        assert!(ResourceType::Volume.is_volume());
        assert!(!ResourceType::Service.is_volume());
        assert!(!ResourceType::Gpu.is_volume());
        assert!(!ResourceType::Custom("postgres".to_string()).is_volume());

        assert!(ResourceType::Gpu.is_gpu());
        assert!(!ResourceType::Service.is_gpu());
        assert!(!ResourceType::Volume.is_gpu());

        assert!(!ResourceType::Service.is_custom());
        assert!(!ResourceType::Volume.is_custom());
        assert!(!ResourceType::Gpu.is_custom());
        assert!(ResourceType::Custom("redis".to_string()).is_custom());
    }

    #[test]
    fn test_resource_type_as_str() {
        assert_eq!(ResourceType::Service.as_str(), "service");
        assert_eq!(ResourceType::ExternalService.as_str(), "external-service");
        assert_eq!(ResourceType::Volume.as_str(), "volume");
        assert_eq!(ResourceType::Gpu.as_str(), "gpu");
        assert_eq!(
            ResourceType::Custom("postgres".to_string()).as_str(),
            "postgres"
        );
    }

    #[test]
    fn test_custom_type_serialization() {
        let custom = ResourceType::Custom("postgres".to_string());
        let serialized = serde_json::to_string(&custom).unwrap();
        assert_eq!(serialized, "\"postgres\"");

        let deserialized: ResourceType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, custom);
    }

    #[test]
    fn test_gpu_params_returns_none_for_non_gpu() {
        let resource = ResourceSpec {
            type_: ResourceType::Volume,
            ..Default::default()
        };
        assert!(resource.params.as_gpu().is_none());
    }

    #[test]
    fn test_gpu_params_defaults_without_params() {
        // GPU resource without params should fail deserialization (count is required)
        let json = serde_json::json!({"type": "gpu"});
        let result = serde_json::from_value::<ResourceSpec>(json);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("gpu resource requires 'params'"),
            "error should mention missing params"
        );
    }

    #[test]
    fn test_gpu_type_serialization() {
        let gpu = ResourceType::Gpu;
        let serialized = serde_json::to_string(&gpu).unwrap();
        assert_eq!(serialized, "\"gpu\"");

        let deserialized: ResourceType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, gpu);
    }

    #[test]
    fn test_gpu_params_validation() {
        let params = GpuParams {
            count: 2,
            memory: None,
            compute: None,
            model: Some("H100".to_string()),
            tolerations: None,
        };
        assert!(params.validate().is_ok());
        assert!(params.is_dedicated());
        assert!(!params.is_fractional());
    }

    #[test]
    fn test_gpu_params_validation_zero_count() {
        let params = GpuParams {
            count: 0,
            ..Default::default()
        };
        let err = params.validate().unwrap_err();
        assert!(err.contains("count must be greater than 0"));
    }

    #[test]
    fn test_gpu_params_validation_invalid_compute() {
        let params = GpuParams {
            count: 1,
            compute: Some(0),
            ..Default::default()
        };
        assert!(params.validate().is_err());

        let params = GpuParams {
            count: 1,
            compute: Some(101),
            ..Default::default()
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_gpu_params_fractional_detection() {
        let full = GpuParams {
            count: 1,
            memory: None,
            compute: None,
            model: None,
            tolerations: None,
        };
        assert!(!full.is_fractional());
        assert!(full.is_dedicated());

        let fractional = GpuParams {
            count: 1,
            memory: Some("20Gi".to_string()),
            compute: Some(50),
            model: None,
            tolerations: None,
        };
        assert!(fractional.is_fractional());
        assert!(!fractional.is_dedicated());
    }

    #[test]
    fn test_gpu_params_product_label() {
        let params = GpuParams {
            count: 1,
            model: Some("H100".to_string()),
            ..Default::default()
        };
        assert_eq!(
            params.product_label(),
            Some("NVIDIA-H100-80GB-HBM3".to_string())
        );

        let params = GpuParams {
            count: 1,
            model: Some("L4".to_string()),
            ..Default::default()
        };
        assert_eq!(params.product_label(), Some("NVIDIA-L4".to_string()));

        let params = GpuParams {
            count: 1,
            model: None,
            ..Default::default()
        };
        assert_eq!(params.product_label(), None);
    }

    #[test]
    fn test_gpu_params_node_selector() {
        let params = GpuParams {
            count: 1,
            model: Some("A100".to_string()),
            ..Default::default()
        };
        let selector = params.node_selector().unwrap();
        assert_eq!(
            selector.get("nvidia.com/gpu.product"),
            Some(&"NVIDIA-A100-SXM4-80GB".to_string())
        );

        let params = GpuParams {
            count: 1,
            model: None,
            ..Default::default()
        };
        assert!(params.node_selector().is_none());
    }

    #[test]
    fn test_parse_gpu_memory_gi() {
        assert_eq!(parse_gpu_memory_mib("20Gi").unwrap(), 20480);
        assert_eq!(parse_gpu_memory_mib("1Gi").unwrap(), 1024);
    }

    #[test]
    fn test_parse_gpu_memory_mi() {
        assert_eq!(parse_gpu_memory_mib("512Mi").unwrap(), 512);
        assert_eq!(parse_gpu_memory_mib("8192Mi").unwrap(), 8192);
    }

    #[test]
    fn test_parse_gpu_memory_bare_number() {
        assert_eq!(parse_gpu_memory_mib("1024").unwrap(), 1024);
    }

    #[test]
    fn test_parse_gpu_memory_invalid() {
        assert!(parse_gpu_memory_mib("abc").is_err());
        assert!(parse_gpu_memory_mib("").is_err());
        assert!(parse_gpu_memory_mib("10Xi").is_err());
    }

    #[test]
    fn test_parse_gpu_memory_overflow_rejected() {
        // This would overflow u64 when multiplied by 1024
        assert!(parse_gpu_memory_mib("18014398509481984Gi").is_err());
    }

    #[test]
    fn test_parse_gpu_memory_exceeds_max_rejected() {
        // Valid multiplication but exceeds MAX_GPU_MEMORY_MIB
        assert!(parse_gpu_memory_mib("9999999999Gi").is_err());
    }

    // =========================================================================
    // Duration validation tests
    // =========================================================================

    #[test]
    fn test_valid_duration_strings() {
        assert!(validate_duration_string("1h").is_ok());
        assert!(validate_duration_string("30m").is_ok());
        assert!(validate_duration_string("15s").is_ok());
        assert!(validate_duration_string("1h30m").is_ok());
        assert!(validate_duration_string("2h0m30s").is_ok());
    }

    #[test]
    fn test_invalid_duration_strings() {
        assert!(validate_duration_string("").is_err());
        assert!(validate_duration_string("abc").is_err());
        assert!(validate_duration_string("1x").is_err());
        assert!(validate_duration_string("1").is_err()); // missing unit
        assert!(validate_duration_string("h").is_err()); // missing number
    }

    // =========================================================================
    // Secret params validation tests
    // =========================================================================

    #[test]
    fn test_secret_params_valid_refresh_interval() {
        let json = serde_json::json!({
            "type": "secret",
            "id": "vault/path",
            "params": {"provider": "vault", "refreshInterval": "1h"}
        });
        let resource: ResourceSpec = serde_json::from_value(json).unwrap();
        assert!(resource.params.as_secret().is_some());
    }

    #[test]
    fn test_secret_params_invalid_refresh_interval() {
        let json = serde_json::json!({
            "type": "secret",
            "id": "vault/path",
            "params": {"provider": "vault", "refreshInterval": "not-a-duration"}
        });
        let result = serde_json::from_value::<ResourceSpec>(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("refresh_interval"), "error was: {err}");
    }

    #[test]
    fn test_secret_params_valid_secret_type() {
        let json = serde_json::json!({
            "type": "secret",
            "id": "vault/path",
            "params": {"provider": "vault", "secretType": "kubernetes.io/tls"}
        });
        let resource: ResourceSpec = serde_json::from_value(json).unwrap();
        assert!(resource.params.as_secret().is_some());
    }

    #[test]
    fn test_secret_params_invalid_secret_type() {
        let json = serde_json::json!({
            "type": "secret",
            "id": "vault/path",
            "params": {"provider": "vault", "secretType": "invalid-type"}
        });
        let result = serde_json::from_value::<ResourceSpec>(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not a recognized"), "error was: {err}");
    }

    #[test]
    fn test_resource_params_accessors() {
        let vol = ResourceParams::Volume(VolumeParams::default());
        assert!(vol.as_volume().is_some());
        assert!(vol.as_secret().is_none());
        assert!(vol.as_gpu().is_none());
        assert!(vol.as_external_service().is_none());
        assert!(!vol.is_none());

        let none = ResourceParams::None;
        assert!(none.is_none());
        assert!(none.as_volume().is_none());
    }
}
