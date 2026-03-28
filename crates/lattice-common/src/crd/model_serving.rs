//! LatticeModel CRD types
//!
//! Defines `LatticeModel` — model serving workloads backed by Volcano ModelServing.
//! Each model contains named roles (e.g. prefill, decode), each with its own `WorkloadSpec`.

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::observability::{MetricsSnapshot, ObservabilitySpec};
use super::workload::cost::CostEstimate;
use super::workload::ingress::IngressTls;
use super::workload::scaling::AutoscalingMetric;
use super::workload::spec::{RuntimeSpec, WorkloadSpec};
use super::workload::topology::WorkloadNetworkTopology;

// =============================================================================
// Phase
// =============================================================================

/// Lifecycle phase of a LatticeModel serving workload
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[non_exhaustive]
pub enum ModelServingPhase {
    /// Model is waiting for configuration
    #[default]
    Pending,
    /// Model artifacts are being loaded
    Loading,
    /// Model is serving inference requests
    Serving,
    /// Model has encountered an error
    Failed,
}

impl std::fmt::Display for ModelServingPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Loading => write!(f, "Loading"),
            Self::Serving => write!(f, "Serving"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Recovery policy for serving groups
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryPolicy {
    /// Recreate the entire serving group on failure
    ServingGroupRecreate,
}

impl std::fmt::Display for RecoveryPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServingGroupRecreate => write!(f, "ServingGroupRecreate"),
        }
    }
}

// =============================================================================
// Role Spec
// =============================================================================

/// A single role within a LatticeModel serving workload.
///
/// Each role maps to a Volcano ModelServing role (e.g. prefill, decode)
/// with separate entry and optional worker pod templates for disaggregated inference.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelRoleSpec {
    /// Number of entry replicas for this role (defaults to 1 when omitted)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<u32>,

    /// Entry pod workload spec (containers, volumes, env, etc.)
    #[serde(default)]
    pub entry_workload: WorkloadSpec,

    /// Entry pod runtime extensions (sidecars, sysctls, hostNetwork, etc.)
    #[serde(default)]
    pub entry_runtime: RuntimeSpec,

    /// Number of worker replicas (None = no workers)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_replicas: Option<u32>,

    /// Worker pod workload spec (None = no workers)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_workload: Option<WorkloadSpec>,

    /// Worker pod runtime extensions (falls back to entry_runtime if None)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_runtime: Option<RuntimeSpec>,

    /// Autoscaling configuration for this role.
    /// Compiles to Kthena AutoscalingPolicy + AutoscalingPolicyBinding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autoscaling: Option<ModelAutoscalingSpec>,
}

impl ModelRoleSpec {
    /// Resolved replica count (defaults to 1 when unset).
    pub fn replicas(&self) -> u32 {
        self.replicas.unwrap_or(1)
    }
}

// =============================================================================
// Autoscaling
// =============================================================================

/// Per-role autoscaling configuration for model serving.
/// Compiles to Kthena AutoscalingPolicy + AutoscalingPolicyBinding.
///
/// Uses the shared `AutoscalingMetric` type for metric definitions (same as LatticeService).
/// The role's `replicas` field is used as the autoscaling minimum; `max` is the ceiling.
/// Metrics port is discovered automatically from `entry_workload.service.ports["metrics"]`.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelAutoscalingSpec {
    /// Maximum replicas Kthena can scale to
    pub max: u32,

    /// Metrics driving autoscaling decisions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<AutoscalingMetric>,

    /// Tolerance percent around target before triggering scaling (default: 10)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tolerance_percent: Option<u32>,

    /// Scaling behavior (stabilization windows, panic mode)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior: Option<ModelAutoscalingBehavior>,
}

/// Scaling behavior configuration for model autoscaling (stabilization windows, panic mode)
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelAutoscalingBehavior {
    /// Scale-up behavior (panic mode, stabilization)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale_up: Option<ModelScaleUpBehavior>,
    /// Scale-down behavior (stabilization window)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale_down: Option<ModelScaleDownBehavior>,
}

/// Scale-up behavior with optional panic mode for spike detection
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelScaleUpBehavior {
    /// Spike detection threshold percent (triggers panic mode)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub panic_threshold_percent: Option<u32>,
    /// Duration to hold panic mode (e.g. "5m")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub panic_mode_hold: Option<String>,
    /// Observation window for sustained load (e.g. "1m")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stabilization_window: Option<String>,
    /// Evaluation frequency (e.g. "30s")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<String>,
}

/// Scale-down behavior with stabilization window
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelScaleDownBehavior {
    /// Observation window before scaling down (e.g. "5m")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stabilization_window: Option<String>,
    /// Evaluation frequency (e.g. "1m")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<String>,
}

impl ModelRoleSpec {
    /// Validate role constraints (e.g. replicas must not exceed autoscaling max).
    pub fn validate(&self) -> Result<(), crate::Error> {
        if let Some(ref autoscaling) = self.autoscaling {
            if self.replicas() > autoscaling.max {
                return Err(crate::Error::validation(
                    "replicas cannot exceed autoscaling max",
                ));
            }
        }
        Ok(())
    }
}

fn default_scheduler() -> String {
    "volcano".to_string()
}

// =============================================================================
// Routing
// =============================================================================

/// Inference routing configuration for Kthena router.
///
/// Compiles to Kthena `ModelServer` + `ModelRoute` resources in the
/// `networking.serving.volcano.sh/v1alpha1` API group.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelRoutingSpec {
    /// Inference engine framework
    pub inference_engine: InferenceEngine,

    /// Model name (e.g. "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B")
    pub model: String,

    /// Container port serving inference (default: 8000)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// Port protocol (default: "http")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,

    /// Traffic policy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_policy: Option<TrafficPolicy>,

    /// KV connector for PD disaggregation (nixl, mooncake, lmcache)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kv_connector: Option<KvConnector>,

    /// Named routes — each compiles to a Kthena ModelRoute
    #[serde(default)]
    pub routes: BTreeMap<String, ModelRouteSpec>,
}

/// Inference engine framework
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[non_exhaustive]
pub enum InferenceEngine {
    /// vLLM inference engine
    #[serde(rename = "vLLM")]
    VLlm,
    /// SGLang inference engine
    SGLang,
}

impl std::fmt::Display for InferenceEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VLlm => write!(f, "vLLM"),
            Self::SGLang => write!(f, "SGLang"),
        }
    }
}

/// Traffic policy for inference routing
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TrafficPolicy {
    /// Retry policy for failed requests
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetryPolicy>,
}

/// Retry policy for inference requests
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RetryPolicy {
    /// Number of retry attempts
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,
}

/// KV connector type for PD disaggregation
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum KvConnectorType {
    /// NIXL connector
    Nixl,
    /// Mooncake connector
    Mooncake,
    /// LMCache connector
    Lmcache,
}

impl std::fmt::Display for KvConnectorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nixl => write!(f, "nixl"),
            Self::Mooncake => write!(f, "mooncake"),
            Self::Lmcache => write!(f, "lmcache"),
        }
    }
}

/// Default nixl side-channel port for KV cache transfer handshake metadata exchange
pub const DEFAULT_KV_SIDE_CHANNEL_PORT: u16 = 5557;

/// KV connector configuration for PD disaggregation
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KvConnector {
    /// Connector type (nixl, mooncake, lmcache)
    #[serde(rename = "type")]
    pub type_: KvConnectorType,

    /// Side-channel port for KV cache transfer metadata exchange (default: 5557)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// A single named route targeting this model's ModelServer
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelRouteSpec {
    /// Virtual model name clients use in requests (defaults to model name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,

    /// LoRA adapters to match
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lora_adapters: Option<Vec<String>>,

    /// Routing rules (first match wins)
    pub rules: Vec<ModelRouteRule>,

    /// Token rate limiting
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,

    /// Bind to a specific Gateway (optional — uses Kthena default if omitted)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_refs: Option<Vec<ModelParentRef>>,
}

/// A single routing rule within a ModelRoute
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelRouteRule {
    /// Rule name
    pub name: String,

    /// Header-based matching
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_match: Option<ModelMatch>,

    /// Backend targets (supports weighted canary split)
    pub target_models: Vec<TargetModel>,
}

/// Header-based match criteria
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelMatch {
    /// Header name → match value
    pub headers: BTreeMap<String, HeaderMatchValue>,
}

/// Header match value
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HeaderMatchValue {
    /// Exact string match
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
}

/// A backend target for a routing rule
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TargetModel {
    /// ModelServer name (defaults to the model's auto-generated ModelServer)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_server_name: Option<String>,

    /// Traffic weight for canary deployments
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
}

/// Time unit for rate limiting
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum RateLimitUnit {
    /// Per-second rate limit
    Second,
    /// Per-minute rate limit
    Minute,
}

impl std::fmt::Display for RateLimitUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Second => write!(f, "second"),
            Self::Minute => write!(f, "minute"),
        }
    }
}

/// Token rate limiting configuration
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RateLimit {
    /// Maximum input tokens per time unit
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens_per_unit: Option<u32>,

    /// Maximum output tokens per time unit
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens_per_unit: Option<u32>,

    /// Time unit
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<RateLimitUnit>,
}

/// Reference to a parent Gateway for a ModelRoute
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelParentRef {
    /// Gateway name
    pub name: String,

    /// Gateway namespace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// Kind (default: Gateway)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

// =============================================================================
// Model Source
// =============================================================================

/// Declarative model artifact source — each pod downloads its own model via
/// an init container before the main serving container starts.
///
/// On model spec change, the init container args change → Kthena rolling update →
/// new pods download the new model → old pods serve until new pods are ready → zero downtime.
///
/// Multiple pods' init containers may download concurrently to shared storage.
/// This is safe because download tools (`hf download`, `aws s3 sync`) are idempotent.
///
/// Supported URI schemes: `hf://` (HuggingFace Hub), `s3://`, `gs://`
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelSourceSpec {
    /// Model URI — determines download method.
    /// Examples: `hf://Qwen/Qwen3-8B`, `s3://bucket/models/llama`, `gs://bucket/models/llama`
    pub uri: String,

    /// Cache volume spec. Determines where downloaded models are stored.
    /// - `pvc://claim-name` → existing PVC (shared across pods, recommended for large models)
    /// - `hostpath:///path/to/cache` → host directory (shared per-node)
    /// - omitted → emptyDir (per-pod, requires `cache_size`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_uri: Option<String>,

    /// Size limit for emptyDir cache (e.g. "50Gi"). Required when `cache_uri` is omitted.
    /// Ignored when `cache_uri` is `pvc://` or `hostpath://`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_size: Option<String>,

    /// Mount path in serving containers (default: "/models")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_path: Option<String>,

    /// K8s Secret name for download auth (mounted as envFrom on init container)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_secret: Option<SecretKeySelector>,

    /// Override the default downloader image (default: Kthena's downloader)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downloader_image: Option<String>,

    /// Egress FQDNs the downloader needs to reach.
    /// When omitted, defaults are derived from the URI scheme:
    /// `hf://` → huggingface.co, `s3://` → *.amazonaws.com, `gs://` → storage.googleapis.com.
    /// When specified, fully overrides the defaults (e.g. for private mirrors).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<String>,
}

/// Reference to a K8s Secret whose keys are mounted as env vars via `envFrom`.
///
/// The secret's keys must match what the download tool expects:
/// - HuggingFace: `HF_TOKEN`
/// - S3: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optionally `AWS_DEFAULT_REGION`
/// - GCS: keys matching `gsutil` expectations
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretKeySelector {
    /// Secret name
    pub name: String,
}

// =============================================================================
// Model Ingress
// =============================================================================

/// Ingress configuration for external model access via Gateway API.
///
/// When set, creates a Gateway with TLS listeners and binds the ModelRoute
/// to it via `parentRefs`. The Kthena router handles inference-aware request
/// routing to model pods — no separate HTTPRoute is needed.
///
/// Traffic flow: Internet → Gateway (TLS) → Kthena Router → ModelServer → Pods
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelIngressSpec {
    /// Hostnames for external access (e.g., `["llama-70b.us-east.lattice.gpu"]`)
    pub hosts: Vec<String>,

    /// TLS configuration — cert-manager auto or manual secret
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<IngressTls>,

    /// GatewayClass name (default: "istio")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_class: Option<String>,

    /// Listen port for HTTPS (default: 443)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
}

impl ModelIngressSpec {
    /// Validate the ingress spec
    pub fn validate(&self) -> Result<(), crate::Error> {
        if self.hosts.is_empty() {
            return Err(crate::Error::validation("ingress hosts must not be empty"));
        }
        if let Some(ref tls) = self.tls {
            if tls.secret_name.is_some() && tls.issuer_ref.is_some() {
                return Err(crate::Error::validation(
                    "ingress tls: specify either secretName or issuerRef, not both",
                ));
            }
        }
        Ok(())
    }

    /// Gateway class to use (defaults to "istio")
    pub fn gateway_class(&self) -> &str {
        self.gateway_class.as_deref().unwrap_or("istio")
    }

    /// HTTPS listen port (defaults to 443)
    pub fn listen_port(&self) -> u16 {
        self.listen_port.unwrap_or(443)
    }
}

// =============================================================================
// CRD
// =============================================================================

/// Model serving workload specification backed by Volcano ModelServing
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "lattice.dev",
    version = "v1alpha1",
    kind = "LatticeModel",
    plural = "latticemodels",
    shortname = "lm",
    namespaced,
    status = "LatticeModelStatus",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LatticeModelSpec {
    /// Volcano scheduler name
    #[serde(default = "default_scheduler")]
    pub scheduler_name: String,

    /// Recovery policy for the serving group
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_policy: Option<RecoveryPolicy>,

    /// Grace period for restart
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_grace_period_seconds: Option<u32>,

    /// Declarative model artifact source — injects downloader init container into pod templates
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_source: Option<ModelSourceSpec>,

    /// Default values inherited by all roles via strategic merge patch.
    /// Role-level fields override defaults. Applied at compile time only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defaults: Option<ModelRoleSpec>,

    /// Model serving roles — each maps to a ModelServing role (e.g. prefill, decode)
    #[serde(default)]
    pub roles: BTreeMap<String, ModelRoleSpec>,

    /// Inference routing configuration (compiles to Kthena ModelServer + ModelRoute)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<ModelRoutingSpec>,

    /// Ingress configuration for external access via Gateway API.
    /// When set, creates a Gateway with TLS listeners and binds ModelRoutes
    /// via parentRefs. Requires `routing` to also be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<ModelIngressSpec>,

    /// Network topology configuration for topology-aware scheduling.
    /// When set, the ModelServing includes networkTopology for Volcano co-placement.
    /// When absent but kv_connector is present, topology is auto-injected (soft mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topology: Option<WorkloadNetworkTopology>,

    /// Observability configuration (metrics mappings, port overrides).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observability: Option<ObservabilitySpec>,
}

impl LatticeModelSpec {
    /// Returns roles with defaults merged in. Used by both validation and compilation.
    pub fn merged_roles(&self) -> BTreeMap<String, ModelRoleSpec> {
        use super::workload::merge::Merge;
        let mut roles = self.roles.clone();
        if let Some(ref defaults) = self.defaults {
            for role in roles.values_mut() {
                role.merge_from(defaults);
            }
        }
        roles
    }

    /// Validate the model specification (all roles, with defaults applied).
    pub fn validate(&self) -> Result<(), crate::Error> {
        let roles = self.merged_roles();
        for (role_name, role_spec) in &roles {
            role_spec
                .validate()
                .map_err(|e| crate::Error::validation(format!("role '{role_name}': {e}")))?;
        }
        if let Some(ref ingress) = self.ingress {
            ingress.validate()?;
            if self.routing.is_none() {
                return Err(crate::Error::validation(
                    "ingress requires routing to be configured",
                ));
            }
        }
        Ok(())
    }
}

impl Default for LatticeModelSpec {
    fn default() -> Self {
        Self {
            scheduler_name: default_scheduler(),
            recovery_policy: None,
            restart_grace_period_seconds: None,
            model_source: None,
            defaults: None,
            roles: BTreeMap::new(),
            routing: None,
            ingress: None,
            topology: None,
            observability: None,
        }
    }
}

/// Status of a LatticeModel serving workload
///
/// All optional fields serialize as `null` (no `skip_serializing_if`) so that
/// merge-patch status updates correctly clear stale values.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatticeModelStatus {
    /// Current phase of the model serving lifecycle
    #[serde(default)]
    pub phase: ModelServingPhase,

    /// Human-readable message about current state
    #[serde(default)]
    pub message: Option<String>,

    /// Generation observed by the controller
    #[serde(default)]
    pub observed_generation: Option<i64>,

    /// Conditions reflecting detailed status from ModelServing
    #[serde(default)]
    pub conditions: Option<Vec<ModelCondition>>,

    /// Auto-injected topology configuration (from kv_connector inference).
    /// Written to status only — never mutates the spec.
    #[serde(default)]
    pub auto_topology: Option<WorkloadNetworkTopology>,

    /// Role graph keys (e.g. "llm-serving-prefill") successfully applied.
    /// Used for orphan cleanup when roles are removed from the spec.
    #[serde(default)]
    pub applied_roles: Option<Vec<String>>,

    /// Estimated cost based on resource requests and current rates
    #[serde(default)]
    pub cost: Option<CostEstimate>,

    /// Scraped metrics snapshot from VictoriaMetrics
    #[serde(default)]
    pub metrics: Option<MetricsSnapshot>,
}

/// A condition on a LatticeModel (mirrored from ModelServing status)
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelCondition {
    /// Condition type (e.g. "Available", "Progressing", "UpdateInProgress")
    #[serde(rename = "type")]
    pub type_: String,

    /// Condition status: "True", "False", or "Unknown"
    pub status: String,

    /// Machine-readable reason for the condition
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Human-readable message
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Timestamp of last transition
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_spec_default_has_empty_roles() {
        let spec = LatticeModelSpec::default();
        assert!(spec.roles.is_empty());
        assert_eq!(spec.scheduler_name, "volcano");
    }

    #[test]
    fn model_role_spec_entry_only() {
        let role = ModelRoleSpec {
            replicas: Some(2),
            entry_workload: WorkloadSpec::default(),
            entry_runtime: RuntimeSpec::default(),
            worker_replicas: None,
            worker_workload: None,
            worker_runtime: None,
            autoscaling: None,
        };
        assert!(role.entry_workload.containers.is_empty());
        assert_eq!(role.replicas, Some(2));
        assert_eq!(role.worker_replicas, None);
    }

    #[test]
    fn model_role_spec_with_workers() {
        let role = ModelRoleSpec {
            replicas: Some(1),
            entry_workload: WorkloadSpec::default(),
            entry_runtime: RuntimeSpec::default(),
            worker_replicas: Some(4),
            worker_workload: Some(WorkloadSpec::default()),
            worker_runtime: None,
            autoscaling: None,
        };
        assert_eq!(role.replicas, Some(1));
        assert_eq!(role.worker_replicas, Some(4));
        assert!(role.worker_workload.is_some());
        assert!(role.worker_runtime.is_none());
    }

    #[test]
    fn model_with_multiple_roles() {
        let mut roles = BTreeMap::new();
        roles.insert(
            "prefill".to_string(),
            ModelRoleSpec {
                replicas: Some(1),
                entry_workload: WorkloadSpec::default(),
                entry_runtime: RuntimeSpec::default(),
                worker_replicas: None,
                worker_workload: None,
                worker_runtime: None,
                autoscaling: None,
            },
        );
        roles.insert(
            "decode".to_string(),
            ModelRoleSpec {
                replicas: Some(2),
                entry_workload: WorkloadSpec::default(),
                entry_runtime: RuntimeSpec::default(),
                worker_replicas: Some(4),
                worker_workload: Some(WorkloadSpec::default()),
                worker_runtime: None,
                autoscaling: None,
            },
        );

        let spec = LatticeModelSpec {
            roles,
            ..Default::default()
        };

        assert_eq!(spec.roles.len(), 2);
        assert_eq!(spec.roles["prefill"].replicas, Some(1));
        assert_eq!(spec.roles["decode"].replicas, Some(2));
        assert_eq!(spec.roles["decode"].worker_replicas, Some(4));
    }

    #[test]
    fn model_serving_phase_display() {
        assert_eq!(ModelServingPhase::Pending.to_string(), "Pending");
        assert_eq!(ModelServingPhase::Loading.to_string(), "Loading");
        assert_eq!(ModelServingPhase::Serving.to_string(), "Serving");
        assert_eq!(ModelServingPhase::Failed.to_string(), "Failed");
    }

    #[test]
    fn model_source_spec_serialization() {
        let source = ModelSourceSpec {
            uri: "hf://Qwen/Qwen3-8B".to_string(),
            cache_uri: Some("pvc://model-cache".to_string()),
            cache_size: None,
            mount_path: None,
            token_secret: Some(SecretKeySelector {
                name: "hf-creds".to_string(),
            }),
            downloader_image: None,
            egress: vec![],
        };

        let json = serde_json::to_value(&source).unwrap();
        assert_eq!(json["uri"], "hf://Qwen/Qwen3-8B");
        assert_eq!(json["cacheUri"], "pvc://model-cache");
        assert!(json.get("cacheSize").is_none());
        assert!(json.get("mountPath").is_none());
        assert_eq!(json["tokenSecret"]["name"], "hf-creds");
        assert!(json.get("downloaderImage").is_none());
    }

    #[test]
    fn model_source_spec_deserialization() {
        let json = serde_json::json!({
            "uri": "s3://bucket/model",
            "cacheSize": "100Gi"
        });

        let source: ModelSourceSpec = serde_json::from_value(json).unwrap();
        assert_eq!(source.uri, "s3://bucket/model");
        assert_eq!(source.cache_size.as_deref(), Some("100Gi"));
        assert!(source.cache_uri.is_none());
        assert!(source.mount_path.is_none());
        assert!(source.token_secret.is_none());
        assert!(source.downloader_image.is_none());
    }

    #[test]
    fn model_spec_default_has_no_model_source() {
        let spec = LatticeModelSpec::default();
        assert!(spec.model_source.is_none());
    }

    #[test]
    fn kv_connector_port_serialized() {
        let kv = KvConnector {
            type_: KvConnectorType::Nixl,
            port: Some(6000),
        };
        let json = serde_json::to_value(&kv).unwrap();
        assert_eq!(json["type"], "nixl");
        assert_eq!(json["port"], 6000);
    }

    #[test]
    fn kv_connector_port_omitted_when_none() {
        let kv = KvConnector {
            type_: KvConnectorType::Nixl,
            port: None,
        };
        let json = serde_json::to_value(&kv).unwrap();
        assert_eq!(json["type"], "nixl");
        assert!(json.get("port").is_none());
    }

    #[test]
    fn kv_connector_deserialization_without_port() {
        let json = serde_json::json!({"type": "mooncake"});
        let kv: KvConnector = serde_json::from_value(json).unwrap();
        assert_eq!(kv.type_, KvConnectorType::Mooncake);
        assert_eq!(kv.port, None);
    }

    // =========================================================================
    // Defaults merge tests
    // =========================================================================

    /// Helper: build a defaults role spec with image, command, resources, and pull secrets
    fn defaults_role() -> ModelRoleSpec {
        use crate::crd::workload::container::ContainerSpec;
        use crate::crd::workload::resources::{ResourceQuantity, ResourceRequirements};

        ModelRoleSpec {
            replicas: Some(1),
            entry_workload: WorkloadSpec {
                containers: BTreeMap::from([(
                    "main".to_string(),
                    ContainerSpec {
                        image: "vllm:latest".to_string(),
                        command: Some(vec!["/usr/bin/python".to_string()]),
                        resources: Some(ResourceRequirements {
                            limits: Some(ResourceQuantity {
                                cpu: Some("8".to_string()),
                                memory: Some("64Gi".to_string()),
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            },
            entry_runtime: RuntimeSpec {
                image_pull_secrets: vec!["reg-creds".to_string()],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn model_spec_with_defaults_serde_roundtrip() {
        let spec = LatticeModelSpec {
            defaults: Some(ModelRoleSpec::default()),
            ..Default::default()
        };

        let json = serde_json::to_string(&spec).unwrap();
        let de: LatticeModelSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec.defaults, de.defaults);
    }

    #[test]
    fn merged_roles_fills_missing_entry_workload() {
        let spec = LatticeModelSpec {
            defaults: Some(defaults_role()),
            roles: BTreeMap::from([(
                "prefill".to_string(),
                ModelRoleSpec {
                    replicas: Some(4),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let roles = spec.merged_roles();
        let role = &roles["prefill"];

        assert_eq!(role.replicas, Some(4));
        assert_eq!(role.entry_workload.containers["main"].image, "vllm:latest");
        assert_eq!(role.entry_runtime.image_pull_secrets, vec!["reg-creds"]);
    }

    #[test]
    fn merged_roles_preserves_role_overrides() {
        use crate::crd::workload::container::ContainerSpec;
        use crate::crd::workload::resources::{ResourceQuantity, ResourceRequirements};

        let spec = LatticeModelSpec {
            defaults: Some(defaults_role()),
            roles: BTreeMap::from([(
                "decode".to_string(),
                ModelRoleSpec {
                    replicas: Some(2),
                    entry_workload: WorkloadSpec {
                        containers: BTreeMap::from([(
                            "main".to_string(),
                            ContainerSpec {
                                image: "".to_string(),
                                resources: Some(ResourceRequirements {
                                    limits: Some(ResourceQuantity {
                                        memory: Some("128Gi".to_string()),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        )]),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let roles = spec.merged_roles();
        let role = &roles["decode"];

        let limits = role.entry_workload.containers["main"]
            .resources
            .as_ref()
            .unwrap()
            .limits
            .as_ref()
            .unwrap();
        assert_eq!(limits.cpu.as_deref(), Some("8"), "cpu from defaults");
        assert_eq!(
            limits.memory.as_deref(),
            Some("128Gi"),
            "memory from role override"
        );
    }

    // ========================================================================
    // ModelIngressSpec Tests
    // ========================================================================

    use super::super::workload::ingress::{CertIssuerRef, IngressTls};

    #[test]
    fn ingress_validate_valid() {
        let ingress = ModelIngressSpec {
            hosts: vec!["model.lattice.gpu".to_string()],
            tls: Some(IngressTls {
                secret_name: None,
                issuer_ref: Some(CertIssuerRef {
                    name: "letsencrypt".to_string(),
                    kind: None,
                }),
            }),
            gateway_class: None,
            listen_port: None,
        };
        assert!(ingress.validate().is_ok());
    }

    #[test]
    fn ingress_validate_empty_hosts() {
        let ingress = ModelIngressSpec {
            hosts: vec![],
            tls: None,
            gateway_class: None,
            listen_port: None,
        };
        assert!(ingress.validate().is_err());
    }

    #[test]
    fn ingress_validate_both_tls_modes() {
        let ingress = ModelIngressSpec {
            hosts: vec!["model.lattice.gpu".to_string()],
            tls: Some(IngressTls {
                secret_name: Some("my-secret".to_string()),
                issuer_ref: Some(CertIssuerRef {
                    name: "letsencrypt".to_string(),
                    kind: None,
                }),
            }),
            gateway_class: None,
            listen_port: None,
        };
        assert!(ingress.validate().is_err());
    }

    #[test]
    fn ingress_defaults() {
        let ingress = ModelIngressSpec {
            hosts: vec!["model.lattice.gpu".to_string()],
            tls: None,
            gateway_class: None,
            listen_port: None,
        };
        assert_eq!(ingress.gateway_class(), "istio");
        assert_eq!(ingress.listen_port(), 443);
    }

    #[test]
    fn spec_validate_ingress_requires_routing() {
        let spec = LatticeModelSpec {
            ingress: Some(ModelIngressSpec {
                hosts: vec!["model.lattice.gpu".to_string()],
                tls: None,
                gateway_class: None,
                listen_port: None,
            }),
            routing: None,
            ..Default::default()
        };
        let err = spec.validate().unwrap_err();
        assert!(err.to_string().contains("routing"));
    }

    #[test]
    fn spec_validate_ingress_with_routing_ok() {
        let spec = LatticeModelSpec {
            ingress: Some(ModelIngressSpec {
                hosts: vec!["model.lattice.gpu".to_string()],
                tls: None,
                gateway_class: None,
                listen_port: None,
            }),
            routing: Some(ModelRoutingSpec {
                inference_engine: InferenceEngine::VLlm,
                model: "test/model".to_string(),
                port: None,
                protocol: None,
                traffic_policy: None,
                kv_connector: None,
                routes: BTreeMap::new(),
            }),
            ..Default::default()
        };
        assert!(spec.validate().is_ok());
    }
}
