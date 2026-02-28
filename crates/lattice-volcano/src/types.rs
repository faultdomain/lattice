//! Volcano VCJob serialization types
//!
//! Typed representation of Volcano `batch.volcano.sh/v1alpha1` Job resources.
//! Uses serde for JSON serialization compatible with server-side apply.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Volcano VCJob resource (`batch.volcano.sh/v1alpha1` Kind: Job)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCJob {
    pub api_version: String,
    pub kind: String,
    pub metadata: VolcanoMetadata,
    pub spec: VCJobSpec,
}

use lattice_common::kube_utils::OwnerReference;

/// Shared metadata for all Volcano/Kthena resources (VCJob, ModelServing, networking).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VolcanoMetadata {
    pub name: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_references: Vec<OwnerReference>,
}

/// VCJob spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCJobSpec {
    pub scheduler_name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_available: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retry: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_class_name: Option<String>,

    pub tasks: Vec<VCJobTask>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<VCJobTaskPolicy>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_topology: Option<serde_json::Value>,
}

/// A single task within a VCJob
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCJobTask {
    pub name: String,
    pub replicas: u32,
    /// Pod template — passed through as pre-serialized JSON from the workload compiler
    pub template: serde_json::Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<VCJobTaskPolicy>,
}

/// Volcano lifecycle policy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCJobTaskPolicy {
    pub event: String,
    pub action: String,
}

// =============================================================================
// PodGroup
// =============================================================================

/// Volcano PodGroup resource (`scheduling.volcano.sh/v1beta1`)
///
/// Used by LatticeService when topology-aware scheduling is configured.
/// Associates a group of pods for co-scheduling with network topology constraints.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodGroup {
    pub api_version: String,
    pub kind: String,
    pub metadata: VolcanoMetadata,
    pub spec: PodGroupSpec,
}

/// PodGroup spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PodGroupSpec {
    pub min_member: u32,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_topology: Option<serde_json::Value>,
}

/// Annotation key for associating pods with a PodGroup
pub const PODGROUP_ANNOTATION: &str = "scheduling.volcano.sh/group-name";

/// Compile a PodGroup for a LatticeService with topology-aware scheduling.
pub fn compile_service_pod_group(
    name: &str,
    namespace: &str,
    replicas: u32,
    topology: &lattice_common::crd::WorkloadNetworkTopology,
) -> PodGroup {
    PodGroup {
        api_version: "scheduling.volcano.sh/v1beta1".to_string(),
        kind: "PodGroup".to_string(),
        metadata: VolcanoMetadata {
            name: name.to_string(),
            namespace: namespace.to_string(),
            labels: BTreeMap::from([
                (
                    "app.kubernetes.io/managed-by".to_string(),
                    "lattice".to_string(),
                ),
                ("app.kubernetes.io/name".to_string(), name.to_string()),
            ]),
            owner_references: Vec::new(),
        },
        spec: PodGroupSpec {
            min_member: replicas,
            network_topology: Some(network_topology_value(topology)),
        },
    }
}

// =============================================================================
// VCCronJob
// =============================================================================

/// Volcano VCCronJob resource (`batch.volcano.sh/v1alpha1` Kind: CronJob)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCCronJob {
    pub api_version: String,
    pub kind: String,
    pub metadata: VolcanoMetadata,
    pub spec: VCCronJobSpec,
}

/// VCCronJob spec — wraps a VCJob template with cron scheduling fields
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCCronJobSpec {
    pub schedule: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency_policy: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspend: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successful_jobs_history_limit: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_jobs_history_limit: Option<u32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starting_deadline_seconds: Option<i64>,

    pub job_template: VCCronJobTemplate,
}

/// Job template embedded in a VCCronJob — contains the VCJob spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VCCronJobTemplate {
    pub spec: VCJobSpec,
}

/// Kthena ModelServing resource (`workload.serving.volcano.sh/v1alpha1` Kind: ModelServing)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelServing {
    pub api_version: String,
    pub kind: String,
    pub metadata: VolcanoMetadata,
    pub spec: ModelServingSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelServingSpec {
    pub scheduler_name: String,
    pub replicas: u32,
    pub template: ServingGroupTemplate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_policy: Option<lattice_common::crd::RecoveryPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollout_strategy: Option<RolloutStrategy>,
}

/// Template for a serving group containing named roles and gang scheduling policy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServingGroupTemplate {
    pub roles: Vec<ModelServingRole>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gang_policy: Option<GangPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_grace_period_seconds: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_topology: Option<serde_json::Value>,
}

/// A single role within a ModelServing (e.g. prefill, decode)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelServingRole {
    pub name: String,
    pub replicas: u32,
    /// Entry pod template — passed through as pre-serialized JSON from the workload compiler
    pub entry_template: serde_json::Value,
    /// Number of worker replicas (0 = no workers). Always serialized — Kthena requires this field.
    #[serde(default)]
    pub worker_replicas: u32,
    /// Worker pod template (None = no workers)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_template: Option<serde_json::Value>,
}

/// Gang scheduling policy for coordinated role startup
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GangPolicy {
    /// Minimum replicas per role required for the gang to start
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub min_role_replicas: BTreeMap<String, u32>,
}

/// Rollout strategy for serving updates
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RolloutStrategy {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling_update: Option<RollingUpdateConfiguration>,
}

/// Configuration for rolling update strategy
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RollingUpdateConfiguration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_unavailable: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition: Option<i32>,
}

// =============================================================================
// Kthena Networking Types (networking.serving.volcano.sh/v1alpha1)
// =============================================================================

/// Kthena ModelServer resource — registers a model with the inference router
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaModelServer {
    pub api_version: String,
    pub kind: String,
    pub metadata: VolcanoMetadata,
    pub spec: KthenaModelServerSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaModelServerSpec {
    /// Model name (e.g. "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// Inference engine (vLLM, SGLang)
    pub inference_engine: String,

    /// Selects pods backing this model server
    pub workload_selector: WorkloadSelector,

    /// Port serving inference traffic
    pub workload_port: WorkloadPort,

    /// Traffic policy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_policy: Option<KthenaTrafficPolicy>,

    /// KV connector for PD disaggregation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kv_connector: Option<KthenaKvConnector>,
}

/// Label selector for model serving pods, with optional PD disaggregation grouping
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadSelector {
    pub match_labels: BTreeMap<String, String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pd_group: Option<PdGroup>,
}

/// PD disaggregation group — identifies prefill vs decode pods by label
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PdGroup {
    pub group_key: String,
    pub prefill_labels: BTreeMap<String, String>,
    pub decode_labels: BTreeMap<String, String>,
}

/// Workload port configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadPort {
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// Traffic policy for Kthena networking resources
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaTrafficPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<KthenaRetryPolicy>,
}

/// Retry policy for inference requests
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaRetryPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,
}

/// KV connector configuration for PD disaggregation
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaKvConnector {
    #[serde(rename = "type")]
    pub type_: lattice_common::crd::KvConnectorType,
}

/// Kthena ModelRoute resource — defines routing rules for a model
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaModelRoute {
    pub api_version: String,
    pub kind: String,
    pub metadata: VolcanoMetadata,
    pub spec: KthenaModelRouteSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaModelRouteSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lora_adapters: Option<Vec<String>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_refs: Option<Vec<KthenaParentRef>>,

    pub rules: Vec<KthenaRouteRule>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<KthenaRateLimit>,
}

/// Reference to a parent Gateway
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaParentRef {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// A single routing rule within a ModelRoute
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaRouteRule {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_match: Option<KthenaModelMatch>,
    pub target_models: Vec<KthenaTargetModel>,
}

/// Header-based match criteria for routing
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaModelMatch {
    pub headers: BTreeMap<String, KthenaHeaderMatch>,
}

/// Header match value
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaHeaderMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
}

/// Backend target for a routing rule
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaTargetModel {
    pub model_server_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
}

/// Token rate limiting for inference traffic
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaRateLimit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens_per_unit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens_per_unit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<lattice_common::crd::RateLimitUnit>,
}

// =============================================================================
// Kthena Autoscaling Types (workload.serving.volcano.sh/v1alpha1)
// =============================================================================

/// Kthena AutoscalingPolicy — defines scaling strategy and metrics
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaAutoscalingPolicy {
    pub api_version: String,
    pub kind: String,
    pub metadata: VolcanoMetadata,
    pub spec: KthenaAutoscalingPolicySpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaAutoscalingPolicySpec {
    pub metrics: Vec<KthenaAutoscalingMetric>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tolerance_percent: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior: Option<KthenaAutoscalingBehavior>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaAutoscalingMetric {
    pub metric_name: String,
    /// Serialized as a string to match Kthena's resource.Quantity type
    pub target_value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaAutoscalingBehavior {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale_up: Option<KthenaScaleUpBehavior>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scale_down: Option<KthenaScaleDownBehavior>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaScaleUpBehavior {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub panic_policy: Option<KthenaPanicPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stable_policy: Option<KthenaStablePolicy>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaPanicPolicy {
    /// Required evaluation frequency (e.g. "30s")
    pub period: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub panic_threshold_percent: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub panic_mode_hold: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaStablePolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stabilization_window: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaScaleDownBehavior {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stabilization_window: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<String>,
}

/// Kthena AutoscalingPolicyBinding — binds a policy to a ModelServing target
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaAutoscalingPolicyBinding {
    pub api_version: String,
    pub kind: String,
    pub metadata: VolcanoMetadata,
    pub spec: KthenaAutoscalingPolicyBindingSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaAutoscalingPolicyBindingSpec {
    pub policy_ref: KthenaPolicyRef,
    pub homogeneous_target: KthenaHomogeneousTarget,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaPolicyRef {
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaHomogeneousTarget {
    pub target: KthenaAutoscalingTarget,
    pub min_replicas: u32,
    pub max_replicas: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaAutoscalingTarget {
    pub target_ref: KthenaTargetRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_targets: Option<KthenaSubTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric_endpoint: Option<KthenaMetricEndpoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaTargetRef {
    pub kind: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaSubTarget {
    pub kind: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KthenaMetricEndpoint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// Convert a `WorkloadNetworkTopology` to the Volcano-native JSON representation.
///
/// Produces `{"mode": "hard"|"soft", "highestTierAllowed": N}` for use in
/// `VCJobSpec.network_topology` and `ServingGroupTemplate.network_topology`.
pub fn network_topology_value(
    topo: &lattice_common::crd::WorkloadNetworkTopology,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert(
        "mode".into(),
        match topo.mode {
            lattice_common::crd::TopologyMode::Hard => "hard".into(),
            lattice_common::crd::TopologyMode::Soft => "soft".into(),
            _ => "soft".into(),
        },
    );
    if let Some(tier) = topo.max_tier {
        map.insert("highestTierAllowed".into(), tier.into());
    }
    serde_json::Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcjob_serialization_roundtrip() {
        let vcjob = VCJob {
            api_version: "batch.volcano.sh/v1alpha1".to_string(),
            kind: "Job".to_string(),
            metadata: VolcanoMetadata {
                name: "test-job".to_string(),
                namespace: "default".to_string(),
                labels: BTreeMap::from([(
                    "app.kubernetes.io/managed-by".to_string(),
                    "lattice".to_string(),
                )]),
                owner_references: vec![],
            },
            spec: VCJobSpec {
                scheduler_name: "volcano".to_string(),
                min_available: Some(2),
                max_retry: None,
                queue: None,
                priority_class_name: None,
                tasks: vec![],
                policies: vec![],
                network_topology: None,
            },
        };

        let json = serde_json::to_string(&vcjob).unwrap();
        let de: VCJob = serde_json::from_str(&json).unwrap();
        assert_eq!(vcjob, de);
    }

    #[test]
    fn vccronjob_serialization_roundtrip() {
        let cron = VCCronJob {
            api_version: "batch.volcano.sh/v1alpha1".to_string(),
            kind: "CronJob".to_string(),
            metadata: VolcanoMetadata {
                name: "test-cron".to_string(),
                namespace: "default".to_string(),
                labels: BTreeMap::from([(
                    "app.kubernetes.io/managed-by".to_string(),
                    "lattice".to_string(),
                )]),
                owner_references: vec![],
            },
            spec: VCCronJobSpec {
                schedule: "*/5 * * * *".to_string(),
                concurrency_policy: Some("Forbid".to_string()),
                suspend: Some(false),
                successful_jobs_history_limit: Some(3),
                failed_jobs_history_limit: Some(1),
                starting_deadline_seconds: Some(60),
                job_template: VCCronJobTemplate {
                    spec: VCJobSpec {
                        scheduler_name: "volcano".to_string(),
                        min_available: Some(1),
                        max_retry: None,
                        queue: None,
                        priority_class_name: None,
                        tasks: vec![VCJobTask {
                            name: "worker".to_string(),
                            replicas: 2,
                            template: serde_json::json!({"spec": {"containers": []}}),
                            policies: vec![],
                        }],
                        policies: vec![],
                        network_topology: None,
                    },
                },
            },
        };

        let json = serde_json::to_string(&cron).unwrap();
        let de: VCCronJob = serde_json::from_str(&json).unwrap();
        assert_eq!(cron, de);

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["kind"], "CronJob");
        assert_eq!(value["spec"]["schedule"], "*/5 * * * *");
        assert_eq!(value["spec"]["concurrencyPolicy"], "Forbid");
        assert_eq!(value["spec"]["suspend"], false);
        assert_eq!(value["spec"]["successfulJobsHistoryLimit"], 3);
        assert_eq!(value["spec"]["failedJobsHistoryLimit"], 1);
        assert_eq!(value["spec"]["startingDeadlineSeconds"], 60);
        assert!(value["spec"]["jobTemplate"]["spec"]
            .get("schedulerName")
            .is_some());
    }

    #[test]
    fn model_serving_serialization_roundtrip() {
        let ms = ModelServing {
            api_version: "workload.serving.volcano.sh/v1alpha1".to_string(),
            kind: "ModelServing".to_string(),
            metadata: VolcanoMetadata {
                name: "test-model".to_string(),
                namespace: "default".to_string(),
                labels: BTreeMap::from([(
                    "app.kubernetes.io/managed-by".to_string(),
                    "lattice".to_string(),
                )]),
                owner_references: vec![],
            },
            spec: ModelServingSpec {
                scheduler_name: "volcano".to_string(),
                replicas: 1,
                template: ServingGroupTemplate {
                    roles: vec![ModelServingRole {
                        name: "decode".to_string(),
                        replicas: 2,
                        entry_template: serde_json::json!({"spec": {"containers": []}}),
                        worker_replicas: 4,
                        worker_template: Some(
                            serde_json::json!({"spec": {"containers": [{"name": "worker"}]}}),
                        ),
                    }],
                    gang_policy: Some(GangPolicy {
                        min_role_replicas: BTreeMap::from([("decode".to_string(), 2)]),
                    }),
                    restart_grace_period_seconds: Some(30),
                    network_topology: None,
                },
                recovery_policy: Some(lattice_common::crd::RecoveryPolicy::ServingGroupRecreate),
                rollout_strategy: None,
            },
        };

        let json = serde_json::to_string(&ms).unwrap();
        let de: ModelServing = serde_json::from_str(&json).unwrap();
        assert_eq!(ms, de);

        // Verify camelCase serialization of key fields
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let role = &value["spec"]["template"]["roles"][0];
        assert!(role.get("entryTemplate").is_some());
        assert!(role.get("workerReplicas").is_some());
        assert!(role.get("workerTemplate").is_some());
        assert!(value["spec"]["template"]
            .get("restartGracePeriodSeconds")
            .is_some());
    }

    #[test]
    fn model_server_serialization_roundtrip() {
        let ms = KthenaModelServer {
            api_version: "networking.serving.volcano.sh/v1alpha1".to_string(),
            kind: "ModelServer".to_string(),
            metadata: VolcanoMetadata {
                name: "test-model".to_string(),
                namespace: "default".to_string(),
                labels: BTreeMap::new(),
                owner_references: vec![],
            },
            spec: KthenaModelServerSpec {
                model: Some("test-model/base".to_string()),
                inference_engine: "vLLM".to_string(),
                workload_selector: WorkloadSelector {
                    match_labels: BTreeMap::from([(
                        "modelserving.volcano.sh/name".to_string(),
                        "test-model".to_string(),
                    )]),
                    pd_group: Some(PdGroup {
                        group_key: "modelserving.volcano.sh/group-name".to_string(),
                        prefill_labels: BTreeMap::from([(
                            "modelserving.volcano.sh/role".to_string(),
                            "prefill".to_string(),
                        )]),
                        decode_labels: BTreeMap::from([(
                            "modelserving.volcano.sh/role".to_string(),
                            "decode".to_string(),
                        )]),
                    }),
                },
                workload_port: WorkloadPort {
                    port: 8000,
                    protocol: Some("http".to_string()),
                },
                traffic_policy: Some(KthenaTrafficPolicy {
                    retry: Some(KthenaRetryPolicy { attempts: Some(3) }),
                }),
                kv_connector: Some(KthenaKvConnector {
                    type_: lattice_common::crd::KvConnectorType::Nixl,
                }),
            },
        };

        let json = serde_json::to_string(&ms).unwrap();
        let de: KthenaModelServer = serde_json::from_str(&json).unwrap();
        assert_eq!(ms, de);

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value["spec"].get("workloadSelector").is_some());
        assert!(value["spec"].get("workloadPort").is_some());
        assert!(value["spec"].get("inferenceEngine").is_some());
        assert!(value["spec"]["workloadSelector"].get("pdGroup").is_some());
        assert_eq!(value["spec"]["kvConnector"]["type"], "nixl");
    }

    #[test]
    fn model_route_serialization_roundtrip() {
        let mr = KthenaModelRoute {
            api_version: "networking.serving.volcano.sh/v1alpha1".to_string(),
            kind: "ModelRoute".to_string(),
            metadata: VolcanoMetadata {
                name: "test-model-default".to_string(),
                namespace: "default".to_string(),
                labels: BTreeMap::new(),
                owner_references: vec![],
            },
            spec: KthenaModelRouteSpec {
                model_name: Some("test-model/base".to_string()),
                lora_adapters: Some(vec!["adapter-1".to_string()]),
                parent_refs: None,
                rules: vec![KthenaRouteRule {
                    name: "default".to_string(),
                    model_match: Some(KthenaModelMatch {
                        headers: BTreeMap::from([(
                            "x-model-version".to_string(),
                            KthenaHeaderMatch {
                                exact: Some("v2".to_string()),
                            },
                        )]),
                    }),
                    target_models: vec![KthenaTargetModel {
                        model_server_name: "test-model".to_string(),
                        weight: Some(100),
                    }],
                }],
                rate_limit: Some(KthenaRateLimit {
                    input_tokens_per_unit: Some(1000),
                    output_tokens_per_unit: Some(500),
                    unit: Some(lattice_common::crd::RateLimitUnit::Minute),
                }),
            },
        };

        let json = serde_json::to_string(&mr).unwrap();
        let de: KthenaModelRoute = serde_json::from_str(&json).unwrap();
        assert_eq!(mr, de);

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value["spec"].get("modelName").is_some());
        assert!(value["spec"].get("loraAdapters").is_some());
        assert!(value["spec"].get("rateLimit").is_some());
        assert_eq!(
            value["spec"]["rules"][0]["targetModels"][0]["modelServerName"],
            "test-model"
        );
    }

    #[test]
    fn autoscaling_policy_serialization_roundtrip() {
        let policy = KthenaAutoscalingPolicy {
            api_version: "workload.serving.volcano.sh/v1alpha1".to_string(),
            kind: "AutoscalingPolicy".to_string(),
            metadata: VolcanoMetadata {
                name: "test-model-decode-scaling".to_string(),
                namespace: "default".to_string(),
                labels: BTreeMap::new(),
                owner_references: vec![],
            },
            spec: KthenaAutoscalingPolicySpec {
                metrics: vec![KthenaAutoscalingMetric {
                    metric_name: "gpu_kv_cache_usage".to_string(),
                    target_value: "0.8".to_string(),
                }],
                tolerance_percent: Some(10),
                behavior: Some(KthenaAutoscalingBehavior {
                    scale_up: Some(KthenaScaleUpBehavior {
                        panic_policy: Some(KthenaPanicPolicy {
                            period: "30s".to_string(),
                            panic_threshold_percent: Some(200),
                            panic_mode_hold: Some("5m".to_string()),
                        }),
                        stable_policy: Some(KthenaStablePolicy {
                            stabilization_window: Some("1m".to_string()),
                            period: Some("30s".to_string()),
                        }),
                    }),
                    scale_down: Some(KthenaScaleDownBehavior {
                        stabilization_window: Some("5m".to_string()),
                        period: Some("1m".to_string()),
                    }),
                }),
            },
        };

        let json = serde_json::to_string(&policy).unwrap();
        let de: KthenaAutoscalingPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, de);

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value["spec"]["metrics"][0]["metricName"],
            "gpu_kv_cache_usage"
        );
        assert_eq!(value["spec"]["metrics"][0]["targetValue"], "0.8");
        assert_eq!(value["spec"]["tolerancePercent"], 10);
        assert!(value["spec"]["behavior"]["scaleUp"]["panicPolicy"]
            .get("panicThresholdPercent")
            .is_some());
        assert!(value["spec"]["behavior"]["scaleDown"]
            .get("stabilizationWindow")
            .is_some());
    }

    #[test]
    fn autoscaling_policy_binding_serialization_roundtrip() {
        let binding = KthenaAutoscalingPolicyBinding {
            api_version: "workload.serving.volcano.sh/v1alpha1".to_string(),
            kind: "AutoscalingPolicyBinding".to_string(),
            metadata: VolcanoMetadata {
                name: "test-model-decode-scaling".to_string(),
                namespace: "default".to_string(),
                labels: BTreeMap::new(),
                owner_references: vec![],
            },
            spec: KthenaAutoscalingPolicyBindingSpec {
                policy_ref: KthenaPolicyRef {
                    name: "test-model-decode-scaling".to_string(),
                },
                homogeneous_target: KthenaHomogeneousTarget {
                    target: KthenaAutoscalingTarget {
                        target_ref: KthenaTargetRef {
                            kind: "ModelServing".to_string(),
                            name: "test-model".to_string(),
                        },
                        sub_targets: Some(KthenaSubTarget {
                            kind: "Role".to_string(),
                            name: "decode".to_string(),
                        }),
                        metric_endpoint: Some(KthenaMetricEndpoint {
                            uri: Some("/metrics".to_string()),
                            port: Some(9090),
                        }),
                    },
                    min_replicas: 1,
                    max_replicas: 10,
                },
            },
        };

        let json = serde_json::to_string(&binding).unwrap();
        let de: KthenaAutoscalingPolicyBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(binding, de);

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value["spec"]["policyRef"]["name"],
            "test-model-decode-scaling"
        );
        assert_eq!(
            value["spec"]["homogeneousTarget"]["target"]["targetRef"]["kind"],
            "ModelServing"
        );
        assert_eq!(
            value["spec"]["homogeneousTarget"]["target"]["subTargets"]["kind"],
            "Role"
        );
        assert_eq!(
            value["spec"]["homogeneousTarget"]["target"]["subTargets"]["name"],
            "decode"
        );
        assert_eq!(value["spec"]["homogeneousTarget"]["minReplicas"], 1);
        assert_eq!(value["spec"]["homogeneousTarget"]["maxReplicas"], 10);
    }

    #[test]
    fn network_topology_value_soft() {
        use lattice_common::crd::{TopologyMode, WorkloadNetworkTopology};

        let topo = WorkloadNetworkTopology {
            mode: TopologyMode::Soft,
            max_tier: Some(2),
        };
        let value = network_topology_value(&topo);
        assert_eq!(value["mode"], "soft");
        assert_eq!(value["highestTierAllowed"], 2);
    }

    #[test]
    fn network_topology_value_hard() {
        use lattice_common::crd::{TopologyMode, WorkloadNetworkTopology};

        let topo = WorkloadNetworkTopology {
            mode: TopologyMode::Hard,
            max_tier: Some(1),
        };
        let value = network_topology_value(&topo);
        assert_eq!(value["mode"], "hard");
        assert_eq!(value["highestTierAllowed"], 1);
    }

    #[test]
    fn network_topology_value_no_tier() {
        use lattice_common::crd::{TopologyMode, WorkloadNetworkTopology};

        let topo = WorkloadNetworkTopology {
            mode: TopologyMode::Soft,
            max_tier: None,
        };
        let value = network_topology_value(&topo);
        assert_eq!(value["mode"], "soft");
        assert!(value.get("highestTierAllowed").is_none());
    }

    #[test]
    fn vcjob_with_network_topology_roundtrip() {
        use lattice_common::crd::{TopologyMode, WorkloadNetworkTopology};

        let topo = WorkloadNetworkTopology {
            mode: TopologyMode::Hard,
            max_tier: Some(1),
        };
        let vcjob = VCJob {
            api_version: "batch.volcano.sh/v1alpha1".to_string(),
            kind: "Job".to_string(),
            metadata: VolcanoMetadata {
                name: "topo-job".to_string(),
                namespace: "default".to_string(),
                labels: BTreeMap::new(),
                owner_references: vec![],
            },
            spec: VCJobSpec {
                scheduler_name: "volcano".to_string(),
                min_available: Some(2),
                max_retry: None,
                queue: None,
                priority_class_name: None,
                tasks: vec![],
                policies: vec![],
                network_topology: Some(network_topology_value(&topo)),
            },
        };

        let json = serde_json::to_string(&vcjob).unwrap();
        let de: VCJob = serde_json::from_str(&json).unwrap();
        assert_eq!(vcjob, de);

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["spec"]["networkTopology"]["mode"], "hard");
        assert_eq!(value["spec"]["networkTopology"]["highestTierAllowed"], 1);
    }
}
