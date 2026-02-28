//! Volcano compiler crate for Lattice batch and model serving workloads
//!
//! Compiles `LatticeJob` specs into Volcano VCJob resources and `LatticeModel`
//! specs into Kthena ModelServing resources for gang scheduling.
//! Pure compilation crate — no controller logic.

pub mod autoscaling_compiler;
mod compiler;
mod model_serving_compiler;
pub mod routing_compiler;
mod types;

pub use autoscaling_compiler::{compile_model_autoscaling, CompiledAutoscaling};
pub use compiler::{compile_vccronjob, compile_vcjob};
pub use model_serving_compiler::{compile_model_serving, ModelServingCompilation, RoleTemplates};
pub use routing_compiler::{compile_model_routing, CompiledRouting};
pub use types::{
    compile_service_pod_group, GangPolicy, KthenaAutoscalingBehavior, KthenaAutoscalingMetric,
    KthenaAutoscalingPolicy, KthenaAutoscalingPolicyBinding, KthenaAutoscalingPolicyBindingSpec,
    KthenaAutoscalingPolicySpec, KthenaAutoscalingTarget, KthenaHeaderMatch,
    KthenaHomogeneousTarget, KthenaKvConnector, KthenaMetricEndpoint, KthenaModelMatch,
    KthenaModelRoute, KthenaModelRouteSpec, KthenaModelServer, KthenaModelServerSpec,
    KthenaPanicPolicy, KthenaParentRef, KthenaPolicyRef, KthenaRateLimit, KthenaRetryPolicy,
    KthenaRouteRule, KthenaScaleDownBehavior, KthenaScaleUpBehavior, KthenaStablePolicy,
    KthenaSubTarget, KthenaTargetModel, KthenaTargetRef, KthenaTrafficPolicy, ModelServing,
    ModelServingRole, ModelServingSpec, PdGroup, PodGroup, PodGroupSpec,
    RollingUpdateConfiguration, RolloutStrategy, ServingGroupTemplate, VCCronJob, VCCronJobSpec,
    VCCronJobTemplate, VCJob, VCJobSpec, VCJobTask, VCJobTaskPolicy, VolcanoMetadata, WorkloadPort,
    WorkloadSelector, PODGROUP_ANNOTATION,
};
