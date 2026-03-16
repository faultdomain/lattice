//! Custom Resource Definitions for Lattice
//!
//! This module contains all CRD definitions used by the Lattice operator.

mod backup_store;
mod cedar_policy;
mod cluster;
mod cluster_backup;
mod cluster_routes;
mod external_endpoint;
mod infra_provider;
mod job;
mod mesh_member;
mod model_serving;
mod observability;
mod oidc_provider;
mod providers;
mod restore;
mod secrets_provider;
mod service;
mod topology;
mod types;
pub mod workload;

pub use backup_store::{
    AzureStorageConfig, BackupStorageProvider, BackupStorageSpec, BackupStore, BackupStorePhase,
    BackupStoreSpec, BackupStoreStatus, GcsStorageConfig, S3StorageConfig,
};
pub use cedar_policy::{CedarPolicy, CedarPolicyPhase, CedarPolicySpec, CedarPolicyStatus};
pub use cluster::{
    BackupsConfig, ChildClusterHealth, InfraComponentPhase, InfraComponentStatus, LatticeCluster,
    LatticeClusterSpec, LatticeClusterStatus, MonitoringConfig, PoolResourceSummary,
    WorkerPoolStatus,
};
pub use cluster_backup::{
    BackupRetentionSpec, BackupScopeSpec, ClusterBackupPhase, LatticeClusterBackup,
    LatticeClusterBackupSpec, LatticeClusterBackupStatus,
};
pub use cluster_backup::{LabelSelectorOperator, LabelSelectorRequirement, NamespaceSelector};
pub use cluster_routes::{
    ClusterRoute, ClusterRoutesPhase, LatticeClusterRoutes, LatticeClusterRoutesSpec,
    LatticeClusterRoutesStatus,
};
pub use external_endpoint::{ParsedEndpoint, Resolution};
pub use infra_provider::{
    AwsProviderConfig, InfraProvider, InfraProviderPhase, InfraProviderSpec, InfraProviderStatus,
    InfraProviderType, OpenStackProviderConfig, ProxmoxProviderConfig,
};
pub use job::{
    ConcurrencyPolicy, JobPhase, JobTaskSpec, LatticeJob, LatticeJobSpec, LatticeJobStatus,
    NcclConfig, RestartPolicy, TrainingConfig, TrainingFramework, VolcanoPolicy,
    VolcanoPolicyAction, VolcanoPolicyEvent,
};
pub use mesh_member::{
    derived_name, AppliedResourceRef, EgressRule, EgressTarget, LatticeMeshMember,
    LatticeMeshMemberSpec, LatticeMeshMemberStatus, MeshMemberPhase, MeshMemberPort,
    MeshMemberScope, MeshMemberTarget, PeerAuth,
};
pub use model_serving::{
    HeaderMatchValue, InferenceEngine, KvConnector, KvConnectorType, LatticeModel,
    LatticeModelSpec, LatticeModelStatus, ModelAutoscalingBehavior, ModelAutoscalingSpec,
    ModelCondition, ModelMatch, ModelParentRef, ModelRoleSpec, ModelRouteRule, ModelRouteSpec,
    ModelRoutingSpec, ModelScaleDownBehavior, ModelScaleUpBehavior, ModelServingPhase,
    ModelSourceSpec, RateLimit, RateLimitUnit, RecoveryPolicy, RetryPolicy, SecretKeySelector,
    TargetModel, TrafficPolicy, DEFAULT_KV_SIDE_CHANNEL_PORT,
};
pub use observability::{
    scrape_metrics, MetricsConfig, MetricsScraper, MetricsSnapshot, NoopMetricsScraper,
    ObservabilitySpec,
};
pub use oidc_provider::{
    OIDCProvider, OIDCProviderPhase, OIDCProviderSpec, OIDCProviderStatus, RequiredClaim,
};
pub use providers::{
    AdditionalNetwork, AwsConfig, DockerConfig, Ipv4PoolConfig, Ipv6PoolConfig, OpenStackConfig,
    ProxmoxConfig,
};
pub use restore::{LatticeRestore, LatticeRestoreSpec, LatticeRestoreStatus, RestorePhase};
pub use secrets_provider::{
    SecretProvider, SecretProviderPhase, SecretProviderSpec, SecretProviderStatus,
};
pub use service::{LatticeService, LatticeServiceSpec, LatticeServiceStatus, ServicePhase};
pub use topology::{
    LabelDiscoveryConfig, LabelTier, NetworkTopologyConfig, TopologyDiscoverySpec,
    UfmDiscoveryConfig,
};
pub use types::{
    BootstrapProvider, CertPolicy, ClusterConfig, ClusterPhase, Condition, ConditionStatus,
    ControlPlaneSpec, EndpointsSpec, InstanceType, KubernetesSpec, NodeResourceSpec, NodeSpec,
    NodeTaint, ProviderConfig, ProviderSpec, ProviderType, RegistryMirror, RootVolume, SecretRef,
    ServiceRef, ServiceSpec, TaintEffect, WorkerPoolSpec,
};
pub use workload::backup::{
    BackupHook, BackupHooksSpec, HookErrorAction, ServiceBackupSpec, VolumeBackupDefault,
    VolumeBackupSpec,
};
pub use workload::container::{
    has_unknown_binary_entrypoint, ContainerSpec, ExecProbe, FileMount, HttpGetProbe, HttpHeader,
    Probe, SecurityContext, SidecarSpec, VolumeMount,
};
pub use workload::cost::{CostBreakdown, CostEstimate};
pub use workload::deploy::{CanarySpec, DeploySpec, DeployStrategy};
pub use workload::ingress::{
    CertIssuerRef, GrpcMethodMatch, HeaderMatch, HeaderMatchType, IngressSpec, IngressTls,
    PathMatch, PathMatchType, RouteKind, RouteMatch, RouteRule, RouteSpec,
};
pub use workload::ports::{PortSpec, ServicePortsSpec};
pub use workload::resources::{
    DependencyDirection, ExternalServiceParams, GpuParams, ResourceMetadata, ResourceParams,
    ResourceQuantity, ResourceRequirements, ResourceSpec, ResourceType, SecretParams,
    VolumeAccessMode, VolumeParams,
};
pub use workload::scaling::{AutoscalingMetric, AutoscalingSpec};
pub use workload::spec::{RuntimeSpec, WorkloadSpec};
pub use workload::topology::{TopologyMode, WorkloadNetworkTopology};

// =============================================================================

/// Serde default helper returning `true`
pub(crate) fn default_true() -> bool {
    true
}

/// Schema helper: marks a field as `x-kubernetes-preserve-unknown-fields: true`.
///
/// Without this, the Kubernetes API server prunes nested objects inside
/// `additionalProperties` fields (e.g., `endpoints: {"default": "https://..."}` → `{}`).
///
/// Used via `#[schemars(schema_with = "crate::crd::preserve_unknown_fields")]`.
pub(crate) fn preserve_unknown_fields(
    _gen: &mut schemars::gen::SchemaGenerator,
) -> schemars::schema::Schema {
    let mut obj = schemars::schema::SchemaObject {
        instance_type: Some(schemars::schema::InstanceType::Object.into()),
        ..Default::default()
    };
    obj.extensions.insert(
        "x-kubernetes-preserve-unknown-fields".to_string(),
        serde_json::json!(true),
    );
    obj.into()
}

/// Validate a DNS-style identifier (lowercase alphanumeric with hyphens).
///
/// Rules:
/// - Must not be empty
/// - Must start with a lowercase letter
/// - May contain lowercase letters, digits, and hyphens
/// - Must not end with a hyphen (if `allow_trailing_hyphen` is false)
///
/// Used for pool IDs, custom resource types, and other identifiers.
pub fn validate_dns_identifier(s: &str, allow_trailing_hyphen: bool) -> Result<(), String> {
    if s.is_empty() {
        return Err("identifier cannot be empty".to_string());
    }

    let mut chars = s.chars();

    // First char must be a lowercase letter
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => {
            return Err(format!(
                "identifier must start with lowercase letter: {}",
                s
            ))
        }
    }

    // Rest must be lowercase alphanumeric or hyphen
    for c in chars {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
            return Err(format!(
                "identifier must be lowercase alphanumeric with hyphens: {}",
                s
            ));
        }
    }

    // Check trailing hyphen
    if !allow_trailing_hyphen && s.ends_with('-') {
        return Err(format!("identifier cannot end with hyphen: {}", s));
    }

    Ok(())
}

/// Validate that a string is a valid K8s DNS label.
///
/// Combines format validation (via [`validate_dns_identifier`]) with the
/// 63-character length limit. `field` is used in error messages to identify
/// what kind of name failed (e.g. "container name", "port name").
pub fn validate_dns_label(name: &str, field: &str) -> Result<(), String> {
    if name.len() > 63 {
        return Err(format!(
            "{} '{}' exceeds 63 character DNS label limit",
            field, name
        ));
    }
    validate_dns_identifier(name, false).map_err(|e| format!("{} '{}': {}", field, name, e))
}
