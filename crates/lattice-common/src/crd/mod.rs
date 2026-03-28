//! Custom Resource Definitions for Lattice
//!
//! This module contains all CRD definitions used by the Lattice operator.

mod backup_store;
mod cedar_policy;
mod cluster;
mod cluster_backup;
mod cluster_routes;
mod dns_provider;
mod external_endpoint;
mod infra_provider;
mod issuer;
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
pub use dns_provider::{
    AzureDnsConfig, CloudflareConfig, DNSProvider, DNSProviderPhase, DNSProviderSpec,
    DNSProviderStatus, DNSProviderType, DesignateConfig, GoogleDnsConfig, PiholeConfig,
    Route53Config,
};
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
pub use issuer::{
    AcmeIssuerSpec, CaIssuerSpec, CertIssuer, CertIssuerPhase, CertIssuerSpec, CertIssuerStatus,
    DnsConfig, IssuerType, VaultIssuerSpec,
};
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
    MeshMemberScope, MeshMemberTarget, NetworkProtocol, PeerAuth,
};
pub use model_serving::{
    HeaderMatchValue, InferenceEngine, KvConnector, KvConnectorType, LatticeModel,
    LatticeModelSpec, LatticeModelStatus, ModelAutoscalingBehavior, ModelAutoscalingSpec,
    ModelCondition, ModelIngressSpec, ModelMatch, ModelParentRef, ModelRoleSpec, ModelRouteRule,
    ModelRouteSpec, ModelRoutingSpec, ModelScaleDownBehavior, ModelScaleUpBehavior,
    ModelServingPhase, ModelSourceSpec, RateLimit, RateLimitUnit, RecoveryPolicy, RetryPolicy,
    SecretKeySelector, TargetModel, TrafficPolicy, DEFAULT_KV_SIDE_CHANNEL_PORT,
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
    _gen: &mut schemars::SchemaGenerator,
) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "x-kubernetes-preserve-unknown-fields": true
    })
}

/// Validate that a string is a valid K8s DNS label.
///
/// Sanitizes the input via [`sanitize_dns_label`] and checks that the result
/// matches the original. `field` is used in error messages to identify
/// what kind of name failed (e.g. "container name", "port name").
pub fn validate_dns_label(name: &str, field: &str) -> Result<(), String> {
    match crate::sanitize_dns_label(name) {
        Some(ref sanitized) if sanitized == name => Ok(()),
        _ => Err(format!(
            "{} '{}' is not a valid DNS label (must be lowercase alphanumeric with hyphens, max 63 chars)",
            field, name
        )),
    }
}
