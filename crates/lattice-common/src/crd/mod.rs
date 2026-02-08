//! Custom Resource Definitions for Lattice
//!
//! This module contains all CRD definitions used by the Lattice operator.

mod backup_policy;
mod cedar_policy;
mod cloud_provider;
mod cluster;
mod external_service;
mod model;
mod oidc_provider;
mod providers;
mod restore;
mod secrets_provider;
mod service;
mod service_policy;
mod types;

pub use backup_policy::{
    BackupPolicyPhase, BackupRetentionSpec, BackupScopeSpec, BackupStorageProvider,
    BackupStorageSpec, LatticeBackupPolicy, LatticeBackupPolicySpec, LatticeBackupPolicyStatus,
    S3StorageConfig, VolumeSnapshotConfig, VolumeSnapshotMethod,
};
pub use cedar_policy::{CedarPolicy, CedarPolicyPhase, CedarPolicySpec, CedarPolicyStatus};
pub use cloud_provider::{
    AwsProviderConfig, CloudProvider, CloudProviderPhase, CloudProviderSpec, CloudProviderStatus,
    CloudProviderType, OpenStackProviderConfig, ProxmoxProviderConfig,
};
pub use cluster::{
    ChildClusterHealth, LatticeCluster, LatticeClusterSpec, LatticeClusterStatus, WorkerPoolStatus,
};
pub use external_service::{
    ExternalServicePhase, LatticeExternalService, LatticeExternalServiceSpec,
    LatticeExternalServiceStatus, ParsedEndpoint, Resolution,
};
pub use model::{
    ModelArtifact, ModelArtifactPhase, ModelArtifactSpec, ModelArtifactStatus, ModelParams,
    MODEL_READY_GATE, RETRY_BASE_DELAY_SECS, RETRY_MAX_DELAY_SECS,
};
pub use oidc_provider::{
    OIDCProvider, OIDCProviderPhase, OIDCProviderSpec, OIDCProviderStatus, RequiredClaim,
};
pub use restore::{
    LatticeRestore, LatticeRestoreSpec, LatticeRestoreStatus, RestoreOrdering, RestorePhase,
};
pub use secrets_provider::{
    SecretProvider, SecretProviderPhase, SecretProviderSpec, SecretProviderStatus,
};
pub use service::{
    AutoscalingMetric, BackupHook, BackupHooksSpec, CertIssuerRef, ContainerSpec,
    DependencyDirection, DeploySpec, DeployStrategy, ExecProbe, FileMount, GPUSpec,
    HookErrorAction, HttpGetProbe, HttpHeader, InboundPolicy, IngressPath, IngressSpec, IngressTls,
    LatticeService, LatticeServiceSpec, LatticeServiceStatus, OutboundPolicy, PathMatchType,
    PortSpec, Probe, ReplicaSpec, ResourceMetadata, ResourceQuantity, ResourceRequirements,
    ResourceSpec, ResourceType, RetryConfig, SecurityContext, ServiceBackupSpec, ServicePhase,
    ServicePortsSpec, SidecarSpec, TimeoutConfig, TlsMode, VolumeAccessMode, VolumeBackupDefault,
    VolumeBackupSpec, VolumeMount, VolumeParams,
};
pub use service_policy::{
    LabelSelectorOperator, LabelSelectorRequirement, LatticeServicePolicy,
    LatticeServicePolicySpec, LatticeServicePolicyStatus, NamespaceSelector, ServicePolicyPhase,
    ServiceSelector,
};
pub use types::{
    AwsConfig, BootstrapProvider, ClusterPhase, Condition, ConditionStatus, ControlPlaneSpec,
    DockerConfig, EndpointsSpec, InstanceType, Ipv4PoolConfig, Ipv6PoolConfig, KubernetesSpec,
    NetworkPool, NetworkingSpec, NodeResourceSpec, NodeSpec, NodeTaint, OpenStackConfig,
    ProviderConfig, ProviderSpec, ProviderType, ProxmoxConfig, RootVolume, SecretRef, ServiceRef,
    ServiceSpec, TaintEffect, WorkerPoolSpec,
};

// =============================================================================

/// Serde default helper returning `true`
pub(crate) fn default_true() -> bool {
    true
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
pub(crate) fn validate_dns_identifier(s: &str, allow_trailing_hyphen: bool) -> Result<(), String> {
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
