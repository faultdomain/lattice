//! Custom Resource Definitions for Lattice
//!
//! This module contains all CRD definitions used by the Lattice operator.

mod cloud_provider;
mod cluster;
mod external_service;
mod providers;
mod secrets_provider;
mod service;
mod types;

pub use cloud_provider::{
    AwsProviderConfig, CloudProvider, CloudProviderPhase, CloudProviderSpec, CloudProviderStatus,
    CloudProviderType, OpenStackProviderConfig, ProxmoxProviderConfig,
};
pub use cluster::{LatticeCluster, LatticeClusterSpec, LatticeClusterStatus, WorkerPoolStatus};
pub use external_service::{
    ExternalServicePhase, LatticeExternalService, LatticeExternalServiceSpec,
    LatticeExternalServiceStatus, ParsedEndpoint, Resolution,
};
pub use secrets_provider::{
    SecretsProvider, SecretsProviderPhase, SecretsProviderSpec, SecretsProviderStatus,
    VaultAuthMethod,
};
pub use service::{
    CertIssuerRef, ContainerSpec, DependencyDirection, DeploySpec, DeployStrategy, ExecProbe,
    FileMount, HttpGetProbe, HttpHeader, InboundPolicy, IngressPath, IngressSpec, IngressTls,
    LatticeService, LatticeServiceSpec, LatticeServiceStatus, OutboundPolicy, PathMatchType,
    PortSpec, Probe, RateLimitConfig, RateLimitSpec, ReplicaSpec, ResourceMetadata,
    ResourceQuantity, ResourceRequirements, ResourceSpec, ResourceType, RetryConfig,
    SecurityContext, ServicePhase, ServicePortsSpec, SidecarSpec, TimeoutConfig, TlsMode,
    VolumeAccessMode, VolumeMount, VolumeParams,
};
pub use types::{
    AwsConfig, BootstrapProvider, ClusterPhase, Condition, ConditionStatus, DockerConfig,
    EndpointsSpec, Ipv4PoolConfig, Ipv6PoolConfig, KubernetesSpec, NetworkPool, NetworkingSpec,
    NodeSpec, NodeTaint, OpenStackConfig, ProviderConfig, ProviderSpec, ProviderType,
    ProxmoxConfig, SecretRef, ServiceRef, ServiceSpec, TaintEffect, WorkerPoolSpec, WorkloadSpec,
};
