//! Custom Resource Definitions for Lattice
//!
//! This module contains all CRD definitions used by the Lattice operator.

mod cluster;
mod external_service;
mod providers;
mod service;
mod types;

pub use cluster::{LatticeCluster, LatticeClusterSpec, LatticeClusterStatus};
pub use external_service::{
    ExternalServicePhase, LatticeExternalService, LatticeExternalServiceSpec,
    LatticeExternalServiceStatus, ParsedEndpoint, Resolution,
};
pub use service::{
    CertIssuerRef, ContainerSpec, DependencyDirection, DeploySpec, DeployStrategy, ExecProbe,
    FileMount, GrpcProbe, HttpGetProbe, HttpHeader, InboundPolicy, IngressPath, IngressSpec,
    IngressTls, LatticeService, LatticeServiceSpec, LatticeServiceStatus, OutboundPolicy,
    PathMatchType, PortSpec, Probe, RateLimitConfig, RateLimitSpec, ReplicaSpec, ResourceMetadata,
    ResourceSpec, ResourceType, RetryConfig, ServicePhase, ServicePortsSpec, TcpSocketProbe,
    TimeoutConfig, TlsMode, VolumeAccessMode, VolumeMount, VolumeParams,
};
pub use types::{
    AwsConfig, BootstrapProvider, ClusterPhase, Condition, ConditionStatus, DockerConfig,
    EndpointsSpec, Ipv4PoolConfig, Ipv6PoolConfig, KubernetesSpec, NetworkPool, NetworkingSpec,
    NodeSpec, OpenStackConfig, ProviderConfig, ProviderSpec, ProviderType, ProxmoxConfig,
    SecretRef, ServiceRef, ServiceSpec, WorkloadSpec,
};
