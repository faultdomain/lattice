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
    CertIssuerRef, CircuitBreakerPolicy, ContainerSpec, DependencyDirection, DeploySpec,
    DeployStrategy, ExecProbe, FileMount, GrpcProbe, HeaderPolicy, HttpGetProbe, HttpHeader,
    InboundTrafficPolicy, IngressPath, IngressSpec, IngressTls, LatticeService, LatticeServiceSpec,
    LatticeServiceStatus, OutboundTrafficPolicy, PathMatchType, PortSpec, Probe, RateLimitSpec,
    ReplicaSpec, ResourceSpec, ResourceType, RetryPolicy, ServicePhase, ServicePortsSpec,
    TcpSocketProbe, TimeoutPolicy, TlsMode, VolumeAccessMode, VolumeMount, VolumeParams,
};
pub use types::{
    BootstrapProvider, ClusterPhase, Condition, ConditionStatus, DockerConfig, EndpointsSpec,
    GitOpsSpec, Ipv4PoolConfig, Ipv6PoolConfig, KubernetesSpec, NetworkPool, NetworkingSpec,
    NodeSpec, OpenStackConfig, ProviderConfig, ProviderSpec, ProviderType, ProxmoxConfig,
    SecretRef, ServiceRef, ServiceSpec, WorkloadSpec,
};
