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
    FileMount, GrpcProbe, HttpGetProbe, HttpHeader, IngressPath, IngressSpec, IngressTls,
    LatticeService, LatticeServiceSpec, LatticeServiceStatus, PathMatchType, PortSpec, Probe,
    ReplicaSpec, ResourceSpec, ResourceType, ServicePhase, ServicePortsSpec, TcpSocketProbe,
    TlsMode, VolumeMount,
};
pub use types::{
    BootstrapProvider, ClusterPhase, Condition, ConditionStatus, DockerConfig, EndpointsSpec,
    GitOpsSpec, Ipv4PoolConfig, Ipv6PoolConfig, KubernetesSpec, NetworkPool, NetworkingSpec,
    NodeSpec, ProviderConfig, ProviderSpec, ProviderType, ProxmoxConfig, SecretRef, ServiceRef,
    ServiceSpec, WorkloadSpec,
};
