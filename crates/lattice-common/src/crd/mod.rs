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
    ContainerSpec, DependencyDirection, DeploySpec, DeployStrategy, ExecProbe, FileMount,
    GrpcProbe, HttpGetProbe, HttpHeader, LatticeService, LatticeServiceSpec, LatticeServiceStatus,
    PortSpec, Probe, ReplicaSpec, ResourceSpec, ResourceType, ServicePhase, ServicePortsSpec,
    TcpSocketProbe, VolumeMount,
};
pub use types::{
    AwsConfig, BootstrapProvider, ClusterPhase, Condition, ConditionStatus, DockerConfig,
    EndpointsSpec, GitOpsSpec, GitSecretRef, KubernetesSpec, NetworkPool, NetworkingSpec, NodeSpec,
    OpenstackConfig, ProviderConfig, ProviderSpec, ProviderType, ProxmoxConfig, ServiceRef,
    ServiceSpec, WorkloadSpec,
};
