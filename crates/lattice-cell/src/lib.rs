//! Lattice Cell - Parent cluster infrastructure
//!
//! This crate provides the server-side infrastructure for parent/management clusters:
//!
//! - **gRPC Server**: Accepts agent connections from child clusters
//! - **Bootstrap Server**: HTTP endpoints for kubeadm callbacks and CSR signing
//! - **K8s API Proxy**: Read-only proxy for CAPI controller access to children
//! - **Connection Registry**: Tracks connected agents
//! - **Resource Distribution**: Fetching resources to sync to children
//! - **Move Sender**: gRPC-based move command sender for distributed pivot

pub mod bootstrap;
pub mod cilium;
pub mod connection;
pub mod k8s_proxy;
pub mod move_sender;
pub mod parent;
pub mod resources;
pub mod server;

pub use bootstrap::{
    bootstrap_router, generate_autoscaler_manifests, generate_aws_addon_manifests,
    generate_bootstrap_bundle, generate_docker_addon_manifests, BootstrapBundleConfig,
    BootstrapState, ClusterRegistration, DefaultManifestGenerator, ManifestGenerator,
};
pub use connection::{
    AgentConnection, AgentRegistry, PivotSourceManifests, PostPivotManifests, SendError,
    SharedAgentRegistry, UnpivotManifests,
};
pub use k8s_proxy::{generate_proxy_kubeconfig, start_proxy_server, ProxyConfig, ProxyError};
pub use move_sender::GrpcMoveCommandSender;
pub use parent::{load_or_create_ca, CellServerError, ParentConfig, ParentServers};
pub use resources::{fetch_distributable_resources, DistributableResources, ResourceError};
pub use server::AgentServer;
