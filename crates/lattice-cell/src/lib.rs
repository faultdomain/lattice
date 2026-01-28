//! Lattice Cell - Parent cluster infrastructure
//!
//! This crate provides the server-side infrastructure for parent/management clusters:
//!
//! - **gRPC Server**: Accepts agent connections from child clusters
//! - **Bootstrap Server**: HTTP endpoints for kubeadm callbacks and CSR signing
//! - **Connection Registry**: Tracks connected agents
//! - **Resource Distribution**: Fetching resources to sync to children

pub mod bootstrap;
pub mod cilium;
pub mod connection;
pub mod parent;
pub mod resources;
pub mod server;

pub use bootstrap::{
    bootstrap_router, generate_autoscaler_manifests, generate_aws_addon_manifests,
    generate_crs_yaml_manifests, generate_docker_addon_manifests, BootstrapState,
    ClusterRegistration, DefaultManifestGenerator, ManifestGenerator, ProviderCredentials,
};
pub use connection::{
    AgentConnection, AgentRegistry, PivotSourceManifests, PostPivotManifests, SendError,
    SharedAgentRegistry, UnpivotManifests,
};
pub use parent::{load_or_create_ca, CellServerError, ParentConfig, ParentServers};
pub use resources::{fetch_distributable_resources, DistributableResources, ResourceError};
pub use server::{
    cleanup_stale_unpivot_secrets, should_cleanup_unpivot_manifests, AgentServer,
    UNPIVOT_MANIFESTS_SECRET_PREFIX,
};
