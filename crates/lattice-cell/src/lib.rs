//! Lattice Cell - Parent cluster infrastructure
//!
//! This crate provides the server-side infrastructure for parent/management clusters:
//!
//! - **gRPC Server**: Accepts agent connections from child clusters
//! - **Bootstrap Server**: HTTP endpoints for kubeadm callbacks and CSR signing
//! - **K8s API Proxy**: Read-only proxy for CAPI controller access to children
//! - **Connection Registry**: Tracks connected agents with connection notifications
//! - **Resource Distribution**: Fetching resources to sync to children
//! - **Move Sender**: gRPC-based move command sender for distributed pivot
//! - **Resilient Tunnel**: K8s API tunneling with automatic reconnection

pub mod blocklist;
pub mod bootstrap;
// must be declared before server (server uses it)
pub mod capi_proxy;
pub mod cilium;
pub mod connection;
pub mod exec_tunnel;
pub mod k8s_tunnel;
pub mod kubeconfig;
pub mod move_sender;
pub mod parent;
pub mod peer_routes;
pub mod resilient_tunnel;
pub mod resources;
pub mod route_reconciler;
pub mod server;
pub mod state_sync;
pub use bootstrap::{
    bootstrap_router, generate_bootstrap_bundle, generate_for_provider, BootstrapBundleConfig,
    BootstrapState, ClusterRegistration, DefaultManifestGenerator, ManifestGenerator,
};
pub use capi_proxy::{start_capi_proxy, CapiProxyConfig, CapiProxyError};
pub use connection::{
    AgentConnection, AgentRegistry, ClusterInfo, K8sResponseRegistry, KubeconfigProxyConfig,
    PivotSourceManifests, RouteInfo, SendError, SharedAgentRegistry, UnpivotManifests,
    HEARTBEAT_STALE_THRESHOLD,
};
pub use exec_tunnel::{
    start_exec_session, ExecRequestParams, ExecSession, ExecTunnelError, EXEC_CHANNEL_SIZE,
};
pub use k8s_tunnel::{
    build_http_response, tunnel_request_streaming, K8sRequestParams, TunnelError, DEFAULT_TIMEOUT,
};
pub use kubeconfig::patch_kubeconfig_for_proxy;
pub use move_sender::GrpcMoveCommandSender;
pub use parent::{create_ca, load_ca, CellServerError, ParentConfig, ParentServers};
pub use resilient_tunnel::tunnel_request;
pub use resources::{
    distributable_resources_to_proto, fetch_distributable_resources, ResourceError,
};
pub use server::{AgentServer, GrpcServerConfig, PeerRouteConfig, SharedPeerRouteConfig};
