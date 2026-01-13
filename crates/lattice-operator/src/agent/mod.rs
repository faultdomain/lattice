//! Agent-Cell communication module
//!
//! This module implements the gRPC-based communication between agents (running on
//! workload clusters) and cells (management clusters).
//!
//! # Architecture
//!
//! All connections are **outbound** from agents to cells. Cells never initiate
//! connections to agents. This ensures firewall-friendly operation.
//!
//! ## Services
//!
//! - **Control Stream** (`StreamMessages`): Bidirectional stream for heartbeats,
//!   commands, and status updates.
//! - **K8s API Proxy** (`ProxyKubernetesAPI`): Allows the cell to execute kubectl
//!   commands on the agent's cluster through the gRPC tunnel.
//!
//! # Security Model
//!
//! All gRPC connections use mTLS:
//! - Cell presents server certificate, verifies agent client certificates
//! - Agent presents client certificate signed by cell CA
//! - Cluster ID is extracted from agent certificate CN
//!
//! # Pivot Flow
//!
//! 1. Cell sends `StartPivotCommand` via control stream
//! 2. Agent enters PIVOTING state, sends `PivotStarted`
//! 3. Cell executes `clusterctl move --to-kubeconfig <proxy-kubeconfig>`
//! 4. Proxy kubeconfig routes requests through `ProxyKubernetesAPI`
//! 5. Agent detects CAPI resources, sends `PivotComplete`

pub mod client;
pub mod connection;
pub mod mtls;
pub mod proxy;
pub mod server;

pub use client::AgentClient;
pub use connection::{AgentConnection, AgentRegistry, PostPivotManifests, ProxyChannels};
pub use mtls::{ClientMtlsConfig, MtlsError, ServerMtlsConfig};
pub use proxy::{generate_central_proxy_kubeconfig, start_central_proxy, CENTRAL_PROXY_PORT};
pub use server::AgentServer;
