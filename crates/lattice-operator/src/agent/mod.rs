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
//! 3. Cell exports CAPI resources via `clusterctl move --to-directory`
//! 4. Cell sends `PivotManifestsCommand` with manifests
//! 5. Agent imports via `clusterctl move --from-directory`
//! 6. Agent sends `PivotComplete`

pub mod client;
pub mod connection;
pub mod mtls;
pub mod server;

pub use client::AgentClient;
pub use connection::{AgentConnection, AgentRegistry, PostPivotManifests};
pub use mtls::{ClientMtlsConfig, MtlsError, ServerMtlsConfig};
pub use server::AgentServer;
