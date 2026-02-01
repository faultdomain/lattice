//! Protocol buffer definitions for Lattice agent-cell communication.
//!
//! This crate provides the gRPC service and message definitions for communication
//! between Lattice workload cluster agents and their parent cell (management cluster).
//!
//! # Architecture
//!
//! All connections are initiated **outbound** from workload clusters - cells never
//! connect directly to agents. This outbound-only architecture provides several benefits:
//!
//! - **Firewall friendly**: No inbound ports required on workload clusters
//! - **No attack surface**: Workload clusters don't expose network services
//! - **NAT traversal**: Works behind NAT without port forwarding
//!
//! # Communication Flow
//!
//! ```text
//! ┌─────────────────────────┐
//! │     Parent Cell         │
//! │  (Management Cluster)   │
//! │                         │
//! │  ┌─────────────────┐    │
//! │  │  gRPC Server    │◄───┼──── Agent connects outbound
//! │  └─────────────────┘    │
//! └─────────────────────────┘
//!            ▲
//!            │ Bidirectional stream
//!            │ (AgentMessage ↔ CellCommand)
//!            │
//! ┌──────────┴──────────────┐
//! │    Workload Cluster     │
//! │                         │
//! │  ┌─────────────────┐    │
//! │  │  Lattice Agent  │────┼──── Initiates outbound connection
//! │  └─────────────────┘    │
//! └─────────────────────────┘
//! ```
//!
//! # Key Message Types
//!
//! ## Agent to Cell (AgentMessage)
//!
//! - [`AgentReady`]: Sent when agent first connects, includes version info
//! - [`BootstrapComplete`]: Confirms CAPI providers are installed
//! - [`Heartbeat`]: Periodic health check with agent state
//! - [`ClusterHealth`]: Node counts and Kubernetes conditions
//! - [`ClusterDeleting`]: Initiates unpivot (moving resources back to parent)
//! - [`MoveObjectAck`]: Acknowledges receipt of CAPI resources during pivot
//! - [`SubtreeState`]: Reports cluster hierarchy for routing
//! - [`StatusResponse`]: Response to status request with agent state and health
//!
//! ## Cell to Agent (CellCommand)
//!
//! - [`ApplyManifestsCommand`]: Apply Kubernetes manifests on the child cluster
//! - [`StatusRequest`]: Request current cluster status from agent
//! - [`SyncDistributedResourcesCommand`]: Sync CloudProviders, SecretsProviders, policies
//! - [`MoveObjectBatch`]: Batch of CAPI resources during pivot
//! - [`MoveComplete`]: Signals all resources sent, agent should unpause CAPI
//! - [`KubernetesRequest`]: Proxy Kubernetes API requests through the agent
//!
//! # Pivot Protocol
//!
//! The pivot process transfers CAPI ownership from parent to child:
//!
//! 1. Cell discovers CAPI CRDs and builds ownership graph
//! 2. Cell pauses Cluster/ClusterClass resources on source
//! 3. Cell sends [`MoveObjectBatch`] messages in topological order
//! 4. Agent creates resources and responds with [`MoveObjectAck`] (UID mappings)
//! 5. Cell sends [`MoveComplete`] with distributable resources
//! 6. Agent unpauses CAPI and becomes self-managing
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use lattice_proto::{AgentMessage, CellCommand, AgentReady, AgentState};
//!
//! // Create an agent ready message
//! let ready = AgentReady {
//!     agent_version: "0.1.0".to_string(),
//!     kubernetes_version: "1.29.0".to_string(),
//!     state: AgentState::Provisioning as i32,
//!     api_server_endpoint: "https://10.0.0.1:6443".to_string(),
//! };
//!
//! let msg = AgentMessage {
//!     cluster_name: "my-cluster".to_string(),
//!     payload: Some(agent_message::Payload::Ready(ready)),
//! };
//! ```

// Generated protobuf code doesn't have docs
#![allow(missing_docs)]

/// Generated protobuf types from agent.proto
pub mod agent {
    /// Version 1 of the agent protocol
    pub mod v1 {
        tonic::include_proto!("lattice.agent.v1");
    }
}

pub use agent::v1::*;
