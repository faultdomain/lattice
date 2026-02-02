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

/// Check if a query string indicates a streaming request.
///
/// Streaming requests include:
/// - `watch=true` or `watch=1` for K8s watch API
/// - `follow=true` or `follow=1` for streaming pod logs
///
/// # Examples
///
/// ```
/// use lattice_proto::is_watch_query;
///
/// assert!(is_watch_query("watch=true"));
/// assert!(is_watch_query("labelSelector=app&watch=true"));
/// assert!(is_watch_query("follow=true"));
/// assert!(!is_watch_query("watch=false"));
/// assert!(!is_watch_query(""));
/// ```
pub fn is_watch_query(query: &str) -> bool {
    query.contains("watch=true")
        || query.contains("watch=1")
        || query.contains("follow=true")
        || query.contains("follow=1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_watch_query() {
        // Watch queries
        assert!(is_watch_query("watch=true"));
        assert!(is_watch_query("watch=1"));
        assert!(is_watch_query("labelSelector=app&watch=true"));
        assert!(is_watch_query("watch=true&resourceVersion=100"));
        // Follow queries (for logs)
        assert!(is_watch_query("follow=true"));
        assert!(is_watch_query("follow=1"));
        assert!(is_watch_query("container=main&follow=true"));
        // Non-streaming
        assert!(!is_watch_query("watch=false"));
        assert!(!is_watch_query("follow=false"));
        assert!(!is_watch_query("labelSelector=app"));
        assert!(!is_watch_query(""));
    }
}
