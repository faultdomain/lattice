//! gRPC protocol definitions for agent-cell communication
//!
//! This module contains the generated Protobuf and gRPC code for the
//! bidirectional streaming protocol between agents and cells.
//!
//! # Protocol Overview
//!
//! Agents (running on workload clusters) initiate outbound gRPC connections
//! to their parent cell (management cluster). The connection establishes a
//! bidirectional stream where:
//!
//! - Agents send: `AgentMessage` (ready, heartbeat, pivot complete, etc.)
//! - Cells send: `CellCommand` (bootstrap, pivot, reconcile, etc.)
//!
//! # Example
//!
//! ```text
//! // Agent connects to cell
//! let mut client = LatticeAgentClient::connect("https://cell:443").await?;
//! let (tx, rx) = mpsc::channel(32);
//! let response = client.connect(ReceiverStream::new(rx)).await?;
//! // Send messages via tx, receive commands from response stream
//! ```

#![allow(missing_docs)] // Generated code doesn't have docs
#![allow(clippy::doc_overindented_list_items)] // Generated proto docs have formatting issues

/// Generated protobuf and gRPC code for agent-cell communication
pub mod agent {
    /// Version 1 of the agent protocol
    pub mod v1 {
        tonic::include_proto!("lattice.agent.v1");
    }
}

// Re-export commonly used types at the module level for convenience
pub use agent::v1::*;
