//! gRPC protocol definitions for Lattice agent-cell communication

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
