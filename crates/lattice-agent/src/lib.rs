//! Lattice Agent - Child cluster runtime
//!
//! This crate provides the client-side runtime for child/workload clusters:
//!
//! - **Agent Client**: gRPC client connecting to the parent cell
//! - **Pivot Execution**: Importing CAPI manifests, patching kubeconfig
//! - **K8s Request Execution**: Handling K8s API requests from parent
//!
//! # Architecture
//!
//! The agent runs on child clusters and maintains an **outbound** connection
//! to the parent cell. All communication is initiated by the agent.

pub mod client;
pub mod executor;
pub mod pivot;
pub mod subtree;
pub mod watch;

pub use client::{AgentClient, AgentClientConfig, AgentCredentials, CertificateError, ClientState};

// Re-export protocol types from lattice_common
pub use executor::{execute_k8s_request, is_watch_request};
pub use lattice_common::{CsrRequest, CsrResponse};
pub use pivot::{
    apply_distributed_resources, patch_kubeconfig_for_self_management, DistributableResources,
    PivotError,
};
pub use subtree::SubtreeSender;
pub use watch::{execute_watch, WatchRegistry};

// Re-export proto types for convenience
pub use lattice_proto::{
    agent_message, cell_command, AgentMessage, AgentReady, AgentState, BootstrapComplete,
    CellCommand, ClusterDeleting, ClusterHealth, Heartbeat, KubernetesRequest, KubernetesResponse,
    StatusResponse,
};

// Re-export mTLS from infra
pub use lattice_infra::{ClientMtlsConfig, MtlsError, ServerMtlsConfig};
