//! Lattice - CRD-driven Kubernetes operator for multi-cluster lifecycle management
//!
//! Lattice manages cluster provisioning, configuration, and self-management through
//! a pivoting architecture where every provisioned cluster becomes fully self-managed.
//!
//! # Architecture
//!
//! Lattice uses a pivoting architecture where:
//! - A management cluster (cell) provisions workload clusters
//! - Each workload cluster becomes fully self-managing after pivot
//! - All communication is outbound from workload clusters (gRPC bidirectional streaming)
//!
//! # Modules
//!
//! - [`crd`] - Custom Resource Definitions (LatticeCluster, LatticeService, etc.)
//! - [`controller`] - Kubernetes controller reconciliation logic
//! - [`provider`] - Infrastructure provider abstractions (Docker, AWS, etc.)
//! - [`proto`] - gRPC protocol definitions for agent-cell communication
//! - [`agent`] - Agent-cell gRPC communication
//! - [`pki`] - PKI operations for mTLS certificates
//! - [`bootstrap`] - Bootstrap endpoint for kubeadm callback
//! - [`capi`] - CAPI installation and management
//! - [`cell`] - On-demand cell servers (gRPC + bootstrap HTTP)
//! - [`graph`] - Service dependency graph for network policy generation
//! - [`compiler`] - Unified service compiler (generates workloads + policies)
//! - [`policy`] - Network policy types (Istio AuthorizationPolicy, CiliumNetworkPolicy)
//! - [`workload`] - Workload types (Deployment, Service, ServiceAccount, HPA)
//! - [`install`] - Installer for bootstrapping management clusters
//! - [`error`] - Error types for the operator

#![deny(missing_docs)]

pub mod agent;
pub mod bootstrap;
pub mod capi;
pub mod cell;
pub mod cilium;
pub mod compiler;
pub mod controller;
pub mod crd;
pub mod error;
pub mod graph;
pub mod infra;
pub mod install;
pub mod pivot;
pub mod pki;
pub mod policy;
pub mod proto;
pub mod provider;
pub mod workload;

pub use error::Error;

/// Result type alias using our custom Error type
pub type Result<T> = std::result::Result<T, Error>;

// =============================================================================
// Default Configuration Constants
// =============================================================================
// These constants define the default values used throughout Lattice.
// Centralizing them here ensures consistency across CRD defaults, server configs,
// and test fixtures.

/// Default port for the bootstrap HTTPS server
///
/// This is where kubeadm postKubeadmCommands calls to get agent/CNI manifests.
/// Port 8443 is used instead of 443 to avoid requiring root privileges.
pub const DEFAULT_BOOTSTRAP_PORT: u16 = 8443;

/// Default port for the gRPC server (agent-cell communication)
pub const DEFAULT_GRPC_PORT: u16 = 50051;
