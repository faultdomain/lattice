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
//! - [`graph`] - Service dependency graph for network policy generation
//! - [`error`] - Error types for the operator

#![deny(missing_docs)]

pub mod agent;
pub mod bootstrap;
pub mod capi;
pub mod controller;
pub mod crd;
pub mod error;
pub mod graph;
pub mod pivot;
pub mod pki;
pub mod proto;
pub mod provider;

pub use error::Error;

/// Result type alias using our custom Error type
pub type Result<T> = std::result::Result<T, Error>;
