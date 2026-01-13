//! Integration tests for Lattice operator
//!
//! These tests require a Kubernetes cluster (kind) to run and tell the story
//! of how platform operators interact with Lattice in real-world scenarios.
//!
//! # Test Organization
//!
//! Tests are organized by the story they tell:
//!
//! - `crd_operations`: Stories about creating, reading, updating, and deleting
//!   LatticeCluster resources through the Kubernetes API
//!
//! - `cluster_lifecycle`: Stories about how the controller manages cluster
//!   state transitions (Pending -> Provisioning -> Pivoting -> Ready)
//!
//! - `agent_cell_integration`: Stories about agent-cell communication,
//!   including registration, bootstrap, and pivot flows
//!
//! - `pivot_protocol`: Protocol integration tests that verify gRPC message
//!   flow works correctly (simulated, fast ~20s)
//!
//! - `pivot_e2e`: Real end-to-end tests that provision actual CAPD clusters
//!   and execute the full pivot flow (slow ~15-20min)
//!
//! # Running These Tests
//!
//! These tests are ignored by default because they require a kind cluster:
//!
//! ```bash
//! # Ensure kind cluster is running with CRDs installed
//! cargo test --test kind -- --ignored
//!
//! # Run fast protocol tests (~20s)
//! cargo test --test kind pivot_protocol -- --ignored --nocapture
//!
//! # Run real e2e tests (~15-20min)
//! cargo test --test kind pivot_e2e -- --ignored --nocapture
//! ```

mod agent_cell_integration;
mod cluster_lifecycle;
mod crd_operations;
mod helpers;
mod pivot_e2e;
mod pivot_protocol;
