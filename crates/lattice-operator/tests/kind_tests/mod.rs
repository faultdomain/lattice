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
//! ```
//!
//! # E2E Tests
//!
//! E2E tests that use the Installer have been moved to the lattice-cli crate:
//!
//! ```bash
//! # Run e2e tests with Docker provider (~15-20min)
//! cargo test -p lattice-cli --features provider-e2e --test e2e -- --nocapture
//! ```

mod agent_cell_integration;
mod cluster_lifecycle;
mod crd_operations;
mod helpers;
mod pivot_protocol;
