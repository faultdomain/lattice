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
//! - `pivot_e2e`: Configurable provider e2e tests that allow mixing
//!   any provider (docker/aws/openstack/proxmox) for mgmt and workload clusters.
//!   This is the main e2e test with optional phases:
//!   - Phase 6: Worker scaling (Docker only)
//!   - Phase 7: Independence verification (LATTICE_ENABLE_INDEPENDENCE_TEST=true)
//!   - Phase 8-9: Mesh tests (LATTICE_ENABLE_MESH_TEST=true) - runs 9-service
//!     bilateral test and 50-100 service stress test in parallel
//!
//! - `aws_e2e`: AWS end-to-end tests that provision real EC2 clusters
//!   using CAPA (requires AWS credentials, slow ~30min)
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
//! # Run e2e tests with Docker provider (~15-20min)
//! cargo test --features provider-e2e --test kind pivot_e2e -- --nocapture
//!
//! # Run full e2e with independence verification (~30min)
//! LATTICE_ENABLE_INDEPENDENCE_TEST=true \
//!   cargo test --features provider-e2e --test kind pivot_e2e -- --nocapture
//!
//! # Run AWS e2e tests (requires AWS credentials, ~30min)
//! export AWS_SSH_KEY_NAME=my-key
//! cargo test --features aws-e2e --test kind aws_e2e -- --nocapture
//!
//! # Run mixed provider tests (Docker mgmt -> AWS workload)
//! LATTICE_MGMT_PROVIDER=docker LATTICE_WORKLOAD_PROVIDER=aws \
//!   cargo test --features provider-e2e --test kind pivot_e2e -- --nocapture
//! ```

mod agent_cell_integration;
#[cfg(feature = "aws-e2e")]
mod aws_e2e;
mod cluster_lifecycle;
mod crd_operations;
mod helpers;
#[cfg(feature = "provider-e2e")]
mod mesh_tests;
#[cfg(feature = "provider-e2e")]
mod pivot_e2e;
mod pivot_protocol;
#[cfg(feature = "provider-e2e")]
mod providers;
