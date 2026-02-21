//! Integration tests for Lattice
//!
//! These tests assume infrastructure exists and can run standalone against
//! existing clusters. They are also composed by E2E tests at appropriate phases.
//!
//! # Design Philosophy
//!
//! - **Integration tests** assume infrastructure exists. Fast, reusable, can run repeatedly.
//! - **E2E tests** build everything from scratch. Full flow, creates and destroys infrastructure.
//!
//! # Running Standalone Tests
//!
//! ```bash
//! # First, set up infrastructure (run once)
//! cargo test --features provider-e2e --test e2e test_setup_hierarchy_only -- --ignored --nocapture
//!
//! # Then run integration tests against existing clusters
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_mesh_standalone -- --ignored --nocapture
//! ```

pub mod autoscaling;
pub mod capi;
pub mod cedar;
pub mod cedar_secrets;
pub mod cedar_security;
pub mod job;
pub mod kubeconfig;
pub mod mesh;
pub mod multi_hop;
pub mod oidc;
pub mod pivot;
pub mod proxy;
pub mod scaling;
pub mod secrets;
pub mod setup;
pub mod tetragon;
