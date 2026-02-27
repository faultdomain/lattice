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
//! Single-cluster tests accept `LATTICE_KUBECONFIG` for direct access to any cluster,
//! or fall back to `LATTICE_MGMT_KUBECONFIG` + `LATTICE_WORKLOAD_KUBECONFIG` with proxy.
//!
//! ```bash
//! # Direct access (simplest — works with any kubeconfig)
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_mesh_standalone -- --ignored --nocapture
//!
//! # Or set up hierarchy first, then use proxy kubeconfigs
//! cargo test --features provider-e2e --test e2e test_setup_hierarchy_only -- --ignored --nocapture
//!
//! LATTICE_MGMT_KUBECONFIG=/path/to/mgmt-kubeconfig \
//! LATTICE_WORKLOAD_KUBECONFIG=/path/to/workload-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_mesh_standalone -- --ignored --nocapture
//! ```

pub mod autoscaling;
pub mod backup;
pub mod capi;
pub mod cedar;
pub mod cedar_secrets;
pub mod cedar_security;
pub mod gateway;
pub mod job;
pub mod kubeconfig;
pub mod media;
pub mod mesh;
pub mod model;
pub mod multi_hop;
pub mod oidc;
pub mod pivot;
pub mod proxy;
pub mod scaling;
pub mod secrets;
pub mod setup;
pub mod tetragon;
pub mod updates;
pub mod vault_secrets;
pub mod webhook;
