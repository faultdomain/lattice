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
pub mod celery_queue;
pub mod cert_manager;
pub mod cost;
pub mod dns;
pub mod ecommerce;
pub mod gateway;
pub mod gpu_health;
pub mod image_provider;
pub mod job;
pub mod kubeconfig;
pub mod media;
pub mod mesh;
pub mod mesh_onboarding;
pub mod model;
pub mod multi_hop;
pub mod node_autoscaling;
pub mod observability;
pub mod oidc;
pub mod package;
pub mod parent_delete;
pub mod pivot;
pub mod proxy;
pub mod quota;
pub mod recreate;
pub mod route_discovery;
pub mod scaling;
pub mod secret_rollout;
pub mod secrets;
pub mod setup;
pub mod tetragon;
pub mod topology;
pub mod training;
pub mod updates;
pub mod upgrade;
pub mod vault_secrets;
pub mod webapp_postgres;
pub mod webhook;
pub mod workload;
