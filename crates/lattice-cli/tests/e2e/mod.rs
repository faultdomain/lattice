//! End-to-end tests for Lattice CLI installation
//!
//! This module contains both E2E tests (full lifecycle) and integration tests
//! (assume infrastructure exists).
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Test Infrastructure                          │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  INTEGRATION TESTS (assume cluster exists, can run standalone)  │
//! │  ├─ integration/mesh.rs       - Mesh bilateral agreement tests  │
//! │  ├─ integration/capi.rs       - CAPI resource verification      │
//! │  ├─ integration/scaling.rs    - Worker scaling tests            │
//! │  ├─ integration/proxy.rs      - K8s API proxy through hierarchy │
//! │  └─ integration/pivot.rs      - Unpivot verification            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  E2E TESTS (build everything, compose integration tests)        │
//! │  ├─ pivot_e2e.rs          - Full lifecycle                      │
//! │  ├─ upgrade_e2e.rs        - Upgrade with mesh traffic           │
//! │  ├─ endurance_e2e.rs      - Infinite loop stress test           │
//! │  └─ docker_independence_e2e.rs - Parent deletion survival       │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Running Tests
//!
//! ## Full E2E (creates all infrastructure)
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e pivot_e2e -- --nocapture
//! ```
//!
//! ## Integration tests on existing clusters
//!
//! ```bash
//! # Set kubeconfig paths from a previous E2E run
//! LATTICE_WORKLOAD_KUBECONFIG=/tmp/e2e-workload-kubeconfig-xxx \
//! cargo test --features provider-e2e --test e2e test_mesh_standalone -- --ignored --nocapture
//! ```

#[cfg(feature = "provider-e2e")]
mod chaos;
#[cfg(feature = "provider-e2e")]
mod context;
mod helpers;
#[cfg(feature = "provider-e2e")]
pub mod integration;
mod media_server_e2e;
mod mesh_tests;
mod providers;

mod docker_independence_e2e;
mod endurance_e2e;
mod pivot_e2e;
mod upgrade_e2e;
