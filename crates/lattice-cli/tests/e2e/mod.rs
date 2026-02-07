//! End-to-end tests for Lattice CLI installation
//!
//! This module contains three tiers of tests:
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Test Infrastructure                          │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  INTEGRATION TESTS (assume cluster exists, can run standalone)  │
//! │  ├─ integration/mesh.rs          - Mesh bilateral agreements    │
//! │  ├─ integration/capi.rs          - CAPI resource verification   │
//! │  ├─ integration/scaling.rs       - Worker scaling tests         │
//! │  ├─ integration/proxy.rs         - K8s API proxy through hier.  │
//! │  ├─ integration/kubeconfig.rs    - Kubeconfig patching verify   │
//! │  ├─ integration/cedar.rs         - Cedar policy enforcement     │
//! │  ├─ integration/cedar_secrets.rs - Cedar secret authorization   │
//! │  ├─ integration/secrets.rs       - Vault secrets integration    │
//! │  ├─ integration/oidc.rs          - OIDC authentication          │
//! │  ├─ integration/multi_hop.rs     - Multi-hop proxy operations   │
//! │  └─ integration/pivot.rs         - Unpivot verification         │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  PER-INTEGRATION E2E (isolated: setup, one test, teardown)      │
//! │  ├─ mesh_e2e.rs              - Mesh only                        │
//! │  ├─ capi_e2e.rs              - CAPI only                        │
//! │  ├─ scaling_e2e.rs           - Scaling only                     │
//! │  ├─ proxy_e2e.rs             - Proxy only                       │
//! │  ├─ kubeconfig_e2e.rs        - Kubeconfig only                  │
//! │  ├─ cedar_e2e.rs             - Cedar only                       │
//! │  ├─ cedar_secrets_e2e.rs     - Cedar secrets only               │
//! │  ├─ secrets_e2e.rs           - Vault secrets only               │
//! │  ├─ oidc_e2e.rs              - OIDC only                        │
//! │  ├─ multi_hop_e2e.rs         - Multi-hop proxy only             │
//! │  └─ pivot_standalone_e2e.rs  - Pivot/unpivot only               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  UNIFIED E2E (full lifecycle, all tests in sequence)            │
//! │  ├─ unified_e2e.rs           - Full lifecycle                   │
//! │  ├─ upgrade_e2e.rs           - Upgrade with mesh traffic        │
//! │  ├─ endurance_e2e.rs         - Infinite loop stress test        │
//! │  └─ docker_independence_e2e.rs - Parent deletion survival       │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Running Tests
//!
//! ## Per-integration E2E (isolated — setup, one test, teardown)
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_mesh_e2e -- --nocapture
//! cargo test --features provider-e2e --test e2e test_proxy_e2e -- --nocapture
//! ```
//!
//! ## Unified E2E (full lifecycle, all tests)
//!
//! ```bash
//! cargo test --features provider-e2e --test e2e test_configurable_provider_pivot -- --nocapture
//! ```
//!
//! ## Integration tests on existing clusters (fast iteration)
//!
//! ```bash
//! LATTICE_MGMT_KUBECONFIG=/tmp/e2e-mgmt-kubeconfig-xxx \
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
mod mesh_fixtures;
mod mesh_helpers;
mod mesh_random;
mod mesh_tests;
mod providers;

// Unified E2E (full lifecycle)
mod unified_e2e;

// Specialized E2E
mod docker_independence_e2e;
mod endurance_e2e;
mod upgrade_e2e;

// Per-integration E2E (isolated: setup, one test, teardown)
mod capi_e2e;
mod cedar_e2e;
mod cedar_secrets_e2e;
mod kubeconfig_e2e;
mod mesh_e2e;
mod multi_hop_e2e;
mod oidc_e2e;
mod pivot_standalone_e2e;
mod proxy_e2e;
mod scaling_e2e;
mod secrets_e2e;
