//! End-to-end integration tests for Lattice operator
//!
//! These tests require a Kubernetes cluster to run. They are ignored by default
//! and can be run with:
//!
//! ```bash
//! cargo test --test kind -- --ignored
//! ```
//!
//! The tests will automatically create a kind cluster named "lattice-integration-test"
//! if one doesn't exist.

mod kind_tests;
