//! End-to-end tests for Lattice CLI installation

mod helpers;
mod mesh_tests;
mod providers;

mod pivot_e2e;

#[cfg(feature = "aws-e2e")]
mod aws_e2e;
