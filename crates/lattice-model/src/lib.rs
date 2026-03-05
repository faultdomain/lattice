//! LatticeModel controller and compiler for model serving workloads
//!
//! Compiles `LatticeModel` CRDs into Kthena ModelServing resources with full mesh integration:
//! - Per-role workload compilation via `WorkloadCompiler`
//! - Per-role Tetragon `TracingPolicyNamespaced` generation
//! - `LatticeMeshMember` CRs for bilateral agreements
//! - Kthena ModelServing for disaggregated inference via gang scheduling

pub mod compiler;
pub mod controller;
pub mod error;
