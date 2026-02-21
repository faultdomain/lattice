//! LatticeJob controller and compiler for batch workloads
//!
//! Compiles `LatticeJob` CRDs into Volcano VCJobs with full mesh integration:
//! - Per-task workload compilation via `WorkloadCompiler`
//! - Per-task Tetragon `TracingPolicyNamespaced` generation
//! - `LatticeMeshMember` CRs for bilateral agreements
//! - Volcano VCJob for gang scheduling

pub mod compiler;
pub mod controller;
pub mod error;
