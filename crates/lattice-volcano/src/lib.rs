//! Volcano VCJob compiler for Lattice batch workloads
//!
//! Compiles `LatticeJob` specs into Volcano VCJob resources for gang scheduling.
//! Pure compilation crate — no controller logic.

mod compiler;
mod types;

pub use compiler::compile_vcjob;
pub use types::{VCJob, VCJobSpec, VCJobTask, VCJobTaskPolicy};
