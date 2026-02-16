//! Tetragon runtime enforcement policy compiler
//!
//! Generates `TracingPolicyNamespaced` resources from workload specs
//! for kernel-level enforcement via eBPF kprobes on LSM hooks.
//! Third layer of Lattice defense-in-depth: L4 Cilium → L7 Istio → kernel Tetragon.
//!
//! Designed to be called from any workload controller (LatticeService, LatticeJob, LatticeModel).

mod compiler;

pub use compiler::compile_tracing_policies;
