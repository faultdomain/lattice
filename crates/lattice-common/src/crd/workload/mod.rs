//! Shared workload types for all Lattice CRDs (LatticeService, LatticeJob, LatticeModel).
//!
//! This module contains the core building blocks that compose `WorkloadSpec`,
//! the shared specification embedded in every workload CRD.

pub mod backup;
pub mod container;
pub mod deploy;
pub mod ingress;
pub mod ports;
pub mod resources;
pub mod scaling;
pub mod spec;
