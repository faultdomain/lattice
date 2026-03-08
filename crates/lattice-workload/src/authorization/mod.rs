//! Authorization for workload compilation (pub(crate))
//!
//! Only called by WorkloadCompiler — not exposed to CRD compilers.

pub(crate) mod external_endpoints;
pub(crate) mod secrets;
pub(crate) mod security;
pub(crate) mod volumes;

use lattice_common::graph::ServiceGraph;

/// How volume authorization behaves
pub enum VolumeAuthorizationMode<'a> {
    /// Full: owner consent via graph + Cedar policy
    Full { graph: &'a ServiceGraph },
    /// Cedar-only: skip owner consent check (used when no graph available)
    CedarOnly,
}
