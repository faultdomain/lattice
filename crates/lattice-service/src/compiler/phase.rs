//! Compiler extension phases
//!
//! A `CompilerPhase` plugs into `ServiceCompiler::compile()` and runs after
//! core compilation. Phases can inspect the service spec and compiled output,
//! then append `DynamicResource` entries to `compiled.extensions` for things
//! like Flagger Canaries, VMServiceScrapes, or rate-limiting EnvoyFilters.

use async_trait::async_trait;

use crate::crd::{LatticeService, MonitoringConfig, ProviderType};
use crate::graph::ServiceGraph;

use super::CompiledService;

/// Immutable context available to all compiler phases.
pub struct CompilationContext<'a> {
    /// The LatticeService being compiled
    pub service: &'a LatticeService,
    /// Service name (from metadata)
    pub name: &'a str,
    /// Service namespace (from metadata)
    pub namespace: &'a str,
    /// The service dependency graph
    pub graph: &'a ServiceGraph,
    /// Cluster name (used in trust domain, etc.)
    pub cluster_name: &'a str,
    /// Infrastructure provider type
    pub provider_type: ProviderType,
    /// Monitoring configuration for this cluster
    pub monitoring: MonitoringConfig,
}

/// A pluggable phase in the service compilation pipeline.
///
/// Phases run after core compilation (workloads, policies, ingress, waypoint)
/// and can append dynamic resources to the compiled output.
///
/// The `compile` method is async to allow phases to perform on-demand API
/// discovery (e.g. checking if a CRD is installed before emitting resources).
#[async_trait]
pub trait CompilerPhase: Send + Sync {
    /// Human-readable name for this phase (used in error messages and logging)
    fn name(&self) -> &str;

    /// Run this phase, optionally appending resources to `output.extensions`.
    ///
    /// Return `Err(message)` to abort compilation with an attribution to this phase.
    async fn compile(
        &self,
        ctx: &CompilationContext<'_>,
        output: &mut CompiledService,
    ) -> Result<(), String>;
}
