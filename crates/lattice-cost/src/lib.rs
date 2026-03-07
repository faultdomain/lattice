//! Cost estimation engine for Lattice workloads.
//!
//! Provides a trait-based abstraction (`CostProvider`) for loading per-resource
//! hourly rates, and calculator functions that compute cost from workload specs.
//!
//! The default implementation (`ConfigMapCostProvider`) reads rates from the
//! `lattice-resource-rates` ConfigMap in `lattice-system`. On-prem operators
//! populate this manually; cloud providers can auto-populate it via a
//! separate controller.

pub mod calculator;
pub mod configmap;
pub mod error;
pub mod rates;

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use lattice_common::crd::CostEstimate;
use tracing::warn;

pub use calculator::{estimate_job_cost, estimate_model_cost, estimate_service_cost};
pub use configmap::ConfigMapCostProvider;
pub use error::CostError;
pub use rates::CostRates;

/// Abstraction for loading cost rates from a backend.
///
/// The default implementation reads from a ConfigMap. Future implementations
/// may pull rates directly from cloud provider pricing APIs.
#[async_trait]
pub trait CostProvider: Send + Sync {
    /// Load current per-resource hourly rates.
    ///
    /// Returns an error if the rate source is unavailable or malformed.
    async fn load_rates(&self) -> Result<CostRates, CostError>;
}

/// Best-effort cost estimation: loads rates, computes cost, logs warnings on failure.
///
/// `compute` is a closure that takes `(&CostRates, &str)` (rates + RFC 3339 timestamp)
/// and returns the estimate. This consolidates the load-rates → compute → warn pattern
/// used by all three controller types.
pub async fn try_estimate<F>(
    provider: &Option<Arc<dyn CostProvider>>,
    compute: F,
) -> Option<CostEstimate>
where
    F: FnOnce(&CostRates, &str) -> Result<CostEstimate, CostError>,
{
    let provider = provider.as_ref()?;
    let rates = match provider.load_rates().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "failed to load cost rates");
            return None;
        }
    };
    let timestamp = Utc::now().to_rfc3339();
    match compute(&rates, &timestamp) {
        Ok(est) => Some(est),
        Err(e) => {
            warn!(error = %e, "failed to compute cost estimate");
            None
        }
    }
}
