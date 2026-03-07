//! Error types for cost estimation.

/// Errors that can occur during cost estimation.
#[derive(Debug, thiserror::Error)]
pub enum CostError {
    /// The `lattice-resource-rates` ConfigMap was not found.
    #[error("cost rates ConfigMap not found: {0}")]
    ConfigMapNotFound(String),

    /// The ConfigMap data could not be parsed.
    #[error("invalid cost rates format: {0}")]
    InvalidFormat(String),

    /// A GPU model referenced by a workload has no rate entry.
    #[error("missing rate for GPU model '{0}'")]
    MissingGpuRate(String),

    /// A required rate entry is missing.
    #[error("missing rate for resource: {0}")]
    MissingRate(String),
}
