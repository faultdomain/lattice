//! Job-specific error types

#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error("compilation failed for task '{task}': {source}")]
    TaskCompilation {
        task: String,
        source: lattice_workload::CompilationError,
    },

    #[error("kubernetes error: {0}")]
    Kube(#[from] kube::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("{0}")]
    Common(#[from] lattice_common::Error),

    #[error("job has no tasks")]
    NoTasks,

    #[error("missing namespace on LatticeJob")]
    MissingNamespace,

    #[error("Volcano Job CRD (batch.volcano.sh/Job) not available")]
    VolcanoCrdMissing,
}
