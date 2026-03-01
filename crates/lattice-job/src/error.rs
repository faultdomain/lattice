//! Job-specific error types

use lattice_common::Retryable;

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

    #[error("Volcano {kind} CRD (batch.volcano.sh/{kind}) not available")]
    VolcanoCrdMissing { kind: &'static str },

    #[error("cron jobs cannot use training checkpoint recovery")]
    CronWithCheckpoint,

    #[error("training coordinator task '{0}' not found in job tasks")]
    CoordinatorTaskMissing(String),

    #[error("unsupported training framework: {0}")]
    UnsupportedFramework(String),

    #[error("training task '{task}' container '{container}' must specify a command")]
    TrainingContainerNoCommand { task: String, container: String },
}

impl Retryable for JobError {
    fn is_retryable(&self) -> bool {
        match self {
            Self::TaskCompilation { .. } => false,
            Self::Kube(_) => true,
            Self::Serialization(_) => false,
            Self::Common(e) => e.is_retryable(),
            Self::NoTasks => false,
            Self::MissingNamespace => false,
            Self::VolcanoCrdMissing { .. } => true,
            Self::CronWithCheckpoint => false,
            Self::CoordinatorTaskMissing(_) => false,
            Self::UnsupportedFramework(_) => false,
            Self::TrainingContainerNoCommand { .. } => false,
        }
    }
}
