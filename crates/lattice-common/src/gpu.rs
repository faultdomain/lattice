//! Shared GPU monitoring constants.
//!
//! These constants define the contract between the GPU monitor DaemonSet
//! (which writes node annotations) and the cluster controller (which reads
//! them to make cordon decisions). Both sides MUST use these constants
//! to stay in sync.

// --- Node annotation keys ---

/// Annotation for the EMA-smoothed anomaly score (0.0 = healthy, 1.0 = anomalous).
pub const ANNOTATION_ANOMALY_SCORE: &str = "lattice.dev/gpu-anomaly-score";

/// Annotation for the discrete health status ("normal", "warning", "unhealthy").
pub const ANNOTATION_GPU_HEALTH: &str = "lattice.dev/gpu-health";

/// Annotation for GPU loss detection ("true" / "false").
pub const ANNOTATION_GPU_LOSS: &str = "lattice.dev/gpu-loss-detected";

/// Annotation for the GPU monitor heartbeat (RFC 3339 timestamp).
pub const ANNOTATION_HEARTBEAT: &str = "lattice.dev/gpu-monitor-heartbeat";

// --- Operational thresholds ---

/// Heartbeat staleness threshold (seconds). If the heartbeat annotation is
/// older than this, the operator treats annotations as stale and ignores them.
pub const HEARTBEAT_STALENESS_SECS: i64 = 120;
