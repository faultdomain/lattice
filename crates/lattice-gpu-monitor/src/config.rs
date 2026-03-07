//! Constants and thresholds for GPU monitoring.

/// Number of features per GPU: 15 raw + 3 derived + 6 relative = 24.
pub const FEATURES_PER_GPU: usize = 24;

/// Number of raw DCGM metrics per GPU.
pub const RAW_FEATURES: usize = 15;

/// Number of derived features per GPU.
pub const DERIVED_FEATURES: usize = 3;

/// Number of relative (cross-GPU) features per GPU.
pub const RELATIVE_FEATURES: usize = 6;

/// Sliding window size (number of 1-second samples).
pub const WINDOW_SIZE: usize = 60;

/// EMA smoothing factor for anomaly scores.
pub const EMA_ALPHA: f32 = 0.1;

/// Anomaly score threshold for Warning status.
pub const WARNING_THRESHOLD: f32 = 0.5;

/// Anomaly score threshold for Unhealthy status.
pub const UNHEALTHY_THRESHOLD: f32 = 0.8;

/// Number of consecutive unhealthy scores before declaring Unhealthy.
pub const MIN_CONSECUTIVE_UNHEALTHY: u32 = 3;

/// GPU thermal throttle temperature (Celsius).
pub const THROTTLE_TEMP: f32 = 83.0;

/// DCGM exporter default URL.
pub const DEFAULT_DCGM_URL: &str = "http://localhost:9400/metrics";

/// GPU loss check interval in seconds.
pub const GPU_LOSS_CHECK_INTERVAL_SECS: u32 = 10;

/// Scrape interval in seconds.
pub const SCRAPE_INTERVAL_SECS: u64 = 1;

// Annotation keys and operational thresholds (heartbeat staleness, drain delay)
// live in `lattice_common::gpu` — the single source of truth shared with the
// cluster controller.

// --- Online training constants ---

/// Number of scrapes before scoring is enabled (~30 min at 1s interval).
pub const WARMUP_WINDOWS: u64 = 1800;

/// Train once every N scrapes (aligned with window turnover).
pub const TRAIN_EVERY_N_SCRAPES: u64 = 60;

/// Initial learning rate for Adam optimizer.
pub const ONLINE_LEARNING_RATE: f64 = 1e-4;

/// LR decay factor applied every DECAY_EVERY_N_STEPS training steps.
pub const LR_DECAY_FACTOR: f64 = 0.998;

/// Apply LR decay every N training steps.
pub const DECAY_EVERY_N_STEPS: u64 = 100;

/// Minimum learning rate floor.
pub const MIN_LEARNING_RATE: f64 = 1e-6;

/// After warmup, skip training on windows with score above this ceiling
/// to avoid learning anomalous patterns as normal.
pub const HEALTHY_SCORE_CEILING: f32 = 0.4;

/// Number of training steps after warmup where the healthy score ceiling
/// is disabled, allowing the model to descend from high initial error.
pub const COLD_START_GRACE_STEPS: u64 = 200;

/// Maximum number of "golden healthy" windows kept for replay.
pub const REPLAY_BUFFER_SIZE: usize = 20;

/// Number of replay windows mixed into each training step.
pub const REPLAY_SAMPLES_PER_STEP: usize = 2;

/// Directory for model checkpoint persistence.
pub const CHECKPOINT_DIR: &str = "/var/lib/lattice/gpu-monitor";

/// Save a checkpoint every N training steps.
pub const CHECKPOINT_EVERY_N_STEPS: u64 = 50;
