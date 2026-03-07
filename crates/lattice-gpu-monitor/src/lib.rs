//! GPU health monitoring vertical slice for lattice-daemonset.
//!
//! Scrapes DCGM exporter metrics, runs a GRU autoencoder for anomaly
//! detection, checks for GPU loss (allocatable < requested), and
//! annotates the node for the cluster controller to act on.
//!
//! The processing pipeline (features → window → training → scoring) is
//! encapsulated in [`GpuMonitorPipeline`] for testability, while `run()`
//! handles the async I/O loop (DCGM scraping, K8s annotation, GPU loss checks).

pub mod annotator;
pub mod collector;
pub mod config;
pub mod features;
pub mod gpu_loss;
pub mod model;
pub mod scorer;
pub mod trainer;
pub mod window;

use std::time::Duration;

use tracing::{info, warn};

use annotator::NodeAnnotator;
use collector::{DcgmCollector, NodeSample};
use config::{DEFAULT_DCGM_URL, GPU_LOSS_CHECK_INTERVAL_SECS, SCRAPE_INTERVAL_SECS, WINDOW_SIZE};
use features::compute_features;
use gpu_loss::{GpuLossChecker, GpuLossStatus};
use model::detect_gpu_architecture;
use scorer::{AnomalyScorer, HealthStatus};
use trainer::OnlineTrainer;
use window::SlidingWindow;

/// Pure processing pipeline: features → window → training → scoring.
///
/// Separates computation from I/O so the core logic is testable without
/// a real DCGM exporter or Kubernetes API server.
pub struct GpuMonitorPipeline {
    window: SlidingWindow,
    scorer: AnomalyScorer,
    trainer: Option<OnlineTrainer>,
    try_checkpoint: bool,
}

impl Default for GpuMonitorPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl GpuMonitorPipeline {
    pub fn new() -> Self {
        Self {
            window: SlidingWindow::new(WINDOW_SIZE),
            scorer: AnomalyScorer::new(),
            trainer: None,
            try_checkpoint: true,
        }
    }

    /// Disable checkpoint loading (for tests that don't have a checkpoint dir).
    pub fn without_checkpoint(mut self) -> Self {
        self.try_checkpoint = false;
        self
    }

    /// Process a single DCGM sample through the pipeline.
    ///
    /// Lazily initializes the trainer on the first sample with GPUs.
    /// Returns the current health status (always Normal during warmup).
    pub fn process_sample(&mut self, sample: &NodeSample) -> HealthStatus {
        let device = Default::default();

        // Lazily initialize trainer once we know the GPU count
        if self.trainer.is_none() && !sample.gpus.is_empty() {
            let num_gpus = sample.gpus.len();
            let mut t = OnlineTrainer::new(num_gpus, WINDOW_SIZE, &device);
            if self.try_checkpoint {
                t.load_checkpoint(&device);
            }
            self.trainer = Some(t);
            info!(num_gpus, "initialized online trainer");
        }

        // Compute features and push into sliding window
        let node_features = compute_features(sample);
        self.window.push(node_features);

        // Run training + scoring when window is full
        if self.window.is_full() {
            if let (Some(ref mut t), Some(flat)) = (&mut self.trainer, self.window.as_contiguous()) {
                if let Some(raw_score) = t.step(flat.as_slice(), &device) {
                    self.scorer.update(raw_score);
                }
            }
        }

        self.scorer.status()
    }

    /// Whether the trainer has been initialized (at least one GPU sample seen).
    pub fn has_trainer(&self) -> bool {
        self.trainer.is_some()
    }
}

/// Run the GPU monitoring loop on this node.
///
/// This is the main entry point called by the daemonset binary's slice runner.
/// It scrapes DCGM metrics every second, feeds them through the pipeline,
/// and annotates the node with health status.
pub async fn run(client: kube::Client, node_name: String) -> anyhow::Result<()> {
    info!(node = %node_name, "starting GPU monitor slice");

    let gpu_arch = detect_gpu_architecture(&client, &node_name).await?;
    info!(node = %node_name, gpu_arch = %gpu_arch, "detected GPU architecture");

    let collector = DcgmCollector::new(DEFAULT_DCGM_URL)?;
    let mut pipeline = GpuMonitorPipeline::new();
    let mut annotator = NodeAnnotator::new(client.clone(), node_name.clone());
    let mut loss_checker = GpuLossChecker::new(client.clone(), node_name.clone());

    let mut interval = tokio::time::interval(Duration::from_secs(SCRAPE_INTERVAL_SECS));
    let mut loss_check_counter = 0u32;
    let mut last_gpu_loss = GpuLossStatus::Normal { allocatable: 0 };

    loop {
        interval.tick().await;

        // Scrape DCGM metrics
        let sample = match collector.scrape().await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to scrape DCGM metrics");
                continue;
            }
        };

        // Track DCGM GPU count for ghost GPU detection
        loss_checker.update_dcgm_gpu_count(sample.gpus.len() as u32);

        // Process through the pipeline (features → window → train/score)
        let health = pipeline.process_sample(&sample);

        // GPU loss check (every GPU_LOSS_CHECK_INTERVAL_SECS).
        // Retain last known status between checks and on errors — never
        // silently default to Normal as that would clear a real detection.
        loss_check_counter += 1;
        if loss_check_counter % GPU_LOSS_CHECK_INTERVAL_SECS == 0 {
            match loss_checker.check().await {
                Ok(status) => last_gpu_loss = status,
                Err(e) => warn!(error = %e, "GPU loss check failed, retaining last status"),
            }
        }

        // Update node annotations
        if let Err(e) = annotator.update(&health, &last_gpu_loss).await {
            warn!(error = %e, "failed to update node annotations");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use collector::GpuSample;
    use std::time::Instant;

    fn make_sample(num_gpus: usize, temp: f32) -> NodeSample {
        NodeSample {
            gpus: (0..num_gpus)
                .map(|i| GpuSample {
                    gpu_index: i as u32,
                    gpu_temp: temp,
                    fb_free: 1.0,
                    ..Default::default()
                })
                .collect(),
            timestamp: Instant::now(),
        }
    }

    #[test]
    fn pipeline_starts_normal() {
        let mut pipeline = GpuMonitorPipeline::new().without_checkpoint();
        let status = pipeline.process_sample(&make_sample(1, 50.0));
        assert!(matches!(status, HealthStatus::Normal { .. }));
    }

    #[test]
    fn pipeline_initializes_trainer_on_first_gpu_sample() {
        let mut pipeline = GpuMonitorPipeline::new().without_checkpoint();
        assert!(!pipeline.has_trainer());
        pipeline.process_sample(&make_sample(1, 50.0));
        assert!(pipeline.has_trainer());
    }

    #[test]
    fn pipeline_handles_empty_samples() {
        let mut pipeline = GpuMonitorPipeline::new().without_checkpoint();
        let empty = NodeSample {
            gpus: vec![],
            timestamp: Instant::now(),
        };
        let status = pipeline.process_sample(&empty);
        assert!(matches!(status, HealthStatus::Normal { .. }));
        assert!(!pipeline.has_trainer());
    }

    #[test]
    fn pipeline_stays_normal_during_warmup() {
        let mut pipeline = GpuMonitorPipeline::new().without_checkpoint();
        // Feed 100 samples — well below warmup threshold
        for _ in 0..100 {
            let status = pipeline.process_sample(&make_sample(1, 50.0));
            assert!(
                matches!(status, HealthStatus::Normal { .. }),
                "should stay Normal during warmup"
            );
        }
    }

    #[test]
    fn pipeline_scorer_receives_scores_after_warmup() {
        let mut pipeline = GpuMonitorPipeline::new().without_checkpoint();

        // Fill window to capacity
        for _ in 0..WINDOW_SIZE {
            pipeline.process_sample(&make_sample(1, 50.0));
        }

        // The window is now full, but we're still in warmup (need WARMUP_WINDOWS
        // scrapes). The scorer should stay at 0.0 (no scores fed to it yet).
        let status = pipeline.process_sample(&make_sample(1, 50.0));
        assert_eq!(status.score(), 0.0, "scorer should not receive scores during warmup");
    }
}
