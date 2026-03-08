//! Online trainer for the GRU autoencoder.
//!
//! Wraps the model with `Autodiff<NdArray>` for gradient computation and
//! implements continuous learning from the live DCGM telemetry stream.
//! During a warmup phase the model trains without producing scores;
//! after warmup it scores each window for anomaly detection while
//! continuing to learn from healthy data.
//!
//! Checkpointing saves model weights only — optimizer state (Adam momentum
//! and second moments) is not persisted. After a restart the optimizer
//! cold-starts, which may cause ~10 steps of slightly larger updates
//! while it re-estimates moments. This is acceptable because the model
//! weights are already warm and the LR is typically low by that point.

use std::collections::VecDeque;
use std::path::Path;

use burn::backend::ndarray::NdArray;
use burn::backend::Autodiff;
use burn::module::{AutodiffModule, Module};
use burn::optim::adaptor::OptimizerAdaptor;
use burn::optim::{Adam, AdamConfig, GradientsParams, Optimizer};
use burn::record::{FullPrecisionSettings, Record};
use burn::tensor::Tensor;
use rand::seq::SliceRandom;
use tracing::{info, warn};

use crate::config::{
    CHECKPOINT_DIR, CHECKPOINT_EVERY_N_STEPS, COLD_START_GRACE_STEPS, DECAY_EVERY_N_STEPS,
    HEALTHY_SCORE_CEILING, LR_DECAY_FACTOR, MIN_LEARNING_RATE, ONLINE_LEARNING_RATE,
    REPLAY_BUFFER_SIZE, REPLAY_SAMPLES_PER_STEP, TRAIN_EVERY_N_SCRAPES, WARMUP_WINDOWS,
};
use crate::model::GpuAnomalyModel;

type TrainBackend = Autodiff<NdArray>;
type NdDevice = <NdArray as burn::tensor::backend::Backend>::Device;

const CHECKPOINT_FILENAME: &str = "model.json";
const CHECKPOINT_TMP_FILENAME: &str = "model.tmp.json";

/// Online trainer that continuously learns "normal" GPU behaviour from
/// the live DCGM stream and produces anomaly scores via reconstruction error.
pub struct OnlineTrainer {
    model: GpuAnomalyModel<TrainBackend>,
    /// Cached `.valid()` snapshot used for inference-only scoring.
    inference_model: Option<GpuAnomalyModel<NdArray>>,
    optim: OptimizerAdaptor<Adam, GpuAnomalyModel<TrainBackend>, TrainBackend>,
    replay_buffer: VecDeque<Vec<f32>>,
    step_count: u64,
    scrape_count: u64,
    current_lr: f64,
    warmup_complete: bool,
    /// Remaining training opportunities where the healthy score ceiling is
    /// disabled. Set to COLD_START_GRACE_STEPS when warmup completes (fresh
    /// model needs room to converge). Set to 0 on checkpoint load (model
    /// already trained). Decremented once per train_step call.
    cold_start_remaining: u64,
    input_dim: usize,
    seq_len: usize,
}

impl OnlineTrainer {
    /// Create a new trainer for the given GPU count and window length.
    pub fn new(num_gpus: usize, seq_len: usize, device: &NdDevice) -> Self {
        let input_dim = num_gpus * crate::config::FEATURES_PER_GPU;
        let model = GpuAnomalyModel::<TrainBackend>::new(device, num_gpus);
        let optim = AdamConfig::new().init();

        Self {
            model,
            inference_model: None,
            optim,
            replay_buffer: VecDeque::with_capacity(REPLAY_BUFFER_SIZE),
            step_count: 0,
            scrape_count: 0,
            current_lr: ONLINE_LEARNING_RATE,
            warmup_complete: false,
            cold_start_remaining: 0,
            input_dim,
            seq_len,
        }
    }

    /// Process one scrape window. Returns `Some(score)` after warmup, `None` during warmup.
    pub fn step(&mut self, window_data: &[f32], device: &NdDevice) -> Option<f32> {
        // Validate input — reject NaN/Inf entirely. Return None rather than
        // scoring corrupt data (a NaN score would poison the EMA scorer forever).
        if window_data.iter().any(|v| !v.is_finite()) {
            warn!("window contains NaN/Inf values, skipping");
            return None;
        }

        self.scrape_count += 1;

        // Score first (if warmed up) using cached inference model
        let score = self.cached_score(window_data, device);

        // Train if it's time
        if self.scrape_count.is_multiple_of(TRAIN_EVERY_N_SCRAPES) {
            self.train_step(window_data, score, device);
        }

        // Check warmup transition
        if !self.warmup_complete && self.scrape_count >= WARMUP_WINDOWS {
            self.warmup_complete = true;
            self.cold_start_remaining = COLD_START_GRACE_STEPS;
            info!(
                step_count = self.step_count,
                scrape_count = self.scrape_count,
                "warmup complete, scoring enabled (cold-start grace: {COLD_START_GRACE_STEPS} training steps)"
            );
        }

        if self.warmup_complete {
            score
        } else {
            None
        }
    }

    /// Run a single training step on the given window data, plus replay samples.
    fn train_step(&mut self, window_data: &[f32], current_score: Option<f32>, device: &NdDevice) {
        let in_cold_start = self.cold_start_remaining > 0;

        // After warmup (and after cold-start grace), skip training on anomalous windows
        if self.warmup_complete && !in_cold_start {
            if let Some(s) = current_score {
                if s > HEALTHY_SCORE_CEILING {
                    return;
                }
            }
        }

        if in_cold_start {
            self.cold_start_remaining -= 1;
        }

        // Train on the live window
        self.train_on_window(window_data, device);

        // Add to replay buffer if healthy
        if current_score.is_none_or(|s| s <= HEALTHY_SCORE_CEILING) {
            if self.replay_buffer.len() >= REPLAY_BUFFER_SIZE {
                self.replay_buffer.pop_front();
            }
            self.replay_buffer.push_back(window_data.to_vec());
        }

        // Train on randomly sampled replay windows for diversity.
        // Note: thread_rng() is used for non-cryptographic sampling only (replay
        // buffer shuffling). This is not a security boundary — FIPS N/A.
        let replay_count = REPLAY_SAMPLES_PER_STEP.min(self.replay_buffer.len());
        if replay_count > 0 {
            let buf_slice: Vec<&Vec<f32>> = self.replay_buffer.iter().collect();
            let mut rng = rand::thread_rng();
            let samples: Vec<Vec<f32>> = buf_slice
                .choose_multiple(&mut rng, replay_count)
                .map(|s| (*s).clone())
                .collect();
            for sample in &samples {
                self.train_on_window(sample, device);
            }
        }

        // Refresh inference model cache after training
        self.inference_model = Some(self.model.valid());

        // LR decay
        if self.step_count.is_multiple_of(DECAY_EVERY_N_STEPS) && self.step_count > 0 {
            self.current_lr = (self.current_lr * LR_DECAY_FACTOR).max(MIN_LEARNING_RATE);
        }

        // Checkpoint (weights only — optimizer state is not persisted)
        if self.step_count.is_multiple_of(CHECKPOINT_EVERY_N_STEPS) && self.step_count > 0 {
            if let Err(e) = self.save_checkpoint() {
                warn!(error = %e, "failed to save model checkpoint");
            }
        }
    }

    /// Run forward + backward + optimizer step on a single window.
    fn train_on_window(&mut self, data: &[f32], device: &NdDevice) {
        let input = Tensor::<TrainBackend, 1>::from_floats(data, device).reshape([
            1,
            self.seq_len,
            self.input_dim,
        ]);

        let loss = self.model.forward_loss(input);
        let grads = loss.backward();
        let grads_params = GradientsParams::from_grads(grads, &self.model);
        // clone() required: Optimizer::step() takes ownership and returns a new model.
        self.model = self
            .optim
            .step(self.current_lr, self.model.clone(), grads_params);
        self.step_count += 1;
    }

    /// Score a window using the cached inference model (no autodiff overhead).
    fn cached_score(&self, window_data: &[f32], device: &NdDevice) -> Option<f32> {
        let inference = self.inference_model.as_ref()?;
        let tensor = Tensor::<NdArray, 1>::from_floats(window_data, device).reshape([
            1,
            self.seq_len,
            self.input_dim,
        ]);
        Some(inference.score(tensor))
    }

    /// Save model checkpoint atomically (write to .tmp, then rename).
    /// Only model weights are saved — optimizer state is lost on restart.
    pub fn save_checkpoint(&self) -> anyhow::Result<()> {
        self.save_checkpoint_to(Path::new(CHECKPOINT_DIR))
    }

    /// Save model checkpoint to a specific directory (for testing).
    fn save_checkpoint_to(&self, dir: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(dir)?;

        let tmp_path = dir.join(CHECKPOINT_TMP_FILENAME);
        let final_path = dir.join(CHECKPOINT_FILENAME);

        let inference = self.model.valid();
        let record = inference.into_record();
        let item = record.into_item::<FullPrecisionSettings>();
        let json = serde_json::to_vec(&item)?;

        std::fs::write(&tmp_path, &json)?;
        std::fs::rename(&tmp_path, &final_path)?;

        info!(step = self.step_count, "saved model checkpoint");
        Ok(())
    }

    /// Attempt to load a checkpoint. Returns true if successful.
    /// Only model weights are restored — optimizer state starts fresh.
    pub fn load_checkpoint(&mut self, device: &NdDevice) -> bool {
        self.load_checkpoint_from(Path::new(CHECKPOINT_DIR), device)
    }

    /// Load checkpoint from a specific directory (for testing).
    fn load_checkpoint_from(&mut self, dir: &Path, device: &NdDevice) -> bool {
        let model_path = dir.join(CHECKPOINT_FILENAME);
        match Self::try_load_model(&model_path, self.input_dim, device) {
            Ok((inference, train)) => {
                self.inference_model = Some(inference);
                self.model = train;
                self.warmup_complete = true;
                self.cold_start_remaining = 0;
                info!("loaded model checkpoint, skipping warmup");
                true
            }
            Err(e) => {
                warn!(error = %e, "failed to load checkpoint, starting fresh");
                Self::delete_checkpoint_files(dir);
                false
            }
        }
    }

    fn try_load_model(
        path: &Path,
        input_dim: usize,
        device: &NdDevice,
    ) -> anyhow::Result<(GpuAnomalyModel<NdArray>, GpuAnomalyModel<TrainBackend>)> {
        let data = std::fs::read(path)?;
        let num_gpus = input_dim / crate::config::FEATURES_PER_GPU;

        // Checkpoint is serialized from NdArray record (via model.valid())
        type NdRecord = <GpuAnomalyModel<NdArray> as Module<NdArray>>::Record;
        type NdRecordItem = <NdRecord as Record<NdArray>>::Item<FullPrecisionSettings>;

        // Load inference model (NdArray)
        let item: NdRecordItem = serde_json::from_slice(&data)?;
        let nd_record = NdRecord::from_item::<FullPrecisionSettings>(item, device);
        let inference = GpuAnomalyModel::<NdArray>::new(device, num_gpus).load_record(nd_record);

        // Load training model: deserialize the same JSON into the Autodiff record.
        // Autodiff<NdArray> and NdArray records have identical serialized forms, but
        // are distinct Rust types, so we must deserialize separately.
        // TODO: burn doesn't expose NdArray→Autodiff record conversion; revisit if
        // a future version adds AutodiffModule::from_inner() or similar.
        type AdRecord = <GpuAnomalyModel<TrainBackend> as Module<TrainBackend>>::Record;
        type AdRecordItem = <AdRecord as Record<TrainBackend>>::Item<FullPrecisionSettings>;

        let ad_item: AdRecordItem = serde_json::from_slice(&data)?;
        let ad_record = AdRecord::from_item::<FullPrecisionSettings>(ad_item, device);
        let train = GpuAnomalyModel::<TrainBackend>::new(device, num_gpus).load_record(ad_record);

        Ok((inference, train))
    }

    /// Delete only the known checkpoint files, logging any errors.
    fn delete_checkpoint_files(dir: &Path) {
        for name in [CHECKPOINT_FILENAME, CHECKPOINT_TMP_FILENAME] {
            let path = dir.join(name);
            if path.exists() {
                if let Err(e) = std::fs::remove_file(&path) {
                    warn!(path = %path.display(), error = %e, "failed to remove stale checkpoint");
                }
            }
        }
    }

    /// Whether the trainer has completed warmup and is producing scores.
    pub fn is_warmed_up(&self) -> bool {
        self.warmup_complete
    }

    /// Current training step count (optimizer updates, including replay).
    pub fn step_count(&self) -> u64 {
        self.step_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_window(input_dim: usize, seq_len: usize, value: f32) -> Vec<f32> {
        vec![value; input_dim * seq_len]
    }

    #[test]
    fn trainer_initializes_not_warmed_up() {
        let device = Default::default();
        let trainer = OnlineTrainer::new(1, 10, &device);
        assert!(!trainer.is_warmed_up());
        assert_eq!(trainer.step_count(), 0);
    }

    #[test]
    fn step_returns_none_before_warmup() {
        let device = Default::default();
        let num_gpus = 1;
        let seq_len = 10;
        let input_dim = num_gpus * crate::config::FEATURES_PER_GPU;
        let mut trainer = OnlineTrainer::new(num_gpus, seq_len, &device);

        let window = make_window(input_dim, seq_len, 0.5);
        let result = trainer.step(&window, &device);
        assert!(result.is_none());
    }

    #[test]
    fn step_returns_some_after_warmup() {
        let device = Default::default();
        let num_gpus = 1;
        let seq_len = 10;
        let input_dim = num_gpus * crate::config::FEATURES_PER_GPU;
        let mut trainer = OnlineTrainer::new(num_gpus, seq_len, &device);

        let window = make_window(input_dim, seq_len, 0.5);

        // Do one train step to create inference model cache
        trainer.scrape_count = TRAIN_EVERY_N_SCRAPES - 1;
        let _ = trainer.step(&window, &device);

        // Fast-forward to warmup boundary
        trainer.scrape_count = WARMUP_WINDOWS - 1;
        let _ = trainer.step(&window, &device);
        assert!(trainer.is_warmed_up());

        // Next step should return Some
        let result = trainer.step(&window, &device);
        assert!(result.is_some());
    }

    #[test]
    fn score_decreases_over_training() {
        let device = Default::default();
        let num_gpus = 1;
        let seq_len = 10;
        let input_dim = num_gpus * crate::config::FEATURES_PER_GPU;
        let mut trainer = OnlineTrainer::new(num_gpus, seq_len, &device);

        let window = make_window(input_dim, seq_len, 0.3);

        // Get initial score by training once to create inference model
        trainer.train_on_window(&window, &device);
        trainer.inference_model = Some(trainer.model.valid());
        let initial_score = trainer.cached_score(&window, &device).unwrap();

        // Train for many steps on the same data
        for _ in 0..100 {
            trainer.train_on_window(&window, &device);
        }
        trainer.inference_model = Some(trainer.model.valid());
        let final_score = trainer.cached_score(&window, &device).unwrap();

        assert!(
            final_score < initial_score,
            "score should decrease with training: initial={initial_score}, final={final_score}"
        );
    }

    #[test]
    fn checkpoint_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();

        let device = Default::default();
        let num_gpus = 1;
        let seq_len = 10;
        let input_dim = num_gpus * crate::config::FEATURES_PER_GPU;

        let mut trainer = OnlineTrainer::new(num_gpus, seq_len, &device);
        let window = make_window(input_dim, seq_len, 0.3);

        // Train a bit so weights diverge from random init
        for _ in 0..10 {
            trainer.train_on_window(&window, &device);
        }
        trainer.inference_model = Some(trainer.model.valid());
        let score_before = trainer.cached_score(&window, &device).unwrap();

        // Save checkpoint
        trainer.save_checkpoint_to(dir.path()).unwrap();

        // Load into a fresh trainer
        let mut trainer2 = OnlineTrainer::new(num_gpus, seq_len, &device);
        assert!(trainer2.load_checkpoint_from(dir.path(), &device));
        assert_eq!(
            trainer2.cold_start_remaining, 0,
            "checkpoint load should not trigger cold-start"
        );

        let score_after = trainer2.cached_score(&window, &device).unwrap();

        assert!(
            (score_before - score_after).abs() < 1e-4,
            "scores should match after checkpoint roundtrip: before={score_before}, after={score_after}"
        );
    }

    #[test]
    fn nan_input_returns_none_not_nan_score() {
        let device = Default::default();
        let num_gpus = 1;
        let seq_len = 10;
        let input_dim = num_gpus * crate::config::FEATURES_PER_GPU;
        let mut trainer = OnlineTrainer::new(num_gpus, seq_len, &device);

        // Train once to create inference model, then mark warmed up
        let good_window = make_window(input_dim, seq_len, 0.5);
        trainer.train_on_window(&good_window, &device);
        trainer.inference_model = Some(trainer.model.valid());
        trainer.warmup_complete = true;

        let step_before = trainer.step_count();

        // Feed NaN window — should return None (not a NaN score)
        let mut bad_window = make_window(input_dim, seq_len, 0.5);
        bad_window[0] = f32::NAN;

        trainer.scrape_count = TRAIN_EVERY_N_SCRAPES - 1;
        let result = trainer.step(&bad_window, &device);

        assert!(
            result.is_none(),
            "NaN input should return None, not a score"
        );
        assert_eq!(
            trainer.step_count(),
            step_before,
            "step count should not increase with NaN input"
        );
    }

    #[test]
    fn inf_input_skips_training() {
        let device = Default::default();
        let num_gpus = 1;
        let seq_len = 10;
        let input_dim = num_gpus * crate::config::FEATURES_PER_GPU;
        let mut trainer = OnlineTrainer::new(num_gpus, seq_len, &device);

        let mut bad_window = make_window(input_dim, seq_len, 0.5);
        bad_window[5] = f32::INFINITY;

        trainer.scrape_count = TRAIN_EVERY_N_SCRAPES - 1;
        let result = trainer.step(&bad_window, &device);

        assert!(result.is_none(), "Inf input should return None");
        assert_eq!(trainer.step_count(), 0, "Inf input should skip training");
    }

    #[test]
    fn stale_checkpoint_discarded_gracefully() {
        let dir = tempfile::tempdir().unwrap();

        // Write garbage to simulate a corrupt checkpoint
        std::fs::write(dir.path().join(CHECKPOINT_FILENAME), b"not valid json {{{").unwrap();

        let device = Default::default();
        let mut trainer = OnlineTrainer::new(1, 10, &device);

        // Should fail gracefully and delete the stale file
        assert!(!trainer.load_checkpoint_from(dir.path(), &device));
        assert!(!trainer.is_warmed_up());
        // Stale file should be cleaned up
        assert!(!dir.path().join(CHECKPOINT_FILENAME).exists());
    }

    #[test]
    fn replay_buffer_fills_and_evicts() {
        let device = Default::default();
        let num_gpus = 1;
        let seq_len = 10;
        let input_dim = num_gpus * crate::config::FEATURES_PER_GPU;
        let mut trainer = OnlineTrainer::new(num_gpus, seq_len, &device);

        for i in 0..(REPLAY_BUFFER_SIZE + 5) {
            let window = make_window(input_dim, seq_len, 0.1 + i as f32 * 0.001);
            trainer.scrape_count = (i as u64 + 1) * TRAIN_EVERY_N_SCRAPES;
            trainer.train_step(&window, None, &device);
        }

        assert_eq!(
            trainer.replay_buffer.len(),
            REPLAY_BUFFER_SIZE,
            "replay buffer should cap at REPLAY_BUFFER_SIZE"
        );
    }

    #[test]
    fn cold_start_grace_allows_high_score_training() {
        let device = Default::default();
        let num_gpus = 1;
        let seq_len = 10;
        let input_dim = num_gpus * crate::config::FEATURES_PER_GPU;
        let mut trainer = OnlineTrainer::new(num_gpus, seq_len, &device);

        // Simulate post-warmup state with cold-start grace active
        trainer.warmup_complete = true;
        trainer.cold_start_remaining = COLD_START_GRACE_STEPS;

        let window = make_window(input_dim, seq_len, 0.5);
        let step_before = trainer.step_count();

        // Score > HEALTHY_SCORE_CEILING but within cold-start grace
        trainer.train_step(&window, Some(0.8), &device);

        assert!(
            trainer.step_count() > step_before,
            "cold-start grace should allow training even with high score"
        );
    }

    #[test]
    fn cold_start_grace_expires() {
        let device = Default::default();
        let num_gpus = 1;
        let seq_len = 10;
        let input_dim = num_gpus * crate::config::FEATURES_PER_GPU;
        let mut trainer = OnlineTrainer::new(num_gpus, seq_len, &device);

        trainer.warmup_complete = true;
        trainer.cold_start_remaining = 1;

        let window = make_window(input_dim, seq_len, 0.5);

        // Last grace step — training should proceed
        trainer.train_step(&window, Some(0.8), &device);
        let step_after_grace = trainer.step_count();
        assert!(step_after_grace > 0, "should train during last grace step");
        assert_eq!(trainer.cold_start_remaining, 0, "grace should be consumed");

        // Grace expired — high score should be skipped
        let step_before = trainer.step_count();
        trainer.train_step(&window, Some(0.8), &device);
        assert_eq!(
            trainer.step_count(),
            step_before,
            "should skip training after grace expires for high-score window"
        );
    }
}
