//! Feature pipeline: raw DCGM metrics → derived + relative features.
//!
//! Transforms raw per-GPU samples into a feature vector suitable for
//! the GRU autoencoder. Each GPU gets 24 features:
//! - 15 raw DCGM metrics
//! - 3 derived (thermal margin, ECC total, memory pressure)
//! - 6 relative (deltas from node mean)

use crate::collector::NodeSample;
use crate::config::{DERIVED_FEATURES, FEATURES_PER_GPU, RAW_FEATURES, RELATIVE_FEATURES, THROTTLE_TEMP};

/// Features for a single GPU.
#[derive(Debug, Clone)]
pub struct GpuFeatures {
    pub raw: [f32; RAW_FEATURES],
    pub derived: [f32; DERIVED_FEATURES],
    pub relative: [f32; RELATIVE_FEATURES],
}

impl GpuFeatures {
    /// Flatten all features into a single slice for the model.
    pub fn as_flat(&self) -> [f32; FEATURES_PER_GPU] {
        let mut out = [0.0f32; FEATURES_PER_GPU];
        out[..RAW_FEATURES].copy_from_slice(&self.raw);
        out[RAW_FEATURES..RAW_FEATURES + DERIVED_FEATURES].copy_from_slice(&self.derived);
        out[RAW_FEATURES + DERIVED_FEATURES..].copy_from_slice(&self.relative);
        out
    }
}

/// Features for all GPUs on a node at a single timestep.
#[derive(Debug, Clone)]
pub struct NodeFeatures {
    pub per_gpu: Vec<GpuFeatures>,
}

impl NodeFeatures {
    /// Total number of floats in this feature set.
    pub fn flat_len(&self) -> usize {
        self.per_gpu.len() * FEATURES_PER_GPU
    }

    /// Flatten all GPU features into a single Vec for tensor construction.
    pub fn as_flat_vec(&self) -> Vec<f32> {
        let mut out = Vec::with_capacity(self.flat_len());
        for gpu in &self.per_gpu {
            out.extend_from_slice(&gpu.as_flat());
        }
        out
    }
}

/// Compute features from a node sample.
pub fn compute_features(sample: &NodeSample) -> NodeFeatures {
    let gpu_count = sample.gpus.len() as f32;
    if gpu_count == 0.0 {
        return NodeFeatures {
            per_gpu: Vec::new(),
        };
    }

    // Node means for relative features
    let mean_temp: f32 = sample.gpus.iter().map(|g| g.gpu_temp).sum::<f32>() / gpu_count;
    let mean_power: f32 = sample.gpus.iter().map(|g| g.power_usage).sum::<f32>() / gpu_count;
    let mean_sm_util: f32 = sample.gpus.iter().map(|g| g.gpu_util).sum::<f32>() / gpu_count;
    let mean_mem_util: f32 =
        sample.gpus.iter().map(|g| g.mem_copy_util).sum::<f32>() / gpu_count;
    let mean_sm_clock: f32 = sample.gpus.iter().map(|g| g.sm_clock).sum::<f32>() / gpu_count;
    let mean_pcie_tx: f32 = sample.gpus.iter().map(|g| g.pcie_tx).sum::<f32>() / gpu_count;

    let per_gpu = sample
        .gpus
        .iter()
        .map(|gpu| {
            let total_fb = (gpu.fb_used + gpu.fb_free).max(1.0);
            GpuFeatures {
                raw: gpu.as_array(),
                derived: [
                    THROTTLE_TEMP - gpu.gpu_temp,  // thermal_margin
                    gpu.ecc_sbe + gpu.ecc_dbe,     // ecc_total (combined ECC error count)
                    gpu.fb_used / total_fb,         // memory_pressure
                ],
                relative: [
                    gpu.gpu_temp - mean_temp,       // temp_delta
                    gpu.power_usage - mean_power,   // power_delta
                    gpu.gpu_util - mean_sm_util,    // sm_util_delta
                    gpu.mem_copy_util - mean_mem_util, // mem_util_delta
                    gpu.sm_clock - mean_sm_clock,   // clock_delta
                    gpu.pcie_tx - mean_pcie_tx,     // pcie_delta
                ],
            }
        })
        .collect();

    NodeFeatures { per_gpu }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::{GpuSample, NodeSample};
    use std::time::Instant;

    fn two_gpu_sample() -> NodeSample {
        NodeSample {
            gpus: vec![
                GpuSample {
                    gpu_index: 0,
                    gpu_temp: 50.0,
                    power_usage: 200.0,
                    gpu_util: 80.0,
                    mem_copy_util: 40.0,
                    fb_used: 20000.0,
                    fb_free: 60000.0,
                    sm_clock: 1400.0,
                    pcie_tx: 5000.0,
                    ..Default::default()
                },
                GpuSample {
                    gpu_index: 1,
                    gpu_temp: 60.0,
                    power_usage: 250.0,
                    gpu_util: 90.0,
                    mem_copy_util: 50.0,
                    fb_used: 30000.0,
                    fb_free: 50000.0,
                    sm_clock: 1350.0,
                    pcie_tx: 6000.0,
                    ..Default::default()
                },
            ],
            timestamp: Instant::now(),
        }
    }

    #[test]
    fn compute_features_two_gpus() {
        let sample = two_gpu_sample();
        let features = compute_features(&sample);
        assert_eq!(features.per_gpu.len(), 2);
    }

    #[test]
    fn features_per_gpu_is_24() {
        let sample = two_gpu_sample();
        let features = compute_features(&sample);
        let flat = features.per_gpu[0].as_flat();
        assert_eq!(flat.len(), 24);
    }

    #[test]
    fn thermal_margin_computed() {
        let sample = two_gpu_sample();
        let features = compute_features(&sample);
        // GPU0 temp=50, THROTTLE_TEMP=83, margin=33
        assert!((features.per_gpu[0].derived[0] - 33.0).abs() < f32::EPSILON);
    }

    #[test]
    fn relative_deltas_sum_to_zero() {
        let sample = two_gpu_sample();
        let features = compute_features(&sample);
        // Temp deltas should sum to approximately 0 across GPUs
        let temp_delta_sum: f32 = features.per_gpu.iter().map(|g| g.relative[0]).sum();
        assert!(temp_delta_sum.abs() < 0.01);
    }

    #[test]
    fn flat_vec_length() {
        let sample = two_gpu_sample();
        let features = compute_features(&sample);
        assert_eq!(features.as_flat_vec().len(), 2 * 24);
    }

    #[test]
    fn empty_sample_returns_empty_features() {
        let sample = NodeSample {
            gpus: vec![],
            timestamp: Instant::now(),
        };
        let features = compute_features(&sample);
        assert!(features.per_gpu.is_empty());
    }

    #[test]
    fn memory_pressure_ratio() {
        let sample = two_gpu_sample();
        let features = compute_features(&sample);
        // GPU0: fb_used=20000, fb_free=60000, pressure = 20000/80000 = 0.25
        let pressure = features.per_gpu[0].derived[2];
        assert!((pressure - 0.25).abs() < 0.01);
    }
}
