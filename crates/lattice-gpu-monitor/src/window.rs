//! Sliding window ring buffer for time-series feature data.
//!
//! Stores the last N timesteps of GPU features for the autoencoder.

use std::collections::VecDeque;

use crate::config::FEATURES_PER_GPU;
use crate::features::NodeFeatures;

/// Fixed-capacity sliding window of NodeFeatures.
pub struct SlidingWindow {
    buffer: VecDeque<NodeFeatures>,
    capacity: usize,
    gpu_count: Option<usize>,
}

impl SlidingWindow {
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: VecDeque::with_capacity(capacity),
            capacity,
            gpu_count: None,
        }
    }

    /// Push a new sample, dropping the oldest if at capacity.
    pub fn push(&mut self, features: NodeFeatures) {
        if self.gpu_count.is_none() && !features.per_gpu.is_empty() {
            self.gpu_count = Some(features.per_gpu.len());
        }
        if self.buffer.len() == self.capacity {
            self.buffer.pop_front();
        }
        self.buffer.push_back(features);
    }

    /// Whether the window has reached full capacity.
    pub fn is_full(&self) -> bool {
        self.buffer.len() == self.capacity
    }

    /// Current number of samples in the window.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the window is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Number of GPUs tracked (from the first sample pushed).
    pub fn gpu_count(&self) -> usize {
        self.gpu_count.unwrap_or(0)
    }

    /// Flatten the window into a 2D array: (window_size, num_gpus * features_per_gpu).
    ///
    /// Returns None if the window is not full or has no GPU data.
    pub fn as_flat_matrix(&self) -> Option<Vec<Vec<f32>>> {
        if !self.is_full() || self.gpu_count.is_none() {
            return None;
        }

        let rows: Vec<Vec<f32>> = self.buffer.iter().map(|nf| nf.as_flat_vec()).collect();
        Some(rows)
    }

    /// Flatten into a single contiguous Vec<f32> of shape (window_size * feature_dim).
    pub fn as_contiguous(&self) -> Option<Vec<f32>> {
        let matrix = self.as_flat_matrix()?;
        let gpu_count = self.gpu_count();
        if gpu_count == 0 {
            return None;
        }
        let feature_dim = gpu_count * FEATURES_PER_GPU;
        let mut out = Vec::with_capacity(self.capacity * feature_dim);
        for row in &matrix {
            if row.len() != feature_dim {
                return None;
            }
            out.extend_from_slice(row);
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::{GpuSample, NodeSample};
    use crate::features::compute_features;
    use std::time::Instant;

    fn one_gpu_sample(temp: f32) -> NodeSample {
        NodeSample {
            gpus: vec![GpuSample {
                gpu_index: 0,
                gpu_temp: temp,
                fb_free: 1.0,
                ..Default::default()
            }],
            timestamp: Instant::now(),
        }
    }

    #[test]
    fn window_fills_to_capacity() {
        let mut w = SlidingWindow::new(3);
        assert!(!w.is_full());
        for i in 0..3 {
            w.push(compute_features(&one_gpu_sample(40.0 + i as f32)));
        }
        assert!(w.is_full());
        assert_eq!(w.len(), 3);
    }

    #[test]
    fn window_drops_oldest() {
        let mut w = SlidingWindow::new(2);
        w.push(compute_features(&one_gpu_sample(40.0)));
        w.push(compute_features(&one_gpu_sample(50.0)));
        w.push(compute_features(&one_gpu_sample(60.0)));
        assert_eq!(w.len(), 2);
        // Oldest (40.0) should be dropped
        let matrix = w.as_flat_matrix().unwrap();
        // GPU temp is the first raw feature (index 0)
        assert!((matrix[0][0] - 50.0).abs() < f32::EPSILON);
        assert!((matrix[1][0] - 60.0).abs() < f32::EPSILON);
    }

    #[test]
    fn not_full_returns_none() {
        let mut w = SlidingWindow::new(3);
        w.push(compute_features(&one_gpu_sample(40.0)));
        assert!(w.as_flat_matrix().is_none());
    }

    #[test]
    fn flat_matrix_shape() {
        let mut w = SlidingWindow::new(2);
        w.push(compute_features(&one_gpu_sample(40.0)));
        w.push(compute_features(&one_gpu_sample(50.0)));
        let matrix = w.as_flat_matrix().unwrap();
        assert_eq!(matrix.len(), 2); // window_size
        assert_eq!(matrix[0].len(), FEATURES_PER_GPU); // 1 GPU * 24 features
    }

    #[test]
    fn contiguous_flattening() {
        let mut w = SlidingWindow::new(2);
        w.push(compute_features(&one_gpu_sample(40.0)));
        w.push(compute_features(&one_gpu_sample(50.0)));
        let flat = w.as_contiguous().unwrap();
        assert_eq!(flat.len(), 2 * FEATURES_PER_GPU);
    }

    #[test]
    fn empty_window() {
        let w = SlidingWindow::new(5);
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
        assert_eq!(w.gpu_count(), 0);
    }
}
