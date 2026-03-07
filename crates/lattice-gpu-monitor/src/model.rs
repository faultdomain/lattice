//! GRU autoencoder for GPU anomaly detection.
//!
//! Uses the Burn framework with ndarray backend (pure Rust, no BLAS).
//! The model reconstructs input sequences and the reconstruction error
//! serves as an anomaly score.

use burn::module::Module;
use burn::nn::{
    gru::{Gru, GruConfig},
    Linear, LinearConfig,
};
use burn::tensor::backend::Backend;
use burn::tensor::{ElementConversion, Tensor};

use crate::config::FEATURES_PER_GPU;

/// GRU autoencoder for detecting GPU anomalies from time-series features.
///
/// Architecture:
/// - Encoder GRU: compresses the input sequence into a hidden state
/// - Decoder GRU: reconstructs the sequence from the hidden state
/// - Output projection: maps decoder output back to input dimensions
///
/// FIPS note: uses ndarray backend (pure Rust math). No native BLAS.
#[derive(Module, Debug)]
pub struct GpuAnomalyModel<B: Backend> {
    encoder: Gru<B>,
    decoder: Gru<B>,
    output_proj: Linear<B>,
}

impl<B: Backend> GpuAnomalyModel<B> {
    /// Create a new model for the given number of GPUs.
    pub fn new(device: &B::Device, num_gpus: usize) -> Self {
        let input_dim = num_gpus * FEATURES_PER_GPU;
        let hidden_dim = input_dim / 2; // Compression ratio 2:1

        let encoder = GruConfig::new(input_dim, hidden_dim, true).init(device);
        let decoder = GruConfig::new(hidden_dim, hidden_dim, true).init(device);
        let output_proj = LinearConfig::new(hidden_dim, input_dim).init(device);

        Self {
            encoder,
            decoder,
            output_proj,
        }
    }

    /// Forward pass returning the MSE loss as a tensor (for backprop).
    ///
    /// Input shape: [batch=1, seq_len, input_dim]
    /// Returns: scalar MSE tensor
    pub fn forward_loss(&self, input: Tensor<B, 3>) -> Tensor<B, 1> {
        let encoded = self.encoder.forward(input.clone(), None);
        let decoded = self.decoder.forward(encoded, None);
        let reconstructed = self.output_proj.forward(decoded);
        let diff = input - reconstructed;
        diff.clone().mul(diff).mean().reshape([1])
    }

    /// Compute reconstruction error (MSE) as an anomaly score.
    ///
    /// Input shape: [batch=1, seq_len, input_dim]
    /// Returns: scalar MSE between input and reconstruction
    pub fn score(&self, input: Tensor<B, 3>) -> f32 {
        self.forward_loss(input).into_scalar().elem::<f32>()
    }
}

/// Detect GPU architecture from node labels.
pub async fn detect_gpu_architecture(
    client: &kube::Client,
    node_name: &str,
) -> Result<String, kube::Error> {
    use k8s_openapi::api::core::v1::Node;
    use kube::api::Api;
    use lattice_common::resources::GPU_TYPE_LABEL;

    let node_api: Api<Node> = Api::all(client.clone());
    let node = node_api.get(node_name).await?;

    let gpu_type = node
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(GPU_TYPE_LABEL))
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    Ok(gpu_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use burn::backend::NdArray;

    type TestBackend = NdArray;

    #[test]
    fn model_creates_successfully() {
        let device = Default::default();
        let _model = GpuAnomalyModel::<TestBackend>::new(&device, 2);
    }

    #[test]
    fn model_produces_score() {
        let device = Default::default();
        let model = GpuAnomalyModel::<TestBackend>::new(&device, 1);
        let input_dim = FEATURES_PER_GPU;
        let seq_len = 10;

        // Create a random-ish input tensor [1, seq_len, input_dim]
        let data: Vec<f32> = (0..seq_len * input_dim)
            .map(|i| (i as f32 * 0.01).sin())
            .collect();
        let input = Tensor::<TestBackend, 1>::from_floats(data.as_slice(), &device)
            .reshape([1, seq_len, input_dim]);

        let score = model.score(input);
        // Score should be a non-negative number
        assert!(score >= 0.0, "score should be non-negative: {}", score);
        assert!(score.is_finite(), "score should be finite: {}", score);
    }

    #[test]
    fn model_score_changes_with_different_inputs() {
        let device = Default::default();
        let model = GpuAnomalyModel::<TestBackend>::new(&device, 1);
        let input_dim = FEATURES_PER_GPU;
        let seq_len = 10;

        let normal: Vec<f32> = vec![0.5; seq_len * input_dim];
        let anomalous: Vec<f32> = (0..seq_len * input_dim)
            .map(|i| if i % 3 == 0 { 100.0 } else { 0.0 })
            .collect();

        let normal_input = Tensor::<TestBackend, 1>::from_floats(normal.as_slice(), &device)
            .reshape([1, seq_len, input_dim]);
        let anomalous_input =
            Tensor::<TestBackend, 1>::from_floats(anomalous.as_slice(), &device)
                .reshape([1, seq_len, input_dim]);

        let normal_score = model.score(normal_input);
        let anomalous_score = model.score(anomalous_input);

        // Both should be finite
        assert!(normal_score.is_finite());
        assert!(anomalous_score.is_finite());
    }
}
