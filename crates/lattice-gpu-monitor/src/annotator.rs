//! Node annotation patcher.
//!
//! Updates node annotations with GPU health status. Only patches when
//! values change to avoid unnecessary API calls.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::Node;
use kube::api::{Api, Patch, PatchParams};
use thiserror::Error;
use tracing::{debug, info};

use lattice_common::gpu::{
    ANNOTATION_ANOMALY_SCORE, ANNOTATION_GPU_HEALTH, ANNOTATION_GPU_LOSS,
    ANNOTATION_HEARTBEAT,
};
use crate::gpu_loss::GpuLossStatus;
use crate::scorer::HealthStatus;

#[derive(Debug, Error)]
pub enum AnnotatorError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
}

/// Patches GPU monitoring annotations on a node.
pub struct NodeAnnotator {
    client: kube::Client,
    node_name: String,
    last_health: Option<String>,
    last_loss: Option<bool>,
}

impl NodeAnnotator {
    pub fn new(client: kube::Client, node_name: String) -> Self {
        Self {
            client,
            node_name,
            last_health: None,
            last_loss: None,
        }
    }

    /// Update node annotations based on current health and GPU loss status.
    ///
    /// Always patches (the heartbeat timestamp changes every call).
    /// Logs state transitions for health and GPU loss.
    pub async fn update(
        &mut self,
        health: &HealthStatus,
        gpu_loss: &GpuLossStatus,
    ) -> Result<(), AnnotatorError> {
        let health_str = health.as_str().to_string();
        let loss_detected = gpu_loss.is_loss_detected();

        let health_changed = self.last_health.as_ref() != Some(&health_str);
        let loss_changed = self.last_loss != Some(loss_detected);

        let now = chrono::Utc::now().to_rfc3339();
        let mut annotations = BTreeMap::new();
        annotations.insert(
            ANNOTATION_ANOMALY_SCORE.to_string(),
            format!("{:.4}", health.score()),
        );
        annotations.insert(ANNOTATION_GPU_HEALTH.to_string(), health_str.clone());
        annotations.insert(
            ANNOTATION_GPU_LOSS.to_string(),
            loss_detected.to_string(),
        );
        annotations.insert(ANNOTATION_HEARTBEAT.to_string(), now.clone());

        let patch = serde_json::json!({
            "metadata": {
                "annotations": annotations
            }
        });

        let node_api: Api<Node> = Api::all(self.client.clone());
        node_api
            .patch(
                &self.node_name,
                &PatchParams::apply("lattice-gpu-monitor"),
                &Patch::Merge(&patch),
            )
            .await?;

        if health_changed {
            info!(
                node = %self.node_name,
                health = %health_str,
                score = health.score(),
                "GPU health status changed"
            );
        }
        if loss_changed {
            info!(
                node = %self.node_name,
                loss_detected,
                "GPU loss status changed"
            );
        }

        self.last_health = Some(health_str);
        self.last_loss = Some(loss_detected);
        debug!(node = %self.node_name, "node annotations updated");
        Ok(())
    }
}
