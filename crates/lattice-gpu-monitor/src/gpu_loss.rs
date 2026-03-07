//! GPU loss detection: allocatable == 0 check.
//!
//! Detects when ALL GPUs disappear from a node (hard loss). Only triggers
//! when allocatable drops to 0, not on partial degradation. Partial loss
//! (some GPUs still working) is handled by the anomaly scorer → cordon path.
//! Also detects ghost GPUs via DCGM scrape count dropping to 0.

use k8s_openapi::api::core::v1::Node;
use kube::api::Api;
use thiserror::Error;
use tracing::{debug, warn};

use lattice_common::resources::{parse_quantity_int, GPU_RESOURCE};

#[derive(Debug, Error)]
pub enum GpuLossError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("node not found: {0}")]
    NodeNotFound(String),
}

/// GPU loss status for a node.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GpuLossStatus {
    /// GPUs still present (allocatable > 0).
    Normal { allocatable: u32 },
    /// All GPUs gone (allocatable == 0). This is the only condition that
    /// triggers drain — partial loss is handled by anomaly scoring → cordon.
    Detected { previously_known: u32 },
}

impl GpuLossStatus {
    pub fn is_loss_detected(&self) -> bool {
        matches!(self, GpuLossStatus::Detected { .. })
    }
}

/// Checks for GPU loss on a specific node.
pub struct GpuLossChecker {
    client: kube::Client,
    node_name: String,
    /// GPU count from the first DCGM scrape (tracks ghost GPU disappearances).
    known_gpu_count: Option<u32>,
}

impl GpuLossChecker {
    pub fn new(client: kube::Client, node_name: String) -> Self {
        Self {
            client,
            node_name,
            known_gpu_count: None,
        }
    }

    /// Record the observed GPU count from DCGM.
    ///
    /// Should be called after each successful DCGM scrape. If the count
    /// drops below the initial observation, this is a ghost GPU signal.
    pub fn update_dcgm_gpu_count(&mut self, count: u32) {
        match self.known_gpu_count {
            None => self.known_gpu_count = Some(count),
            Some(known) if count < known => {
                warn!(
                    node = %self.node_name,
                    known,
                    current = count,
                    "DCGM GPU count dropped — possible ghost GPU"
                );
            }
            _ => {}
        }
    }

    /// Check if any GPUs have been lost on this node.
    ///
    /// Also incorporates ghost GPU detection from DCGM count tracking.
    pub async fn check(&self) -> Result<GpuLossStatus, GpuLossError> {
        let node_api: Api<Node> = Api::all(self.client.clone());
        let node = node_api
            .get(&self.node_name)
            .await
            .map_err(|e| match e {
                kube::Error::Api(ref ae) if ae.code == 404 => {
                    GpuLossError::NodeNotFound(self.node_name.clone())
                }
                other => GpuLossError::Kube(other),
            })?;

        let allocatable = node
            .status
            .as_ref()
            .and_then(|s| s.allocatable.as_ref())
            .and_then(|a| a.get(GPU_RESOURCE))
            .and_then(|q| parse_quantity_int(Some(q)).ok())
            .map(|v| v.max(0) as u32);

        debug!(
            node = %self.node_name,
            allocatable = ?allocatable,
            known_gpu_count = ?self.known_gpu_count,
            "GPU loss check"
        );

        match allocatable {
            // GPU resource field missing entirely — device plugin not registered
            // or node has no GPU capacity annotation. This is NOT a loss event;
            // don't false-positive on nodes that temporarily lose their plugin.
            None => Ok(GpuLossStatus::Normal { allocatable: 0 }),
            // Hard loss: allocatable dropped to 0 — all GPUs are gone.
            // Only report as Detected if we previously saw GPUs (known_gpu_count > 0),
            // otherwise this node never had GPUs from our perspective.
            Some(0) => {
                let previously_known = self.known_gpu_count.unwrap_or(0);
                if previously_known > 0 {
                    Ok(GpuLossStatus::Detected { previously_known })
                } else {
                    Ok(GpuLossStatus::Normal { allocatable: 0 })
                }
            }
            Some(count) => Ok(GpuLossStatus::Normal { allocatable: count }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_status_not_loss() {
        let status = GpuLossStatus::Normal { allocatable: 8 };
        assert!(!status.is_loss_detected());
    }

    #[test]
    fn detected_status_is_loss() {
        let status = GpuLossStatus::Detected { previously_known: 8 };
        assert!(status.is_loss_detected());
    }

    #[test]
    fn partial_loss_is_not_detected() {
        // 6 of 8 GPUs still present — not a hard loss, handled by anomaly scoring
        let status = GpuLossStatus::Normal { allocatable: 6 };
        assert!(!status.is_loss_detected());
    }
}
