//! Forwarding event publisher for agent clusters
//!
//! Publishes events locally via KubeEventPublisher AND forwards Lattice
//! lifecycle events up the hierarchy to the parent cell over the gRPC stream.

use async_trait::async_trait;
use k8s_openapi::api::core::v1::ObjectReference;
use kube::runtime::events::EventType;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use lattice_common::events::{reasons, EventPublisher, KubeEventPublisher};
use lattice_proto::{agent_message::Payload, AgentMessage, LatticeEvent};

/// Set of event reasons that are forwarded up the hierarchy.
///
/// Only Lattice lifecycle reasons are forwarded — not arbitrary K8s events.
const FORWARDED_REASONS: &[&str] = &[
    reasons::PROVISIONING_STARTED,
    reasons::INFRASTRUCTURE_READY,
    reasons::PIVOT_STARTED,
    reasons::PIVOT_COMPLETE,
    reasons::CLUSTER_READY,
    reasons::CLUSTER_FAILED,
    reasons::DELETION_STARTED,
    reasons::UNPIVOT_STARTED,
    reasons::WORKER_SCALING,
    reasons::VALIDATION_FAILED,
    reasons::COMPILATION_SUCCESS,
    reasons::COMPILATION_FAILED,
    reasons::SECRET_ACCESS_DENIED,
];

/// Event publisher that publishes locally AND forwards lifecycle events to parent.
pub struct ForwardingEventPublisher {
    local: KubeEventPublisher,
    tx: mpsc::Sender<AgentMessage>,
    cluster_name: String,
}

impl ForwardingEventPublisher {
    /// Create a new ForwardingEventPublisher.
    ///
    /// - `local`: the KubeEventPublisher for local K8s events
    /// - `tx`: the gRPC message sender to forward events to parent
    /// - `cluster_name`: this cluster's name (used as source_cluster)
    pub fn new(
        local: KubeEventPublisher,
        tx: mpsc::Sender<AgentMessage>,
        cluster_name: impl Into<String>,
    ) -> Self {
        Self {
            local,
            tx,
            cluster_name: cluster_name.into(),
        }
    }
}

#[async_trait]
impl EventPublisher for ForwardingEventPublisher {
    async fn publish(
        &self,
        resource_ref: &ObjectReference,
        type_: EventType,
        reason: &str,
        action: &str,
        note: Option<String>,
    ) {
        // Always publish locally
        self.local
            .publish(resource_ref, type_, reason, action, note.clone())
            .await;

        // Forward if this is a Lattice lifecycle reason
        if FORWARDED_REASONS.contains(&reason) {
            let severity = match type_ {
                EventType::Normal => "Normal",
                EventType::Warning => "Warning",
            };

            let event = LatticeEvent {
                reason: reason.to_string(),
                action: action.to_string(),
                message: note.unwrap_or_default(),
                severity: severity.to_string(),
                timestamp: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
                source_cluster: self.cluster_name.clone(),
            };

            let msg = AgentMessage {
                cluster_name: self.cluster_name.clone(),
                payload: Some(Payload::Event(event)),
            };

            if let Err(e) = self.tx.send(msg).await {
                warn!(reason, error = %e, "Failed to forward event to parent");
            } else {
                debug!(reason, "Forwarded lifecycle event to parent");
            }
        }
    }
}
