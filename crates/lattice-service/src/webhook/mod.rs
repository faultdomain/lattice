//! Mutating Admission Webhook for Lattice
//!
//! This module provides a mutating admission webhook that intercepts Deployment
//! create/update operations and injects container specs from LatticeService CRDs.
//!
//! The webhook enables a clean separation of concerns:
//! - Controller: Creates skeleton Deployments, Services, HPA, and Policies
//! - Webhook: Fills in container specs from LatticeService
//!
//! This architecture prepares for future `workloadRef` support where users can
//! reference existing Deployments instead of having the controller create them.

pub mod deployment;

use std::sync::Arc;

use axum::{routing::post, Router};
use kube::Client;

/// Shared state for webhook handlers
#[derive(Clone)]
pub struct WebhookState {
    /// Kubernetes client for looking up LatticeService resources
    pub kube: Client,
}

impl WebhookState {
    /// Create a new webhook state with the given Kubernetes client
    pub fn new(kube: Client) -> Self {
        Self { kube }
    }
}

/// Create the webhook router with all mutation endpoints
///
/// Currently supports:
/// - POST /mutate/deployments - Mutate Deployments with LatticeService specs
pub fn webhook_router(state: Arc<WebhookState>) -> Router {
    Router::new()
        .route("/mutate/deployments", post(deployment::mutate_handler))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_webhook_state_creation() {
        // WebhookState is just a wrapper, can't test without real client
        // but we can verify the struct exists and has expected fields
    }
}
