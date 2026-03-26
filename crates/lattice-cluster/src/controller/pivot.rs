//! Pivot operations implementation.
//!
//! This module contains the real implementation of the `PivotOperations` trait,
//! which uses the AgentRegistry to orchestrate the distributed move protocol.

use std::sync::Arc;

use async_trait::async_trait;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use tracing::{info, warn};

#[cfg(test)]
use mockall::automock;

use lattice_common::crd::LatticeCluster;
use lattice_common::{DistributableResources, Error};
use lattice_move::CellMoverConfig;
use lattice_proto::AgentState;

use lattice_cell::{fetch_distributable_resources, SharedAgentRegistry};

use super::FIELD_MANAGER;

/// Trait abstracting pivot operations for testability
#[cfg_attr(test, automock)]
#[async_trait]
pub trait PivotOperations: Send + Sync {
    /// Export CAPI manifests and send to agent for import.
    async fn trigger_pivot(
        &self,
        cluster_name: &str,
        source_namespace: &str,
        target_namespace: &str,
    ) -> Result<(), Error>;

    /// Check if agent is ready for pivot
    fn is_agent_ready(&self, cluster_name: &str) -> bool;

    /// Check if pivot is complete
    fn is_pivot_complete(&self, cluster_name: &str) -> bool;
}

/// Real implementation of PivotOperations using AgentRegistry
pub struct PivotOperationsImpl {
    agent_registry: SharedAgentRegistry,
    client: Client,
    self_cluster_name: Option<String>,
}

impl PivotOperationsImpl {
    /// Create new pivot operations with the given agent registry
    pub fn new(
        agent_registry: SharedAgentRegistry,
        client: Client,
        self_cluster_name: Option<String>,
    ) -> Self {
        Self {
            agent_registry,
            client,
            self_cluster_name,
        }
    }
}

#[async_trait]
impl PivotOperations for PivotOperationsImpl {
    async fn trigger_pivot(
        &self,
        cluster_name: &str,
        source_namespace: &str,
        target_namespace: &str,
    ) -> Result<(), Error> {
        // Check if agent is connected
        if self.agent_registry.get(cluster_name).is_none() {
            return Err(Error::pivot(format!(
                "agent not connected for cluster {}",
                cluster_name
            )));
        }

        // Mark pivot in progress to prevent duplicate triggers
        self.agent_registry
            .update_state(cluster_name, AgentState::Pivoting);

        // Fetch resources for distribution (InfraProviders, SecretProviders, CedarPolicies, OIDCProviders, and their secrets)
        let self_cluster_name = self.self_cluster_name.as_deref().unwrap_or("unknown");
        let resources = fetch_distributable_resources(&self.client, self_cluster_name)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "failed to fetch distributable resources, continuing without");
                DistributableResources::default()
            });

        // Configure the distributed move with resources
        // Note: Infrastructure manifests (network policies, etc.) are reconciled
        // continuously by the child cluster's controller after pivot
        let config = CellMoverConfig::new(source_namespace, target_namespace, cluster_name)
            .with_distributable_resources(&resources);

        // Create the gRPC command sender
        let sender = Arc::new(lattice_cell::GrpcMoveCommandSender::new(
            self.agent_registry.clone(),
            cluster_name.to_string(),
        ));

        // Execute the distributed move
        // All resources and manifests are sent via MoveComplete which has an ack
        let mut mover = lattice_move::CellMover::new(self.client.clone(), config, sender);
        let result = mover.execute().await.map_err(|e| {
            // Reset state on failure
            self.agent_registry
                .update_state(cluster_name, AgentState::Provisioning);
            Error::pivot(format!("distributed move failed: {}", e))
        })?;

        info!(
            cluster = %cluster_name,
            objects_moved = result.objects_moved,
            objects_deleted = result.objects_deleted,
            "pivot completed via distributed move"
        );

        // Move completed successfully (MoveCompleteAck received) - mark state
        self.agent_registry
            .update_state(cluster_name, AgentState::Ready);
        self.agent_registry.set_pivot_complete(cluster_name, true);

        // Persist pivot_complete to CRD status — this MUST succeed for crash
        // safety. Without it, the parent would re-trigger pivot on restart since
        // in-memory registry state is lost on crash.
        let api: Api<LatticeCluster> = Api::all(self.client.clone());
        let patch = serde_json::json!({
            "status": {
                "pivotComplete": true
            }
        });
        api.patch_status(
            cluster_name,
            &PatchParams::apply(FIELD_MANAGER),
            &Patch::Merge(&patch),
        )
        .await
        .map_err(|e| {
            Error::pivot(format!(
                "pivot succeeded but failed to persist pivot_complete: {e}"
            ))
        })?;

        Ok(())
    }

    fn is_agent_ready(&self, cluster_name: &str) -> bool {
        self.agent_registry
            .get(cluster_name)
            .is_some_and(|a| a.is_ready_for_pivot())
    }

    fn is_pivot_complete(&self, cluster_name: &str) -> bool {
        self.agent_registry
            .get(cluster_name)
            .is_some_and(|a| a.pivot_complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_cell::AgentRegistry;

    /// Get a K8s client for tests, or skip if not available
    async fn test_client() -> Option<Client> {
        lattice_common::fips::install_crypto_provider();
        Client::try_default().await.ok()
    }

    /// Story: Creating a new PivotOperationsImpl should work
    #[tokio::test]
    async fn create_pivot_operations() {
        let Some(client) = test_client().await else {
            eprintln!("Skipping test: no K8s cluster available");
            return;
        };
        let registry = Arc::new(AgentRegistry::new());
        let ops = PivotOperationsImpl::new(registry, client, None);
        // Just verify it can be created
        assert!(!ops.is_agent_ready("nonexistent-cluster"));
    }

    /// Story: Agent ready check should return false for unconnected cluster
    #[tokio::test]
    async fn agent_not_ready_when_not_connected() {
        let Some(client) = test_client().await else {
            eprintln!("Skipping test: no K8s cluster available");
            return;
        };
        let registry = Arc::new(AgentRegistry::new());
        let ops = PivotOperationsImpl::new(registry, client, None);

        assert!(!ops.is_agent_ready("test-cluster"));
    }

    /// Story: Pivot complete check should return false for unconnected cluster
    #[tokio::test]
    async fn pivot_not_complete_when_not_connected() {
        let Some(client) = test_client().await else {
            eprintln!("Skipping test: no K8s cluster available");
            return;
        };
        let registry = Arc::new(AgentRegistry::new());
        let ops = PivotOperationsImpl::new(registry, client, None);

        assert!(!ops.is_pivot_complete("test-cluster"));
    }

    /// Story: Trigger pivot should fail when agent is not connected
    #[tokio::test]
    async fn trigger_pivot_fails_when_no_agent() {
        let Some(client) = test_client().await else {
            eprintln!("Skipping test: no K8s cluster available");
            return;
        };
        let registry = Arc::new(AgentRegistry::new());
        let ops = PivotOperationsImpl::new(registry, client, None);

        let result = ops
            .trigger_pivot("test-cluster", "default", "default")
            .await;

        assert!(result.is_err());
        match result {
            Err(Error::Pivot { message, .. }) => {
                assert!(message.contains("agent not connected"));
            }
            _ => panic!("Expected Pivot error"),
        }
    }
}
