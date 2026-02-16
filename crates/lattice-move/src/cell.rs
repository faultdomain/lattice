//! Cell-side move orchestrator
//!
//! Orchestrates the distributed move operation from the parent cluster (cell).
//! Discovers CAPI resources, computes move sequence, and streams batches to agent.
//!
//! This module also provides `prepare_move_objects()` for unpivot, where the agent
//! (child cluster) needs to discover and prepare objects for sending back to the cell.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kube::api::{Api, DeleteParams, DynamicObject, Patch, PatchParams};
use kube::Client;
use tracing::{debug, error, info, instrument, warn};

use lattice_common::kube_utils::build_api_resource;
use lattice_common::retry::{retry_with_backoff, RetryConfig};
use lattice_proto::{MoveObject, SourceOwnerRef};

use crate::error::MoveError;
use crate::graph::{GraphNode, ObjectGraph};
use crate::sequence::{extract_nodes_for_group, MoveSequence};
use lattice_common::capi_lifecycle::DELETE_FOR_MOVE_ANNOTATION;

// =============================================================================
// Standalone Functions (used by both pivot and unpivot)
// =============================================================================

/// Discover CAPI resources for a cluster and prepare them for move.
///
/// This is the shared logic used by both:
/// - Cell (pivot): discovers on parent, streams to agent
/// - Agent (unpivot): discovers on child, sends to cell via ClusterDeleting
///
/// Returns objects in topological order (owners before dependents).
/// The cluster is paused before objects are collected.
#[instrument(
    skip(client),
    fields(otel.kind = "internal")
)]
pub async fn prepare_move_objects(
    client: &Client,
    namespace: &str,
    cluster_name: &str,
) -> Result<Vec<MoveObjectOutput>, MoveError> {
    // Step 1: Pause cluster first (objects captured with paused=true)
    pause_cluster(client, namespace).await?;

    // Step 2: Discover and build graph
    let mut graph = ObjectGraph::new(namespace);
    graph.discover(client).await?;
    graph.filter_by_cluster(cluster_name);

    if graph.is_empty() {
        // Unpause and return error
        if let Err(e) = unpause_cluster(client, namespace).await {
            error!("Failed to unpause after discovery error: {}", e);
        }
        return Err(MoveError::Discovery("no objects to move".to_string()));
    }

    // Step 3: Compute topological order
    let sequence = MoveSequence::from_graph(&graph)?;

    info!(
        namespace = %namespace,
        cluster = %cluster_name,
        objects = graph.len(),
        groups = sequence.num_groups(),
        "Prepared objects for move"
    );

    // Step 4: Build move objects in order
    let mut objects = Vec::with_capacity(graph.len());
    for (_, group) in sequence.iter_groups() {
        let nodes = extract_nodes_for_group(&graph, group);
        for node in nodes {
            objects.push(build_move_object(node)?);
        }
    }

    Ok(objects)
}

/// Pause Cluster and ClusterClass resources in a namespace
pub async fn pause_cluster(client: &Client, namespace: &str) -> Result<(), MoveError> {
    set_cluster_paused(client, namespace, true).await
}

/// Unpause Cluster and ClusterClass resources in a namespace
pub async fn unpause_cluster(client: &Client, namespace: &str) -> Result<(), MoveError> {
    set_cluster_paused(client, namespace, false).await
}

async fn set_cluster_paused(
    client: &Client,
    namespace: &str,
    paused: bool,
) -> Result<(), MoveError> {
    let action = if paused { "Pausing" } else { "Unpausing" };

    // Pause/unpause Cluster (required)
    if let Err(e) = crate::utils::patch_resources_paused(
        client,
        namespace,
        "cluster.x-k8s.io",
        "Cluster",
        paused,
    )
    .await
    {
        return Err(MoveError::PauseFailed(format!(
            "{} Cluster failed: {}",
            action, e
        )));
    }

    // Pause/unpause ClusterClass (optional - might not exist)
    if let Err(e) = crate::utils::patch_resources_paused(
        client,
        namespace,
        "cluster.x-k8s.io",
        "ClusterClass",
        paused,
    )
    .await
    {
        debug!(error = %e, "{} ClusterClass failed (may not exist)", action);
    }

    info!(namespace = %namespace, paused = paused, "Cluster resources {}", if paused { "paused" } else { "unpaused" });
    Ok(())
}

/// Build a MoveObjectOutput from a graph node
///
/// Returns an error if the object cannot be serialized to JSON.
fn build_move_object(node: &GraphNode) -> Result<MoveObjectOutput, MoveError> {
    let owners = extract_owner_refs(node);
    let manifest = serde_json::to_vec(&node.object).map_err(|e| {
        MoveError::Serialization(format!(
            "failed to serialize object {}/{}: {}",
            node.identity.kind, node.identity.name, e
        ))
    })?;
    Ok(MoveObjectOutput {
        source_uid: node.uid().to_string(),
        manifest,
        owners,
    })
}

/// Extract owner references from a graph node
fn extract_owner_refs(node: &GraphNode) -> Vec<SourceOwnerRefOutput> {
    let owner_refs = node
        .object
        .get("metadata")
        .and_then(|m| m.get("ownerReferences"))
        .and_then(|r| r.as_array());

    match owner_refs {
        Some(refs) => refs
            .iter()
            .filter_map(|r| {
                Some(SourceOwnerRefOutput {
                    source_uid: r.get("uid")?.as_str()?.to_string(),
                    api_version: r.get("apiVersion")?.as_str()?.to_string(),
                    kind: r.get("kind")?.as_str()?.to_string(),
                    name: r.get("name")?.as_str()?.to_string(),
                    controller: r
                        .get("controller")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    block_owner_deletion: r
                        .get("blockOwnerDeletion")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                })
            })
            .collect(),
        None => Vec::new(),
    }
}

// =============================================================================
// Data Types
// =============================================================================

/// Trait for sending move commands to the agent
///
/// This abstraction allows testing without actual gRPC.
#[async_trait]
pub trait MoveCommandSender: Send + Sync {
    /// Send a batch of objects to the agent
    async fn send_batch(&self, batch: MoveBatch) -> Result<BatchAck, MoveError>;

    /// Send move complete signal
    async fn send_complete(&self, complete: MoveCompleteInput) -> Result<CompleteAck, MoveError>;
}

/// A batch of objects to send to the agent
#[derive(Debug, Clone)]
pub struct MoveBatch {
    /// Move operation ID
    pub move_id: String,
    /// Batch index
    pub batch_index: u32,
    /// Total batches
    pub total_batches: u32,
    /// Objects in this batch
    pub objects: Vec<MoveObjectOutput>,
    /// Target namespace
    pub target_namespace: String,
    /// Cluster name
    pub cluster_name: String,
}

/// A single object to send
#[derive(Debug, Clone)]
pub struct MoveObjectOutput {
    /// Source UID
    pub source_uid: String,
    /// Object manifest (JSON bytes)
    pub manifest: Vec<u8>,
    /// Owner references
    pub owners: Vec<SourceOwnerRefOutput>,
}

impl From<MoveObjectOutput> for MoveObject {
    fn from(obj: MoveObjectOutput) -> Self {
        Self {
            source_uid: obj.source_uid,
            manifest: obj.manifest,
            owners: obj.owners.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<MoveObject> for MoveObjectOutput {
    fn from(obj: MoveObject) -> Self {
        Self {
            source_uid: obj.source_uid,
            manifest: obj.manifest,
            owners: obj.owners.into_iter().map(Into::into).collect(),
        }
    }
}

/// Owner reference to send
#[derive(Debug, Clone)]
pub struct SourceOwnerRefOutput {
    /// Source UID
    pub source_uid: String,
    /// API version
    pub api_version: String,
    /// Kind
    pub kind: String,
    /// Name
    pub name: String,
    /// Is controller
    pub controller: bool,
    /// Block owner deletion
    pub block_owner_deletion: bool,
}

impl From<SourceOwnerRefOutput> for SourceOwnerRef {
    fn from(o: SourceOwnerRefOutput) -> Self {
        Self {
            source_uid: o.source_uid,
            api_version: o.api_version,
            kind: o.kind,
            name: o.name,
            controller: o.controller,
            block_owner_deletion: o.block_owner_deletion,
        }
    }
}

impl From<SourceOwnerRef> for SourceOwnerRefOutput {
    fn from(o: SourceOwnerRef) -> Self {
        Self {
            source_uid: o.source_uid,
            api_version: o.api_version,
            kind: o.kind,
            name: o.name,
            controller: o.controller,
            block_owner_deletion: o.block_owner_deletion,
        }
    }
}

/// Acknowledgment for a batch
#[derive(Debug, Clone)]
pub struct BatchAck {
    /// UID mappings (source_uid, target_uid)
    pub mappings: Vec<(String, String)>,
    /// Errors (source_uid, message, retryable)
    pub errors: Vec<(String, String, bool)>,
}

/// Input for move complete
#[derive(Debug, Clone)]
pub struct MoveCompleteInput {
    /// Move ID
    pub move_id: String,
    /// Cluster name
    pub cluster_name: String,
    /// Target namespace
    pub target_namespace: String,
    /// Cloud providers JSON
    pub cloud_providers: Vec<Vec<u8>>,
    /// Secrets providers JSON
    pub secrets_providers: Vec<Vec<u8>>,
    /// Secrets JSON
    pub secrets: Vec<Vec<u8>>,
    /// Additional manifests to apply (e.g., CiliumNetworkPolicy)
    pub manifests: Vec<Vec<u8>>,
    /// Cedar policies JSON (inherited from ancestors)
    pub cedar_policies: Vec<Vec<u8>>,
    /// OIDC providers JSON (inherited from ancestors)
    pub oidc_providers: Vec<Vec<u8>>,
}

/// Acknowledgment for move complete
#[derive(Debug, Clone)]
pub struct CompleteAck {
    /// Success
    pub success: bool,
    /// Error message if failed
    pub error: String,
    /// Resources created
    pub resources_created: i32,
}

/// Configuration for the CellMover
#[derive(Debug, Clone)]
pub struct CellMoverConfig {
    /// Source namespace
    pub source_namespace: String,
    /// Target namespace on agent
    pub target_namespace: String,
    /// Cluster name to move
    pub cluster_name: String,
    /// Move operation ID
    pub move_id: String,
    /// Timeout for batch operations
    pub batch_timeout: Duration,
    /// Distributable resources
    pub cloud_providers: Vec<Vec<u8>>,
    pub secrets_providers: Vec<Vec<u8>>,
    pub secrets: Vec<Vec<u8>>,
    pub cedar_policies: Vec<Vec<u8>>,
    pub oidc_providers: Vec<Vec<u8>>,
    /// Additional manifests to apply (e.g., CiliumNetworkPolicy)
    pub manifests: Vec<Vec<u8>>,
}

impl CellMoverConfig {
    /// Create a new config
    pub fn new(source_namespace: &str, target_namespace: &str, cluster_name: &str) -> Self {
        Self {
            source_namespace: source_namespace.to_string(),
            target_namespace: target_namespace.to_string(),
            cluster_name: cluster_name.to_string(),
            move_id: uuid::Uuid::new_v4().to_string(),
            batch_timeout: Duration::from_secs(60),
            cloud_providers: Vec::new(),
            secrets_providers: Vec::new(),
            secrets: Vec::new(),
            cedar_policies: Vec::new(),
            oidc_providers: Vec::new(),
            manifests: Vec::new(),
        }
    }

    /// Set distributable resources from DistributableResources struct
    pub fn with_distributable_resources(
        mut self,
        resources: &lattice_common::DistributableResources,
    ) -> Self {
        self.cloud_providers = resources.cloud_providers.clone();
        self.secrets_providers = resources.secrets_providers.clone();
        self.secrets = resources.secrets.clone();
        self.cedar_policies = resources.cedar_policies.clone();
        self.oidc_providers = resources.oidc_providers.clone();
        self
    }

    /// Set additional manifests to apply post-pivot
    pub fn with_manifests(mut self, manifests: Vec<Vec<u8>>) -> Self {
        self.manifests = manifests;
        self
    }
}

/// Result of a move operation
#[derive(Debug, Clone)]
pub struct MoveResult {
    /// Move operation ID
    pub move_id: String,
    /// Number of objects moved to target
    pub objects_moved: u32,
    /// Number of objects deleted from source
    pub objects_deleted: u32,
}

// =============================================================================
// CellMover - Orchestrates streaming pivot over gRPC
// =============================================================================

/// Cell-side orchestrator for distributed move operations
pub struct CellMover<S: MoveCommandSender> {
    /// Kubernetes client for source cluster
    client: Client,
    /// Configuration
    config: CellMoverConfig,
    /// Command sender for agent communication
    sender: Arc<S>,
    /// Object graph
    graph: Option<ObjectGraph>,
    /// Move sequence
    sequence: Option<MoveSequence>,
}

impl<S: MoveCommandSender> CellMover<S> {
    /// Create a new CellMover
    pub fn new(client: Client, config: CellMoverConfig, sender: Arc<S>) -> Self {
        Self {
            client,
            config,
            sender,
            graph: None,
            sequence: None,
        }
    }

    /// Execute the full move operation
    ///
    /// This is the main entry point that orchestrates:
    /// 1. Pausing source resources
    /// 2. Discovery and graph building
    /// 3. Streaming batches to agent
    /// 4. Finalizing (agent unpause)
    /// 5. Deleting source resources
    #[instrument(
        skip(self),
        fields(
            move_id = %self.config.move_id,
            cluster = %self.config.cluster_name,
            source_ns = %self.config.source_namespace,
            target_ns = %self.config.target_namespace,
            otel.kind = "internal"
        )
    )]
    pub async fn execute(&mut self) -> Result<MoveResult, MoveError> {
        const OVERALL_MOVE_TIMEOUT: Duration = Duration::from_secs(1800);

        match tokio::time::timeout(OVERALL_MOVE_TIMEOUT, self.execute_inner()).await {
            Ok(result) => result,
            Err(_) => {
                warn!(cluster = %self.config.cluster_name, "Move timed out after 30 minutes, unpausing source");
                let _ = unpause_cluster(&self.client, &self.config.source_namespace).await;
                Err(MoveError::Timeout { seconds: OVERALL_MOVE_TIMEOUT.as_secs() })
            }
        }
    }

    async fn execute_inner(&mut self) -> Result<MoveResult, MoveError> {
        info!(
            move_id = %self.config.move_id,
            cluster = %self.config.cluster_name,
            source_ns = %self.config.source_namespace,
            target_ns = %self.config.target_namespace,
            "Starting distributed move"
        );

        // Step 1: Pause source resources FIRST (so objects are captured with paused=true)
        pause_cluster(&self.client, &self.config.source_namespace).await?;

        // Step 2: Discover and build graph (now includes paused state)
        self.discover_and_build_graph().await?;

        let graph = self
            .graph
            .as_ref()
            .ok_or_else(|| MoveError::Discovery("graph not built".to_string()))?;

        if graph.is_empty() {
            // Unpause before returning error
            if let Err(e) = unpause_cluster(&self.client, &self.config.source_namespace).await {
                error!("Failed to unpause after empty graph error: {}", e);
            }
            return Err(MoveError::Discovery("no objects to move".to_string()));
        }

        // Step 3: Compute move sequence
        self.compute_sequence()?;

        // Step 4: Stream batches to agent
        let stream_result = self.stream_batches().await;

        // If streaming failed, unpause source and return error
        if let Err(e) = stream_result {
            warn!(error = %e, "Batch streaming failed, unpausing source");
            if let Err(unpause_err) =
                unpause_cluster(&self.client, &self.config.source_namespace).await
            {
                error!("Failed to unpause after streaming error: {}", unpause_err);
            }
            return Err(e);
        }

        // Step 5: Finalize (agent unpause)
        let complete_result = self.finalize().await?;

        if !complete_result.success {
            warn!(error = %complete_result.error, "Agent finalization failed, unpausing source");
            if let Err(unpause_err) =
                unpause_cluster(&self.client, &self.config.source_namespace).await
            {
                error!(
                    "Failed to unpause after finalization error: {}",
                    unpause_err
                );
            }
            return Err(MoveError::AgentCommunication(complete_result.error));
        }

        // Step 6: Delete source resources
        let deleted = self.delete_source().await?;

        let result = MoveResult {
            move_id: self.config.move_id.clone(),
            objects_moved: complete_result.resources_created as u32,
            objects_deleted: deleted,
        };

        info!(
            move_id = %result.move_id,
            moved = result.objects_moved,
            deleted = result.objects_deleted,
            "Distributed move complete"
        );

        Ok(result)
    }

    /// Discover CAPI CRDs and build the object graph
    async fn discover_and_build_graph(&mut self) -> Result<(), MoveError> {
        let mut graph = ObjectGraph::new(&self.config.source_namespace);
        graph.discover(&self.client).await?;
        graph.filter_by_cluster(&self.config.cluster_name);

        info!(
            namespace = %self.config.source_namespace,
            cluster = %self.config.cluster_name,
            objects = graph.len(),
            "Built object graph"
        );

        self.graph = Some(graph);
        Ok(())
    }

    /// Compute the move sequence from the graph
    fn compute_sequence(&mut self) -> Result<(), MoveError> {
        let graph = self
            .graph
            .as_ref()
            .ok_or_else(|| MoveError::Discovery("graph not built".to_string()))?;

        let sequence = MoveSequence::from_graph(graph)?;

        info!(
            groups = sequence.num_groups(),
            objects = sequence.total_objects(),
            "Computed move sequence"
        );

        self.sequence = Some(sequence);
        Ok(())
    }

    /// Stream batches to the agent
    ///
    /// Retries batches when the agent reports retryable errors (e.g., webhook
    /// endpoints not yet available). Already-created objects are handled
    /// gracefully by the agent via 409 conflict -> get existing UID.
    async fn stream_batches(&self) -> Result<(), MoveError> {
        let graph = self
            .graph
            .as_ref()
            .ok_or_else(|| MoveError::Discovery("graph not built".to_string()))?;
        let sequence = self
            .sequence
            .as_ref()
            .ok_or_else(|| MoveError::Discovery("sequence not computed".to_string()))?;

        let total_batches = sequence.num_groups() as u32;

        // Retry config for transient batch failures (webhook not ready, etc.).
        // The agent already retries individual objects 5x with short backoff,
        // so batch retries use longer delays to let infrastructure stabilize.
        let retry_config = RetryConfig {
            max_attempts: 6,
            initial_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        };

        for (index, group) in sequence.iter_groups() {
            let nodes = extract_nodes_for_group(graph, group);
            let objects: Vec<MoveObjectOutput> = nodes
                .iter()
                .map(|n| build_move_object(n))
                .collect::<Result<Vec<_>, _>>()?;

            let batch = MoveBatch {
                move_id: self.config.move_id.clone(),
                batch_index: index as u32,
                total_batches,
                objects,
                target_namespace: self.config.target_namespace.clone(),
                cluster_name: self.config.cluster_name.clone(),
            };

            info!(
                batch = index,
                total = total_batches,
                objects = batch.objects.len(),
                "Sending batch"
            );

            let batch_ref = &batch;
            let sender_ref = &self.sender;

            // Use nested Result: Ok(Ok(())) = success, Ok(Err(e)) = non-retryable
            // (stops retries), Err(e) = retryable (retry_with_backoff retries).
            let result = retry_with_backoff(
                &retry_config,
                &format!("batch {}/{}", index, total_batches),
                || async {
                    let ack = sender_ref.send_batch(batch_ref.clone()).await?;

                    if ack.errors.is_empty() {
                        debug!(
                            batch = index,
                            mappings = ack.mappings.len(),
                            "Batch acknowledged"
                        );
                        return Ok(Ok(()));
                    }

                    let all_retryable = ack.errors.iter().all(|(_, _, retryable)| *retryable);

                    for (uid, msg, retryable) in &ack.errors {
                        error!(source_uid = %uid, error = %msg, retryable = %retryable, "Object creation failed");
                    }

                    let first_msg = &ack.errors[0].1;
                    let err = MoveError::BatchFailed {
                        index: index as u32,
                        message: format!(
                            "{} objects failed, first: {}",
                            ack.errors.len(),
                            first_msg
                        ),
                    };

                    if all_retryable {
                        Err(err)
                    } else {
                        Ok(Err(err))
                    }
                },
            )
            .await;

            // Unwrap nested Result
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Finalize the move (agent unpause and apply distributed resources)
    async fn finalize(&self) -> Result<CompleteAck, MoveError> {
        let complete = MoveCompleteInput {
            move_id: self.config.move_id.clone(),
            cluster_name: self.config.cluster_name.clone(),
            target_namespace: self.config.target_namespace.clone(),
            cloud_providers: self.config.cloud_providers.clone(),
            secrets_providers: self.config.secrets_providers.clone(),
            secrets: self.config.secrets.clone(),
            manifests: self.config.manifests.clone(),
            cedar_policies: self.config.cedar_policies.clone(),
            oidc_providers: self.config.oidc_providers.clone(),
        };

        self.sender.send_complete(complete).await
    }

    /// Delete source resources after successful move
    async fn delete_source(&self) -> Result<u32, MoveError> {
        let sequence = self
            .sequence
            .as_ref()
            .ok_or_else(|| MoveError::Discovery("sequence not computed".to_string()))?;
        let graph = self
            .graph
            .as_ref()
            .ok_or_else(|| MoveError::Discovery("graph not built".to_string()))?;

        // Delete in reverse order (dependents before owners)
        let uids = sequence.all_uids_for_deletion();
        let mut deleted = 0u32;

        for uid in &uids {
            let node = match graph.get(uid) {
                Some(n) => n,
                None => continue,
            };

            match delete_resource_for_move(&self.client, &self.config.source_namespace, node).await
            {
                Ok(_) => deleted += 1,
                Err(e) => {
                    warn!(
                        uid = %uid,
                        kind = %node.identity.kind,
                        name = %node.identity.name,
                        error = %e,
                        "Failed to delete source resource"
                    );
                }
            }
        }

        info!(
            deleted = deleted,
            total = uids.len(),
            "Source resources deleted"
        );
        Ok(deleted)
    }
}

/// Delete a single resource with finalizer removal
async fn delete_resource_for_move(
    client: &Client,
    namespace: &str,
    node: &GraphNode,
) -> Result<(), MoveError> {
    let api_resource = build_api_resource(&node.identity.api_version, &node.identity.kind);
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &api_resource);

    // Check if resource still exists
    let obj = match api.get(&node.identity.name).await {
        Ok(o) => o,
        Err(kube::Error::Api(e)) if e.code == 404 => {
            debug!(kind = %node.identity.kind, name = %node.identity.name, "Resource already deleted");
            return Ok(());
        }
        Err(e) => return Err(MoveError::Kube(e)),
    };

    // Add delete-for-move annotation
    let annotation_patch = serde_json::json!({
        "metadata": { "annotations": { DELETE_FOR_MOVE_ANNOTATION: "" } }
    });

    if let Err(e) = api
        .patch(
            &node.identity.name,
            &PatchParams::default(),
            &Patch::Merge(&annotation_patch),
        )
        .await
    {
        warn!(kind = %node.identity.kind, name = %node.identity.name, error = %e, "Failed to add delete-for-move annotation");
    }

    // Remove finalizers to prevent infrastructure deletion
    if !obj
        .metadata
        .finalizers
        .as_ref()
        .is_none_or(|f| f.is_empty())
    {
        let finalizer_patch = serde_json::json!({ "metadata": { "finalizers": null } });
        if let Err(e) = api
            .patch(
                &node.identity.name,
                &PatchParams::default(),
                &Patch::Merge(&finalizer_patch),
            )
            .await
        {
            warn!(kind = %node.identity.kind, name = %node.identity.name, error = %e, "Failed to remove finalizers");
        }
    }

    // Delete the resource
    match api
        .delete(&node.identity.name, &DeleteParams::default())
        .await
    {
        Ok(_) => {
            debug!(kind = %node.identity.kind, name = %node.identity.name, "Deleted source resource");
            Ok(())
        }
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => Err(MoveError::Kube(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_mover_config() {
        let config = CellMoverConfig::new("source-ns", "target-ns", "test-cluster");
        assert_eq!(config.source_namespace, "source-ns");
        assert_eq!(config.target_namespace, "target-ns");
        assert_eq!(config.cluster_name, "test-cluster");
        assert!(!config.move_id.is_empty());
    }
}
