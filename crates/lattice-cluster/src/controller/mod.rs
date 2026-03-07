//! LatticeCluster controller implementation
//!
//! This module implements the reconciliation logic for LatticeCluster resources.
//! It follows the Kubernetes controller pattern: observe current state, determine
//! desired state, calculate diff, and apply changes.

mod context;
mod deletion;
mod kube_client;
mod pivot;
mod pure;

// Re-export everything that was previously public from this module
pub use context::{Context, ContextBuilder};
pub use deletion::CLUSTER_FINALIZER;
pub use kube_client::{KubeClient, KubeClientImpl, NodeCounts};
pub use pivot::{PivotOperations, PivotOperationsImpl};
pub use pure::{
    autoscaling_warning, build_gpu_cordon_plan, determine_gpu_action, determine_pivot_action,
    determine_scaling_action, is_self_cluster, GpuAction, GpuCordonPlan, GpuNodeState,
    PivotAction, ScalingAction, MAX_CORDON_FRACTION,
};

// Re-export pub(crate) items for sibling modules (phases, etc.)
// Note: is_control_plane_node, is_node_ready, and get_optional are
// used internally by submodules via super:: imports

// Re-export MockKubeClient and MockPivotOperations for tests
#[cfg(test)]
pub use kube_client::MockKubeClient;
#[cfg(test)]
pub use pivot::MockPivotOperations;

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::{Resource, ResourceExt};
use tracing::{debug, error, info, instrument, warn};

use kube::runtime::events::EventType;
use lattice_common::crd::{ClusterPhase, LatticeCluster, LatticeClusterStatus};

use lattice_common::events::{actions, reasons};
use lattice_common::metrics::{self, ReconcileTimer};
use lattice_common::{Error, LATTICE_SYSTEM_NAMESPACE, PARENT_CONFIG_SECRET};

use crate::phases::{
    handle_pending, handle_pivoting, handle_provisioning, handle_ready, update_status,
};

use deletion::{add_finalizer, handle_deletion, has_finalizer};

pub(crate) const FIELD_MANAGER: &str = "lattice-cluster-controller";

/// Reconcile a LatticeCluster resource
///
/// This function implements the main reconciliation loop for LatticeCluster.
/// It observes the current state, determines the desired state, and makes
/// incremental changes to converge on the desired state.
///
/// # Arguments
///
/// * `cluster` - The LatticeCluster resource to reconcile
/// * `ctx` - Shared controller context
///
/// # Returns
///
/// Returns an `Action` indicating when to requeue the resource, or an error
/// if reconciliation failed.
#[instrument(
    skip(cluster, ctx),
    fields(
        cluster = %cluster.name_any(),
        phase = ?cluster.status.as_ref().map(|s| &s.phase),
        otel.kind = "internal"
    )
)]
pub async fn reconcile(cluster: Arc<LatticeCluster>, ctx: Arc<Context>) -> Result<Action, Error> {
    let name = cluster.name_any();
    let timer = ReconcileTimer::start(&name);
    info!("reconciling cluster");

    // Check if we're reconciling our own cluster (the one we're running on)
    let is_self = is_self_cluster(&name, ctx.self_cluster_name.as_deref());

    // Handle deletion via finalizer
    // Root/management clusters cannot be unpivoted (they have nowhere to unpivot to)
    // Only self-managed workload clusters need unpivot handling
    if cluster.metadata.deletion_timestamp.is_some() {
        let result = handle_deletion(&cluster, &ctx, is_self).await;
        match &result {
            Ok(_) => timer.success(),
            Err(_) => timer.error("transient"),
        }
        return result;
    }

    // Ensure finalizer is present for clusters that need cleanup on deletion
    // Two cases:
    // 1. Self cluster with parent - needs unpivot (export CAPI to parent)
    // 2. Non-self cluster (child) - needs CAPI cleanup (delete infrastructure)
    if !has_finalizer(&cluster) {
        if is_self {
            // Check if parent config secret exists (indicates we have a parent)
            let has_parent = ctx
                .kube
                .get_secret(PARENT_CONFIG_SECRET, LATTICE_SYSTEM_NAMESPACE)
                .await?
                .is_some();

            if has_parent {
                info!("Adding finalizer (self cluster with parent - needs unpivot)");
                add_finalizer(&cluster, &ctx).await?;
                timer.success();
                return Ok(Action::requeue(Duration::from_secs(1)));
            }
        } else {
            // Non-self cluster (we're the parent) - add finalizer for CAPI cleanup
            info!("Adding finalizer (child cluster - needs CAPI cleanup on deletion)");
            add_finalizer(&cluster, &ctx).await?;
            timer.success();
            return Ok(Action::requeue(Duration::from_secs(1)));
        }
    }

    // Validate the cluster spec
    if let Err(e) = cluster.spec.validate() {
        warn!(error = %e, "cluster validation failed");
        ctx.events
            .publish(
                &cluster.object_ref(&()),
                EventType::Warning,
                reasons::VALIDATION_FAILED,
                actions::RECONCILE,
                Some(e.to_string()),
            )
            .await;
        update_status(
            &cluster,
            &ctx,
            ClusterPhase::Failed,
            Some(&e.to_string()),
            false,
        )
        .await?;
        timer.error("permanent");
        // Don't requeue for validation errors - they require spec changes
        return Ok(Action::await_change());
    }

    // Get current status, defaulting to Pending if not set
    let current_phase = cluster
        .status
        .as_ref()
        .map(|s| s.phase)
        .unwrap_or(ClusterPhase::Pending);

    // Phase regression guard: once pivot_complete is true, a non-self cluster
    // (i.e. a child viewed from the parent) must never regress to a pre-pivot
    // phase. This prevents Flux or other external agents from accidentally
    // re-triggering provisioning on the parent side.
    let pivot_complete = cluster
        .status
        .as_ref()
        .map(|s| s.pivot_complete)
        .unwrap_or(false);
    if pivot_complete && !is_self && current_phase.is_pre_pivot() {
        warn!(
            cluster = %name,
            current_phase = ?current_phase,
            "phase regressed on pivoted cluster, forcing back to Pivoted"
        );
        update_status(&cluster, &ctx, ClusterPhase::Pivoted, None, false).await?;
        return Ok(Action::requeue(Duration::from_secs(60)));
    }

    debug!(?current_phase, is_self, "current cluster phase");

    // State machine: dispatch to phase handlers
    let result = match current_phase {
        ClusterPhase::Pending => handle_pending(&cluster, &ctx, is_self).await,
        ClusterPhase::Provisioning => handle_provisioning(&cluster, &ctx).await,
        ClusterPhase::Pivoting => handle_pivoting(&cluster, &ctx, is_self).await,
        ClusterPhase::Pivoted => {
            // Child cluster is self-managing after pivot — update status
            // from agent heartbeat health data if available
            debug!("child cluster is self-managing (pivoted), monitoring");
            if let Some(ref parent_servers) = ctx.parent_servers {
                if parent_servers.is_running() {
                    let registry = parent_servers.agent_registry();
                    if let Some(health) = registry.get_health(&name) {
                        let ready_cp = health.ready_control_plane as u32;
                        let ready_workers =
                            (health.ready_nodes - health.ready_control_plane).max(0) as u32;
                        let current_status = cluster.status.clone().unwrap_or_default();
                        let updated_status = LatticeClusterStatus {
                            ready_control_plane: Some(ready_cp),
                            ready_workers: Some(ready_workers),
                            ..current_status
                        };
                        if let Err(e) = ctx.kube.patch_status(&name, &updated_status).await {
                            warn!(error = %e, "Failed to update pivoted cluster status from heartbeat");
                        }
                    }
                }
            }
            Ok(Action::requeue(Duration::from_secs(60)))
        }
        ClusterPhase::Ready => handle_ready(&cluster, &ctx).await,
        ClusterPhase::Unpivoting => {
            // Unpivoting is handled by handle_deletion, just wait
            debug!("cluster is Unpivoting, waiting for completion");
            Ok(Action::requeue(Duration::from_secs(5)))
        }
        ClusterPhase::Deleting => {
            // Deleting is handled by handle_deletion, just wait
            debug!("cluster is Deleting, waiting for completion");
            Ok(Action::requeue(Duration::from_secs(5)))
        }
        ClusterPhase::Failed => {
            // Failed state requires manual intervention
            warn!("cluster is in Failed state, awaiting spec change");
            Ok(Action::await_change())
        }
    };

    // Record reconcile metrics and update phase gauge
    match &result {
        Ok(_) => {
            timer.success();
            ctx.error_counts.remove(&cluster.name_any());
            // Update cluster phase gauge with current phase
            let phase_label = match current_phase {
                ClusterPhase::Pending => metrics::ClusterPhase::Pending,
                ClusterPhase::Provisioning => metrics::ClusterPhase::Provisioning,
                ClusterPhase::Pivoting | ClusterPhase::Pivoted => metrics::ClusterPhase::Pivoting,
                ClusterPhase::Ready => metrics::ClusterPhase::Ready,
                ClusterPhase::Failed => metrics::ClusterPhase::Failed,
                ClusterPhase::Deleting | ClusterPhase::Unpivoting => {
                    metrics::ClusterPhase::Deleting
                }
            };
            metrics::set_cluster_phase_count(phase_label, 1);
        }
        Err(_) => timer.error("transient"),
    }

    result
}

/// Maximum backoff delay for retryable errors (5 minutes)
const MAX_ERROR_BACKOFF: Duration = Duration::from_secs(300);

/// Error policy for the controller
///
/// This function is called when reconciliation fails. It determines
/// the requeue strategy:
/// - Retryable errors: exponential backoff (5s, 10s, 20s, ... capped at 5m)
/// - Non-retryable errors: await spec change, don't retry
pub fn error_policy(cluster: Arc<LatticeCluster>, error: &Error, ctx: Arc<Context>) -> Action {
    let cluster_name = cluster.name_any();

    if error.is_retryable() {
        let count = ctx
            .error_counts
            .entry(cluster_name.clone())
            .and_modify(|c| *c = c.saturating_add(1))
            .or_insert(1);
        let backoff_secs = (5u64 << (*count - 1).min(6)).min(MAX_ERROR_BACKOFF.as_secs());

        error!(
            ?error,
            cluster = %cluster_name,
            retry_count = *count,
            backoff_secs,
            "reconciliation failed (retryable)"
        );
        Action::requeue(Duration::from_secs(backoff_secs))
    } else {
        error!(
            ?error,
            cluster = %cluster_name,
            "reconciliation failed (permanent)"
        );
        ctx.error_counts.remove(&cluster_name);
        Action::await_change()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phases::{generate_capi_manifests, update_status as update_cluster_status};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::Client;
    use lattice_capi::client::CAPIClient;
    use lattice_capi::installer::CapiInstaller;
    use lattice_capi::installer::CapiProviderConfig;
    use lattice_capi::provider::CAPIManifest;
    use lattice_common::crd::{
        BackupsConfig, BootstrapProvider, Condition, ConditionStatus, ControlPlaneSpec,
        EndpointsSpec, InfraProvider, KubernetesSpec, LatticeClusterSpec, MonitoringConfig,
        NodeSpec, ProviderConfig, ProviderSpec, ServiceSpec, WorkerPoolSpec,
    };
    use mockall::mock;

    // Local mocks for traits defined in other crates - the mockall-generated mocks
    // are only available within those crates' test configurations
    mock! {
        pub CapiInstaller {}

        #[async_trait::async_trait]
        impl CapiInstaller for CapiInstaller {
            async fn ensure(&self, config: &CapiProviderConfig) -> Result<(), Error>;
        }
    }

    mock! {
        pub CAPIClient {}

        #[async_trait::async_trait]
        impl CAPIClient for CAPIClient {
            async fn apply_manifests(&self, manifests: &[CAPIManifest], namespace: &str) -> Result<(), Error>;
            async fn is_infrastructure_ready(&self, cluster_name: &str, namespace: &str, bootstrap: BootstrapProvider) -> Result<bool, Error>;
            async fn get_pool_replicas(&self, cluster_name: &str, pool_id: &str, namespace: &str) -> Result<Option<u32>, Error>;
            async fn scale_pool(&self, cluster_name: &str, pool_id: &str, namespace: &str, replicas: u32) -> Result<(), Error>;
            async fn delete_capi_cluster(&self, cluster_name: &str, namespace: &str) -> Result<(), Error>;
            async fn capi_cluster_exists(&self, cluster_name: &str, namespace: &str) -> Result<bool, Error>;
            async fn is_cluster_stable(&self, cluster_name: &str, namespace: &str) -> Result<bool, Error>;
            async fn get_cp_version(&self, cluster_name: &str, namespace: &str, bootstrap: BootstrapProvider) -> Result<Option<String>, Error>;
            async fn update_cp_version(&self, cluster_name: &str, namespace: &str, bootstrap: BootstrapProvider, version: &str) -> Result<(), Error>;
            async fn get_pool_version(&self, cluster_name: &str, pool_id: &str, namespace: &str) -> Result<Option<String>, Error>;
            async fn update_pool_version(&self, cluster_name: &str, pool_id: &str, namespace: &str, version: &str) -> Result<(), Error>;
            fn kube_client(&self) -> Client;
        }
    }

    /// Create a sample LatticeCluster for testing
    /// Note: Includes finalizer by default since non-self clusters get one on first reconcile
    fn sample_cluster(name: &str) -> LatticeCluster {
        LatticeCluster {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                finalizers: Some(vec![CLUSTER_FINALIZER.to_string()]),
                ..Default::default()
            },
            spec: LatticeClusterSpec {
                provider_ref: "test-provider".to_string(),
                provider: ProviderSpec {
                    kubernetes: KubernetesSpec {
                        version: "1.32.0".to_string(),
                        cert_sans: None,
                        bootstrap: BootstrapProvider::default(),
                    },
                    config: ProviderConfig::docker(),
                    credentials_secret_ref: None,
                },
                nodes: NodeSpec {
                    control_plane: ControlPlaneSpec {
                        replicas: 1,
                        instance_type: None,
                        root_volume: None,
                    },
                    worker_pools: std::collections::BTreeMap::from([(
                        "default".to_string(),
                        WorkerPoolSpec {
                            replicas: 2,
                            ..Default::default()
                        },
                    )]),
                },
                parent_config: None,
                services: true,
                gpu: false,
                monitoring: MonitoringConfig::default(),
                backups: BackupsConfig::default(),
                network_topology: None,
                registry_mirrors: None,
            },
            status: None,
        }
    }

    /// Create a sample cell (management cluster) for testing
    fn sample_parent(name: &str) -> LatticeCluster {
        let mut cluster = sample_cluster(name);
        cluster.spec.parent_config = Some(EndpointsSpec {
            grpc_port: 50051,
            bootstrap_port: 8443,
            proxy_port: 8081,
            service: ServiceSpec {
                type_: "LoadBalancer".to_string(),
            },
        });
        cluster
    }

    /// Create a sample Docker InfraProvider for testing
    fn sample_docker_provider() -> InfraProvider {
        use lattice_common::crd::{InfraProviderSpec, InfraProviderType};

        InfraProvider::new(
            "test-provider",
            InfraProviderSpec {
                provider_type: InfraProviderType::Docker,
                region: None,
                credentials_secret_ref: None,
                credentials: None,
                credential_data: None,
                aws: None,
                proxmox: None,
                openstack: None,
                labels: Default::default(),
            },
        )
    }

    /// Create a cluster with a specific status phase
    fn cluster_with_phase(name: &str, phase: ClusterPhase) -> LatticeCluster {
        let mut cluster = sample_cluster(name);
        cluster.status = Some(LatticeClusterStatus::with_phase(phase));
        // Add finalizer - non-self clusters get this on first reconcile
        cluster.metadata.finalizers = Some(vec![CLUSTER_FINALIZER.to_string()]);
        cluster
    }

    /// Create a cluster with invalid spec (zero control plane nodes)
    fn invalid_cluster(name: &str) -> LatticeCluster {
        let mut cluster = sample_cluster(name);
        cluster.spec.nodes.control_plane.replicas = 0;
        cluster
    }

    mod reconcile_logic {
        use super::*;

        #[test]
        fn test_validation_with_valid_cluster() {
            let cluster = sample_cluster("valid-cluster");
            assert!(cluster.spec.validate().is_ok());
        }

        #[test]
        fn test_validation_with_invalid_cluster() {
            let cluster = invalid_cluster("invalid-cluster");
            assert!(cluster.spec.validate().is_err());
        }

        #[test]
        fn test_cell_cluster_validation() {
            let cluster = sample_parent("mgmt");
            assert!(cluster.spec.validate().is_ok());
            assert!(cluster.spec.is_parent());
        }
    }

    mod status_helpers {
        use super::*;

        #[test]
        fn test_multiple_condition_types_are_preserved() {
            let provisioning = Condition::new(
                "Provisioning",
                ConditionStatus::True,
                "InProgress",
                "Infrastructure provisioning",
            );
            let ready = Condition::new(
                "Ready",
                ConditionStatus::False,
                "NotReady",
                "Waiting for infrastructure",
            );

            let status = LatticeClusterStatus::default()
                .condition(provisioning)
                .condition(ready);

            assert_eq!(status.conditions.len(), 2);
        }
    }

    /// Cluster Lifecycle State Machine Tests
    ///
    /// These tests verify the complete cluster lifecycle flow through the reconciler.
    /// Each test represents a story of what happens when a cluster is in a specific
    /// state and the controller reconciles it.
    ///
    /// Lifecycle: Pending -> Provisioning -> Pivoting -> Ready
    ///            (any state can transition to Failed on error)
    ///
    /// Test Philosophy:
    /// - Tests focus on OBSERVABLE OUTCOMES (Action returned, errors propagated)
    /// - We avoid verifying internal mock call parameters
    /// - Status capture allows verifying phase transitions without tight coupling
    mod cluster_lifecycle_flow {
        use super::*;

        use std::sync::{Arc as StdArc, Mutex};

        /// Captured status update for verification without coupling to mock internals.
        /// This allows us to verify "status was updated to Provisioning" without
        /// using withf() matchers that couple tests to implementation details.
        #[derive(Clone)]
        struct StatusCapture {
            updates: StdArc<Mutex<Vec<LatticeClusterStatus>>>,
        }

        impl StatusCapture {
            fn new() -> Self {
                Self {
                    updates: StdArc::new(Mutex::new(Vec::new())),
                }
            }

            fn record(&self, status: LatticeClusterStatus) {
                self.updates
                    .lock()
                    .expect("mutex should not be poisoned")
                    .push(status);
            }

            fn last_phase(&self) -> Option<ClusterPhase> {
                self.updates
                    .lock()
                    .expect("mutex should not be poisoned")
                    .last()
                    .map(|s| s.phase)
            }

            fn was_updated(&self) -> bool {
                !self
                    .updates
                    .lock()
                    .expect("mutex should not be poisoned")
                    .is_empty()
            }
        }

        // ===== Test Fixture Helpers =====
        // These create mock contexts that capture status updates for verification

        /// Creates mock installer for CAPI (always succeeds)
        fn mock_capi_installer() -> Arc<MockCapiInstaller> {
            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));
            Arc::new(installer)
        }

        /// Creates a context that captures status updates for later verification.
        /// Use this when you need to verify WHAT phase was set, not HOW it was set.
        fn mock_context_with_status_capture() -> (Arc<Context>, StatusCapture) {
            let capture = StatusCapture::new();
            let capture_clone = capture.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                capture_clone.record(status.clone());
                Ok(())
            });
            mock.expect_ensure_namespace().returning(|_| Ok(()));
            // Non-self clusters get a finalizer added on first reconcile
            mock.expect_add_cluster_finalizer().returning(|_, _| Ok(()));
            // Return a Docker InfraProvider (no credentials needed)
            mock.expect_get_cloud_provider()
                .returning(|_| Ok(Some(sample_docker_provider())));

            let mut capi_mock = MockCAPIClient::new();
            capi_mock.expect_apply_manifests().returning(|_, _| Ok(()));

            (
                Arc::new(Context::for_testing(
                    Arc::new(mock),
                    Arc::new(capi_mock),
                    mock_capi_installer(),
                )),
                capture,
            )
        }

        /// Creates a context for read-only scenarios (minimal status updates).
        fn mock_context_readonly() -> Arc<Context> {
            let mut mock = MockKubeClient::new();
            // Default expectations for node operations (Ready phase)
            // Return 2 workers to match sample_cluster spec (so we get 60s requeue)
            mock.expect_get_ready_node_counts().returning(|| {
                Ok(NodeCounts {
                    ready_control_plane: 1,
                    ready_workers: 2,
                    pool_resources: vec![],
                })
            });
            // GPU health check lists all nodes — return empty (no GPU nodes)
            mock.expect_list_nodes().returning(|| Ok(vec![]));
            // Non-self clusters get a finalizer added on first reconcile
            mock.expect_add_cluster_finalizer().returning(|_, _| Ok(()));
            // Ready phase updates worker pool status
            mock.expect_patch_status().returning(|_, _| Ok(()));
            // Return a Docker InfraProvider (no credentials needed)
            mock.expect_get_cloud_provider()
                .returning(|_| Ok(Some(sample_docker_provider())));

            let mut capi_mock = MockCAPIClient::new();
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _, _| Ok(false));
            // MachineDeployment has 2 replicas to match spec - no scaling needed
            capi_mock
                .expect_get_pool_replicas()
                .returning(|_, _, _| Ok(Some(2)));
            // Version matches spec (v1.32.0) - no upgrade needed
            capi_mock
                .expect_get_cp_version()
                .returning(|_, _, _| Ok(Some("v1.32.0".to_string())));
            capi_mock
                .expect_is_cluster_stable()
                .returning(|_, _| Ok(true));
            capi_mock
                .expect_get_pool_version()
                .returning(|_, _, _| Ok(Some("v1.32.0".to_string())));
            Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                mock_capi_installer(),
            ))
        }

        /// Creates a context where infrastructure reports ready.
        fn mock_context_infra_ready_with_capture() -> (Arc<Context>, StatusCapture) {
            let capture = StatusCapture::new();
            let capture_clone = capture.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                capture_clone.record(status.clone());
                Ok(())
            });
            // Non-self clusters get a finalizer added on first reconcile
            mock.expect_add_cluster_finalizer().returning(|_, _| Ok(()));
            // Return a Docker InfraProvider (no credentials needed)
            mock.expect_get_cloud_provider()
                .returning(|_| Ok(Some(sample_docker_provider())));

            let mut capi_mock = MockCAPIClient::new();
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _, _| Ok(true));

            (
                Arc::new(Context::for_testing(
                    Arc::new(mock),
                    Arc::new(capi_mock),
                    mock_capi_installer(),
                )),
                capture,
            )
        }

        // ===== Lifecycle Flow Tests =====

        /// Story: When a user creates a new LatticeCluster, the controller should
        /// generate CAPI manifests and transition the cluster to Provisioning phase.
        /// This kicks off the infrastructure provisioning process.
        #[tokio::test]
        async fn new_cluster_starts_provisioning() {
            let cluster = Arc::new(sample_cluster("new-cluster"));
            let (ctx, capture) = mock_context_with_status_capture();

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Verify observable outcomes:
            // 1. Status was updated to Provisioning phase
            assert!(capture.was_updated(), "status should be updated");
            assert_eq!(capture.last_phase(), Some(ClusterPhase::Provisioning));
            // 2. Quick requeue to check provisioning progress
            assert_eq!(action, Action::requeue(Duration::from_secs(5)));
        }

        /// Story: A cluster explicitly in Pending phase should behave identically
        /// to a new cluster - both enter the provisioning pipeline.
        #[tokio::test]
        async fn pending_cluster_starts_provisioning() {
            let cluster = Arc::new(cluster_with_phase("pending-cluster", ClusterPhase::Pending));
            let (ctx, capture) = mock_context_with_status_capture();

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            assert!(capture.was_updated(), "status should be updated");
            assert_eq!(capture.last_phase(), Some(ClusterPhase::Provisioning));
            assert_eq!(action, Action::requeue(Duration::from_secs(5)));
        }

        /// Story: While infrastructure is being provisioned (VMs starting, etc.),
        /// the controller should keep checking until CAPI reports ready.
        #[tokio::test]
        async fn provisioning_cluster_waits_for_infrastructure() {
            let cluster = Arc::new(cluster_with_phase(
                "provisioning-cluster",
                ClusterPhase::Provisioning,
            ));
            let ctx = mock_context_readonly();

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Observable outcome: longer requeue interval while waiting
            assert_eq!(action, Action::requeue(Duration::from_secs(30)));
        }

        /// Story: Once infrastructure is ready, the cluster transitions to Pivoting
        /// phase where CAPI resources are moved into the cluster for self-management.
        #[tokio::test]
        async fn ready_infrastructure_triggers_pivot() {
            let cluster = Arc::new(cluster_with_phase(
                "ready-infra-cluster",
                ClusterPhase::Provisioning,
            ));
            let (ctx, capture) = mock_context_infra_ready_with_capture();

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Verify transition to Pivoting phase
            assert!(capture.was_updated(), "status should be updated");
            assert_eq!(capture.last_phase(), Some(ClusterPhase::Pivoting));
            // Quick requeue to monitor pivot progress
            assert_eq!(action, Action::requeue(Duration::from_secs(5)));
        }

        /// Story: Once a cluster is fully self-managing, the controller only needs
        /// periodic drift detection to ensure the cluster matches its spec.
        #[tokio::test]
        async fn ready_cluster_performs_drift_detection() {
            let cluster = Arc::new(cluster_with_phase("ready-cluster", ClusterPhase::Ready));
            let ctx = mock_context_readonly();

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Long requeue interval for healthy clusters
            assert_eq!(action, Action::requeue(Duration::from_secs(60)));
        }

        /// Story: A failed cluster requires human intervention to fix the spec.
        /// The controller waits for spec changes rather than retrying on a timer.
        #[tokio::test]
        async fn failed_cluster_awaits_human_intervention() {
            let cluster = Arc::new(cluster_with_phase("failed-cluster", ClusterPhase::Failed));
            let ctx = mock_context_readonly();

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Wait for spec changes, don't retry on timer
            assert_eq!(action, Action::await_change());
        }

        /// Story: Invalid cluster specs (like zero control plane nodes) should
        /// immediately fail rather than attempting to provision bad infrastructure.
        #[tokio::test]
        async fn invalid_spec_immediately_fails() {
            let cluster = Arc::new(invalid_cluster("invalid-cluster"));
            let (ctx, capture) = mock_context_with_status_capture();

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Verify transition to Failed phase
            assert!(capture.was_updated(), "status should be updated");
            assert_eq!(capture.last_phase(), Some(ClusterPhase::Failed));
            // Wait for user to fix the spec
            assert_eq!(action, Action::await_change());
        }

        // ===== Phase Regression Guard Tests =====

        /// Story: A non-self cluster with pivot_complete=true must never regress
        /// to a pre-pivot phase. This prevents Flux or other external agents from
        /// accidentally re-triggering provisioning on the parent side.
        #[tokio::test]
        async fn pivoted_cluster_rejects_phase_regression() {
            let mut cluster = cluster_with_phase("pivoted-child", ClusterPhase::Pending);
            // Simulate Flux resetting phase to Pending while pivot_complete is true
            cluster.status.as_mut().unwrap().pivot_complete = true;
            let cluster = Arc::new(cluster);
            let (ctx, capture) = mock_context_with_status_capture();

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Should force back to Pivoted, not start provisioning
            assert!(capture.was_updated(), "status should be updated");
            assert_eq!(capture.last_phase(), Some(ClusterPhase::Pivoted));
            assert_eq!(action, Action::requeue(Duration::from_secs(60)));
        }

        // ===== Error Propagation Tests =====

        /// Story: When the Kubernetes API is unavailable, errors should propagate
        /// so the controller can apply exponential backoff.
        #[tokio::test]
        async fn kube_api_errors_trigger_retry() {
            let cluster = Arc::new(sample_cluster("error-cluster"));

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status()
                .returning(|_, _| Err(Error::provider("connection refused".to_string())));
            mock.expect_ensure_namespace().returning(|_| Ok(()));
            mock.expect_get_cloud_provider()
                .returning(|_| Ok(Some(sample_docker_provider())));

            let mut capi_mock = MockCAPIClient::new();
            capi_mock.expect_apply_manifests().returning(|_, _| Ok(()));

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                mock_capi_installer(),
            ));

            let result = reconcile(cluster, ctx).await;

            // Observable outcome: error propagates for retry
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("connection refused"));
        }

        /// Story: CAPI manifest application failures should propagate so the
        /// error policy can handle retries.
        #[tokio::test]
        async fn capi_failures_trigger_retry() {
            let cluster = Arc::new(sample_cluster("capi-error-cluster"));

            let mut mock = MockKubeClient::new();
            mock.expect_ensure_namespace().returning(|_| Ok(()));
            mock.expect_get_cloud_provider()
                .returning(|_| Ok(Some(sample_docker_provider())));

            let mut capi_mock = MockCAPIClient::new();
            capi_mock
                .expect_apply_manifests()
                .returning(|_, _| Err(Error::provider("CAPI apply failed".to_string())));

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                mock_capi_installer(),
            ));

            let result = reconcile(cluster, ctx).await;

            // Observable outcome: error with context propagates
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("CAPI apply failed"));
        }
    }

    mod error_policy_tests {
        use super::*;

        use rstest::rstest;

        fn mock_context_no_updates() -> Arc<Context> {
            let mock = MockKubeClient::new();
            let capi_mock = MockCAPIClient::new();
            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));
            Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(installer),
            ))
        }

        #[rstest]
        #[case::provider_error(Error::provider("test error".to_string()), true)]
        #[case::validation_error(Error::validation("invalid spec".to_string()), false)]
        #[case::pivot_error(Error::pivot("pivot failed".to_string()), true)]
        fn test_error_policy_requeue_behavior(#[case] error: Error, #[case] retryable: bool) {
            let cluster = Arc::new(sample_cluster("test-cluster"));
            let ctx = mock_context_no_updates();

            let action = error_policy(cluster, &error, ctx);

            if retryable {
                assert_eq!(action, Action::requeue(Duration::from_secs(5)));
            } else {
                assert_eq!(action, Action::await_change());
            }
        }
    }

    /// Tests for status update error handling
    ///
    /// Note: The actual status content (phase, message, conditions) is tested
    /// through the reconcile flow tests which verify the complete behavior.
    /// These tests focus on error propagation which is a separate concern.
    mod status_error_handling {
        use super::*;

        /// Story: When the Kubernetes API fails during status update, the error
        /// should propagate up so the controller can retry the reconciliation.
        #[tokio::test]
        async fn test_kube_api_failure_propagates_error() {
            let cluster = sample_cluster("test-cluster");

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status()
                .returning(|_, _| Err(Error::provider("connection failed".to_string())));

            let capi_mock = MockCAPIClient::new();
            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));
            let ctx =
                Context::for_testing(Arc::new(mock), Arc::new(capi_mock), Arc::new(installer));

            let result =
                update_cluster_status(&cluster, &ctx, ClusterPhase::Provisioning, None, false)
                    .await;

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("connection failed"));
        }
    }
    mod generate_manifests_tests {
        use super::*;

        fn cluster_with_docker_config(name: &str) -> LatticeCluster {
            LatticeCluster {
                metadata: ObjectMeta {
                    name: Some(name.to_string()),
                    ..Default::default()
                },
                spec: LatticeClusterSpec {
                    provider_ref: "test-provider".to_string(),
                    provider: ProviderSpec {
                        kubernetes: KubernetesSpec {
                            version: "1.32.0".to_string(),
                            cert_sans: None,
                            bootstrap: BootstrapProvider::default(),
                        },
                        config: ProviderConfig::docker(),
                        credentials_secret_ref: None,
                    },
                    nodes: NodeSpec {
                        control_plane: ControlPlaneSpec {
                            replicas: 1,
                            instance_type: None,
                            root_volume: None,
                        },
                        worker_pools: std::collections::BTreeMap::from([(
                            "default".to_string(),
                            WorkerPoolSpec {
                                replicas: 2,
                                ..Default::default()
                            },
                        )]),
                    },

                    parent_config: None,
                    services: true,
                    gpu: false,
                    monitoring: MonitoringConfig::default(),
                    backups: BackupsConfig::default(),
                    network_topology: None,
                    registry_mirrors: None,
                },
                status: None,
            }
        }

        fn mock_context() -> Arc<Context> {
            let mock = MockKubeClient::new();
            let capi_mock = MockCAPIClient::new();
            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));
            Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(installer),
            ))
        }

        #[tokio::test]
        async fn test_generate_capi_manifests_docker_provider() {
            let cluster = cluster_with_docker_config("docker-cluster");
            let ctx = mock_context();
            let result = generate_capi_manifests(&cluster, &ctx).await;

            assert!(result.is_ok());
            let manifests = result.expect("manifest generation should succeed");
            // Docker provider should generate manifests
            assert!(!manifests.is_empty());
        }
    }

    /// Infrastructure Ready Detection Tests
    ///
    /// These tests verify the controller correctly detects when CAPI
    /// infrastructure is ready based on the Cluster resource status.
    mod infrastructure_ready_detection {
        use super::*;

        /// Story: When CAPI reports infrastructure NOT ready, the controller
        /// should continue polling with the Provisioning phase requeue interval.
        #[tokio::test]
        async fn not_ready_infrastructure_triggers_requeue() {
            let cluster = Arc::new(cluster_with_phase(
                "provisioning-cluster",
                ClusterPhase::Provisioning,
            ));

            let mock = MockKubeClient::new();
            let mut capi_mock = MockCAPIClient::new();

            // Infrastructure is NOT ready
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _, _| Ok(false));

            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(installer),
            ));

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Should requeue with longer interval while waiting
            assert_eq!(action, Action::requeue(Duration::from_secs(30)));
        }

        /// Story: When CAPI reports infrastructure IS ready, the controller
        /// should transition to Pivoting phase.
        #[tokio::test]
        async fn ready_infrastructure_triggers_phase_transition() {
            use std::sync::{Arc as StdArc, Mutex};

            let cluster = Arc::new(cluster_with_phase(
                "ready-cluster",
                ClusterPhase::Provisioning,
            ));

            let updates: StdArc<Mutex<Vec<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(Vec::new()));
            let updates_clone = updates.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                updates_clone
                    .lock()
                    .expect("mutex should not be poisoned")
                    .push(status.clone());
                Ok(())
            });

            let mut capi_mock = MockCAPIClient::new();
            // Infrastructure IS ready
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _, _| Ok(true));

            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(installer),
            ));

            let action = reconcile(cluster, ctx)
                .await
                .expect("reconcile should succeed");

            // Should transition to Pivoting and requeue quickly
            let recorded = updates.lock().expect("mutex should not be poisoned");
            assert!(!recorded.is_empty());
            assert_eq!(
                recorded.last().expect("should have records").phase,
                ClusterPhase::Pivoting
            );
            assert_eq!(action, Action::requeue(Duration::from_secs(5)));
        }

        /// Story: When CAPI infrastructure check fails, error should propagate
        /// for retry with backoff.
        #[tokio::test]
        async fn infrastructure_check_failure_propagates_error() {
            let cluster = Arc::new(cluster_with_phase(
                "error-cluster",
                ClusterPhase::Provisioning,
            ));

            let mock = MockKubeClient::new();
            let mut capi_mock = MockCAPIClient::new();

            // Infrastructure check fails
            capi_mock
                .expect_is_infrastructure_ready()
                .returning(|_, _, _| Err(Error::provider("CAPI API unavailable".to_string())));

            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(installer),
            ));

            let result = reconcile(cluster, ctx).await;

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("CAPI API unavailable"));
        }
    }

    /// CAPI Installation Flow Tests
    ///
    /// These tests verify the controller correctly handles CAPI installation.
    /// CAPI ensure is always called (it's idempotent).
    mod capi_installation_flow {
        use super::*;

        use std::sync::{Arc as StdArc, Mutex};

        /// Story: Controller always calls CAPI ensure before provisioning
        /// (ensure is idempotent - handles upgrades and no-ops).
        #[tokio::test]
        async fn capi_init_called_before_provisioning() {
            let cluster = Arc::new(sample_cluster("ready-to-provision"));

            let updates: StdArc<Mutex<Vec<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(Vec::new()));
            let updates_clone = updates.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                updates_clone
                    .lock()
                    .expect("mutex should not be poisoned")
                    .push(status.clone());
                Ok(())
            });
            mock.expect_ensure_namespace().returning(|_| Ok(()));
            mock.expect_get_cloud_provider()
                .returning(|_| Ok(Some(sample_docker_provider())));

            let mut capi_mock = MockCAPIClient::new();
            capi_mock.expect_apply_manifests().returning(|_, _| Ok(()));

            let mut installer = MockCapiInstaller::new();
            // Installer should always be called (idempotent)
            installer.expect_ensure().times(1).returning(|_| Ok(()));

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(installer),
            ));

            let result = reconcile(cluster, ctx).await;

            assert!(result.is_ok());
            // Should have transitioned to Provisioning
            let recorded = updates.lock().expect("mutex should not be poisoned");
            assert!(!recorded.is_empty());
        }

        /// Story: When CAPI installation fails, the error should propagate
        /// for retry with exponential backoff.
        #[tokio::test]
        async fn capi_installation_failure_propagates_error() {
            let cluster = Arc::new(sample_cluster("install-fails"));

            let mut mock = MockKubeClient::new();
            mock.expect_get_cloud_provider()
                .returning(|_| Ok(Some(sample_docker_provider())));
            let capi_mock = MockCAPIClient::new();

            let mut installer = MockCapiInstaller::new();
            // Installation fails
            installer.expect_ensure().returning(|_| {
                Err(Error::capi_installation(
                    "provider manifests not found".to_string(),
                ))
            });

            let ctx = Arc::new(Context::for_testing(
                Arc::new(mock),
                Arc::new(capi_mock),
                Arc::new(installer),
            ));

            let result = reconcile(cluster, ctx).await;

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("provider manifests"));
        }
    }

    /// Status Update Content Tests
    ///
    /// These tests verify that status updates contain the correct phase,
    /// message, and conditions as the cluster progresses through its lifecycle.
    mod status_update_content {
        use super::*;

        use std::sync::{Arc as StdArc, Mutex};

        /// Story: When transitioning to Provisioning, the status should include
        /// a clear message and Provisioning condition for observability.
        #[tokio::test]
        async fn provisioning_status_has_correct_content() {
            let cluster = sample_cluster("new-cluster");

            let captured_status: StdArc<Mutex<Option<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(None));
            let captured_clone = captured_status.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                *captured_clone.lock().expect("mutex should not be poisoned") =
                    Some(status.clone());
                Ok(())
            });

            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));
            let ctx = Context::for_testing(
                Arc::new(mock),
                Arc::new(MockCAPIClient::new()),
                Arc::new(installer),
            );

            update_cluster_status(&cluster, &ctx, ClusterPhase::Provisioning, None, false)
                .await
                .expect("update_cluster_status should succeed");

            let status = captured_status
                .lock()
                .expect("mutex should not be poisoned")
                .clone()
                .expect("status should be set");
            assert_eq!(status.phase, ClusterPhase::Provisioning);
            assert!(status
                .message
                .expect("message should be set")
                .contains("Provisioning"));
            assert!(!status.conditions.is_empty());

            let condition = &status.conditions[0];
            assert_eq!(condition.type_, "Provisioning");
            assert_eq!(condition.status, ConditionStatus::True);
        }

        /// Story: When transitioning to Pivoting, the status should indicate
        /// that the cluster is being transitioned to self-management.
        #[tokio::test]
        async fn pivoting_status_has_correct_content() {
            let cluster = sample_cluster("pivoting-cluster");

            let captured_status: StdArc<Mutex<Option<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(None));
            let captured_clone = captured_status.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                *captured_clone.lock().expect("mutex should not be poisoned") =
                    Some(status.clone());
                Ok(())
            });

            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));
            let ctx = Context::for_testing(
                Arc::new(mock),
                Arc::new(MockCAPIClient::new()),
                Arc::new(installer),
            );

            update_cluster_status(&cluster, &ctx, ClusterPhase::Pivoting, None, false)
                .await
                .expect("update_cluster_status should succeed");

            let status = captured_status
                .lock()
                .expect("mutex should not be poisoned")
                .clone()
                .expect("status should be set");
            assert_eq!(status.phase, ClusterPhase::Pivoting);
            assert!(status
                .message
                .expect("message should be set")
                .contains("Pivoting"));

            let condition = &status.conditions[0];
            assert_eq!(condition.type_, "Pivoting");
            assert_eq!(condition.reason, "StartingPivot");
        }

        /// Story: When a cluster fails validation, the status should clearly
        /// indicate the failure reason so users can fix the configuration.
        #[tokio::test]
        async fn failed_status_includes_error_message() {
            let cluster = sample_cluster("invalid-cluster");

            let captured_status: StdArc<Mutex<Option<LatticeClusterStatus>>> =
                StdArc::new(Mutex::new(None));
            let captured_clone = captured_status.clone();

            let mut mock = MockKubeClient::new();
            mock.expect_patch_status().returning(move |_, status| {
                *captured_clone.lock().expect("mutex should not be poisoned") =
                    Some(status.clone());
                Ok(())
            });

            let mut installer = MockCapiInstaller::new();
            installer.expect_ensure().returning(|_| Ok(()));
            let ctx = Context::for_testing(
                Arc::new(mock),
                Arc::new(MockCAPIClient::new()),
                Arc::new(installer),
            );

            let error_msg = "control plane count must be at least 1";
            update_cluster_status(&cluster, &ctx, ClusterPhase::Failed, Some(error_msg), false)
                .await
                .expect("update_cluster_status should succeed");

            let status = captured_status
                .lock()
                .expect("mutex should not be poisoned")
                .clone()
                .expect("status should be set");
            assert_eq!(status.phase, ClusterPhase::Failed);
            assert_eq!(
                status.message.as_ref().expect("message should be set"),
                error_msg
            );

            let condition = &status.conditions[0];
            assert_eq!(condition.type_, "Ready");
            assert_eq!(condition.status, ConditionStatus::False);
            assert_eq!(condition.reason, "ValidationFailed");
            assert_eq!(condition.message, error_msg);
        }
    }

    /// Error Policy Behavior Tests
    ///
    /// These tests verify that the error policy correctly handles different
    /// types of errors and returns appropriate requeue actions.
    mod error_policy_behavior {
        use super::*;

        fn mock_context_minimal() -> Arc<Context> {
            Arc::new(Context::for_testing(
                Arc::new(MockKubeClient::new()),
                Arc::new(MockCAPIClient::new()),
                Arc::new(MockCapiInstaller::new()),
            ))
        }

        /// Story: Retryable errors requeue with exponential backoff,
        /// non-retryable errors await change.
        #[test]
        fn retryable_errors_requeue_nonretryable_await() {
            let cluster = Arc::new(sample_cluster("error-cluster"));

            // Retryable errors should requeue
            let retryable = vec![
                Error::provider("provider error".to_string()),
                Error::pivot("pivot error".to_string()),
                Error::capi_installation("capi error".to_string()),
            ];
            for error in retryable {
                let ctx = mock_context_minimal(); // Fresh context per error
                let action = error_policy(cluster.clone(), &error, ctx);
                assert_ne!(
                    action,
                    Action::await_change(),
                    "retryable error {:?} should requeue",
                    error
                );
            }

            // Non-retryable errors should await change
            let non_retryable = vec![
                Error::validation("validation error".to_string()),
                Error::serialization("serialization error".to_string()),
            ];
            for error in non_retryable {
                let ctx = mock_context_minimal();
                let action = error_policy(cluster.clone(), &error, ctx);
                assert_eq!(
                    action,
                    Action::await_change(),
                    "non-retryable error {:?} should await change",
                    error
                );
            }
        }

        /// Story: Error policy should work correctly with clusters in any phase.
        #[test]
        fn error_policy_works_for_all_phases() {
            let phases = vec![
                ClusterPhase::Pending,
                ClusterPhase::Provisioning,
                ClusterPhase::Pivoting,
                ClusterPhase::Pivoted,
                ClusterPhase::Ready,
                ClusterPhase::Deleting,
                ClusterPhase::Unpivoting,
                ClusterPhase::Failed,
            ];

            for phase in phases {
                let ctx = mock_context_minimal(); // Fresh context per phase
                let cluster = Arc::new(cluster_with_phase("test", phase));
                let error = Error::provider("test error".to_string());
                let action = error_policy(cluster, &error, ctx);

                assert_eq!(
                    action,
                    Action::requeue(Duration::from_secs(5)),
                    "phase {:?} should trigger requeue on first error",
                    phase
                );
            }
        }
    }
}
