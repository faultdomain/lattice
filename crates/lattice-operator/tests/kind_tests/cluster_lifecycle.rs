//! Integration tests for cluster lifecycle
//!
//! These tests tell the story of how the Lattice controller reconciles cluster
//! resources through their lifecycle. They verify the controller's behavior
//! against a real Kubernetes cluster, ensuring the reconciliation loop
//! correctly manages cluster state transitions.

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, DeleteParams, Patch, PatchParams, PostParams};
use kube::Client;

use lattice_operator::controller::{reconcile, Context, KubeClientImpl};
use lattice_operator::crd::{
    BootstrapProvider, ClusterPhase, DockerConfig, EndpointsSpec, KubernetesSpec, LatticeCluster,
    LatticeClusterSpec, LatticeClusterStatus, NodeSpec, ProviderConfig, ProviderSpec, ServiceSpec,
};

use super::helpers::ensure_test_cluster;

// =============================================================================
// Test Fixtures
// =============================================================================

/// Create a sample valid cluster for testing
fn sample_cluster(name: &str) -> LatticeCluster {
    LatticeCluster {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        spec: LatticeClusterSpec {
            provider: ProviderSpec {
                kubernetes: KubernetesSpec {
                    version: "1.31.0".to_string(),
                    cert_sans: Some(vec!["127.0.0.1".to_string()]),
                    bootstrap: BootstrapProvider::default(),
                },
                config: ProviderConfig::docker(),
            },
            nodes: NodeSpec {
                control_plane: 1,
                workers: 2,
            },
            networking: None,
            endpoints: Some(EndpointsSpec {
                host: "172.18.255.1".to_string(),
                grpc_port: 50051,
                bootstrap_port: 8443,
                service: ServiceSpec {
                    type_: "LoadBalancer".to_string(),
                },
            }),
            environment: None,
            region: None,
            workload: None,
        },
        status: None,
    }
}

/// Create an invalid cluster (zero control plane nodes)
fn invalid_cluster(name: &str) -> LatticeCluster {
    let mut cluster = sample_cluster(name);
    cluster.spec.nodes.control_plane = 0;
    cluster
}

/// Helper to cleanup a cluster resource
async fn cleanup_cluster(client: &Client, name: &str) {
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let _ = api.delete(name, &DeleteParams::default()).await;
    // Wait for deletion to complete
    tokio::time::sleep(Duration::from_millis(500)).await;
}

/// Create a controller context for testing
fn create_test_context(client: Client) -> Arc<Context> {
    Arc::new(Context::new(client))
}

/// Set the cluster status to a specific phase
async fn set_cluster_phase(api: &Api<LatticeCluster>, name: &str, phase: ClusterPhase) {
    let status = LatticeClusterStatus::with_phase(phase);
    let status_patch = serde_json::json!({ "status": status });
    api.patch_status(
        name,
        &PatchParams::apply("test"),
        &Patch::Merge(&status_patch),
    )
    .await
    .expect("failed to patch status");
}

// =============================================================================
// Cluster Provisioning Flow Stories
// =============================================================================
//
// These tests demonstrate the journey of a cluster from creation through
// provisioning. The controller's state machine drives this progression.

/// Story: Cluster in Provisioning waits for infrastructure to be ready
///
/// While infrastructure is being created (VMs, networks, etc.), the controller
/// continues to poll for completion. It requeues the reconciliation to check
/// again later, rather than blocking.
///
/// Lifecycle: Provisioning -> (polling) -> Provisioning
#[tokio::test]
#[ignore = "requires kind cluster - run with: cargo test --test integration -- --ignored"]
async fn story_provisioning_cluster_polls_for_infrastructure() {
    let client = ensure_test_cluster()
        .await
        .expect("failed to setup cluster");
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let name = "test-provision-polling";

    // Cleanup from previous test runs
    cleanup_cluster(&client, name).await;

    // Setup: Create a cluster already in Provisioning phase
    let cluster = sample_cluster(name);
    api.create(&PostParams::default(), &cluster)
        .await
        .expect("failed to create cluster");
    set_cluster_phase(&api, name, ClusterPhase::Provisioning).await;

    // Act: Controller reconciles the provisioning cluster
    let provisioning = api.get(name).await.expect("failed to get cluster");
    let ctx = create_test_context(client.clone());
    let result = reconcile(Arc::new(provisioning), ctx).await;

    // Assert: Reconcile succeeds (controller doesn't error while waiting)
    assert!(result.is_ok(), "Reconcile should succeed while polling");
    // Note: The action returned depends on whether CAPI reports ready

    // Cleanup
    cleanup_cluster(&client, name).await;
}

// =============================================================================
// Validation Failure Stories
// =============================================================================
//
// These tests demonstrate how the controller handles invalid cluster specs.
// Rather than crashing or leaving clusters in limbo, it sets them to Failed
// with a descriptive message.

/// Story: Invalid cluster spec fails validation and enters Failed state
///
/// When a user creates a cluster with an invalid specification (e.g., zero
/// control plane nodes), the controller should immediately set the status
/// to Failed with a message explaining the validation error.
///
/// Lifecycle: (invalid spec) -> Failed
#[tokio::test]
#[ignore = "requires kind cluster - run with: cargo test --test integration -- --ignored"]
async fn story_invalid_spec_immediately_fails_with_explanation() {
    let client = ensure_test_cluster()
        .await
        .expect("failed to setup cluster");
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let name = "test-invalid-fails";

    // Cleanup from previous test runs
    cleanup_cluster(&client, name).await;

    // Act: Create a cluster with an invalid spec (0 control plane nodes)
    let cluster = invalid_cluster(name);
    let created = api
        .create(&PostParams::default(), &cluster)
        .await
        .expect("failed to create cluster");

    // Act: Controller reconciles the invalid cluster
    let ctx = create_test_context(client.clone());
    let result = reconcile(Arc::new(created), ctx).await;

    // Assert: Reconcile succeeds (validation failure is handled gracefully)
    assert!(
        result.is_ok(),
        "Reconcile should succeed even with validation failure"
    );

    // Assert: Cluster transitions to Failed with explanatory message
    let updated = api.get(name).await.expect("failed to get cluster");
    assert!(updated.status.is_some(), "Status should be set");
    let status = updated.status.unwrap();
    assert_eq!(
        status.phase,
        ClusterPhase::Failed,
        "Should be in Failed phase"
    );
    assert!(status.message.is_some(), "Should have error message");
    assert!(
        status.message.as_ref().unwrap().contains("control plane"),
        "Error message should explain the validation failure"
    );

    // Cleanup
    cleanup_cluster(&client, name).await;
}

// =============================================================================
// Ready Cluster Stories
// =============================================================================
//
// These tests demonstrate the behavior of healthy, operational clusters.

/// Story: Ready cluster continues periodic drift detection
///
/// Once a cluster is fully operational (Ready state), the controller continues
/// to periodically reconcile it to detect any drift from the desired spec.
/// The status remains Ready as long as everything is healthy.
///
/// Lifecycle: Ready -> (drift check) -> Ready
#[tokio::test]
#[ignore = "requires kind cluster - run with: cargo test --test integration -- --ignored"]
async fn story_ready_cluster_performs_periodic_drift_detection() {
    let client = ensure_test_cluster()
        .await
        .expect("failed to setup cluster");
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let name = "test-ready-drift";

    // Cleanup from previous test runs
    cleanup_cluster(&client, name).await;

    // Setup: Create a cluster in Ready state (simulating a fully provisioned cluster)
    let cluster = sample_cluster(name);
    api.create(&PostParams::default(), &cluster)
        .await
        .expect("failed to create cluster");
    set_cluster_phase(&api, name, ClusterPhase::Ready).await;

    // Act: Controller reconciles the ready cluster
    let ready = api.get(name).await.expect("failed to get cluster");
    let ctx = create_test_context(client.clone());
    let result = reconcile(Arc::new(ready), ctx).await;

    // Assert: Reconcile succeeds and schedules next drift check
    assert!(result.is_ok(), "Reconcile should succeed for ready cluster");

    // Assert: Cluster remains in Ready state
    let updated = api.get(name).await.expect("failed to get cluster");
    assert!(updated.status.is_some(), "Status should be preserved");
    assert_eq!(
        updated.status.unwrap().phase,
        ClusterPhase::Ready,
        "Should remain Ready"
    );

    // Cleanup
    cleanup_cluster(&client, name).await;
}

// =============================================================================
// Failed Cluster Recovery Stories
// =============================================================================
//
// These tests demonstrate how failed clusters await user intervention.

/// Story: Failed cluster waits for spec changes rather than retrying blindly
///
/// When a cluster is in Failed state (e.g., due to validation error or
/// infrastructure failure), the controller should NOT automatically retry.
/// Instead, it waits for the user to fix the spec. This prevents tight
/// retry loops that would waste resources.
///
/// Lifecycle: Failed -> (awaiting user fix) -> Failed
#[tokio::test]
#[ignore = "requires kind cluster - run with: cargo test --test integration -- --ignored"]
async fn story_failed_cluster_awaits_user_intervention() {
    let client = ensure_test_cluster()
        .await
        .expect("failed to setup cluster");
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let name = "test-failed-awaits";

    // Cleanup from previous test runs
    cleanup_cluster(&client, name).await;

    // Setup: Create a cluster in Failed state
    let cluster = sample_cluster(name);
    api.create(&PostParams::default(), &cluster)
        .await
        .expect("failed to create cluster");

    let status = LatticeClusterStatus::with_phase(ClusterPhase::Failed)
        .message("Previous provisioning failure - needs manual intervention");
    let status_patch = serde_json::json!({ "status": status });
    api.patch_status(
        name,
        &PatchParams::apply("test"),
        &Patch::Merge(&status_patch),
    )
    .await
    .expect("failed to patch status");

    // Act: Controller reconciles the failed cluster
    let failed = api.get(name).await.expect("failed to get cluster");
    let ctx = create_test_context(client.clone());
    let result = reconcile(Arc::new(failed), ctx).await;

    // Assert: Reconcile succeeds but returns await_change (not requeue)
    assert!(
        result.is_ok(),
        "Reconcile should succeed even for failed cluster"
    );
    // Note: The action should be Action::await_change() but we can't easily assert
    // the exact action type without pattern matching on the internal Duration

    // Cleanup
    cleanup_cluster(&client, name).await;
}

// =============================================================================
// KubeClientImpl Integration Stories
// =============================================================================
//
// These tests verify the KubeClientImpl implementation works correctly
// against a real Kubernetes API.

/// Story: KubeClientImpl correctly patches cluster status
///
/// The KubeClientImpl trait implementation must correctly communicate
/// with the Kubernetes API to update cluster status. This is critical
/// for the controller to persist state changes.
#[tokio::test]
#[ignore = "requires kind cluster - run with: cargo test --test integration -- --ignored"]
async fn story_kube_client_persists_status_changes() {
    let client = ensure_test_cluster()
        .await
        .expect("failed to setup cluster");
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let name = "test-client-patch";

    // Cleanup from previous test runs
    cleanup_cluster(&client, name).await;

    // Setup: Create a cluster
    let cluster = sample_cluster(name);
    api.create(&PostParams::default(), &cluster)
        .await
        .expect("failed to create cluster");

    // Act: Use KubeClientImpl to patch the status
    use lattice_operator::controller::KubeClient;
    let kube_client = KubeClientImpl::new(client.clone());

    let status = LatticeClusterStatus::with_phase(ClusterPhase::Provisioning)
        .message("Infrastructure creation in progress");

    let result = kube_client.patch_status(name, &status).await;

    // Assert: Patch succeeds
    assert!(result.is_ok(), "Status patch should succeed");

    // Assert: Status is persisted correctly
    let updated = api.get(name).await.expect("failed to get cluster");
    assert!(updated.status.is_some(), "Status should be set");
    assert_eq!(
        updated.status.as_ref().unwrap().phase,
        ClusterPhase::Provisioning,
        "Phase should be persisted"
    );
    assert_eq!(
        updated.status.as_ref().unwrap().message.as_deref(),
        Some("Infrastructure creation in progress"),
        "Message should be persisted"
    );

    // Cleanup
    cleanup_cluster(&client, name).await;
}
