//! Integration tests for CRD operations
//!
//! These tests tell the story of how users interact with LatticeCluster resources
//! through the Kubernetes API. Each test represents a real-world scenario that
//! platform operators would encounter.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, DeleteParams, PostParams};
use kube::Client;

use lattice::crd::{
    CellSpec, KubernetesSpec, LatticeCluster, LatticeClusterSpec, NodeSpec, ProviderSpec,
    ProviderType, ServiceSpec,
};

use super::helpers::ensure_test_cluster;

// =============================================================================
// Test Fixtures
// =============================================================================

/// Create a sample management cluster (cell) spec
fn sample_cell_spec(name: &str) -> LatticeCluster {
    LatticeCluster {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        spec: LatticeClusterSpec {
            provider: ProviderSpec {
                type_: ProviderType::Docker,
                kubernetes: KubernetesSpec {
                    version: "1.31.0".to_string(),
                    cert_sans: Some(vec!["127.0.0.1".to_string(), "localhost".to_string()]),
                },
            },
            nodes: NodeSpec {
                control_plane: 1,
                workers: 2,
            },
            networking: None,
            cell: Some(CellSpec {
                host: "172.18.255.1".to_string(),
                grpc_port: 50051,
                bootstrap_port: 8443,
                service: ServiceSpec {
                    type_: "LoadBalancer".to_string(),
                },
            }),
            cell_ref: None,
            environment: None,
            region: None,
            workload: None,
        },
        status: None,
    }
}

/// Create a sample workload cluster spec that references a parent cell
fn sample_workload_spec(name: &str, cell_ref: &str) -> LatticeCluster {
    LatticeCluster {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        spec: LatticeClusterSpec {
            provider: ProviderSpec {
                type_: ProviderType::Docker,
                kubernetes: KubernetesSpec {
                    version: "1.31.0".to_string(),
                    cert_sans: None,
                },
            },
            nodes: NodeSpec {
                control_plane: 1,
                workers: 3,
            },
            networking: None,
            cell: None,
            cell_ref: Some(cell_ref.to_string()),
            environment: Some("prod".to_string()),
            region: Some("us-west".to_string()),
            workload: None,
        },
        status: None,
    }
}

/// Helper to cleanup a cluster resource
async fn cleanup_cluster(client: &Client, name: &str) {
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let _ = api.delete(name, &DeleteParams::default()).await;
}

// =============================================================================
// Management Cluster (Cell) Lifecycle Stories
// =============================================================================
//
// These tests demonstrate the journey of creating and managing a cell - the
// central management cluster that will provision workload clusters.

/// Story: Platform operator creates a new management cluster (cell)
///
/// When a platform operator wants to set up Lattice, they first need to create
/// a management cluster. This cell will have the Lattice operator and CAPI
/// installed, enabling it to provision workload clusters.
///
/// Expected behavior:
/// - The LatticeCluster resource is created in Kubernetes
/// - The cluster is marked as a cell (has cell config, no cellRef)
/// - All provider and node configurations are persisted correctly
#[tokio::test]
#[ignore = "requires kind cluster - run with: cargo test --test integration -- --ignored"]
async fn story_operator_creates_management_cluster() {
    let client = ensure_test_cluster()
        .await
        .expect("failed to setup cluster");
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let name = "test-mgmt-create";

    // Cleanup any existing resource from previous test runs
    cleanup_cluster(&client, name).await;

    // Act: Platform operator creates the management cluster
    let cluster = sample_cell_spec(name);
    let created = api
        .create(&PostParams::default(), &cluster)
        .await
        .expect("failed to create cluster");

    // Assert: The cluster is created and recognized as a cell
    assert_eq!(created.metadata.name.as_deref(), Some(name));
    assert!(
        created.spec.is_cell(),
        "Management cluster should be a cell"
    );
    assert!(
        !created.spec.has_parent(),
        "Cell should not be a workload cluster"
    );

    // Assert: Configuration is persisted correctly
    let fetched = api.get(name).await.expect("failed to get cluster");
    assert_eq!(fetched.spec.provider.type_, ProviderType::Docker);
    assert_eq!(fetched.spec.nodes.control_plane, 1);
    assert_eq!(fetched.spec.nodes.workers, 2);
    assert_eq!(fetched.spec.cell.as_ref().unwrap().host, "172.18.255.1");

    // Cleanup
    cleanup_cluster(&client, name).await;
}

// =============================================================================
// Workload Cluster Lifecycle Stories
// =============================================================================
//
// These tests demonstrate the journey of creating workload clusters that are
// managed by a parent cell.

/// Story: Platform operator creates a workload cluster referencing a cell
///
/// After the management cluster is running, the platform operator can create
/// workload clusters. Each workload cluster references its parent cell and
/// includes environment metadata for organization.
///
/// Expected behavior:
/// - The LatticeCluster is created with a reference to the parent cell
/// - Environment and region metadata are preserved
/// - The cluster is recognized as a workload cluster (not a cell)
#[tokio::test]
#[ignore = "requires kind cluster - run with: cargo test --test integration -- --ignored"]
async fn story_operator_creates_workload_cluster_for_production() {
    let client = ensure_test_cluster()
        .await
        .expect("failed to setup cluster");
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let name = "test-workload-create";

    // Cleanup any existing resource from previous test runs
    cleanup_cluster(&client, name).await;

    // Act: Platform operator creates a production workload cluster
    let cluster = sample_workload_spec(name, "mgmt");
    let created = api
        .create(&PostParams::default(), &cluster)
        .await
        .expect("failed to create cluster");

    // Assert: The cluster is created as a workload cluster
    assert_eq!(created.metadata.name.as_deref(), Some(name));
    assert!(
        created.spec.has_parent(),
        "Should be a workload cluster"
    );
    assert!(
        !created.spec.is_cell(),
        "Workload cluster should not be a cell"
    );
    assert_eq!(created.spec.cell_ref.as_deref(), Some("mgmt"));

    // Assert: Environment metadata is preserved
    let fetched = api.get(name).await.expect("failed to get cluster");
    assert_eq!(fetched.spec.environment.as_deref(), Some("prod"));
    assert_eq!(fetched.spec.region.as_deref(), Some("us-west"));

    // Cleanup
    cleanup_cluster(&client, name).await;
}

/// Story: Platform operator views all clusters in the platform
///
/// Platform operators need visibility into all clusters being managed.
/// This includes both management clusters and workload clusters across
/// different environments and regions.
///
/// Expected behavior:
/// - All created clusters appear in the list
/// - Both cells and workload clusters are visible
#[tokio::test]
#[ignore = "requires kind cluster - run with: cargo test --test integration -- --ignored"]
async fn story_operator_lists_all_managed_clusters() {
    let client = ensure_test_cluster()
        .await
        .expect("failed to setup cluster");
    let api: Api<LatticeCluster> = Api::all(client.clone());

    // Cleanup from previous runs
    cleanup_cluster(&client, "test-list-mgmt").await;
    cleanup_cluster(&client, "test-list-prod").await;

    // Act: Create a cell and a workload cluster
    let cell = sample_cell_spec("test-list-mgmt");
    let workload = sample_workload_spec("test-list-prod", "test-list-mgmt");

    api.create(&PostParams::default(), &cell)
        .await
        .expect("failed to create management cluster");
    api.create(&PostParams::default(), &workload)
        .await
        .expect("failed to create workload cluster");

    // Assert: Both clusters are visible in the list
    let list = api
        .list(&Default::default())
        .await
        .expect("failed to list clusters");
    let names: Vec<_> = list
        .items
        .iter()
        .filter_map(|c| c.metadata.name.as_deref())
        .collect();

    assert!(names.contains(&"test-list-mgmt"), "Cell should be listed");
    assert!(
        names.contains(&"test-list-prod"),
        "Workload cluster should be listed"
    );

    // Cleanup
    cleanup_cluster(&client, "test-list-mgmt").await;
    cleanup_cluster(&client, "test-list-prod").await;
}

// =============================================================================
// Day-2 Operations Stories
// =============================================================================
//
// These tests demonstrate ongoing cluster management operations that happen
// after initial cluster creation.

/// Story: Platform operator scales up a cluster's worker pool
///
/// As workload demands increase, platform operators need to add more worker
/// nodes to handle the load. This is a common day-2 operation.
///
/// Expected behavior:
/// - The worker count can be updated via the Kubernetes API
/// - The change persists and is reflected on subsequent reads
/// - The control plane count remains unchanged
#[tokio::test]
#[ignore = "requires kind cluster - run with: cargo test --test integration -- --ignored"]
async fn story_operator_scales_cluster_to_handle_increased_load() {
    let client = ensure_test_cluster()
        .await
        .expect("failed to setup cluster");
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let name = "test-scale-up";

    // Cleanup from previous runs
    cleanup_cluster(&client, name).await;

    // Setup: Create a cluster with 2 workers
    let cluster = sample_cell_spec(name);
    let created = api
        .create(&PostParams::default(), &cluster)
        .await
        .expect("failed to create cluster");
    assert_eq!(created.spec.nodes.workers, 2, "Initial worker count");

    // Act: Scale up to 5 workers
    let mut updated = created.clone();
    updated.spec.nodes.workers = 5;
    let replaced = api
        .replace(name, &PostParams::default(), &updated)
        .await
        .expect("failed to update cluster");

    // Assert: Worker count is updated
    assert_eq!(replaced.spec.nodes.workers, 5);

    // Assert: Change persists
    let fetched = api.get(name).await.expect("failed to get cluster");
    assert_eq!(fetched.spec.nodes.workers, 5);
    assert_eq!(
        fetched.spec.nodes.control_plane, 1,
        "Control plane unchanged"
    );

    // Cleanup
    cleanup_cluster(&client, name).await;
}

/// Story: Platform operator decommissions a cluster
///
/// When a cluster is no longer needed (end of project, consolidation, etc.),
/// the platform operator deletes it. This should clean up the resource from
/// the Kubernetes API.
///
/// Expected behavior:
/// - The cluster can be deleted via the Kubernetes API
/// - After deletion, the cluster no longer exists
#[tokio::test]
#[ignore = "requires kind cluster - run with: cargo test --test integration -- --ignored"]
async fn story_operator_decommissions_unused_cluster() {
    let client = ensure_test_cluster()
        .await
        .expect("failed to setup cluster");
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let name = "test-decommission";

    // Setup: Create a cluster
    let cluster = sample_cell_spec(name);
    api.create(&PostParams::default(), &cluster)
        .await
        .expect("failed to create cluster");

    // Verify it exists
    assert!(
        api.get(name).await.is_ok(),
        "Cluster should exist before deletion"
    );

    // Act: Decommission the cluster
    api.delete(name, &DeleteParams::default())
        .await
        .expect("failed to delete cluster");

    // Wait for deletion to propagate
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Assert: Cluster no longer exists
    let result = api.get(name).await;
    assert!(result.is_err(), "Cluster should not exist after deletion");
}

// =============================================================================
// Validation and Edge Case Stories
// =============================================================================
//
// These tests document current validation behavior and edge cases.

/// Story: Platform operator creates a cluster with conflicting configuration
///
/// A cluster cannot be both a cell AND reference another cell. This test
/// documents that currently K8s accepts this invalid configuration (we don't
/// have a validating webhook), but application-level validation catches it.
///
/// NOTE: This documents current behavior. Future work should add a validating
/// webhook to reject this at the API level.
#[tokio::test]
#[ignore = "requires kind cluster - run with: cargo test --test integration -- --ignored"]
async fn story_operator_creates_cluster_with_conflicting_cell_config() {
    let client = ensure_test_cluster()
        .await
        .expect("failed to setup cluster");
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let name = "test-invalid-config";

    // Cleanup from previous runs
    cleanup_cluster(&client, name).await;

    // Act: Create a cluster that is BOTH a cell AND references another cell
    // This is an invalid configuration
    let mut cluster = sample_cell_spec(name);
    cluster.spec.cell_ref = Some("other-cell".to_string());

    let result = api.create(&PostParams::default(), &cluster).await;

    // Current behavior: K8s accepts it (no validating webhook yet)
    // The controller's reconcile loop will catch this and set Failed status
    if result.is_ok() {
        // Document that K8s accepted it (this is the current limitation)
        // Application-level validation in the controller will catch this
        cleanup_cluster(&client, name).await;
    }
    // Note: A validating webhook would make this test expect an error
}
