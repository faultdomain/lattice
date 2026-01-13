//! Test helpers for integration tests
//!
//! Provides utilities for managing kind clusters and Kubernetes resources.

use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, DeleteParams, PostParams};
use kube::{Client, Config, CustomResourceExt};
use tokio::sync::OnceCell;
use tokio::time::sleep;

use lattice_operator::crd::LatticeCluster;

/// Name of the kind cluster used for integration tests
pub const TEST_CLUSTER_NAME: &str = "lattice-integration-test";

/// Global lock to ensure cluster is created only once
static CLUSTER_INIT: OnceLock<Result<(), String>> = OnceLock::new();

/// Track if CRD has been installed (async-safe)
static CRD_INSTALLED: OnceCell<Result<(), String>> = OnceCell::const_new();

/// Check if a kind cluster with the given name exists
pub fn kind_cluster_exists(name: &str) -> bool {
    let output = Command::new("kind")
        .args(["get", "clusters"])
        .output()
        .expect("failed to run kind");

    let clusters = String::from_utf8_lossy(&output.stdout);
    clusters.lines().any(|line| line.trim() == name)
}

/// Create a kind cluster for testing
pub fn create_kind_cluster(name: &str) -> Result<(), String> {
    if kind_cluster_exists(name) {
        println!("Kind cluster '{name}' already exists, reusing it");
        return Ok(());
    }

    println!("Creating kind cluster '{name}'...");
    let output = Command::new("kind")
        .args(["create", "cluster", "--name", name, "--wait", "60s"])
        .output()
        .map_err(|e| format!("failed to run kind: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "failed to create kind cluster: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    println!("Kind cluster '{name}' created successfully");
    Ok(())
}

/// Delete a kind cluster
#[allow(dead_code)]
pub fn delete_kind_cluster(name: &str) -> Result<(), String> {
    if !kind_cluster_exists(name) {
        return Ok(());
    }

    println!("Deleting kind cluster '{name}'...");
    let output = Command::new("kind")
        .args(["delete", "cluster", "--name", name])
        .output()
        .map_err(|e| format!("failed to run kind: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "failed to delete kind cluster: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

/// Install the LatticeCluster CRD into the cluster
pub async fn install_crd(client: &Client) -> Result<(), kube::Error> {
    let crd = LatticeCluster::crd();
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());

    // Check if CRD already exists
    match crds.get(&crd.metadata.name.clone().unwrap()).await {
        Ok(_) => {
            println!("CRD already installed, deleting and reinstalling...");
            crds.delete(
                &crd.metadata.name.clone().unwrap(),
                &DeleteParams::default(),
            )
            .await?;
            // Wait for deletion
            sleep(Duration::from_secs(2)).await;
        }
        Err(kube::Error::Api(e)) if e.code == 404 => {
            // CRD doesn't exist, continue with installation
        }
        Err(e) => return Err(e),
    }

    println!("Installing LatticeCluster CRD...");
    crds.create(&PostParams::default(), &crd).await?;

    // Wait for CRD to be established
    sleep(Duration::from_secs(2)).await;

    println!("CRD installed successfully");
    Ok(())
}

/// Create a Kubernetes client connected to the test cluster
pub async fn create_test_client() -> Result<Client, String> {
    // Use the kind cluster context directly without modifying kubeconfig
    let context_name = format!("kind-{TEST_CLUSTER_NAME}");

    let config = Config::from_kubeconfig(&kube::config::KubeConfigOptions {
        context: Some(context_name),
        ..Default::default()
    })
    .await
    .map_err(|e| format!("failed to load kubeconfig: {e}"))?;

    Client::try_from(config).map_err(|e| format!("failed to create client: {e}"))
}

/// Ensure the test cluster is ready (thread-safe, cluster created once)
///
/// Returns a fresh Client for each call - clients should not be shared across test threads.
pub async fn ensure_test_cluster() -> Result<Client, String> {
    // Install default crypto provider (required for rustls)
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Ensure cluster is created exactly once using OnceLock (sync is fine for shell commands)
    let cluster_result = CLUSTER_INIT.get_or_init(|| create_kind_cluster(TEST_CLUSTER_NAME));

    // Check if cluster creation succeeded
    cluster_result.clone()?;

    // Create a fresh client for this test
    let client = create_test_client().await?;

    // Install CRD if not already installed (async-safe)
    let crd_result = CRD_INSTALLED
        .get_or_init(|| async {
            let client = create_test_client().await?;
            install_crd(&client)
                .await
                .map_err(|e| format!("failed to install CRD: {e}"))
        })
        .await;

    crd_result.clone()?;

    Ok(client)
}
