//! Uninstall command - Tear down a self-managing Lattice cluster
//!
//! Usage: lattice uninstall --kubeconfig <path>
//!
//! This command safely destroys a self-managing Lattice cluster by:
//! 1. Creating a temporary kind cluster
//! 2. Installing CAPI providers matching the target cluster
//! 3. Deleting LatticeCluster (stops operator from recreating LoadBalancer)
//! 4. Deleting the cell LoadBalancer service
//! 5. Reverse-pivoting CAPI resources from target to kind
//! 6. Patching kubeconfig to use external endpoint
//! 7. Waiting for CAPI to reconcile (InfrastructureReady)
//! 8. Deleting the Cluster resource (triggers infrastructure cleanup)
//! 9. Waiting for infrastructure deletion
//! 10. Deleting the kind cluster

use std::path::PathBuf;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use clap::Args;
use k8s_openapi::api::core::v1::{Secret, Service};
use kube::api::{Api, DeleteParams, DynamicObject, Patch, PatchParams};
use kube::Client;
use tokio::process::Command;
use tracing::{debug, info};

use super::{kind_utils, CommandErrorExt};

use lattice_common::clusterctl::{move_to_kubeconfig, teardown_cluster, TeardownConfig};
use lattice_common::kube_utils;
use lattice_common::AwsCredentials;
use lattice_common::LATTICE_SYSTEM_NAMESPACE;
use lattice_operator::crd::{LatticeCluster, ProviderType};

use crate::{Error, Result};

/// Uninstall a self-managing Lattice cluster
#[derive(Args, Debug)]
pub struct UninstallArgs {
    /// Path to kubeconfig for the cluster to uninstall
    #[arg(short = 'k', long = "kubeconfig")]
    pub kubeconfig: PathBuf,

    /// Cluster name (if different from context)
    #[arg(short = 'n', long = "name")]
    pub name: Option<String>,

    /// Skip confirmation prompt
    #[arg(short = 'y', long = "yes")]
    pub yes: bool,

    /// Skip kind cluster deletion on failure (for debugging)
    #[arg(long)]
    pub keep_bootstrap_on_failure: bool,
}

/// Fixed uninstall bootstrap cluster name
const UNINSTALL_CLUSTER_NAME: &str = "lattice-uninstall";

pub struct Uninstaller {
    kubeconfig: PathBuf,
    cluster_name: String,
    provider: ProviderType,
    capi_namespace: String,
    keep_bootstrap_on_failure: bool,
}

impl Uninstaller {
    pub async fn new(args: &UninstallArgs) -> Result<Self> {
        let client = kube_utils::create_client(Some(&args.kubeconfig))
            .await
            .map_err(|e| Error::command_failed(format!("Failed to create client: {}", e)))?;

        let clusters: Api<LatticeCluster> = Api::all(client);
        let cluster_list = clusters
            .list(&Default::default())
            .await
            .map_err(|e| Error::command_failed(format!("Failed to list clusters: {}", e)))?;

        let cluster = if let Some(name) = &args.name {
            cluster_list
                .items
                .into_iter()
                .find(|c| c.metadata.name.as_deref() == Some(name.as_str()))
                .ok_or_else(|| Error::command_failed(format!("Cluster '{}' not found", name)))?
        } else if cluster_list.items.len() == 1 {
            cluster_list
                .items
                .into_iter()
                .next()
                .expect("len() == 1 guarantees at least one item")
        } else if cluster_list.items.is_empty() {
            return Err(Error::command_failed("No LatticeCluster found"));
        } else {
            let names: Vec<&str> = cluster_list
                .items
                .iter()
                .filter_map(|c| c.metadata.name.as_deref())
                .collect();
            return Err(Error::command_failed(format!(
                "Multiple clusters found, specify --name: {}",
                names.join(", ")
            )));
        };

        let cluster_name = cluster
            .metadata
            .name
            .ok_or_else(|| Error::command_failed("Cluster has no name"))?;

        let provider = cluster.spec.provider.provider_type();
        let capi_namespace = format!("capi-{}", cluster_name);

        Ok(Self {
            kubeconfig: args.kubeconfig.clone(),
            cluster_name,
            provider,
            capi_namespace,
            keep_bootstrap_on_failure: args.keep_bootstrap_on_failure,
        })
    }

    pub fn cluster_name(&self) -> &str {
        &self.cluster_name
    }

    pub fn provider(&self) -> ProviderType {
        self.provider
    }

    fn bootstrap_kubeconfig_path(&self) -> PathBuf {
        std::env::temp_dir().join("lattice-uninstall-bootstrap.kubeconfig")
    }

    async fn target_client(&self) -> Result<Client> {
        kube_utils::create_client(Some(&self.kubeconfig))
            .await
            .map_err(|e| Error::command_failed(format!("Failed to create target client: {}", e)))
    }

    async fn bootstrap_client(&self) -> Result<Client> {
        kube_utils::create_client(Some(&self.bootstrap_kubeconfig_path()))
            .await
            .map_err(|e| Error::command_failed(format!("Failed to create bootstrap client: {}", e)))
    }

    /// Delete the LatticeCluster to stop the operator from reconciling
    ///
    /// This must be called BEFORE deleting the cell service, otherwise the
    /// operator will keep recreating the LoadBalancer service.
    async fn delete_lattice_cluster(&self) -> Result<()> {
        let client = self.target_client().await?;
        let api: Api<LatticeCluster> = Api::all(client);

        match api
            .delete(&self.cluster_name, &DeleteParams::default())
            .await
        {
            Ok(_) => info!(cluster = %self.cluster_name, "Deleted LatticeCluster"),
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(cluster = %self.cluster_name, "LatticeCluster not found (already deleted)");
            }
            Err(e) => {
                return Err(Error::command_failed(format!(
                    "Failed to delete LatticeCluster: {}",
                    e
                )));
            }
        }

        // Wait for LatticeCluster to be fully deleted (finalizers removed)
        info!("Waiting for LatticeCluster deletion...");
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(120) {
            match api.get(&self.cluster_name).await {
                Ok(_) => {
                    debug!("LatticeCluster still exists, waiting...");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(kube::Error::Api(ae)) if ae.code == 404 => {
                    info!("LatticeCluster deleted");
                    return Ok(());
                }
                Err(_) => return Ok(()),
            }
        }

        // Timeout - try to remove finalizer manually
        tracing::warn!("Timeout waiting for LatticeCluster deletion, removing finalizer...");
        if let Ok(cluster) = api.get(&self.cluster_name).await {
            if cluster.metadata.finalizers.is_some() {
                let patch = serde_json::json!({
                    "metadata": {
                        "finalizers": null
                    }
                });
                let _ = api
                    .patch(
                        &self.cluster_name,
                        &PatchParams::default(),
                        &Patch::Merge(&patch),
                    )
                    .await;
            }
        }

        Ok(())
    }

    /// Delete the lattice-cell LoadBalancer service and wait for cleanup
    async fn delete_cell_service(&self) -> Result<()> {
        let client = self.target_client().await?;
        let api: Api<Service> = Api::namespaced(client, LATTICE_SYSTEM_NAMESPACE);

        match api.delete("lattice-cell", &DeleteParams::default()).await {
            Ok(_) => info!("Deleted lattice-cell LoadBalancer service"),
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!("lattice-cell service not found (already deleted)");
                return Ok(());
            }
            Err(e) => {
                return Err(Error::command_failed(format!(
                    "Failed to delete lattice-cell service: {}",
                    e
                )));
            }
        }

        // Wait for deletion
        info!("Waiting for LoadBalancer cleanup...");
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(60) {
            match api.get("lattice-cell").await {
                Ok(_) => tokio::time::sleep(Duration::from_secs(2)).await,
                Err(kube::Error::Api(ae)) if ae.code == 404 => return Ok(()),
                Err(_) => return Ok(()),
            }
        }

        tracing::warn!("Timeout waiting for cell service deletion, proceeding anyway");
        Ok(())
    }

    /// Patch the kubeconfig secret to use the external control plane endpoint.
    ///
    /// After `clusterctl move`, the kubeconfig secret points to the internal Kubernetes
    /// endpoint (kubernetes.default.svc:443) which only works from inside the target cluster.
    /// We patch it to use the external endpoint from the CAPI Cluster's controlPlaneEndpoint
    /// so CAPI controllers on the kind cluster can reach the target for teardown.
    async fn patch_kubeconfig_for_direct_access(&self, client: &Client) -> Result<()> {
        let server_url = self.get_control_plane_endpoint(client).await?;

        let secrets: Api<Secret> = Api::namespaced(client.clone(), &self.capi_namespace);
        let secret_name = format!("{}-kubeconfig", self.cluster_name);

        let secret = secrets.get(&secret_name).await.map_err(|e| {
            Error::command_failed(format!("Failed to get kubeconfig secret: {}", e))
        })?;

        let data = secret
            .data
            .ok_or_else(|| Error::command_failed("Kubeconfig secret has no data"))?;

        let kubeconfig_bytes = data
            .get("value")
            .ok_or_else(|| Error::command_failed("Kubeconfig secret missing 'value' key"))?;

        let kubeconfig_str = String::from_utf8(kubeconfig_bytes.0.clone())
            .map_err(|e| Error::command_failed(format!("Kubeconfig is not valid UTF-8: {}", e)))?;

        // Skip if already pointing to the correct URL
        if kubeconfig_str.contains(&server_url) {
            debug!("Kubeconfig already points to {}", server_url);
            return Ok(());
        }

        info!(
            "Patching kubeconfig to use external endpoint {}",
            server_url
        );

        let mut kubeconfig: serde_json::Value =
            lattice_common::yaml::parse_yaml(&kubeconfig_str)
                .map_err(|e| Error::command_failed(format!("Failed to parse kubeconfig: {}", e)))?;

        // Update server URL in all cluster entries (keep existing CA - it's valid)
        if let Some(clusters) = kubeconfig
            .get_mut("clusters")
            .and_then(|c| c.as_array_mut())
        {
            for cluster in clusters {
                if let Some(server) = cluster.get_mut("cluster").and_then(|c| c.get_mut("server")) {
                    *server = serde_json::Value::String(server_url.clone());
                }
            }
        }

        let encoded = STANDARD.encode(
            serde_json::to_string(&kubeconfig)
                .map_err(|e| Error::command_failed(format!("Failed to serialize: {}", e)))?
                .as_bytes(),
        );

        secrets
            .patch(
                &secret_name,
                &PatchParams::apply("lattice-uninstall"),
                &Patch::Merge(&serde_json::json!({"data": {"value": encoded}})),
            )
            .await
            .map_err(|e| Error::command_failed(format!("Failed to patch secret: {}", e)))?;

        Ok(())
    }

    /// Get the control plane endpoint URL from the CAPI Cluster resource
    async fn get_control_plane_endpoint(&self, client: &Client) -> Result<String> {
        let api_resource = lattice_common::kube_utils::build_api_resource_with_discovery(
            client,
            "cluster.x-k8s.io",
            "Cluster",
        )
        .await
        .map_err(|e| Error::command_failed(format!("API discovery failed: {}", e)))?;

        let api: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), &self.capi_namespace, &api_resource);

        let cluster = api
            .get(&self.cluster_name)
            .await
            .map_err(|e| Error::command_failed(format!("Failed to get CAPI Cluster: {}", e)))?;

        let endpoint = cluster
            .data
            .get("spec")
            .and_then(|s| s.get("controlPlaneEndpoint"))
            .ok_or_else(|| Error::command_failed("CAPI Cluster has no controlPlaneEndpoint"))?;

        let host = endpoint
            .get("host")
            .and_then(|h| h.as_str())
            .ok_or_else(|| Error::command_failed("controlPlaneEndpoint has no host"))?;

        let port = endpoint
            .get("port")
            .and_then(|p| p.as_i64())
            .unwrap_or(6443);

        Ok(format!("https://{}:{}", host, port))
    }

    pub async fn run(&self) -> Result<()> {
        info!(
            "Uninstalling cluster '{}' (provider: {})",
            self.cluster_name, self.provider
        );

        info!("Creating temporary kind cluster...");
        kind_utils::create_kind_cluster(UNINSTALL_CLUSTER_NAME, &self.bootstrap_kubeconfig_path())
            .await?;

        let result = self.run_uninstall().await;

        if result.is_err() && self.keep_bootstrap_on_failure {
            info!("Keeping kind cluster for debugging (--keep-bootstrap-on-failure)");
        } else {
            info!("Deleting temporary kind cluster...");
            if let Err(e) = kind_utils::delete_kind_cluster(UNINSTALL_CLUSTER_NAME).await {
                tracing::warn!("Failed to delete kind cluster: {}", e);
            }
        }

        result
    }

    async fn run_uninstall(&self) -> Result<()> {
        let bootstrap_client = self.bootstrap_client().await?;

        info!("Installing CAPI providers on kind cluster...");
        self.install_capi_providers().await?;

        // Delete LatticeCluster first to stop the operator from reconciling.
        // This prevents the operator from recreating the LoadBalancer service.
        info!("Deleting LatticeCluster to stop operator reconciliation...");
        self.delete_lattice_cluster().await?;

        info!("Cleaning up LoadBalancer service...");
        self.delete_cell_service().await?;

        info!("Moving CAPI resources from target to kind cluster...");
        let bootstrap_kubeconfig = self.bootstrap_kubeconfig_path();
        move_to_kubeconfig(
            &self.kubeconfig,
            &bootstrap_kubeconfig,
            &self.capi_namespace,
            &self.cluster_name,
        )
        .await
        .cmd_err()?;

        info!("Patching kubeconfig for direct cluster access...");
        self.patch_kubeconfig_for_direct_access(&bootstrap_client)
            .await?;

        info!("Tearing down cluster...");
        teardown_cluster(
            &bootstrap_client,
            &self.capi_namespace,
            &self.cluster_name,
            &TeardownConfig::default(),
            Some(&bootstrap_kubeconfig),
        )
        .await
        .cmd_err()?;

        info!("Cluster '{}' successfully uninstalled", self.cluster_name);
        Ok(())
    }

    async fn install_capi_providers(&self) -> Result<()> {
        let kubeconfig = self.bootstrap_kubeconfig_path();
        let init_args = self.clusterctl_init_args();

        let mut cmd = Command::new("clusterctl");
        cmd.args(&init_args).env("KUBECONFIG", &kubeconfig);

        if self.provider == ProviderType::Aws {
            if let Ok(creds) = AwsCredentials::from_env() {
                cmd.env("AWS_B64ENCODED_CREDENTIALS", creds.to_b64_encoded());
            }
        }

        let output = cmd.output().await?;

        if !output.status.success() {
            return Err(Error::command_failed(format!(
                "clusterctl init failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    fn clusterctl_init_args(&self) -> Vec<String> {
        super::clusterctl_init_args(self.provider)
    }
}

pub async fn run(args: UninstallArgs) -> Result<()> {
    let uninstaller = Uninstaller::new(&args).await?;

    if !args.yes {
        println!(
            "This will permanently delete cluster '{}' and all its resources.",
            uninstaller.cluster_name()
        );
        println!("Provider: {}", uninstaller.provider());
        println!();
        print!("Are you sure? [y/N] ");

        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        tokio::io::stdout().flush().await?;

        let mut input = String::new();
        let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
        reader.read_line(&mut input).await?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted");
            return Ok(());
        }
    }

    uninstaller.run().await
}
