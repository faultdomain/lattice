//! Lattice Operator - Kubernetes multi-cluster lifecycle management

use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use futures::StreamExt;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Api, Client, CustomResourceExt};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use lattice::agent::client::{AgentClient, AgentClientConfig};
use lattice::cell::{CellConfig, CellServers};
use lattice::controller::{
    error_policy, error_policy_external, reconcile, reconcile_external, service_error_policy,
    service_reconcile, Context, ServiceContext,
};
use lattice::crd::{LatticeCluster, LatticeExternalService, LatticeService};
use lattice::infra::IstioReconciler;
use lattice::install::{InstallConfig, Installer};

/// Lattice - CRD-driven Kubernetes operator for multi-cluster lifecycle management
#[derive(Parser, Debug)]
#[command(name = "lattice", version, about, long_about = None)]
struct Cli {
    /// Generate CRD manifests and exit
    #[arg(long)]
    crd: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run as controller (default mode)
    ///
    /// Every Lattice instance runs as a controller that:
    /// - Watches LatticeCluster CRDs and reconciles them
    /// - If this cluster has a cellRef (parent), also connects as an agent
    /// - If this cluster has a cell spec, starts cell servers for child clusters
    ///
    /// This unified mode means every cluster is self-managing.
    Controller,

    /// Install Lattice - bootstrap a new management cluster
    ///
    /// Creates a temporary kind cluster, provisions the management cluster,
    /// pivots CAPI resources, and deletes the bootstrap cluster.
    Install(InstallArgs),
}

/// Install mode arguments
#[derive(Parser, Debug)]
struct InstallArgs {
    /// Path to the LatticeCluster YAML configuration file
    ///
    /// This file defines the management cluster spec and is applied as-is.
    /// The same file is used for both provisioning and the self-referential
    /// CRD on the management cluster, making it GitOps-friendly.
    #[arg(short = 'f', long = "config")]
    config_file: std::path::PathBuf,

    /// Lattice container image
    #[arg(
        long,
        env = "LATTICE_IMAGE",
        default_value = "ghcr.io/evan-hines-js/lattice:latest"
    )]
    image: String,

    /// Path to registry credentials file (dockerconfigjson format)
    #[arg(long, env = "REGISTRY_CREDENTIALS_FILE")]
    registry_credentials_file: Option<std::path::PathBuf>,

    /// Skip kind cluster deletion on failure (for debugging)
    #[arg(long)]
    keep_bootstrap_on_failure: bool,

    /// Timeout for the entire installation in seconds
    #[arg(long, default_value = "1200")]
    timeout_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install crypto provider - FIPS-validated aws-lc-rs
    // This MUST succeed for the application to operate securely.
    // Failure here indicates a serious system configuration issue.
    if let Err(e) = rustls::crypto::aws_lc_rs::default_provider().install_default() {
        eprintln!(
            "CRITICAL: Failed to install FIPS-validated crypto provider: {:?}. \
             The application cannot operate securely without a working TLS implementation. \
             This may indicate aws-lc-rs was not compiled correctly or there is a \
             conflict with another crypto provider.",
            e
        );
        std::process::exit(1);
    }

    // Initialize tracing
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    if cli.crd {
        // Generate CRD YAML
        let crd = serde_yaml::to_string(&LatticeCluster::crd())
            .map_err(|e| anyhow::anyhow!("Failed to serialize CRD: {}", e))?;
        println!("{crd}");
        return Ok(());
    }

    match cli.command {
        Some(Commands::Install(args)) => run_install(args).await,
        Some(Commands::Controller) | None => run_controller().await,
    }
}

/// Run the installer - bootstrap a new management cluster
async fn run_install(args: InstallArgs) -> anyhow::Result<()> {
    // Read and validate the cluster config file
    let config_content = tokio::fs::read_to_string(&args.config_file)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read config file {:?}: {}", args.config_file, e))?;

    // Parse the YAML to validate it's a valid LatticeCluster
    let cluster: LatticeCluster = serde_yaml::from_str(&config_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse LatticeCluster config: {}", e))?;

    let cluster_name = cluster
        .metadata
        .name
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("LatticeCluster must have metadata.name"))?;

    let provider = &cluster.spec.provider.type_;

    println!("=== Lattice Installer ===");
    println!("Config file: {:?}", args.config_file);
    println!("Management cluster: {}", cluster_name);
    println!("Provider: {}", provider);
    println!(
        "Kubernetes version: {}",
        cluster.spec.provider.kubernetes.version
    );
    println!();

    // Read registry credentials if provided
    let registry_credentials = if let Some(creds_path) = &args.registry_credentials_file {
        Some(
            tokio::fs::read_to_string(creds_path)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to read registry credentials: {}", e))?,
        )
    } else {
        None
    };

    let config = InstallConfig {
        cluster_config_path: args.config_file,
        cluster_config_content: config_content,
        image: args.image,
        keep_bootstrap_on_failure: args.keep_bootstrap_on_failure,
        timeout: Duration::from_secs(args.timeout_secs),
        registry_credentials,
    };

    let installer = Installer::new(config).map_err(|e| anyhow::anyhow!("{}", e))?;
    installer.run().await.map_err(|e| anyhow::anyhow!("{}", e))
}

/// Ensure all Lattice CRDs are installed
///
/// The operator installs its own CRDs on startup using server-side apply.
/// This ensures the CRD versions always match the operator version.
async fn ensure_crds_installed(client: &Client) -> anyhow::Result<()> {
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::api::{Patch, PatchParams};

    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    let params = PatchParams::apply("lattice-controller").force();

    // Install LatticeCluster CRD
    tracing::info!("Installing LatticeCluster CRD...");
    crds.patch(
        "latticeclusters.lattice.dev",
        &params,
        &Patch::Apply(&LatticeCluster::crd()),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to install LatticeCluster CRD: {}", e))?;

    // Install LatticeService CRD
    tracing::info!("Installing LatticeService CRD...");
    crds.patch(
        "latticeservices.lattice.dev",
        &params,
        &Patch::Apply(&LatticeService::crd()),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to install LatticeService CRD: {}", e))?;

    // Install LatticeExternalService CRD
    tracing::info!("Installing LatticeExternalService CRD...");
    crds.patch(
        "latticeexternalservices.lattice.dev",
        &params,
        &Patch::Apply(&LatticeExternalService::crd()),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to install LatticeExternalService CRD: {}", e))?;

    tracing::info!("All Lattice CRDs installed/updated");
    Ok(())
}

/// Reconcile infrastructure components
///
/// Ensures Istio is installed at the correct version. Cilium is deployed at bootstrap.
/// This runs on every controller startup, enabling version upgrades when
/// Lattice is upgraded (new binary has new component versions).
async fn ensure_infrastructure(client: &Client) -> anyhow::Result<()> {
    use k8s_openapi::api::apps::v1::Deployment;
    use kube::api::{Api, Patch, PatchParams};

    let reconciler = IstioReconciler::new();
    let expected_version = reconciler.version();

    // Check current Istio version
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), "istio-system");
    let current_version = match deployments.get("istiod").await {
        Ok(deploy) => {
            // Extract version from image tag (e.g., "docker.io/istio/pilot:1.24.2")
            deploy
                .spec
                .and_then(|s| s.template.spec)
                .and_then(|s| s.containers.into_iter().next())
                .and_then(|c| c.image)
                .and_then(|img| img.split(':').next_back().map(String::from))
        }
        Err(_) => None,
    };

    // Decide action based on current state
    match current_version {
        Some(ref v) if v == expected_version => {
            tracing::debug!(version = %v, "Istio at expected version, skipping");
            return Ok(());
        }
        Some(ref v) => {
            tracing::info!(from = %v, to = %expected_version, "Upgrading Istio");
        }
        None => {
            tracing::info!(version = %expected_version, "Installing Istio");
        }
    }

    // Get manifests and apply them
    let manifests = reconciler
        .manifests()
        .map_err(|e| anyhow::anyhow!("Failed to generate Istio manifests: {}", e))?;

    tracing::info!(count = manifests.len(), "Applying Istio manifests");

    // Ensure istio-system namespace exists
    let namespaces: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());
    let ns = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": { "name": "istio-system" }
    });
    let params = PatchParams::apply("lattice").force();
    namespaces
        .patch("istio-system", &params, &Patch::Apply(&ns))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create istio-system namespace: {}", e))?;

    // Apply manifests (server-side apply handles create or update)
    for manifest in manifests {
        apply_manifest(client, manifest).await?;
    }

    // Apply PeerAuthentication for STRICT mTLS
    let peer_auth = IstioReconciler::generate_peer_authentication();
    apply_manifest(client, &peer_auth).await?;

    tracing::info!(version = %expected_version, "Istio reconciliation complete");
    Ok(())
}

/// Apply a single YAML manifest to the cluster
async fn apply_manifest(client: &Client, manifest: &str) -> anyhow::Result<()> {
    use kube::api::{Api, DynamicObject, Patch, PatchParams};
    use kube::discovery::ApiResource;

    let obj: serde_json::Value =
        serde_yaml::from_str(manifest).map_err(|e| anyhow::anyhow!("Invalid YAML: {}", e))?;

    let kind = obj
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing kind"))?;
    let api_version = obj
        .get("apiVersion")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing apiVersion"))?;
    let name = obj
        .pointer("/metadata/name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing metadata.name"))?;
    let namespace = obj.pointer("/metadata/namespace").and_then(|v| v.as_str());

    // Parse apiVersion into group/version
    let (group, version) = if api_version.contains('/') {
        let parts: Vec<&str> = api_version.splitn(2, '/').collect();
        (parts[0].to_string(), parts[1].to_string())
    } else {
        (String::new(), api_version.to_string())
    };

    let gvk = kube::api::GroupVersionKind {
        group,
        version,
        kind: kind.to_string(),
    };
    let api_resource = ApiResource::from_gvk(&gvk);

    let api: Api<DynamicObject> = match namespace {
        Some(ns) => Api::namespaced_with(client.clone(), ns, &api_resource),
        None => Api::all_with(client.clone(), &api_resource),
    };

    let params = PatchParams::apply("lattice").force();
    api.patch(name, &params, &Patch::Apply(&obj))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to apply {}/{}: {}", kind, name, e))?;

    tracing::debug!(kind = kind, name = name, "Applied manifest");
    Ok(())
}

/// Run in controller mode - manages clusters
///
/// Cell servers (gRPC + bootstrap HTTP) start automatically when needed.
/// Cell endpoint configuration is read from the local LatticeCluster CRD's spec.cell.
///
/// If this cluster has a cellRef (parent), the controller also connects as an agent
/// to the parent cell for pivot coordination and health reporting.
async fn run_controller() -> anyhow::Result<()> {
    tracing::info!("Lattice controller starting...");

    // Create Kubernetes client
    let client = Client::try_default()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create Kubernetes client: {}", e))?;

    // Operator installs its own CRDs on startup
    ensure_crds_installed(&client).await?;

    // Ensure infrastructure components are installed (Istio)
    // This enables day-2 upgrades: new Lattice version has new component versions
    if let Err(e) = ensure_infrastructure(&client).await {
        tracing::warn!(error = %e, "Failed to install infrastructure, continuing anyway");
        // Don't fail startup - controllers can still run, services just won't have mesh
    }

    // Create cell servers (starts on-demand when Pending CRDs detected)
    let cell_servers = Arc::new(
        CellServers::new(CellConfig::default())
            .map_err(|e| anyhow::anyhow!("Failed to create cell servers: {}", e))?,
    );

    // Create controller context with cell servers
    // Cell endpoint config is read from CRD spec.cell during reconciliation
    // LATTICE_CLUSTER_NAME tells the controller which cluster it's running on (to avoid self-provisioning)
    let self_cluster_name = std::env::var("LATTICE_CLUSTER_NAME").ok();
    let mut ctx_builder = Context::builder(client.clone()).cell_servers(cell_servers.clone());
    if let Some(ref name) = self_cluster_name {
        tracing::info!(cluster = %name, "Running as self-managed cluster");
        ctx_builder = ctx_builder.self_cluster_name(name.clone());
    }
    let ctx = Arc::new(ctx_builder.build());

    // Check if we need to connect as an agent to a parent cell
    // This happens when the cluster has a cellRef (was provisioned by a parent)
    let agent_handle = if let Some(ref cluster_name) = self_cluster_name {
        match start_agent_if_needed(&client, cluster_name).await {
            Ok(Some(handle)) => {
                tracing::info!("Agent connection to parent cell started");
                Some(handle)
            }
            Ok(None) => {
                tracing::debug!("No parent cell configured, running as standalone");
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to start agent connection, continuing without");
                None
            }
        }
    } else {
        None
    };

    // Create APIs for all CRDs (cluster-scoped)
    let clusters: Api<LatticeCluster> = Api::all(client.clone());
    let services: Api<LatticeService> = Api::all(client.clone());
    let external_services: Api<LatticeExternalService> = Api::all(client.clone());

    // Create service context for service controllers
    let service_ctx = Arc::new(ServiceContext::from_client(client, "cluster.local"));

    tracing::info!("Starting Lattice controllers...");
    tracing::info!("  - LatticeCluster controller");
    tracing::info!("  - LatticeService controller");
    tracing::info!("  - LatticeExternalService controller");

    // Create all controllers
    let cluster_controller = Controller::new(clusters, WatcherConfig::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx.clone())
        .for_each(|result| async move {
            match result {
                Ok(action) => {
                    tracing::debug!(?action, "Cluster reconciliation completed");
                }
                Err(e) => {
                    tracing::error!(error = ?e, "Cluster reconciliation error");
                }
            }
        });

    let service_controller = Controller::new(services, WatcherConfig::default())
        .shutdown_on_signal()
        .run(service_reconcile, service_error_policy, service_ctx.clone())
        .for_each(|result| async move {
            match result {
                Ok(action) => {
                    tracing::debug!(?action, "Service reconciliation completed");
                }
                Err(e) => {
                    tracing::error!(error = ?e, "Service reconciliation error");
                }
            }
        });

    let external_service_controller = Controller::new(external_services, WatcherConfig::default())
        .shutdown_on_signal()
        .run(
            reconcile_external,
            error_policy_external,
            service_ctx.clone(),
        )
        .for_each(|result| async move {
            match result {
                Ok(action) => {
                    tracing::debug!(?action, "External service reconciliation completed");
                }
                Err(e) => {
                    tracing::error!(error = ?e, "External service reconciliation error");
                }
            }
        });

    // Run all controllers concurrently
    tokio::select! {
        _ = cluster_controller => {
            tracing::info!("Cluster controller completed");
        }
        _ = service_controller => {
            tracing::info!("Service controller completed");
        }
        _ = external_service_controller => {
            tracing::info!("External service controller completed");
        }
    }

    // Shutdown agent if running
    if let Some(mut agent) = agent_handle {
        agent.shutdown().await;
    }

    // Shutdown cell servers
    cell_servers.shutdown().await;

    tracing::info!("Lattice controller shutting down");
    Ok(())
}

/// Check if this cluster has a parent cell and start agent connection if so
///
/// Returns Ok(Some(client)) if agent started, Ok(None) if no parent, Err on failure
async fn start_agent_if_needed(
    client: &Client,
    cluster_name: &str,
) -> anyhow::Result<Option<AgentClient>> {
    use k8s_openapi::api::core::v1::Secret;
    use kube::api::Api;

    // Read our own LatticeCluster CRD to check for cellRef
    let clusters: Api<LatticeCluster> = Api::all(client.clone());
    let cluster = match clusters.get(cluster_name).await {
        Ok(c) => c,
        Err(kube::Error::Api(e)) if e.code == 404 => {
            tracing::debug!("LatticeCluster CRD not found yet, skipping agent");
            return Ok(None);
        }
        Err(e) => return Err(anyhow::anyhow!("Failed to get LatticeCluster: {}", e)),
    };

    // Check if we have a parent (cellRef)
    if cluster.spec.cell_ref.is_none() {
        tracing::debug!("No cellRef, this is a root cluster");
        return Ok(None);
    }

    tracing::info!(
        cell_ref = ?cluster.spec.cell_ref,
        "Cluster has parent cell, starting agent connection"
    );

    // Read parent connection config from secret
    let secrets: Api<Secret> = Api::namespaced(client.clone(), "lattice-system");
    let parent_config = secrets
        .get("lattice-parent-config")
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get parent config secret: {}", e))?;

    let data = parent_config
        .data
        .ok_or_else(|| anyhow::anyhow!("Parent config secret has no data"))?;

    // Parse cell endpoint (format: "host:http_port:grpc_port")
    let cell_endpoint = data
        .get("cell_endpoint")
        .ok_or_else(|| anyhow::anyhow!("Missing cell_endpoint in parent config"))?;
    let cell_endpoint = String::from_utf8(cell_endpoint.0.clone())
        .map_err(|e| anyhow::anyhow!("Invalid cell_endpoint encoding: {}", e))?;

    let ca_cert = data
        .get("ca.crt")
        .ok_or_else(|| anyhow::anyhow!("Missing ca.crt in parent config"))?;
    let ca_cert_pem = String::from_utf8(ca_cert.0.clone())
        .map_err(|e| anyhow::anyhow!("Invalid CA cert encoding: {}", e))?;

    // Parse endpoint parts
    let parts: Vec<&str> = cell_endpoint.split(':').collect();
    if parts.len() != 3 {
        return Err(anyhow::anyhow!(
            "Invalid cell_endpoint format, expected host:http_port:grpc_port"
        ));
    }
    let host = parts[0];
    let http_port: u16 = parts[1]
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid HTTP port: {}", e))?;
    let grpc_port: u16 = parts[2]
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid gRPC port: {}", e))?;

    let http_endpoint = format!("https://{}:{}", host, http_port);
    let grpc_endpoint = format!("https://{}:{}", host, grpc_port);

    tracing::info!(
        http_endpoint = %http_endpoint,
        grpc_endpoint = %grpc_endpoint,
        "Connecting to parent cell"
    );

    // Request certificate from cell
    let credentials = AgentClient::request_certificate(&http_endpoint, cluster_name, &ca_cert_pem)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get certificate: {}", e))?;

    // Create agent client config
    let config = AgentClientConfig {
        cluster_name: cluster_name.to_string(),
        cell_grpc_endpoint: grpc_endpoint,
        cell_http_endpoint: http_endpoint,
        ca_cert_pem: Some(ca_cert_pem),
        heartbeat_interval: Duration::from_secs(30),
        ..Default::default()
    };

    // Create and connect agent
    let mut agent = AgentClient::new(config);
    agent
        .connect_with_mtls(&credentials)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to cell: {}", e))?;

    tracing::info!("Agent connected to parent cell");
    Ok(Some(agent))
}
