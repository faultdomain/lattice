//! Lattice Operator - Kubernetes multi-cluster lifecycle management
//!
//! This is the main entry point. It handles CLI parsing and starts subsystems.
//! All business logic lives in library modules.

use std::sync::Arc;

use clap::{Parser, Subcommand};
use kube::CustomResourceExt;

use lattice_operator::agent::start_agent_with_retry;
use lattice_operator::bootstrap::DefaultManifestGenerator;
use lattice_operator::crd::LatticeCluster;
use lattice_operator::parent::{ParentConfig, ParentServers};
use lattice_operator::startup::{
    ensure_crds_installed, ensure_infrastructure, get_cell_server_sans,
    re_register_existing_clusters, start_ca_rotation, wait_for_api_ready,
};

mod controller_runner;

#[derive(Parser, Debug)]
#[command(name = "lattice", version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    crd: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum ControllerMode {
    #[default]
    All,
    Cluster,
    Service,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Controller {
        #[arg(long, short, value_enum, default_value = "all")]
        mode: ControllerMode,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_crypto();
    init_tracing();

    let cli = Cli::parse();

    if cli.crd {
        println!(
            "{}",
            serde_json::to_string(&LatticeCluster::crd())
                .map_err(|e| anyhow::anyhow!("Failed to serialize CRD: {}", e))?
        );
        return Ok(());
    }

    match cli.command {
        Some(Commands::Controller { mode }) => run_controller(mode).await,
        None => run_controller(ControllerMode::All).await,
    }
}

fn init_crypto() {
    if let Err(e) = rustls::crypto::aws_lc_rs::default_provider().install_default() {
        eprintln!("CRITICAL: Failed to install crypto provider: {:?}", e);
        std::process::exit(1);
    }

    #[cfg(feature = "fips")]
    {
        if let Err(e) = aws_lc_rs::try_fips_mode() {
            eprintln!("CRITICAL: FIPS mode failed: {}", e);
            std::process::exit(1);
        }
        eprintln!("FIPS mode: ENABLED");
    }

    #[cfg(not(feature = "fips"))]
    eprintln!("WARNING: Running without FIPS mode");
}

fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();
}

async fn run_controller(mode: ControllerMode) -> anyhow::Result<()> {
    tracing::info!(?mode, "Starting...");

    // Create client with proper timeouts (5s connect, 30s read)
    let client = lattice_common::kube_utils::create_client(None).await?;

    // Install CRDs and infrastructure
    ensure_crds_installed(&client).await?;
    ensure_infrastructure(&client).await?;
    wait_for_api_ready(&client).await?;

    // Create cell servers
    let parent_config = ParentConfig::default();
    let parent_servers = Arc::new(ParentServers::new(parent_config, &client).await?);

    // Get cluster identity from environment
    let self_cluster_name = std::env::var("LATTICE_CLUSTER_NAME").ok();
    let is_bootstrap = lattice_common::is_bootstrap_cluster();

    // Start agent connection to parent (if we have one)
    let agent_token = tokio_util::sync::CancellationToken::new();
    if let Some(ref name) = self_cluster_name {
        let client = client.clone();
        let name = name.clone();
        let token = agent_token.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = token.cancelled() => {}
                _ = start_agent_with_retry(&client, &name) => {}
            }
        });
    }

    // Start cell servers with TLS SANs from LoadBalancer
    let extra_sans = get_cell_server_sans(&client, &self_cluster_name, is_bootstrap).await;
    parent_servers
        .ensure_running(DefaultManifestGenerator::new(), &extra_sans, client.clone())
        .await?;
    tracing::info!("Cell servers started");

    // Start CA rotation background task
    start_ca_rotation(parent_servers.clone());

    // Re-register clusters after restart (crash recovery)
    if let Some(state) = parent_servers.bootstrap_state().await {
        re_register_existing_clusters(&client, &state, &self_cluster_name, &parent_servers).await;
    }

    // Run controllers until shutdown
    controller_runner::run_controllers(client, mode, self_cluster_name, parent_servers.clone())
        .await;

    // Shutdown
    agent_token.cancel();
    parent_servers.shutdown().await;
    tracing::info!("Shutting down");
    Ok(())
}
