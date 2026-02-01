//! Lattice Operator - Kubernetes multi-cluster lifecycle management
//!
//! This is the main entry point. It handles CLI parsing and starts subsystems.
//! All business logic lives in library modules.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use kube::CustomResourceExt;

use lattice_api::{AuthChain, PolicyEngine, SaValidator, ServerConfig as AuthProxyConfig};
use lattice_common::{lattice_svc_dns, CELL_SERVICE_NAME, DEFAULT_AUTH_PROXY_PORT};
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
                .map_err(|e| anyhow::anyhow!("failed to serialize CRD: {}", e))?
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

    // Start auth proxy server (for authenticated access with Cedar authorization)
    let auth_proxy_handle =
        start_auth_proxy(&client, parent_servers.clone(), &self_cluster_name).await;

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
    if let Some(handle) = auth_proxy_handle {
        handle.abort();
    }
    parent_servers.shutdown().await;
    tracing::info!("Shutting down");
    Ok(())
}

/// Start the auth proxy server for authenticated cluster access
///
/// The auth proxy provides:
/// - ServiceAccount token authentication (via TokenReview API)
/// - Cedar policy authorization
/// - Routing to local or child cluster K8s APIs
async fn start_auth_proxy(
    client: &kube::Client,
    parent_servers: Arc<ParentServers<DefaultManifestGenerator>>,
    cluster_name: &Option<String>,
) -> Option<tokio::task::JoinHandle<()>> {
    // Get cluster name (default to "unknown")
    let cluster_name = cluster_name
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

    // Create SA validator for ServiceAccount token authentication
    let sa_validator = Arc::new(SaValidator::new(client.clone()));

    // Create auth chain (SA auth only for now, OIDC can be added later)
    let auth_chain = Arc::new(AuthChain::sa_only(sa_validator));

    // Create Cedar policy engine (loads policies from CRDs)
    let cedar = match PolicyEngine::from_crds(client).await {
        Ok(engine) => Arc::new(engine),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to load Cedar policies, using default-deny");
            Arc::new(PolicyEngine::new())
        }
    };

    // Generate server certificate
    let ca_bundle = parent_servers.ca_bundle().read().await;
    let cell_dns = lattice_svc_dns(CELL_SERVICE_NAME);
    let sans = vec!["localhost", "127.0.0.1", &cell_dns];
    let (cert_pem, key_pem) = match ca_bundle.generate_server_cert(&sans) {
        Ok((cert, key)) => (cert, key),
        Err(e) => {
            tracing::error!(error = %e, "Failed to generate auth proxy certificate");
            return None;
        }
    };
    drop(ca_bundle);

    // Create server config
    let addr: SocketAddr = match format!("0.0.0.0:{}", DEFAULT_AUTH_PROXY_PORT).parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "Failed to parse auth proxy address");
            return None;
        }
    };

    let base_url = format!(
        "https://{}:{}",
        lattice_svc_dns(CELL_SERVICE_NAME),
        DEFAULT_AUTH_PROXY_PORT
    );

    let config = AuthProxyConfig {
        addr,
        cert_pem,
        key_pem,
        k8s_api_url: "https://kubernetes.default.svc".to_string(),
        cluster_name: cluster_name.clone(),
        base_url,
    };

    // Get shared registries from parent servers
    let subtree = parent_servers.subtree_registry();
    let agent_registry = Some(parent_servers.agent_registry());

    tracing::info!(addr = %addr, cluster = %cluster_name, "Starting auth proxy server");

    // Start in background task
    let handle = tokio::spawn(async move {
        if let Err(e) = lattice_api::start_server_with_registry(
            config,
            auth_chain,
            cedar,
            subtree,
            agent_registry,
        )
        .await
        {
            tracing::error!(error = %e, "Auth proxy server error");
        }
    });

    Some(handle)
}
