//! Lattice DaemonSet — per-node monitoring binary.
//!
//! Analogous to `lattice-operator/src/main.rs`, this is the DaemonSet
//! entrypoint that hosts vertical monitoring slices (GPU health, etc.).
//!
//! # Architecture
//!
//! Each `SliceMode` runs a subset of monitoring slices. Future slices
//! (network health, disk pressure) plug in here the same way.

use std::net::SocketAddr;

use axum::routing::get;
use axum::Router;
use clap::{Parser, Subcommand};
use tracing::info;

use lattice_common::telemetry::{init_telemetry, TelemetryConfig};
use lattice_common::DEFAULT_HEALTH_PORT;

mod slice_runner;

#[derive(Parser, Debug)]
#[command(name = "lattice-daemonset", version, about = "Lattice DaemonSet node monitor")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Monitoring slice modes.
///
/// Each mode runs a specific subset of monitoring slices:
/// - `All`: All monitoring slices (default)
/// - `Gpu`: GPU health monitoring only
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum SliceMode {
    /// Run all monitoring slices
    #[default]
    All,
    /// Run GPU health monitoring only
    Gpu,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Monitor {
        #[arg(long, short, value_enum, default_value = "all")]
        mode: SliceMode,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_crypto();
    init_telemetry_global();

    let cli = Cli::parse();

    let client = lattice_common::kube_utils::create_client(None, None, None).await?;

    let node_name = std::env::var("NODE_NAME").map_err(|_| {
        anyhow::anyhow!(
            "NODE_NAME env var not set. Set via Kubernetes Downward API: \
             env.valueFrom.fieldRef.fieldPath=spec.nodeName"
        )
    })?;

    info!(node = %node_name, "starting lattice-daemonset");

    let health_handle = start_health_server();

    let mode = match cli.command {
        Some(Commands::Monitor { mode }) => mode,
        None => SliceMode::All,
    };

    let result = match mode {
        SliceMode::Gpu => slice_runner::run_gpu_slice(&client, &node_name).await,
        SliceMode::All => slice_runner::run_all_slices(&client, &node_name).await,
    };

    health_handle.abort();
    result
}

fn init_crypto() {
    lattice_common::fips::install_crypto_provider();
    eprintln!("FIPS mode: ENABLED");
}

fn init_telemetry_global() {
    let config = TelemetryConfig {
        service_name: "lattice-daemonset".to_string(),
        ..Default::default()
    };

    match init_telemetry(config) {
        Ok(()) => {
            tracing::info!("Telemetry initialized");
        }
        Err(e) => {
            eprintln!("WARNING: Failed to initialize telemetry: {}", e);
            use tracing_subscriber::{fmt, prelude::*, EnvFilter};
            let _ = tracing_subscriber::registry()
                .with(fmt::layer())
                .with(EnvFilter::from_default_env())
                .try_init();
        }
    }
}

fn start_health_server() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let app = Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route("/readyz", get(|| async { "ok" }));

        let addr: SocketAddr = ([0, 0, 0, 0], DEFAULT_HEALTH_PORT).into();

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => {
                tracing::info!(port = DEFAULT_HEALTH_PORT, "Health server started");
                l
            }
            Err(e) => {
                tracing::error!(error = %e, port = DEFAULT_HEALTH_PORT, "Failed to bind health server port");
                return;
            }
        };

        if let Err(e) = axum::serve(listener, app.into_make_service()).await {
            tracing::error!(error = %e, "Health server error");
        }
    })
}
