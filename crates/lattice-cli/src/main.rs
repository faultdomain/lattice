//! Lattice CLI
//!
//! CLI for managing Lattice cluster hierarchies via GitOps.

use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use lattice_cli::{Cli, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Panics on failure — FIPS mode is mandatory
    lattice_common::fips::install_crypto_provider();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    let cli = Cli::parse();
    cli.run().await
}
