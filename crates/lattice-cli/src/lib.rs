//! Lattice CLI library
//!
//! This crate provides the CLI implementation for managing Lattice cluster
//! hierarchies. It works on a local git checkout - git operations (pull, commit, push)
//! are handled by the developer using standard git commands.

pub mod commands;
pub mod error;
pub mod git;
pub mod repo;

pub use error::{Error, Result};

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Lattice - Multi-cluster Kubernetes management via GitOps
#[derive(Parser, Debug)]
#[command(name = "lattice")]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Path to the lattice-clusters repository (defaults to current directory)
    #[arg(short, long, global = true, env = "LATTICE_REPO")]
    pub repo: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Install Lattice from a git repository
    Install(commands::install::InstallArgs),

    /// Manage clusters
    #[command(subcommand)]
    Cluster(commands::cluster::ClusterCommands),

    /// Manage service registrations
    #[command(subcommand)]
    Service(commands::service::ServiceCommands),

    /// Manage service placements
    #[command(subcommand)]
    Placement(commands::placement::PlacementCommands),

    /// Manage Flux configuration
    #[command(subcommand)]
    Flux(commands::flux::FluxCommands),

    /// Validate repository structure
    Validate(commands::validate::ValidateArgs),
}

impl Cli {
    /// Run the CLI command
    pub async fn run(self) -> Result<()> {
        let repo_path = self.repo.unwrap_or_else(|| PathBuf::from("."));

        match self.command {
            Commands::Install(args) => commands::install::run(args).await,
            Commands::Cluster(cmd) => commands::cluster::run(cmd, &repo_path).await,
            Commands::Service(cmd) => commands::service::run(cmd, &repo_path).await,
            Commands::Placement(cmd) => commands::placement::run(cmd, &repo_path).await,
            Commands::Flux(cmd) => commands::flux::run(cmd, &repo_path).await,
            Commands::Validate(args) => commands::validate::run(args, &repo_path).await,
        }
    }
}
