//! Lattice CLI library

pub mod commands;
pub mod config;
pub mod error;

pub use error::{Error, Result};

use clap::{Parser, Subcommand};

/// Lattice - Multi-cluster Kubernetes management
#[derive(Parser, Debug)]
#[command(name = "lattice")]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Authenticate and save a proxy kubeconfig for all future commands
    Login(commands::login::LoginArgs),
    /// Switch the default cluster context
    Use(commands::use_cluster::UseArgs),
    /// Install a self-managing Lattice cluster from a LatticeCluster CRD
    Install(commands::install::InstallArgs),
    /// Uninstall a self-managing Lattice cluster (reverse pivot and destroy)
    Uninstall(commands::uninstall::UninstallArgs),
    /// Get a ServiceAccount token (exec credential plugin for kubeconfig)
    Token(commands::token::TokenArgs),
    /// Get Lattice resources (clusters, services, hierarchy)
    Get(commands::get::GetArgs),
    /// Clear saved credentials and proxy kubeconfig
    Logout(commands::logout::LogoutArgs),
}

impl Cli {
    /// Run the CLI command
    pub async fn run(self) -> Result<()> {
        match self.command {
            Commands::Login(args) => commands::login::run(args).await,
            Commands::Use(args) => commands::use_cluster::run(args).await,
            Commands::Install(args) => commands::install::run(args).await,
            Commands::Uninstall(args) => commands::uninstall::run(args).await,
            Commands::Token(args) => commands::token::run(args).await,
            Commands::Get(args) => commands::get::run(args).await,
            Commands::Logout(args) => commands::logout::run(args).await,
        }
    }
}
