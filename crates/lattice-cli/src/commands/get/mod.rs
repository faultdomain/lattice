//! Get command — query Lattice resources across cluster contexts.
//!
//! All `lattice get` commands discover clusters from kubeconfig contexts,
//! connect to each, and build a unified view of the cluster tree.
//!
//! Kubeconfig is resolved via the standard chain: `--kubeconfig` flag >
//! `LATTICE_KUBECONFIG` env > `~/.lattice/kubeconfig` > kube defaults.

mod cluster;
mod clusters;
mod format;
mod health;
mod hierarchy;
pub(crate) mod tree;

use clap::{Args, Subcommand, ValueEnum};

use crate::Result;

/// Get Lattice resources
#[derive(Args, Debug)]
pub struct GetArgs {
    #[command(subcommand)]
    pub resource: GetResource,

    /// Output format
    #[arg(short, long, default_value = "table", global = true)]
    pub output: OutputFormat,

    /// Path to kubeconfig file (overrides resolution chain)
    #[arg(long, global = true)]
    pub kubeconfig: Option<String>,
}

/// Resource to get
#[derive(Subcommand, Debug)]
pub enum GetResource {
    /// List all clusters discovered from kubeconfig contexts
    Clusters,
    /// Show detailed info for a single cluster
    Cluster {
        /// Cluster name (must match a LatticeCluster CRD name)
        name: String,
    },
    /// Show ASCII tree visualization of the cluster hierarchy
    Hierarchy,
    /// Show fleet health overview with node status and heartbeat info
    Health,
}

/// Output format
#[derive(Clone, Debug, Default, ValueEnum)]
pub enum OutputFormat {
    /// Columnar table (default)
    #[default]
    Table,
    /// JSON
    Json,
}

/// Run the get command.
pub async fn run(args: GetArgs) -> Result<()> {
    let kc = args.kubeconfig.as_deref();

    match args.resource {
        GetResource::Clusters => clusters::run(kc, &args.output).await,
        GetResource::Cluster { name } => cluster::run(kc, &name, &args.output).await,
        GetResource::Hierarchy => hierarchy::run(kc, &args.output).await,
        GetResource::Health => health::run(kc, &args.output).await,
    }
}
