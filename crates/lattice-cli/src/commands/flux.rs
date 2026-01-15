//! Flux configuration commands

use clap::{Args, Subcommand};
use std::path::Path;

use crate::repo::LatticeRepo;
use crate::Result;

#[derive(Subcommand, Debug)]
pub enum FluxCommands {
    /// Set Flux version (globally or for a specific cluster)
    SetVersion(SetVersionArgs),

    /// Suspend Flux on a cluster
    Suspend(SuspendArgs),

    /// Resume Flux on a cluster
    Resume(ResumeArgs),
}

#[derive(Args, Debug)]
pub struct SetVersionArgs {
    /// Flux version
    pub version: String,

    /// Apply to specific cluster (otherwise applies globally)
    #[arg(long)]
    pub cluster: Option<String>,
}

#[derive(Args, Debug)]
pub struct SuspendArgs {
    /// Cluster name
    pub cluster: String,
}

#[derive(Args, Debug)]
pub struct ResumeArgs {
    /// Cluster name
    pub cluster: String,
}

pub async fn run(cmd: FluxCommands, repo_path: &Path) -> Result<()> {
    match cmd {
        FluxCommands::SetVersion(args) => {
            set_version(repo_path, &args.version, args.cluster.as_deref())
        }
        FluxCommands::Suspend(args) => set_suspend(repo_path, &args.cluster, true),
        FluxCommands::Resume(args) => set_suspend(repo_path, &args.cluster, false),
    }
}

fn set_version(repo_path: &Path, version: &str, cluster: Option<&str>) -> Result<()> {
    if let Some(cluster_name) = cluster {
        // Set version for specific cluster
        let repo = LatticeRepo::open(repo_path)?;
        let cluster = repo.get_cluster(cluster_name)?;

        let content = std::fs::read_to_string(&cluster.path)?;
        let mut value: serde_yaml::Value = serde_yaml::from_str(&content)?;

        // Add or update flux section
        let spec = value
            .get_mut("spec")
            .ok_or_else(|| crate::Error::validation("missing spec"))?;

        if spec.get("flux").is_none() {
            spec["flux"] = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        }

        spec["flux"]["version"] = serde_yaml::Value::String(version.to_string());

        let output = serde_yaml::to_string(&value)?;
        std::fs::write(&cluster.path, output)?;

        println!("Updated {}", cluster.path.display());
    } else {
        // Set global version in .lattice/config.yaml
        let config_path = repo_path.join(".lattice/config.yaml");

        let content = if config_path.exists() {
            std::fs::read_to_string(&config_path)?
        } else {
            std::fs::create_dir_all(repo_path.join(".lattice"))?;
            r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeRepoConfig
metadata:
  name: config
spec: {}
"#
            .to_string()
        };

        let mut value: serde_yaml::Value = serde_yaml::from_str(&content)?;

        let spec = value
            .get_mut("spec")
            .ok_or_else(|| crate::Error::validation("missing spec"))?;

        if spec.get("flux").is_none() {
            spec["flux"] = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        }

        spec["flux"]["version"] = serde_yaml::Value::String(version.to_string());

        let output = serde_yaml::to_string(&value)?;
        std::fs::write(&config_path, output)?;

        println!("Updated {}", config_path.display());
    }

    Ok(())
}

fn set_suspend(repo_path: &Path, cluster_name: &str, suspend: bool) -> Result<()> {
    let repo = LatticeRepo::open(repo_path)?;
    let cluster = repo.get_cluster(cluster_name)?;

    let content = std::fs::read_to_string(&cluster.path)?;
    let mut value: serde_yaml::Value = serde_yaml::from_str(&content)?;

    let spec = value
        .get_mut("spec")
        .ok_or_else(|| crate::Error::validation("missing spec"))?;

    if spec.get("flux").is_none() {
        spec["flux"] = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }

    spec["flux"]["suspend"] = serde_yaml::Value::Bool(suspend);

    let output = serde_yaml::to_string(&value)?;
    std::fs::write(&cluster.path, output)?;

    println!("Updated {}", cluster.path.display());
    println!(
        "Flux is now {} for cluster {}",
        if suspend { "suspended" } else { "resumed" },
        cluster_name
    );

    Ok(())
}
