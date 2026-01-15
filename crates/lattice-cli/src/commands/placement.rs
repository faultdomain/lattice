//! Placement commands

use clap::{Args, Subcommand};
use std::path::Path;

use crate::repo::LatticeRepo;
use crate::Result;

#[derive(Subcommand, Debug)]
pub enum PlacementCommands {
    /// List placements for a cluster
    List(ListArgs),
    /// Create a new placement
    Create(CreateArgs),
    /// Scale a placement
    Scale(ScaleArgs),
    /// Delete a placement
    Delete(DeleteArgs),
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Cluster name
    #[arg(long)]
    pub cluster: String,
}

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Service name (must match a registration)
    pub name: String,
    /// Target cluster
    #[arg(long)]
    pub cluster: String,
    /// Git tag to use (instead of branch from registration)
    #[arg(long)]
    pub tag: Option<String>,
    /// Number of replicas
    #[arg(long)]
    pub replicas: Option<i32>,
    /// Environment variables (key=value)
    #[arg(long)]
    pub env: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ScaleArgs {
    /// Service name
    pub name: String,
    /// Target cluster
    #[arg(long)]
    pub cluster: String,
    /// Number of replicas
    #[arg(long)]
    pub replicas: i32,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// Service name
    pub name: String,
    /// Target cluster
    #[arg(long)]
    pub cluster: String,
}

pub async fn run(cmd: PlacementCommands, repo_path: &Path) -> Result<()> {
    match cmd {
        PlacementCommands::List(args) => list_placements(repo_path, &args.cluster),
        PlacementCommands::Create(args) => create_placement(repo_path, args),
        PlacementCommands::Scale(args) => {
            scale_placement(repo_path, &args.name, &args.cluster, args.replicas)
        }
        PlacementCommands::Delete(args) => delete_placement(repo_path, &args.name, &args.cluster),
    }
}

fn list_placements(repo_path: &Path, cluster_name: &str) -> Result<()> {
    let repo = LatticeRepo::open(repo_path)?;
    let placements = repo.list_placements(cluster_name)?;

    println!("{:<20} {:<20} {:<10}", "SERVICE", "REF", "REPLICAS");
    for p in placements {
        println!(
            "{:<20} {:<20} {:<10}",
            p.name,
            p.service_ref,
            p.replicas.map_or("-".into(), |r| r.to_string())
        );
    }

    Ok(())
}

fn create_placement(repo_path: &Path, args: CreateArgs) -> Result<()> {
    let repo = LatticeRepo::open(repo_path)?;
    let cluster = repo.get_cluster(&args.cluster)?;

    let placements_dir = cluster.path.parent().unwrap().join("placements");
    std::fs::create_dir_all(&placements_dir)?;

    // Build YAML sections
    let source_override = args.tag.as_ref().map_or(String::new(), |tag| {
        format!("  sourceOverride:\n    tag: {tag}\n")
    });

    let overrides = build_overrides(&args);

    let placement_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeServicePlacement
metadata:
  name: {name}
spec:
  serviceRef: {name}
{source_override}{overrides}"#,
        name = args.name
    );

    let path = placements_dir.join(format!("{}.yaml", args.name));
    std::fs::write(&path, &placement_yaml)?;

    add_to_kustomization(
        &placements_dir.join("kustomization.yaml"),
        &format!("{}.yaml", args.name),
    )?;

    println!(
        "Created placement '{}' in cluster '{}'",
        args.name, args.cluster
    );
    Ok(())
}

fn build_overrides(args: &CreateArgs) -> String {
    let mut lines = Vec::new();

    if let Some(replicas) = args.replicas {
        lines.push(format!("    replicas: {replicas}"));
    }

    if !args.env.is_empty() {
        lines.push("    env:".to_string());
        for env_var in &args.env {
            if let Some((key, value)) = env_var.split_once('=') {
                lines.push(format!("      {key}: \"{value}\""));
            }
        }
    }

    if lines.is_empty() {
        String::new()
    } else {
        format!("  overrides:\n{}\n", lines.join("\n"))
    }
}

fn scale_placement(repo_path: &Path, name: &str, cluster_name: &str, replicas: i32) -> Result<()> {
    let repo = LatticeRepo::open(repo_path)?;
    let cluster = repo.get_cluster(cluster_name)?;

    let placement_path = cluster
        .path
        .parent()
        .unwrap()
        .join("placements")
        .join(format!("{name}.yaml"));

    if !placement_path.exists() {
        return Err(crate::Error::Other(format!(
            "Placement '{name}' not found in cluster '{cluster_name}'"
        )));
    }

    let content = std::fs::read_to_string(&placement_path)?;
    let mut value: serde_yaml::Value = serde_yaml::from_str(&content)?;

    let spec = value
        .get_mut("spec")
        .ok_or_else(|| crate::Error::validation("missing spec"))?;

    if spec.get("overrides").is_none() {
        spec["overrides"] = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }
    spec["overrides"]["replicas"] = serde_yaml::Value::Number(replicas.into());

    std::fs::write(&placement_path, serde_yaml::to_string(&value)?)?;
    println!("Scaled '{}' to {} replicas", name, replicas);
    Ok(())
}

fn delete_placement(repo_path: &Path, name: &str, cluster_name: &str) -> Result<()> {
    let repo = LatticeRepo::open(repo_path)?;
    let cluster = repo.get_cluster(cluster_name)?;

    let placements_dir = cluster.path.parent().unwrap().join("placements");
    let placement_path = placements_dir.join(format!("{name}.yaml"));

    if !placement_path.exists() {
        return Err(crate::Error::Other(format!(
            "Placement '{name}' not found in cluster '{cluster_name}'"
        )));
    }

    std::fs::remove_file(&placement_path)?;
    remove_from_kustomization(
        &placements_dir.join("kustomization.yaml"),
        &format!("{name}.yaml"),
    )?;

    println!("Deleted placement '{name}' from cluster '{cluster_name}'");
    Ok(())
}

// --- Kustomization helpers ---

const EMPTY_KUSTOMIZATION: &str = r#"apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: []
"#;

fn add_to_kustomization(path: &Path, resource: &str) -> Result<()> {
    let content = if path.exists() {
        std::fs::read_to_string(path)?
    } else {
        EMPTY_KUSTOMIZATION.to_string()
    };

    let mut value: serde_yaml::Value = serde_yaml::from_str(&content)?;

    if let Some(resources) = value.get_mut("resources").and_then(|r| r.as_sequence_mut()) {
        if !resources.iter().any(|r| r.as_str() == Some(resource)) {
            resources.push(serde_yaml::Value::String(resource.to_string()));
        }
    }

    std::fs::write(path, serde_yaml::to_string(&value)?)?;
    Ok(())
}

fn remove_from_kustomization(path: &Path, resource: &str) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let content = std::fs::read_to_string(path)?;
    let mut value: serde_yaml::Value = serde_yaml::from_str(&content)?;

    if let Some(resources) = value.get_mut("resources").and_then(|r| r.as_sequence_mut()) {
        resources.retain(|r| r.as_str() != Some(resource));
    }

    std::fs::write(path, serde_yaml::to_string(&value)?)?;
    Ok(())
}
