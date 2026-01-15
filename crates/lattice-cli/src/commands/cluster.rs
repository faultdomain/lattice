//! Cluster commands

use clap::{Args, Subcommand};
use std::collections::HashMap;
use std::path::Path;

use crate::repo::LatticeRepo;
use crate::Result;

#[derive(Subcommand, Debug)]
pub enum ClusterCommands {
    /// List all clusters
    List,
    /// Show cluster hierarchy as tree
    Tree,
    /// Show cluster details
    Get(GetArgs),
    /// Add a cluster from a LatticeCluster YAML file
    Add(AddArgs),
    /// Scale cluster workers
    Scale(ScaleArgs),
    /// Upgrade cluster Kubernetes version
    Upgrade(UpgradeArgs),
    /// Delete a cluster
    Delete(DeleteArgs),
}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// Cluster name
    pub name: String,
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// Path to LatticeCluster YAML file (use "-" for stdin)
    pub file: String,
    /// Parent cluster name
    #[arg(long)]
    pub parent: String,
}

#[derive(Args, Debug)]
pub struct ScaleArgs {
    /// Cluster name
    pub name: String,
    /// Number of worker nodes
    #[arg(long)]
    pub workers: i32,
}

#[derive(Args, Debug)]
pub struct UpgradeArgs {
    /// Cluster name
    pub name: String,
    /// Target Kubernetes version
    #[arg(long)]
    pub k8s_version: String,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// Cluster name
    pub name: String,
    /// Skip confirmation
    #[arg(long)]
    pub yes: bool,
}

pub async fn run(cmd: ClusterCommands, repo_path: &Path) -> Result<()> {
    match cmd {
        ClusterCommands::List => list_clusters(repo_path),
        ClusterCommands::Tree => show_tree(repo_path),
        ClusterCommands::Get(args) => get_cluster(repo_path, &args.name),
        ClusterCommands::Add(args) => add_cluster(repo_path, args),
        ClusterCommands::Scale(args) => scale_cluster(repo_path, &args.name, args.workers),
        ClusterCommands::Upgrade(args) => upgrade_cluster(repo_path, &args.name, &args.k8s_version),
        ClusterCommands::Delete(args) => delete_cluster(repo_path, &args.name, args.yes),
    }
}

fn list_clusters(repo_path: &Path) -> Result<()> {
    let repo = LatticeRepo::open(repo_path)?;
    let clusters = repo.list_clusters()?;

    println!(
        "{:<15} {:<10} {:<12} {:<10} {:<8}",
        "NAME", "PARENT", "PROVIDER", "K8S", "WORKERS"
    );

    for c in clusters {
        println!(
            "{:<15} {:<10} {:<12} {:<10} {:<8}",
            c.name,
            c.parent.as_deref().unwrap_or("-"),
            c.provider.as_deref().unwrap_or("-"),
            c.k8s_version.as_deref().unwrap_or("-"),
            c.worker_nodes.map_or("-".into(), |n| n.to_string()),
        );
    }

    Ok(())
}

fn show_tree(repo_path: &Path) -> Result<()> {
    let repo = LatticeRepo::open(repo_path)?;
    let clusters = repo.list_clusters()?;
    let tree = repo.build_tree()?;

    if let Some(root) = clusters.iter().find(|c| c.parent.is_none()) {
        print_tree(&root.name, &tree, "", true);
    }

    Ok(())
}

fn print_tree(name: &str, tree: &HashMap<String, Vec<String>>, prefix: &str, is_last: bool) {
    let connector = if is_last { "└── " } else { "├── " };
    println!("{prefix}{connector}{name}");

    let new_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });

    if let Some(children) = tree.get(name) {
        for (i, child) in children.iter().enumerate() {
            print_tree(child, tree, &new_prefix, i == children.len() - 1);
        }
    }
}

fn get_cluster(repo_path: &Path, name: &str) -> Result<()> {
    let repo = LatticeRepo::open(repo_path)?;
    let c = repo.get_cluster(name)?;

    println!("Name:         {}", c.name);
    println!("Parent:       {}", c.parent.as_deref().unwrap_or("-"));
    println!("Provider:     {}", c.provider.as_deref().unwrap_or("-"));
    println!("K8s Version:  {}", c.k8s_version.as_deref().unwrap_or("-"));
    println!("Cell:         {}", c.is_cell);
    println!("Nodes:");
    println!(
        "  Control Plane: {}",
        c.control_plane_nodes.map_or("-".into(), |n| n.to_string())
    );
    println!(
        "  Workers:       {}",
        c.worker_nodes.map_or("-".into(), |n| n.to_string())
    );
    println!("Path:         {}", c.path.display());

    Ok(())
}

fn add_cluster(repo_path: &Path, args: AddArgs) -> Result<()> {
    use std::io::Read;

    let repo = LatticeRepo::open(repo_path)?;

    // Read YAML from file or stdin
    let yaml = if args.file == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        std::fs::read_to_string(&args.file)?
    };

    // Validate and extract cluster name
    let cluster_name = validate_lattice_cluster_yaml(&yaml)?;

    // Set up paths
    let parent = repo.get_cluster(&args.parent)?;
    let parent_dir = parent.path.parent().unwrap();
    let cluster_dir = parent_dir.join("children").join(&cluster_name);

    if cluster_dir.exists() {
        return Err(crate::Error::ClusterAlreadyExists { name: cluster_name });
    }

    // Create directory structure and files
    std::fs::create_dir_all(cluster_dir.join("placements"))?;
    std::fs::write(cluster_dir.join("cluster.yaml"), &yaml)?;
    std::fs::write(
        cluster_dir.join("kustomization.yaml"),
        CLUSTER_KUSTOMIZATION,
    )?;
    std::fs::write(
        cluster_dir.join("placements/kustomization.yaml"),
        EMPTY_KUSTOMIZATION,
    )?;

    // Update parent's children kustomization
    let children_kust = parent_dir.join("children/kustomization.yaml");
    add_to_kustomization(&children_kust, &format!("{}/cluster.yaml", cluster_name))?;

    println!("Added cluster '{}' under '{}'", cluster_name, args.parent);
    Ok(())
}

fn scale_cluster(repo_path: &Path, name: &str, workers: i32) -> Result<()> {
    let repo = LatticeRepo::open(repo_path)?;
    let cluster = repo.get_cluster(name)?;

    let content = std::fs::read_to_string(&cluster.path)?;
    let mut value: serde_yaml::Value = serde_yaml::from_str(&content)?;

    if let Some(nodes) = value.get_mut("spec").and_then(|s| s.get_mut("nodes")) {
        nodes["workers"] = serde_yaml::Value::Number(workers.into());
    }

    std::fs::write(&cluster.path, serde_yaml::to_string(&value)?)?;
    println!("Updated {}", cluster.path.display());
    Ok(())
}

fn upgrade_cluster(repo_path: &Path, name: &str, k8s_version: &str) -> Result<()> {
    let repo = LatticeRepo::open(repo_path)?;
    let cluster = repo.get_cluster(name)?;

    let content = std::fs::read_to_string(&cluster.path)?;
    let mut value: serde_yaml::Value = serde_yaml::from_str(&content)?;

    if let Some(k8s) = value
        .get_mut("spec")
        .and_then(|s| s.get_mut("provider"))
        .and_then(|p| p.get_mut("kubernetes"))
    {
        k8s["version"] = serde_yaml::Value::String(k8s_version.to_string());
    }

    std::fs::write(&cluster.path, serde_yaml::to_string(&value)?)?;
    println!("Updated {}", cluster.path.display());
    Ok(())
}

fn delete_cluster(repo_path: &Path, name: &str, confirmed: bool) -> Result<()> {
    let repo = LatticeRepo::open(repo_path)?;
    let cluster = repo.get_cluster(name)?;

    if !confirmed {
        println!("Delete cluster '{name}'? This will remove:");
        println!("  {}", cluster.path.display());
        println!("\nRun with --yes to confirm");
        return Ok(());
    }

    let cluster_dir = cluster.path.parent().unwrap();

    // Update parent's kustomization
    if let Some(parent_name) = &cluster.parent {
        let parent = repo.get_cluster(parent_name)?;
        let parent_dir = parent.path.parent().unwrap();
        let children_kust = parent_dir.join("children/kustomization.yaml");
        remove_from_kustomization(&children_kust, &format!("{}/cluster.yaml", name))?;
    }

    std::fs::remove_dir_all(cluster_dir)?;
    println!("Deleted cluster '{name}'");
    Ok(())
}

// --- Helpers ---

const CLUSTER_KUSTOMIZATION: &str = r#"apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - placements
"#;

const EMPTY_KUSTOMIZATION: &str = r#"apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: []
"#;

fn validate_lattice_cluster_yaml(yaml: &str) -> Result<String> {
    let parsed: serde_yaml::Value =
        serde_yaml::from_str(yaml).map_err(|e| crate::Error::InvalidYaml(e.to_string()))?;

    let api_version = parsed.get("apiVersion").and_then(|v| v.as_str());
    let kind = parsed.get("kind").and_then(|v| v.as_str());
    let name = parsed
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(|n| n.as_str());

    match (api_version, kind, name) {
        (Some("lattice.dev/v1alpha1"), Some("LatticeCluster"), Some(n)) => Ok(n.to_string()),
        (None, _, _) => Err(crate::Error::InvalidYaml("missing apiVersion".into())),
        (Some(v), _, _) if v != "lattice.dev/v1alpha1" => Err(crate::Error::InvalidYaml(format!(
            "expected apiVersion 'lattice.dev/v1alpha1', got '{v}'"
        ))),
        (_, None, _) => Err(crate::Error::InvalidYaml("missing kind".into())),
        (_, Some(k), _) if k != "LatticeCluster" => Err(crate::Error::InvalidYaml(format!(
            "expected kind 'LatticeCluster', got '{k}'"
        ))),
        (_, _, None) => Err(crate::Error::InvalidYaml("missing metadata.name".into())),
        _ => unreachable!(),
    }
}

fn add_to_kustomization(path: &Path, resource: &str) -> Result<()> {
    let content = read_or_create_kustomization(path)?;
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

fn read_or_create_kustomization(path: &Path) -> Result<String> {
    if path.exists() {
        Ok(std::fs::read_to_string(path)?)
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(EMPTY_KUSTOMIZATION.to_string())
    }
}
