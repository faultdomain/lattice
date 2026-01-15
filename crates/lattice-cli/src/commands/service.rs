//! Service registration commands

use clap::{Args, Subcommand};
use std::path::Path;

use crate::repo::LatticeRepo;
use crate::Result;

#[derive(Subcommand, Debug)]
pub enum ServiceCommands {
    /// List service registrations
    List,
    /// Register a new service
    Register(RegisterArgs),
    /// Remove a service registration
    Remove(RemoveArgs),
}

#[derive(Args, Debug)]
pub struct RegisterArgs {
    /// Service name
    pub name: String,
    /// Git repository URL
    #[arg(long)]
    pub git_url: String,
    /// Path within the git repository
    #[arg(long, default_value = ".")]
    pub git_path: String,
    /// Git branch
    #[arg(long, default_value = "main")]
    pub branch: String,
    /// Default replicas
    #[arg(long, default_value = "1")]
    pub default_replicas: i32,
    /// Register at a specific cluster level (defaults to root)
    #[arg(long)]
    pub at: Option<String>,
}

#[derive(Args, Debug)]
pub struct RemoveArgs {
    /// Service name
    pub name: String,
}

pub async fn run(cmd: ServiceCommands, repo_path: &Path) -> Result<()> {
    match cmd {
        ServiceCommands::List => list_services(repo_path),
        ServiceCommands::Register(args) => register_service(repo_path, args),
        ServiceCommands::Remove(args) => remove_service(repo_path, &args.name),
    }
}

fn list_services(repo_path: &Path) -> Result<()> {
    let repo = LatticeRepo::open(repo_path)?;
    let registrations = repo.list_registrations()?;

    println!("{:<20} {:<40} {:<15}", "NAME", "SOURCE", "PATH");
    for reg in registrations {
        println!("{:<20} {:<40} {:<15}", reg.name, reg.git_url, reg.git_path);
    }

    Ok(())
}

fn register_service(repo_path: &Path, args: RegisterArgs) -> Result<()> {
    let repo = LatticeRepo::open(repo_path)?;

    let registrations_dir = if let Some(ref at) = args.at {
        let cluster = repo.get_cluster(at)?;
        cluster.path.parent().unwrap().join("registrations")
    } else {
        repo.root().join("registrations")
    };

    std::fs::create_dir_all(&registrations_dir)?;

    let registration_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeServiceRegistration
metadata:
  name: {name}
spec:
  source:
    git:
      url: {url}
      path: {path}
      branch: {branch}
  defaults:
    replicas: {replicas}
"#,
        name = args.name,
        url = args.git_url,
        path = args.git_path,
        branch = args.branch,
        replicas = args.default_replicas
    );

    let path = registrations_dir.join(format!("{}.yaml", args.name));
    std::fs::write(&path, &registration_yaml)?;

    add_to_kustomization(
        &registrations_dir.join("kustomization.yaml"),
        &format!("{}.yaml", args.name),
    )?;

    println!("Registered service '{}'", args.name);
    Ok(())
}

fn remove_service(repo_path: &Path, name: &str) -> Result<()> {
    let repo = LatticeRepo::open(repo_path)?;
    let registrations = repo.list_registrations()?;

    let reg = registrations
        .into_iter()
        .find(|r| r.name == name)
        .ok_or_else(|| crate::Error::RegistrationNotFound {
            name: name.to_string(),
        })?;

    std::fs::remove_file(&reg.path)?;

    let registrations_dir = reg.path.parent().unwrap();
    remove_from_kustomization(
        &registrations_dir.join("kustomization.yaml"),
        &format!("{name}.yaml"),
    )?;

    println!("Removed service '{name}'");
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
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
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
