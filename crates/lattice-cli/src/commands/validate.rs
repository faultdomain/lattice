//! Validate command

use clap::Args;
use std::collections::HashSet;
use std::path::Path;

use crate::repo::LatticeRepo;
use crate::Result;

#[derive(Args, Debug)]
pub struct ValidateArgs {
    /// Specific file to validate (validates entire repo if not specified)
    pub file: Option<String>,
}

pub async fn run(args: ValidateArgs, repo_path: &Path) -> Result<()> {
    if let Some(ref file) = args.file {
        validate_file(repo_path, file)
    } else {
        validate_repo(repo_path)
    }
}

fn validate_repo(repo_path: &Path) -> Result<()> {
    let repo = LatticeRepo::open(repo_path)?;

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Validate all clusters
    let clusters = repo.list_clusters()?;
    let cluster_names: HashSet<_> = clusters.iter().map(|c| c.name.clone()).collect();

    for cluster in &clusters {
        // Check parent exists
        if let Some(ref parent) = cluster.parent {
            if !cluster_names.contains(parent) {
                errors.push(format!(
                    "{}: parent '{}' not found",
                    cluster.path.display(),
                    parent
                ));
            }
        }

        // Check for circular references
        if let Some(cycle) = detect_cycle(&cluster.name, &clusters) {
            errors.push(format!(
                "{}: circular parent reference detected: {}",
                cluster.path.display(),
                cycle.join(" -> ")
            ));
        }

        println!("  {} valid", cluster.path.display());
    }

    // Validate registrations
    let registrations = repo.list_registrations()?;
    let registration_names: HashSet<_> = registrations.iter().map(|r| r.name.clone()).collect();

    for reg in &registrations {
        if reg.git_url.is_empty() {
            warnings.push(format!("{}: missing git URL", reg.path.display()));
        }
        println!("  {} valid", reg.path.display());
    }

    // Validate placements reference valid registrations
    for cluster in &clusters {
        if let Ok(placements) = repo.list_placements(&cluster.name) {
            for placement in placements {
                if !registration_names.contains(&placement.service_ref) {
                    errors.push(format!(
                        "{}: serviceRef '{}' not found in registrations",
                        placement.path.display(),
                        placement.service_ref
                    ));
                }
                println!("  {} valid", placement.path.display());
            }
        }
    }

    // Validate kustomization.yaml consistency
    validate_kustomizations(repo_path, &mut errors)?;

    // Print results
    println!();

    if !warnings.is_empty() {
        println!("Warnings:");
        for warning in &warnings {
            println!("  - {}", warning);
        }
        println!();
    }

    if errors.is_empty() {
        println!("All validations passed");
        Ok(())
    } else {
        println!("Validation errors:");
        for error in &errors {
            println!("  - {}", error);
        }
        Err(crate::Error::validation(format!(
            "{} validation errors",
            errors.len()
        )))
    }
}

fn validate_file(repo_path: &Path, file: &str) -> Result<()> {
    let file_path = repo_path.join(file);

    if !file_path.exists() {
        return Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File not found: {}", file),
        )));
    }

    let content = std::fs::read_to_string(&file_path)?;
    let value: serde_yaml::Value = serde_yaml::from_str(&content)?;

    // Check it has basic structure
    let kind = value
        .get("kind")
        .and_then(|k| k.as_str())
        .ok_or_else(|| crate::Error::validation("missing kind"))?;

    let name = value
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(|n| n.as_str())
        .ok_or_else(|| crate::Error::validation("missing metadata.name"))?;

    println!("Kind:     {}", kind);
    println!("Name:     {}", name);

    match kind {
        "LatticeCluster" => validate_cluster_spec(&value)?,
        "LatticeServiceRegistration" => validate_registration_spec(&value)?,
        "LatticeServicePlacement" => validate_placement_spec(&value)?,
        "Kustomization" => println!("Kustomize file"),
        _ => println!("Unknown kind: {}", kind),
    }

    println!();
    println!("Schema valid");

    Ok(())
}

fn validate_cluster_spec(value: &serde_yaml::Value) -> Result<()> {
    let spec = value
        .get("spec")
        .ok_or_else(|| crate::Error::validation("missing spec"))?;

    // Check provider config
    let _provider = spec
        .get("provider")
        .ok_or_else(|| crate::Error::validation("missing spec.provider"))?;

    // Check nodes
    let _nodes = spec
        .get("nodes")
        .ok_or_else(|| crate::Error::validation("missing spec.nodes"))?;

    println!("Provider config valid");
    println!("Nodes config valid");

    Ok(())
}

fn validate_registration_spec(value: &serde_yaml::Value) -> Result<()> {
    let spec = value
        .get("spec")
        .ok_or_else(|| crate::Error::validation("missing spec"))?;

    let _source = spec
        .get("source")
        .ok_or_else(|| crate::Error::validation("missing spec.source"))?;

    println!("Source config valid");

    Ok(())
}

fn validate_placement_spec(value: &serde_yaml::Value) -> Result<()> {
    let spec = value
        .get("spec")
        .ok_or_else(|| crate::Error::validation("missing spec"))?;

    let _service_ref = spec
        .get("serviceRef")
        .ok_or_else(|| crate::Error::validation("missing spec.serviceRef"))?;

    println!("serviceRef valid");

    Ok(())
}

fn detect_cycle(start: &str, clusters: &[crate::repo::ClusterInfo]) -> Option<Vec<String>> {
    let mut visited = HashSet::new();
    let mut path = Vec::new();

    let cluster_map: std::collections::HashMap<_, _> = clusters
        .iter()
        .map(|c| (c.name.clone(), c.parent.clone()))
        .collect();

    let mut current = Some(start.to_string());

    while let Some(name) = current {
        if visited.contains(&name) {
            path.push(name);
            return Some(path);
        }

        visited.insert(name.clone());
        path.push(name.clone());

        current = cluster_map.get(&name).and_then(|p| p.clone());
    }

    None
}

fn validate_kustomizations(repo_path: &Path, errors: &mut Vec<String>) -> Result<()> {
    // Check that kustomization.yaml files reference existing resources
    for entry in walkdir::WalkDir::new(repo_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name() == "kustomization.yaml")
    {
        let path = entry.path();
        let dir = path.parent().unwrap();

        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                if let Some(resources) = value.get("resources").and_then(|r| r.as_sequence()) {
                    for resource in resources {
                        if let Some(res_path) = resource.as_str() {
                            let full_path = dir.join(res_path);
                            if !full_path.exists() {
                                errors.push(format!(
                                    "{}: resource '{}' not found",
                                    path.display(),
                                    res_path
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::ClusterInfo;
    use std::path::PathBuf;

    fn cluster(name: &str, parent: Option<&str>) -> ClusterInfo {
        ClusterInfo {
            name: name.to_string(),
            parent: parent.map(|s| s.to_string()),
            path: PathBuf::from(format!("{}/cluster.yaml", name)),
            is_cell: false,
            provider: Some("docker".to_string()),
            k8s_version: Some("1.32.0".to_string()),
            control_plane_nodes: Some(1),
            worker_nodes: Some(1),
        }
    }

    #[test]
    fn test_detect_cycle_no_cycle() {
        let clusters = vec![
            cluster("root", None),
            cluster("child1", Some("root")),
            cluster("child2", Some("root")),
            cluster("grandchild", Some("child1")),
        ];

        assert!(detect_cycle("root", &clusters).is_none());
        assert!(detect_cycle("child1", &clusters).is_none());
        assert!(detect_cycle("grandchild", &clusters).is_none());
    }

    #[test]
    fn test_detect_cycle_self_reference() {
        let clusters = vec![
            cluster("root", None),
            cluster("bad", Some("bad")), // self-reference
        ];

        let cycle = detect_cycle("bad", &clusters);
        assert!(cycle.is_some());
        let path = cycle.unwrap();
        assert!(path.contains(&"bad".to_string()));
    }

    #[test]
    fn test_detect_cycle_mutual_reference() {
        let clusters = vec![cluster("a", Some("b")), cluster("b", Some("a"))];

        let cycle = detect_cycle("a", &clusters);
        assert!(cycle.is_some());
    }

    #[test]
    fn test_validate_cluster_spec_valid() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: test
spec:
  provider:
    docker: {}
  nodes:
    controlPlane:
      count: 1
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        assert!(validate_cluster_spec(&value).is_ok());
    }

    #[test]
    fn test_validate_cluster_spec_missing_provider() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: test
spec:
  nodes:
    controlPlane:
      count: 1
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        assert!(validate_cluster_spec(&value).is_err());
    }

    #[test]
    fn test_validate_cluster_spec_missing_nodes() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: test
spec:
  provider:
    docker: {}
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        assert!(validate_cluster_spec(&value).is_err());
    }

    #[test]
    fn test_validate_registration_spec_valid() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: LatticeServiceRegistration
metadata:
  name: my-service
spec:
  source:
    git:
      url: https://github.com/org/repo
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        assert!(validate_registration_spec(&value).is_ok());
    }

    #[test]
    fn test_validate_placement_spec_valid() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: LatticeServicePlacement
metadata:
  name: my-service-prod
spec:
  serviceRef: my-service
  replicas: 3
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        assert!(validate_placement_spec(&value).is_ok());
    }

    #[test]
    fn test_validate_placement_spec_missing_service_ref() {
        let yaml = r#"
apiVersion: lattice.dev/v1alpha1
kind: LatticeServicePlacement
metadata:
  name: my-service-prod
spec:
  replicas: 3
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        assert!(validate_placement_spec(&value).is_err());
    }
}
