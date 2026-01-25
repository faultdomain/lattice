//! Build script for lattice-operator
//!
//! Downloads Helm charts and CAPI providers based on versions.toml.
//! All version information is centralized in versions.toml.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

/// Root structure of versions.toml
#[derive(Debug, Deserialize)]
struct Versions {
    charts: HashMap<String, Chart>,
    resources: HashMap<String, Resource>,
    providers: HashMap<String, Provider>,
}

#[derive(Debug, Clone, Deserialize)]
struct Chart {
    version: String,
    repo: String,
    chart: String,
    filename: String,
    #[serde(default)]
    oci: bool,
    #[serde(default)]
    version_prefix: String,
}

#[derive(Debug, Deserialize)]
struct Resource {
    version: String,
    url: String,
    filename: String,
}

#[derive(Debug, Deserialize)]
struct Provider {
    version: String,
    repo: String,
    components: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let workspace_root = Path::new(&manifest_dir)
        .parent()
        .expect("crate should have parent")
        .parent()
        .expect("crates dir should have parent");

    let versions_path = workspace_root.join("versions.toml");
    println!("cargo:rerun-if-changed={}", versions_path.display());

    let content = std::fs::read_to_string(&versions_path)?;
    let versions: Versions = toml::from_str(&content)?;

    let charts_dir = workspace_root.join("test-charts");
    let providers_dir = workspace_root.join("test-providers");
    let scripts_dir = workspace_root.join("scripts/runtime");

    // Set environment variables for runtime
    println!(
        "cargo:rustc-env=LATTICE_CHARTS_DIR={}",
        charts_dir.display()
    );
    println!(
        "cargo:rustc-env=LATTICE_SCRIPTS_DIR={}",
        scripts_dir.display()
    );
    println!(
        "cargo:rustc-env=CLUSTERCTL_CONFIG={}",
        providers_dir.join("clusterctl.yaml").display()
    );

    // Export specific env vars that code expects
    // Charts
    println!(
        "cargo:rustc-env=CILIUM_VERSION={}",
        versions.charts["cilium"].version
    );
    println!(
        "cargo:rustc-env=ISTIO_VERSION={}",
        versions.charts["istio-base"].version
    );
    println!(
        "cargo:rustc-env=CERT_MANAGER_VERSION={}",
        versions.charts["cert-manager"].version
    );
    println!(
        "cargo:rustc-env=EXTERNAL_SECRETS_VERSION={}",
        versions.charts["external-secrets"].version
    );

    // Resources
    println!(
        "cargo:rustc-env=GATEWAY_API_VERSION={}",
        versions.resources["gateway-api"].version
    );

    // Providers
    println!(
        "cargo:rustc-env=CAPI_VERSION={}",
        versions.providers["cluster-api"].version
    );
    println!(
        "cargo:rustc-env=CAPA_VERSION={}",
        versions.providers["infrastructure-aws"].version
    );
    println!(
        "cargo:rustc-env=CAPO_VERSION={}",
        versions.providers["infrastructure-openstack"].version
    );
    println!(
        "cargo:rustc-env=CAPMOX_VERSION={}",
        versions.providers["infrastructure-proxmox"].version
    );

    // Download artifacts
    download_charts(&versions, &charts_dir)?;
    download_resources(&versions, &charts_dir)?;
    download_providers(&versions, &providers_dir)?;

    Ok(())
}

fn download_charts(
    versions: &Versions,
    charts_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check if all charts exist
    let mut missing = Vec::new();
    for (name, chart) in &versions.charts {
        let filename = chart.filename.replace("{version}", &chart.version);
        let path = charts_dir.join(&filename);
        println!("cargo:rerun-if-changed={}", path.display());
        if !path.exists() {
            missing.push((name.clone(), chart.clone(), path));
        }
    }

    if missing.is_empty() {
        return Ok(());
    }

    if Command::new("helm").arg("version").output().is_err() {
        eprintln!("helm not found, skipping chart download");
        return Ok(());
    }

    std::fs::create_dir_all(charts_dir)?;

    // Collect unique repos (skip OCI repos)
    let mut repos: HashMap<String, String> = HashMap::new();
    for chart in versions.charts.values() {
        if !chart.oci && !repos.contains_key(&chart.repo) {
            // Extract repo name from chart name (e.g., "cilium/cilium" -> "cilium")
            if let Some(repo_name) = chart.chart.split('/').next() {
                repos.insert(chart.repo.clone(), repo_name.to_string());
            }
        }
    }

    // Add repos
    for (url, name) in &repos {
        let _ = Command::new("helm")
            .args(["repo", "add", name, url])
            .output();
    }
    let _ = Command::new("helm").args(["repo", "update"]).output();

    // Download missing charts
    for (name, chart, _path) in &missing {
        let version = if chart.version_prefix.is_empty() {
            chart.version.clone()
        } else {
            format!("{}{}", chart.version_prefix, chart.version)
        };

        eprintln!("Downloading {} chart v{}...", name, chart.version);

        if chart.oci {
            let _ = Command::new("helm")
                .args(["pull", &chart.chart, "--version", &version, "--destination"])
                .arg(charts_dir)
                .status();
        } else {
            let _ = Command::new("helm")
                .args([
                    "pull",
                    &chart.chart,
                    "--version",
                    &chart.version,
                    "--destination",
                ])
                .arg(charts_dir)
                .status();
        }
    }

    Ok(())
}

fn download_resources(
    versions: &Versions,
    charts_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    for (name, resource) in &versions.resources {
        let filename = resource.filename.replace("{version}", &resource.version);
        let path = charts_dir.join(&filename);
        println!("cargo:rerun-if-changed={}", path.display());

        if path.exists() {
            continue;
        }

        let url = resource.url.replace("{version}", &resource.version);
        eprintln!("Downloading {} v{}...", name, resource.version);
        download_file(&url, &path);
    }

    Ok(())
}

fn download_providers(
    versions: &Versions,
    providers_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = providers_dir.join("clusterctl.yaml");
    println!("cargo:rerun-if-changed={}", config_path.display());

    // Check if all providers exist
    let mut all_exist = config_path.exists();
    for (name, provider) in &versions.providers {
        let provider_dir = providers_dir
            .join(name)
            .join(format!("v{}", provider.version));
        for component in &provider.components {
            let path = provider_dir.join(component);
            println!("cargo:rerun-if-changed={}", path.display());
            if !path.exists() {
                all_exist = false;
            }
        }
    }

    if all_exist {
        return Ok(());
    }

    if Command::new("curl").arg("--version").output().is_err() {
        eprintln!("curl not found, skipping provider download");
        return Ok(());
    }

    eprintln!("Downloading CAPI providers...");

    // Download each provider
    for (name, provider) in &versions.providers {
        let provider_dir = providers_dir
            .join(name)
            .join(format!("v{}", provider.version));
        std::fs::create_dir_all(&provider_dir)?;

        let base_url = format!(
            "https://github.com/{}/releases/download/v{}",
            provider.repo, provider.version
        );

        for component in &provider.components {
            let path = provider_dir.join(component);
            if !path.exists() {
                let url = format!("{}/{}", base_url, component);
                eprintln!("  Downloading {}/{}...", name, component);
                download_file(&url, &path);
            }
        }
    }

    // Copy metadata.yaml for providers that share it
    copy_metadata(providers_dir, &versions.providers)?;

    // Generate clusterctl.yaml
    generate_clusterctl_config(providers_dir, &versions.providers)?;

    Ok(())
}

fn copy_metadata(
    providers_dir: &Path,
    providers: &HashMap<String, Provider>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Providers that need metadata copied from their parent
    let copies = [
        ("bootstrap-kubeadm", "cluster-api"),
        ("control-plane-kubeadm", "cluster-api"),
        ("infrastructure-docker", "cluster-api"),
        ("control-plane-rke2", "bootstrap-rke2"),
    ];

    for (target, source) in copies {
        if let (Some(target_provider), Some(source_provider)) =
            (providers.get(target), providers.get(source))
        {
            let source_path = providers_dir
                .join(source)
                .join(format!("v{}", source_provider.version))
                .join("metadata.yaml");
            let target_path = providers_dir
                .join(target)
                .join(format!("v{}", target_provider.version))
                .join("metadata.yaml");

            if source_path.exists() && !target_path.exists() {
                std::fs::copy(&source_path, &target_path).ok();
            }
        }
    }

    Ok(())
}

fn generate_clusterctl_config(
    providers_dir: &Path,
    providers: &HashMap<String, Provider>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = providers_dir.join("clusterctl.yaml");

    // Map provider names to clusterctl types
    let type_map: HashMap<&str, (&str, &str)> = [
        ("cluster-api", ("cluster-api", "CoreProvider")),
        ("bootstrap-kubeadm", ("kubeadm", "BootstrapProvider")),
        ("control-plane-kubeadm", ("kubeadm", "ControlPlaneProvider")),
        ("bootstrap-rke2", ("rke2", "BootstrapProvider")),
        ("control-plane-rke2", ("rke2", "ControlPlaneProvider")),
        (
            "infrastructure-docker",
            ("docker", "InfrastructureProvider"),
        ),
        (
            "infrastructure-proxmox",
            ("proxmox", "InfrastructureProvider"),
        ),
        ("infrastructure-aws", ("aws", "InfrastructureProvider")),
        (
            "infrastructure-openstack",
            ("openstack", "InfrastructureProvider"),
        ),
        ("ipam-in-cluster", ("in-cluster", "IPAMProvider")),
    ]
    .into_iter()
    .collect();

    let mut config = String::from("providers:\n");

    for (name, provider) in providers {
        if let Some((clusterctl_name, provider_type)) = type_map.get(name.as_str()) {
            // Find the main component file
            let component = provider
                .components
                .iter()
                .find(|c| {
                    c.ends_with("-components.yaml") || c.ends_with("-components-development.yaml")
                })
                .unwrap_or(&provider.components[0]);

            let url = format!(
                "file://{}/{}/v{}/{}",
                providers_dir.display(),
                name,
                provider.version,
                component
            );

            config.push_str(&format!(
                "  - name: \"{}\"\n    url: \"{}\"\n    type: \"{}\"\n",
                clusterctl_name, url, provider_type
            ));
        }
    }

    std::fs::write(&config_path, config)?;
    Ok(())
}

fn download_file(url: &str, dest: &Path) {
    if dest.exists() {
        return;
    }
    let _ = Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(dest)
        .arg(url)
        .status();
}
