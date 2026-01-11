use std::path::Path;
use std::process::Command;

/// Versions loaded from versions.toml - single source of truth
struct Versions {
    capi: String,
    cilium: String,
    istio: String,
    cert_manager: String,
}

/// Load versions from versions.toml
fn load_versions() -> Versions {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let versions_path = Path::new(&manifest_dir).join("versions.toml");
    let content = std::fs::read_to_string(&versions_path).expect("Failed to read versions.toml");

    // Simple TOML parsing for our flat structure
    let mut versions = Versions {
        capi: String::new(),
        cilium: String::new(),
        istio: String::new(),
        cert_manager: String::new(),
    };
    let mut section = "";

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = line.trim_matches(|c| c == '[' || c == ']');
        } else if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"');
            match (section, key) {
                ("capi", "version") => versions.capi = value.to_string(),
                ("charts", "cilium") => versions.cilium = value.to_string(),
                ("charts", "istio") => versions.istio = value.to_string(),
                ("charts", "cert-manager") => versions.cert_manager = value.to_string(),
                _ => {}
            }
        }
    }

    // Re-run if versions.toml changes
    println!("cargo:rerun-if-changed=versions.toml");

    versions
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let versions = load_versions();

    // Compile proto files
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/agent.proto"], &["proto"])?;

    // Re-run if proto files change
    println!("cargo:rerun-if-changed=proto/agent.proto");

    // Download helm charts for local development/testing if they don't exist
    download_helm_charts(&versions)?;

    // Download CAPI providers for offline clusterctl init
    download_capi_providers(&versions)?;

    Ok(())
}

/// Download helm charts for local testing if not present
fn download_helm_charts(versions: &Versions) -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let charts_dir = Path::new(&manifest_dir).join("test-charts");

    // Check if all required charts exist
    let cilium_chart = charts_dir.join(format!("cilium-{}.tgz", versions.cilium));
    let base_chart = charts_dir.join(format!("base-{}.tgz", versions.istio));
    let istiod_chart = charts_dir.join(format!("istiod-{}.tgz", versions.istio));
    let cni_chart = charts_dir.join(format!("cni-{}.tgz", versions.istio));
    let ztunnel_chart = charts_dir.join(format!("ztunnel-{}.tgz", versions.istio));
    let cert_manager_chart =
        charts_dir.join(format!("cert-manager-v{}.tgz", versions.cert_manager));

    // Set env vars for runtime code
    let scripts_dir = Path::new(&manifest_dir).join("scripts");
    println!(
        "cargo:rustc-env=LATTICE_CHARTS_DIR={}",
        charts_dir.display()
    );
    println!(
        "cargo:rustc-env=LATTICE_SCRIPTS_DIR={}",
        scripts_dir.display()
    );
    println!("cargo:rustc-env=CILIUM_VERSION={}", versions.cilium);
    println!("cargo:rustc-env=ISTIO_VERSION={}", versions.istio);
    println!("cargo:rustc-env=CAPI_VERSION={}", versions.capi);

    if cilium_chart.exists()
        && base_chart.exists()
        && istiod_chart.exists()
        && cni_chart.exists()
        && ztunnel_chart.exists()
        && cert_manager_chart.exists()
    {
        return Ok(());
    }

    // Check if helm is available
    if Command::new("helm").arg("version").output().is_err() {
        eprintln!("helm not found, skipping chart download");
        return Ok(());
    }

    // Create charts directory
    std::fs::create_dir_all(&charts_dir)?;

    // Add repos (ignore errors if already added)
    let _ = Command::new("helm")
        .args(["repo", "add", "cilium", "https://helm.cilium.io/"])
        .output();
    let _ = Command::new("helm")
        .args([
            "repo",
            "add",
            "istio",
            "https://istio-release.storage.googleapis.com/charts",
        ])
        .output();
    let _ = Command::new("helm")
        .args(["repo", "add", "jetstack", "https://charts.jetstack.io"])
        .output();
    let _ = Command::new("helm").args(["repo", "update"]).output();

    // Pull charts if not present
    if !cilium_chart.exists() {
        eprintln!("Downloading Cilium chart v{}...", versions.cilium);
        let status = Command::new("helm")
            .args([
                "pull",
                "cilium/cilium",
                "--version",
                &versions.cilium,
                "--destination",
            ])
            .arg(&charts_dir)
            .status()?;
        if !status.success() {
            eprintln!("Failed to download Cilium chart");
        }
    }

    if !base_chart.exists() {
        eprintln!("Downloading Istio base chart v{}...", versions.istio);
        let status = Command::new("helm")
            .args([
                "pull",
                "istio/base",
                "--version",
                &versions.istio,
                "--destination",
            ])
            .arg(&charts_dir)
            .status()?;
        if !status.success() {
            eprintln!("Failed to download Istio base chart");
        }
    }

    if !istiod_chart.exists() {
        eprintln!("Downloading Istio istiod chart v{}...", versions.istio);
        let status = Command::new("helm")
            .args([
                "pull",
                "istio/istiod",
                "--version",
                &versions.istio,
                "--destination",
            ])
            .arg(&charts_dir)
            .status()?;
        if !status.success() {
            eprintln!("Failed to download Istio istiod chart");
        }
    }

    if !cni_chart.exists() {
        eprintln!("Downloading Istio CNI chart v{}...", versions.istio);
        let status = Command::new("helm")
            .args([
                "pull",
                "istio/cni",
                "--version",
                &versions.istio,
                "--destination",
            ])
            .arg(&charts_dir)
            .status()?;
        if !status.success() {
            eprintln!("Failed to download Istio CNI chart");
        }
    }

    if !ztunnel_chart.exists() {
        eprintln!("Downloading Istio ztunnel chart v{}...", versions.istio);
        let status = Command::new("helm")
            .args([
                "pull",
                "istio/ztunnel",
                "--version",
                &versions.istio,
                "--destination",
            ])
            .arg(&charts_dir)
            .status()?;
        if !status.success() {
            eprintln!("Failed to download Istio ztunnel chart");
        }
    }

    if !cert_manager_chart.exists() {
        eprintln!(
            "Downloading cert-manager chart v{}...",
            versions.cert_manager
        );
        let status = Command::new("helm")
            .args([
                "pull",
                "jetstack/cert-manager",
                "--version",
                &versions.cert_manager,
                "--destination",
            ])
            .arg(&charts_dir)
            .status()?;
        if !status.success() {
            eprintln!("Failed to download cert-manager chart");
        }
    }

    Ok(())
}

/// Download CAPI providers for offline clusterctl init
fn download_capi_providers(versions: &Versions) -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let providers_dir = Path::new(&manifest_dir).join("test-providers");

    // Set env var for clusterctl config location
    let config_path = providers_dir.join("clusterctl.yaml");
    println!(
        "cargo:rustc-env=CLUSTERCTL_CONFIG={}",
        config_path.display()
    );

    // Provider directories (clusterctl local repository structure)
    let core_dir = providers_dir
        .join("cluster-api")
        .join(format!("v{}", versions.capi));
    let bootstrap_dir = providers_dir
        .join("bootstrap-kubeadm")
        .join(format!("v{}", versions.capi));
    let controlplane_dir = providers_dir
        .join("control-plane-kubeadm")
        .join(format!("v{}", versions.capi));
    let docker_dir = providers_dir
        .join("infrastructure-docker")
        .join(format!("v{}", versions.capi));

    let core = core_dir.join("core-components.yaml");
    let core_metadata = core_dir.join("metadata.yaml");
    let bootstrap = bootstrap_dir.join("bootstrap-components.yaml");
    let bootstrap_metadata = bootstrap_dir.join("metadata.yaml");
    let controlplane = controlplane_dir.join("control-plane-components.yaml");
    let controlplane_metadata = controlplane_dir.join("metadata.yaml");
    let docker = docker_dir.join("infrastructure-components-development.yaml");
    let docker_metadata = docker_dir.join("metadata.yaml");

    // Check if all files exist
    let all_exist = core.exists()
        && core_metadata.exists()
        && bootstrap.exists()
        && bootstrap_metadata.exists()
        && controlplane.exists()
        && controlplane_metadata.exists()
        && docker.exists()
        && docker_metadata.exists()
        && config_path.exists();

    if all_exist {
        return Ok(());
    }

    // Check if curl is available
    if Command::new("curl").arg("--version").output().is_err() {
        eprintln!("curl not found, skipping CAPI provider download");
        return Ok(());
    }

    eprintln!("Downloading CAPI providers v{}...", versions.capi);

    // Create provider directories
    std::fs::create_dir_all(&core_dir)?;
    std::fs::create_dir_all(&bootstrap_dir)?;
    std::fs::create_dir_all(&controlplane_dir)?;
    std::fs::create_dir_all(&docker_dir)?;

    // Download components and metadata from GitHub releases
    let base_url = format!(
        "https://github.com/kubernetes-sigs/cluster-api/releases/download/v{}",
        versions.capi
    );

    download_file(&format!("{}/core-components.yaml", base_url), &core);
    download_file(&format!("{}/metadata.yaml", base_url), &core_metadata);
    download_file(
        &format!("{}/bootstrap-components.yaml", base_url),
        &bootstrap,
    );
    std::fs::copy(&core_metadata, &bootstrap_metadata).ok();
    download_file(
        &format!("{}/control-plane-components.yaml", base_url),
        &controlplane,
    );
    std::fs::copy(&core_metadata, &controlplane_metadata).ok();
    download_file(
        &format!("{}/infrastructure-components-development.yaml", base_url),
        &docker,
    );
    std::fs::copy(&core_metadata, &docker_metadata).ok();

    // Create clusterctl.yaml with provider definitions using file:// URLs
    let config_content = format!(
        r#"providers:
  - name: "cluster-api"
    url: "file://{providers_dir}/cluster-api/v{version}/core-components.yaml"
    type: "CoreProvider"
  - name: "kubeadm"
    url: "file://{providers_dir}/bootstrap-kubeadm/v{version}/bootstrap-components.yaml"
    type: "BootstrapProvider"
  - name: "kubeadm"
    url: "file://{providers_dir}/control-plane-kubeadm/v{version}/control-plane-components.yaml"
    type: "ControlPlaneProvider"
  - name: "docker"
    url: "file://{providers_dir}/infrastructure-docker/v{version}/infrastructure-components-development.yaml"
    type: "InfrastructureProvider"
"#,
        providers_dir = providers_dir.display(),
        version = versions.capi,
    );
    std::fs::write(&config_path, config_content)?;

    Ok(())
}

fn download_file(url: &str, dest: &Path) {
    if dest.exists() {
        return;
    }
    eprintln!(
        "  Downloading {}...",
        dest.file_name().unwrap().to_string_lossy()
    );
    let _ = Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(dest)
        .arg(url)
        .status();
}
