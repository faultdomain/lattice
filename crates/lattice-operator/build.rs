use std::path::Path;
use std::process::Command;

/// Versions loaded from versions.toml - single source of truth
struct Versions {
    capi: String,
    rke2: String,
    cilium: String,
    istio: String,
    cert_manager: String,
}

/// Load versions from versions.toml in workspace root
fn load_versions() -> Versions {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // Go up two levels: crates/lattice-operator -> workspace root
    let workspace_root = Path::new(&manifest_dir).parent().unwrap().parent().unwrap();
    let versions_path = workspace_root.join("versions.toml");
    let content = std::fs::read_to_string(&versions_path).expect("Failed to read versions.toml");

    let mut versions = Versions {
        capi: String::new(),
        rke2: String::new(),
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
                ("rke2", "version") => versions.rke2 = value.to_string(),
                ("charts", "cilium") => versions.cilium = value.to_string(),
                ("charts", "istio") => versions.istio = value.to_string(),
                ("charts", "cert-manager") => versions.cert_manager = value.to_string(),
                _ => {}
            }
        }
    }

    println!("cargo:rerun-if-changed={}", versions_path.display());

    versions
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let workspace_root = Path::new(&manifest_dir).parent().unwrap().parent().unwrap();

    let versions = load_versions();

    // Set env vars pointing to workspace root directories
    let charts_dir = workspace_root.join("test-charts");
    let providers_dir = workspace_root.join("test-providers");
    let scripts_dir = workspace_root.join("scripts");

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
    println!("cargo:rustc-env=RKE2_VERSION={}", versions.rke2);

    let config_path = providers_dir.join("clusterctl.yaml");
    println!(
        "cargo:rustc-env=CLUSTERCTL_CONFIG={}",
        config_path.display()
    );

    // Download charts and providers if needed
    download_helm_charts(&versions, &charts_dir)?;
    download_capi_providers(&versions, &providers_dir)?;

    Ok(())
}

fn download_helm_charts(
    versions: &Versions,
    charts_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let cilium_chart = charts_dir.join(format!("cilium-{}.tgz", versions.cilium));
    let base_chart = charts_dir.join(format!("base-{}.tgz", versions.istio));
    let istiod_chart = charts_dir.join(format!("istiod-{}.tgz", versions.istio));
    let cni_chart = charts_dir.join(format!("cni-{}.tgz", versions.istio));
    let ztunnel_chart = charts_dir.join(format!("ztunnel-{}.tgz", versions.istio));
    let cert_manager_chart =
        charts_dir.join(format!("cert-manager-v{}.tgz", versions.cert_manager));

    if cilium_chart.exists()
        && base_chart.exists()
        && istiod_chart.exists()
        && cni_chart.exists()
        && ztunnel_chart.exists()
        && cert_manager_chart.exists()
    {
        return Ok(());
    }

    if Command::new("helm").arg("version").output().is_err() {
        eprintln!("helm not found, skipping chart download");
        return Ok(());
    }

    std::fs::create_dir_all(charts_dir)?;

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

    if !cilium_chart.exists() {
        eprintln!("Downloading Cilium chart v{}...", versions.cilium);
        let _ = Command::new("helm")
            .args([
                "pull",
                "cilium/cilium",
                "--version",
                &versions.cilium,
                "--destination",
            ])
            .arg(charts_dir)
            .status();
    }
    if !base_chart.exists() {
        eprintln!("Downloading Istio base chart v{}...", versions.istio);
        let _ = Command::new("helm")
            .args([
                "pull",
                "istio/base",
                "--version",
                &versions.istio,
                "--destination",
            ])
            .arg(charts_dir)
            .status();
    }
    if !istiod_chart.exists() {
        eprintln!("Downloading Istio istiod chart v{}...", versions.istio);
        let _ = Command::new("helm")
            .args([
                "pull",
                "istio/istiod",
                "--version",
                &versions.istio,
                "--destination",
            ])
            .arg(charts_dir)
            .status();
    }
    if !cni_chart.exists() {
        eprintln!("Downloading Istio CNI chart v{}...", versions.istio);
        let _ = Command::new("helm")
            .args([
                "pull",
                "istio/cni",
                "--version",
                &versions.istio,
                "--destination",
            ])
            .arg(charts_dir)
            .status();
    }
    if !ztunnel_chart.exists() {
        eprintln!("Downloading Istio ztunnel chart v{}...", versions.istio);
        let _ = Command::new("helm")
            .args([
                "pull",
                "istio/ztunnel",
                "--version",
                &versions.istio,
                "--destination",
            ])
            .arg(charts_dir)
            .status();
    }
    if !cert_manager_chart.exists() {
        eprintln!(
            "Downloading cert-manager chart v{}...",
            versions.cert_manager
        );
        let _ = Command::new("helm")
            .args([
                "pull",
                "jetstack/cert-manager",
                "--version",
                &versions.cert_manager,
                "--destination",
            ])
            .arg(charts_dir)
            .status();
    }

    Ok(())
}

fn download_capi_providers(
    versions: &Versions,
    providers_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = providers_dir.join("clusterctl.yaml");

    let core_dir = providers_dir
        .join("cluster-api")
        .join(format!("v{}", versions.capi));
    let bootstrap_kubeadm_dir = providers_dir
        .join("bootstrap-kubeadm")
        .join(format!("v{}", versions.capi));
    let controlplane_kubeadm_dir = providers_dir
        .join("control-plane-kubeadm")
        .join(format!("v{}", versions.capi));
    let docker_dir = providers_dir
        .join("infrastructure-docker")
        .join(format!("v{}", versions.capi));
    let bootstrap_rke2_dir = providers_dir
        .join("bootstrap-rke2")
        .join(format!("v{}", versions.rke2));
    let controlplane_rke2_dir = providers_dir
        .join("control-plane-rke2")
        .join(format!("v{}", versions.rke2));

    let core = core_dir.join("core-components.yaml");
    let bootstrap_rke2 = bootstrap_rke2_dir.join("bootstrap-components.yaml");

    if core.exists() && bootstrap_rke2.exists() && config_path.exists() {
        return Ok(());
    }

    if Command::new("curl").arg("--version").output().is_err() {
        eprintln!("curl not found, skipping CAPI provider download");
        return Ok(());
    }

    eprintln!("Downloading CAPI providers v{}...", versions.capi);

    std::fs::create_dir_all(&core_dir)?;
    std::fs::create_dir_all(&bootstrap_kubeadm_dir)?;
    std::fs::create_dir_all(&controlplane_kubeadm_dir)?;
    std::fs::create_dir_all(&docker_dir)?;
    std::fs::create_dir_all(&bootstrap_rke2_dir)?;
    std::fs::create_dir_all(&controlplane_rke2_dir)?;

    let capi_base_url = format!(
        "https://github.com/kubernetes-sigs/cluster-api/releases/download/v{}",
        versions.capi
    );
    download_file(
        &format!("{}/core-components.yaml", capi_base_url),
        &core_dir.join("core-components.yaml"),
    );
    download_file(
        &format!("{}/metadata.yaml", capi_base_url),
        &core_dir.join("metadata.yaml"),
    );
    download_file(
        &format!("{}/bootstrap-components.yaml", capi_base_url),
        &bootstrap_kubeadm_dir.join("bootstrap-components.yaml"),
    );
    std::fs::copy(
        core_dir.join("metadata.yaml"),
        bootstrap_kubeadm_dir.join("metadata.yaml"),
    )
    .ok();
    download_file(
        &format!("{}/control-plane-components.yaml", capi_base_url),
        &controlplane_kubeadm_dir.join("control-plane-components.yaml"),
    );
    std::fs::copy(
        core_dir.join("metadata.yaml"),
        controlplane_kubeadm_dir.join("metadata.yaml"),
    )
    .ok();
    download_file(
        &format!(
            "{}/infrastructure-components-development.yaml",
            capi_base_url
        ),
        &docker_dir.join("infrastructure-components-development.yaml"),
    );
    std::fs::copy(
        core_dir.join("metadata.yaml"),
        docker_dir.join("metadata.yaml"),
    )
    .ok();

    let rke2_base_url = format!(
        "https://github.com/rancher/cluster-api-provider-rke2/releases/download/v{}",
        versions.rke2
    );
    download_file(
        &format!("{}/bootstrap-components.yaml", rke2_base_url),
        &bootstrap_rke2_dir.join("bootstrap-components.yaml"),
    );
    download_file(
        &format!("{}/metadata.yaml", rke2_base_url),
        &bootstrap_rke2_dir.join("metadata.yaml"),
    );
    download_file(
        &format!("{}/control-plane-components.yaml", rke2_base_url),
        &controlplane_rke2_dir.join("control-plane-components.yaml"),
    );
    std::fs::copy(
        bootstrap_rke2_dir.join("metadata.yaml"),
        controlplane_rke2_dir.join("metadata.yaml"),
    )
    .ok();

    let config_content = format!(
        r#"providers:
  - name: "cluster-api"
    url: "file://{providers_dir}/cluster-api/v{capi_version}/core-components.yaml"
    type: "CoreProvider"
  - name: "kubeadm"
    url: "file://{providers_dir}/bootstrap-kubeadm/v{capi_version}/bootstrap-components.yaml"
    type: "BootstrapProvider"
  - name: "kubeadm"
    url: "file://{providers_dir}/control-plane-kubeadm/v{capi_version}/control-plane-components.yaml"
    type: "ControlPlaneProvider"
  - name: "rke2"
    url: "file://{providers_dir}/bootstrap-rke2/v{rke2_version}/bootstrap-components.yaml"
    type: "BootstrapProvider"
  - name: "rke2"
    url: "file://{providers_dir}/control-plane-rke2/v{rke2_version}/control-plane-components.yaml"
    type: "ControlPlaneProvider"
  - name: "docker"
    url: "file://{providers_dir}/infrastructure-docker/v{capi_version}/infrastructure-components-development.yaml"
    type: "InfrastructureProvider"
"#,
        providers_dir = providers_dir.display(),
        capi_version = versions.capi,
        rke2_version = versions.rke2,
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
