use std::path::Path;
use std::process::Command;

/// Versions loaded from versions.toml - single source of truth
struct Versions {
    capi: String,
    rke2: String,
    capmox: String,
    capa: String,
    capo: String,
    ipam_in_cluster: String,
    cilium: String,
    istio: String,
    cert_manager: String,
    flux: String,
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
        capmox: String::new(),
        capa: String::new(),
        capo: String::new(),
        ipam_in_cluster: String::new(),
        cilium: String::new(),
        istio: String::new(),
        cert_manager: String::new(),
        flux: String::new(),
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
                ("capmox", "version") => versions.capmox = value.to_string(),
                ("capa", "version") => versions.capa = value.to_string(),
                ("capo", "version") => versions.capo = value.to_string(),
                ("ipam-in-cluster", "version") => versions.ipam_in_cluster = value.to_string(),
                ("charts", "cilium") => versions.cilium = value.to_string(),
                ("charts", "istio") => versions.istio = value.to_string(),
                ("charts", "cert-manager") => versions.cert_manager = value.to_string(),
                ("charts", "flux") => versions.flux = value.to_string(),
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
    println!("cargo:rustc-env=FLUX_VERSION={}", versions.flux);
    println!("cargo:rustc-env=CAPMOX_VERSION={}", versions.capmox);
    println!("cargo:rustc-env=CAPA_VERSION={}", versions.capa);
    println!("cargo:rustc-env=CAPO_VERSION={}", versions.capo);
    println!(
        "cargo:rustc-env=IPAM_IN_CLUSTER_VERSION={}",
        versions.ipam_in_cluster
    );

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
    let flux_chart = charts_dir.join(format!("flux2-{}.tgz", versions.flux));

    // Tell cargo to re-run if any chart is missing or changes
    println!("cargo:rerun-if-changed={}", cilium_chart.display());
    println!("cargo:rerun-if-changed={}", base_chart.display());
    println!("cargo:rerun-if-changed={}", istiod_chart.display());
    println!("cargo:rerun-if-changed={}", cni_chart.display());
    println!("cargo:rerun-if-changed={}", ztunnel_chart.display());
    println!("cargo:rerun-if-changed={}", cert_manager_chart.display());
    println!("cargo:rerun-if-changed={}", flux_chart.display());

    let all_charts = [
        &cilium_chart,
        &base_chart,
        &istiod_chart,
        &cni_chart,
        &ztunnel_chart,
        &cert_manager_chart,
        &flux_chart,
    ];

    if all_charts.iter().all(|c| c.exists()) {
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
    let _ = Command::new("helm")
        .args([
            "repo",
            "add",
            "fluxcd-community",
            "https://fluxcd-community.github.io/helm-charts",
        ])
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
    if !flux_chart.exists() {
        eprintln!("Downloading Flux chart v{}...", versions.flux);
        let _ = Command::new("helm")
            .args([
                "pull",
                "fluxcd-community/flux2",
                "--version",
                &versions.flux,
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
    let proxmox_dir = providers_dir
        .join("infrastructure-proxmox")
        .join(format!("v{}", versions.capmox));
    let aws_dir = providers_dir
        .join("infrastructure-aws")
        .join(format!("v{}", versions.capa));
    let openstack_dir = providers_dir
        .join("infrastructure-openstack")
        .join(format!("v{}", versions.capo));
    let ipam_dir = providers_dir
        .join("ipam-in-cluster")
        .join(format!("v{}", versions.ipam_in_cluster));

    let core = core_dir.join("core-components.yaml");
    let bootstrap_rke2 = bootstrap_rke2_dir.join("bootstrap-components.yaml");
    let proxmox = proxmox_dir.join("infrastructure-components.yaml");
    let aws = aws_dir.join("infrastructure-components.yaml");
    let openstack = openstack_dir.join("infrastructure-components.yaml");
    let ipam = ipam_dir.join("ipam-components.yaml");

    // Tell cargo to re-run if providers are missing or change
    println!("cargo:rerun-if-changed={}", core.display());
    println!("cargo:rerun-if-changed={}", bootstrap_rke2.display());
    println!("cargo:rerun-if-changed={}", proxmox.display());
    println!("cargo:rerun-if-changed={}", aws.display());
    println!("cargo:rerun-if-changed={}", openstack.display());
    println!("cargo:rerun-if-changed={}", ipam.display());
    println!("cargo:rerun-if-changed={}", config_path.display());

    if core.exists()
        && bootstrap_rke2.exists()
        && proxmox.exists()
        && aws.exists()
        && openstack.exists()
        && ipam.exists()
        && config_path.exists()
    {
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
    std::fs::create_dir_all(&proxmox_dir)?;
    std::fs::create_dir_all(&aws_dir)?;
    std::fs::create_dir_all(&openstack_dir)?;
    std::fs::create_dir_all(&ipam_dir)?;

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

    // Download CAPMOX (Proxmox) infrastructure provider
    let capmox_base_url = format!(
        "https://github.com/ionos-cloud/cluster-api-provider-proxmox/releases/download/v{}",
        versions.capmox
    );
    download_file(
        &format!("{}/infrastructure-components.yaml", capmox_base_url),
        &proxmox_dir.join("infrastructure-components.yaml"),
    );
    download_file(
        &format!("{}/metadata.yaml", capmox_base_url),
        &proxmox_dir.join("metadata.yaml"),
    );

    // Download CAPA (AWS) infrastructure provider
    let capa_base_url = format!(
        "https://github.com/kubernetes-sigs/cluster-api-provider-aws/releases/download/v{}",
        versions.capa
    );
    download_file(
        &format!("{}/infrastructure-components.yaml", capa_base_url),
        &aws_dir.join("infrastructure-components.yaml"),
    );
    download_file(
        &format!("{}/metadata.yaml", capa_base_url),
        &aws_dir.join("metadata.yaml"),
    );

    // Download CAPO (OpenStack) infrastructure provider
    let capo_base_url = format!(
        "https://github.com/kubernetes-sigs/cluster-api-provider-openstack/releases/download/v{}",
        versions.capo
    );
    download_file(
        &format!("{}/infrastructure-components.yaml", capo_base_url),
        &openstack_dir.join("infrastructure-components.yaml"),
    );
    download_file(
        &format!("{}/metadata.yaml", capo_base_url),
        &openstack_dir.join("metadata.yaml"),
    );

    // Download IPAM in-cluster provider (required by CAPMOX)
    let ipam_base_url = format!(
        "https://github.com/kubernetes-sigs/cluster-api-ipam-provider-in-cluster/releases/download/v{}",
        versions.ipam_in_cluster
    );
    download_file(
        &format!("{}/ipam-components.yaml", ipam_base_url),
        &ipam_dir.join("ipam-components.yaml"),
    );
    download_file(
        &format!("{}/metadata.yaml", ipam_base_url),
        &ipam_dir.join("metadata.yaml"),
    );

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
  - name: "proxmox"
    url: "file://{providers_dir}/infrastructure-proxmox/v{capmox_version}/infrastructure-components.yaml"
    type: "InfrastructureProvider"
  - name: "aws"
    url: "file://{providers_dir}/infrastructure-aws/v{capa_version}/infrastructure-components.yaml"
    type: "InfrastructureProvider"
  - name: "openstack"
    url: "file://{providers_dir}/infrastructure-openstack/v{capo_version}/infrastructure-components.yaml"
    type: "InfrastructureProvider"
  - name: "in-cluster"
    url: "file://{providers_dir}/ipam-in-cluster/v{ipam_version}/ipam-components.yaml"
    type: "IPAMProvider"
"#,
        providers_dir = providers_dir.display(),
        capi_version = versions.capi,
        rke2_version = versions.rke2,
        capmox_version = versions.capmox,
        capa_version = versions.capa,
        capo_version = versions.capo,
        ipam_version = versions.ipam_in_cluster,
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
