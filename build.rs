use std::path::Path;
use std::process::Command;

/// Helm chart versions - must match src/infra/cilium.rs and src/infra/istio.rs
const CILIUM_VERSION: &str = "1.16.5";
const ISTIO_VERSION: &str = "1.24.2";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile proto files
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/agent.proto"], &["proto"])?;

    // Re-run if proto files change
    println!("cargo:rerun-if-changed=proto/agent.proto");

    // Download helm charts for local development/testing if they don't exist
    download_helm_charts()?;

    Ok(())
}

/// Download helm charts for local testing if not present
fn download_helm_charts() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let charts_dir = Path::new(&manifest_dir).join("test-charts");

    // Check if all required charts exist
    let cilium_chart = charts_dir.join(format!("cilium-{}.tgz", CILIUM_VERSION));
    let base_chart = charts_dir.join(format!("base-{}.tgz", ISTIO_VERSION));
    let istiod_chart = charts_dir.join(format!("istiod-{}.tgz", ISTIO_VERSION));

    // Set env var for tests to find charts
    println!(
        "cargo:rustc-env=LATTICE_CHARTS_DIR={}",
        charts_dir.display()
    );

    if cilium_chart.exists() && base_chart.exists() && istiod_chart.exists() {
        // All charts present, nothing to do
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
    let _ = Command::new("helm").args(["repo", "update"]).output();

    // Pull charts if not present
    if !cilium_chart.exists() {
        eprintln!("Downloading Cilium chart v{}...", CILIUM_VERSION);
        let status = Command::new("helm")
            .args(["pull", "cilium/cilium", "--version", CILIUM_VERSION])
            .arg("--destination")
            .arg(&charts_dir)
            .status()?;
        if !status.success() {
            eprintln!("Failed to download Cilium chart");
        }
    }

    if !base_chart.exists() {
        eprintln!("Downloading Istio base chart v{}...", ISTIO_VERSION);
        let status = Command::new("helm")
            .args(["pull", "istio/base", "--version", ISTIO_VERSION])
            .arg("--destination")
            .arg(&charts_dir)
            .status()?;
        if !status.success() {
            eprintln!("Failed to download Istio base chart");
        }
    }

    if !istiod_chart.exists() {
        eprintln!("Downloading Istio istiod chart v{}...", ISTIO_VERSION);
        let status = Command::new("helm")
            .args(["pull", "istio/istiod", "--version", ISTIO_VERSION])
            .arg("--destination")
            .arg(&charts_dir)
            .status()?;
        if !status.success() {
            eprintln!("Failed to download Istio istiod chart");
        }
    }

    Ok(())
}
