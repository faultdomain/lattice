//! Build script for lattice-infra
//!
//! Sets compile-time environment variables for chart versions and paths.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct Versions {
    charts: HashMap<String, Chart>,
    resources: HashMap<String, Resource>,
}

#[derive(Debug, Deserialize)]
struct Chart {
    version: String,
}

#[derive(Debug, Deserialize)]
struct Resource {
    version: String,
}

fn main() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR should be set");
    let workspace_root = Path::new(&manifest_dir)
        .parent()
        .expect("crate should have parent")
        .parent()
        .expect("crates dir should have parent");

    let versions_path = workspace_root.join("versions.toml");
    println!("cargo:rerun-if-changed={}", versions_path.display());

    let content = std::fs::read_to_string(&versions_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", versions_path.display(), e));

    let versions: Versions = toml::from_str(&content).expect("versions.toml should be valid TOML");

    println!(
        "cargo:rustc-env=CILIUM_VERSION={}",
        versions.charts["cilium"].version
    );
    println!(
        "cargo:rustc-env=ISTIO_VERSION={}",
        versions.charts["istio-base"].version
    );
    println!(
        "cargo:rustc-env=GATEWAY_API_VERSION={}",
        versions.resources["gateway-api"].version
    );
    println!(
        "cargo:rustc-env=EXTERNAL_SECRETS_VERSION={}",
        versions.charts["external-secrets"].version
    );
    println!(
        "cargo:rustc-env=VELERO_VERSION={}",
        versions.charts["velero"].version
    );
    println!(
        "cargo:rustc-env=GPU_OPERATOR_VERSION={}",
        versions.charts["gpu-operator"].version
    );
    println!(
        "cargo:rustc-env=HAMI_VERSION={}",
        versions.charts["hami"].version
    );
    println!(
        "cargo:rustc-env=PROMETHEUS_ADAPTER_VERSION={}",
        versions.charts["prometheus-adapter"].version
    );
    println!(
        "cargo:rustc-env=VICTORIA_METRICS_VERSION={}",
        versions.charts["victoria-metrics-k8s-stack"].version
    );

    let charts_dir = workspace_root.join("test-charts");
    println!(
        "cargo:rustc-env=LATTICE_CHARTS_DIR={}",
        charts_dir.display()
    );
}
