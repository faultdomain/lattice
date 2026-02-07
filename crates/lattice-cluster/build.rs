//! Build script for lattice-cluster
//!
//! Sets compile-time environment variables for CAPI provider versions and paths.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct Versions {
    providers: HashMap<String, Provider>,
}

#[derive(Debug, Deserialize)]
struct Provider {
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

    // Set paths
    let scripts_dir = workspace_root.join("scripts/runtime");
    let providers_dir = workspace_root.join("test-providers");

    println!(
        "cargo:rustc-env=LATTICE_SCRIPTS_DIR={}",
        scripts_dir.display()
    );
    println!("cargo:rustc-env=PROVIDERS_DIR={}", providers_dir.display());

    let content = std::fs::read_to_string(&versions_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", versions_path.display(), e));

    let versions: Versions = toml::from_str(&content).expect("versions.toml should be valid TOML");

    println!(
        "cargo:rustc-env=CAPI_VERSION={}",
        versions.providers["cluster-api"].version
    );
    println!(
        "cargo:rustc-env=RKE2_VERSION={}",
        versions.providers["bootstrap-rke2"].version
    );
    println!(
        "cargo:rustc-env=CAPMOX_VERSION={}",
        versions.providers["infrastructure-proxmox"].version
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
        "cargo:rustc-env=IPAM_IN_CLUSTER_VERSION={}",
        versions.providers["ipam-in-cluster"].version
    );
}
