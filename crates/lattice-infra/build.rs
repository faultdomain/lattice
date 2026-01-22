use std::path::Path;

fn main() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR should be set by cargo");
    // Go up two levels: crates/lattice-infra -> workspace root
    let workspace_root = Path::new(&manifest_dir)
        .parent()
        .expect("lattice-infra crate should have a parent directory")
        .parent()
        .expect("crates directory should have a parent (workspace root)");

    let versions_path = workspace_root.join("versions.toml");
    println!("cargo:rerun-if-changed={}", versions_path.display());

    let content = match std::fs::read_to_string(&versions_path) {
        Ok(c) => c,
        Err(_) => {
            // Use defaults if versions.toml not found
            println!("cargo:rustc-env=CILIUM_VERSION=1.16.0");
            println!("cargo:rustc-env=ISTIO_VERSION=1.24.0");
            println!("cargo:rustc-env=GATEWAY_API_VERSION=1.2.1");
            return;
        }
    };

    let mut cilium = String::new();
    let mut istio = String::new();
    let mut gateway_api = String::new();
    let mut section = "";

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = line.trim_matches(|c| c == '[' || c == ']');
        } else if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"');
            match (section, key) {
                ("charts", "cilium") => cilium = value.to_string(),
                ("charts", "istio") => istio = value.to_string(),
                ("gateway-api", "version") => gateway_api = value.to_string(),
                _ => {}
            }
        }
    }

    println!("cargo:rustc-env=CILIUM_VERSION={}", cilium);
    println!("cargo:rustc-env=ISTIO_VERSION={}", istio);
    println!("cargo:rustc-env=GATEWAY_API_VERSION={}", gateway_api);

    // Set charts directory for local development
    let charts_dir = workspace_root.join("test-charts");
    println!(
        "cargo:rustc-env=LATTICE_CHARTS_DIR={}",
        charts_dir.display()
    );
}
