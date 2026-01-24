use std::path::Path;

fn main() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR should be set by cargo");
    let workspace_root = Path::new(&manifest_dir)
        .parent()
        .expect("lattice-cluster crate should have a parent directory")
        .parent()
        .expect("crates directory should have a parent (workspace root)");

    let versions_path = workspace_root.join("versions.toml");
    println!("cargo:rerun-if-changed={}", versions_path.display());

    let content = match std::fs::read_to_string(&versions_path) {
        Ok(c) => c,
        Err(_) => {
            // Use defaults if versions.toml not found
            println!("cargo:rustc-env=CAPI_VERSION=1.9.0");
            println!("cargo:rustc-env=RKE2_VERSION=0.9.0");
            println!("cargo:rustc-env=CAPMOX_VERSION=0.5.0");
            println!("cargo:rustc-env=CAPA_VERSION=2.7.0");
            println!("cargo:rustc-env=CAPO_VERSION=0.11.0");
            println!("cargo:rustc-env=IPAM_IN_CLUSTER_VERSION=0.2.0");

            let scripts_dir = workspace_root.join("scripts/runtime");
            println!(
                "cargo:rustc-env=LATTICE_SCRIPTS_DIR={}",
                scripts_dir.display()
            );

            let providers_dir = workspace_root.join("test-providers");
            let config_path = providers_dir.join("clusterctl.yaml");
            println!(
                "cargo:rustc-env=CLUSTERCTL_CONFIG={}",
                config_path.display()
            );
            return;
        }
    };

    let mut capi = String::new();
    let mut rke2 = String::new();
    let mut capmox = String::new();
    let mut capa = String::new();
    let mut capo = String::new();
    let mut ipam = String::new();
    let mut section = "";

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = line.trim_matches(|c| c == '[' || c == ']');
        } else if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"');
            match (section, key) {
                ("capi", "version") => capi = value.to_string(),
                ("rke2", "version") => rke2 = value.to_string(),
                ("capmox", "version") => capmox = value.to_string(),
                ("capa", "version") => capa = value.to_string(),
                ("capo", "version") => capo = value.to_string(),
                ("ipam-in-cluster", "version") => ipam = value.to_string(),
                _ => {}
            }
        }
    }

    println!("cargo:rustc-env=CAPI_VERSION={}", capi);
    println!("cargo:rustc-env=RKE2_VERSION={}", rke2);
    println!("cargo:rustc-env=CAPMOX_VERSION={}", capmox);
    println!("cargo:rustc-env=CAPA_VERSION={}", capa);
    println!("cargo:rustc-env=CAPO_VERSION={}", capo);
    println!("cargo:rustc-env=IPAM_IN_CLUSTER_VERSION={}", ipam);

    // Set paths for local development
    let scripts_dir = workspace_root.join("scripts/runtime");
    println!(
        "cargo:rustc-env=LATTICE_SCRIPTS_DIR={}",
        scripts_dir.display()
    );

    let providers_dir = workspace_root.join("test-providers");
    let config_path = providers_dir.join("clusterctl.yaml");
    println!(
        "cargo:rustc-env=CLUSTERCTL_CONFIG={}",
        config_path.display()
    );
}
