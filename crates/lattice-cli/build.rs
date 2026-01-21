use std::path::Path;

fn main() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR should be set by cargo");
    let workspace_root = Path::new(&manifest_dir)
        .parent()
        .expect("lattice-cli crate should have a parent directory")
        .parent()
        .expect("crates directory should have a parent (workspace root)");

    // Point to the same clusterctl config as the operator
    let providers_dir = workspace_root.join("test-providers");
    let config_path = providers_dir.join("clusterctl.yaml");

    println!(
        "cargo:rustc-env=CLUSTERCTL_CONFIG={}",
        config_path.display()
    );
    println!("cargo:rerun-if-changed={}", config_path.display());
}
