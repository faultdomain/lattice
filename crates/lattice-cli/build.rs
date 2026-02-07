use std::path::Path;

fn main() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR should be set by cargo");
    let workspace_root = Path::new(&manifest_dir)
        .parent()
        .expect("lattice-cli crate should have a parent directory")
        .parent()
        .expect("crates directory should have a parent (workspace root)");

    let providers_dir = workspace_root.join("test-providers");

    println!(
        "cargo:rustc-env=PROVIDERS_DIR={}",
        providers_dir.display()
    );
    println!("cargo:rerun-if-changed={}", providers_dir.display());
}
