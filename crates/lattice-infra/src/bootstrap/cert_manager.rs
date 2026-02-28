//! cert-manager manifest generation
//!
//! Embeds pre-rendered cert-manager manifests from build time.
//! Includes control-plane tolerations so cert-manager schedules on tainted CP nodes
//! before workers are available.

use std::sync::LazyLock;

use super::{namespace_yaml, split_yaml_documents};

static CERT_MANAGER_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = vec![namespace_yaml("cert-manager")];
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/cert-manager.yaml"
    ))));
    manifests
});

pub fn generate_cert_manager() -> &'static [String] {
    &CERT_MANAGER_MANIFESTS
}

pub fn cert_manager_version() -> &'static str {
    env!("CERT_MANAGER_VERSION")
}
