//! GPU stack manifest generation
//!
//! Embeds pre-rendered NVIDIA GPU Operator manifests from build time.
//! GPU scheduling uses Volcano's native vGPU device plugin (deployed alongside Volcano).

use std::sync::LazyLock;

use super::{namespace_yaml, split_yaml_documents};

/// Pre-rendered GPU stack manifests (GPU Operator) with namespaces.
static GPU_MANIFESTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut manifests = Vec::new();

    // GPU Operator
    manifests.push(namespace_yaml("gpu-operator"));
    manifests.extend(split_yaml_documents(include_str!(concat!(
        env!("OUT_DIR"),
        "/gpu-operator.yaml"
    ))));

    manifests
});

/// NVIDIA GPU Operator version (pinned at build time)
pub fn gpu_operator_version() -> &'static str {
    env!("GPU_OPERATOR_VERSION")
}

/// Generate GPU stack manifests (GPU Operator)
///
/// Returns pre-rendered manifests embedded at build time.
/// The Volcano vGPU device plugin is deployed as part of the Volcano stack,
/// not here, since it's a Volcano scheduler component.
pub fn generate_gpu_stack() -> &'static [String] {
    &GPU_MANIFESTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_operator_version_is_set() {
        let version = gpu_operator_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn gpu_namespace_is_correct() {
        let ns = namespace_yaml("gpu-operator");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: gpu-operator"));
    }

    #[test]
    fn manifests_are_embedded() {
        let manifests = generate_gpu_stack();
        assert!(!manifests.is_empty());
    }
}
