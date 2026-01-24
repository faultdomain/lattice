//! AWS-specific addon manifests
//!
//! Generates AWS Cloud Controller Manager (CCM) and EBS CSI Driver manifests.
//! These are included in the bootstrap manifests via `generate_all_manifests()`.

use minijinja::{context, Environment};

/// AWS EBS CSI Driver version (not tied to Kubernetes version)
const AWS_EBS_CSI_VERSION: &str = "v1.54.0";

/// CCM template loaded at compile time
const CCM_TEMPLATE: &str = include_str!("../../templates/aws-ccm.yaml");

/// EBS CSI template loaded at compile time
const EBS_CSI_TEMPLATE: &str = include_str!("../../templates/aws-ebs-csi.yaml");

/// Convert Kubernetes version to CCM image tag.
///
/// CCM releases match Kubernetes versions. "1.32.0" -> "v1.32.0"
fn ccm_version_from_k8s(k8s_version: &str) -> String {
    let version = k8s_version.trim_start_matches('v');
    format!("v{}", version)
}

fn render_template(template: &str, version: &str) -> String {
    let mut env = Environment::new();
    env.add_template("manifest", template)
        .expect("Invalid template");
    env.get_template("manifest")
        .expect("Template not found")
        .render(context! { version => version })
        .expect("Failed to render template")
}

/// Generate raw AWS CCM manifest YAML.
///
/// The CCM version is derived from the Kubernetes version.
fn generate_ccm_manifest(k8s_version: &str) -> String {
    let ccm_version = ccm_version_from_k8s(k8s_version);
    render_template(CCM_TEMPLATE, &ccm_version)
}

/// Generate raw AWS EBS CSI Driver manifest YAML.
fn generate_ebs_csi_manifest() -> String {
    render_template(EBS_CSI_TEMPLATE, AWS_EBS_CSI_VERSION)
}

/// Generate all AWS addon manifests (CCM + EBS CSI) as raw YAML.
///
/// Returns a single YAML string with all resources separated by `---`.
/// Used by `generate_all_manifests()` to include AWS addons in bootstrap.
pub fn generate_aws_addon_manifests(k8s_version: &str) -> String {
    format!(
        "{}\n---\n{}",
        generate_ccm_manifest(k8s_version),
        generate_ebs_csi_manifest()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ccm_version_extraction() {
        assert_eq!(ccm_version_from_k8s("1.32.0"), "v1.32.0");
        assert_eq!(ccm_version_from_k8s("v1.32.0"), "v1.32.0");
        assert_eq!(ccm_version_from_k8s("1.30.5"), "v1.30.5");
    }

    #[test]
    fn raw_ccm_manifest_contains_required_resources() {
        let manifest = generate_ccm_manifest("1.32.0");

        assert!(manifest.contains("kind: ServiceAccount"));
        assert!(manifest.contains("kind: ClusterRole"));
        assert!(manifest.contains("kind: ClusterRoleBinding"));
        assert!(manifest.contains("kind: DaemonSet"));
        assert!(manifest.contains("cloud-controller-manager"));
        assert!(manifest.contains("v1.32.0"));
    }

    #[test]
    fn raw_ebs_csi_manifest_contains_required_resources() {
        let manifest = generate_ebs_csi_manifest();

        assert!(manifest.contains("kind: ServiceAccount"));
        assert!(manifest.contains("kind: Deployment"));
        assert!(manifest.contains("kind: DaemonSet"));
        assert!(manifest.contains("kind: CSIDriver"));
        assert!(manifest.contains("ebs.csi.aws.com"));
    }

    #[test]
    fn combined_addon_manifests() {
        let manifest = generate_aws_addon_manifests("1.32.0");

        // Contains both CCM and EBS CSI
        assert!(manifest.contains("cloud-controller-manager"));
        assert!(manifest.contains("ebs.csi.aws.com"));
        // Separated by ---
        assert!(manifest.contains("---"));
    }
}
