//! AWS-specific addon manifests for ClusterResourceSets
//!
//! This module generates the AWS Cloud Controller Manager (CCM) and
//! EBS CSI Driver manifests that are deployed via ClusterResourceSet
//! to AWS clusters. Templates are loaded from the templates/ directory.

use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use minijinja::{context, Environment};
use std::collections::BTreeMap;

use super::crs::ClusterResourceSet;

/// AWS Cloud Controller Manager version
const AWS_CCM_VERSION: &str = "v1.28.3";

/// AWS EBS CSI Driver version
const AWS_EBS_CSI_VERSION: &str = "v1.25.0";

/// CCM template loaded at compile time
const CCM_TEMPLATE: &str = include_str!("../../templates/aws-ccm.yaml");

/// EBS CSI template loaded at compile time
const EBS_CSI_TEMPLATE: &str = include_str!("../../templates/aws-ebs-csi.yaml");

fn render_template(template: &str, version: &str) -> String {
    let mut env = Environment::new();
    env.add_template("manifest", template)
        .expect("Invalid template");
    env.get_template("manifest")
        .expect("Template not found")
        .render(context! { version => version })
        .expect("Failed to render template")
}

fn create_addon_configmap(
    name: &str,
    namespace: &str,
    data_key: &str,
    content: String,
) -> ConfigMap {
    let mut data = BTreeMap::new();
    data.insert(data_key.to_string(), content);

    let mut labels = BTreeMap::new();
    labels.insert("type".to_string(), "generated".to_string());

    let mut annotations = BTreeMap::new();
    annotations.insert("note".to_string(), "generated".to_string());

    ConfigMap {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    }
}

fn create_addon_crs(
    name: &str,
    namespace: &str,
    label_key: &str,
    configmap_name: &str,
) -> ClusterResourceSet {
    let mut crs = ClusterResourceSet {
        api_version: "addons.cluster.x-k8s.io/v1beta1".to_string(),
        kind: "ClusterResourceSet".to_string(),
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: super::crs::ClusterResourceSetSpec {
            strategy: "ApplyOnce".to_string(),
            cluster_selector: super::crs::ClusterSelector {
                match_labels: {
                    let mut labels = BTreeMap::new();
                    labels.insert(label_key.to_string(), "external".to_string());
                    labels
                },
            },
            resources: Vec::new(),
        },
    };
    crs.add_configmap(configmap_name);
    crs
}

/// Generate AWS Cloud Controller Manager ClusterResourceSet manifests
pub fn generate_ccm_crs(namespace: &str) -> Vec<String> {
    let manifest = render_template(CCM_TEMPLATE, AWS_CCM_VERSION);
    let configmap = create_addon_configmap("aws-ccm", namespace, "aws-ccm-external.yaml", manifest);
    let crs = create_addon_crs("crs-ccm", namespace, "ccm", "aws-ccm");

    vec![
        serde_yaml::to_string(&configmap).expect("ConfigMap serialization"),
        serde_yaml::to_string(&crs).expect("CRS serialization"),
    ]
}

/// Generate AWS EBS CSI Driver ClusterResourceSet manifests
pub fn generate_ebs_csi_crs(namespace: &str) -> Vec<String> {
    let manifest = render_template(EBS_CSI_TEMPLATE, AWS_EBS_CSI_VERSION);
    let configmap = create_addon_configmap(
        "aws-ebs-csi",
        namespace,
        "aws-ebs-csi-external.yaml",
        manifest,
    );
    let crs = create_addon_crs("crs-csi", namespace, "csi", "aws-ebs-csi");

    vec![
        serde_yaml::to_string(&configmap).expect("ConfigMap serialization"),
        serde_yaml::to_string(&crs).expect("CRS serialization"),
    ]
}

/// Generate all AWS addon ClusterResourceSet manifests (CCM + CSI)
pub fn generate_all_aws_addon_crs(namespace: &str) -> Vec<String> {
    let mut manifests = generate_ccm_crs(namespace);
    manifests.extend(generate_ebs_csi_crs(namespace));
    manifests
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ccm_crs() {
        let manifests = generate_ccm_crs("capi-test");

        assert_eq!(manifests.len(), 2);
        assert!(manifests[0].contains("kind: ConfigMap"));
        assert!(manifests[0].contains("name: aws-ccm"));
        assert!(manifests[1].contains("kind: ClusterResourceSet"));
        assert!(manifests[1].contains("ccm: external"));
    }

    #[test]
    fn test_generate_ebs_csi_crs() {
        let manifests = generate_ebs_csi_crs("capi-test");

        assert_eq!(manifests.len(), 2);
        assert!(manifests[0].contains("kind: ConfigMap"));
        assert!(manifests[0].contains("name: aws-ebs-csi"));
        assert!(manifests[1].contains("kind: ClusterResourceSet"));
        assert!(manifests[1].contains("csi: external"));
    }

    #[test]
    fn test_generate_all_aws_addon_crs() {
        let manifests = generate_all_aws_addon_crs("capi-test");

        assert_eq!(manifests.len(), 4); // 2 for CCM + 2 for CSI
    }

    #[test]
    fn test_ccm_manifest_contains_required_resources() {
        let manifest = render_template(CCM_TEMPLATE, AWS_CCM_VERSION);

        assert!(manifest.contains("kind: ServiceAccount"));
        assert!(manifest.contains("kind: ClusterRole"));
        assert!(manifest.contains("kind: ClusterRoleBinding"));
        assert!(manifest.contains("kind: DaemonSet"));
        assert!(manifest.contains("cloud-controller-manager"));
        assert!(manifest.contains("extension-apiserver-authentication-reader"));
    }

    #[test]
    fn test_ebs_csi_manifest_contains_required_resources() {
        let manifest = render_template(EBS_CSI_TEMPLATE, AWS_EBS_CSI_VERSION);

        assert!(manifest.contains("kind: ServiceAccount"));
        assert!(manifest.contains("kind: Deployment"));
        assert!(manifest.contains("kind: DaemonSet"));
        assert!(manifest.contains("kind: CSIDriver"));
        assert!(manifest.contains("kind: Secret"));
        assert!(manifest.contains("kind: PodDisruptionBudget"));
        assert!(manifest.contains("ebs.csi.aws.com"));
        assert!(manifest.contains("ebs-csi-node"));
        assert!(manifest.contains("ebs-external-resizer-role"));
        assert!(manifest.contains("ebs-external-snapshotter-role"));
    }
}
