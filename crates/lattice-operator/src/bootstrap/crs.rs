//! ClusterResourceSet manifest generation for CLI-based bootstrap
//!
//! This module provides functions to generate YAML manifests for
//! ClusterResourceSet-based bootstrap. Used by the CLI installer
//! for the initial kind cluster (which cannot be reached externally).

/// Generate CRS YAML manifests for CLI usage
///
/// Returns a vector of YAML strings that can be applied via kubectl:
/// - ConfigMap for Cilium CNI
/// - ConfigMap for Lattice operator
/// - Secret for CAPMOX credentials (if Proxmox provider)
/// - ClusterResourceSet
///
/// This allows the CLI to share CRS generation logic with the operator.
pub fn generate_crs_yaml_manifests(
    cluster_name: &str,
    namespace: &str,
    all_manifests: &[String],
    capmox_credentials: Option<(&str, &str, &str)>,
) -> Vec<String> {
    let mut result = Vec::new();

    // Separate YAML manifests (Cilium) from JSON manifests (operator)
    let yaml_manifests: Vec<&str> = all_manifests
        .iter()
        .filter(|m| m.starts_with("---") || m.starts_with("apiVersion:"))
        .map(|s| s.as_str())
        .collect();

    let operator_manifests: Vec<&str> = all_manifests
        .iter()
        .filter(|m| m.starts_with("{"))
        .map(|s| s.as_str())
        .collect();

    // Cilium ConfigMap
    let cilium_yaml = yaml_manifests.join("\n---\n");
    let cilium_data_indented = cilium_yaml
        .lines()
        .map(|l| format!("    {}", l))
        .collect::<Vec<_>>()
        .join("\n");
    result.push(format!(
        r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-cni
  namespace: {namespace}
data:
  cilium.yaml: |
{cilium_data}"#,
        namespace = namespace,
        cilium_data = cilium_data_indented
    ));

    // Operator ConfigMap with numbered manifest files
    let mut operator_data_keys = String::new();
    for (i, manifest) in operator_manifests.iter().enumerate() {
        let key_name = format!("{:02}-manifest.json", i + 1);
        let indented = manifest
            .lines()
            .map(|l| format!("    {}", l))
            .collect::<Vec<_>>()
            .join("\n");
        operator_data_keys.push_str(&format!("  {}: |\n{}\n", key_name, indented));
    }
    result.push(format!(
        r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: lattice-operator
  namespace: {namespace}
data:
{operator_data}"#,
        namespace = namespace,
        operator_data = operator_data_keys.trim_end()
    ));

    // Build CRS resources list
    let mut crs_resources = String::from(
        r#"    - kind: ConfigMap
      name: cilium-cni
    - kind: ConfigMap
      name: lattice-operator"#,
    );

    // CAPMOX credentials secret if provided
    if let Some((url, token, secret)) = capmox_credentials {
        crs_resources.push_str(
            r#"
    - kind: Secret
      name: capmox-credentials"#,
        );

        let capmox_manifests = super::capmox_credentials_manifests(url, token, secret);
        let capmox_data_indented = capmox_manifests
            .lines()
            .map(|l| format!("    {}", l))
            .collect::<Vec<_>>()
            .join("\n");

        result.push(format!(
            r#"apiVersion: v1
kind: Secret
metadata:
  name: capmox-credentials
  namespace: {namespace}
type: addons.cluster.x-k8s.io/resource-set
stringData:
  capmox.yaml: |
{capmox_data}"#,
            namespace = namespace,
            capmox_data = capmox_data_indented
        ));
    }

    // ClusterResourceSet
    result.push(format!(
        r#"apiVersion: addons.cluster.x-k8s.io/v1beta2
kind: ClusterResourceSet
metadata:
  name: {cluster_name}-bootstrap
  namespace: {namespace}
spec:
  strategy: ApplyOnce
  clusterSelector:
    matchLabels:
      cluster.x-k8s.io/cluster-name: {cluster_name}
  resources:
{crs_resources}"#,
        cluster_name = cluster_name,
        namespace = namespace,
        crs_resources = crs_resources
    ));

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_crs_yaml_manifests_basic() {
        let all_manifests = vec![
            "---\napiVersion: v1\nkind: ConfigMap".to_string(),
            r#"{"kind": "Deployment"}"#.to_string(),
        ];

        let result =
            generate_crs_yaml_manifests("my-cluster", "capi-my-cluster", &all_manifests, None);

        assert_eq!(result.len(), 3); // cilium cm, operator cm, crs

        // Check cilium ConfigMap
        assert!(result[0].contains("kind: ConfigMap"));
        assert!(result[0].contains("name: cilium-cni"));
        assert!(result[0].contains("namespace: capi-my-cluster"));

        // Check operator ConfigMap
        assert!(result[1].contains("kind: ConfigMap"));
        assert!(result[1].contains("name: lattice-operator"));
        assert!(result[1].contains("01-manifest.json"));

        // Check ClusterResourceSet
        assert!(result[2].contains("kind: ClusterResourceSet"));
        assert!(result[2].contains("name: my-cluster-bootstrap"));
        assert!(result[2].contains("cluster.x-k8s.io/cluster-name: my-cluster"));
    }

    #[test]
    fn test_generate_crs_yaml_manifests_with_capmox() {
        let all_manifests = vec!["apiVersion: v1\nkind: ConfigMap".to_string()];

        let result = generate_crs_yaml_manifests(
            "proxmox-cluster",
            "capi-proxmox-cluster",
            &all_manifests,
            Some(("https://proxmox.local:8006", "user@pve!token", "secret123")),
        );

        assert_eq!(result.len(), 4); // cilium cm, operator cm, capmox secret, crs

        // Check CAPMOX secret is present
        assert!(result[2].contains("kind: Secret"));
        assert!(result[2].contains("name: capmox-credentials"));
        assert!(result[2].contains("type: addons.cluster.x-k8s.io/resource-set"));

        // Check CRS references the secret
        assert!(result[3].contains("name: capmox-credentials"));
    }

    #[test]
    fn test_generate_crs_yaml_manifests_separates_yaml_and_json() {
        let all_manifests = vec![
            "---\napiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy".to_string(),
            "apiVersion: v1\nkind: Namespace".to_string(),
            r#"{"apiVersion": "v1", "kind": "ServiceAccount"}"#.to_string(),
            r#"{"apiVersion": "apps/v1", "kind": "Deployment"}"#.to_string(),
        ];

        let result = generate_crs_yaml_manifests("test", "capi-test", &all_manifests, None);

        // Cilium CM should have YAML manifests
        assert!(result[0].contains("CiliumNetworkPolicy"));
        assert!(result[0].contains("kind: Namespace"));

        // Operator CM should have JSON manifests
        assert!(result[1].contains("01-manifest.json"));
        assert!(result[1].contains("02-manifest.json"));
        assert!(result[1].contains("ServiceAccount"));
        assert!(result[1].contains("Deployment"));
    }

    #[test]
    fn test_generate_crs_yaml_manifests_crs_strategy() {
        let all_manifests = vec!["apiVersion: v1\nkind: ConfigMap".to_string()];

        let result = generate_crs_yaml_manifests("cluster", "ns", &all_manifests, None);

        // Verify CRS uses ApplyOnce strategy
        assert!(result[2].contains("strategy: ApplyOnce"));
    }

    #[test]
    fn test_generate_crs_yaml_manifests_cluster_selector() {
        let all_manifests = vec!["apiVersion: v1\nkind: ConfigMap".to_string()];

        let result =
            generate_crs_yaml_manifests("target-cluster", "capi-target", &all_manifests, None);

        // CRS should select the correct cluster
        let crs = &result[2];
        assert!(crs.contains("clusterSelector:"));
        assert!(crs.contains("matchLabels:"));
        assert!(crs.contains("cluster.x-k8s.io/cluster-name: target-cluster"));
    }

    #[test]
    fn test_generate_crs_yaml_manifests_empty_inputs() {
        let all_manifests: Vec<String> = vec![];

        let result = generate_crs_yaml_manifests("empty", "capi-empty", &all_manifests, None);

        // Should still generate valid structures even with no manifests
        assert_eq!(result.len(), 3);
        assert!(result[0].contains("name: cilium-cni"));
        assert!(result[1].contains("name: lattice-operator"));
        assert!(result[2].contains("kind: ClusterResourceSet"));
    }
}
