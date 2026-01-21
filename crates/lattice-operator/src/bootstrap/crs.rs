//! ClusterResourceSet manifest generation for CLI-based bootstrap
//!
//! This module provides functions to generate YAML manifests for
//! ClusterResourceSet-based bootstrap. Used by the CLI installer
//! for the initial kind cluster (which cannot be reached externally).

/// Default size limit for ConfigMap data to stay under etcd's 1 MiB limit
pub const DEFAULT_CHUNK_SIZE: usize = 800 * 1024;

/// Chunk manifests into groups that fit within a size limit
///
/// Each chunk will be under `max_size` bytes when combined, except for
/// individual manifests that exceed the limit (they get their own chunk).
pub fn chunk_manifests(manifests: &[String], max_size: usize) -> Vec<Vec<String>> {
    let mut chunks = Vec::new();
    let mut current_chunk = Vec::new();
    let mut current_size = 0;

    for manifest in manifests {
        let manifest_size = manifest.len();

        // If single manifest exceeds limit, it gets its own chunk
        if manifest_size > max_size {
            // Flush current chunk first
            if !current_chunk.is_empty() {
                chunks.push(current_chunk);
                current_chunk = Vec::new();
                current_size = 0;
            }
            chunks.push(vec![manifest.clone()]);
            continue;
        }

        // Would adding this manifest exceed the limit?
        if current_size + manifest_size > max_size && !current_chunk.is_empty() {
            chunks.push(current_chunk);
            current_chunk = Vec::new();
            current_size = 0;
        }

        current_chunk.push(manifest.clone());
        current_size += manifest_size;
    }

    // Don't forget the last chunk
    if !current_chunk.is_empty() {
        chunks.push(current_chunk);
    }

    chunks
}

/// Generate ConfigMaps from chunked manifests
///
/// Returns (configmap_yamls, configmap_names) for use in ClusterResourceSet.
pub fn generate_chunked_configmaps(
    namespace: &str,
    prefix: &str,
    manifests: &[String],
    max_size: usize,
) -> (Vec<String>, Vec<String>) {
    let chunks = chunk_manifests(manifests, max_size);
    let mut configmaps = Vec::new();
    let mut names = Vec::new();

    for (i, chunk) in chunks.iter().enumerate() {
        let name = format!("{}-{:02}", prefix, i);
        names.push(name.clone());

        let combined = chunk.join("\n---\n");
        let indented = combined
            .lines()
            .map(|l| format!("    {}", l))
            .collect::<Vec<_>>()
            .join("\n");

        configmaps.push(format!(
            r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: {name}
  namespace: {namespace}
data:
  manifests.yaml: |
{indented}"#
        ));
    }

    (configmaps, names)
}

/// Generate ClusterResourceSet referencing ConfigMaps
pub fn generate_crs(
    cluster_name: &str,
    namespace: &str,
    configmap_names: &[String],
    secret_name: Option<&str>,
) -> String {
    let mut resources = String::new();
    for name in configmap_names {
        resources.push_str(&format!(
            r#"    - kind: ConfigMap
      name: {}
"#,
            name
        ));
    }
    if let Some(secret) = secret_name {
        resources.push_str(&format!(
            r#"    - kind: Secret
      name: {}
"#,
            secret
        ));
    }

    format!(
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
{resources}"#,
        resources = resources.trim_end()
    )
}

/// Generate CRS YAML manifests for CLI usage
///
/// Returns a vector of YAML strings that can be applied via kubectl:
/// - Chunked ConfigMaps for all manifests (split to stay under 512KB each)
/// - Secret for CAPMOX credentials (if Proxmox provider)
/// - ClusterResourceSet referencing all ConfigMaps
///
/// This allows the CLI to share CRS generation logic with the operator.
pub fn generate_crs_yaml_manifests(
    cluster_name: &str,
    namespace: &str,
    all_manifests: &[String],
    capmox_credentials: Option<(&str, &str, &str)>,
) -> Vec<String> {
    let mut result = Vec::new();

    // Chunk all manifests into ConfigMaps
    let (configmaps, configmap_names) =
        generate_chunked_configmaps(namespace, "bootstrap", all_manifests, DEFAULT_CHUNK_SIZE);
    result.extend(configmaps);

    // CAPMOX credentials secret if provided
    let secret_name = if let Some((url, token, secret)) = capmox_credentials {
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
            capmox_data = capmox_data_indented
        ));
        Some("capmox-credentials")
    } else {
        None
    };

    // ClusterResourceSet referencing all chunks
    result.push(generate_crs(
        cluster_name,
        namespace,
        &configmap_names,
        secret_name,
    ));

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_crs_yaml_manifests_basic() {
        let all_manifests = vec![
            "apiVersion: v1\nkind: ConfigMap".to_string(),
            "apiVersion: apps/v1\nkind: Deployment".to_string(),
        ];

        let result =
            generate_crs_yaml_manifests("my-cluster", "capi-my-cluster", &all_manifests, None);

        // ConfigMap(s) + CRS
        assert!(result.len() >= 2);

        // First should be a ConfigMap
        assert!(result[0].contains("kind: ConfigMap"));
        assert!(result[0].contains("name: bootstrap-00"));
        assert!(result[0].contains("namespace: capi-my-cluster"));

        // Last should be ClusterResourceSet
        let crs = result
            .last()
            .expect("result should have at least one element");
        assert!(crs.contains("kind: ClusterResourceSet"));
        assert!(crs.contains("name: my-cluster-bootstrap"));
        assert!(crs.contains("cluster.x-k8s.io/cluster-name: my-cluster"));
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

        // Should have ConfigMap(s), CAPMOX secret, CRS
        assert!(result.len() >= 3);

        // Check CAPMOX secret is present (second to last)
        let secret = &result[result.len() - 2];
        assert!(secret.contains("kind: Secret"));
        assert!(secret.contains("name: capmox-credentials"));
        assert!(secret.contains("type: addons.cluster.x-k8s.io/resource-set"));

        // Check CRS references the secret
        let crs = result
            .last()
            .expect("result should have at least one element");
        assert!(crs.contains("name: capmox-credentials"));
    }

    #[test]
    fn test_generate_crs_yaml_manifests_contains_all_manifests() {
        let all_manifests = vec![
            "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy".to_string(),
            "apiVersion: v1\nkind: Namespace".to_string(),
            "apiVersion: v1\nkind: ServiceAccount".to_string(),
            "apiVersion: apps/v1\nkind: Deployment".to_string(),
        ];

        let result = generate_crs_yaml_manifests("test", "capi-test", &all_manifests, None);

        // All manifests should be present in the ConfigMaps
        let configmaps: String = result[..result.len() - 1].join("\n");
        assert!(configmaps.contains("CiliumNetworkPolicy"));
        assert!(configmaps.contains("Namespace"));
        assert!(configmaps.contains("ServiceAccount"));
        assert!(configmaps.contains("Deployment"));
    }

    #[test]
    fn test_generate_crs_yaml_manifests_crs_strategy() {
        let all_manifests = vec!["apiVersion: v1\nkind: ConfigMap".to_string()];

        let result = generate_crs_yaml_manifests("cluster", "ns", &all_manifests, None);

        // Verify CRS uses ApplyOnce strategy
        let crs = result
            .last()
            .expect("result should have at least one element");
        assert!(crs.contains("strategy: ApplyOnce"));
    }

    #[test]
    fn test_generate_crs_yaml_manifests_cluster_selector() {
        let all_manifests = vec!["apiVersion: v1\nkind: ConfigMap".to_string()];

        let result =
            generate_crs_yaml_manifests("target-cluster", "capi-target", &all_manifests, None);

        // CRS should select the correct cluster
        let crs = result
            .last()
            .expect("result should have at least one element");
        assert!(crs.contains("clusterSelector:"));
        assert!(crs.contains("matchLabels:"));
        assert!(crs.contains("cluster.x-k8s.io/cluster-name: target-cluster"));
    }

    #[test]
    fn test_generate_crs_yaml_manifests_empty_inputs() {
        let all_manifests: Vec<String> = vec![];

        let result = generate_crs_yaml_manifests("empty", "capi-empty", &all_manifests, None);

        // Just CRS with no ConfigMaps
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("kind: ClusterResourceSet"));
    }

    // =========================================================================
    // Chunking tests
    // =========================================================================

    const TEST_CHUNK_SIZE: usize = 1000; // Small limit for testing

    #[test]
    fn test_chunk_manifests_small_fits_in_one() {
        let manifests = vec!["small".to_string(), "also small".to_string()];
        let chunks = chunk_manifests(&manifests, TEST_CHUNK_SIZE);

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 2);
    }

    #[test]
    fn test_chunk_manifests_splits_at_limit() {
        let big = "x".repeat(400);
        let manifests = vec![big.clone(), big.clone(), big];
        let chunks = chunk_manifests(&manifests, TEST_CHUNK_SIZE);

        // Two fit, third causes split
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 2);
        assert_eq!(chunks[1].len(), 1);
    }

    #[test]
    fn test_chunk_manifests_single_oversized_gets_own_chunk() {
        let huge = "x".repeat(2000);
        let small = "tiny".to_string();
        let manifests = vec![small.clone(), huge, small];

        let chunks = chunk_manifests(&manifests, TEST_CHUNK_SIZE);

        assert!(chunks.len() >= 2);
        // Oversized manifest is alone
        let huge_chunk = chunks
            .iter()
            .find(|c| c.iter().any(|m| m.len() > TEST_CHUNK_SIZE));
        assert!(huge_chunk.is_some());
        assert_eq!(huge_chunk.expect("huge chunk should exist").len(), 1);
    }

    #[test]
    fn test_chunk_manifests_empty_input() {
        let manifests: Vec<String> = vec![];
        let chunks = chunk_manifests(&manifests, TEST_CHUNK_SIZE);
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_generate_chunked_configmaps() {
        let manifests = vec!["apiVersion: v1\nkind: ConfigMap".to_string()];

        let (configmaps, names) =
            generate_chunked_configmaps("test-ns", "bootstrap", &manifests, TEST_CHUNK_SIZE);

        assert_eq!(configmaps.len(), 1);
        assert_eq!(names.len(), 1);
        assert!(configmaps[0].contains("name: bootstrap-00"));
        assert!(configmaps[0].contains("namespace: test-ns"));
        assert_eq!(names[0], "bootstrap-00");
    }

    #[test]
    fn test_generate_chunked_configmaps_multiple_chunks() {
        let big = "x".repeat(600);
        let manifests = vec![big.clone(), big.clone(), big];

        let (configmaps, names) =
            generate_chunked_configmaps("ns", "infra", &manifests, TEST_CHUNK_SIZE);

        assert!(configmaps.len() >= 2);
        assert_eq!(configmaps.len(), names.len());
        assert!(names.contains(&"infra-00".to_string()));
        assert!(names.contains(&"infra-01".to_string()));
    }

    #[test]
    fn test_crs_references_all_chunks() {
        let names = vec!["chunk-00".to_string(), "chunk-01".to_string()];
        let crs = generate_crs("cluster", "ns", &names, None);

        for name in &names {
            assert!(crs.contains(name), "CRS should reference {}", name);
        }
    }
}
