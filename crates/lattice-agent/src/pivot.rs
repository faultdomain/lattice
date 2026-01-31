//! Pivot support for cluster self-management (agent-side)
//!
//! This module provides:
//! - Kubeconfig patching for self-management (internal K8s endpoint)
//! - Distributed resource application (CloudProviders, SecretsProviders, Secrets)

use base64::{engine::general_purpose::STANDARD, Engine};
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use thiserror::Error;
use tracing::{debug, info};

use lattice_common::crd::{CloudProvider, SecretsProvider};
pub use lattice_common::DistributableResources;
use lattice_common::{INTERNAL_K8S_ENDPOINT, LATTICE_SYSTEM_NAMESPACE};

/// Pivot errors
#[derive(Debug, Error)]
pub enum PivotError {
    /// Kubeconfig generation failed
    #[error("kubeconfig generation failed: {0}")]
    KubeconfigFailed(String),

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}

// =============================================================================
// Kubeconfig Patching for Self-Management
// =============================================================================

async fn fetch_kubeconfig_from_secret(
    secrets: &Api<Secret>,
    secret_name: &str,
) -> Result<serde_json::Value, PivotError> {
    let secret = secrets.get(secret_name).await.map_err(|e| {
        PivotError::Internal(format!(
            "failed to get kubeconfig secret '{}': {}",
            secret_name, e
        ))
    })?;

    let data = secret
        .data
        .ok_or_else(|| PivotError::Internal("kubeconfig secret has no data".to_string()))?;

    let kubeconfig_bytes = data
        .get("value")
        .ok_or_else(|| PivotError::Internal("kubeconfig secret missing 'value' key".to_string()))?;

    let kubeconfig_str = String::from_utf8(kubeconfig_bytes.0.clone())
        .map_err(|e| PivotError::Internal(format!("kubeconfig is not valid UTF-8: {}", e)))?;

    lattice_common::yaml::parse_yaml(&kubeconfig_str)
        .map_err(|e| PivotError::Internal(format!("failed to parse kubeconfig YAML: {}", e)))
}

/// Path to the cluster CA certificate (available in all pods via service account)
const CLUSTER_CA_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

fn update_cluster_entry(cluster_entry: &mut serde_json::Value, cluster_name: &str) -> bool {
    let Some(cluster_config) = cluster_entry.get_mut("cluster") else {
        return false;
    };

    let Some(server) = cluster_config.get_mut("server") else {
        return false;
    };

    let old_server = server.as_str().unwrap_or("unknown").to_string();
    if old_server.contains("kubernetes.default.svc") {
        return false;
    }

    *server = serde_json::Value::String(INTERNAL_K8S_ENDPOINT.to_string());

    // Remove certificate-authority file path if present (won't work inside pod)
    if let Some(obj) = cluster_config.as_object_mut() {
        obj.remove("certificate-authority");
    }

    // Update certificate-authority-data with the cluster's CA
    // This is necessary because during air-gapped pivot, the kubeconfig may have
    // been patched to use the parent's proxy CA. After pivot, we need to use
    // the cluster's own CA for self-management.
    if let Ok(cluster_ca) = std::fs::read_to_string(CLUSTER_CA_PATH) {
        let ca_b64 = STANDARD.encode(cluster_ca.as_bytes());
        if let Some(obj) = cluster_config.as_object_mut() {
            obj.insert(
                "certificate-authority-data".to_string(),
                serde_json::Value::String(ca_b64),
            );
        }
        debug!(
            cluster = %cluster_name,
            "Updated kubeconfig CA to cluster CA from service account"
        );
    } else {
        // If we can't read the cluster CA, just leave certificate-authority-data as is
        // This handles the case where we're running outside of a pod (e.g., tests)
        debug!(
            cluster = %cluster_name,
            "Could not read cluster CA from service account, keeping existing CA"
        );
    }

    info!(
        cluster = %cluster_name,
        old_server = %old_server,
        new_server = INTERNAL_K8S_ENDPOINT,
        "Updated kubeconfig server URL"
    );

    true
}

fn update_all_cluster_entries(kubeconfig: &mut serde_json::Value, cluster_name: &str) -> usize {
    let Some(clusters) = kubeconfig
        .get_mut("clusters")
        .and_then(|c| c.as_array_mut())
    else {
        return 0;
    };

    let mut count = 0;
    for entry in clusters.iter_mut() {
        if update_cluster_entry(entry, cluster_name) {
            count += 1;
        }
    }
    count
}

async fn apply_kubeconfig_patch(
    secrets: &Api<Secret>,
    secret_name: &str,
    kubeconfig: &serde_json::Value,
) -> Result<(), PivotError> {
    // Serialize as JSON - Kubernetes accepts both JSON and YAML
    let updated_kubeconfig = serde_json::to_string(kubeconfig)
        .map_err(|e| PivotError::Internal(format!("failed to serialize kubeconfig: {}", e)))?;

    let encoded = STANDARD.encode(updated_kubeconfig.as_bytes());

    let patch = serde_json::json!({
        "data": {
            "value": encoded
        }
    });

    secrets
        .patch(
            secret_name,
            &PatchParams::apply("lattice"),
            &Patch::Merge(&patch),
        )
        .await
        .map_err(|e| PivotError::Internal(format!("failed to patch kubeconfig secret: {}", e)))?;

    Ok(())
}

/// Patch the kubeconfig secret to use the internal Kubernetes service endpoint.
pub async fn patch_kubeconfig_for_self_management(
    cluster_name: &str,
    namespace: &str,
) -> Result<(), PivotError> {
    info!(cluster = %cluster_name, namespace = %namespace, "Patching kubeconfig for self-management");

    let client = kube::Client::try_default()
        .await
        .map_err(|e| PivotError::Internal(format!("failed to create k8s client: {}", e)))?;

    let secrets: Api<Secret> = Api::namespaced(client, namespace);
    let secret_name = format!("{}-kubeconfig", cluster_name);

    let mut kubeconfig = fetch_kubeconfig_from_secret(&secrets, &secret_name).await?;

    let updated_count = update_all_cluster_entries(&mut kubeconfig, cluster_name);

    if updated_count == 0 {
        debug!(cluster = %cluster_name, "Kubeconfig already uses internal endpoint, skipping patch");
        return Ok(());
    }

    apply_kubeconfig_patch(&secrets, &secret_name, &kubeconfig).await?;

    info!(
        cluster = %cluster_name,
        updated_servers = updated_count,
        "Kubeconfig patched for self-management"
    );
    Ok(())
}

// =============================================================================
// Distributed Resources
// =============================================================================

/// Apply distributed resources to the lattice-system namespace.
pub async fn apply_distributed_resources(
    client: &Client,
    resources: &DistributableResources,
) -> Result<(), PivotError> {
    if resources.is_empty() {
        return Ok(());
    }

    let params = PatchParams::apply("lattice-pivot").force();

    // Apply secrets first (credentials needed by providers)
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    for secret_bytes in &resources.secrets {
        let yaml_str = String::from_utf8_lossy(secret_bytes);
        let value = lattice_common::yaml::parse_yaml(&yaml_str)
            .map_err(|e| PivotError::Internal(format!("failed to parse secret YAML: {}", e)))?;
        let secret: Secret = serde_json::from_value(value)
            .map_err(|e| PivotError::Internal(format!("failed to deserialize secret: {}", e)))?;

        let name = secret
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| PivotError::Internal("secret has no name".to_string()))?;

        secret_api
            .patch(name, &params, &Patch::Apply(&secret))
            .await
            .map_err(|e| PivotError::Internal(format!("failed to apply secret {}: {}", name, e)))?;

        info!(secret = %name, "Applied distributed secret");
    }

    // Apply CloudProviders
    let cp_api: Api<CloudProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    for cp_bytes in &resources.cloud_providers {
        let yaml_str = String::from_utf8_lossy(cp_bytes);
        let value = lattice_common::yaml::parse_yaml(&yaml_str).map_err(|e| {
            PivotError::Internal(format!("failed to parse CloudProvider YAML: {}", e))
        })?;
        let cp: CloudProvider = serde_json::from_value(value).map_err(|e| {
            PivotError::Internal(format!("failed to deserialize CloudProvider: {}", e))
        })?;

        let name = cp
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| PivotError::Internal("CloudProvider has no name".to_string()))?;

        cp_api
            .patch(name, &params, &Patch::Apply(&cp))
            .await
            .map_err(|e| {
                PivotError::Internal(format!("failed to apply CloudProvider {}: {}", name, e))
            })?;

        info!(cloud_provider = %name, "Applied distributed CloudProvider");
    }

    // Apply SecretsProviders
    let sp_api: Api<SecretsProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    for sp_bytes in &resources.secrets_providers {
        let yaml_str = String::from_utf8_lossy(sp_bytes);
        let value = lattice_common::yaml::parse_yaml(&yaml_str).map_err(|e| {
            PivotError::Internal(format!("failed to parse SecretsProvider YAML: {}", e))
        })?;
        let sp: SecretsProvider = serde_json::from_value(value).map_err(|e| {
            PivotError::Internal(format!("failed to deserialize SecretsProvider: {}", e))
        })?;

        let name = sp
            .metadata
            .name
            .as_ref()
            .ok_or_else(|| PivotError::Internal("SecretsProvider has no name".to_string()))?;

        sp_api
            .patch(name, &params, &Patch::Apply(&sp))
            .await
            .map_err(|e| {
                PivotError::Internal(format!("failed to apply SecretsProvider {}: {}", name, e))
            })?;

        info!(secrets_provider = %name, "Applied distributed SecretsProvider");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::yaml::parse_yaml;

    #[test]
    fn test_update_cluster_entry_updates_server() {
        let mut entry = parse_yaml(
            r#"
            name: test-cluster
            cluster:
              server: https://172.18.0.3:6443
              certificate-authority: /path/to/ca
            "#,
        )
        .unwrap();

        let updated = update_cluster_entry(&mut entry, "test");
        assert!(updated);

        let server = entry["cluster"]["server"].as_str().unwrap();
        assert_eq!(server, INTERNAL_K8S_ENDPOINT);
        // certificate-authority file path should be removed
        assert!(entry["cluster"]["certificate-authority"].is_null());
    }

    #[test]
    fn test_update_cluster_entry_skips_already_internal() {
        let mut entry = parse_yaml(
            r#"
            name: test-cluster
            cluster:
              server: https://kubernetes.default.svc:443
            "#,
        )
        .unwrap();

        let updated = update_cluster_entry(&mut entry, "test");
        assert!(!updated);
    }

    #[test]
    fn test_distributable_resources_is_empty() {
        let empty = DistributableResources::default();
        assert!(empty.is_empty());

        let with_cp = DistributableResources {
            cloud_providers: vec![vec![1, 2, 3]],
            ..Default::default()
        };
        assert!(!with_cp.is_empty());
    }

    #[test]
    fn test_update_all_cluster_entries_multiple() {
        let mut kubeconfig = parse_yaml(
            r#"
            clusters:
              - name: cluster-1
                cluster:
                  server: https://172.18.0.2:6443
                  certificate-authority: /path/to/ca
              - name: cluster-2
                cluster:
                  server: https://172.18.0.3:6443
            "#,
        )
        .unwrap();

        let count = update_all_cluster_entries(&mut kubeconfig, "test");
        assert_eq!(count, 2);
    }

    #[test]
    fn test_update_all_cluster_entries_mixed() {
        let mut kubeconfig = parse_yaml(
            r#"
            clusters:
              - name: external
                cluster:
                  server: https://172.18.0.2:6443
              - name: internal
                cluster:
                  server: https://kubernetes.default.svc:443
            "#,
        )
        .unwrap();

        let count = update_all_cluster_entries(&mut kubeconfig, "test");
        // Only the external one should be updated
        assert_eq!(count, 1);
    }

    #[test]
    fn test_update_all_cluster_entries_no_clusters() {
        let mut kubeconfig = parse_yaml(
            r#"
            apiVersion: v1
            kind: Config
            "#,
        )
        .unwrap();

        let count = update_all_cluster_entries(&mut kubeconfig, "test");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_update_cluster_entry_missing_cluster_key() {
        let mut entry = parse_yaml(
            r#"
            name: test-cluster
            "#,
        )
        .unwrap();

        let updated = update_cluster_entry(&mut entry, "test");
        assert!(!updated);
    }

    #[test]
    fn test_update_cluster_entry_missing_server() {
        let mut entry = parse_yaml(
            r#"
            name: test-cluster
            cluster:
              certificate-authority: /path/to/ca
            "#,
        )
        .unwrap();

        let updated = update_cluster_entry(&mut entry, "test");
        assert!(!updated);
    }
}
