//! Kubeconfig patching for proxy access
//!
//! Patches CAPI-generated kubeconfig Secrets to route through the K8s API proxy.
//! This enables CAPI controllers to access child clusters through the gRPC tunnel.

use base64::{engine::general_purpose::STANDARD, Engine};
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use lattice_common::{kubeconfig_secret_name, Error};
use tracing::{debug, info};

// =============================================================================
// Pure Functions (unit-testable)
// =============================================================================

/// Check if a kubeconfig has already been patched for proxy access.
///
/// A kubeconfig is considered patched if its server URL contains "/clusters/",
/// which indicates it's using the proxy path format.
fn is_kubeconfig_patched(kubeconfig_str: &str) -> bool {
    kubeconfig_str.contains("/clusters/")
}

/// Patch a kubeconfig YAML string for proxy access.
///
/// This is a pure function that transforms the kubeconfig without any I/O.
/// It updates the server URL to route through the proxy and replaces the
/// CA certificate with the proxy's CA.
///
/// # Arguments
///
/// * `kubeconfig_str` - The original kubeconfig YAML/JSON string
/// * `proxy_url` - Base URL of the proxy (e.g., "https://lattice-cell.lattice-system.svc:8081")
/// * `cluster_name` - Name of the cluster (used in the proxy path)
/// * `ca_cert_pem` - PEM-encoded CA certificate for the proxy
///
/// # Returns
///
/// * `Ok(Some(patched))` - The patched kubeconfig as a JSON string
/// * `Ok(None)` - Kubeconfig is already patched, no changes needed
/// * `Err` - Failed to parse or serialize the kubeconfig
fn patch_kubeconfig_yaml(
    kubeconfig_str: &str,
    proxy_url: &str,
    cluster_name: &str,
    ca_cert_pem: &str,
) -> Result<Option<String>, Error> {
    // Check if already patched
    if is_kubeconfig_patched(kubeconfig_str) {
        return Ok(None);
    }

    // Parse the existing kubeconfig
    let mut config = lattice_core::yaml::parse_yaml(kubeconfig_str)
        .map_err(|e| Error::internal(format!("failed to parse kubeconfig YAML: {}", e)))?;

    // Build the new server URL with cluster path
    let new_server = format!("{}/clusters/{}", proxy_url, cluster_name);
    let ca_b64 = STANDARD.encode(ca_cert_pem.as_bytes());

    // Update only the cluster server and CA, preserving everything else
    if let Some(clusters) = config.get_mut("clusters").and_then(|c| c.as_array_mut()) {
        for cluster in clusters {
            if let Some(cluster_data) = cluster.get_mut("cluster") {
                // Update server URL
                if let Some(server) = cluster_data.get_mut("server") {
                    *server = serde_json::Value::String(new_server.clone());
                }
                // Update CA certificate
                if let Some(ca) = cluster_data.get_mut("certificate-authority-data") {
                    *ca = serde_json::Value::String(ca_b64.clone());
                } else {
                    // Add CA if not present
                    if let Some(obj) = cluster_data.as_object_mut() {
                        obj.insert(
                            "certificate-authority-data".to_string(),
                            serde_json::Value::String(ca_b64.clone()),
                        );
                    }
                }
            }
        }
    }

    // Serialize the modified kubeconfig as JSON (Kubernetes accepts both)
    let patched_kubeconfig = serde_json::to_string(&config)
        .map_err(|e| Error::internal(format!("failed to serialize kubeconfig: {}", e)))?;

    Ok(Some(patched_kubeconfig))
}

// =============================================================================
// K8s API Operations
// =============================================================================

/// Patch a CAPI-generated kubeconfig Secret to use the K8s API proxy.
///
/// This rewrites the Secret to point to the proxy URL with the operator's CA,
/// enabling CAPI controllers to access the child cluster through the gRPC tunnel.
///
/// This function modifies ONLY the server URL and CA certificate in the existing kubeconfig,
/// preserving all user credentials (client-certificate-data, client-key-data, token, etc.).
///
/// # Arguments
///
/// * `client` - Kubernetes client
/// * `cluster_name` - Name of the cluster
/// * `namespace` - Namespace containing the kubeconfig Secret (capi-{cluster})
/// * `proxy_url` - Base URL of the proxy (e.g., "https://lattice-cell.lattice-system.svc:8081")
/// * `ca_cert_pem` - PEM-encoded CA certificate for the proxy
///
/// # Returns
///
/// * `Ok(true)` - Kubeconfig was patched successfully
/// * `Ok(false)` - Kubeconfig Secret not ready yet (doesn't exist or missing data)
/// * `Err` - An error occurred
pub async fn patch_kubeconfig_for_proxy(
    client: &Client,
    cluster_name: &str,
    namespace: &str,
    proxy_url: &str,
    ca_cert_pem: &str,
) -> Result<bool, Error> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let secret_name = kubeconfig_secret_name(cluster_name);

    // Check if the Secret exists
    let secret = match secrets.get(&secret_name).await {
        Ok(s) => s,
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            debug!(
                cluster = %cluster_name,
                secret = %secret_name,
                "Kubeconfig Secret not found yet (CAPI still creating)"
            );
            return Ok(false);
        }
        Err(e) => return Err(e.into()),
    };

    // Get the current kubeconfig data
    let Some(data) = secret.data else {
        debug!(
            cluster = %cluster_name,
            "Kubeconfig Secret has no data"
        );
        return Ok(false);
    };

    let Some(kubeconfig_bytes) = data.get("value") else {
        debug!(
            cluster = %cluster_name,
            "Kubeconfig Secret missing 'value' key"
        );
        return Ok(false);
    };

    // Parse the kubeconfig as YAML
    let kubeconfig_str = String::from_utf8(kubeconfig_bytes.0.clone())
        .map_err(|e| Error::internal(format!("kubeconfig is not valid UTF-8: {}", e)))?;

    // Transform using pure function
    let Some(patched_kubeconfig) =
        patch_kubeconfig_yaml(&kubeconfig_str, proxy_url, cluster_name, ca_cert_pem)?
    else {
        debug!(
            cluster = %cluster_name,
            "Kubeconfig already patched for proxy"
        );
        return Ok(true);
    };

    // Encode and patch
    let encoded = STANDARD.encode(patched_kubeconfig.as_bytes());

    let patch = serde_json::json!({
        "data": {
            "value": encoded
        }
    });

    secrets
        .patch(
            &secret_name,
            &PatchParams::apply("lattice-proxy"),
            &Patch::Merge(&patch),
        )
        .await?;

    info!(
        cluster = %cluster_name,
        proxy_url = %proxy_url,
        "Patched kubeconfig Secret to use K8s API proxy"
    );

    Ok(true)
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KUBECONFIG: &str = r#"
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMvakNDQWVhZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwcmRXSmwKY201bGRHVnpNQjRYRFRJME1URXhPVEUzTXpBd04xb1hEVE0wTVRFeE56RTNNekF3TjFvd0ZURVRNQkVHQTFVRQpBeE1LYTNWaVpYSnVaWFJsY3pDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBS3ZoCjBuNGlNT0JZVEprbGZlb2loTnZvK2tObHNaMVdmWGhsQlZKd2xyV0t3bFVVWHBPQkMzL0ZQME5EV0Y0cTZDT0EKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
    server: https://172.18.0.5:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: admin
  name: test-context
current-context: test-context
users:
- name: admin
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg==
    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQo=
"#;

    const TEST_CA_CERT: &str =
        "-----BEGIN CERTIFICATE-----\nNEWCACERTIFICATE\n-----END CERTIFICATE-----";

    #[test]
    fn test_is_kubeconfig_patched_false() {
        assert!(!is_kubeconfig_patched(TEST_KUBECONFIG));
    }

    #[test]
    fn test_is_kubeconfig_patched_true() {
        let patched = TEST_KUBECONFIG.replace("172.18.0.5:6443", "proxy.example.com/clusters/test");
        assert!(is_kubeconfig_patched(&patched));
    }

    #[test]
    fn test_patch_kubeconfig_yaml_updates_server() {
        let result = patch_kubeconfig_yaml(
            TEST_KUBECONFIG,
            "https://proxy.example.com:8443",
            "my-cluster",
            TEST_CA_CERT,
        )
        .unwrap();

        assert!(result.is_some());
        let patched = result.unwrap();
        assert!(patched.contains("https://proxy.example.com:8443/clusters/my-cluster"));
    }

    #[test]
    fn test_patch_kubeconfig_yaml_skips_if_already_patched() {
        let already_patched = TEST_KUBECONFIG.replace(
            "https://172.18.0.5:6443",
            "https://proxy.example.com/clusters/test",
        );
        let result = patch_kubeconfig_yaml(
            &already_patched,
            "https://proxy.example.com:8443",
            "my-cluster",
            TEST_CA_CERT,
        )
        .unwrap();

        assert!(result.is_none()); // Already patched, returns None
    }

    #[test]
    fn test_patch_kubeconfig_yaml_updates_ca() {
        let result = patch_kubeconfig_yaml(
            TEST_KUBECONFIG,
            "https://proxy.example.com:8443",
            "my-cluster",
            TEST_CA_CERT,
        )
        .unwrap()
        .unwrap();

        // Verify CA was updated (base64 encoded)
        let config: serde_json::Value = serde_json::from_str(&result).unwrap();
        let ca = config["clusters"][0]["cluster"]["certificate-authority-data"]
            .as_str()
            .unwrap();
        let decoded = STANDARD.decode(ca).unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert!(decoded_str.contains("NEWCACERTIFICATE"));
    }

    #[test]
    fn test_patch_kubeconfig_yaml_preserves_user_credentials() {
        let result = patch_kubeconfig_yaml(
            TEST_KUBECONFIG,
            "https://proxy.example.com:8443",
            "my-cluster",
            TEST_CA_CERT,
        )
        .unwrap()
        .unwrap();

        let config: serde_json::Value = serde_json::from_str(&result).unwrap();

        // Verify user credentials are preserved
        assert!(config["users"][0]["user"]["client-certificate-data"]
            .as_str()
            .is_some());
        assert!(config["users"][0]["user"]["client-key-data"]
            .as_str()
            .is_some());

        // Verify context is preserved
        assert_eq!(config["current-context"].as_str().unwrap(), "test-context");
    }

    #[test]
    fn test_patch_kubeconfig_yaml_multiple_clusters() {
        let multi_cluster = r#"
apiVersion: v1
clusters:
- cluster:
    server: https://172.18.0.5:6443
  name: cluster1
- cluster:
    server: https://172.18.0.6:6443
  name: cluster2
"#;
        let result = patch_kubeconfig_yaml(
            multi_cluster,
            "https://proxy.example.com:8443",
            "my-cluster",
            TEST_CA_CERT,
        )
        .unwrap()
        .unwrap();

        let config: serde_json::Value = serde_json::from_str(&result).unwrap();

        // Both clusters should have their server updated
        assert!(config["clusters"][0]["cluster"]["server"]
            .as_str()
            .unwrap()
            .contains("/clusters/my-cluster"));
        assert!(config["clusters"][1]["cluster"]["server"]
            .as_str()
            .unwrap()
            .contains("/clusters/my-cluster"));
    }

    #[test]
    fn test_patch_kubeconfig_yaml_adds_ca_if_missing() {
        let no_ca_kubeconfig = r#"
apiVersion: v1
clusters:
- cluster:
    server: https://172.18.0.5:6443
  name: test-cluster
"#;
        let result = patch_kubeconfig_yaml(
            no_ca_kubeconfig,
            "https://proxy.example.com:8443",
            "my-cluster",
            TEST_CA_CERT,
        )
        .unwrap()
        .unwrap();

        let config: serde_json::Value = serde_json::from_str(&result).unwrap();

        // CA should be added
        assert!(
            config["clusters"][0]["cluster"]["certificate-authority-data"]
                .as_str()
                .is_some()
        );
    }
}
