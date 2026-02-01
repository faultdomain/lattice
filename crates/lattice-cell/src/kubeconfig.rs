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

    // Check if already patched (contains proxy URL path)
    if kubeconfig_str.contains("/cluster/") {
        debug!(
            cluster = %cluster_name,
            "Kubeconfig already patched for proxy"
        );
        return Ok(true);
    }

    // Parse the existing kubeconfig and modify only server + CA, preserving credentials
    let mut config = lattice_common::yaml::parse_yaml(&kubeconfig_str)
        .map_err(|e| Error::internal(format!("failed to parse kubeconfig YAML: {}", e)))?;

    // Build the new server URL with cluster path
    let new_server = format!("{}/cluster/{}", proxy_url, cluster_name);
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
