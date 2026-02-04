//! Kubeconfig generation endpoint
//!
//! Returns a multi-context kubeconfig with all clusters the user can access.
//!
//! ## Query Parameters
//!
//! - `format`: Optional. Controls the authentication method in the generated kubeconfig.
//!   - `oidc` (default): Uses OIDC exec plugin for human users
//!   - `sa`: Uses lattice token exec plugin for ServiceAccount token refresh
//!
//! - `kubeconfig`: Required when format=sa. Path to the kubeconfig for token refresh.
//! - `namespace`: ServiceAccount namespace (default: lattice-system, used with format=sa)
//! - `service_account`: ServiceAccount name (default: lattice-operator, used with format=sa)

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::auth::{authenticate, OidcConfig};
use crate::error::Error;
use crate::server::AppState;

/// Kubeconfig structure
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Kubeconfig {
    /// API version
    pub api_version: String,
    /// Kind (always "Config")
    pub kind: String,
    /// Clusters
    pub clusters: Vec<KubeconfigCluster>,
    /// Users
    pub users: Vec<KubeconfigUser>,
    /// Contexts
    pub contexts: Vec<KubeconfigContext>,
    /// Current context
    pub current_context: String,
}

/// Cluster entry in kubeconfig
#[derive(Debug, Serialize, Deserialize)]
pub struct KubeconfigCluster {
    /// Cluster name
    pub name: String,
    /// Cluster config
    pub cluster: ClusterConfig,
}

/// Cluster configuration
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClusterConfig {
    /// API server URL
    pub server: String,
    /// CA certificate (base64 encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_authority_data: Option<String>,
}

/// User entry in kubeconfig
#[derive(Debug, Serialize, Deserialize)]
pub struct KubeconfigUser {
    /// User name
    pub name: String,
    /// User config
    pub user: UserConfig,
}

/// User configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct UserConfig {
    /// Exec credential plugin
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec: Option<ExecConfig>,
    /// Bearer token (alternative to exec)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// Query parameters for kubeconfig endpoint
#[derive(Debug, Deserialize, Default)]
pub struct KubeconfigParams {
    /// Format: "oidc" (default) or "sa" (ServiceAccount with auto-refresh)
    #[serde(default)]
    pub format: Option<String>,
    /// Kubeconfig path for format=sa (where the ServiceAccount exists)
    #[serde(default)]
    pub kubeconfig: Option<String>,
    /// ServiceAccount namespace (default: lattice-system)
    #[serde(default)]
    pub namespace: Option<String>,
    /// ServiceAccount name (default: lattice-operator)
    #[serde(default)]
    pub service_account: Option<String>,
}

/// Exec credential plugin configuration
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecConfig {
    /// API version
    pub api_version: String,
    /// Command to run
    pub command: String,
    /// Arguments
    pub args: Vec<String>,
}

/// Context entry in kubeconfig
#[derive(Debug, Serialize, Deserialize)]
pub struct KubeconfigContext {
    /// Context name
    pub name: String,
    /// Context config
    pub context: ContextConfig,
}

/// Context configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct ContextConfig {
    /// Cluster name (reference)
    pub cluster: String,
    /// User name (reference)
    pub user: String,
}

/// Handle GET /kubeconfig
pub async fn kubeconfig_handler(
    State(state): State<AppState>,
    Query(params): Query<KubeconfigParams>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    // Authenticate (no Cedar authorization - kubeconfig just lists accessible clusters)
    let identity = authenticate(&state.auth, &headers).await?;

    // Get all clusters in subtree
    let subtree_clusters = state.subtree.all_clusters().await;

    // Update Cedar's known clusters and filter by authorization
    state
        .cedar
        .set_known_clusters(subtree_clusters.clone())
        .await;
    let accessible_clusters = state.cedar.accessible_clusters(&identity).await;

    if accessible_clusters.is_empty() {
        return Err(Error::Forbidden("No accessible clusters".into()));
    }

    // Build kubeconfig
    let kubeconfig = build_kubeconfig(
        &accessible_clusters,
        &identity.username,
        &state.base_url,
        state.oidc_config.as_ref(),
        &state.ca_cert_base64,
        &params,
    );

    // Return as JSON - kubectl accepts both JSON and YAML kubeconfigs
    let json = serde_json::to_string_pretty(&kubeconfig)
        .map_err(|e| Error::Internal(format!("Failed to serialize kubeconfig: {}", e)))?;

    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        json,
    )
        .into_response())
}

/// Build a multi-context kubeconfig
///
/// All server URLs point to the entry point cluster (base_url), which routes
/// internally via the subtree registry.
///
/// # Arguments
///
/// * `clusters` - List of cluster names the user can access
/// * `username` - Username for the kubeconfig user entry
/// * `base_url` - Base URL of the proxy (e.g., "https://lattice.example.com")
/// * `oidc_config` - OIDC configuration for exec plugin (used for OIDC format)
/// * `ca_cert_base64` - Base64-encoded CA certificate for TLS verification
/// * `params` - Query parameters controlling output format
fn build_kubeconfig(
    clusters: &[String],
    username: &str,
    base_url: &str,
    oidc_config: Option<&OidcConfig>,
    ca_cert_base64: &str,
    params: &KubeconfigParams,
) -> Kubeconfig {
    // Build cluster entries - all point to the same entry point but with different paths
    // CA cert is always included to ensure kubeconfigs are self-contained
    let cluster_entries: Vec<KubeconfigCluster> = clusters
        .iter()
        .map(|name| KubeconfigCluster {
            name: name.clone(),
            cluster: ClusterConfig {
                server: format!("{}/clusters/{}", base_url, name),
                certificate_authority_data: Some(ca_cert_base64.to_string()),
            },
        })
        .collect();

    // Build context entries
    let context_entries: Vec<KubeconfigContext> = clusters
        .iter()
        .map(|name| KubeconfigContext {
            name: name.clone(),
            context: ContextConfig {
                cluster: name.clone(),
                user: username.to_string(),
            },
        })
        .collect();

    // Build user config based on format parameter
    let user_config = match params.format.as_deref() {
        Some("sa") => {
            // ServiceAccount format: use lattice token exec plugin for automatic refresh
            let kubeconfig_path = params.kubeconfig.clone().unwrap_or_default();
            let namespace = params
                .namespace
                .clone()
                .unwrap_or_else(|| "lattice-system".to_string());
            let service_account = params
                .service_account
                .clone()
                .unwrap_or_else(|| "lattice-operator".to_string());

            UserConfig {
                exec: Some(ExecConfig {
                    api_version: "client.authentication.k8s.io/v1beta1".into(),
                    command: "lattice".into(),
                    args: vec![
                        "token".into(),
                        format!("--kubeconfig={}", kubeconfig_path),
                        format!("--namespace={}", namespace),
                        format!("--service-account={}", service_account),
                    ],
                }),
                token: None,
            }
        }
        _ => {
            // OIDC format (default): use kubectl oidc-login exec plugin
            let exec = oidc_config.map(|config| ExecConfig {
                api_version: "client.authentication.k8s.io/v1beta1".into(),
                command: "kubectl".into(),
                args: vec![
                    "oidc-login".into(),
                    "get-token".into(),
                    format!("--oidc-issuer-url={}", config.issuer_url),
                    format!("--oidc-client-id={}", config.client_id),
                ],
            });
            UserConfig { exec, token: None }
        }
    };

    let current_context = clusters.first().cloned().unwrap_or_default();

    Kubeconfig {
        api_version: "v1".into(),
        kind: "Config".into(),
        clusters: cluster_entries,
        users: vec![KubeconfigUser {
            name: username.to_string(),
            user: user_config,
        }],
        contexts: context_entries,
        current_context,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CA_CERT: &str = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t";

    #[test]
    fn test_build_kubeconfig_basic() {
        let clusters = vec!["prod-frontend".into(), "staging-frontend".into()];
        let params = KubeconfigParams::default();
        let config = build_kubeconfig(
            &clusters,
            "alice@example.com",
            "https://lattice.example.com",
            None,
            TEST_CA_CERT,
            &params,
        );

        assert_eq!(config.clusters.len(), 2);
        assert_eq!(config.contexts.len(), 2);
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.current_context, "prod-frontend");

        // CA cert always included
        assert_eq!(
            config.clusters[0].cluster.certificate_authority_data,
            Some(TEST_CA_CERT.to_string())
        );

        // Verify server URLs point to entry point
        assert_eq!(
            config.clusters[0].cluster.server,
            "https://lattice.example.com/clusters/prod-frontend"
        );
        assert_eq!(
            config.clusters[1].cluster.server,
            "https://lattice.example.com/clusters/staging-frontend"
        );
    }

    #[test]
    fn test_build_kubeconfig_with_oidc() {
        let clusters = vec!["test-cluster".into()];
        let oidc_config = OidcConfig {
            issuer_url: "https://idp.example.com".into(),
            client_id: "lattice".into(),
            ..Default::default()
        };
        let params = KubeconfigParams::default();

        let config = build_kubeconfig(
            &clusters,
            "alice@example.com",
            "https://lattice.example.com",
            Some(&oidc_config),
            TEST_CA_CERT,
            &params,
        );

        // Verify exec config is set
        let exec = config.users[0].user.exec.as_ref().unwrap();
        assert_eq!(exec.command, "kubectl");
        assert!(exec.args.contains(&"oidc-login".to_string()));
        assert!(exec
            .args
            .iter()
            .any(|a| a.contains("https://idp.example.com")));
        assert!(exec.args.iter().any(|a| a.contains("lattice")));
        assert!(config.users[0].user.token.is_none());
    }

    #[test]
    fn test_build_kubeconfig_with_sa_format() {
        let clusters = vec!["test-cluster".into()];
        let params = KubeconfigParams {
            format: Some("sa".to_string()),
            kubeconfig: Some("/path/to/kubeconfig".to_string()),
            namespace: Some("my-namespace".to_string()),
            service_account: Some("my-sa".to_string()),
        };

        let config = build_kubeconfig(
            &clusters,
            "system:serviceaccount:my-namespace:my-sa",
            "https://lattice.example.com",
            None,
            TEST_CA_CERT,
            &params,
        );

        // Verify exec config uses lattice token command
        let exec = config.users[0].user.exec.as_ref().unwrap();
        assert_eq!(exec.command, "lattice");
        assert!(exec.args.contains(&"token".to_string()));
        assert!(exec.args.iter().any(|a| a.contains("/path/to/kubeconfig")));
        assert!(exec.args.iter().any(|a| a.contains("my-namespace")));
        assert!(exec.args.iter().any(|a| a.contains("my-sa")));
        assert!(config.users[0].user.token.is_none());
    }

    #[test]
    fn test_build_kubeconfig_sa_format_defaults() {
        let clusters = vec!["test-cluster".into()];
        let params = KubeconfigParams {
            format: Some("sa".to_string()),
            kubeconfig: None,
            namespace: None,
            service_account: None,
        };

        let config = build_kubeconfig(
            &clusters,
            "default-user",
            "https://lattice.example.com",
            None,
            TEST_CA_CERT,
            &params,
        );

        // Verify defaults are used (lattice-system namespace, lattice-operator SA)
        let exec = config.users[0].user.exec.as_ref().unwrap();
        assert!(exec.args.iter().any(|a| a.contains("lattice-system")));
        assert!(exec
            .args
            .iter()
            .any(|a| a.contains("--service-account=lattice-operator")));
    }

    #[test]
    fn test_build_kubeconfig_empty_clusters() {
        let clusters: Vec<String> = vec![];
        let params = KubeconfigParams::default();
        let config = build_kubeconfig(
            &clusters,
            "alice@example.com",
            "https://lattice.example.com",
            None,
            TEST_CA_CERT,
            &params,
        );

        assert!(config.clusters.is_empty());
        assert!(config.contexts.is_empty());
        assert_eq!(config.current_context, "");
    }

    #[test]
    fn test_kubeconfig_params_default() {
        let params = KubeconfigParams::default();
        assert!(params.format.is_none());
    }
}
