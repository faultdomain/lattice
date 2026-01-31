//! Kubeconfig generation endpoint
//!
//! Returns a multi-context kubeconfig with all clusters the user can access.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::auth::{extract_bearer_token, OidcConfig};
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
    headers: HeaderMap,
) -> Result<Response, Error> {
    // Extract and validate token
    let token = extract_bearer_token(&headers)
        .ok_or_else(|| Error::Unauthorized("Missing Authorization header".into()))?;

    let identity = state.oidc.validate(token).await?;

    // Get all clusters in subtree
    let subtree_clusters = state.subtree.all_clusters().await;

    // Update Cedar's known clusters and filter by authorization
    state.cedar.set_known_clusters(subtree_clusters.clone()).await;
    let accessible_clusters = state.cedar.accessible_clusters_async(&identity).await;

    if accessible_clusters.is_empty() {
        return Err(Error::Forbidden("No accessible clusters".into()));
    }

    // Build kubeconfig
    let kubeconfig = build_kubeconfig(
        &accessible_clusters,
        &identity.username,
        &state.base_url,
        state.oidc_config.as_ref(),
    );

    // Return as YAML
    let yaml = serde_yaml::to_string(&kubeconfig)
        .map_err(|e| Error::Internal(format!("Failed to serialize kubeconfig: {}", e)))?;

    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/x-yaml")],
        yaml,
    )
        .into_response())
}

/// Build a multi-context kubeconfig
///
/// All server URLs point to the entry point cluster (base_url), which routes
/// internally via the subtree registry.
fn build_kubeconfig(
    clusters: &[String],
    username: &str,
    base_url: &str,
    oidc_config: Option<&OidcConfig>,
) -> Kubeconfig {
    // Build cluster entries - all point to the same entry point but with different paths
    let cluster_entries: Vec<KubeconfigCluster> = clusters
        .iter()
        .map(|name| KubeconfigCluster {
            name: name.clone(),
            cluster: ClusterConfig {
                server: format!("{}/clusters/{}", base_url, name),
                certificate_authority_data: None, // TODO: Add CA from config
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

    // Build exec config based on OIDC settings
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

    let current_context = clusters.first().cloned().unwrap_or_default();

    Kubeconfig {
        api_version: "v1".into(),
        kind: "Config".into(),
        clusters: cluster_entries,
        users: vec![KubeconfigUser {
            name: username.to_string(),
            user: UserConfig { exec },
        }],
        contexts: context_entries,
        current_context,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_kubeconfig_basic() {
        let clusters = vec!["prod-frontend".into(), "staging-frontend".into()];
        let config = build_kubeconfig(
            &clusters,
            "alice@example.com",
            "https://lattice.example.com",
            None,
        );

        assert_eq!(config.clusters.len(), 2);
        assert_eq!(config.contexts.len(), 2);
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.current_context, "prod-frontend");

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

        let config = build_kubeconfig(
            &clusters,
            "alice@example.com",
            "https://lattice.example.com",
            Some(&oidc_config),
        );

        // Verify exec config is set
        let exec = config.users[0].user.exec.as_ref().unwrap();
        assert_eq!(exec.command, "kubectl");
        assert!(exec.args.contains(&"oidc-login".to_string()));
        assert!(exec.args.iter().any(|a| a.contains("https://idp.example.com")));
        assert!(exec.args.iter().any(|a| a.contains("lattice")));
    }

    #[test]
    fn test_build_kubeconfig_empty_clusters() {
        let clusters: Vec<String> = vec![];
        let config = build_kubeconfig(
            &clusters,
            "alice@example.com",
            "https://lattice.example.com",
            None,
        );

        assert!(config.clusters.is_empty());
        assert!(config.contexts.is_empty());
        assert_eq!(config.current_context, "");
    }
}
