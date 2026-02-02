//! Agent startup and connection management
//!
//! Provides functions for starting and maintaining the agent connection to a parent cell.

use std::collections::BTreeMap;
use std::time::Duration;

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::ByteString;
use kube::api::{Api, PostParams};
use kube::Client;

use lattice_agent::{
    AgentClient, AgentClientConfig, AgentCredentials, ClientState, SharedK8sForwarder,
};
use lattice_common::{
    ParentConfig, AGENT_CREDENTIALS_SECRET, CA_CERT_KEY, LATTICE_SYSTEM_NAMESPACE, TLS_CERT_KEY,
    TLS_KEY_KEY,
};

/// Supervise agent connection with automatic reconnection.
/// If a parent cell is configured, maintains connection indefinitely with retries.
/// The agent handles unpivot automatically by detecting deletion_timestamp on connect.
///
/// The forwarder is used for hierarchical routing - when this cluster receives
/// K8s API requests destined for child clusters, it forwards them via the forwarder.
pub async fn start_agent_with_retry(
    client: &Client,
    cluster_name: &str,
    forwarder: SharedK8sForwarder,
) {
    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(5);

    loop {
        match start_agent_if_needed(client, cluster_name, forwarder.clone()).await {
            Ok(Some(agent)) => {
                tracing::info!("Agent connection to parent cell established");
                retry_delay = Duration::from_secs(1);

                // Monitor connection health
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    let state = agent.state().await;
                    if state == ClientState::Disconnected || state == ClientState::Failed {
                        tracing::warn!(state = ?state, "Agent disconnected, will reconnect...");
                        break;
                    }
                }
            }
            Ok(None) => {
                tracing::debug!("No parent cell configured, running as standalone");
                return;
            }
            Err(e) => {
                tracing::warn!(error = %e, retry_in = ?retry_delay, "Failed to connect to parent cell, retrying...");
            }
        }

        tokio::time::sleep(retry_delay).await;
        retry_delay = std::cmp::min(retry_delay * 2, max_retry_delay);
    }
}

async fn start_agent_if_needed(
    client: &Client,
    cluster_name: &str,
    forwarder: SharedK8sForwarder,
) -> anyhow::Result<Option<AgentClient>> {
    // Read parent config - if missing, this is a root cluster
    let parent = match ParentConfig::read(client).await {
        Ok(Some(config)) => config,
        Ok(None) => {
            tracing::debug!("No parent config secret, this is a root cluster");
            return Ok(None);
        }
        Err(e) => return Err(anyhow::anyhow!("failed to read parent config: {}", e)),
    };

    let http_endpoint = parent.endpoint.https_url();
    let grpc_endpoint = parent.endpoint.grpc_url();

    tracing::info!(
        cluster = %cluster_name,
        http_endpoint = %http_endpoint,
        grpc_endpoint = %grpc_endpoint,
        "Found parent config, connecting to parent cell"
    );

    // Try to load existing credentials from secret, or request new ones
    let secrets: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
    let credentials = match load_agent_credentials(&secrets).await {
        Ok(creds) => {
            tracing::info!("Using existing agent credentials from secret");
            creds
        }
        Err(_) => {
            tracing::info!("No existing credentials, requesting new certificate from cell");
            let creds =
                AgentClient::request_certificate(&http_endpoint, cluster_name, &parent.ca_cert_pem)
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to get certificate: {}", e))?;

            // Store credentials for future restarts
            if let Err(e) = save_agent_credentials(&secrets, &creds).await {
                tracing::warn!(error = %e, "Failed to save agent credentials to secret");
            }
            creds
        }
    };

    // Create agent client config
    let config = AgentClientConfig {
        cluster_name: cluster_name.to_string(),
        cell_grpc_endpoint: grpc_endpoint,
        cell_http_endpoint: http_endpoint,
        ca_cert_pem: Some(parent.ca_cert_pem),
        heartbeat_interval: Duration::from_secs(30),
        ..Default::default()
    };

    // Create and connect agent with forwarder for hierarchical routing
    let mut agent = AgentClient::with_forwarder(config, forwarder);
    agent
        .connect_with_mtls(&credentials)
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to cell: {}", e))?;

    tracing::info!("Agent connected to parent cell");
    Ok(Some(agent))
}

/// Load agent credentials from Kubernetes secret
async fn load_agent_credentials(secrets: &Api<Secret>) -> anyhow::Result<AgentCredentials> {
    let secret = secrets.get(AGENT_CREDENTIALS_SECRET).await?;
    let data = secret
        .data
        .ok_or_else(|| anyhow::anyhow!("credentials secret has no data"))?;

    let cert_pem = data
        .get(TLS_CERT_KEY)
        .ok_or_else(|| anyhow::anyhow!("missing {}", TLS_CERT_KEY))?;
    let key_pem = data
        .get(TLS_KEY_KEY)
        .ok_or_else(|| anyhow::anyhow!("missing {}", TLS_KEY_KEY))?;
    let ca_pem = data
        .get(CA_CERT_KEY)
        .ok_or_else(|| anyhow::anyhow!("missing {}", CA_CERT_KEY))?;

    Ok(AgentCredentials {
        cert_pem: String::from_utf8(cert_pem.0.clone())?,
        key_pem: String::from_utf8(key_pem.0.clone())?,
        ca_cert_pem: String::from_utf8(ca_pem.0.clone())?,
    })
}

/// Save agent credentials to Kubernetes secret
async fn save_agent_credentials(
    secrets: &Api<Secret>,
    credentials: &AgentCredentials,
) -> anyhow::Result<()> {
    let mut data = BTreeMap::new();
    data.insert(
        TLS_CERT_KEY.to_string(),
        ByteString(credentials.cert_pem.as_bytes().to_vec()),
    );
    data.insert(
        TLS_KEY_KEY.to_string(),
        ByteString(credentials.key_pem.as_bytes().to_vec()),
    );
    data.insert(
        CA_CERT_KEY.to_string(),
        ByteString(credentials.ca_cert_pem.as_bytes().to_vec()),
    );

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(AGENT_CREDENTIALS_SECRET.to_string()),
            namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
            ..Default::default()
        },
        data: Some(data),
        type_: Some("kubernetes.io/tls".to_string()),
        ..Default::default()
    };

    // Try to create, if exists then replace
    match secrets.create(&PostParams::default(), &secret).await {
        Ok(_) => {
            tracing::info!("Created agent credentials secret");
        }
        Err(kube::Error::Api(e)) if e.code == 409 => {
            // Already exists, replace it
            secrets
                .replace(AGENT_CREDENTIALS_SECRET, &PostParams::default(), &secret)
                .await?;
            tracing::info!("Updated agent credentials secret");
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}
