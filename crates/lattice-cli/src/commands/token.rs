//! Token command - Kubernetes exec credential plugin for ServiceAccount tokens
//!
//! This command outputs a fresh ServiceAccount token in ExecCredential format,
//! allowing kubeconfigs to automatically refresh expired tokens.
//!
//! # Usage in kubeconfig
//!
//! ```yaml
//! users:
//! - name: lattice-proxy
//!   user:
//!     exec:
//!       apiVersion: client.authentication.k8s.io/v1beta1
//!       command: lattice
//!       args:
//!       - token
//!       - --kubeconfig=/path/to/cluster-kubeconfig
//!       - --namespace=lattice-system
//!       - --service-account=default
//! ```

use clap::Args;
use serde::Serialize;

use crate::{Error, Result};

/// Token command arguments
#[derive(Args, Debug)]
pub struct TokenArgs {
    /// Path to kubeconfig for the cluster where the ServiceAccount exists
    #[arg(long, env = "KUBECONFIG")]
    pub kubeconfig: String,

    /// Namespace of the ServiceAccount
    #[arg(long, short = 'n', default_value = "lattice-system")]
    pub namespace: String,

    /// ServiceAccount name
    #[arg(long, short = 's', default_value = "default")]
    pub service_account: String,

    /// Token duration (e.g., "1h", "8h", "24h")
    #[arg(long, short = 'd', default_value = "1h")]
    pub duration: String,
}

/// ExecCredential response format for Kubernetes
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecCredential {
    api_version: String,
    kind: String,
    status: ExecCredentialStatus,
}

#[derive(Debug, Serialize)]
struct ExecCredentialStatus {
    token: String,
}

impl ExecCredential {
    fn new(token: String) -> Self {
        Self {
            api_version: "client.authentication.k8s.io/v1beta1".to_string(),
            kind: "ExecCredential".to_string(),
            status: ExecCredentialStatus { token },
        }
    }
}

/// Run the token command
///
/// Creates a fresh ServiceAccount token using the Kubernetes TokenRequest API
/// and outputs it in ExecCredential format for use as a kubeconfig exec plugin.
pub async fn run(args: TokenArgs) -> Result<()> {
    let duration_secs = super::parse_duration(&args.duration)?;
    let client = super::kube_client_from_path(&args.kubeconfig).await?;
    let token = super::create_sa_token_native(
        &client,
        &args.namespace,
        &args.service_account,
        duration_secs,
    )
    .await?;

    let credential = ExecCredential::new(token);
    let json = serde_json::to_string(&credential)
        .map_err(|e| Error::command_failed(format!("Failed to serialize credential: {}", e)))?;

    // Print to stdout (kubectl reads this)
    println!("{}", json);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_credential_format() {
        let cred = ExecCredential::new("test-token".to_string());
        let json = serde_json::to_string_pretty(&cred).unwrap();

        assert!(json.contains("client.authentication.k8s.io/v1beta1"));
        assert!(json.contains("ExecCredential"));
        assert!(json.contains("test-token"));
    }

    #[test]
    fn test_exec_credential_serialization() {
        let cred = ExecCredential::new("my-token".to_string());
        let value: serde_json::Value = serde_json::to_value(&cred).unwrap();

        assert_eq!(value["apiVersion"], "client.authentication.k8s.io/v1beta1");
        assert_eq!(value["kind"], "ExecCredential");
        assert_eq!(value["status"]["token"], "my-token");
    }
}
