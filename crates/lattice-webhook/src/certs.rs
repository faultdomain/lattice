//! Certificate management for the webhook server
//!
//! Generates or loads TLS certificates from a Kubernetes Secret. Uses
//! `lattice-infra/src/pki.rs` to create a self-signed CA and server cert.

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use kube::api::{ObjectMeta, PostParams};
use kube::{Api, Client};
use std::collections::BTreeMap;

use lattice_core::SECRET_TYPE_TLS;
use lattice_infra::pki::CertificateAuthority;

use crate::error::Error;

/// Name of the K8s Secret storing webhook TLS credentials
pub const WEBHOOK_TLS_SECRET_NAME: &str = "lattice-webhook-tls";

/// Namespace for webhook TLS credentials
pub const WEBHOOK_NAMESPACE: &str = lattice_core::LATTICE_SYSTEM_NAMESPACE;

/// SAN for the webhook service (short DNS)
const WEBHOOK_SAN_SHORT: &str = "lattice-operator.lattice-system.svc";

/// SAN for the webhook service (FQDN)
const WEBHOOK_SAN_FQDN: &str = "lattice-operator.lattice-system.svc.cluster.local";

/// TLS material for the webhook server
pub struct WebhookTls {
    /// PEM-encoded server certificate
    pub cert_pem: String,
    /// PEM-encoded server private key
    pub key_pem: String,
    /// PEM-encoded CA certificate (for injection into webhook config)
    pub ca_pem: String,
}

/// Load TLS credentials from K8s Secret, or generate new ones.
///
/// On first run, generates a self-signed CA + server cert and stores them
/// in a K8s Secret. On subsequent runs, loads from the existing Secret.
pub async fn ensure_tls(client: &Client) -> Result<WebhookTls, Error> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), WEBHOOK_NAMESPACE);

    // Try to load existing secret
    match secrets.get_opt(WEBHOOK_TLS_SECRET_NAME).await? {
        Some(secret) => load_from_secret(&secret),
        None => {
            let tls = generate_tls()?;
            store_secret(client, &tls).await?;
            Ok(tls)
        }
    }
}

/// Generate fresh TLS credentials using the PKI module
fn generate_tls() -> Result<WebhookTls, Error> {
    let ca = CertificateAuthority::new("Lattice Webhook CA")?;

    let sans = [WEBHOOK_SAN_SHORT, WEBHOOK_SAN_FQDN];
    let (cert_pem, key_pem) = ca.generate_server_cert(&sans)?;

    Ok(WebhookTls {
        cert_pem,
        key_pem: key_pem.to_string(),
        ca_pem: ca.ca_cert_pem().to_string(),
    })
}

/// Load TLS material from an existing K8s Secret
fn load_from_secret(secret: &Secret) -> Result<WebhookTls, Error> {
    let data = secret
        .data
        .as_ref()
        .ok_or_else(|| Error::Tls("webhook TLS secret has no data".to_string()))?;

    let cert_pem = extract_string(data, "tls.crt")?;
    let key_pem = extract_string(data, "tls.key")?;
    let ca_pem = extract_string(data, "ca.crt")?;

    Ok(WebhookTls {
        cert_pem,
        key_pem,
        ca_pem,
    })
}

/// Extract a UTF-8 string from a Secret's binary data map
fn extract_string(data: &BTreeMap<String, ByteString>, key: &str) -> Result<String, Error> {
    let bytes = data
        .get(key)
        .ok_or_else(|| Error::Tls(format!("webhook TLS secret missing key '{key}'")))?;
    String::from_utf8(bytes.0.clone()).map_err(|e| {
        Error::Tls(format!(
            "webhook TLS secret key '{key}' is not valid UTF-8: {e}"
        ))
    })
}

/// Store TLS credentials in a K8s Secret
async fn store_secret(client: &Client, tls: &WebhookTls) -> Result<(), Error> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), WEBHOOK_NAMESPACE);

    let mut data = BTreeMap::new();
    data.insert(
        "tls.crt".to_string(),
        ByteString(tls.cert_pem.as_bytes().to_vec()),
    );
    data.insert(
        "tls.key".to_string(),
        ByteString(tls.key_pem.as_bytes().to_vec()),
    );
    data.insert(
        "ca.crt".to_string(),
        ByteString(tls.ca_pem.as_bytes().to_vec()),
    );

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(WEBHOOK_TLS_SECRET_NAME.to_string()),
            namespace: Some(WEBHOOK_NAMESPACE.to_string()),
            ..Default::default()
        },
        data: Some(data),
        type_: Some(SECRET_TYPE_TLS.to_string()),
        ..Default::default()
    };

    secrets.create(&PostParams::default(), &secret).await?;
    tracing::info!(
        secret = WEBHOOK_TLS_SECRET_NAME,
        namespace = WEBHOOK_NAMESPACE,
        "Created webhook TLS secret"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_tls_produces_valid_pem() {
        let tls = generate_tls().expect("TLS generation should succeed");

        assert!(tls.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(tls.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(tls.ca_pem.contains("BEGIN CERTIFICATE"));

        // CA and server cert should be different
        assert_ne!(tls.cert_pem, tls.ca_pem);
    }

    #[test]
    fn load_from_secret_handles_missing_data() {
        let secret = Secret {
            data: None,
            ..Default::default()
        };
        assert!(load_from_secret(&secret).is_err());
    }

    #[test]
    fn load_from_secret_handles_missing_key() {
        let mut data = BTreeMap::new();
        data.insert("tls.crt".to_string(), ByteString(b"cert".to_vec()));
        // Missing tls.key and ca.crt
        let secret = Secret {
            data: Some(data),
            ..Default::default()
        };
        assert!(load_from_secret(&secret).is_err());
    }

    #[test]
    fn load_from_secret_succeeds_with_all_keys() {
        let mut data = BTreeMap::new();
        data.insert("tls.crt".to_string(), ByteString(b"cert-data".to_vec()));
        data.insert("tls.key".to_string(), ByteString(b"key-data".to_vec()));
        data.insert("ca.crt".to_string(), ByteString(b"ca-data".to_vec()));
        let secret = Secret {
            data: Some(data),
            ..Default::default()
        };

        let tls = load_from_secret(&secret).expect("should load from secret");
        assert_eq!(tls.cert_pem, "cert-data");
        assert_eq!(tls.key_pem, "key-data");
        assert_eq!(tls.ca_pem, "ca-data");
    }
}
