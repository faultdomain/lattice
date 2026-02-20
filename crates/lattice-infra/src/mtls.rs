//! mTLS configuration for gRPC connections
//!
//! Configures TLS for both server (cell) and client (agent) sides.

use thiserror::Error;
use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};
use zeroize::Zeroizing;

/// mTLS configuration errors
#[derive(Debug, Error)]
pub enum MtlsError {
    /// Certificate parsing error
    #[error("certificate parsing error: {0}")]
    CertificateParseError(String),

    /// Key parsing error
    #[error("key parsing error: {0}")]
    KeyParseError(String),

    /// TLS configuration error
    #[error("TLS configuration error: {0}")]
    TlsConfigError(String),

    /// Missing certificate
    #[error("missing certificate")]
    MissingCertificate,
}

/// Server-side mTLS configuration
pub struct ServerMtlsConfig {
    /// Server certificate PEM
    pub server_cert_pem: String,
    /// Server private key PEM (zeroized on drop)
    pub server_key_pem: Zeroizing<String>,
    /// CA certificate PEM for verifying clients
    pub ca_cert_pem: String,
}

impl ServerMtlsConfig {
    /// Create a new server mTLS config
    pub fn new(
        server_cert_pem: String,
        server_key_pem: Zeroizing<String>,
        ca_cert_pem: String,
    ) -> Self {
        Self {
            server_cert_pem,
            server_key_pem,
            ca_cert_pem,
        }
    }

    /// Build a tonic ServerTlsConfig
    pub fn to_tonic_config(&self) -> Result<ServerTlsConfig, MtlsError> {
        let identity = Identity::from_pem(&self.server_cert_pem, &self.server_key_pem);
        let ca_cert = Certificate::from_pem(&self.ca_cert_pem);

        Ok(ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(ca_cert))
    }
}

/// Client-side mTLS configuration
pub struct ClientMtlsConfig {
    /// Client certificate PEM
    pub client_cert_pem: String,
    /// Client private key PEM (zeroized on drop)
    pub client_key_pem: Zeroizing<String>,
    /// CA certificate PEM for verifying server
    pub ca_cert_pem: String,
    /// Server domain name for verification
    pub server_domain: String,
}

impl ClientMtlsConfig {
    /// Create a new client mTLS config
    pub fn new(
        client_cert_pem: String,
        client_key_pem: Zeroizing<String>,
        ca_cert_pem: String,
        server_domain: String,
    ) -> Self {
        Self {
            client_cert_pem,
            client_key_pem,
            ca_cert_pem,
            server_domain,
        }
    }

    /// Build a tonic ClientTlsConfig
    pub fn to_tonic_config(&self) -> Result<ClientTlsConfig, MtlsError> {
        let identity = Identity::from_pem(&self.client_cert_pem, &self.client_key_pem);
        let ca_cert = Certificate::from_pem(&self.ca_cert_pem);

        Ok(ClientTlsConfig::new()
            .identity(identity)
            .ca_certificate(ca_cert)
            .domain_name(&self.server_domain))
    }
}

/// Extract cluster ID from a client certificate's CN
///
/// The CN is expected to be in the format "lattice-agent-{cluster_id}".
/// This is a wrapper around the shared implementation in pki module.
pub fn extract_cluster_id_from_cert(cert_der: &[u8]) -> Result<String, MtlsError> {
    crate::pki::extract_cluster_id(cert_der)
        .map_err(|e| MtlsError::CertificateParseError(e.to_string()))
}

/// Verify a certificate chain against a CA
pub fn verify_cert_chain(cert_der: &[u8], ca_cert_pem: &str) -> Result<bool, MtlsError> {
    use crate::pki::verify_client_cert;

    match verify_client_cert(cert_der, ca_cert_pem) {
        Ok(result) => Ok(result.valid),
        Err(e) => Err(MtlsError::CertificateParseError(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::{AgentCertRequest, CertificateAuthority};

    fn create_test_certs() -> (CertificateAuthority, String, Zeroizing<String>) {
        let ca = CertificateAuthority::new("Test CA").expect("CA creation should succeed");
        let agent_req =
            AgentCertRequest::new("test-cluster").expect("agent cert request should succeed");
        let agent_cert = ca
            .sign_csr(agent_req.csr_pem(), "test-cluster")
            .expect("CSR signing should succeed");
        let agent_key = Zeroizing::new(agent_req.private_key_pem().to_string());

        (ca, agent_cert, agent_key)
    }

    #[test]
    fn test_extract_cluster_id() {
        let (_ca, agent_cert, _) = create_test_certs();

        let pem_obj = pem::parse(agent_cert.as_bytes()).expect("PEM parsing should succeed");
        let cert_der = pem_obj.contents();

        let cluster_id = extract_cluster_id_from_cert(cert_der).expect("extraction should succeed");
        assert_eq!(cluster_id, "test-cluster");
    }

    #[test]
    fn test_verify_cert_chain() {
        let (ca, agent_cert, _) = create_test_certs();

        let pem_obj = pem::parse(agent_cert.as_bytes()).expect("PEM parsing should succeed");
        let cert_der = pem_obj.contents();

        let result =
            verify_cert_chain(cert_der, ca.ca_cert_pem()).expect("verification should succeed");
        assert!(result);
    }

    #[test]
    fn test_server_tls_config() {
        let (ca, agent_cert, agent_key) = create_test_certs();
        let config = ServerMtlsConfig::new(agent_cert, agent_key, ca.ca_cert_pem().to_string());

        assert!(config.to_tonic_config().is_ok());
    }

    #[test]
    fn test_client_tls_config() {
        let (ca, agent_cert, agent_key) = create_test_certs();
        let config = ClientMtlsConfig::new(
            agent_cert,
            agent_key,
            ca.ca_cert_pem().to_string(),
            "cell.lattice.local".to_string(),
        );

        assert!(config.to_tonic_config().is_ok());
    }

    #[test]
    fn test_invalid_cn_format_rejected() {
        use rcgen::{CertificateParams, DistinguishedName, DnType, DnValue, KeyPair};

        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            DnValue::Utf8String("wrong-format".to_string()),
        );
        params.distinguished_name = dn;

        let key_pair = KeyPair::generate().expect("key pair generation should succeed");
        let cert = params
            .self_signed(&key_pair)
            .expect("self-signed cert creation should succeed");
        let cert_der = cert.der();

        let result = extract_cluster_id_from_cert(cert_der);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("prefix"));
    }
}
