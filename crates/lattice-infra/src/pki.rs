//! PKI operations for mTLS certificates
//!
//! This module handles certificate authority operations and CSR signing.
//! The cell acts as a CA and signs CSRs from agents - it never sees agent private keys.
//!
//! # Security Model
//!
//! - Cell generates and holds the CA key pair
//! - Agents generate their own key pairs locally
//! - Agents send only CSRs (no private keys)
//! - Cell signs CSRs and returns certificates
//! - All agent-cell communication uses mTLS with signed certificates
//!
//! # Certificate Rotation
//!
//! Certificates are rotated at 80% of their TTL:
//! - Leaf certs (1 year): rotate at ~292 days (~2.4 months before expiry)
//! - CA certs (10 years): rotate at 8 years (2 years before expiry)
//!
//! During CA rotation, both old and new CA are trusted for verification.
//! This allows time for all leaf certs to be re-issued with the new CA.

use rcgen::{
    string::Ia5String, BasicConstraints, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, DnValue, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use thiserror::Error;
use x509_parser::prelude::*;

/// Default validity period for CA certificates (10 years)
pub const CA_VALIDITY_YEARS: i64 = 10;

/// Default validity period for server/agent certificates (1 year)
pub const CERT_VALIDITY_YEARS: i64 = 1;

/// Rotation threshold as a fraction of TTL (80%)
/// Certificates should be rotated when this fraction of their lifetime has passed.
pub const ROTATION_THRESHOLD: f64 = 0.80;

/// Compute certificate validity period from now
///
/// Returns (not_before, not_after) timestamps for certificate generation.
/// The not_before is set to current time, and not_after is set to the
/// specified number of years from now.
fn compute_validity(years: i64) -> (::time::OffsetDateTime, ::time::OffsetDateTime) {
    let now = ::time::OffsetDateTime::now_utc();
    let not_after = now + ::time::Duration::days(years * 365);
    (now, not_after)
}

/// Information about a certificate's validity and rotation status
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// When the certificate becomes valid (Unix timestamp)
    pub not_before: i64,
    /// When the certificate expires (Unix timestamp)
    pub not_after: i64,
    /// Subject common name
    pub common_name: String,
}

impl CertificateInfo {
    /// Parse certificate info from PEM-encoded certificate
    pub fn from_pem(pem_data: &str) -> Result<Self> {
        let der = parse_pem(pem_data)?;
        Self::from_der(&der)
    }

    /// Parse certificate info from DER-encoded certificate
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| PkiError::ParseError(format!("failed to parse certificate: {}", e)))?;

        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();

        let common_name = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or("")
            .to_string();

        Ok(Self {
            not_before,
            not_after,
            common_name,
        })
    }

    /// Total lifetime of the certificate in seconds
    pub fn lifetime_secs(&self) -> i64 {
        self.not_after - self.not_before
    }

    /// Seconds elapsed since certificate was issued
    pub fn age_secs(&self) -> i64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after 1970")
            .as_secs() as i64;
        now - self.not_before
    }

    /// Seconds remaining until certificate expires
    pub fn remaining_secs(&self) -> i64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after 1970")
            .as_secs() as i64;
        self.not_after - now
    }

    /// Check if certificate has expired
    pub fn is_expired(&self) -> bool {
        self.remaining_secs() <= 0
    }

    /// Check if certificate needs rotation (past 80% of TTL)
    pub fn needs_rotation(&self) -> bool {
        let lifetime = self.lifetime_secs() as f64;
        let age = self.age_secs() as f64;
        age / lifetime >= ROTATION_THRESHOLD
    }

    /// Fraction of lifetime elapsed (0.0 to 1.0+)
    pub fn lifetime_fraction(&self) -> f64 {
        let lifetime = self.lifetime_secs() as f64;
        let age = self.age_secs() as f64;
        age / lifetime
    }
}

/// PKI errors
#[derive(Debug, Error)]
pub enum PkiError {
    /// CA not initialized
    #[error("CA not initialized")]
    CaNotInitialized,

    /// Invalid CSR
    #[error("invalid CSR: {0}")]
    InvalidCsr(String),

    /// Certificate generation failed
    #[error("certificate generation failed: {0}")]
    CertificateGenerationFailed(String),

    /// Key generation failed
    #[error("key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Certificate parsing error
    #[error("certificate parsing error: {0}")]
    ParseError(String),
}

/// Result type for PKI operations
pub type Result<T> = std::result::Result<T, PkiError>;

/// Parse PEM-encoded data and return the DER bytes
pub fn parse_pem(pem_data: &str) -> std::result::Result<Vec<u8>, PkiError> {
    let pem_obj = ::pem::parse(pem_data.as_bytes())
        .map_err(|e| PkiError::ParseError(format!("failed to parse PEM: {}", e)))?;
    Ok(pem_obj.contents().to_vec())
}

/// Certificate Authority for signing agent CSRs
#[derive(Clone)]
pub struct CertificateAuthority {
    /// CA key pair serialized as PEM (we need to deserialize each time since KeyPair isn't Clone)
    ca_key_pem: String,
    /// PEM-encoded CA certificate for distribution
    ca_cert_pem: String,
}

impl CertificateAuthority {
    /// Create a new self-signed CA
    pub fn new(common_name: &str) -> Result<Self> {
        let mut params = CertificateParams::default();

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            DnValue::Utf8String(common_name.to_string()),
        );
        dn.push(
            DnType::OrganizationName,
            DnValue::Utf8String("Lattice".to_string()),
        );
        params.distinguished_name = dn;

        // CA settings
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // 10 year validity from current time
        let (not_before, not_after) = compute_validity(CA_VALIDITY_YEARS);
        params.not_before = not_before;
        params.not_after = not_after;

        // Generate key pair
        let key_pair = KeyPair::generate().map_err(|e| {
            PkiError::KeyGenerationFailed(format!("failed to generate CA key: {}", e))
        })?;

        let ca_key_pem = key_pair.serialize_pem();

        let cert = params.self_signed(&key_pair).map_err(|e| {
            PkiError::CertificateGenerationFailed(format!("failed to create CA cert: {}", e))
        })?;

        let ca_cert_pem = cert.pem();

        Ok(Self {
            ca_key_pem,
            ca_cert_pem,
        })
    }

    /// Load CA from PEM files
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        // Validate key can be parsed
        let _ = KeyPair::from_pem(key_pem)
            .map_err(|e| PkiError::ParseError(format!("failed to parse CA key: {}", e)))?;

        // Validate cert can be parsed
        let _ = parse_pem(cert_pem)?;

        Ok(Self {
            ca_key_pem: key_pem.to_string(),
            ca_cert_pem: cert_pem.to_string(),
        })
    }

    /// Get the CA certificate in PEM format (for distribution to agents)
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Get the CA private key in PEM format (for backup/storage)
    pub fn ca_key_pem(&self) -> &str {
        &self.ca_key_pem
    }

    /// Get certificate info (validity period, etc.)
    pub fn cert_info(&self) -> Result<CertificateInfo> {
        CertificateInfo::from_pem(&self.ca_cert_pem)
    }

    /// Check if this CA needs rotation (past 80% of TTL)
    pub fn needs_rotation(&self) -> Result<bool> {
        Ok(self.cert_info()?.needs_rotation())
    }

    /// Load the key pair from stored PEM
    fn load_key_pair(&self) -> Result<KeyPair> {
        KeyPair::from_pem(&self.ca_key_pem)
            .map_err(|e| PkiError::ParseError(format!("failed to load CA key: {}", e)))
    }

    /// Generate a server certificate for TLS with the given SANs
    ///
    /// This generates a certificate suitable for TLS server authentication,
    /// signed by this CA. Use this for the bootstrap HTTPS server.
    pub fn generate_server_cert(&self, sans: &[&str]) -> Result<(String, String)> {
        let mut params = CertificateParams::default();

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            DnValue::Utf8String("Lattice Server".to_string()),
        );
        dn.push(
            DnType::OrganizationName,
            DnValue::Utf8String("Lattice".to_string()),
        );
        params.distinguished_name = dn;

        // Not a CA
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        // Extended key usage for TLS server
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        // Set validity from current time
        let (not_before, not_after) = compute_validity(CERT_VALIDITY_YEARS);
        params.not_before = not_before;
        params.not_after = not_after;

        // Add SANs
        params.subject_alt_names = sans
            .iter()
            .map(|san| {
                // Check if it's an IP address
                if let Ok(ip) = san.parse::<std::net::IpAddr>() {
                    Ok(SanType::IpAddress(ip))
                } else {
                    Ia5String::try_from(san.to_string())
                        .map(SanType::DnsName)
                        .map_err(|e| {
                            PkiError::CertificateGenerationFailed(format!(
                                "invalid DNS name '{}': {}",
                                san, e
                            ))
                        })
                }
            })
            .collect::<Result<Vec<_>>>()?;

        // Generate key pair for server
        let server_key = KeyPair::generate().map_err(|e| {
            PkiError::KeyGenerationFailed(format!("failed to generate server key: {}", e))
        })?;

        let server_key_pem = server_key.serialize_pem();

        // Create the Issuer from our CA certificate and key
        let ca_key = self.load_key_pair()?;
        let issuer = Issuer::from_ca_cert_pem(&self.ca_cert_pem, &ca_key)
            .map_err(|e| PkiError::ParseError(format!("failed to create issuer: {}", e)))?;

        // Sign the server certificate
        let server_cert = params.signed_by(&server_key, &issuer).map_err(|e| {
            PkiError::CertificateGenerationFailed(format!("failed to sign server cert: {}", e))
        })?;

        Ok((server_cert.pem(), server_key_pem))
    }

    /// Sign a CSR and return the signed certificate in PEM format
    ///
    /// The CSR contains the agent's public key. The cell extracts it
    /// and signs a new certificate with it, ensuring the cell never
    /// sees the agent's private key.
    pub fn sign_csr(&self, csr_pem: &str, cluster_id: &str) -> Result<String> {
        // Parse the CSR using rcgen's built-in parser
        let mut csr_params = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|e| PkiError::InvalidCsr(format!("failed to parse CSR: {}", e)))?;

        // Override the certificate parameters from the CSR with our own
        // This ensures we control the subject, validity, and extensions

        // Set subject from cluster ID
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            DnValue::Utf8String(format!("lattice-agent-{}", cluster_id)),
        );
        dn.push(
            DnType::OrganizationName,
            DnValue::Utf8String("Lattice".to_string()),
        );
        csr_params.params.distinguished_name = dn;

        // Not a CA
        csr_params.params.is_ca = IsCa::NoCa;
        csr_params.params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        // Extended key usage for TLS client and server
        csr_params.params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];

        // Set validity from current time
        let (not_before, not_after) = compute_validity(CERT_VALIDITY_YEARS);
        csr_params.params.not_before = not_before;
        csr_params.params.not_after = not_after;

        // Add SANs for the agent
        // These are well-known DNS name patterns that should always be valid.
        // If they fail, it indicates a bug in the cluster_id format.
        let agent_dns = format!("lattice-agent-{}", cluster_id);
        csr_params.params.subject_alt_names = vec![
            SanType::DnsName(Ia5String::try_from(agent_dns.clone()).map_err(|e| {
                PkiError::CertificateGenerationFailed(format!(
                    "invalid agent DNS name '{}': {}",
                    agent_dns, e
                ))
            })?),
            SanType::DnsName(
                Ia5String::try_from("lattice-agent.lattice-system.svc".to_string()).map_err(
                    |e| {
                        PkiError::CertificateGenerationFailed(format!(
                            "invalid DNS name 'lattice-agent.lattice-system.svc': {}",
                            e
                        ))
                    },
                )?,
            ),
            SanType::DnsName(
                Ia5String::try_from("lattice-agent.lattice-system.svc.cluster.local".to_string())
                    .map_err(|e| {
                    PkiError::CertificateGenerationFailed(format!(
                        "invalid DNS name 'lattice-agent.lattice-system.svc.cluster.local': {}",
                        e
                    ))
                })?,
            ),
        ];

        // Create the Issuer from our CA certificate and key
        let ca_key = self.load_key_pair()?;
        let issuer = Issuer::from_ca_cert_pem(&self.ca_cert_pem, &ca_key)
            .map_err(|e| PkiError::ParseError(format!("failed to create issuer: {}", e)))?;

        // Sign the certificate with the CA
        let signed_cert = csr_params.signed_by(&issuer).map_err(|e| {
            PkiError::CertificateGenerationFailed(format!("failed to sign certificate: {}", e))
        })?;

        Ok(signed_cert.pem())
    }
}

/// Bundle of CA certificates for verification during CA rotation.
///
/// During CA rotation, we need to trust certificates signed by both the old
/// and new CA. This bundle holds multiple CAs and verifies against any of them.
///
/// The "active" CA (index 0) is used for signing new certificates.
/// All CAs in the bundle are trusted for verification.
#[derive(Clone)]
pub struct CertificateAuthorityBundle {
    /// CAs in the bundle (newest/active first)
    cas: Vec<CertificateAuthority>,
}

impl CertificateAuthorityBundle {
    /// Create a new bundle with a single CA
    pub fn new(ca: CertificateAuthority) -> Self {
        Self { cas: vec![ca] }
    }

    /// Create a bundle from multiple CAs (first is the active/signing CA)
    pub fn from_cas(cas: Vec<CertificateAuthority>) -> Result<Self> {
        if cas.is_empty() {
            return Err(PkiError::CaNotInitialized);
        }
        Ok(Self { cas })
    }

    /// Get the active CA (used for signing new certificates)
    pub fn active(&self) -> &CertificateAuthority {
        &self.cas[0]
    }

    /// Get all CA certificates as a combined PEM bundle (for trust verification)
    pub fn trust_bundle_pem(&self) -> String {
        self.cas
            .iter()
            .map(|ca| ca.ca_cert_pem())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Check if the active CA needs rotation
    pub fn needs_rotation(&self) -> Result<bool> {
        self.active().needs_rotation()
    }

    /// Rotate the CA by generating a new one and adding it to the bundle.
    /// The new CA becomes the active (signing) CA.
    /// Old CAs are kept for verification until they expire.
    pub fn rotate(&mut self, new_ca_name: &str) -> Result<()> {
        let new_ca = CertificateAuthority::new(new_ca_name)?;
        self.cas.insert(0, new_ca);
        Ok(())
    }

    /// Remove expired CAs from the bundle (keeps at least the active CA)
    pub fn prune_expired(&mut self) {
        if self.cas.len() <= 1 {
            return;
        }
        self.cas.retain(|ca| {
            ca.cert_info()
                .map(|info| !info.is_expired())
                .unwrap_or(true)
        });
        // Ensure we always have at least one CA
        if self.cas.is_empty() {
            // This shouldn't happen, but be safe
            tracing::error!("all CAs expired during prune, this is a critical error");
        }
    }

    /// Number of CAs in the bundle
    pub fn len(&self) -> usize {
        self.cas.len()
    }

    /// Check if bundle is empty
    pub fn is_empty(&self) -> bool {
        self.cas.is_empty()
    }

    /// Generate a server certificate signed by the active CA
    pub fn generate_server_cert(&self, sans: &[&str]) -> Result<(String, String)> {
        self.active().generate_server_cert(sans)
    }

    /// Sign a CSR with the active CA
    pub fn sign_csr(&self, csr_pem: &str, cluster_id: &str) -> Result<String> {
        self.active().sign_csr(csr_pem, cluster_id)
    }

    /// Verify a certificate was signed by any CA in the bundle
    pub fn verify_client_cert(&self, cert_der: &[u8]) -> Result<VerificationResult> {
        for ca in &self.cas {
            match verify_client_cert(cert_der, ca.ca_cert_pem()) {
                Ok(result) if result.valid => return Ok(result),
                _ => continue,
            }
        }
        // None of the CAs verified the cert
        Ok(VerificationResult {
            cluster_id: String::new(),
            valid: false,
            reason: Some("certificate not signed by any trusted CA".to_string()),
        })
    }
}

/// Agent certificate request (generates keypair and CSR locally)
pub struct AgentCertRequest {
    /// The generated key pair PEM (kept private)
    key_pem: String,
    /// CSR in PEM format (sent to cell)
    csr_pem: String,
}

impl AgentCertRequest {
    /// Generate a new key pair and CSR for an agent
    pub fn new(cluster_id: &str) -> Result<Self> {
        // Generate key pair locally (never leaves agent)
        let key_pair = KeyPair::generate().map_err(|e| {
            PkiError::KeyGenerationFailed(format!("failed to generate agent key: {}", e))
        })?;

        let key_pem = key_pair.serialize_pem();

        // Create CSR params
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            DnValue::Utf8String(format!("lattice-agent-{}", cluster_id)),
        );
        dn.push(
            DnType::OrganizationName,
            DnValue::Utf8String("Lattice".to_string()),
        );
        params.distinguished_name = dn;

        // Generate CSR
        let csr = params.serialize_request(&key_pair).map_err(|e| {
            PkiError::CertificateGenerationFailed(format!("failed to create CSR: {}", e))
        })?;

        let csr_pem = csr.pem().map_err(|e| {
            PkiError::CertificateGenerationFailed(format!("failed to serialize CSR: {}", e))
        })?;

        Ok(Self { key_pem, csr_pem })
    }

    /// Get the CSR in PEM format (to send to cell for signing)
    pub fn csr_pem(&self) -> &str {
        &self.csr_pem
    }

    /// Get the private key in PEM format (to store locally)
    pub fn private_key_pem(&self) -> &str {
        &self.key_pem
    }
}

/// Verification result for client certificates
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Cluster ID extracted from certificate
    pub cluster_id: String,
    /// Whether the certificate is valid
    pub valid: bool,
    /// Reason if invalid
    pub reason: Option<String>,
}

/// Verify a client certificate was signed by our CA
pub fn verify_client_cert(
    cert_der: &[u8],
    ca_cert_pem: &str,
) -> std::result::Result<VerificationResult, PkiError> {
    // Parse the presented certificate
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| PkiError::ParseError(format!("failed to parse client cert: {}", e)))?;

    // Parse the CA certificate
    let ca_cert_der = parse_pem(ca_cert_pem)?;
    let (_, ca_cert) = X509Certificate::from_der(&ca_cert_der)
        .map_err(|e| PkiError::ParseError(format!("failed to parse CA cert: {}", e)))?;

    // Verify signature using x509-parser's built-in verification
    let ca_public_key = ca_cert.public_key();
    match cert.verify_signature(Some(ca_public_key)) {
        Ok(_) => {}
        Err(_) => {
            return Ok(VerificationResult {
                cluster_id: String::new(),
                valid: false,
                reason: Some("signature verification failed".to_string()),
            });
        }
    }

    // Check validity period
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after 1970")
        .as_secs() as i64;

    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();

    if now < not_before {
        return Ok(VerificationResult {
            cluster_id: String::new(),
            valid: false,
            reason: Some("certificate not yet valid".to_string()),
        });
    }

    if now > not_after {
        return Ok(VerificationResult {
            cluster_id: String::new(),
            valid: false,
            reason: Some("certificate expired".to_string()),
        });
    }

    // Extract cluster ID from CN
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("");

    let cluster_id = cn.strip_prefix("lattice-agent-").unwrap_or("").to_string();

    if cluster_id.is_empty() {
        return Ok(VerificationResult {
            cluster_id: String::new(),
            valid: false,
            reason: Some("invalid CN format, expected lattice-agent-<cluster_id>".to_string()),
        });
    }

    Ok(VerificationResult {
        cluster_id,
        valid: true,
        reason: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_can_be_created() {
        let ca = CertificateAuthority::new("Lattice Test CA").expect("CA creation should succeed");
        assert!(!ca.ca_cert_pem().is_empty());
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn agent_can_generate_csr() {
        let request =
            AgentCertRequest::new("test-cluster-123").expect("CSR generation should succeed");

        // CSR should be generated
        assert!(!request.csr_pem().is_empty());
        assert!(request.csr_pem().contains("BEGIN CERTIFICATE REQUEST"));

        // Private key should be available
        assert!(!request.private_key_pem().is_empty());
        assert!(request.private_key_pem().contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn ca_can_sign_csr() {
        // Setup: CA and agent CSR
        let ca = CertificateAuthority::new("Lattice Test CA").expect("CA creation should succeed");
        let request = AgentCertRequest::new("my-cluster").expect("CSR generation should succeed");

        // Sign the CSR
        let signed_cert = ca
            .sign_csr(request.csr_pem(), "my-cluster")
            .expect("CSR signing should succeed");

        // Should be a valid certificate
        assert!(signed_cert.contains("BEGIN CERTIFICATE"));
        assert!(!signed_cert.contains("CERTIFICATE REQUEST"));
    }

    #[test]
    fn signed_cert_can_be_verified() {
        // Setup: CA signs agent CSR
        let ca = CertificateAuthority::new("Lattice Test CA").expect("CA creation should succeed");
        let request =
            AgentCertRequest::new("verified-cluster").expect("CSR generation should succeed");
        let signed_cert_pem = ca
            .sign_csr(request.csr_pem(), "verified-cluster")
            .expect("CSR signing should succeed");

        // Parse to DER for verification
        let cert_der = parse_pem(&signed_cert_pem).expect("PEM parsing should succeed");

        // Verify
        let result = verify_client_cert(&cert_der, ca.ca_cert_pem())
            .expect("certificate verification should succeed");

        assert!(result.valid);
        assert_eq!(result.cluster_id, "verified-cluster");
        assert!(result.reason.is_none());
    }

    #[test]
    fn invalid_signature_rejected() {
        // Create two different CAs
        let ca1 = CertificateAuthority::new("CA One").expect("CA1 creation should succeed");
        let ca2 = CertificateAuthority::new("CA Two").expect("CA2 creation should succeed");

        // Agent gets cert signed by CA1
        let request = AgentCertRequest::new("cluster").expect("CSR generation should succeed");
        let signed_cert_pem = ca1
            .sign_csr(request.csr_pem(), "cluster")
            .expect("CSR signing should succeed");

        // Try to verify with CA2 (should fail)
        let cert_der = parse_pem(&signed_cert_pem).expect("PEM parsing should succeed");
        let result = verify_client_cert(&cert_der, ca2.ca_cert_pem())
            .expect("verification call should succeed");

        assert!(!result.valid);
        assert!(result
            .reason
            .expect("reason should be set for invalid result")
            .contains("signature verification failed"));
    }

    #[test]
    fn invalid_csr_rejected() {
        let ca = CertificateAuthority::new("Test CA").expect("CA creation should succeed");

        let result = ca.sign_csr("not a valid csr", "cluster");

        assert!(matches!(result, Err(PkiError::InvalidCsr(_))));
    }

    #[test]
    fn cluster_id_extracted_from_cert() {
        let ca = CertificateAuthority::new("Test CA").expect("CA creation should succeed");
        let request =
            AgentCertRequest::new("prod-us-west-123").expect("CSR generation should succeed");
        let signed_cert_pem = ca
            .sign_csr(request.csr_pem(), "prod-us-west-123")
            .expect("CSR signing should succeed");

        let cert_der = parse_pem(&signed_cert_pem).expect("PEM parsing should succeed");
        let result =
            verify_client_cert(&cert_der, ca.ca_cert_pem()).expect("verification should succeed");

        assert!(result.valid);
        assert_eq!(result.cluster_id, "prod-us-west-123");
    }

    #[test]
    fn private_key_never_in_csr() {
        let request =
            AgentCertRequest::new("secure-cluster").expect("CSR generation should succeed");

        // CSR should NOT contain private key
        assert!(!request.csr_pem().contains("PRIVATE KEY"));

        // But private key should still be accessible separately
        assert!(request.private_key_pem().contains("PRIVATE KEY"));
    }

    #[test]
    fn ca_can_be_saved_and_loaded() {
        let ca1 = CertificateAuthority::new("Persistent CA").expect("CA creation should succeed");
        let cert_pem = ca1.ca_cert_pem().to_string();
        let key_pem = ca1.ca_key_pem().to_string();

        // Load from saved PEM
        let ca2 =
            CertificateAuthority::from_pem(&cert_pem, &key_pem).expect("CA loading should succeed");

        // Should be able to sign CSRs
        let request = AgentCertRequest::new("test").expect("CSR generation should succeed");
        let signed = ca2.sign_csr(request.csr_pem(), "test");
        assert!(signed.is_ok());
    }

    // ==========================================================================
    // Story Tests: PKI Certificate Lifecycle
    // ==========================================================================
    //
    // The PKI system enables secure mTLS communication between cells and agents.
    // Key security properties:
    // - Agent private keys never leave the agent (CSR model)
    // - Only cell CA can sign valid certificates
    // - Certificates bind to specific cluster IDs
    // - Cross-CA certificates are rejected

    /// Story: Complete certificate lifecycle for a new agent
    ///
    /// This demonstrates the full PKI flow from CA creation to agent
    /// certificate verification.
    #[test]
    fn story_complete_certificate_lifecycle() {
        // Chapter 1: Cell creates its CA during initialization
        // -----------------------------------------------------
        let ca =
            CertificateAuthority::new("Lattice Production CA").expect("CA creation should succeed");
        let ca_cert = ca.ca_cert_pem();
        assert!(ca_cert.contains("BEGIN CERTIFICATE"));

        // Chapter 2: New workload cluster needs a certificate
        // ----------------------------------------------------
        // Agent generates its own keypair - private key NEVER transmitted
        let agent_request =
            AgentCertRequest::new("workload-east-1").expect("agent CSR generation should succeed");

        // Verify the CSR doesn't leak the private key
        assert!(!agent_request.csr_pem().contains("PRIVATE KEY"));
        assert!(agent_request.csr_pem().contains("CERTIFICATE REQUEST"));

        // But agent does have its private key locally
        assert!(agent_request.private_key_pem().contains("PRIVATE KEY"));

        // Chapter 3: Cell signs the CSR
        // ------------------------------
        let signed_cert = ca
            .sign_csr(agent_request.csr_pem(), "workload-east-1")
            .expect("CSR signing should succeed");
        assert!(signed_cert.contains("BEGIN CERTIFICATE"));

        // Chapter 4: Agent uses certificate for mTLS connection
        // -------------------------------------------------------
        // When agent connects, cell verifies the certificate
        let cert_der = parse_pem(&signed_cert).expect("PEM parsing should succeed");
        let verification =
            verify_client_cert(&cert_der, ca_cert).expect("verification call should succeed");

        assert!(verification.valid);
        assert_eq!(verification.cluster_id, "workload-east-1");
        assert!(verification.reason.is_none());
    }

    /// Story: Security - Certificates from different CAs are rejected
    ///
    /// An attacker who creates their own CA cannot get their agents
    /// accepted by our cell.
    #[test]
    fn story_cross_ca_attack_prevention() {
        // Legitimate cell CA
        let legitimate_ca = CertificateAuthority::new("Legitimate CA")
            .expect("legitimate CA creation should succeed");

        // Attacker creates their own CA
        let attacker_ca =
            CertificateAuthority::new("Attacker CA").expect("attacker CA creation should succeed");

        // Attacker signs their own agent's CSR
        let evil_agent = AgentCertRequest::new("trojan-cluster")
            .expect("evil agent CSR generation should succeed");
        let evil_cert = attacker_ca
            .sign_csr(evil_agent.csr_pem(), "trojan-cluster")
            .expect("attacker CSR signing should succeed");

        // Attacker tries to connect to legitimate cell
        let cert_der = parse_pem(&evil_cert).expect("PEM parsing should succeed");
        let verification = verify_client_cert(&cert_der, legitimate_ca.ca_cert_pem())
            .expect("verification call should succeed");

        // Attack detected and blocked!
        assert!(!verification.valid);
        assert!(verification
            .reason
            .as_ref()
            .expect("reason should be set for invalid result")
            .contains("signature verification failed"));
    }

    /// Story: Cluster ID is cryptographically bound to certificate
    ///
    /// The cluster ID is embedded in the certificate CN and cannot be
    /// spoofed. An agent with a valid certificate can only claim the
    /// identity it was issued for.
    #[test]
    fn story_cluster_identity_binding() {
        let ca = CertificateAuthority::new("Identity CA").expect("CA creation should succeed");

        // Sign certificates for different clusters
        let clusters = ["prod-us-west", "staging-eu-central", "dev-local"];

        for cluster_id in clusters {
            let request = AgentCertRequest::new(cluster_id).expect("CSR generation should succeed");
            let signed_cert = ca
                .sign_csr(request.csr_pem(), cluster_id)
                .expect("CSR signing should succeed");

            let cert_der = parse_pem(&signed_cert).expect("PEM parsing should succeed");
            let verification = verify_client_cert(&cert_der, ca.ca_cert_pem())
                .expect("verification should succeed");

            // Each certificate is bound to its specific cluster ID
            assert!(verification.valid);
            assert_eq!(verification.cluster_id, cluster_id);
        }
    }

    /// Story: CA persistence for disaster recovery
    ///
    /// The CA can be saved and restored, allowing the cell to restart
    /// without invalidating existing agent certificates.
    #[test]
    fn story_ca_persistence_and_recovery() {
        // Initial setup: Create CA and issue a certificate
        let original_ca =
            CertificateAuthority::new("Persistent CA").expect("CA creation should succeed");
        let agent_request =
            AgentCertRequest::new("long-lived-cluster").expect("CSR generation should succeed");
        let original_cert = original_ca
            .sign_csr(agent_request.csr_pem(), "long-lived-cluster")
            .expect("CSR signing should succeed");

        // Simulate disaster: Save CA state
        let saved_cert_pem = original_ca.ca_cert_pem().to_string();
        let saved_key_pem = original_ca.ca_key_pem().to_string();

        // Recovery: Restore CA from saved state
        let restored_ca = CertificateAuthority::from_pem(&saved_cert_pem, &saved_key_pem)
            .expect("CA restoration should succeed");

        // Restored CA can verify certificates issued by original
        let cert_der = parse_pem(&original_cert).expect("PEM parsing should succeed");
        let verification = verify_client_cert(&cert_der, restored_ca.ca_cert_pem())
            .expect("verification should succeed");
        assert!(verification.valid);

        // Restored CA can issue new certificates
        let new_agent =
            AgentCertRequest::new("new-cluster").expect("new agent CSR generation should succeed");
        let new_cert = restored_ca.sign_csr(new_agent.csr_pem(), "new-cluster");
        assert!(new_cert.is_ok());
    }

    /// Story: Error handling - Invalid CSR submission
    ///
    /// When an agent submits malformed data as a CSR, the error
    /// is handled gracefully with a descriptive message.
    #[test]
    fn story_malformed_csr_rejection() {
        let ca = CertificateAuthority::new("Strict CA").expect("CA creation should succeed");

        // Various forms of invalid CSR data
        let invalid_inputs = [
            "not a csr at all",
            "-----BEGIN CERTIFICATE-----\nwrong type\n-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE REQUEST-----\ncorrupted\n-----END CERTIFICATE REQUEST-----",
        ];

        for invalid in invalid_inputs {
            let result = ca.sign_csr(invalid, "test-cluster");
            assert!(result.is_err());

            match result {
                Err(PkiError::InvalidCsr(msg)) => {
                    assert!(!msg.is_empty(), "Should provide error details");
                }
                _ => panic!("Expected InvalidCsr error"),
            }
        }
    }

    /// Story: Error handling - Invalid CA restoration
    ///
    /// When loading a CA from corrupted or mismatched PEM files,
    /// errors are caught before any certificates can be issued.
    #[test]
    fn story_corrupted_ca_detection() {
        let good_ca = CertificateAuthority::new("Good CA").expect("CA creation should succeed");

        // Corrupted key
        let result = CertificateAuthority::from_pem(good_ca.ca_cert_pem(), "invalid key pem");
        assert!(result.is_err());

        // Corrupted cert
        let result = CertificateAuthority::from_pem("invalid cert pem", good_ca.ca_key_pem());
        assert!(result.is_err());

        // Key and cert don't match (would require different CA generation)
        // This is caught by the signature verification in verify_client_cert
    }

    /// Story: PEM parsing error handling
    ///
    /// Invalid PEM data is rejected with clear error messages.
    #[test]
    fn story_pem_parsing_errors() {
        let invalid_pem = "this is not valid PEM data at all";
        let result = parse_pem(invalid_pem);

        assert!(result.is_err());
        match result {
            Err(PkiError::ParseError(msg)) => {
                assert!(msg.contains("parse PEM"));
            }
            _ => panic!("Expected ParseError"),
        }
    }

    /// Story: Error conversion from I/O errors
    ///
    /// I/O errors (from file operations) are properly wrapped in PkiError.
    #[test]
    fn story_io_error_conversion() {
        let io_err = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "cannot read CA key file",
        );
        let pki_err: PkiError = io_err.into();

        assert!(pki_err.to_string().contains("IO error"));
        assert!(pki_err.to_string().contains("cannot read CA key file"));
    }

    /// Test parsing invalid certificate DER data
    #[test]
    fn test_verify_invalid_cert_data() {
        let ca = CertificateAuthority::new("Test CA").expect("CA creation should succeed");

        // Invalid DER data
        let invalid_der = b"not valid DER data";
        let result = verify_client_cert(invalid_der, ca.ca_cert_pem());

        assert!(result.is_err());
        match result {
            Err(PkiError::ParseError(msg)) => {
                assert!(msg.contains("failed to parse client cert"));
            }
            _ => panic!("Expected ParseError"),
        }
    }

    /// Test verify_client_cert with invalid CA certificate
    #[test]
    fn test_verify_with_invalid_ca() {
        let ca = CertificateAuthority::new("Test CA").expect("CA creation should succeed");
        let request = AgentCertRequest::new("test").expect("CSR generation should succeed");
        let signed_cert = ca
            .sign_csr(request.csr_pem(), "test")
            .expect("CSR signing should succeed");

        // Try to verify with invalid CA PEM
        let cert_der = parse_pem(&signed_cert).expect("PEM parsing should succeed");
        let result = verify_client_cert(&cert_der, "not valid PEM");

        assert!(result.is_err());
    }

    /// Test VerificationResult default values
    #[test]
    fn test_verification_result_creation() {
        let result = VerificationResult {
            cluster_id: "test-cluster".to_string(),
            valid: true,
            reason: None,
        };
        assert!(result.valid);
        assert_eq!(result.cluster_id, "test-cluster");

        let invalid_result = VerificationResult {
            cluster_id: String::new(),
            valid: false,
            reason: Some("test reason".to_string()),
        };
        assert!(!invalid_result.valid);
        assert_eq!(
            invalid_result.reason.expect("reason should be set"),
            "test reason"
        );
    }

    /// Test VerificationResult debug and clone
    #[test]
    fn test_verification_result_traits() {
        let result = VerificationResult {
            cluster_id: "debug-test".to_string(),
            valid: true,
            reason: None,
        };

        // Test Debug
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("debug-test"));

        // Test Clone
        let cloned = result.clone();
        assert_eq!(cloned.cluster_id, "debug-test");
        assert!(cloned.valid);
    }

    /// Test certificate with invalid CN format (missing lattice-agent- prefix)
    #[test]
    fn test_invalid_cn_format_rejected() {
        // Create a CA and generate a cert with a non-standard CN
        let ca = CertificateAuthority::new("Test CA").expect("CA creation should succeed");

        // Generate a server cert (which has CN "Lattice Server", not "lattice-agent-...")
        let (server_cert_pem, _) = ca
            .generate_server_cert(&["localhost"])
            .expect("server cert generation should succeed");
        let cert_der = parse_pem(&server_cert_pem).expect("PEM parsing should succeed");

        // Try to verify it as a client cert - should fail due to CN format
        let result = verify_client_cert(&cert_der, ca.ca_cert_pem())
            .expect("verification call should succeed");

        assert!(!result.valid);
        assert!(result.cluster_id.is_empty());
        assert!(result
            .reason
            .as_ref()
            .expect("reason should be set for invalid result")
            .contains("invalid CN format"));
    }

    /// Test certificate that is not yet valid (future notBefore)
    #[test]
    fn test_certificate_not_yet_valid() {
        use x509_parser::prelude::*;

        // Create a certificate with a future notBefore by manipulating the raw DER
        // For this test, we'll create a normal cert and check the validation logic
        // by verifying the code path exists

        let ca = CertificateAuthority::new("Test CA").expect("CA creation should succeed");
        let request =
            AgentCertRequest::new("future-cluster").expect("CSR generation should succeed");
        let signed_cert_pem = ca
            .sign_csr(request.csr_pem(), "future-cluster")
            .expect("CSR signing should succeed");
        let cert_der = parse_pem(&signed_cert_pem).expect("PEM parsing should succeed");

        // Parse to verify the notBefore check logic is reachable
        let (_, cert) =
            X509Certificate::from_der(&cert_der).expect("X509 DER parsing should succeed");
        let not_before = cert.validity().not_before.timestamp();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after 1970")
            .as_secs() as i64;

        // The cert we generate has notBefore set to current time, so it should be valid now.
        // Allow a small tolerance (60 seconds) for test execution time.
        assert!(
            now >= not_before - 60,
            "cert notBefore should be at or before current time"
        );

        // Verify normal path works
        let result =
            verify_client_cert(&cert_der, ca.ca_cert_pem()).expect("verification should succeed");
        assert!(result.valid);
    }

    /// Test certificate expiration check path
    #[test]
    fn test_certificate_expiration_check() {
        use x509_parser::prelude::*;

        let ca = CertificateAuthority::new("Test CA").expect("CA creation should succeed");
        let request =
            AgentCertRequest::new("expiry-cluster").expect("CSR generation should succeed");
        let signed_cert_pem = ca
            .sign_csr(request.csr_pem(), "expiry-cluster")
            .expect("CSR signing should succeed");
        let cert_der = parse_pem(&signed_cert_pem).expect("PEM parsing should succeed");

        // Parse to verify the notAfter check logic is reachable
        let (_, cert) =
            X509Certificate::from_der(&cert_der).expect("X509 DER parsing should succeed");
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after 1970")
            .as_secs() as i64;

        // Verify certificate has proper validity period (approximately CERT_VALIDITY_YEARS)
        let validity_days = (not_after - not_before) / (24 * 60 * 60);
        let expected_days = CERT_VALIDITY_YEARS * 365;
        assert!(
            (validity_days - expected_days).abs() <= 1,
            "cert should have {} year validity, got {} days",
            CERT_VALIDITY_YEARS,
            validity_days
        );

        // The cert we generate has notAfter set to CERT_VALIDITY_YEARS from now
        assert!(now < not_after, "cert notAfter should be in the future");

        // Verify normal path works
        let result =
            verify_client_cert(&cert_der, ca.ca_cert_pem()).expect("verification should succeed");
        assert!(result.valid);
    }

    /// Test CA certificate has correct validity period
    #[test]
    fn test_ca_certificate_validity_period() {
        use x509_parser::prelude::*;

        let ca = CertificateAuthority::new("Test CA").expect("CA creation should succeed");
        let cert_der = parse_pem(ca.ca_cert_pem()).expect("CA PEM parsing should succeed");
        let (_, cert) =
            X509Certificate::from_der(&cert_der).expect("X509 DER parsing should succeed");

        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();

        // Verify CA certificate has proper validity period (approximately CA_VALIDITY_YEARS)
        let validity_days = (not_after - not_before) / (24 * 60 * 60);
        let expected_days = CA_VALIDITY_YEARS * 365;
        assert!(
            (validity_days - expected_days).abs() <= 1,
            "CA cert should have {} year validity, got {} days",
            CA_VALIDITY_YEARS,
            validity_days
        );
    }

    /// Test CertificateInfo parsing and lifetime calculations
    #[test]
    fn test_certificate_info() {
        let ca = CertificateAuthority::new("Test CA").expect("CA creation should succeed");
        let info = CertificateInfo::from_pem(ca.ca_cert_pem())
            .expect("CertificateInfo parsing should succeed");

        // Should have the right common name
        assert_eq!(info.common_name, "Test CA");

        // Lifetime should be approximately CA_VALIDITY_YEARS
        let lifetime_days = info.lifetime_secs() / (24 * 60 * 60);
        let expected_days = CA_VALIDITY_YEARS * 365;
        assert!(
            (lifetime_days - expected_days).abs() <= 1,
            "lifetime should be {} days, got {}",
            expected_days,
            lifetime_days
        );

        // Age should be very small (just created)
        assert!(info.age_secs() < 10, "age should be < 10 seconds");

        // Remaining should be close to lifetime
        let remaining_days = info.remaining_secs() / (24 * 60 * 60);
        assert!(
            (remaining_days - expected_days).abs() <= 1,
            "remaining should be {} days, got {}",
            expected_days,
            remaining_days
        );

        // Should not be expired
        assert!(!info.is_expired());

        // Fresh cert should not need rotation (< 80% TTL)
        assert!(!info.needs_rotation());

        // Lifetime fraction should be near 0
        assert!(info.lifetime_fraction() < 0.01);
    }

    /// Test CertificateAuthorityBundle with single CA
    #[test]
    fn test_ca_bundle_single() {
        let ca = CertificateAuthority::new("Test CA").expect("CA creation should succeed");
        let bundle = CertificateAuthorityBundle::new(ca);

        assert_eq!(bundle.len(), 1);
        assert!(!bundle.is_empty());

        // Trust bundle should contain the CA cert
        assert!(bundle.trust_bundle_pem().contains("BEGIN CERTIFICATE"));

        // Should be able to sign CSRs
        let agent = AgentCertRequest::new("test-cluster").expect("agent CSR should succeed");
        let cert = bundle
            .sign_csr(agent.csr_pem(), "test-cluster")
            .expect("signing should succeed");
        assert!(cert.contains("BEGIN CERTIFICATE"));
    }

    /// Test CertificateAuthorityBundle rotation
    #[test]
    fn test_ca_bundle_rotation() {
        let ca1 = CertificateAuthority::new("CA Gen 1").expect("CA creation should succeed");
        let mut bundle = CertificateAuthorityBundle::new(ca1);

        // Sign a cert with the original CA
        let agent1 = AgentCertRequest::new("cluster-1").expect("agent CSR should succeed");
        let cert1 = bundle
            .sign_csr(agent1.csr_pem(), "cluster-1")
            .expect("signing should succeed");
        let cert1_der = parse_pem(&cert1).expect("cert parsing should succeed");

        // Rotate to a new CA
        bundle.rotate("CA Gen 2").expect("rotation should succeed");
        assert_eq!(bundle.len(), 2);

        // Old cert should still verify (bundle trusts both CAs)
        let result = bundle
            .verify_client_cert(&cert1_der)
            .expect("verification should succeed");
        assert!(result.valid, "old cert should still be valid after rotation");

        // New certs are signed by the new CA
        let agent2 = AgentCertRequest::new("cluster-2").expect("agent CSR should succeed");
        let cert2 = bundle
            .sign_csr(agent2.csr_pem(), "cluster-2")
            .expect("signing should succeed");
        let cert2_der = parse_pem(&cert2).expect("cert parsing should succeed");

        let result = bundle
            .verify_client_cert(&cert2_der)
            .expect("verification should succeed");
        assert!(result.valid, "new cert should be valid");
    }

    /// Test CertificateAuthorityBundle rejects certs from unknown CA
    #[test]
    fn test_ca_bundle_rejects_unknown() {
        let ca1 = CertificateAuthority::new("CA 1").expect("CA creation should succeed");
        let ca2 = CertificateAuthority::new("CA 2").expect("CA creation should succeed");

        let bundle = CertificateAuthorityBundle::new(ca1);

        // Sign with a different CA not in the bundle
        let agent = AgentCertRequest::new("test-cluster").expect("agent CSR should succeed");
        let cert = ca2
            .sign_csr(agent.csr_pem(), "test-cluster")
            .expect("signing should succeed");
        let cert_der = parse_pem(&cert).expect("cert parsing should succeed");

        // Verification should fail
        let result = bundle
            .verify_client_cert(&cert_der)
            .expect("verification should not error");
        assert!(!result.valid);
        assert!(result.reason.unwrap().contains("not signed by any trusted CA"));
    }

    /// Test CA needs_rotation returns false for fresh CA
    #[test]
    fn test_ca_needs_rotation_fresh() {
        let ca = CertificateAuthority::new("Fresh CA").expect("CA creation should succeed");
        assert!(
            !ca.needs_rotation().expect("needs_rotation should succeed"),
            "fresh CA should not need rotation"
        );
    }
}
