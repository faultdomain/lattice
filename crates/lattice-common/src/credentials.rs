//! Cloud provider credentials
//!
//! Data structures for cloud provider credentials used by CAPI.
//! Each credential type can serialize itself to a K8s Secret.
//!
//! All credential types implement the `CredentialProvider` trait, which provides
//! a consistent interface for loading from environment variables, K8s secrets,
//! and serializing to K8s secrets.

use std::collections::{BTreeMap, HashMap};

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use thiserror::Error;
use tracing::warn;
use zeroize::Zeroizing;

use crate::{
    AWS_CREDENTIALS_SECRET, LATTICE_SYSTEM_NAMESPACE, OPENSTACK_CREDENTIALS_SECRET, PROVIDER_LABEL,
    PROXMOX_CREDENTIALS_SECRET,
};

/// Errors when loading credentials
#[derive(Debug, Error)]
pub enum CredentialError {
    /// Required field missing from secret
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Required environment variable not set
    #[error("environment variable not set: {0}")]
    EnvVarNotSet(&'static str),
}

/// Trait for credential types that can be loaded from environment or K8s secrets.
///
/// All cloud provider credential types (AWS, Proxmox, OpenStack) implement this trait
/// to provide a consistent interface for credential management.
///
/// # Example
/// ```ignore
/// use lattice_common::credentials::{CredentialProvider, AwsCredentials};
///
/// // Load from environment
/// let creds = AwsCredentials::from_env()?;
///
/// // Create K8s secret for storage
/// let secret = creds.to_k8s_secret();
///
/// // Load from K8s secret data
/// let restored = AwsCredentials::from_secret(&secret_data)?;
/// ```
pub trait CredentialProvider: Sized {
    /// The provider identifier used in labels (e.g., "aws", "proxmox", "openstack")
    const PROVIDER_TYPE: &'static str;
    /// The default secret name for this credential type
    const SECRET_NAME: &'static str;

    /// Load credentials from environment variables.
    ///
    /// Returns `Err(CredentialError::EnvVarNotSet)` if required variables are missing.
    fn from_env() -> Result<Self, CredentialError>;

    /// Load credentials from a K8s secret's string data.
    ///
    /// The `data` parameter contains the secret's stringData as key-value pairs.
    /// Returns `Err(CredentialError::MissingField)` if required fields are missing.
    fn from_secret(data: &HashMap<String, String>) -> Result<Self, CredentialError>;

    /// Convert to a K8s Secret for storage in the lattice-system namespace.
    ///
    /// Creates a secret with the standard name and appropriate provider label.
    fn to_k8s_secret(&self) -> Secret;
}

/// Helper to build a K8s Secret with common metadata.
fn build_credential_secret(
    secret_name: &str,
    provider_type: &str,
    string_data: BTreeMap<String, String>,
) -> Secret {
    let mut labels = BTreeMap::new();
    labels.insert(PROVIDER_LABEL.to_string(), provider_type.to_string());

    Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.to_string()),
            namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        type_: Some("Opaque".to_string()),
        string_data: Some(string_data),
        ..Default::default()
    }
}

/// AWS credentials for CAPA provider
#[derive(Debug, Clone)]
pub struct AwsCredentials {
    /// AWS access key ID
    pub access_key_id: String,
    /// AWS secret access key (zeroized on drop)
    pub secret_access_key: Zeroizing<String>,
    /// AWS region
    pub region: String,
    /// Optional session token for temporary credentials (zeroized on drop)
    pub session_token: Option<Zeroizing<String>>,
}

impl CredentialProvider for AwsCredentials {
    const PROVIDER_TYPE: &'static str = "aws";
    const SECRET_NAME: &'static str = AWS_CREDENTIALS_SECRET;

    fn from_env() -> Result<Self, CredentialError> {
        Ok(Self {
            access_key_id: std::env::var("AWS_ACCESS_KEY_ID")
                .map_err(|_| CredentialError::EnvVarNotSet("AWS_ACCESS_KEY_ID"))?,
            secret_access_key: Zeroizing::new(
                std::env::var("AWS_SECRET_ACCESS_KEY")
                    .map_err(|_| CredentialError::EnvVarNotSet("AWS_SECRET_ACCESS_KEY"))?,
            ),
            region: std::env::var("AWS_REGION")
                .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                .map_err(|_| CredentialError::EnvVarNotSet("AWS_REGION or AWS_DEFAULT_REGION"))?,
            session_token: std::env::var("AWS_SESSION_TOKEN").ok().map(Zeroizing::new),
        })
    }

    fn from_secret(data: &HashMap<String, String>) -> Result<Self, CredentialError> {
        Ok(Self {
            access_key_id: data
                .get("AWS_ACCESS_KEY_ID")
                .cloned()
                .ok_or(CredentialError::MissingField("AWS_ACCESS_KEY_ID"))?,
            secret_access_key: Zeroizing::new(
                data.get("AWS_SECRET_ACCESS_KEY")
                    .cloned()
                    .ok_or(CredentialError::MissingField("AWS_SECRET_ACCESS_KEY"))?,
            ),
            region: data
                .get("AWS_REGION")
                .cloned()
                .ok_or(CredentialError::MissingField("AWS_REGION"))?,
            session_token: data.get("AWS_SESSION_TOKEN").cloned().map(Zeroizing::new),
        })
    }

    fn to_k8s_secret(&self) -> Secret {
        let mut string_data = BTreeMap::new();
        string_data.insert("AWS_ACCESS_KEY_ID".to_string(), self.access_key_id.clone());
        string_data.insert(
            "AWS_SECRET_ACCESS_KEY".to_string(),
            (*self.secret_access_key).clone(),
        );
        string_data.insert("AWS_REGION".to_string(), self.region.clone());
        if let Some(ref token) = self.session_token {
            string_data.insert("AWS_SESSION_TOKEN".to_string(), (**token).clone());
        }

        build_credential_secret(Self::SECRET_NAME, Self::PROVIDER_TYPE, string_data)
    }
}

impl AwsCredentials {
    /// Generate AWS_B64ENCODED_CREDENTIALS for CAPI AWS provider
    ///
    /// The AWS provider requires credentials in a base64-encoded INI profile format.
    pub fn to_b64_encoded(&self) -> String {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;

        let mut profile = format!(
            "[default]\naws_access_key_id = {}\naws_secret_access_key = {}\nregion = {}",
            self.access_key_id, *self.secret_access_key, self.region
        );

        if let Some(ref token) = self.session_token {
            profile.push_str(&format!("\naws_session_token = {}", **token));
        }

        STANDARD.encode(profile)
    }
}

/// Proxmox credentials for CAPMOX provider
#[derive(Debug, Clone)]
pub struct ProxmoxCredentials {
    /// Proxmox API URL
    pub url: String,
    /// Proxmox API token ID (zeroized on drop)
    pub token: Zeroizing<String>,
    /// Proxmox API token secret (zeroized on drop)
    pub secret: Zeroizing<String>,
}

impl CredentialProvider for ProxmoxCredentials {
    const PROVIDER_TYPE: &'static str = "proxmox";
    const SECRET_NAME: &'static str = PROXMOX_CREDENTIALS_SECRET;

    fn from_env() -> Result<Self, CredentialError> {
        Ok(Self {
            url: std::env::var("PROXMOX_URL")
                .map_err(|_| CredentialError::EnvVarNotSet("PROXMOX_URL"))?,
            token: Zeroizing::new(
                std::env::var("PROXMOX_TOKEN")
                    .map_err(|_| CredentialError::EnvVarNotSet("PROXMOX_TOKEN"))?,
            ),
            secret: Zeroizing::new(
                std::env::var("PROXMOX_SECRET")
                    .map_err(|_| CredentialError::EnvVarNotSet("PROXMOX_SECRET"))?,
            ),
        })
    }

    fn from_secret(data: &HashMap<String, String>) -> Result<Self, CredentialError> {
        Ok(Self {
            url: data
                .get("url")
                .cloned()
                .ok_or(CredentialError::MissingField("url"))?,
            token: Zeroizing::new(
                data.get("token")
                    .cloned()
                    .ok_or(CredentialError::MissingField("token"))?,
            ),
            secret: Zeroizing::new(
                data.get("secret")
                    .cloned()
                    .ok_or(CredentialError::MissingField("secret"))?,
            ),
        })
    }

    fn to_k8s_secret(&self) -> Secret {
        let mut string_data = BTreeMap::new();
        string_data.insert("url".to_string(), self.url.clone());
        string_data.insert("token".to_string(), (*self.token).clone());
        string_data.insert("secret".to_string(), (*self.secret).clone());

        build_credential_secret(Self::SECRET_NAME, Self::PROVIDER_TYPE, string_data)
    }
}

/// OpenStack credentials for CAPO provider
#[derive(Debug, Clone)]
pub struct OpenStackCredentials {
    /// Full clouds.yaml file content (contains passwords, zeroized on drop)
    pub clouds_yaml: Zeroizing<String>,
    /// Cloud name within clouds.yaml (default: "openstack")
    pub cloud_name: String,
    /// Optional CA certificate for self-signed endpoints
    pub cacert: Option<String>,
}

impl CredentialProvider for OpenStackCredentials {
    const PROVIDER_TYPE: &'static str = "openstack";
    const SECRET_NAME: &'static str = OPENSTACK_CREDENTIALS_SECRET;

    fn from_env() -> Result<Self, CredentialError> {
        let clouds_yaml =
            Zeroizing::new(if let Ok(path) = std::env::var("OPENSTACK_CLOUD_CONFIG") {
                std::fs::read_to_string(&path).map_err(|_| {
                    CredentialError::EnvVarNotSet("OPENSTACK_CLOUD_CONFIG (file not readable)")
                })?
            } else {
                Self::build_clouds_yaml_from_env()?
            });

        let cloud_name = std::env::var("OS_CLOUD").unwrap_or_else(|_| "openstack".to_string());

        // Load CA cert with proper error logging instead of silently ignoring failures
        let cacert = match std::env::var("OPENSTACK_CACERT") {
            Ok(path) => match std::fs::read_to_string(&path) {
                Ok(content) => Some(content),
                Err(e) => {
                    warn!(
                        path = %path,
                        error = %e,
                        "Failed to read OpenStack CA certificate file"
                    );
                    None
                }
            },
            Err(_) => None,
        };

        Ok(Self {
            clouds_yaml,
            cloud_name,
            cacert,
        })
    }

    fn from_secret(data: &HashMap<String, String>) -> Result<Self, CredentialError> {
        Ok(Self {
            clouds_yaml: Zeroizing::new(
                data.get("clouds.yaml")
                    .cloned()
                    .ok_or(CredentialError::MissingField("clouds.yaml"))?,
            ),
            cloud_name: data
                .get("cloud")
                .cloned()
                .unwrap_or_else(|| "openstack".to_string()),
            cacert: data.get("cacert").cloned(),
        })
    }

    fn to_k8s_secret(&self) -> Secret {
        let mut string_data = BTreeMap::new();
        string_data.insert("clouds.yaml".to_string(), (*self.clouds_yaml).clone());
        string_data.insert("cloud".to_string(), self.cloud_name.clone());
        if let Some(ref cacert) = self.cacert {
            string_data.insert("cacert".to_string(), cacert.clone());
        }

        build_credential_secret(Self::SECRET_NAME, Self::PROVIDER_TYPE, string_data)
    }
}

impl OpenStackCredentials {
    /// Build a clouds.yaml from individual OS_* environment variables
    fn build_clouds_yaml_from_env() -> Result<String, CredentialError> {
        let auth_url = std::env::var("OS_AUTH_URL")
            .map_err(|_| CredentialError::EnvVarNotSet("OPENSTACK_CLOUD_CONFIG or OS_AUTH_URL"))?;
        let username = std::env::var("OS_USERNAME")
            .map_err(|_| CredentialError::EnvVarNotSet("OS_USERNAME"))?;
        let password = std::env::var("OS_PASSWORD")
            .map_err(|_| CredentialError::EnvVarNotSet("OS_PASSWORD"))?;
        // Support both OS_PROJECT_NAME (v3) and OS_TENANT_NAME (v2, legacy)
        let project_name = std::env::var("OS_PROJECT_NAME")
            .or_else(|_| std::env::var("OS_TENANT_NAME"))
            .map_err(|_| CredentialError::EnvVarNotSet("OS_PROJECT_NAME or OS_TENANT_NAME"))?;
        let user_domain =
            std::env::var("OS_USER_DOMAIN_NAME").unwrap_or_else(|_| "Default".to_string());
        let project_domain =
            std::env::var("OS_PROJECT_DOMAIN_NAME").unwrap_or_else(|_| "Default".to_string());
        let region = std::env::var("OS_REGION_NAME").unwrap_or_else(|_| "RegionOne".to_string());

        Ok(format!(
            r#"clouds:
  openstack:
    auth:
      auth_url: {auth_url}
      username: {username}
      password: {password}
      project_name: {project_name}
      user_domain_name: {user_domain}
      project_domain_name: {project_domain}
    region_name: {region}
    interface: public
    identity_api_version: 3"#
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use zeroize::Zeroizing;

    #[test]
    fn test_aws_credentials_from_secret() {
        let mut secret = HashMap::new();
        secret.insert("AWS_ACCESS_KEY_ID".to_string(), "AKID".to_string());
        secret.insert("AWS_SECRET_ACCESS_KEY".to_string(), "SECRET".to_string());
        secret.insert("AWS_REGION".to_string(), "us-west-2".to_string());

        let creds = AwsCredentials::from_secret(&secret).unwrap();
        assert_eq!(creds.access_key_id, "AKID");
        assert_eq!(creds.region, "us-west-2");
        assert!(creds.session_token.is_none());
    }

    #[test]
    fn test_aws_credentials_from_secret_with_session_token() {
        let mut secret = HashMap::new();
        secret.insert("AWS_ACCESS_KEY_ID".to_string(), "AKID".to_string());
        secret.insert("AWS_SECRET_ACCESS_KEY".to_string(), "SECRET".to_string());
        secret.insert("AWS_REGION".to_string(), "us-east-1".to_string());
        secret.insert("AWS_SESSION_TOKEN".to_string(), "token123".to_string());

        let creds = AwsCredentials::from_secret(&secret).unwrap();
        assert_eq!(
            creds.session_token,
            Some(Zeroizing::new("token123".to_string()))
        );
    }

    #[test]
    fn test_aws_credentials_from_secret_missing_access_key() {
        let mut secret = HashMap::new();
        secret.insert("AWS_SECRET_ACCESS_KEY".to_string(), "SECRET".to_string());
        secret.insert("AWS_REGION".to_string(), "us-west-2".to_string());

        let err = AwsCredentials::from_secret(&secret).unwrap_err();
        assert!(matches!(
            err,
            CredentialError::MissingField("AWS_ACCESS_KEY_ID")
        ));
    }

    #[test]
    fn test_aws_credentials_from_secret_missing_secret_key() {
        let mut secret = HashMap::new();
        secret.insert("AWS_ACCESS_KEY_ID".to_string(), "AKID".to_string());
        secret.insert("AWS_REGION".to_string(), "us-west-2".to_string());

        let err = AwsCredentials::from_secret(&secret).unwrap_err();
        assert!(matches!(
            err,
            CredentialError::MissingField("AWS_SECRET_ACCESS_KEY")
        ));
    }

    #[test]
    fn test_aws_credentials_from_secret_missing_region() {
        let mut secret = HashMap::new();
        secret.insert("AWS_ACCESS_KEY_ID".to_string(), "AKID".to_string());
        secret.insert("AWS_SECRET_ACCESS_KEY".to_string(), "SECRET".to_string());

        let err = AwsCredentials::from_secret(&secret).unwrap_err();
        assert!(matches!(err, CredentialError::MissingField("AWS_REGION")));
    }

    #[test]
    fn test_aws_credentials_b64_encoded() {
        let creds = AwsCredentials {
            access_key_id: "AKID".to_string(),
            secret_access_key: Zeroizing::new("SECRET".to_string()),
            region: "us-west-2".to_string(),
            session_token: None,
        };

        let encoded = creds.to_b64_encoded();
        let decoded = String::from_utf8(STANDARD.decode(&encoded).unwrap()).unwrap();

        assert!(decoded.contains("[default]"));
        assert!(decoded.contains("aws_access_key_id = AKID"));
        assert!(decoded.contains("aws_secret_access_key = SECRET"));
        assert!(decoded.contains("region = us-west-2"));
        assert!(!decoded.contains("aws_session_token"));
    }

    #[test]
    fn test_aws_credentials_b64_encoded_with_session_token() {
        let creds = AwsCredentials {
            access_key_id: "AKID".to_string(),
            secret_access_key: Zeroizing::new("SECRET".to_string()),
            region: "us-west-2".to_string(),
            session_token: Some(Zeroizing::new("my-session-token".to_string())),
        };

        let encoded = creds.to_b64_encoded();
        let decoded = String::from_utf8(STANDARD.decode(&encoded).unwrap()).unwrap();

        assert!(decoded.contains("[default]"));
        assert!(decoded.contains("aws_session_token = my-session-token"));
    }

    #[test]
    fn test_aws_credentials_to_k8s_secret() {
        let creds = AwsCredentials {
            access_key_id: "AKID".to_string(),
            secret_access_key: Zeroizing::new("SECRET".to_string()),
            region: "us-west-2".to_string(),
            session_token: None,
        };

        let secret = creds.to_k8s_secret();
        assert_eq!(
            secret.metadata.name,
            Some(AWS_CREDENTIALS_SECRET.to_string())
        );
        assert_eq!(
            secret.metadata.namespace,
            Some(LATTICE_SYSTEM_NAMESPACE.to_string())
        );

        let labels = secret.metadata.labels.unwrap();
        assert_eq!(labels.get(PROVIDER_LABEL), Some(&"aws".to_string()));

        let data = secret.string_data.unwrap();
        assert_eq!(data.get("AWS_ACCESS_KEY_ID"), Some(&"AKID".to_string()));
        assert_eq!(
            data.get("AWS_SECRET_ACCESS_KEY"),
            Some(&"SECRET".to_string())
        );
        assert_eq!(data.get("AWS_REGION"), Some(&"us-west-2".to_string()));
        assert!(!data.contains_key("AWS_SESSION_TOKEN"));
    }

    #[test]
    fn test_aws_credentials_to_k8s_secret_with_session_token() {
        let creds = AwsCredentials {
            access_key_id: "AKID".to_string(),
            secret_access_key: Zeroizing::new("SECRET".to_string()),
            region: "us-west-2".to_string(),
            session_token: Some(Zeroizing::new("token123".to_string())),
        };

        let secret = creds.to_k8s_secret();
        let data = secret.string_data.unwrap();
        assert_eq!(data.get("AWS_SESSION_TOKEN"), Some(&"token123".to_string()));
    }

    #[test]
    fn test_credential_error_display() {
        let err = CredentialError::MissingField("AWS_ACCESS_KEY_ID");
        assert_eq!(err.to_string(), "missing required field: AWS_ACCESS_KEY_ID");

        let err = CredentialError::EnvVarNotSet("AWS_REGION");
        assert_eq!(err.to_string(), "environment variable not set: AWS_REGION");
    }

    #[test]
    fn test_proxmox_credentials_from_secret() {
        let mut secret = HashMap::new();
        secret.insert(
            "url".to_string(),
            "https://pve.example.com:8006".to_string(),
        );
        secret.insert("token".to_string(), "user@pam!token".to_string());
        secret.insert("secret".to_string(), "secret-value".to_string());

        let creds = ProxmoxCredentials::from_secret(&secret).unwrap();
        assert_eq!(creds.url, "https://pve.example.com:8006");
        assert_eq!(&*creds.token, "user@pam!token");
        assert_eq!(&*creds.secret, "secret-value");
    }

    #[test]
    fn test_proxmox_credentials_from_secret_missing_url() {
        let mut secret = HashMap::new();
        secret.insert("token".to_string(), "user@pam!token".to_string());
        secret.insert("secret".to_string(), "secret-value".to_string());

        let err = ProxmoxCredentials::from_secret(&secret).unwrap_err();
        assert!(matches!(err, CredentialError::MissingField("url")));
    }

    #[test]
    fn test_proxmox_credentials_from_secret_missing_token() {
        let mut secret = HashMap::new();
        secret.insert(
            "url".to_string(),
            "https://pve.example.com:8006".to_string(),
        );
        secret.insert("secret".to_string(), "secret-value".to_string());

        let err = ProxmoxCredentials::from_secret(&secret).unwrap_err();
        assert!(matches!(err, CredentialError::MissingField("token")));
    }

    #[test]
    fn test_proxmox_credentials_from_secret_missing_secret() {
        let mut secret = HashMap::new();
        secret.insert(
            "url".to_string(),
            "https://pve.example.com:8006".to_string(),
        );
        secret.insert("token".to_string(), "user@pam!token".to_string());

        let err = ProxmoxCredentials::from_secret(&secret).unwrap_err();
        assert!(matches!(err, CredentialError::MissingField("secret")));
    }

    #[test]
    fn test_proxmox_credentials_to_k8s_secret() {
        let creds = ProxmoxCredentials {
            url: "https://pve.example.com:8006".to_string(),
            token: Zeroizing::new("user@pam!token".to_string()),
            secret: Zeroizing::new("secret-value".to_string()),
        };

        let secret = creds.to_k8s_secret();
        assert_eq!(
            secret.metadata.name,
            Some(PROXMOX_CREDENTIALS_SECRET.to_string())
        );
        assert_eq!(
            secret.metadata.namespace,
            Some(LATTICE_SYSTEM_NAMESPACE.to_string())
        );

        let labels = secret.metadata.labels.unwrap();
        assert_eq!(labels.get(PROVIDER_LABEL), Some(&"proxmox".to_string()));

        let data = secret.string_data.unwrap();
        assert_eq!(
            data.get("url"),
            Some(&"https://pve.example.com:8006".to_string())
        );
        assert_eq!(data.get("token"), Some(&"user@pam!token".to_string()));
        assert_eq!(data.get("secret"), Some(&"secret-value".to_string()));
    }

    #[test]
    fn test_openstack_credentials_from_secret() {
        let mut secret = HashMap::new();
        secret.insert(
            "clouds.yaml".to_string(),
            "clouds:\n  openstack:\n    auth:\n      auth_url: https://keystone.example.com"
                .to_string(),
        );
        secret.insert("cloud".to_string(), "mycloud".to_string());

        let creds = OpenStackCredentials::from_secret(&secret).unwrap();
        assert!(creds.clouds_yaml.contains("keystone.example.com"));
        assert_eq!(creds.cloud_name, "mycloud");
        assert!(creds.cacert.is_none());
    }

    #[test]
    fn test_openstack_credentials_from_secret_with_cacert() {
        let mut secret = HashMap::new();
        secret.insert("clouds.yaml".to_string(), "clouds: {}".to_string());
        secret.insert(
            "cacert".to_string(),
            "-----BEGIN CERTIFICATE-----".to_string(),
        );

        let creds = OpenStackCredentials::from_secret(&secret).unwrap();
        assert_eq!(
            creds.cacert,
            Some("-----BEGIN CERTIFICATE-----".to_string())
        );
    }

    #[test]
    fn test_openstack_credentials_from_secret_default_cloud_name() {
        let mut secret = HashMap::new();
        secret.insert("clouds.yaml".to_string(), "clouds: {}".to_string());

        let creds = OpenStackCredentials::from_secret(&secret).unwrap();
        assert_eq!(creds.cloud_name, "openstack");
    }

    #[test]
    fn test_openstack_credentials_from_secret_missing_clouds_yaml() {
        let mut secret = HashMap::new();
        secret.insert("cloud".to_string(), "mycloud".to_string());

        let err = OpenStackCredentials::from_secret(&secret).unwrap_err();
        assert!(matches!(err, CredentialError::MissingField("clouds.yaml")));
    }

    #[test]
    fn test_openstack_credentials_to_k8s_secret() {
        let creds = OpenStackCredentials {
            clouds_yaml: Zeroizing::new("clouds:\n  mycloud:\n    auth: {}".to_string()),
            cloud_name: "mycloud".to_string(),
            cacert: None,
        };

        let secret = creds.to_k8s_secret();
        assert_eq!(
            secret.metadata.name,
            Some(OPENSTACK_CREDENTIALS_SECRET.to_string())
        );
        assert_eq!(
            secret.metadata.namespace,
            Some(LATTICE_SYSTEM_NAMESPACE.to_string())
        );

        let labels = secret.metadata.labels.unwrap();
        assert_eq!(labels.get(PROVIDER_LABEL), Some(&"openstack".to_string()));

        let data = secret.string_data.unwrap();
        assert_eq!(
            data.get("clouds.yaml"),
            Some(&"clouds:\n  mycloud:\n    auth: {}".to_string())
        );
        assert_eq!(data.get("cloud"), Some(&"mycloud".to_string()));
        assert!(!data.contains_key("cacert"));
    }

    #[test]
    fn test_openstack_credentials_to_k8s_secret_with_cacert() {
        let creds = OpenStackCredentials {
            clouds_yaml: Zeroizing::new("clouds: {}".to_string()),
            cloud_name: "openstack".to_string(),
            cacert: Some("-----BEGIN CERTIFICATE-----".to_string()),
        };

        let secret = creds.to_k8s_secret();
        let data = secret.string_data.unwrap();
        assert_eq!(
            data.get("cacert"),
            Some(&"-----BEGIN CERTIFICATE-----".to_string())
        );
    }
}
