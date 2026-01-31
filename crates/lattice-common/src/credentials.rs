//! Cloud provider credentials
//!
//! Data structures for cloud provider credentials used by CAPI.
//! Each credential type can serialize itself to a K8s Secret.

use std::collections::{BTreeMap, HashMap};

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use thiserror::Error;

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

/// AWS credentials for CAPA provider
#[derive(Debug, Clone)]
pub struct AwsCredentials {
    /// AWS access key ID
    pub access_key_id: String,
    /// AWS secret access key
    pub secret_access_key: String,
    /// AWS region
    pub region: String,
    /// Optional session token for temporary credentials
    pub session_token: Option<String>,
}

impl AwsCredentials {
    /// Load credentials from environment variables
    pub fn from_env() -> Result<Self, CredentialError> {
        Ok(Self {
            access_key_id: std::env::var("AWS_ACCESS_KEY_ID")
                .map_err(|_| CredentialError::EnvVarNotSet("AWS_ACCESS_KEY_ID"))?,
            secret_access_key: std::env::var("AWS_SECRET_ACCESS_KEY")
                .map_err(|_| CredentialError::EnvVarNotSet("AWS_SECRET_ACCESS_KEY"))?,
            region: std::env::var("AWS_REGION")
                .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                .map_err(|_| CredentialError::EnvVarNotSet("AWS_REGION or AWS_DEFAULT_REGION"))?,
            session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
        })
    }

    /// Load credentials from a K8s secret's string data
    pub fn from_secret(secret: &HashMap<String, String>) -> Result<Self, CredentialError> {
        Ok(Self {
            access_key_id: secret
                .get("AWS_ACCESS_KEY_ID")
                .cloned()
                .ok_or(CredentialError::MissingField("AWS_ACCESS_KEY_ID"))?,
            secret_access_key: secret
                .get("AWS_SECRET_ACCESS_KEY")
                .cloned()
                .ok_or(CredentialError::MissingField("AWS_SECRET_ACCESS_KEY"))?,
            region: secret
                .get("AWS_REGION")
                .cloned()
                .ok_or(CredentialError::MissingField("AWS_REGION"))?,
            session_token: secret.get("AWS_SESSION_TOKEN").cloned(),
        })
    }

    /// Generate AWS_B64ENCODED_CREDENTIALS for clusterctl
    ///
    /// clusterctl requires credentials in a base64-encoded INI profile format.
    pub fn to_b64_encoded(&self) -> String {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;

        let mut profile = format!(
            "[default]\naws_access_key_id = {}\naws_secret_access_key = {}\nregion = {}",
            self.access_key_id, self.secret_access_key, self.region
        );

        if let Some(ref token) = self.session_token {
            profile.push_str(&format!("\naws_session_token = {}", token));
        }

        STANDARD.encode(profile)
    }

    /// Convert to a K8s Secret for storage in lattice-system namespace
    pub fn to_k8s_secret(&self) -> Secret {
        let mut string_data = BTreeMap::new();
        string_data.insert("AWS_ACCESS_KEY_ID".to_string(), self.access_key_id.clone());
        string_data.insert(
            "AWS_SECRET_ACCESS_KEY".to_string(),
            self.secret_access_key.clone(),
        );
        string_data.insert("AWS_REGION".to_string(), self.region.clone());
        if let Some(ref token) = self.session_token {
            string_data.insert("AWS_SESSION_TOKEN".to_string(), token.clone());
        }

        let mut labels = BTreeMap::new();
        labels.insert(PROVIDER_LABEL.to_string(), "aws".to_string());

        Secret {
            metadata: ObjectMeta {
                name: Some(AWS_CREDENTIALS_SECRET.to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            type_: Some("Opaque".to_string()),
            string_data: Some(string_data),
            ..Default::default()
        }
    }
}

/// Proxmox credentials for CAPMOX provider
#[derive(Debug, Clone)]
pub struct ProxmoxCredentials {
    /// Proxmox API URL
    pub url: String,
    /// Proxmox API token ID
    pub token: String,
    /// Proxmox API token secret
    pub secret: String,
}

impl ProxmoxCredentials {
    /// Load credentials from environment variables
    pub fn from_env() -> Result<Self, CredentialError> {
        Ok(Self {
            url: std::env::var("PROXMOX_URL")
                .map_err(|_| CredentialError::EnvVarNotSet("PROXMOX_URL"))?,
            token: std::env::var("PROXMOX_TOKEN")
                .map_err(|_| CredentialError::EnvVarNotSet("PROXMOX_TOKEN"))?,
            secret: std::env::var("PROXMOX_SECRET")
                .map_err(|_| CredentialError::EnvVarNotSet("PROXMOX_SECRET"))?,
        })
    }

    /// Load credentials from a K8s secret's string data
    pub fn from_secret(data: &HashMap<String, String>) -> Result<Self, CredentialError> {
        Ok(Self {
            url: data
                .get("url")
                .cloned()
                .ok_or(CredentialError::MissingField("url"))?,
            token: data
                .get("token")
                .cloned()
                .ok_or(CredentialError::MissingField("token"))?,
            secret: data
                .get("secret")
                .cloned()
                .ok_or(CredentialError::MissingField("secret"))?,
        })
    }

    /// Convert to a K8s Secret for storage in lattice-system namespace
    pub fn to_k8s_secret(&self) -> Secret {
        let mut string_data = BTreeMap::new();
        string_data.insert("url".to_string(), self.url.clone());
        string_data.insert("token".to_string(), self.token.clone());
        string_data.insert("secret".to_string(), self.secret.clone());

        let mut labels = BTreeMap::new();
        labels.insert(PROVIDER_LABEL.to_string(), "proxmox".to_string());

        Secret {
            metadata: ObjectMeta {
                name: Some(PROXMOX_CREDENTIALS_SECRET.to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            type_: Some("Opaque".to_string()),
            string_data: Some(string_data),
            ..Default::default()
        }
    }
}

/// OpenStack credentials for CAPO provider
#[derive(Debug, Clone)]
pub struct OpenStackCredentials {
    /// Full clouds.yaml file content
    pub clouds_yaml: String,
    /// Cloud name within clouds.yaml (default: "openstack")
    pub cloud_name: String,
    /// Optional CA certificate for self-signed endpoints
    pub cacert: Option<String>,
}

impl OpenStackCredentials {
    /// Load credentials from environment variables
    ///
    /// Supports two modes:
    /// 1. OPENSTACK_CLOUD_CONFIG points to a clouds.yaml file
    /// 2. Individual OS_* environment variables are used to build clouds.yaml
    pub fn from_env() -> Result<Self, CredentialError> {
        let clouds_yaml = if let Ok(path) = std::env::var("OPENSTACK_CLOUD_CONFIG") {
            std::fs::read_to_string(&path).map_err(|_| {
                CredentialError::EnvVarNotSet("OPENSTACK_CLOUD_CONFIG (file not readable)")
            })?
        } else {
            Self::build_clouds_yaml_from_env()?
        };

        let cloud_name = std::env::var("OS_CLOUD").unwrap_or_else(|_| "openstack".to_string());
        let cacert = std::env::var("OPENSTACK_CACERT")
            .ok()
            .and_then(|path| std::fs::read_to_string(&path).ok());

        Ok(Self {
            clouds_yaml,
            cloud_name,
            cacert,
        })
    }

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

    /// Load credentials from a K8s secret's string data
    pub fn from_secret(data: &HashMap<String, String>) -> Result<Self, CredentialError> {
        Ok(Self {
            clouds_yaml: data
                .get("clouds.yaml")
                .cloned()
                .ok_or(CredentialError::MissingField("clouds.yaml"))?,
            cloud_name: data
                .get("cloud")
                .cloned()
                .unwrap_or_else(|| "openstack".to_string()),
            cacert: data.get("cacert").cloned(),
        })
    }

    /// Convert to a K8s Secret for storage in lattice-system namespace
    pub fn to_k8s_secret(&self) -> Secret {
        let mut string_data = BTreeMap::new();
        string_data.insert("clouds.yaml".to_string(), self.clouds_yaml.clone());
        string_data.insert("cloud".to_string(), self.cloud_name.clone());
        if let Some(ref cacert) = self.cacert {
            string_data.insert("cacert".to_string(), cacert.clone());
        }

        let mut labels = BTreeMap::new();
        labels.insert(PROVIDER_LABEL.to_string(), "openstack".to_string());

        Secret {
            metadata: ObjectMeta {
                name: Some(OPENSTACK_CREDENTIALS_SECRET.to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                labels: Some(labels),
                ..Default::default()
            },
            type_: Some("Opaque".to_string()),
            string_data: Some(string_data),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

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
        assert_eq!(creds.session_token, Some("token123".to_string()));
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
            secret_access_key: "SECRET".to_string(),
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
            secret_access_key: "SECRET".to_string(),
            region: "us-west-2".to_string(),
            session_token: Some("my-session-token".to_string()),
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
            secret_access_key: "SECRET".to_string(),
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
            secret_access_key: "SECRET".to_string(),
            region: "us-west-2".to_string(),
            session_token: Some("token123".to_string()),
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
        assert_eq!(creds.token, "user@pam!token");
        assert_eq!(creds.secret, "secret-value");
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
            token: "user@pam!token".to_string(),
            secret: "secret-value".to_string(),
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
            clouds_yaml: "clouds:\n  mycloud:\n    auth: {}".to_string(),
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
            clouds_yaml: "clouds: {}".to_string(),
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
