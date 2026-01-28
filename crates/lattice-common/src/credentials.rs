//! Cloud provider credentials
//!
//! Data structures for cloud provider credentials used by CAPI.

use std::collections::HashMap;
use thiserror::Error;

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
        assert!(matches!(err, CredentialError::MissingField("AWS_ACCESS_KEY_ID")));
        assert!(err.to_string().contains("AWS_ACCESS_KEY_ID"));
    }

    #[test]
    fn test_aws_credentials_from_secret_missing_secret_key() {
        let mut secret = HashMap::new();
        secret.insert("AWS_ACCESS_KEY_ID".to_string(), "AKID".to_string());
        secret.insert("AWS_REGION".to_string(), "us-west-2".to_string());

        let err = AwsCredentials::from_secret(&secret).unwrap_err();
        assert!(matches!(err, CredentialError::MissingField("AWS_SECRET_ACCESS_KEY")));
        assert!(err.to_string().contains("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn test_aws_credentials_from_secret_missing_region() {
        let mut secret = HashMap::new();
        secret.insert("AWS_ACCESS_KEY_ID".to_string(), "AKID".to_string());
        secret.insert("AWS_SECRET_ACCESS_KEY".to_string(), "SECRET".to_string());

        let err = AwsCredentials::from_secret(&secret).unwrap_err();
        assert!(matches!(err, CredentialError::MissingField("AWS_REGION")));
        assert!(err.to_string().contains("AWS_REGION"));
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
    fn test_credential_error_display() {
        let err = CredentialError::MissingField("AWS_ACCESS_KEY_ID");
        assert_eq!(err.to_string(), "missing required field: AWS_ACCESS_KEY_ID");

        let err = CredentialError::EnvVarNotSet("AWS_REGION");
        assert_eq!(err.to_string(), "environment variable not set: AWS_REGION");
    }
}
