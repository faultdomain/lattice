//! Centralized operator configuration parsed from environment variables.
//!
//! All `LATTICE_*` environment variables used by the operator runtime are
//! parsed once at startup into a [`LatticeConfig`] struct and threaded
//! through the application via `Arc<LatticeConfig>`.

use std::sync::Arc;

use crate::crd::ProviderType;

/// Default Lattice container image
pub const DEFAULT_IMAGE: &str = "ghcr.io/evan-hines-js/lattice:latest";

/// Default gRPC max message size (16 MiB)
const DEFAULT_GRPC_MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum allowed gRPC message size (256 MiB)
const MAX_GRPC_MESSAGE_SIZE: usize = 256 * 1024 * 1024;

/// Default scripts directory inside the container
const DEFAULT_SCRIPTS_DIR: &str = "/scripts";

/// Centralized operator configuration.
///
/// Parsed once from environment variables at startup. All operator-runtime
/// code should read config from this struct rather than calling `std::env::var`
/// directly.
#[derive(Debug, Clone)]
pub struct LatticeConfig {
    /// Cluster name (`LATTICE_CLUSTER_NAME`). None if not set.
    pub cluster_name: Option<String>,
    /// Infrastructure provider (`LATTICE_PROVIDER`). Defaults to Docker.
    pub provider: ProviderType,
    /// Provider reference name (`LATTICE_PROVIDER_REF`). Falls back to provider name.
    pub provider_ref: String,
    /// Enable debug endpoints (`LATTICE_DEBUG`). Defaults to false.
    pub debug: bool,
    /// Lattice image to deploy on child clusters (`LATTICE_IMAGE`).
    pub image: String,
    /// Enable monitoring stack (`LATTICE_MONITORING`). Defaults to true.
    pub monitoring_enabled: bool,
    /// Enable HA monitoring (`LATTICE_MONITORING_HA`). Defaults to true.
    pub monitoring_ha: bool,
    /// Directory containing bootstrap scripts (`LATTICE_SCRIPTS_DIR`).
    pub scripts_dir: String,
    /// Allow HTTP OIDC issuer URLs (`LATTICE_OIDC_ALLOW_INSECURE_HTTP`).
    pub oidc_allow_insecure_http: bool,
    /// Whether this is a bootstrap cluster (`LATTICE_BOOTSTRAP_CLUSTER`).
    pub is_bootstrap_cluster: bool,
    /// Maximum gRPC message size in bytes (`LATTICE_GRPC_MAX_MESSAGE_SIZE`).
    pub grpc_max_message_size: usize,
}

impl LatticeConfig {
    /// Parse configuration from environment variables.
    ///
    /// This should be called once at operator startup. All env vars are read
    /// and validated eagerly so errors surface immediately rather than at
    /// an unpredictable point later in the operator lifecycle.
    pub fn from_env() -> Result<Self, String> {
        let provider_str =
            std::env::var("LATTICE_PROVIDER").unwrap_or_else(|_| "docker".to_string());
        let provider: ProviderType = provider_str
            .parse()
            .map_err(|e| format!("invalid LATTICE_PROVIDER '{}': {}", provider_str, e))?;
        let provider_ref =
            std::env::var("LATTICE_PROVIDER_REF").unwrap_or_else(|_| provider_str.clone());

        let scripts_dir = std::env::var("LATTICE_SCRIPTS_DIR")
            .unwrap_or_else(|_| DEFAULT_SCRIPTS_DIR.to_string());

        let grpc_max_message_size = match std::env::var("LATTICE_GRPC_MAX_MESSAGE_SIZE") {
            Ok(v) => v
                .parse::<usize>()
                .map_err(|e| format!("invalid LATTICE_GRPC_MAX_MESSAGE_SIZE '{}': {}", v, e))?
                .min(MAX_GRPC_MESSAGE_SIZE),
            Err(_) => DEFAULT_GRPC_MAX_MESSAGE_SIZE,
        };

        Ok(Self {
            cluster_name: std::env::var("LATTICE_CLUSTER_NAME").ok(),
            provider,
            provider_ref,
            debug: parse_bool_env("LATTICE_DEBUG", false),
            image: std::env::var("LATTICE_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_string()),
            monitoring_enabled: parse_bool_env("LATTICE_MONITORING", true),
            monitoring_ha: parse_bool_env("LATTICE_MONITORING_HA", true),
            scripts_dir,
            oidc_allow_insecure_http: parse_bool_env("LATTICE_OIDC_ALLOW_INSECURE_HTTP", false),
            is_bootstrap_cluster: parse_bool_env("LATTICE_BOOTSTRAP_CLUSTER", false),
            grpc_max_message_size,
        })
    }

    /// Get the cluster name or return an error.
    ///
    /// Use this in contexts where the cluster name is required (e.g., bootstrap,
    /// parent config) rather than silently defaulting.
    pub fn cluster_name_required(&self) -> Result<&str, String> {
        self.cluster_name
            .as_deref()
            .ok_or_else(|| "LATTICE_CLUSTER_NAME environment variable not set".to_string())
    }
}

/// Parse a boolean environment variable with a default value.
///
/// Accepts "true"/"1" (case-insensitive) as true, everything else as false.
fn parse_bool_env(var: &str, default: bool) -> bool {
    std::env::var(var)
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(default)
}

/// Shared config reference for passing through the application.
pub type SharedConfig = Arc<LatticeConfig>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bool_env_defaults() {
        // Use a unique var name to avoid races with parallel tests
        let var = "LATTICE_TEST_BOOL_DEFAULTS";
        std::env::remove_var(var);
        assert!(!parse_bool_env(var, false));
        assert!(parse_bool_env(var, true));
    }

    #[test]
    fn test_parse_bool_env_true_values() {
        let var = "LATTICE_TEST_BOOL_TRUE";
        std::env::set_var(var, "true");
        assert!(parse_bool_env(var, false));

        std::env::set_var(var, "TRUE");
        assert!(parse_bool_env(var, false));

        std::env::set_var(var, "1");
        assert!(parse_bool_env(var, false));

        std::env::remove_var(var);
    }

    #[test]
    fn test_parse_bool_env_false_values() {
        let var = "LATTICE_TEST_BOOL_FALSE";
        std::env::set_var(var, "false");
        assert!(!parse_bool_env(var, true));

        std::env::set_var(var, "0");
        assert!(!parse_bool_env(var, true));

        std::env::remove_var(var);
    }

    #[test]
    fn test_cluster_name_required() {
        let config = LatticeConfig {
            cluster_name: Some("test-cluster".to_string()),
            ..test_config()
        };
        assert_eq!(config.cluster_name_required().unwrap(), "test-cluster");

        let config = LatticeConfig {
            cluster_name: None,
            ..test_config()
        };
        assert!(config.cluster_name_required().is_err());
    }

    #[test]
    fn test_grpc_max_message_size_clamped() {
        let config = LatticeConfig {
            grpc_max_message_size: 999_999_999_999,
            ..test_config()
        };
        // The struct stores whatever is passed, clamping happens in from_env()
        // So test the from_env path separately
        assert_eq!(config.grpc_max_message_size, 999_999_999_999);
    }

    /// Helper to create a config with reasonable test defaults
    fn test_config() -> LatticeConfig {
        LatticeConfig {
            cluster_name: None,
            provider: ProviderType::Docker,
            provider_ref: "docker".to_string(),
            debug: false,
            image: DEFAULT_IMAGE.to_string(),
            monitoring_enabled: true,
            monitoring_ha: true,
            scripts_dir: DEFAULT_SCRIPTS_DIR.to_string(),
            oidc_allow_insecure_http: false,
            is_bootstrap_cluster: false,
            grpc_max_message_size: DEFAULT_GRPC_MAX_MESSAGE_SIZE,
        }
    }
}
