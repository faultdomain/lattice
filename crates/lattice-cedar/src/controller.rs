//! LatticeService controller for Cedar policy management
//!
//! Watches LatticeService CRDs and updates the policy store when
//! services with authorization configuration are created/updated/deleted.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Api, Client, ResourceExt};
use tracing::{debug, error, info, warn};

use lattice_common::crd::LatticeService;

use crate::error::{CedarError, Result};
use crate::jwt::{JwksCache, JwtValidator};
use crate::policy::PolicyStore;

/// OIDC configuration extracted from LatticeService
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// OIDC issuer URL
    pub issuer: String,
    /// Expected audience
    pub audience: String,
    /// JWKS URI
    pub jwks_uri: String,
    /// Claim path for roles
    pub roles_claim: String,
    /// Claim path for groups
    pub groups_claim: String,
}

/// Shared context for Cedar authorization
pub struct Context {
    /// Kubernetes client
    client: Client,
    /// Policy store
    policy_store: Arc<PolicyStore>,
    /// JWKS cache
    jwks_cache: Arc<JwksCache>,
    /// JWT validator
    jwt_validator: JwtValidator,
    /// OIDC configurations by service (namespace/name -> config)
    oidc_configs: dashmap::DashMap<String, OidcConfig>,
}

impl Context {
    /// Create a new context
    pub fn new(client: Client) -> Self {
        let jwks_cache = Arc::new(JwksCache::new());
        let jwt_validator = JwtValidator::new(jwks_cache.clone());

        Self {
            client,
            policy_store: Arc::new(PolicyStore::new()),
            jwks_cache,
            jwt_validator,
            oidc_configs: dashmap::DashMap::new(),
        }
    }

    /// Get the Kubernetes client
    pub fn client(&self) -> Client {
        self.client.clone()
    }

    /// Get the policy store
    pub fn policy_store(&self) -> Arc<PolicyStore> {
        self.policy_store.clone()
    }

    /// Get the JWKS cache
    pub fn jwks_cache(&self) -> Arc<JwksCache> {
        self.jwks_cache.clone()
    }

    /// Get the JWT validator
    pub fn jwt_validator(&self) -> &JwtValidator {
        &self.jwt_validator
    }

    /// Get OIDC config for a service
    pub fn get_oidc_config(&self, namespace: &str, name: &str) -> Option<OidcConfig> {
        let key = format!("{}/{}", namespace, name);
        self.oidc_configs.get(&key).map(|v| v.clone())
    }

    /// Set OIDC config for a service
    pub fn set_oidc_config(&self, namespace: &str, name: &str, config: OidcConfig) {
        let key = format!("{}/{}", namespace, name);
        self.oidc_configs.insert(key, config);
    }

    /// Remove OIDC config for a service
    pub fn remove_oidc_config(&self, namespace: &str, name: &str) {
        let key = format!("{}/{}", namespace, name);
        self.oidc_configs.remove(&key);
    }
}

/// Reconcile a LatticeService for Cedar authorization
pub async fn reconcile(
    service: Arc<LatticeService>,
    ctx: Arc<Context>,
) -> std::result::Result<Action, CedarError> {
    let namespace = service.namespace().unwrap_or_default();
    let name = service.name_any();
    let resource_version = service.resource_version().unwrap_or_default();

    debug!(
        namespace = %namespace,
        service = %name,
        "Reconciling LatticeService for Cedar"
    );

    // Check if service has authorization configuration
    let spec = &service.spec;

    // Get authorization config from spec
    let authz_config = spec.authorization.as_ref();

    // Extract Cedar policy if configured
    let cedar_policy = authz_config
        .and_then(|a| a.cedar.as_ref())
        .map(|c| c.policies.clone());

    // Extract OIDC config if configured
    let oidc = authz_config.and_then(|a| a.oidc.as_ref());

    match cedar_policy {
        Some(policy) => {
            // Update policy store
            ctx.policy_store()
                .upsert(&namespace, &name, &policy, &resource_version)?;

            // Update OIDC config if present
            if let Some(oidc_crd) = oidc {
                let jwks_uri = oidc_crd.jwks_uri.clone().unwrap_or_else(|| {
                    format!(
                        "{}/.well-known/jwks.json",
                        oidc_crd.issuer.trim_end_matches('/')
                    )
                });

                let claim_mappings = oidc_crd.claim_mappings.as_ref();

                let config = OidcConfig {
                    issuer: oidc_crd.issuer.clone(),
                    audience: oidc_crd.audience.clone(),
                    jwks_uri: jwks_uri.clone(),
                    roles_claim: claim_mappings
                        .and_then(|c| c.roles.clone())
                        .unwrap_or_else(|| "roles".to_string()),
                    groups_claim: claim_mappings
                        .and_then(|c| c.groups.clone())
                        .unwrap_or_else(|| "groups".to_string()),
                };

                ctx.set_oidc_config(&namespace, &name, config);

                // Preload JWKS
                ctx.jwks_cache().preload(jwks_uri);
            }

            info!(
                namespace = %namespace,
                service = %name,
                "Cedar policy updated"
            );
        }
        None => {
            // No policy - remove from store if exists
            if ctx.policy_store().remove(&namespace, &name) {
                ctx.remove_oidc_config(&namespace, &name);
                info!(
                    namespace = %namespace,
                    service = %name,
                    "Cedar policy removed"
                );
            }
        }
    }

    // Requeue after 5 minutes to catch any changes
    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Error policy for Cedar controller
pub fn error_policy(
    service: Arc<LatticeService>,
    error: &CedarError,
    _ctx: Arc<Context>,
) -> Action {
    let namespace = service.namespace().unwrap_or_default();
    let name = service.name_any();

    warn!(
        namespace = %namespace,
        service = %name,
        error = %error,
        "Cedar reconciliation error, will retry"
    );

    // Exponential backoff with max 5 minutes
    Action::requeue(Duration::from_secs(30))
}

/// Start the Cedar policy controller
pub async fn run_controller(ctx: Arc<Context>) -> Result<()> {
    let client = ctx.client();
    let services: Api<LatticeService> = Api::all(client);

    info!("Starting Cedar policy controller");

    Controller::new(services, WatcherConfig::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|result| async move {
            match result {
                Ok(action) => {
                    debug!(?action, "Cedar reconciliation completed");
                }
                Err(e) => {
                    error!(error = ?e, "Cedar reconciliation error");
                }
            }
        })
        .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oidc_config() {
        let config = OidcConfig {
            issuer: "https://auth.example.com".to_string(),
            audience: "api".to_string(),
            jwks_uri: "https://auth.example.com/.well-known/jwks.json".to_string(),
            roles_claim: "roles".to_string(),
            groups_claim: "groups".to_string(),
        };

        assert_eq!(config.issuer, "https://auth.example.com");
        assert_eq!(config.audience, "api");
    }
}
