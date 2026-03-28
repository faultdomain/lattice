//! OIDC authentication adapter
//!
//! Re-exports core OIDC validation from `lattice-auth` and adds CRD-specific
//! provider loading for the K8s auth proxy.
//!
//! # Provider Inheritance
//!
//! OIDC providers can be inherited from parent clusters:
//! - If an inherited provider exists (labeled `lattice.dev/inherited: true`), it's used by default
//! - Local providers only take effect if `allow_child_override: true` on the inherited provider
//! - This ensures authentication cannot be bypassed by child clusters

use std::time::Duration;

use kube::{Api, Client};
use tracing::{debug, info};

use crate::error::{Error, Result};
use lattice_common::crd::OIDCProvider;
use lattice_common::{is_local_resource, LATTICE_SYSTEM_NAMESPACE};

pub use lattice_auth::{Identity as UserIdentity, OidcConfig, OidcValidator};

/// Load an OidcValidator from the OIDCProvider CRD in lattice-system namespace.
///
/// Respects inheritance rules:
/// - Inherited providers take precedence by default
/// - Local providers only used if inherited provider has `allow_child_override: true`
pub async fn from_crd(client: &Client) -> Result<OidcValidator> {
    let api: Api<OIDCProvider> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

    let all_providers = api.list(&Default::default()).await?;
    let mut inherited: Option<OIDCProvider> = None;
    let mut local: Option<OIDCProvider> = None;
    for provider in all_providers.items {
        if is_local_resource(&provider.metadata) {
            local.get_or_insert(provider);
        } else {
            inherited.get_or_insert(provider);
        }
    }

    let (provider, source) = match (inherited, local) {
        (Some(inherited_provider), Some(local_provider)) => {
            if inherited_provider.spec.allow_child_override {
                info!(
                    inherited_issuer = %inherited_provider.spec.issuer_url,
                    local_issuer = %local_provider.spec.issuer_url,
                    "Using local OIDC provider (child override allowed)"
                );
                (local_provider, "local")
            } else {
                debug!(
                    inherited_issuer = %inherited_provider.spec.issuer_url,
                    local_issuer = %local_provider.spec.issuer_url,
                    "Ignoring local OIDC provider (child override not allowed)"
                );
                (inherited_provider, "inherited")
            }
        }
        (Some(inherited_provider), None) => (inherited_provider, "inherited"),
        (None, Some(local_provider)) => (local_provider, "local"),
        (None, None) => {
            return Err(Error::Config(
                "No OIDCProvider found in lattice-system".into(),
            ));
        }
    };

    let spec = &provider.spec;
    let allow_insecure_http = spec.allow_insecure_http;

    let audiences = if spec.audiences.is_empty() {
        vec![spec.client_id.clone()]
    } else {
        spec.audiences.clone()
    };

    let config = OidcConfig {
        issuer_url: spec.issuer_url.clone(),
        client_id: spec.client_id.clone(),
        audiences,
        username_claim: spec.username_claim.clone(),
        groups_claim: spec.groups_claim.clone(),
        username_prefix: spec.username_prefix.clone(),
        groups_prefix: spec.groups_prefix.clone(),
        jwks_refresh_interval: Duration::from_secs(spec.jwks_refresh_interval_seconds as u64),
    };

    info!(
        issuer = %config.issuer_url,
        client_id = %config.client_id,
        source = source,
        "Loaded OIDC configuration from CRD"
    );

    let validator = if allow_insecure_http {
        OidcValidator::with_config_insecure(config)
    } else {
        OidcValidator::with_config(config)
    };

    Ok(validator)
}
