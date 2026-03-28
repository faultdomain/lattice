//! Authenticated identity types
//!
//! Shared between lattice-api (OIDC + ServiceAccount) and lattice-console
//! (OIDC + API key).

use serde::{Deserialize, Serialize};

/// Authenticated user identity.
///
/// Core identity fields shared across all Lattice auth flows:
/// - OIDC JWT validation → username from claims, groups from claims
/// - API key validation → username from key metadata, groups synthetic
/// - ServiceAccount TokenReview → username from SA, groups from K8s
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Username (email from OIDC, SA name from TokenReview, email from API key)
    pub username: String,
    /// Groups (OIDC groups claim, SA groups, or synthetic from API key team)
    pub groups: Vec<String>,
}

/// How the identity was established
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// OIDC JWT (Keycloak, etc.)
    Oidc,
    /// Lattice API key (lk_ prefix)
    ApiKey,
    /// Kubernetes ServiceAccount TokenReview
    ServiceAccount,
}
