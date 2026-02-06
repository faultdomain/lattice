//! Lattice Auth Proxy
//!
//! A kubectl-native auth proxy that runs on every cluster.
//! Handles authentication (OIDC or ServiceAccount tokens), Cedar authorization,
//! and routes requests to the appropriate cluster in the subtree.
//!
//! # Architecture
//!
//! ```text
//! kubectl --► Auth Proxy --► Cedar --► K8s API Server
//!             (OIDC/SA)      (authz)     (private)
//! ```
//!
//! # Endpoints
//!
//! - `GET /kubeconfig` - Returns multi-context kubeconfig for all accessible clusters
//! - `* /clusters/{name}/api/*` - Proxy to cluster's K8s API
//! - `* /clusters/{name}/apis/*` - Proxy to cluster's K8s API
//! - `GET /healthz` - Health check

#![deny(missing_docs)]

pub mod auth;
pub mod auth_chain;
pub mod auth_context;
pub mod backend;
pub mod cedar;
pub mod error;
pub mod exec_proxy;
pub mod k8s_forwarder;
pub mod kubeconfig;
pub mod proxy;
pub mod routing;
pub mod sa_auth;
pub mod server;

use kube::api::ObjectMeta;
use lattice_common::INHERITED_LABEL;

/// Check if a Kubernetes resource is inherited from a parent cluster.
///
/// Resources with the label `lattice.dev/inherited: true` are considered inherited.
pub fn is_inherited_resource(metadata: &ObjectMeta) -> bool {
    metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(INHERITED_LABEL))
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Check if a Kubernetes resource is a local resource (not inherited).
///
/// Resources without the `lattice.dev/inherited` label or with it set to a value
/// other than "true" are considered local.
pub fn is_local_resource(metadata: &ObjectMeta) -> bool {
    !is_inherited_resource(metadata)
}

pub use auth::{OidcConfig, OidcValidator, UserIdentity};
pub use auth_chain::AuthChain;
pub use auth_context::AuthContext;
pub use backend::{
    ExecSessionHandle, ExecTunnelRequest, K8sTunnelRequest, ProxyBackend, ProxyError,
    ProxyRouteInfo,
};
pub use cedar::PolicyEngine;
pub use error::{Error, Result};
pub use sa_auth::SaValidator;
pub use server::{start_server, AppState, ServerConfig};
