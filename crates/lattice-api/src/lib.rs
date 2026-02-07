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
pub(crate) mod portforward;
pub mod proxy;
pub mod routing;
pub mod sa_auth;
pub mod server;

pub use auth::{OidcConfig, OidcValidator, UserIdentity};
pub use auth_chain::AuthChain;
pub use auth_context::AuthContext;
pub use backend::{
    ExecSessionHandle, ExecTunnelRequest, K8sTunnelRequest, ProxyBackend, ProxyError,
    ProxyRouteInfo,
};
pub use error::{Error, Result};
pub use sa_auth::SaValidator;
pub use server::{start_server, AppState, ServerConfig};
