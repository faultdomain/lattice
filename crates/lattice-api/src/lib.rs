//! Lattice Auth Proxy
//!
//! A kubectl-native auth proxy that runs on every cluster.
//! Handles OIDC authentication, Cedar authorization, and routes
//! requests to the appropriate cluster in the subtree.
//!
//! # Architecture
//!
//! ```text
//! kubectl ──► Auth Proxy ──► Cedar ──► K8s API Server
//!               (OIDC)      (authz)     (private)
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
pub mod cedar;
pub mod error;
pub mod kubeconfig;
pub mod proxy;
pub mod router;
pub mod server;

pub use auth::{OidcConfig, OidcValidator, UserIdentity};
pub use cedar::PolicyEngine;
pub use error::{Error, Result};
pub use server::{
    start_server, start_server_with_registry, AppState, ClusterInfo, RouteInfo, ServerConfig,
    SharedAgentRegistry, SubtreeRegistry,
};
