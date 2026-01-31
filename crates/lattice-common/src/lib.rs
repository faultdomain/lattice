//! Common types for Lattice: CRDs, errors, and utilities

#![deny(missing_docs)]

pub mod clusterctl;
pub mod crd;
pub mod credentials;
pub mod error;
pub mod fips;
pub mod graph;
pub mod kube_utils;
pub mod policy;
pub mod protocol;
pub mod retry;
pub mod template;
pub mod yaml;

pub use credentials::{AwsCredentials, CredentialError, OpenStackCredentials, ProxmoxCredentials};
pub use error::Error;
pub use kube_utils::pluralize_kind;
pub use protocol::{CsrRequest, CsrResponse, DistributableResources};

/// Result type alias using our custom Error type
pub type Result<T> = std::result::Result<T, Error>;

/// Default port for the bootstrap HTTPS server
pub const DEFAULT_BOOTSTRAP_PORT: u16 = 8443;

/// Default port for the gRPC server (agent-cell communication)
pub const DEFAULT_GRPC_PORT: u16 = 50051;

/// Default port for the K8s API proxy server (CAPI controller access to child clusters)
pub const DEFAULT_PROXY_PORT: u16 = 8081;

/// Namespace for Lattice system resources (CA, credentials, operator)
pub const LATTICE_SYSTEM_NAMESPACE: &str = "lattice-system";

/// Construct a Kubernetes service DNS name for a Lattice service.
///
/// Returns `{service}.{LATTICE_SYSTEM_NAMESPACE}.svc`
pub fn lattice_svc_dns(service: &str) -> String {
    format!("{}.{}.svc", service, LATTICE_SYSTEM_NAMESPACE)
}

/// Construct a fully-qualified Kubernetes service DNS name for a Lattice service.
///
/// Returns `{service}.{LATTICE_SYSTEM_NAMESPACE}.svc.cluster.local`
pub fn lattice_svc_dns_fqdn(service: &str) -> String {
    format!("{}.{}.svc.cluster.local", service, LATTICE_SYSTEM_NAMESPACE)
}

/// Environment variable to indicate this is a bootstrap cluster
pub const BOOTSTRAP_CLUSTER_ENV: &str = "LATTICE_BOOTSTRAP_CLUSTER";

/// Check if the current operator is running on a bootstrap cluster
///
/// Returns true if LATTICE_BOOTSTRAP_CLUSTER is set to "true" or "1".
/// Bootstrap clusters are temporary clusters used during initial installation
/// that don't need the full proxy/pivot setup.
pub fn is_bootstrap_cluster() -> bool {
    std::env::var(BOOTSTRAP_CLUSTER_ENV)
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

/// Install the FIPS-validated crypto provider for rustls.
///
/// This must be called before creating any TLS connections (including kube clients).
/// Safe to call multiple times - subsequent calls are no-ops.
///
/// Uses aws-lc-rs which provides FIPS 140-2/140-3 validated cryptography.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

// CAPI provider namespaces
/// Target namespace for CAPA (AWS) provider
pub const CAPA_NAMESPACE: &str = "capa-system";
/// Target namespace for CAPMOX (Proxmox) provider
pub const CAPMOX_NAMESPACE: &str = "capmox-system";
/// Target namespace for CAPO (OpenStack) provider
pub const CAPO_NAMESPACE: &str = "capo-system";

// CAPI provider credential secret names
/// Secret name for Proxmox credentials
pub const PROXMOX_CREDENTIALS_SECRET: &str = "proxmox-credentials";
/// Secret name for AWS credentials
pub const AWS_CREDENTIALS_SECRET: &str = "aws-credentials";
/// Secret name for OpenStack credentials
pub const OPENSTACK_CREDENTIALS_SECRET: &str = "openstack-cloud-config";

/// Label key for provider identification on secrets
pub const PROVIDER_LABEL: &str = "lattice.dev/provider";

// Standard Kubernetes labels (see https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/)
/// Standard name label key - identifies the name of the application
pub const LABEL_NAME: &str = "app.kubernetes.io/name";
/// Standard managed-by label key - identifies the tool managing the resource
pub const LABEL_MANAGED_BY: &str = "app.kubernetes.io/managed-by";
/// Standard managed-by label value for Lattice-managed resources
pub const LABEL_MANAGED_BY_LATTICE: &str = "lattice";

// Cilium label selectors (use k8s: prefix for Kubernetes labels)
/// Cilium selector for app name label
pub const CILIUM_LABEL_NAME: &str = "k8s:app.kubernetes.io/name";
/// Cilium selector for pod namespace
pub const CILIUM_LABEL_NAMESPACE: &str = "k8s:io.kubernetes.pod.namespace";
