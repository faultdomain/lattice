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
pub use error::{default_error_policy, ControllerContext, Error, ReconcileError};
pub use kube_utils::{
    apply_manifest_with_discovery, apply_manifests_with_discovery, kind_priority, pluralize_kind,
    ApplyOptions,
};
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

/// Construct the CAPI namespace for a cluster.
///
/// CAPI resources for each cluster are stored in a dedicated namespace
/// named `capi-{cluster_name}`.
pub fn capi_namespace(cluster_name: &str) -> String {
    format!("capi-{}", cluster_name)
}

/// Construct the kubeconfig secret name for a cluster.
///
/// CAPI creates a kubeconfig secret named `{cluster_name}-kubeconfig`
/// in the CAPI namespace.
pub fn kubeconfig_secret_name(cluster_name: &str) -> String {
    format!("{}-kubeconfig", cluster_name)
}

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

/// Parsed cell endpoint containing host and ports
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellEndpoint {
    /// Host (IP address or hostname)
    pub host: String,
    /// HTTP/HTTPS port for bootstrap webhook
    pub http_port: u16,
    /// gRPC port for agent-cell communication
    pub grpc_port: u16,
}

impl CellEndpoint {
    /// Parse a cell endpoint string
    ///
    /// Format: "host:http_port:grpc_port" (e.g., "172.18.255.10:8443:50051")
    ///
    /// # Examples
    /// ```
    /// use lattice_common::CellEndpoint;
    ///
    /// let endpoint = CellEndpoint::parse("172.18.255.10:8443:50051").expect("valid endpoint");
    /// assert_eq!(endpoint.host, "172.18.255.10");
    /// assert_eq!(endpoint.http_port, 8443);
    /// assert_eq!(endpoint.grpc_port, 50051);
    /// ```
    pub fn parse(endpoint: &str) -> Option<Self> {
        let parts: Vec<&str> = endpoint.split(':').collect();
        match parts.as_slice() {
            [host, http_port, grpc_port] => Some(Self {
                host: (*host).to_string(),
                http_port: http_port.parse().ok()?,
                grpc_port: grpc_port.parse().ok()?,
            }),
            _ => None,
        }
    }

    /// Get the HTTPS endpoint URL for the bootstrap webhook
    pub fn https_url(&self) -> String {
        format!("https://{}:{}", self.host, self.http_port)
    }

    /// Get the gRPC endpoint URL
    pub fn grpc_url(&self) -> String {
        format!("https://{}:{}", self.host, self.grpc_port)
    }
}

/// Parent cell configuration read from the `lattice-parent-config` secret
///
/// This secret is created during bootstrap and contains the information
/// needed to connect back to the parent cell.
#[derive(Debug, Clone)]
pub struct ParentConfig {
    /// Parsed cell endpoint
    pub endpoint: CellEndpoint,
    /// CA certificate PEM for TLS verification
    pub ca_cert_pem: String,
}

impl ParentConfig {
    /// Read parent config from the Kubernetes secret
    ///
    /// Returns `None` if the secret doesn't exist (indicating this is a root cluster).
    /// Returns `Err` if the secret exists but is malformed.
    pub async fn read(client: &kube::Client) -> std::result::Result<Option<Self>, Error> {
        use k8s_openapi::api::core::v1::Secret;
        use kube::Api;

        let secrets: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
        let secret = match secrets.get(PARENT_CONFIG_SECRET).await {
            Ok(s) => s,
            Err(kube::Error::Api(e)) if e.code == 404 => return Ok(None),
            Err(e) => {
                return Err(Error::internal(format!(
                    "failed to get parent config secret: {}",
                    e
                )))
            }
        };

        let data = secret
            .data
            .ok_or_else(|| Error::internal("parent config secret has no data"))?;

        let endpoint_bytes = data
            .get(PARENT_CONFIG_ENDPOINT_KEY)
            .ok_or_else(|| Error::internal("missing cell_endpoint in parent config"))?;
        let endpoint_str = std::str::from_utf8(&endpoint_bytes.0)
            .map_err(|e| Error::internal(format!("invalid cell_endpoint encoding: {}", e)))?;
        let endpoint = CellEndpoint::parse(endpoint_str).ok_or_else(|| {
            Error::internal(format!(
                "invalid cell_endpoint format '{}', expected host:http_port:grpc_port",
                endpoint_str
            ))
        })?;

        let ca_bytes = data
            .get(PARENT_CONFIG_CA_KEY)
            .ok_or_else(|| Error::internal("missing ca.crt in parent config"))?;
        let ca_cert_pem = std::str::from_utf8(&ca_bytes.0)
            .map_err(|e| Error::internal(format!("invalid CA cert encoding: {}", e)))?
            .to_string();

        Ok(Some(Self {
            endpoint,
            ca_cert_pem,
        }))
    }
}

// CAPI provider namespaces
/// Target namespace for CAPA (AWS) provider
pub const CAPA_NAMESPACE: &str = "capa-system";
/// Target namespace for CAPMOX (Proxmox) provider
pub const CAPMOX_NAMESPACE: &str = "capmox-system";
/// Target namespace for CAPO (OpenStack) provider
pub const CAPO_NAMESPACE: &str = "capo-system";

// CAPI provider credential secret names (source secrets in lattice-system)
/// Secret name for Proxmox credentials
pub const PROXMOX_CREDENTIALS_SECRET: &str = "proxmox-credentials";
/// Secret name for AWS credentials (source secret)
pub const AWS_CREDENTIALS_SECRET: &str = "aws-credentials";
/// Secret name for OpenStack credentials
pub const OPENSTACK_CREDENTIALS_SECRET: &str = "openstack-cloud-config";

// CAPI provider secret names (target secrets in provider namespaces)
// These are the names expected by each CAPI provider
/// AWS CAPA expects this specific secret name
pub const AWS_CAPA_CREDENTIALS_SECRET: &str = "capa-manager-bootstrap-credentials";

// Lattice system secrets
/// Secret containing parent cell endpoint and CA certificate (created during bootstrap)
pub const PARENT_CONFIG_SECRET: &str = "lattice-parent-config";
/// Key for cell endpoint in parent config secret (format: "host:http_port:grpc_port")
pub const PARENT_CONFIG_ENDPOINT_KEY: &str = "cell_endpoint";
/// Key for CA certificate in parent config secret
pub const PARENT_CONFIG_CA_KEY: &str = "ca.crt";
/// Secret containing private registry credentials (Docker config)
pub const REGISTRY_CREDENTIALS_SECRET: &str = "lattice-registry";
/// Secret containing agent mTLS credentials (cert, key, CA)
pub const AGENT_CREDENTIALS_SECRET: &str = "lattice-agent-credentials";
/// Secret containing the Lattice CA certificate and key
pub const CA_SECRET: &str = "lattice-ca";

// TLS secret data keys (standard Kubernetes TLS secret format)
/// Key for TLS certificate in secrets
pub const TLS_CERT_KEY: &str = "tls.crt";
/// Key for TLS private key in secrets
pub const TLS_KEY_KEY: &str = "tls.key";

// CA secret data keys
/// Key for CA certificate in CA secrets
pub const CA_CERT_KEY: &str = "ca.crt";
/// Key for CA private key in CA secrets
pub const CA_KEY_KEY: &str = "ca.key";
/// Key for CA trust bundle (full chain)
pub const CA_TRUST_KEY: &str = "ca-trust.crt";

// Service and resource names
/// Name of the Lattice cell service
pub const CELL_SERVICE_NAME: &str = "lattice-cell";
/// Name of the Lattice operator deployment and service account
pub const OPERATOR_NAME: &str = "lattice-operator";

/// Internal Kubernetes service endpoint for self-management
///
/// This is the standard in-cluster endpoint that pods use to access the
/// Kubernetes API from within the cluster.
pub const INTERNAL_K8S_ENDPOINT: &str = "https://kubernetes.default.svc:443";

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

// Resource inheritance labels (for hierarchical policy propagation)
/// Label indicating which cluster originally created this resource
pub const ORIGIN_CLUSTER_LABEL: &str = "lattice.dev/origin-cluster";
/// Label indicating the original name before prefixing
pub const ORIGINAL_NAME_LABEL: &str = "lattice.dev/original-name";
/// Label indicating this resource was inherited from a parent cluster
pub const INHERITED_LABEL: &str = "lattice.dev/inherited";
