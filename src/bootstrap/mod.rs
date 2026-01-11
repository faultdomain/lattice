//! Bootstrap endpoint for kubeadm callback and CSR signing
//!
//! This module implements HTTP endpoints that run WITHOUT mTLS:
//! - Bootstrap endpoint: kubeadm postKubeadmCommands calls to get manifests
//! - CSR signing endpoint: agents submit CSRs to get signed certificates
//!
//! # Security Model
//!
//! - Endpoints are NON-mTLS (agent doesn't have cert yet)
//! - Bootstrap uses one-time token authentication
//! - CSR signing validates cluster is registered
//!
//! # Bootstrap Flow
//!
//! 1. Cluster created → bootstrap token generated
//! 2. kubeadm runs postKubeadmCommands
//! 3. Script calls `GET /api/clusters/{id}/manifests` with Bearer token
//! 4. Endpoint validates token, marks as used
//! 5. Returns: agent manifest, CNI manifest, CA certificate
//!
//! # CSR Flow
//!
//! 1. Agent generates keypair locally (private key never leaves agent)
//! 2. Agent creates CSR and sends to `POST /api/clusters/{id}/csr`
//! 3. Cell signs CSR with CA and returns certificate
//! 4. Agent uses cert for mTLS connection to gRPC server

mod token;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use dashmap::DashMap;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, EnvVar, LocalObjectReference, Namespace, PodSpec, PodTemplateSpec,
    Secret, SecretVolumeSource, ServiceAccount, Volume, VolumeMount,
};
use k8s_openapi::api::rbac::v1::{ClusterRoleBinding, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use k8s_openapi::ByteString;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

use crate::crd::LatticeCluster;
use crate::pki::{CertificateAuthority, PkiError};
use kube::CustomResourceExt;

pub use token::{BootstrapToken, TokenGenerationError, TokenStore};

/// Bootstrap endpoint errors
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// Invalid or expired token
    #[error("invalid or expired token")]
    InvalidToken,

    /// Token already used
    #[error("token already used")]
    TokenAlreadyUsed,

    /// Cluster not found
    #[error("cluster not found: {0}")]
    ClusterNotFound(String),

    /// Missing authorization header
    #[error("missing authorization header")]
    MissingAuth,

    /// CSR signing error
    #[error("CSR signing failed: {0}")]
    CsrSigningFailed(String),

    /// Cluster not bootstrapped yet
    #[error("cluster not bootstrapped: {0}")]
    ClusterNotBootstrapped(String),

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for BootstrapError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            BootstrapError::InvalidToken => (StatusCode::UNAUTHORIZED, self.to_string()),
            BootstrapError::TokenAlreadyUsed => (StatusCode::GONE, self.to_string()),
            BootstrapError::ClusterNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            BootstrapError::MissingAuth => (StatusCode::UNAUTHORIZED, self.to_string()),
            BootstrapError::CsrSigningFailed(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            BootstrapError::ClusterNotBootstrapped(_) => {
                (StatusCode::PRECONDITION_FAILED, self.to_string())
            }
            BootstrapError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string(),
            ),
        };

        (status, Json(serde_json::json!({"error": message}))).into_response()
    }
}

impl From<PkiError> for BootstrapError {
    fn from(e: PkiError) -> Self {
        BootstrapError::CsrSigningFailed(e.to_string())
    }
}

/// Bootstrap response containing manifests for the agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapResponse {
    /// Cluster ID
    pub cluster_id: String,
    /// Cell endpoint for gRPC connection (after CSR is signed)
    pub cell_endpoint: String,
    /// CA certificate in PEM format (for verifying cell)
    pub ca_certificate: String,
    /// Kubernetes manifests to apply (YAML)
    pub manifests: Vec<String>,
}

/// CSR signing request from agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrRequest {
    /// CSR in PEM format
    pub csr_pem: String,
}

/// CSR signing response with signed certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrResponse {
    /// Signed certificate in PEM format
    pub certificate_pem: String,
    /// CA certificate in PEM format (for verifying peer)
    pub ca_certificate_pem: String,
}

/// Configuration for registering a cluster for bootstrap
///
/// Groups related parameters for `register_cluster` to improve readability
/// and satisfy clippy's too_many_arguments lint.
#[derive(Debug, Clone)]
pub struct ClusterRegistration {
    /// Unique cluster identifier
    pub cluster_id: String,
    /// Cell endpoint (format: "host:http_port:grpc_port")
    pub cell_endpoint: String,
    /// CA certificate PEM for the parent cell
    pub ca_certificate: String,
    /// LatticeCluster CRD JSON to apply on workload cluster
    pub cluster_manifest: String,
    /// Optional networking config for Cilium LB-IPAM
    pub networking: Option<crate::crd::NetworkingSpec>,
    /// Infrastructure provider (docker, aws, gcp, azure)
    pub provider: String,
    /// Bootstrap mechanism (kubeadm or rke2)
    pub bootstrap: crate::crd::BootstrapProvider,
}

/// Bootstrap manifest generator
pub trait ManifestGenerator: Send + Sync {
    /// Generate bootstrap manifests for a cluster
    ///
    /// These manifests are applied during initial bootstrap (before pivot).
    /// They include CNI and operator - NOT LatticeCluster CRD (that comes post-pivot
    /// via ApplyManifestsCommand to avoid fighting with pivot).
    ///
    /// Environment variables set on the operator:
    /// - LATTICE_CLUSTER_NAME: So controller knows which cluster it's on
    /// - LATTICE_PROVIDER: So agent knows which CAPI provider to install
    fn generate(
        &self,
        image: &str,
        registry_credentials: Option<&str>,
        cluster_name: Option<&str>,
        provider: Option<&str>,
    ) -> Vec<String>;
}

/// Configuration for generating bootstrap manifests
///
/// Groups related parameters for `generate_all_manifests` to improve readability
/// and allow easier extension without breaking call sites.
#[derive(Debug, Clone)]
pub struct ManifestConfig<'a> {
    /// Container image for the operator
    pub image: &'a str,
    /// Optional registry credentials (image pull secret)
    pub registry_credentials: Option<&'a str>,
    /// Optional networking configuration (for LB-IPAM)
    pub networking: Option<&'a crate::crd::NetworkingSpec>,
    /// Cluster name (for operator identity)
    pub cluster_name: Option<&'a str>,
    /// Provider type (docker, aws, etc.)
    pub provider: Option<&'a str>,
    /// Parent host (None for root/cell clusters)
    pub parent_host: Option<&'a str>,
    /// Parent gRPC port
    pub parent_grpc_port: u16,
    /// Whether to relax FIPS mode (add GODEBUG=fips140=on)
    /// Used for bootstrap cluster and kubeadm-based clusters connecting to non-FIPS API servers
    pub relax_fips: bool,
}

/// Generate all bootstrap manifests including LB-IPAM resources if networking is configured
///
/// This is the single entry point for manifest generation - both CRS (management cluster)
/// and bootstrap webhook (child clusters) should call this function to avoid drift.
pub fn generate_all_manifests<G: ManifestGenerator>(
    generator: &G,
    config: &ManifestConfig<'_>,
) -> Vec<String> {
    let mut manifests = generator.generate(
        config.image,
        config.registry_credentials,
        config.cluster_name,
        config.provider,
    );

    // Apply FIPS relaxation if needed (for kubeadm-based bootstrap or non-FIPS targets)
    if config.relax_fips {
        manifests = manifests
            .into_iter()
            .map(|m| {
                if crate::fips::is_deployment(&m) {
                    crate::fips::add_fips_relax_env(&m)
                } else {
                    m
                }
            })
            .collect();
    }

    // Add Cilium LB-IPAM resources if networking is configured
    if let Some(networking) = config.networking {
        manifests.extend(crate::cilium::generate_lb_resources(networking));
    }

    // Add CiliumNetworkPolicy for the operator/agent
    // This is the ONLY policy applied at bootstrap - just enough for the agent to connect
    // - Root clusters (no parent): egress to DNS + API server only
    // - Child clusters (have parent): also include parent for gRPC connection
    // All other policies (default-deny, ztunnel allowlist, Istio policies) are applied
    // by the operator once it starts - single source of truth, no drift.
    manifests.push(crate::infra::generate_operator_network_policy(
        config.parent_host,
        config.parent_grpc_port,
    ));

    manifests
}

/// Default manifest generator that creates agent and CNI manifests
///
/// Uses the shared CiliumReconciler from infra module to ensure bootstrap
/// and day-2 reconciliation use the same manifest generation.
pub struct DefaultManifestGenerator {
    /// Cilium reconciler (shared with agent for consistent manifests)
    cilium: crate::infra::CiliumReconciler,
}

impl DefaultManifestGenerator {
    /// Create a new generator, pre-rendering Cilium manifests via helm template
    pub fn new() -> Result<Self, BootstrapError> {
        let cilium = crate::infra::CiliumReconciler::new().map_err(|e| {
            BootstrapError::Internal(format!("failed to create Cilium reconciler: {}", e))
        })?;
        Ok(Self { cilium })
    }

    /// Create with custom Cilium configuration
    pub fn with_cilium_config(config: crate::infra::CiliumConfig) -> Result<Self, BootstrapError> {
        let cilium = crate::infra::CiliumReconciler::with_config(config).map_err(|e| {
            BootstrapError::Internal(format!("failed to create Cilium reconciler: {}", e))
        })?;
        Ok(Self { cilium })
    }

    /// Get the Cilium reconciler (for shared use with agent)
    pub fn cilium(&self) -> &crate::infra::CiliumReconciler {
        &self.cilium
    }

    /// Generate the Lattice operator manifests (non-Cilium)
    ///
    /// Every cluster runs the same deployment - the controller reads its
    /// LatticeCluster CRD to determine behavior (cell vs leaf, parent connection, etc.)
    ///
    /// Environment variables set:
    /// - LATTICE_CLUSTER_NAME: So controller knows which cluster it's on
    /// - LATTICE_PROVIDER: So agent knows which CAPI provider to install
    fn generate_operator_manifests(
        &self,
        image: &str,
        registry_credentials: Option<&str>,
        cluster_name: Option<&str>,
        provider: Option<&str>,
    ) -> Result<Vec<String>, serde_json::Error> {
        const NAMESPACE: &str = "lattice-system";

        let registry_creds = registry_credentials.map(|s| s.to_string());

        // 1. Namespace
        let namespace = Namespace {
            metadata: ObjectMeta {
                name: Some(NAMESPACE.to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        // 2. Registry credentials secret (if available)
        let registry_secret = registry_creds.as_ref().map(|creds| Secret {
            metadata: ObjectMeta {
                name: Some("lattice-registry".to_string()),
                namespace: Some(NAMESPACE.to_string()),
                ..Default::default()
            },
            type_: Some("kubernetes.io/dockerconfigjson".to_string()),
            data: Some(BTreeMap::from([(
                ".dockerconfigjson".to_string(),
                ByteString(creds.as_bytes().to_vec()),
            )])),
            ..Default::default()
        });

        // 3. ServiceAccount
        let service_account = ServiceAccount {
            metadata: ObjectMeta {
                name: Some("lattice-operator".to_string()),
                namespace: Some(NAMESPACE.to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        // 4. ClusterRoleBinding (cluster-admin - we manage everything)
        let cluster_role_binding = ClusterRoleBinding {
            metadata: ObjectMeta {
                name: Some("lattice-operator".to_string()),
                ..Default::default()
            },
            role_ref: RoleRef {
                api_group: "rbac.authorization.k8s.io".to_string(),
                kind: "ClusterRole".to_string(),
                name: "cluster-admin".to_string(),
            },
            subjects: Some(vec![Subject {
                kind: "ServiceAccount".to_string(),
                name: "lattice-operator".to_string(),
                namespace: Some(NAMESPACE.to_string()),
                ..Default::default()
            }]),
        };

        // 5. Operator Deployment
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "lattice-operator".to_string());

        let operator_deployment = Deployment {
            metadata: ObjectMeta {
                name: Some("lattice-operator".to_string()),
                namespace: Some(NAMESPACE.to_string()),
                ..Default::default()
            },
            spec: Some(DeploymentSpec {
                replicas: Some(1),
                selector: LabelSelector {
                    match_labels: Some(labels.clone()),
                    ..Default::default()
                },
                template: PodTemplateSpec {
                    metadata: Some(ObjectMeta {
                        labels: Some(labels),
                        ..Default::default()
                    }),
                    spec: Some(PodSpec {
                        service_account_name: Some("lattice-operator".to_string()),
                        image_pull_secrets: if registry_secret.is_some() {
                            Some(vec![LocalObjectReference {
                                name: "lattice-registry".to_string(),
                            }])
                        } else {
                            None
                        },
                        // Mount registry credentials so operator can pass them to workload clusters
                        volumes: if registry_secret.is_some() {
                            Some(vec![Volume {
                                name: "registry-creds".to_string(),
                                secret: Some(SecretVolumeSource {
                                    secret_name: Some("lattice-registry".to_string()),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }])
                        } else {
                            None
                        },
                        containers: vec![Container {
                            name: "operator".to_string(),
                            image: Some(image.to_string()),
                            image_pull_policy: Some("Always".to_string()),
                            // No args needed - controller is default mode
                            // Controller reads LatticeCluster CRD to determine behavior
                            env: Some({
                                let mut envs = vec![EnvVar {
                                    name: "RUST_LOG".to_string(),
                                    value: Some("info,lattice=debug".to_string()),
                                    ..Default::default()
                                }];
                                if let Some(name) = cluster_name {
                                    envs.push(EnvVar {
                                        name: "LATTICE_CLUSTER_NAME".to_string(),
                                        value: Some(name.to_string()),
                                        ..Default::default()
                                    });
                                }
                                if let Some(prov) = provider {
                                    envs.push(EnvVar {
                                        name: "LATTICE_PROVIDER".to_string(),
                                        value: Some(prov.to_string()),
                                        ..Default::default()
                                    });
                                }
                                if registry_secret.is_some() {
                                    envs.push(EnvVar {
                                        name: "REGISTRY_CREDENTIALS_FILE".to_string(),
                                        value: Some(
                                            "/etc/lattice/registry/.dockerconfigjson".to_string(),
                                        ),
                                        ..Default::default()
                                    });
                                }
                                envs
                            }),
                            // Mount registry credentials if available
                            volume_mounts: if registry_secret.is_some() {
                                Some(vec![VolumeMount {
                                    name: "registry-creds".to_string(),
                                    mount_path: "/etc/lattice/registry".to_string(),
                                    read_only: Some(true),
                                    ..Default::default()
                                }])
                            } else {
                                None
                            },
                            // Expose cell server ports for LoadBalancer Service
                            ports: Some(vec![
                                ContainerPort {
                                    name: Some("bootstrap".to_string()),
                                    container_port: crate::DEFAULT_BOOTSTRAP_PORT as i32,
                                    protocol: Some("TCP".to_string()),
                                    ..Default::default()
                                },
                                ContainerPort {
                                    name: Some("grpc".to_string()),
                                    container_port: crate::DEFAULT_GRPC_PORT as i32,
                                    protocol: Some("TCP".to_string()),
                                    ..Default::default()
                                },
                            ]),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                },
                ..Default::default()
            }),
            ..Default::default()
        };

        // Serialize all resources to JSON
        let mut manifests = vec![serde_json::to_string(&namespace)?];
        if let Some(ref reg_secret) = registry_secret {
            manifests.push(serde_json::to_string(reg_secret)?);
        }
        manifests.extend([
            serde_json::to_string(&service_account)?,
            serde_json::to_string(&cluster_role_binding)?,
            serde_json::to_string(&operator_deployment)?,
        ]);
        Ok(manifests)
    }
}

impl ManifestGenerator for DefaultManifestGenerator {
    fn generate(
        &self,
        image: &str,
        registry_credentials: Option<&str>,
        cluster_name: Option<&str>,
        provider: Option<&str>,
    ) -> Vec<String> {
        let mut manifests = Vec::new();

        // CNI manifests first (Cilium) - must be applied before other pods can run
        // Uses the same generator as agent reconciliation to prevent drift
        manifests.extend(self.cilium.manifests().iter().cloned());

        // Then operator manifests - same deployment for all clusters
        // Controller reads LatticeCluster CRD to determine behavior:
        // - spec.endpoints present → starts cell servers, can provision clusters
        // - spec.endpointsRef present → connects to parent
        //
        // Note: generate_operator_manifests returns Result, but serialization of
        // well-known k8s types should never fail. If it does, it indicates a
        // serious bug in the struct definitions.
        manifests.extend(
            self.generate_operator_manifests(image, registry_credentials, cluster_name, provider)
                .unwrap_or_else(|e| {
                    panic!(
                        "BUG: failed to serialize operator manifests to JSON: {}. \
                         This indicates a bug in the Kubernetes resource definitions.",
                        e
                    )
                }),
        );

        // Note: CiliumNetworkPolicy is added by generate_all_manifests()
        // based on whether parent_host is provided.

        // Note: LatticeCluster CRD and resource are sent post-pivot via ApplyManifestsCommand
        // to avoid the local controller fighting with the pivot process

        manifests
    }
}

/// Cluster info stored in bootstrap state
#[derive(Clone, Debug)]
pub struct ClusterBootstrapInfo {
    /// Cluster ID
    pub cluster_id: String,
    /// Cell endpoint for agent to connect to (format: "host:http_port:grpc_port")
    pub cell_endpoint: String,
    /// CA certificate PEM
    pub ca_certificate: String,
    /// The LatticeCluster CRD manifest (JSON) to apply on the workload cluster
    pub cluster_manifest: String,
    /// Bootstrap token (hashed)
    pub token_hash: String,
    /// When the token was created
    pub token_created: Instant,
    /// Whether the token has been used
    pub token_used: bool,
    /// Networking configuration for Cilium LB-IPAM
    pub networking: Option<crate::crd::NetworkingSpec>,
    /// Infrastructure provider (docker, aws, gcp, azure)
    pub provider: String,
    /// Bootstrap mechanism (kubeadm or rke2) - determines FIPS relaxation needs
    pub bootstrap: crate::crd::BootstrapProvider,
}

/// Bootstrap endpoint state
pub struct BootstrapState<G: ManifestGenerator = DefaultManifestGenerator> {
    /// Cluster info indexed by cluster_id
    clusters: DashMap<String, ClusterBootstrapInfo>,
    /// Manifest generator
    manifest_generator: G,
    /// Lattice image to deploy
    image: String,
    /// Registry credentials (optional)
    registry_credentials: Option<String>,
    /// Token TTL
    token_ttl: Duration,
    /// Certificate authority for signing CSRs
    ca: Arc<CertificateAuthority>,
}

impl<G: ManifestGenerator> BootstrapState<G> {
    /// Create a new bootstrap state with a CA
    pub fn new(
        generator: G,
        token_ttl: Duration,
        ca: Arc<CertificateAuthority>,
        image: String,
        registry_credentials: Option<String>,
    ) -> Self {
        Self {
            clusters: DashMap::new(),
            manifest_generator: generator,
            image,
            registry_credentials,
            token_ttl,
            ca,
        }
    }

    /// Get the CA certificate PEM for distribution
    pub fn ca_cert_pem(&self) -> &str {
        self.ca.ca_cert_pem()
    }

    /// Register a cluster for bootstrap
    ///
    /// # Arguments
    /// * `registration` - Cluster registration configuration
    pub fn register_cluster(&self, registration: ClusterRegistration) -> BootstrapToken {
        let token = BootstrapToken::generate();
        let token_hash = token.hash();

        let info = ClusterBootstrapInfo {
            cluster_id: registration.cluster_id.clone(),
            cell_endpoint: registration.cell_endpoint,
            ca_certificate: registration.ca_certificate,
            cluster_manifest: registration.cluster_manifest,
            token_hash,
            token_created: Instant::now(),
            token_used: false,
            networking: registration.networking,
            provider: registration.provider,
            bootstrap: registration.bootstrap,
        };

        self.clusters.insert(registration.cluster_id, info);
        token
    }

    /// Validate and consume a bootstrap token
    pub fn validate_and_consume(
        &self,
        cluster_id: &str,
        token: &str,
    ) -> Result<ClusterBootstrapInfo, BootstrapError> {
        let mut entry = self
            .clusters
            .get_mut(cluster_id)
            .ok_or_else(|| BootstrapError::ClusterNotFound(cluster_id.to_string()))?;

        let info = entry.value_mut();

        // Check if already used
        if info.token_used {
            return Err(BootstrapError::TokenAlreadyUsed);
        }

        // Check TTL
        if info.token_created.elapsed() > self.token_ttl {
            return Err(BootstrapError::InvalidToken);
        }

        // Verify token hash
        let token_obj = BootstrapToken::from_string(token);
        if token_obj.hash() != info.token_hash {
            return Err(BootstrapError::InvalidToken);
        }

        // Mark as used
        info.token_used = true;

        Ok(info.clone())
    }

    /// Generate bootstrap response for a cluster
    ///
    /// This generates manifests for clusters with a parent:
    /// - CNI (Cilium)
    /// - Lattice operator
    /// - CiliumNetworkPolicy (with parent for egress)
    /// - LatticeCluster CRD definition (CustomResourceDefinition)
    /// - LatticeCluster CRD instance (with parent reference)
    /// - Parent connection config Secret
    pub fn generate_response(&self, info: &ClusterBootstrapInfo) -> BootstrapResponse {
        // Parse parent endpoint for network policy
        // Format: "host:http_port:grpc_port"
        let (parent_host, grpc_port) = parse_parent_endpoint(&info.cell_endpoint);

        // Use the standard manifest generation - pass cluster_id, provider, and parent info
        // relax_fips is based on bootstrap provider: kubeadm clusters need relaxation,
        // RKE2 clusters are FIPS-compliant out of the box
        let config = ManifestConfig {
            image: &self.image,
            registry_credentials: self.registry_credentials.as_deref(),
            networking: info.networking.as_ref(),
            cluster_name: Some(&info.cluster_id),
            provider: Some(&info.provider),
            parent_host: parent_host.as_deref(),
            parent_grpc_port: grpc_port,
            relax_fips: info.bootstrap.needs_fips_relax(),
        };
        let mut manifests = generate_all_manifests(&self.manifest_generator, &config);

        // Add the LatticeCluster CRD definition (CustomResourceDefinition)
        // The CRD is needed so post-pivot manifests can create the LatticeCluster instance
        let crd_definition = serde_yaml::to_string(&LatticeCluster::crd()).unwrap_or_else(|e| {
            panic!(
                "BUG: failed to serialize LatticeCluster CRD to YAML: {}. \
                 This indicates a bug in the CRD definition.",
                e
            )
        });
        manifests.push(crd_definition);

        // NOTE: LatticeCluster instance is NOT included in bootstrap manifests.
        // It will be applied via post-pivot manifests after pivot completes.
        // Before pivot, the workload cluster just needs the agent + parent config.

        // Add parent connection config Secret for agent to use
        let parent_config = Secret {
            metadata: ObjectMeta {
                name: Some("lattice-parent-config".to_string()),
                namespace: Some("lattice-system".to_string()),
                ..Default::default()
            },
            type_: Some("Opaque".to_string()),
            string_data: Some(BTreeMap::from([
                ("cell_endpoint".to_string(), info.cell_endpoint.clone()),
                ("ca.crt".to_string(), info.ca_certificate.clone()),
            ])),
            ..Default::default()
        };
        manifests.push(serde_json::to_string(&parent_config).unwrap_or_else(|e| {
            panic!(
                "BUG: failed to serialize parent config Secret to JSON: {}. \
                 This indicates a bug in the Secret definition.",
                e
            )
        }));

        BootstrapResponse {
            cluster_id: info.cluster_id.clone(),
            cell_endpoint: info.cell_endpoint.clone(),
            ca_certificate: info.ca_certificate.clone(),
            manifests,
        }
    }

    /// Sign a CSR for a cluster
    ///
    /// The cluster must be registered and have completed bootstrap (token used).
    /// This ensures only legitimate agents can get certificates.
    pub fn sign_csr(&self, cluster_id: &str, csr_pem: &str) -> Result<CsrResponse, BootstrapError> {
        // Check cluster exists
        let entry = self
            .clusters
            .get(cluster_id)
            .ok_or_else(|| BootstrapError::ClusterNotFound(cluster_id.to_string()))?;

        // Check cluster has been bootstrapped (token consumed)
        if !entry.token_used {
            return Err(BootstrapError::ClusterNotBootstrapped(
                cluster_id.to_string(),
            ));
        }

        // Sign the CSR
        let certificate_pem = self.ca.sign_csr(csr_pem, cluster_id)?;

        Ok(CsrResponse {
            certificate_pem,
            ca_certificate_pem: self.ca.ca_cert_pem().to_string(),
        })
    }

    /// Check if a cluster is registered
    pub fn is_cluster_registered(&self, cluster_id: &str) -> bool {
        self.clusters.contains_key(cluster_id)
    }
}

/// Parse parent endpoint into host and gRPC port
/// Format: "host:http_port:grpc_port"
fn parse_parent_endpoint(endpoint: &str) -> (Option<String>, u16) {
    let parts: Vec<&str> = endpoint.split(':').collect();
    match parts.as_slice() {
        [host, _http_port, grpc_port] => {
            let port = grpc_port.parse().unwrap_or(crate::DEFAULT_GRPC_PORT);
            (Some((*host).to_string()), port)
        }
        _ => (None, crate::DEFAULT_GRPC_PORT),
    }
}

/// Extract bearer token from headers
fn extract_bearer_token(headers: &HeaderMap) -> Result<String, BootstrapError> {
    let auth_header = headers
        .get("authorization")
        .ok_or(BootstrapError::MissingAuth)?;

    let auth_str = auth_header
        .to_str()
        .map_err(|_| BootstrapError::InvalidToken)?;

    auth_str
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
        .ok_or(BootstrapError::InvalidToken)
}

/// CSR signing endpoint handler
///
/// Agents call this endpoint to get their CSR signed after bootstrap.
/// The cluster must have completed bootstrap (token consumed).
pub async fn csr_handler<G: ManifestGenerator>(
    State(state): State<Arc<BootstrapState<G>>>,
    Path(cluster_id): Path<String>,
    Json(request): Json<CsrRequest>,
) -> Result<Json<CsrResponse>, BootstrapError> {
    debug!(cluster_id = %cluster_id, "CSR signing request received");

    // Sign the CSR
    let response = state.sign_csr(&cluster_id, &request.csr_pem)?;

    info!(cluster_id = %cluster_id, "CSR signed successfully");

    Ok(Json(response))
}

/// Bootstrap manifests endpoint handler - returns raw YAML for kubectl apply
///
/// This endpoint is called by kubeadm postKubeadmCommands. It validates the
/// one-time token and returns the manifests as concatenated YAML that can
/// be piped directly to `kubectl apply -f -`.
pub async fn bootstrap_manifests_handler<G: ManifestGenerator>(
    State(state): State<Arc<BootstrapState<G>>>,
    Path(cluster_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, BootstrapError> {
    debug!(cluster_id = %cluster_id, "Bootstrap manifests request received");

    // Extract token
    let token = extract_bearer_token(&headers)?;

    // Validate and consume the token
    let info = state.validate_and_consume(&cluster_id, &token)?;

    info!(cluster_id = %cluster_id, "Bootstrap token validated, returning manifests");

    // Generate full bootstrap response (includes CNI, operator, LatticeCluster CRD, parent config)
    let response = state.generate_response(&info);

    // Join with YAML document separator
    let yaml_output = response.manifests.join("\n---\n");

    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/x-yaml")],
        yaml_output,
    )
        .into_response())
}

/// Create the bootstrap router
///
/// Routes:
/// - `GET /api/clusters/{cluster_id}/manifests` - Get raw YAML manifests for kubectl apply (one-time with token)
/// - `POST /api/clusters/{cluster_id}/csr` - Sign a CSR (after bootstrap)
pub fn bootstrap_router<G: ManifestGenerator + 'static>(
    state: Arc<BootstrapState<G>>,
) -> axum::Router {
    axum::Router::new()
        .route(
            "/api/clusters/{cluster_id}/manifests",
            get(bootstrap_manifests_handler::<G>),
        )
        .route("/api/clusters/{cluster_id}/csr", post(csr_handler::<G>))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::AgentCertRequest;
    use x509_parser::prelude::FromDer;

    struct TestManifestGenerator;

    impl ManifestGenerator for TestManifestGenerator {
        fn generate(
            &self,
            image: &str,
            _registry_credentials: Option<&str>,
            _cluster_name: Option<&str>,
            _provider: Option<&str>,
        ) -> Vec<String> {
            vec![format!("# Test manifest with image {}", image)]
        }
    }

    fn test_ca() -> Arc<CertificateAuthority> {
        Arc::new(CertificateAuthority::new("Test CA").unwrap())
    }

    fn test_state() -> BootstrapState<TestManifestGenerator> {
        BootstrapState::new(
            TestManifestGenerator,
            Duration::from_secs(3600),
            test_ca(),
            "test:latest".to_string(),
            None,
        )
    }

    fn test_state_with_ttl(ttl: Duration) -> BootstrapState<TestManifestGenerator> {
        BootstrapState::new(
            TestManifestGenerator,
            ttl,
            test_ca(),
            "test:latest".to_string(),
            None,
        )
    }

    /// Test helper to register cluster without networking config
    fn register_test_cluster<G: ManifestGenerator>(
        state: &BootstrapState<G>,
        cluster_id: impl Into<String>,
        cell_endpoint: impl Into<String>,
        ca_certificate: impl Into<String>,
    ) -> BootstrapToken {
        // Use a minimal test cluster manifest
        let cluster_manifest = r#"{"apiVersion":"lattice.dev/v1alpha1","kind":"LatticeCluster","metadata":{"name":"test"}}"#.to_string();
        state.register_cluster(ClusterRegistration {
            cluster_id: cluster_id.into(),
            cell_endpoint: cell_endpoint.into(),
            ca_certificate: ca_certificate.into(),
            cluster_manifest,
            networking: None,
            provider: "docker".to_string(),
            bootstrap: crate::crd::BootstrapProvider::default(),
        })
    }

    #[test]
    fn cluster_can_be_registered() {
        let state = test_state();

        let token = register_test_cluster(
            &state,
            "test-cluster".to_string(),
            "cell.example.com:8443:50051".to_string(),
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
        );

        assert!(!token.as_str().is_empty());
    }

    #[test]
    fn valid_token_is_accepted() {
        let state = test_state();

        let token = register_test_cluster(
            &state,
            "test-cluster".to_string(),
            "cell.example.com:8443:50051".to_string(),
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
        );

        let info = state
            .validate_and_consume("test-cluster", token.as_str())
            .unwrap();

        assert_eq!(info.cluster_id, "test-cluster");
    }

    #[test]
    fn invalid_token_is_rejected() {
        let state = test_state();

        register_test_cluster(
            &state,
            "test-cluster".to_string(),
            "cell.example.com:8443:50051".to_string(),
            "cert".to_string(),
        );

        let result = state.validate_and_consume("test-cluster", "wrong-token");

        assert!(matches!(result, Err(BootstrapError::InvalidToken)));
    }

    #[test]
    fn token_can_only_be_used_once() {
        let state = test_state();

        let token = register_test_cluster(
            &state,
            "test-cluster".to_string(),
            "cell.example.com:8443:50051".to_string(),
            "cert".to_string(),
        );

        // First use succeeds
        let _ = state
            .validate_and_consume("test-cluster", token.as_str())
            .unwrap();

        // Second use fails
        let result = state.validate_and_consume("test-cluster", token.as_str());
        assert!(matches!(result, Err(BootstrapError::TokenAlreadyUsed)));
    }

    #[test]
    fn expired_token_is_rejected() {
        let state = test_state_with_ttl(Duration::from_millis(1));

        let token = register_test_cluster(
            &state,
            "test-cluster".to_string(),
            "cell.example.com:8443:50051".to_string(),
            "cert".to_string(),
        );

        // Wait for token to expire
        std::thread::sleep(Duration::from_millis(10));

        let result = state.validate_and_consume("test-cluster", token.as_str());
        assert!(matches!(result, Err(BootstrapError::InvalidToken)));
    }

    #[test]
    fn unknown_cluster_is_rejected() {
        let state = test_state();

        let result = state.validate_and_consume("unknown-cluster", "any-token");
        assert!(matches!(result, Err(BootstrapError::ClusterNotFound(_))));
    }

    #[test]
    fn response_contains_manifests() {
        let state = test_state();

        let token = register_test_cluster(
            &state,
            "test-cluster".to_string(),
            "cell.example.com:8443:50051".to_string(),
            "ca-cert".to_string(),
        );

        let info = state
            .validate_and_consume("test-cluster", token.as_str())
            .unwrap();
        let response = state.generate_response(&info);

        assert_eq!(response.cluster_id, "test-cluster");
        assert_eq!(response.cell_endpoint, "cell.example.com:8443:50051");
        assert_eq!(response.ca_certificate, "ca-cert");
        assert!(!response.manifests.is_empty());
        // Manifest contains image from TestManifestGenerator, not cluster ID
        assert!(response.manifests[0].contains("# Test manifest"));
    }

    // CSR signing tests

    #[test]
    fn csr_requires_bootstrapped_cluster() {
        let state = test_state();

        // Register but don't bootstrap
        register_test_cluster(
            &state,
            "not-bootstrapped".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        );

        let agent_req = AgentCertRequest::new("not-bootstrapped").unwrap();
        let result = state.sign_csr("not-bootstrapped", agent_req.csr_pem());

        assert!(matches!(
            result,
            Err(BootstrapError::ClusterNotBootstrapped(_))
        ));
    }

    #[test]
    fn csr_rejected_for_unknown_cluster() {
        let state = test_state();

        let agent_req = AgentCertRequest::new("unknown").unwrap();
        let result = state.sign_csr("unknown", agent_req.csr_pem());

        assert!(matches!(result, Err(BootstrapError::ClusterNotFound(_))));
    }

    #[test]
    fn csr_signed_after_bootstrap() {
        let state = test_state();

        // Register and bootstrap
        let token = register_test_cluster(
            &state,
            "csr-test".to_string(),
            "cell:8443:50051".to_string(),
            state.ca_cert_pem().to_string(),
        );
        state
            .validate_and_consume("csr-test", token.as_str())
            .unwrap();

        // Now CSR signing should work
        let agent_req = AgentCertRequest::new("csr-test").unwrap();
        let result = state.sign_csr("csr-test", agent_req.csr_pem());

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(response.ca_certificate_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn signed_cert_contains_cluster_id() {
        let state = test_state();

        // Register and bootstrap
        let token = register_test_cluster(
            &state,
            "cluster-xyz".to_string(),
            "cell:8443:50051".to_string(),
            state.ca_cert_pem().to_string(),
        );
        state
            .validate_and_consume("cluster-xyz", token.as_str())
            .unwrap();

        // Sign CSR
        let agent_req = AgentCertRequest::new("cluster-xyz").unwrap();
        let response = state.sign_csr("cluster-xyz", agent_req.csr_pem()).unwrap();

        // Verify the cert contains cluster ID in CN
        // Parse and check (using x509-parser)
        let cert_pem = &response.certificate_pem;
        let pem_obj = ::pem::parse(cert_pem.as_bytes()).unwrap();
        let (_, cert) =
            x509_parser::prelude::X509Certificate::from_der(pem_obj.contents()).unwrap();

        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap();

        assert!(cn.contains("cluster-xyz"));
    }

    #[test]
    fn default_generator_creates_namespace() {
        let generator = DefaultManifestGenerator::new().unwrap();
        let manifests = generator.generate("test:latest", None, None, None);

        // Operator manifests are JSON, check for JSON format
        let has_namespace = manifests
            .iter()
            .any(|m| m.contains("\"kind\":\"Namespace\"") && m.contains("lattice-system"));
        assert!(has_namespace);
    }

    #[test]
    fn default_generator_creates_operator_deployment() {
        let generator = DefaultManifestGenerator::new().unwrap();
        let manifests = generator.generate("test:latest", None, None, None);

        // Operator manifests are JSON, check for JSON format
        let has_deployment = manifests
            .iter()
            .any(|m| m.contains("\"kind\":\"Deployment\"") && m.contains("lattice-operator"));
        assert!(has_deployment);
    }

    #[test]
    fn default_generator_creates_service_account() {
        let generator = DefaultManifestGenerator::new().unwrap();
        let manifests = generator.generate("test:latest", None, None, None);

        // Should have ServiceAccount for operator
        let has_sa = manifests
            .iter()
            .any(|m| m.contains("\"kind\":\"ServiceAccount\"") && m.contains("lattice-operator"));
        assert!(has_sa);
    }

    #[test]
    fn default_generator_creates_cilium_cni() {
        let generator = DefaultManifestGenerator::new().unwrap();
        let manifests = generator.generate("test:latest", None, None, None);

        // Should include Cilium DaemonSet (rendered from helm template)
        let has_cilium_daemonset = manifests
            .iter()
            .any(|m| m.contains("kind: DaemonSet") && m.contains("cilium"));
        assert!(has_cilium_daemonset, "Should include Cilium DaemonSet");

        // Should include Cilium ConfigMap
        let has_cilium_config = manifests
            .iter()
            .any(|m| m.contains("kind: ConfigMap") && m.contains("cilium"));
        assert!(has_cilium_config, "Should include Cilium ConfigMap");
    }

    #[test]
    fn bearer_token_extracted_correctly() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-token-123".parse().unwrap());

        let token = extract_bearer_token(&headers).unwrap();
        assert_eq!(token, "test-token-123");
    }

    #[test]
    fn missing_auth_header_rejected() {
        let headers = HeaderMap::new();
        let result = extract_bearer_token(&headers);
        assert!(matches!(result, Err(BootstrapError::MissingAuth)));
    }

    #[test]
    fn non_bearer_auth_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic abc123".parse().unwrap());

        let result = extract_bearer_token(&headers);
        assert!(matches!(result, Err(BootstrapError::InvalidToken)));
    }

    // ==========================================================================
    // Story Tests: Complete Bootstrap Flow
    // ==========================================================================
    //
    // These tests document the full bootstrap workflow as described in CLAUDE.md:
    // 1. Cluster is registered with a one-time token
    // 2. kubeadm postKubeadmCommands calls bootstrap endpoint with token
    // 3. Token is validated and consumed (one-time use)
    // 4. Agent receives manifests and CA certificate
    // 5. Agent generates keypair and submits CSR
    // 6. Cell signs CSR and returns certificate
    // 7. Agent uses certificate for mTLS connection

    /// Story: Complete bootstrap flow from registration to certificate
    ///
    /// This test demonstrates the entire bootstrap sequence as experienced
    /// by a newly provisioned workload cluster connecting to its parent cell.
    #[test]
    fn story_complete_bootstrap_flow() {
        let state = test_state();

        // Chapter 1: Cell registers a new cluster for provisioning
        // ---------------------------------------------------------
        // When CAPI creates a cluster, the cell registers it with a bootstrap token.
        // This token will be embedded in kubeadm postKubeadmCommands.
        let token = register_test_cluster(
            &state,
            "prod-us-west-001".to_string(),
            "cell.lattice.example.com:8443:50051".to_string(),
            state.ca_cert_pem().to_string(),
        );
        assert!(state.is_cluster_registered("prod-us-west-001"));

        // Chapter 2: kubeadm runs postKubeadmCommands on the new cluster
        // ---------------------------------------------------------------
        // The bootstrap script calls: GET /api/clusters/prod-us-west-001/bootstrap
        // with Authorization: Bearer <token>
        let info = state
            .validate_and_consume("prod-us-west-001", token.as_str())
            .unwrap();
        assert_eq!(info.cluster_id, "prod-us-west-001");
        assert_eq!(info.cell_endpoint, "cell.lattice.example.com:8443:50051");

        // Chapter 3: Cell returns bootstrap response with manifests
        // ----------------------------------------------------------
        let response = state.generate_response(&info);
        assert!(!response.manifests.is_empty());
        assert!(!response.ca_certificate.is_empty());
        assert_eq!(
            response.cell_endpoint,
            "cell.lattice.example.com:8443:50051"
        );

        // Chapter 4: Agent generates keypair and submits CSR
        // ---------------------------------------------------
        // Agent's private key NEVER leaves the workload cluster
        let agent_request = AgentCertRequest::new("prod-us-west-001").unwrap();
        assert!(!agent_request.csr_pem().contains("PRIVATE KEY")); // CSR doesn't contain key

        // Chapter 5: Cell signs the CSR
        // ------------------------------
        let csr_response = state
            .sign_csr("prod-us-west-001", agent_request.csr_pem())
            .unwrap();
        assert!(csr_response.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(csr_response
            .ca_certificate_pem
            .contains("BEGIN CERTIFICATE"));

        // Epilogue: Agent now has everything needed for mTLS
        // - Private key (locally generated, never transmitted)
        // - Signed certificate (from CSR response)
        // - CA certificate (for verifying the cell)
    }

    /// Story: Security - Token replay attacks are prevented
    ///
    /// Bootstrap tokens are one-time use. An attacker who captures
    /// a token cannot use it to bootstrap a malicious agent.
    #[test]
    fn story_token_replay_attack_prevention() {
        let state = test_state();

        // Legitimate cluster gets registered
        let token = register_test_cluster(
            &state,
            "secure-cluster".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        );

        // Legitimate bootstrap succeeds
        let _ = state
            .validate_and_consume("secure-cluster", token.as_str())
            .unwrap();

        // Attacker captures the token and tries to replay it
        let replay_result = state.validate_and_consume("secure-cluster", token.as_str());

        // Attack is blocked!
        assert!(matches!(
            replay_result,
            Err(BootstrapError::TokenAlreadyUsed)
        ));
    }

    /// Story: Security - Wrong tokens are rejected
    ///
    /// Tokens are cryptographically random and cluster-specific.
    /// Guessing or using the wrong token fails.
    #[test]
    fn story_invalid_token_rejection() {
        let state = test_state();

        register_test_cluster(
            &state,
            "guarded-cluster".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        );

        // Wrong token
        let result = state.validate_and_consume("guarded-cluster", "totally-wrong-token");
        assert!(matches!(result, Err(BootstrapError::InvalidToken)));

        // Token for wrong cluster
        let other_token = register_test_cluster(
            &state,
            "other-cluster".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        );
        let cross_cluster_result =
            state.validate_and_consume("guarded-cluster", other_token.as_str());
        assert!(matches!(
            cross_cluster_result,
            Err(BootstrapError::InvalidToken)
        ));
    }

    /// Story: Security - CSR signing requires completed bootstrap
    ///
    /// An agent can only get its CSR signed after completing the bootstrap
    /// flow. This prevents rogue agents from getting valid certificates.
    #[test]
    fn story_csr_requires_bootstrap_completion() {
        let state = test_state();

        // Register cluster but DON'T complete bootstrap
        let _token = register_test_cluster(
            &state,
            "premature-cluster".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        );

        // Try to get CSR signed without completing bootstrap
        let agent_request = AgentCertRequest::new("premature-cluster").unwrap();
        let result = state.sign_csr("premature-cluster", agent_request.csr_pem());

        // Blocked! Must complete bootstrap first
        assert!(matches!(
            result,
            Err(BootstrapError::ClusterNotBootstrapped(_))
        ));
    }

    /// Story: Security - Unknown clusters cannot bootstrap
    ///
    /// Only pre-registered clusters can use the bootstrap endpoint.
    /// Random cluster IDs are rejected.
    #[test]
    fn story_unknown_cluster_rejection() {
        let state = test_state();

        // No clusters registered - attacker tries to bootstrap
        let result = state.validate_and_consume("hacker-cluster", "fake-token");
        assert!(matches!(result, Err(BootstrapError::ClusterNotFound(_))));

        // Unknown cluster can't get CSR signed either
        let agent_request = AgentCertRequest::new("hacker-cluster").unwrap();
        let csr_result = state.sign_csr("hacker-cluster", agent_request.csr_pem());
        assert!(matches!(
            csr_result,
            Err(BootstrapError::ClusterNotFound(_))
        ));
    }

    /// Story: Token expiration for time-limited bootstrap windows
    ///
    /// Tokens have a TTL. If a cluster takes too long to bootstrap,
    /// the token expires and a new one must be generated.
    #[test]
    fn story_expired_token_rejection() {
        // Very short TTL for testing
        let state = test_state_with_ttl(Duration::from_millis(1));

        let token = register_test_cluster(
            &state,
            "slow-cluster".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        );

        // Simulate slow bootstrap by waiting
        std::thread::sleep(Duration::from_millis(10));

        // Token has expired
        let result = state.validate_and_consume("slow-cluster", token.as_str());
        assert!(matches!(result, Err(BootstrapError::InvalidToken)));
    }

    /// Story: Manifest generation for operator deployment
    ///
    /// The bootstrap response includes Kubernetes manifests that set up
    /// the Lattice operator on new clusters. Every cluster runs the same
    /// deployment - the controller reads LatticeCluster CRD to determine behavior.
    #[test]
    fn story_manifest_generation() {
        let generator = DefaultManifestGenerator::new().unwrap();
        let manifests = generator.generate("test:latest", None, None, None);

        // Manifests create the lattice-system namespace (JSON format)
        let has_namespace = manifests
            .iter()
            .any(|m| m.contains("\"kind\":\"Namespace\"") && m.contains("lattice-system"));
        assert!(has_namespace, "Should create lattice-system namespace");

        // Manifests deploy the operator (JSON format)
        let has_operator = manifests
            .iter()
            .any(|m| m.contains("\"kind\":\"Deployment\"") && m.contains("lattice-operator"));
        assert!(has_operator, "Should deploy lattice-operator");

        // Should have cluster-admin binding
        let has_rbac = manifests
            .iter()
            .any(|m| m.contains("\"kind\":\"ClusterRoleBinding\"") && m.contains("cluster-admin"));
        assert!(has_rbac, "Should have cluster-admin binding");
    }

    /// Story: HTTP API - Bearer token extraction
    ///
    /// The bootstrap endpoint uses standard Bearer token authentication.
    #[test]
    fn story_bearer_token_authentication() {
        // Valid Bearer token
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer my-secret-token".parse().unwrap());
        let token = extract_bearer_token(&headers).unwrap();
        assert_eq!(token, "my-secret-token");

        // Missing header
        let empty_headers = HeaderMap::new();
        let missing_result = extract_bearer_token(&empty_headers);
        assert!(matches!(missing_result, Err(BootstrapError::MissingAuth)));

        // Wrong auth scheme (Basic instead of Bearer)
        let mut basic_headers = HeaderMap::new();
        basic_headers.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
        let wrong_scheme = extract_bearer_token(&basic_headers);
        assert!(matches!(wrong_scheme, Err(BootstrapError::InvalidToken)));
    }

    /// Story: HTTP error responses map to correct status codes
    ///
    /// Different error types return appropriate HTTP status codes
    /// for proper client error handling.
    #[tokio::test]
    async fn story_error_http_responses() {
        use axum::http::StatusCode;

        // Authentication errors -> 401 Unauthorized
        let auth_err = BootstrapError::InvalidToken.into_response();
        assert_eq!(auth_err.status(), StatusCode::UNAUTHORIZED);

        let missing_auth = BootstrapError::MissingAuth.into_response();
        assert_eq!(missing_auth.status(), StatusCode::UNAUTHORIZED);

        // Token already used -> 410 Gone (resource no longer available)
        let used_err = BootstrapError::TokenAlreadyUsed.into_response();
        assert_eq!(used_err.status(), StatusCode::GONE);

        // Unknown cluster -> 404 Not Found
        let not_found = BootstrapError::ClusterNotFound("x".to_string()).into_response();
        assert_eq!(not_found.status(), StatusCode::NOT_FOUND);

        // CSR before bootstrap -> 412 Precondition Failed
        let precondition = BootstrapError::ClusterNotBootstrapped("x".to_string()).into_response();
        assert_eq!(precondition.status(), StatusCode::PRECONDITION_FAILED);

        // Bad CSR -> 400 Bad Request
        let bad_csr = BootstrapError::CsrSigningFailed("error".to_string()).into_response();
        assert_eq!(bad_csr.status(), StatusCode::BAD_REQUEST);

        // Internal errors -> 500 (and message hidden for security)
        let internal = BootstrapError::Internal("secret details".to_string()).into_response();
        assert_eq!(internal.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Story: PkiError converts to BootstrapError correctly
    ///
    /// When CSR signing fails due to PKI errors (invalid CSR format, etc.),
    /// the error should be properly converted to a BootstrapError.
    #[test]
    fn story_pki_error_converts_to_bootstrap_error() {
        use crate::pki::PkiError;

        // Test the From<PkiError> implementation
        let pki_error = PkiError::InvalidCsr("malformed CSR data".to_string());
        let bootstrap_error: BootstrapError = pki_error.into();

        match bootstrap_error {
            BootstrapError::CsrSigningFailed(msg) => {
                assert!(msg.contains("malformed CSR"));
            }
            _ => panic!("Expected CsrSigningFailed"),
        }
    }

    /// Story: CSR signing with malformed CSR returns proper error
    ///
    /// When an agent submits an invalid CSR (not proper PEM format),
    /// the signing should fail with a descriptive error.
    #[test]
    fn story_malformed_csr_returns_error() {
        let state = test_state();

        // Register and bootstrap
        let token = register_test_cluster(
            &state,
            "malformed-csr-test".to_string(),
            "cell:8443:50051".to_string(),
            state.ca_cert_pem().to_string(),
        );
        state
            .validate_and_consume("malformed-csr-test", token.as_str())
            .unwrap();

        // Try to sign a malformed CSR
        let result = state.sign_csr("malformed-csr-test", "not a valid CSR");

        // Should fail with CsrSigningFailed
        assert!(matches!(result, Err(BootstrapError::CsrSigningFailed(_))));
    }

    /// Story: CA certificate availability for distribution
    #[test]
    fn story_ca_certificate_distribution() {
        let state = test_state();

        // Cell provides CA cert for agents to verify mTLS
        let ca_cert = state.ca_cert_pem();
        assert!(ca_cert.contains("BEGIN CERTIFICATE"));

        // This CA cert is included in bootstrap response
        let token = register_test_cluster(
            &state,
            "ca-test".to_string(),
            "cell:8443:50051".to_string(),
            ca_cert.to_string(),
        );
        let info = state
            .validate_and_consume("ca-test", token.as_str())
            .unwrap();
        let response = state.generate_response(&info);

        assert_eq!(response.ca_certificate, ca_cert);
    }

    // ==========================================================================
    // Integration Tests: HTTP Handlers
    // ==========================================================================

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// Integration test: bootstrap_router creates valid routes
    #[tokio::test]
    async fn integration_bootstrap_router_creation() {
        let state = Arc::new(test_state());
        let _router = bootstrap_router(state);

        // Router should be created without panic
    }

    /// Integration test: manifests endpoint with valid token
    #[tokio::test]
    async fn integration_manifests_handler_success() {
        let state = Arc::new(test_state());
        let token = register_test_cluster(
            &state,
            "http-test".to_string(),
            "cell:8443:50051".to_string(),
            "ca-cert".to_string(),
        );

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/clusters/http-test/manifests")
            .header("authorization", format!("Bearer {}", token.as_str()))
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Response is raw YAML for kubectl apply
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let manifests_yaml = String::from_utf8(body.to_vec()).unwrap();

        // Should contain test manifest from TestManifestGenerator
        assert!(manifests_yaml.contains("# Test manifest"));
    }

    /// Integration test: manifests endpoint with missing auth
    #[tokio::test]
    async fn integration_manifests_handler_missing_auth() {
        let state = Arc::new(test_state());
        register_test_cluster(
            &state,
            "auth-test".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        );

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/clusters/auth-test/manifests")
            // No authorization header
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Integration test: manifests endpoint with invalid token
    #[tokio::test]
    async fn integration_manifests_handler_invalid_token() {
        let state = Arc::new(test_state());
        register_test_cluster(
            &state,
            "token-test".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        );

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/clusters/token-test/manifests")
            .header("authorization", "Bearer wrong-token")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Integration test: manifests endpoint for unknown cluster
    #[tokio::test]
    async fn integration_manifests_handler_unknown_cluster() {
        let state = Arc::new(test_state());
        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/clusters/nonexistent/manifests")
            .header("authorization", "Bearer any-token")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Integration test: CSR endpoint with valid request
    #[tokio::test]
    async fn integration_csr_handler_success() {
        let state = Arc::new(test_state());

        // Register and bootstrap first
        let token = register_test_cluster(
            &state,
            "csr-http-test".to_string(),
            "cell:8443:50051".to_string(),
            state.ca_cert_pem().to_string(),
        );
        state
            .validate_and_consume("csr-http-test", token.as_str())
            .unwrap();

        // Generate CSR
        let agent_req = AgentCertRequest::new("csr-http-test").unwrap();
        let csr_request = CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
        };

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/api/clusters/csr-http-test/csr")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&csr_request).unwrap()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Parse response
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let csr_response: CsrResponse = serde_json::from_slice(&body).unwrap();

        assert!(csr_response.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(csr_response
            .ca_certificate_pem
            .contains("BEGIN CERTIFICATE"));
    }

    /// Integration test: CSR endpoint before bootstrap
    #[tokio::test]
    async fn integration_csr_handler_before_bootstrap() {
        let state = Arc::new(test_state());

        // Register but DON'T bootstrap
        register_test_cluster(
            &state,
            "not-bootstrapped".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        );

        let agent_req = AgentCertRequest::new("not-bootstrapped").unwrap();
        let csr_request = CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
        };

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/api/clusters/not-bootstrapped/csr")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&csr_request).unwrap()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    }

    /// Integration test: CSR endpoint for unknown cluster
    #[tokio::test]
    async fn integration_csr_handler_unknown_cluster() {
        let state = Arc::new(test_state());

        let agent_req = AgentCertRequest::new("unknown").unwrap();
        let csr_request = CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
        };

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/api/clusters/unknown/csr")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&csr_request).unwrap()))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Integration test: Full HTTP bootstrap flow (manifests + CSR)
    #[tokio::test]
    async fn integration_full_http_bootstrap_flow() {
        let state = Arc::new(test_state());
        let ca_cert = state.ca_cert_pem().to_string();

        // Step 1: Register cluster
        let token = register_test_cluster(
            &state,
            "full-flow-test".to_string(),
            "cell.example.com:8443:50051".to_string(),
            ca_cert.clone(),
        );

        let router = bootstrap_router(state);

        // Step 2: Get manifests (returns raw YAML for kubectl apply)
        let manifests_request = Request::builder()
            .method("GET")
            .uri("/api/clusters/full-flow-test/manifests")
            .header("authorization", format!("Bearer {}", token.as_str()))
            .body(Body::empty())
            .unwrap();

        let response = router.clone().oneshot(manifests_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let manifests_yaml = String::from_utf8(body.to_vec()).unwrap();
        // Manifest contains image from TestManifestGenerator, not cluster ID
        assert!(manifests_yaml.contains("# Test manifest"));

        // Step 3: CSR signing
        let agent_req = AgentCertRequest::new("full-flow-test").unwrap();
        let csr_body = serde_json::to_string(&CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
        })
        .unwrap();

        let csr_request = Request::builder()
            .method("POST")
            .uri("/api/clusters/full-flow-test/csr")
            .header("content-type", "application/json")
            .body(Body::from(csr_body))
            .unwrap();

        let response = router.oneshot(csr_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let csr_response: CsrResponse = serde_json::from_slice(&body).unwrap();
        assert!(csr_response.certificate_pem.contains("BEGIN CERTIFICATE"));
    }

    // ==========================================================================
    // FIPS Relaxation Tests
    // ==========================================================================
    //
    // These tests verify that FIPS relaxation is correctly applied based on
    // the bootstrap provider:
    // - Kubeadm clusters need FIPS relaxation (GODEBUG=fips140=on) because
    //   kubeadm's API server uses non-FIPS cipher suites
    // - RKE2 clusters are FIPS-compliant out of the box (no relaxation needed)

    /// Story: Kubeadm clusters get FIPS relaxation in manifests
    ///
    /// When a cluster uses kubeadm bootstrap, the generated manifests should
    /// include GODEBUG=fips140=on to allow the operator to communicate with
    /// the kubeadm API server which uses non-FIPS cipher suites (like X25519).
    #[test]
    fn story_kubeadm_clusters_get_fips_relaxation() {
        // Use real DefaultManifestGenerator to get actual Deployment
        let state = BootstrapState::new(
            DefaultManifestGenerator::new().unwrap(),
            Duration::from_secs(3600),
            test_ca(),
            "test:latest".to_string(),
            None,
        );

        // Register cluster with kubeadm bootstrap
        let cluster_manifest = r#"{"apiVersion":"lattice.dev/v1alpha1","kind":"LatticeCluster","metadata":{"name":"kubeadm-test"}}"#.to_string();
        state.clusters.insert(
            "kubeadm-test".to_string(),
            ClusterBootstrapInfo {
                cluster_id: "kubeadm-test".to_string(),
                cell_endpoint: "cell:8443:50051".to_string(),
                ca_certificate: "ca-cert".to_string(),
                cluster_manifest,
                token_hash: "hash".to_string(),
                token_created: std::time::Instant::now(),
                token_used: true, // Already bootstrapped
                networking: None,
                provider: "docker".to_string(),
                bootstrap: crate::crd::BootstrapProvider::Kubeadm,
            },
        );

        let info = state.clusters.get("kubeadm-test").unwrap().clone();
        let response = state.generate_response(&info);

        // Should have GODEBUG=fips140=on in the deployment
        let manifests_str = response.manifests.join("\n");
        assert!(
            manifests_str.contains("fips140=on"),
            "Kubeadm clusters should have FIPS relaxation (GODEBUG=fips140=on)"
        );
    }

    /// Story: RKE2 clusters do NOT get FIPS relaxation in manifests
    ///
    /// When a cluster uses RKE2 bootstrap, the generated manifests should NOT
    /// include FIPS relaxation because RKE2 is FIPS-compliant out of the box.
    /// The container default (fips140=only) is appropriate for RKE2 clusters.
    #[test]
    fn story_rke2_clusters_no_fips_relaxation() {
        // Use real DefaultManifestGenerator to get actual Deployment
        let state = BootstrapState::new(
            DefaultManifestGenerator::new().unwrap(),
            Duration::from_secs(3600),
            test_ca(),
            "test:latest".to_string(),
            None,
        );

        // Register cluster with RKE2 bootstrap
        let cluster_manifest = r#"{"apiVersion":"lattice.dev/v1alpha1","kind":"LatticeCluster","metadata":{"name":"rke2-test"}}"#.to_string();
        state.clusters.insert(
            "rke2-test".to_string(),
            ClusterBootstrapInfo {
                cluster_id: "rke2-test".to_string(),
                cell_endpoint: "cell:8443:50051".to_string(),
                ca_certificate: "ca-cert".to_string(),
                cluster_manifest,
                token_hash: "hash".to_string(),
                token_created: std::time::Instant::now(),
                token_used: true, // Already bootstrapped
                networking: None,
                provider: "docker".to_string(),
                bootstrap: crate::crd::BootstrapProvider::Rke2,
            },
        );

        let info = state.clusters.get("rke2-test").unwrap().clone();
        let response = state.generate_response(&info);

        // Should NOT have GODEBUG=fips140=on in the deployment
        let manifests_str = response.manifests.join("\n");
        assert!(
            !manifests_str.contains("fips140=on"),
            "RKE2 clusters should NOT have FIPS relaxation (uses container default fips140=only)"
        );
    }

    /// Story: BootstrapProvider correctly reports FIPS requirements
    #[test]
    fn story_bootstrap_provider_fips_properties() {
        use crate::crd::BootstrapProvider;

        // Kubeadm needs FIPS relaxation
        assert!(BootstrapProvider::Kubeadm.needs_fips_relax());
        assert!(!BootstrapProvider::Kubeadm.is_fips_native());

        // RKE2 is FIPS-native, no relaxation needed
        assert!(!BootstrapProvider::Rke2.needs_fips_relax());
        assert!(BootstrapProvider::Rke2.is_fips_native());
    }
}
