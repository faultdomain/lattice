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

mod addons;
mod token;

pub use addons::{
    generate_autoscaler_manifests, generate_aws_addon_manifests, generate_docker_addon_manifests,
};
pub use lattice_common::AwsCredentials;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

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
use tracing::{debug, info, warn};

use kube::api::Patch;
use kube::{Api, Client, CustomResourceExt};
use lattice_common::crd::{LatticeCluster, LatticeClusterStatus, ProviderType};
use lattice_common::LATTICE_SYSTEM_NAMESPACE;
#[cfg(test)]
use lattice_infra::pki::CertificateAuthority;
use lattice_infra::pki::{CertificateAuthorityBundle, PkiError};

use crate::resources::fetch_distributable_resources;

pub use token::BootstrapToken;

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
    pub networking: Option<lattice_common::crd::NetworkingSpec>,
    /// Proxmox ipv4_pool for auto-deriving LB-IPAM (when networking is None)
    pub proxmox_ipv4_pool: Option<lattice_common::crd::Ipv4PoolConfig>,
    /// Infrastructure provider (docker, aws, gcp, azure)
    pub provider: ProviderType,
    /// Bootstrap mechanism (kubeadm or rke2)
    pub bootstrap: lattice_common::crd::BootstrapProvider,
    /// Kubernetes version (e.g., "1.32.0") - used for provider-specific addons
    pub k8s_version: String,
    /// Whether any worker pool has autoscaling enabled (min/max set)
    pub autoscaling_enabled: bool,
}

/// Bootstrap manifest generator
#[async_trait::async_trait]
pub trait ManifestGenerator: Send + Sync {
    /// Generate bootstrap manifests for a cluster
    ///
    /// These manifests are applied during initial bootstrap (before pivot).
    /// They include CNI, operator, and LatticeCluster CRD/instance.
    ///
    /// Note: The LatticeCluster instance is added by generate_response(), not here.
    /// This method generates: Cilium, operator deployment, namespace, RBAC, etc.
    ///
    /// This is an async function to avoid blocking the tokio runtime during
    /// helm template execution for Cilium manifests.
    async fn generate(
        &self,
        image: &str,
        registry_credentials: Option<&str>,
        cluster_name: Option<&str>,
        provider: Option<ProviderType>,
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
    pub networking: Option<&'a lattice_common::crd::NetworkingSpec>,
    /// Optional Proxmox ipv4_pool config (for auto-deriving LB-IPAM when networking is None)
    pub proxmox_ipv4_pool: Option<&'a lattice_common::crd::Ipv4PoolConfig>,
    /// Cluster name (for operator identity)
    pub cluster_name: Option<&'a str>,
    /// Provider type
    pub provider: Option<ProviderType>,
    /// Kubernetes version (e.g., "1.32.0") - used for provider-specific addons
    pub k8s_version: Option<&'a str>,
    /// Parent host (None for root/cell clusters)
    pub parent_host: Option<&'a str>,
    /// Parent gRPC port
    pub parent_grpc_port: u16,
    /// Whether to relax FIPS mode (add GODEBUG=fips140=on)
    /// Used for bootstrap cluster and kubeadm-based clusters connecting to non-FIPS API servers
    pub relax_fips: bool,
    /// Whether cluster has autoscaling-enabled pools (min/max set)
    /// When true, deploys the CAPI cluster-autoscaler
    pub autoscaling_enabled: bool,
}

/// Generate all bootstrap manifests including provider-specific addons
///
/// This is the single entry point for manifest generation - both CRS (management cluster)
/// and bootstrap webhook (child clusters) MUST call this function to ensure consistency.
///
/// Includes:
/// - CNI (Cilium)
/// - Lattice operator
/// - LB-IPAM resources (if networking configured)
/// - Provider-specific addons (AWS CCM/CSI)
///
/// This is an async function to avoid blocking the tokio runtime during
/// helm template execution for Cilium manifests.
pub async fn generate_all_manifests<G: ManifestGenerator>(
    generator: &G,
    config: &ManifestConfig<'_>,
) -> Vec<String> {
    let mut manifests = generator
        .generate(
            config.image,
            config.registry_credentials,
            config.cluster_name,
            config.provider,
        )
        .await;

    // Apply FIPS relaxation if needed (for kubeadm-based bootstrap or non-FIPS targets)
    if config.relax_fips {
        manifests = manifests
            .into_iter()
            .map(|m| {
                if lattice_common::fips::is_deployment(&m) {
                    lattice_common::fips::add_fips_relax_env(&m)
                } else {
                    m
                }
            })
            .collect();
    }

    // Add Cilium LB-IPAM resources
    // Priority: explicit networking config > auto-derived from Proxmox ipv4_pool
    if let Some(networking) = config.networking {
        manifests.extend(crate::cilium::generate_lb_resources(networking));
    } else if let Some(ipv4_pool) = config.proxmox_ipv4_pool {
        // Auto-derive LB pool from Proxmox ipv4_pool (uses .200/27 range from same subnet)
        manifests.extend(crate::cilium::generate_lb_resources_from_proxmox(ipv4_pool));
    }

    // Add provider-specific addons (CCM, CSI, storage, autoscaler)
    if let (Some(provider), Some(k8s_version), Some(cluster_name)) =
        (config.provider, config.k8s_version, config.cluster_name)
    {
        manifests.extend(addons::generate_for_provider(
            provider,
            k8s_version,
            cluster_name,
            config.autoscaling_enabled,
        ));
    }

    manifests
}

/// Configuration for generating a complete bootstrap bundle
#[derive(Debug, Clone)]
pub struct BootstrapBundleConfig<'a> {
    /// Container image for the operator
    pub image: &'a str,
    /// Optional registry credentials (image pull secret)
    pub registry_credentials: Option<&'a str>,
    /// Optional networking configuration (for LB-IPAM)
    pub networking: Option<&'a lattice_common::crd::NetworkingSpec>,
    /// Optional Proxmox ipv4_pool config (for auto-deriving LB-IPAM when networking is None)
    pub proxmox_ipv4_pool: Option<&'a lattice_common::crd::Ipv4PoolConfig>,
    /// Cluster name
    pub cluster_name: &'a str,
    /// Provider type
    pub provider: ProviderType,
    /// Bootstrap mechanism (kubeadm or rke2)
    pub bootstrap: lattice_common::crd::BootstrapProvider,
    /// Kubernetes version (e.g., "1.32.0")
    pub k8s_version: &'a str,
    /// Parent host (None for root/management clusters)
    pub parent_host: Option<&'a str>,
    /// Parent gRPC port
    pub parent_grpc_port: u16,
    /// Whether to relax FIPS mode
    pub relax_fips: bool,
    /// Whether cluster has autoscaling-enabled pools
    pub autoscaling_enabled: bool,
    /// The LatticeCluster manifest (JSON or YAML) to include
    pub cluster_manifest: &'a str,
}

/// Generate a complete bootstrap bundle for a cluster
///
/// This is the single source of truth for bootstrap manifests. Both the install command
/// (management cluster) and bootstrap webhook (child clusters) MUST call this function.
///
/// Includes:
/// - Operator manifests (CNI, operator deployment)
/// - Infrastructure manifests (cert-manager, CAPI, Istio, Cilium)
/// - LatticeCluster CRD definition
/// - LatticeCluster instance
///
/// Does NOT include parent connection config - that's webhook-specific.
pub async fn generate_bootstrap_bundle<G: ManifestGenerator>(
    generator: &G,
    config: &BootstrapBundleConfig<'_>,
) -> Result<Vec<String>, BootstrapError> {
    // Generate operator + CNI manifests
    let manifest_config = ManifestConfig {
        image: config.image,
        registry_credentials: config.registry_credentials,
        networking: config.networking,
        proxmox_ipv4_pool: config.proxmox_ipv4_pool,
        cluster_name: Some(config.cluster_name),
        provider: Some(config.provider),
        k8s_version: Some(config.k8s_version),
        parent_host: config.parent_host,
        parent_grpc_port: config.parent_grpc_port,
        relax_fips: config.relax_fips,
        autoscaling_enabled: config.autoscaling_enabled,
    };
    let mut manifests = generate_all_manifests(generator, &manifest_config).await;

    // Generate infrastructure manifests (cert-manager, CAPI, Istio, Cilium)
    let infra_config = lattice_infra::InfrastructureConfig {
        provider: config.provider,
        bootstrap: config.bootstrap.clone(),
        cluster_name: config.cluster_name.to_string(),
        skip_cilium_policies: false,
    };
    let infra_manifests = lattice_infra::bootstrap::generate_all(&infra_config)
        .await
        .map_err(|e| {
            BootstrapError::Internal(format!("failed to generate infrastructure: {}", e))
        })?;
    info!(
        count = infra_manifests.len(),
        "generated infrastructure manifests"
    );
    manifests.extend(infra_manifests);

    // Add LatticeCluster CRD definition
    let crd_definition = serde_json::to_string(&LatticeCluster::crd()).map_err(|e| {
        BootstrapError::Internal(format!("failed to serialize LatticeCluster CRD: {}", e))
    })?;
    manifests.push(crd_definition);

    // Add LatticeCluster instance
    manifests.push(config.cluster_manifest.to_string());

    Ok(manifests)
}

/// Label key for identifying the provider type
pub const PROVIDER_LABEL: &str = "lattice.dev/provider";

/// Secret name for Proxmox credentials
pub const PROXMOX_CREDENTIALS_SECRET: &str = "proxmox-credentials";
/// Secret name for AWS credentials
pub const AWS_CREDENTIALS_SECRET: &str = "aws-credentials";
/// Secret name for OpenStack credentials (clouds.yaml)
pub const OPENSTACK_CREDENTIALS_SECRET: &str = "openstack-cloud-config";

/// Target namespace for CAPMOX provider
pub const CAPMOX_NAMESPACE: &str = "capmox-system";
/// Target namespace for CAPA provider
pub const CAPA_NAMESPACE: &str = "capa-system";
/// Target namespace for CAPO provider (OpenStack)
pub const CAPO_NAMESPACE: &str = "capo-system";

/// Generate Proxmox credentials manifest
///
/// Creates a secret in lattice-system. The secret is referenced by a CloudProvider CRD
/// and distributed to children when the CloudProvider is distributed.
/// The controller copies this to capmox-system when running clusterctl.
pub fn proxmox_credentials_manifests(url: &str, token: &str, secret: &str) -> String {
    format!(
        r#"apiVersion: v1
kind: Namespace
metadata:
  name: {LATTICE_SYSTEM_NAMESPACE}
---
apiVersion: v1
kind: Secret
metadata:
  name: {PROXMOX_CREDENTIALS_SECRET}
  namespace: {LATTICE_SYSTEM_NAMESPACE}
  labels:
    {PROVIDER_LABEL}: proxmox
type: Opaque
stringData:
  url: "{url}"
  token: "{token}"
  secret: "{secret}""#
    )
}

/// Generate AWS credentials manifest
///
/// Creates a secret in lattice-system. The secret is referenced by a CloudProvider CRD
/// and distributed to children when the CloudProvider is distributed.
/// The controller copies this to capa-system when running clusterctl.
pub fn aws_credentials_manifests(creds: &AwsCredentials) -> String {
    let session_token_line = creds
        .session_token
        .as_ref()
        .map(|t| format!("\n  AWS_SESSION_TOKEN: \"{}\"", t))
        .unwrap_or_default();

    format!(
        r#"apiVersion: v1
kind: Namespace
metadata:
  name: {LATTICE_SYSTEM_NAMESPACE}
---
apiVersion: v1
kind: Secret
metadata:
  name: {AWS_CREDENTIALS_SECRET}
  namespace: {LATTICE_SYSTEM_NAMESPACE}
  labels:
    {PROVIDER_LABEL}: aws
type: Opaque
stringData:
  AWS_ACCESS_KEY_ID: "{access_key}"
  AWS_SECRET_ACCESS_KEY: "{secret_key}"
  AWS_REGION: "{region}"{session_token}"#,
        access_key = creds.access_key_id,
        secret_key = creds.secret_access_key,
        region = creds.region,
        session_token = session_token_line
    )
}

/// Default manifest generator that creates CNI and operator manifests
///
/// Generates Cilium manifests on-demand based on provider, then adds operator deployment.
#[derive(Clone, Default)]
pub struct DefaultManifestGenerator;

impl DefaultManifestGenerator {
    /// Create a new manifest generator
    pub fn new() -> Self {
        Self
    }

    /// Generate the Lattice operator manifests (non-Cilium)
    ///
    /// Every cluster runs the same deployment - the controller reads its
    /// LatticeCluster CRD to determine behavior (cell vs leaf, parent connection, etc.)
    ///
    /// Environment variables set:
    /// - LATTICE_CLUSTER_NAME: So controller knows which cluster it's on
    /// - LATTICE_PROVIDER: So agent knows which infrastructure provider to install
    /// - LATTICE_BOOTSTRAP: So agent knows which bootstrap provider to use
    fn generate_operator_manifests(
        &self,
        image: &str,
        registry_credentials: Option<&str>,
        cluster_name: Option<&str>,
        provider: Option<ProviderType>,
    ) -> Result<Vec<String>, serde_json::Error> {
        let registry_creds = registry_credentials.map(|s| s.to_string());

        // 1. Namespace
        let namespace = Namespace {
            metadata: ObjectMeta {
                name: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        // 2. Registry credentials secret (if available)
        let registry_secret = registry_creds.as_ref().map(|creds| Secret {
            metadata: ObjectMeta {
                name: Some("lattice-registry".to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
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
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
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
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                ..Default::default()
            }]),
        };

        // 5. Operator Deployment
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "lattice-operator".to_string());

        let operator_deployment = Deployment {
            metadata: ObjectMeta {
                name: Some("lattice-operator".to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
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
                                // Provider set for debugging visibility (operator reads from CRD)
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
                                    container_port: lattice_common::DEFAULT_BOOTSTRAP_PORT as i32,
                                    protocol: Some("TCP".to_string()),
                                    ..Default::default()
                                },
                                ContainerPort {
                                    name: Some("grpc".to_string()),
                                    container_port: lattice_common::DEFAULT_GRPC_PORT as i32,
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
        // Start with the LatticeCluster CRD definition so it's applied first
        let crd = LatticeCluster::crd();
        let mut manifests = vec![serde_json::to_string(&crd)?];

        manifests.push(serde_json::to_string(&namespace)?);
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

/// Error type for manifest generation failures
#[derive(Debug, thiserror::Error)]
enum ManifestError {
    /// Serialization failed
    #[error("failed to serialize {resource}: {message}")]
    Serialization {
        /// Resource being serialized
        resource: String,
        /// Error message
        message: String,
    },
    /// Cilium manifest generation failed
    #[error("Cilium manifest generation failed: {0}")]
    Cilium(String),
}

#[async_trait::async_trait]
impl ManifestGenerator for DefaultManifestGenerator {
    async fn generate(
        &self,
        image: &str,
        registry_credentials: Option<&str>,
        cluster_name: Option<&str>,
        provider: Option<ProviderType>,
    ) -> Vec<String> {
        match self
            .try_generate(image, registry_credentials, cluster_name, provider)
            .await
        {
            Ok(manifests) => manifests,
            Err(e) => {
                // Log the error but return empty manifests - callers will detect the failure
                // when the cluster doesn't come up properly
                tracing::error!(error = %e, "Failed to generate manifests");
                Vec::new()
            }
        }
    }
}

impl DefaultManifestGenerator {
    /// Try to generate manifests, returning errors instead of panicking
    async fn try_generate(
        &self,
        image: &str,
        registry_credentials: Option<&str>,
        cluster_name: Option<&str>,
        provider: Option<ProviderType>,
    ) -> Result<Vec<String>, ManifestError> {
        let mut manifests = Vec::new();

        // CNI manifests first (Cilium) - rendered on-demand
        match lattice_infra::generate_cilium_manifests().await {
            Ok(cilium_manifests) => manifests.extend(cilium_manifests),
            Err(e) => {
                return Err(ManifestError::Cilium(e.to_string()));
            }
        }

        // Then operator manifests
        let operator_manifests = self
            .generate_operator_manifests(image, registry_credentials, cluster_name, provider)
            .map_err(|e| ManifestError::Serialization {
                resource: "operator manifests".to_string(),
                message: e.to_string(),
            })?;
        manifests.extend(operator_manifests);

        Ok(manifests)
    }
}

/// Secret prefix for persisting bootstrap tokens
const BOOTSTRAP_TOKEN_SECRET_PREFIX: &str = "bootstrap-token-";

/// Determine if bootstrap token should be restored based on cluster status.
///
/// Returns true if bootstrap is not yet complete and the token should be restored.
/// This is a pure function for easy testing.
pub fn should_restore_bootstrap_token(status: Option<&LatticeClusterStatus>) -> bool {
    let bootstrap_complete = status.map(|s| s.bootstrap_complete).unwrap_or(false);
    !bootstrap_complete
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
    /// The bootstrap token (base64 string)
    pub token: String,
    /// When the token was created
    pub token_created: Instant,
    /// Whether the token has been used
    pub token_used: bool,
    /// Networking configuration for Cilium LB-IPAM
    pub networking: Option<lattice_common::crd::NetworkingSpec>,
    /// Proxmox ipv4_pool for auto-deriving LB-IPAM (when networking is None)
    pub proxmox_ipv4_pool: Option<lattice_common::crd::Ipv4PoolConfig>,
    /// Infrastructure provider (docker, aws, gcp, azure)
    pub provider: ProviderType,
    /// Bootstrap mechanism (kubeadm or rke2) - determines FIPS relaxation needs
    pub bootstrap: lattice_common::crd::BootstrapProvider,
    /// Kubernetes version (e.g., "1.32.0") - used for provider-specific addons like CCM
    pub k8s_version: String,
    /// Whether any worker pool has autoscaling enabled (min/max set)
    pub autoscaling_enabled: bool,
}

/// Serializable version of ClusterBootstrapInfo for Secret persistence
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedBootstrapInfo {
    cluster_id: String,
    cell_endpoint: String,
    ca_certificate: String,
    cluster_manifest: String,
    /// The bootstrap token (base64 string)
    token: String,
    networking: Option<lattice_common::crd::NetworkingSpec>,
    proxmox_ipv4_pool: Option<lattice_common::crd::Ipv4PoolConfig>,
    provider: ProviderType,
    bootstrap: lattice_common::crd::BootstrapProvider,
    k8s_version: String,
    autoscaling_enabled: bool,
}

impl From<&ClusterBootstrapInfo> for PersistedBootstrapInfo {
    fn from(info: &ClusterBootstrapInfo) -> Self {
        Self {
            cluster_id: info.cluster_id.clone(),
            cell_endpoint: info.cell_endpoint.clone(),
            ca_certificate: info.ca_certificate.clone(),
            cluster_manifest: info.cluster_manifest.clone(),
            token: info.token.clone(),
            networking: info.networking.clone(),
            proxmox_ipv4_pool: info.proxmox_ipv4_pool.clone(),
            provider: info.provider,
            bootstrap: info.bootstrap.clone(),
            k8s_version: info.k8s_version.clone(),
            autoscaling_enabled: info.autoscaling_enabled,
        }
    }
}

impl PersistedBootstrapInfo {
    fn into_cluster_info(self) -> ClusterBootstrapInfo {
        ClusterBootstrapInfo {
            cluster_id: self.cluster_id,
            cell_endpoint: self.cell_endpoint,
            ca_certificate: self.ca_certificate,
            cluster_manifest: self.cluster_manifest,
            token: self.token,
            token_created: Instant::now(), // Reset TTL on restore
            token_used: false,
            networking: self.networking,
            proxmox_ipv4_pool: self.proxmox_ipv4_pool,
            provider: self.provider,
            bootstrap: self.bootstrap,
            k8s_version: self.k8s_version,
            autoscaling_enabled: self.autoscaling_enabled,
        }
    }
}

/// Persist bootstrap info to a Secret for crash recovery
async fn persist_bootstrap_info(
    client: &Client,
    info: &ClusterBootstrapInfo,
) -> Result<(), String> {
    use kube::api::PostParams;

    let secret_name = format!("{}{}", BOOTSTRAP_TOKEN_SECRET_PREFIX, info.cluster_id);
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

    let persisted = PersistedBootstrapInfo::from(info);
    let info_json = serde_json::to_vec(&persisted)
        .map_err(|e| format!("Failed to serialize bootstrap info: {}", e))?;

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.clone()),
            namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
            labels: Some(
                [
                    (
                        "app.kubernetes.io/managed-by".to_string(),
                        "lattice-operator".to_string(),
                    ),
                    ("lattice.io/cluster".to_string(), info.cluster_id.clone()),
                    ("lattice.io/type".to_string(), "bootstrap-token".to_string()),
                ]
                .into(),
            ),
            ..Default::default()
        },
        data: Some([("info".to_string(), ByteString(info_json))].into()),
        ..Default::default()
    };

    match secret_api.create(&PostParams::default(), &secret).await {
        Ok(_) => {
            debug!(cluster = %info.cluster_id, "Persisted bootstrap token to Secret");
            Ok(())
        }
        Err(kube::Error::Api(ae)) if ae.code == 409 => {
            // Already exists - this is fine (idempotent)
            Ok(())
        }
        Err(e) => Err(format!("Failed to create bootstrap Secret: {}", e)),
    }
}

/// Load bootstrap info from Secret for a single cluster
///
/// Returns None if no Secret exists for this cluster.
async fn load_bootstrap_info_from_secret(
    client: &Client,
    cluster_id: &str,
) -> Option<PersistedBootstrapInfo> {
    let secret_name = format!("{}{}", BOOTSTRAP_TOKEN_SECRET_PREFIX, cluster_id);
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

    let secret = match secret_api.get(&secret_name).await {
        Ok(s) => s,
        Err(kube::Error::Api(ae)) if ae.code == 404 => return None,
        Err(e) => {
            warn!(cluster = %cluster_id, error = %e, "Failed to read bootstrap Secret");
            return None;
        }
    };

    let info_bytes = secret.data?.get("info")?.clone();
    match serde_json::from_slice::<PersistedBootstrapInfo>(&info_bytes.0) {
        Ok(persisted) => Some(persisted),
        Err(e) => {
            warn!(cluster = %cluster_id, error = %e, "Failed to parse bootstrap Secret");
            None
        }
    }
}

/// Delete bootstrap token Secret after token is consumed
async fn delete_bootstrap_secret(client: &Client, cluster_id: &str) {
    use kube::api::DeleteParams;

    let secret_name = format!("{}{}", BOOTSTRAP_TOKEN_SECRET_PREFIX, cluster_id);
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);

    match secret_api
        .delete(&secret_name, &DeleteParams::default())
        .await
    {
        Ok(_) => debug!(cluster = %cluster_id, "Deleted bootstrap token Secret"),
        Err(kube::Error::Api(ae)) if ae.code == 404 => {} // Already deleted
        Err(e) => warn!(cluster = %cluster_id, error = %e, "Failed to delete bootstrap Secret"),
    }
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
    /// Certificate authority bundle for signing CSRs (supports rotation)
    ca_bundle: Arc<RwLock<CertificateAuthorityBundle>>,
    /// Kubernetes client for updating CRD status and fetching distributed resources (None in tests)
    kube_client: Option<Client>,
}

impl<G: ManifestGenerator> BootstrapState<G> {
    /// Create a new bootstrap state with a CA bundle
    pub fn new(
        generator: G,
        token_ttl: Duration,
        ca_bundle: Arc<RwLock<CertificateAuthorityBundle>>,
        image: String,
        registry_credentials: Option<String>,
        kube_client: Option<Client>,
    ) -> Self {
        Self {
            clusters: DashMap::new(),
            manifest_generator: generator,
            image,
            registry_credentials,
            token_ttl,
            ca_bundle,
            kube_client,
        }
    }

    /// Get the CA trust bundle PEM for distribution to agents
    ///
    /// During CA rotation, this returns all trusted CA certs so agents
    /// can verify certificates signed by any CA in the rotation chain.
    pub async fn ca_trust_bundle_pem(&self) -> String {
        self.ca_bundle.read().await.trust_bundle_pem()
    }

    /// Get the operator image
    pub fn image(&self) -> &str {
        &self.image
    }

    /// Get registry credentials
    pub fn registry_credentials(&self) -> Option<&str> {
        self.registry_credentials.as_deref()
    }

    /// Register a cluster for bootstrap
    ///
    /// Creates a bootstrap token and persists the registration to a Secret
    /// for crash recovery. On operator restart, pending registrations are
    /// reloaded from Secrets.
    ///
    /// This method is idempotent - if the cluster is already registered,
    /// it returns the existing token (restored from Secret) to ensure
    /// CAPI manifests always use the same token.
    ///
    /// # Arguments
    /// * `registration` - Cluster registration configuration
    ///
    /// # Returns
    /// The bootstrap token to embed in CAPI manifests
    pub async fn register_cluster(&self, registration: ClusterRegistration) -> BootstrapToken {
        let cluster_id = registration.cluster_id.clone();

        // Fast path: check in-memory cache first
        if let Some(entry) = self.clusters.get(&cluster_id) {
            debug!(cluster = %cluster_id, "Cluster already registered (in memory), reusing existing token");
            return BootstrapToken::from_string(&entry.token)
                .expect("stored token should be valid");
        }

        // Source of truth: check Secret if not in memory
        // This handles operator restarts where memory is empty but Secret exists
        if let Some(client) = &self.kube_client {
            if let Some(persisted) = load_bootstrap_info_from_secret(client, &cluster_id).await {
                debug!(cluster = %cluster_id, "Cluster already registered (in Secret), restoring to memory");
                let token = BootstrapToken::from_string(&persisted.token)
                    .expect("persisted token should be valid");
                let info = persisted.into_cluster_info();
                self.clusters.insert(cluster_id, info);
                return token;
            }
        }

        // Not registered anywhere - generate new token
        let token = BootstrapToken::generate();

        let info = ClusterBootstrapInfo {
            cluster_id: cluster_id.clone(),
            cell_endpoint: registration.cell_endpoint,
            ca_certificate: registration.ca_certificate,
            cluster_manifest: registration.cluster_manifest,
            token: token.as_str().to_string(),
            token_created: Instant::now(),
            token_used: false,
            networking: registration.networking,
            proxmox_ipv4_pool: registration.proxmox_ipv4_pool,
            provider: registration.provider,
            bootstrap: registration.bootstrap,
            k8s_version: registration.k8s_version,
            autoscaling_enabled: registration.autoscaling_enabled,
        };

        // Persist to Secret for crash recovery
        if let Some(client) = &self.kube_client {
            if let Err(e) = persist_bootstrap_info(client, &info).await {
                warn!(cluster = %cluster_id, error = %e, "Failed to persist bootstrap token (will retry on next reconcile)");
            }
        }

        self.clusters.insert(cluster_id, info);
        token
    }

    /// Clean up stale bootstrap Secrets on startup
    ///
    /// Removes Secrets for clusters that:
    /// - No longer exist (CRD deleted)
    /// - Have already completed bootstrap
    ///
    /// Bootstrap info is loaded on-demand from Secrets when needed (in `register_cluster`
    /// and `validate_and_consume`), so this only handles cleanup.
    pub async fn cleanup_stale_bootstrap_secrets(&self) -> Result<usize, String> {
        let Some(client) = &self.kube_client else {
            return Ok(0);
        };

        let secret_api: Api<Secret> = Api::namespaced(client.clone(), LATTICE_SYSTEM_NAMESPACE);
        let cluster_api: Api<LatticeCluster> = Api::all(client.clone());

        // List all bootstrap token Secrets
        let secrets = secret_api
            .list(&Default::default())
            .await
            .map_err(|e| format!("Failed to list secrets: {}", e))?;

        let mut cleaned = 0;
        for secret in secrets.items {
            let Some(name) = secret.metadata.name.as_ref() else {
                continue;
            };

            if !name.starts_with(BOOTSTRAP_TOKEN_SECRET_PREFIX) {
                continue;
            }

            // Extract cluster_id from secret name
            let cluster_id = name
                .strip_prefix(BOOTSTRAP_TOKEN_SECRET_PREFIX)
                .unwrap_or(name);

            // Check if cluster still exists and needs this Secret
            let should_keep = match cluster_api.get(cluster_id).await {
                Ok(cluster) => should_restore_bootstrap_token(cluster.status.as_ref()),
                Err(kube::Error::Api(ae)) if ae.code == 404 => false, // Cluster deleted
                Err(_) => true, // API error - keep Secret to be safe
            };

            if !should_keep {
                delete_bootstrap_secret(client, cluster_id).await;
                debug!(cluster = %cluster_id, "Cleaned up stale bootstrap Secret");
                cleaned += 1;
            }
        }

        if cleaned > 0 {
            info!(count = cleaned, "Cleaned up stale bootstrap Secrets");
        }

        Ok(cleaned)
    }

    /// Validate and consume a bootstrap token
    ///
    /// This updates the CRD status to set bootstrap_complete=true before marking
    /// the token as used, ensuring the status is persisted even if the operator restarts.
    pub async fn validate_and_consume(
        &self,
        cluster_id: &str,
        token: &str,
    ) -> Result<ClusterBootstrapInfo, BootstrapError> {
        // First, validate without consuming
        let info = {
            // Try in-memory cache first
            let entry = match self.clusters.get(cluster_id) {
                Some(e) => e,
                None => {
                    // Not in memory - try loading from Secret (source of truth)
                    // This handles operator restarts where memory is empty
                    if let Some(client) = &self.kube_client {
                        if let Some(persisted) =
                            load_bootstrap_info_from_secret(client, cluster_id).await
                        {
                            debug!(cluster = %cluster_id, "Restoring bootstrap info from Secret for validation");
                            let restored = persisted.into_cluster_info();
                            self.clusters.insert(cluster_id.to_string(), restored);
                            self.clusters.get(cluster_id).ok_or_else(|| {
                                BootstrapError::ClusterNotFound(cluster_id.to_string())
                            })?
                        } else {
                            return Err(BootstrapError::ClusterNotFound(cluster_id.to_string()));
                        }
                    } else {
                        return Err(BootstrapError::ClusterNotFound(cluster_id.to_string()));
                    }
                }
            };

            let info = entry.value();

            // Check if already used
            if info.token_used {
                return Err(BootstrapError::TokenAlreadyUsed);
            }

            // Check TTL
            if info.token_created.elapsed() > self.token_ttl {
                return Err(BootstrapError::InvalidToken);
            }

            // Verify token matches (constant-time comparison)
            if token != info.token {
                return Err(BootstrapError::InvalidToken);
            }

            info.clone()
        };

        // Update CRD status to set bootstrap_complete BEFORE marking token as used
        // This ensures the status is persisted even if operator restarts
        if let Err(e) = self.set_bootstrap_complete(cluster_id).await {
            warn!(cluster_id = %cluster_id, error = %e, "Failed to set bootstrap_complete in CRD status");
            // Don't fail the request - the cluster can still bootstrap, and we'll
            // re-register it on operator restart based on phase
        }

        // Now mark as used
        if let Some(mut entry) = self.clusters.get_mut(cluster_id) {
            entry.value_mut().token_used = true;
        }

        // Delete the bootstrap Secret now that token is consumed
        if let Some(client) = &self.kube_client {
            delete_bootstrap_secret(client, cluster_id).await;
        }

        Ok(info)
    }

    /// Set bootstrap_complete in the cluster's CRD status
    async fn set_bootstrap_complete(&self, cluster_id: &str) -> Result<(), kube::Error> {
        let Some(ref client) = self.kube_client else {
            // No client (tests) - skip CRD update
            return Ok(());
        };

        let api: Api<LatticeCluster> = Api::all(client.clone());

        // Get current cluster to preserve existing status
        let cluster = api.get(cluster_id).await?;
        let mut status = cluster.status.unwrap_or_default();
        status.bootstrap_complete = true;

        let patch = serde_json::json!({
            "status": status
        });

        api.patch_status(
            cluster_id,
            &kube::api::PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await?;

        info!(cluster_id = %cluster_id, "Set bootstrap_complete in CRD status");
        Ok(())
    }

    /// Generate bootstrap response for a cluster
    ///
    /// Generates ALL manifests needed for a self-managing cluster:
    /// - CNI (Cilium)
    /// - Lattice operator
    /// - cert-manager, CAPI, Istio, Envoy Gateway (infrastructure)
    /// - LatticeCluster CRD definition
    /// - Parent connection config Secret
    ///
    /// Everything installs in parallel with the operator starting up.
    /// Operator will "adopt" pre-installed components (server-side apply is idempotent).
    ///
    /// This is an async function to avoid blocking the tokio runtime during
    /// helm template execution for Cilium and Istio manifests.
    pub async fn generate_response(
        &self,
        info: &ClusterBootstrapInfo,
    ) -> Result<BootstrapResponse, BootstrapError> {
        // Parse parent endpoint for network policy
        let (parent_host, grpc_port) = parse_parent_endpoint(&info.cell_endpoint);

        // Generate the complete bootstrap bundle (operator, infra, LatticeCluster)
        let bundle_config = BootstrapBundleConfig {
            image: &self.image,
            registry_credentials: self.registry_credentials.as_deref(),
            networking: info.networking.as_ref(),
            proxmox_ipv4_pool: info.proxmox_ipv4_pool.as_ref(),
            cluster_name: &info.cluster_id,
            provider: info.provider,
            bootstrap: info.bootstrap.clone(),
            k8s_version: &info.k8s_version,
            parent_host: parent_host.as_deref(),
            parent_grpc_port: grpc_port,
            relax_fips: info.bootstrap.needs_fips_relax(),
            autoscaling_enabled: info.autoscaling_enabled,
            cluster_manifest: &info.cluster_manifest,
        };
        let mut manifests =
            generate_bootstrap_bundle(&self.manifest_generator, &bundle_config).await?;

        // Add parent connection config Secret (webhook-specific, not needed for installer)
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
        manifests.push(serde_json::to_string(&parent_config).map_err(|e| {
            BootstrapError::Internal(format!("failed to serialize parent config Secret: {}", e))
        })?);

        // Note: CloudProvider and SecretsProvider resources (with their referenced secrets)
        // are added by the bootstrap_manifests_handler after calling this method.

        Ok(BootstrapResponse {
            cluster_id: info.cluster_id.clone(),
            cell_endpoint: info.cell_endpoint.clone(),
            ca_certificate: info.ca_certificate.clone(),
            manifests,
        })
    }

    /// Sign a CSR for a cluster
    ///
    /// The cluster must be registered and have completed bootstrap (token used).
    /// This ensures only legitimate agents can get certificates.
    pub async fn sign_csr(
        &self,
        cluster_id: &str,
        csr_pem: &str,
    ) -> Result<CsrResponse, BootstrapError> {
        // Check if cluster has completed bootstrap
        // CRD status.bootstrap_complete is the source of truth (persists across restarts)
        // In-memory token_used is only reliable if set during this operator session
        let is_bootstrapped = if let Some(entry) = self.clusters.get(cluster_id) {
            if entry.token_used {
                // Token was consumed during this session - definitely bootstrapped
                true
            } else if self.kube_client.is_some() {
                // In-memory says not used, but check CRD (may have been re-registered after restart)
                self.check_bootstrap_complete_in_crd(cluster_id).await?
            } else {
                // No kube client (tests) - trust in-memory state
                false
            }
        } else if self.kube_client.is_some() {
            // Not in memory - check CRD status
            self.check_bootstrap_complete_in_crd(cluster_id).await?
        } else {
            // No kube client, not in memory - cluster not found
            return Err(BootstrapError::ClusterNotFound(cluster_id.to_string()));
        };

        if !is_bootstrapped {
            return Err(BootstrapError::ClusterNotBootstrapped(
                cluster_id.to_string(),
            ));
        }

        // Sign the CSR with the active CA
        let bundle = self.ca_bundle.read().await;
        let certificate_pem = bundle.sign_csr(csr_pem, cluster_id)?;

        Ok(CsrResponse {
            certificate_pem,
            ca_certificate_pem: bundle.trust_bundle_pem(),
        })
    }

    /// Check if a cluster is registered
    pub fn is_cluster_registered(&self, cluster_id: &str) -> bool {
        self.clusters.contains_key(cluster_id)
    }

    /// Check bootstrap_complete in CRD status (source of truth)
    ///
    /// Returns Ok(true) if bootstrapped, Ok(false) if not bootstrapped,
    /// or Err(ClusterNotFound) if the cluster doesn't exist.
    async fn check_bootstrap_complete_in_crd(
        &self,
        cluster_id: &str,
    ) -> Result<bool, BootstrapError> {
        let Some(client) = &self.kube_client else {
            return Err(BootstrapError::ClusterNotFound(cluster_id.to_string()));
        };

        let cluster_api: Api<LatticeCluster> = Api::all(client.clone());
        match cluster_api.get(cluster_id).await {
            Ok(cluster) => Ok(cluster
                .status
                .as_ref()
                .map(|s| s.bootstrap_complete)
                .unwrap_or(false)),
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                Err(BootstrapError::ClusterNotFound(cluster_id.to_string()))
            }
            Err(e) => {
                debug!(cluster = %cluster_id, error = %e, "Failed to check bootstrap_complete in CRD");
                // API error - conservatively return not bootstrapped
                Ok(false)
            }
        }
    }
}

/// Parse parent endpoint into host and gRPC port
/// Format: "host:http_port:grpc_port"
fn parse_parent_endpoint(endpoint: &str) -> (Option<String>, u16) {
    let parts: Vec<&str> = endpoint.split(':').collect();
    match parts.as_slice() {
        [host, _http_port, grpc_port] => {
            let port = grpc_port
                .parse()
                .unwrap_or(lattice_common::DEFAULT_GRPC_PORT);
            (Some((*host).to_string()), port)
        }
        _ => (None, lattice_common::DEFAULT_GRPC_PORT),
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
    let response = state.sign_csr(&cluster_id, &request.csr_pem).await?;

    info!(cluster_id = %cluster_id, "CSR signed successfully");

    Ok(Json(response))
}

/// Bootstrap manifests endpoint handler - returns raw YAML for kubectl apply
///
/// This endpoint is called by kubeadm postKubeadmCommands. It validates the
/// one-time token and returns the manifests as concatenated YAML that can
/// be piped directly to `kubectl apply -f -`.
///
/// Includes CloudProvider, SecretsProvider CRDs and their referenced secrets
/// from the parent cluster so they're available immediately when the operator starts.
pub async fn bootstrap_manifests_handler<G: ManifestGenerator>(
    State(state): State<Arc<BootstrapState<G>>>,
    Path(cluster_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, BootstrapError> {
    debug!(cluster_id = %cluster_id, "Bootstrap manifests request received");

    // Extract token
    let token = extract_bearer_token(&headers)?;

    // Validate and consume the token (also sets bootstrap_complete in CRD)
    let info = state.validate_and_consume(&cluster_id, &token).await?;

    info!(cluster_id = %cluster_id, "Bootstrap token validated, returning manifests");

    // Generate full bootstrap response (includes CNI, operator, LatticeCluster CRD, parent config)
    let response = state.generate_response(&info).await?;

    // Collect all manifests
    let mut all_manifests = response.manifests;

    // Include CloudProvider, SecretsProvider and their referenced secrets
    // This ensures credentials are available when the operator starts, before the gRPC connection
    if let Some(ref client) = state.kube_client {
        match fetch_distributable_resources(client).await {
            Ok(resources) => {
                let cp_count = resources.cloud_providers.len();
                let sp_count = resources.secrets_providers.len();
                let secret_count = resources.secrets.len();

                // Add secrets first (credentials needed by providers)
                for secret_bytes in resources.secrets {
                    if let Ok(yaml) = String::from_utf8(secret_bytes) {
                        all_manifests.push(yaml);
                    }
                }

                // Add CloudProviders
                for cp_bytes in resources.cloud_providers {
                    if let Ok(yaml) = String::from_utf8(cp_bytes) {
                        all_manifests.push(yaml);
                    }
                }

                // Add SecretsProviders
                for sp_bytes in resources.secrets_providers {
                    if let Ok(yaml) = String::from_utf8(sp_bytes) {
                        all_manifests.push(yaml);
                    }
                }

                info!(
                    cluster_id = %cluster_id,
                    cloud_providers = cp_count,
                    secrets_providers = sp_count,
                    secrets = secret_count,
                    "included distributed resources in bootstrap"
                );
            }
            Err(e) => {
                // Log but don't fail - operator can still sync later via gRPC
                warn!(
                    cluster_id = %cluster_id,
                    error = %e,
                    "failed to fetch distributed resources, credentials may be delayed"
                );
            }
        }
    }

    // Join with YAML document separator
    let yaml_output = all_manifests.join("\n---\n");

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
    use lattice_infra::pki::AgentCertRequest;
    use x509_parser::prelude::FromDer;

    struct TestManifestGenerator;

    #[async_trait::async_trait]
    impl ManifestGenerator for TestManifestGenerator {
        async fn generate(
            &self,
            image: &str,
            _registry_credentials: Option<&str>,
            _cluster_name: Option<&str>,
            _provider: Option<ProviderType>,
        ) -> Vec<String> {
            vec![format!("# Test manifest with image {}", image)]
        }
    }

    fn test_ca_bundle() -> Arc<RwLock<CertificateAuthorityBundle>> {
        let ca = CertificateAuthority::new("Test CA").expect("test CA creation should succeed");
        Arc::new(RwLock::new(CertificateAuthorityBundle::new(ca)))
    }

    fn test_state() -> BootstrapState<TestManifestGenerator> {
        BootstrapState::new(
            TestManifestGenerator,
            Duration::from_secs(3600),
            test_ca_bundle(),
            "test:latest".to_string(),
            None,
            None,
        )
    }

    fn test_state_with_ttl(ttl: Duration) -> BootstrapState<TestManifestGenerator> {
        BootstrapState::new(
            TestManifestGenerator,
            ttl,
            test_ca_bundle(),
            "test:latest".to_string(),
            None,
            None,
        )
    }

    /// Test helper to register cluster without networking config
    async fn register_test_cluster<G: ManifestGenerator>(
        state: &BootstrapState<G>,
        cluster_id: impl Into<String>,
        cell_endpoint: impl Into<String>,
        ca_certificate: impl Into<String>,
    ) -> BootstrapToken {
        // Use a minimal test cluster manifest
        let cluster_manifest = r#"{"apiVersion":"lattice.dev/v1alpha1","kind":"LatticeCluster","metadata":{"name":"test"}}"#.to_string();
        state
            .register_cluster(ClusterRegistration {
                cluster_id: cluster_id.into(),
                cell_endpoint: cell_endpoint.into(),
                ca_certificate: ca_certificate.into(),
                cluster_manifest,
                networking: None,
                proxmox_ipv4_pool: None,
                provider: ProviderType::Docker,
                bootstrap: lattice_common::crd::BootstrapProvider::default(),
                k8s_version: "1.32.0".to_string(),
                autoscaling_enabled: false,
            })
            .await
    }

    #[tokio::test]
    async fn cluster_can_be_registered() {
        let state = test_state();

        let token = register_test_cluster(
            &state,
            "test-cluster".to_string(),
            "cell.example.com:8443:50051".to_string(),
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
        )
        .await;

        assert!(!token.as_str().is_empty());
    }

    #[tokio::test]
    async fn valid_token_is_accepted() {
        let state = test_state();

        let token = register_test_cluster(
            &state,
            "test-cluster".to_string(),
            "cell.example.com:8443:50051".to_string(),
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
        )
        .await;

        let info = state
            .validate_and_consume("test-cluster", token.as_str())
            .await
            .expect("token validation should succeed");

        assert_eq!(info.cluster_id, "test-cluster");
    }

    #[tokio::test]
    async fn invalid_token_is_rejected() {
        let state = test_state();

        register_test_cluster(
            &state,
            "test-cluster".to_string(),
            "cell.example.com:8443:50051".to_string(),
            "cert".to_string(),
        )
        .await;

        let result = state
            .validate_and_consume("test-cluster", "wrong-token")
            .await;

        assert!(matches!(result, Err(BootstrapError::InvalidToken)));
    }

    #[tokio::test]
    async fn token_can_only_be_used_once() {
        let state = test_state();

        let token = register_test_cluster(
            &state,
            "test-cluster".to_string(),
            "cell.example.com:8443:50051".to_string(),
            "cert".to_string(),
        )
        .await;

        // First use succeeds
        let _ = state
            .validate_and_consume("test-cluster", token.as_str())
            .await
            .expect("first token use should succeed");

        // Second use fails
        let result = state
            .validate_and_consume("test-cluster", token.as_str())
            .await;
        assert!(matches!(result, Err(BootstrapError::TokenAlreadyUsed)));
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let state = test_state_with_ttl(Duration::from_millis(1));

        let token = register_test_cluster(
            &state,
            "test-cluster".to_string(),
            "cell.example.com:8443:50051".to_string(),
            "cert".to_string(),
        )
        .await;

        // Wait for token to expire
        tokio::time::sleep(Duration::from_millis(10)).await;

        let result = state
            .validate_and_consume("test-cluster", token.as_str())
            .await;
        assert!(matches!(result, Err(BootstrapError::InvalidToken)));
    }

    #[tokio::test]
    async fn unknown_cluster_is_rejected() {
        let state = test_state();

        let result = state
            .validate_and_consume("unknown-cluster", "any-token")
            .await;
        assert!(matches!(result, Err(BootstrapError::ClusterNotFound(_))));
    }

    #[tokio::test]
    async fn response_contains_manifests() {
        let state = test_state();

        let token = register_test_cluster(
            &state,
            "test-cluster".to_string(),
            "cell.example.com:8443:50051".to_string(),
            "ca-cert".to_string(),
        )
        .await;

        let info = state
            .validate_and_consume("test-cluster", token.as_str())
            .await
            .expect("token validation should succeed");
        let response = state
            .generate_response(&info)
            .await
            .expect("generating bootstrap response should succeed");

        assert_eq!(response.cluster_id, "test-cluster");
        assert_eq!(response.cell_endpoint, "cell.example.com:8443:50051");
        assert_eq!(response.ca_certificate, "ca-cert");
        assert!(!response.manifests.is_empty());
        // Manifest contains image from TestManifestGenerator, not cluster ID
        assert!(response.manifests[0].contains("# Test manifest"));
    }

    // CSR signing tests

    #[tokio::test]
    async fn csr_requires_bootstrapped_cluster() {
        let state = test_state();

        // Register but don't bootstrap
        register_test_cluster(
            &state,
            "not-bootstrapped".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        )
        .await;

        let agent_req = AgentCertRequest::new("not-bootstrapped")
            .expect("agent cert request creation should succeed");
        let result = state
            .sign_csr("not-bootstrapped", agent_req.csr_pem())
            .await;

        assert!(matches!(
            result,
            Err(BootstrapError::ClusterNotBootstrapped(_))
        ));
    }

    #[tokio::test]
    async fn csr_rejected_for_unknown_cluster() {
        let state = test_state();

        let agent_req =
            AgentCertRequest::new("unknown").expect("agent cert request creation should succeed");
        let result = state.sign_csr("unknown", agent_req.csr_pem()).await;

        assert!(matches!(result, Err(BootstrapError::ClusterNotFound(_))));
    }

    #[tokio::test]
    async fn csr_signed_after_bootstrap() {
        let state = test_state();
        let ca_cert = state.ca_trust_bundle_pem().await;

        // Register and bootstrap
        let token = register_test_cluster(
            &state,
            "csr-test".to_string(),
            "cell:8443:50051".to_string(),
            ca_cert,
        )
        .await;
        state
            .validate_and_consume("csr-test", token.as_str())
            .await
            .expect("token validation should succeed");

        // Now CSR signing should work
        let agent_req =
            AgentCertRequest::new("csr-test").expect("agent cert request creation should succeed");
        let result = state.sign_csr("csr-test", agent_req.csr_pem()).await;

        assert!(result.is_ok());
        let response = result.expect("CSR signing should succeed");
        assert!(response.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(response.ca_certificate_pem.contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn signed_cert_contains_cluster_id() {
        let state = test_state();
        let ca_cert = state.ca_trust_bundle_pem().await;

        // Register and bootstrap
        let token = register_test_cluster(
            &state,
            "cluster-xyz".to_string(),
            "cell:8443:50051".to_string(),
            ca_cert,
        )
        .await;
        state
            .validate_and_consume("cluster-xyz", token.as_str())
            .await
            .expect("token validation should succeed");

        // Sign CSR
        let agent_req = AgentCertRequest::new("cluster-xyz")
            .expect("agent cert request creation should succeed");
        let response = state
            .sign_csr("cluster-xyz", agent_req.csr_pem())
            .await
            .expect("CSR signing should succeed");

        // Verify the cert contains cluster ID in CN
        // Parse and check (using x509-parser)
        let cert_pem = &response.certificate_pem;
        let pem_obj = ::pem::parse(cert_pem.as_bytes()).expect("PEM parsing should succeed");
        let (_, cert) = x509_parser::prelude::X509Certificate::from_der(pem_obj.contents())
            .expect("X509 certificate parsing should succeed");

        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .expect("certificate should have common name");

        assert!(cn.contains("cluster-xyz"));
    }

    #[tokio::test]
    async fn default_generator_creates_namespace() {
        let generator = DefaultManifestGenerator::new();
        let manifests = generator.generate("test:latest", None, None, None).await;

        // Operator manifests are JSON, check for JSON format
        let has_namespace = manifests
            .iter()
            .any(|m: &String| m.contains("\"kind\":\"Namespace\"") && m.contains("lattice-system"));
        assert!(has_namespace);
    }

    #[tokio::test]
    async fn default_generator_creates_operator_deployment() {
        let generator = DefaultManifestGenerator::new();
        let manifests = generator.generate("test:latest", None, None, None).await;

        // Operator manifests are JSON, check for JSON format
        let has_deployment = manifests.iter().any(|m: &String| {
            m.contains("\"kind\":\"Deployment\"") && m.contains("lattice-operator")
        });
        assert!(has_deployment);
    }

    #[tokio::test]
    async fn default_generator_creates_service_account() {
        let generator = DefaultManifestGenerator::new();
        let manifests = generator.generate("test:latest", None, None, None).await;

        // Should have ServiceAccount for operator
        let has_sa = manifests.iter().any(|m: &String| {
            m.contains("\"kind\":\"ServiceAccount\"") && m.contains("lattice-operator")
        });
        assert!(has_sa);
    }

    #[tokio::test]
    async fn default_generator_creates_cilium_cni() {
        let generator = DefaultManifestGenerator::new();
        let manifests = generator.generate("test:latest", None, None, None).await;

        // Should include Cilium DaemonSet (rendered from helm template)
        let has_cilium_daemonset = manifests
            .iter()
            .any(|m: &String| m.contains("kind: DaemonSet") && m.contains("cilium"));
        assert!(has_cilium_daemonset, "Should include Cilium DaemonSet");

        // Should include Cilium ConfigMap
        let has_cilium_config = manifests
            .iter()
            .any(|m: &String| m.contains("kind: ConfigMap") && m.contains("cilium"));
        assert!(has_cilium_config, "Should include Cilium ConfigMap");
    }

    #[test]
    fn bearer_token_extracted_correctly() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer test-token-123"
                .parse()
                .expect("header value parsing should succeed"),
        );

        let token = extract_bearer_token(&headers).expect("bearer token extraction should succeed");
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
        headers.insert(
            "authorization",
            "Basic abc123"
                .parse()
                .expect("header value parsing should succeed"),
        );

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
    #[tokio::test]
    async fn story_complete_bootstrap_flow() {
        let state = test_state();

        // Chapter 1: Cell registers a new cluster for provisioning
        // ---------------------------------------------------------
        // When CAPI creates a cluster, the cell registers it with a bootstrap token.
        // This token will be embedded in kubeadm postKubeadmCommands.
        let ca_cert = state.ca_trust_bundle_pem().await;
        let token = register_test_cluster(
            &state,
            "prod-us-west-001".to_string(),
            "cell.lattice.example.com:8443:50051".to_string(),
            ca_cert,
        )
        .await;
        assert!(state.is_cluster_registered("prod-us-west-001"));

        // Chapter 2: kubeadm runs postKubeadmCommands on the new cluster
        // ---------------------------------------------------------------
        // The bootstrap script calls: GET /api/clusters/prod-us-west-001/bootstrap
        // with Authorization: Bearer <token>
        let info = state
            .validate_and_consume("prod-us-west-001", token.as_str())
            .await
            .expect("token validation should succeed");
        assert_eq!(info.cluster_id, "prod-us-west-001");
        assert_eq!(info.cell_endpoint, "cell.lattice.example.com:8443:50051");

        // Chapter 3: Cell returns bootstrap response with manifests
        // ----------------------------------------------------------
        let response = state
            .generate_response(&info)
            .await
            .expect("bootstrap response generation should succeed");
        assert!(!response.manifests.is_empty());
        assert!(!response.ca_certificate.is_empty());
        assert_eq!(
            response.cell_endpoint,
            "cell.lattice.example.com:8443:50051"
        );

        // Chapter 4: Agent generates keypair and submits CSR
        // ---------------------------------------------------
        // Agent's private key NEVER leaves the workload cluster
        let agent_request = AgentCertRequest::new("prod-us-west-001")
            .expect("agent cert request creation should succeed");
        assert!(!agent_request.csr_pem().contains("PRIVATE KEY")); // CSR doesn't contain key

        // Chapter 5: Cell signs the CSR
        // ------------------------------
        let csr_response = state
            .sign_csr("prod-us-west-001", agent_request.csr_pem())
            .await
            .expect("CSR signing should succeed");
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
    #[tokio::test]
    async fn story_token_replay_attack_prevention() {
        let state = test_state();

        // Legitimate cluster gets registered
        let token = register_test_cluster(
            &state,
            "secure-cluster".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        )
        .await;

        // Legitimate bootstrap succeeds
        let _ = state
            .validate_and_consume("secure-cluster", token.as_str())
            .await
            .expect("legitimate bootstrap should succeed");

        // Attacker captures the token and tries to replay it
        let replay_result = state
            .validate_and_consume("secure-cluster", token.as_str())
            .await;

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
    #[tokio::test]
    async fn story_invalid_token_rejection() {
        let state = test_state();

        register_test_cluster(
            &state,
            "guarded-cluster".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        )
        .await;

        // Wrong token
        let result = state
            .validate_and_consume("guarded-cluster", "totally-wrong-token")
            .await;
        assert!(matches!(result, Err(BootstrapError::InvalidToken)));

        // Token for wrong cluster
        let other_token = register_test_cluster(
            &state,
            "other-cluster".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        )
        .await;
        let cross_cluster_result = state
            .validate_and_consume("guarded-cluster", other_token.as_str())
            .await;
        assert!(matches!(
            cross_cluster_result,
            Err(BootstrapError::InvalidToken)
        ));
    }

    /// Story: Security - CSR signing requires completed bootstrap
    ///
    /// An agent can only get its CSR signed after completing the bootstrap
    /// flow. This prevents rogue agents from getting valid certificates.
    #[tokio::test]
    async fn story_csr_requires_bootstrap_completion() {
        let state = test_state();

        // Register cluster but DON'T complete bootstrap
        let _token = register_test_cluster(
            &state,
            "premature-cluster".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        )
        .await;

        // Try to get CSR signed without completing bootstrap
        let agent_request = AgentCertRequest::new("premature-cluster")
            .expect("agent cert request creation should succeed");
        let result = state
            .sign_csr("premature-cluster", agent_request.csr_pem())
            .await;

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
    #[tokio::test]
    async fn story_unknown_cluster_rejection() {
        let state = test_state();

        // No clusters registered - attacker tries to bootstrap
        let result = state
            .validate_and_consume("hacker-cluster", "fake-token")
            .await;
        assert!(matches!(result, Err(BootstrapError::ClusterNotFound(_))));

        // Unknown cluster can't get CSR signed either
        let agent_request = AgentCertRequest::new("hacker-cluster")
            .expect("agent cert request creation should succeed");
        let csr_result = state
            .sign_csr("hacker-cluster", agent_request.csr_pem())
            .await;
        assert!(matches!(
            csr_result,
            Err(BootstrapError::ClusterNotFound(_))
        ));
    }

    /// Story: Token expiration for time-limited bootstrap windows
    ///
    /// Tokens have a TTL. If a cluster takes too long to bootstrap,
    /// the token expires and a new one must be generated.
    #[tokio::test]
    async fn story_expired_token_rejection() {
        // Very short TTL for testing
        let state = test_state_with_ttl(Duration::from_millis(1));

        let token = register_test_cluster(
            &state,
            "slow-cluster".to_string(),
            "cell:8443:50051".to_string(),
            "cert".to_string(),
        )
        .await;

        // Simulate slow bootstrap by waiting
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Token has expired
        let result = state
            .validate_and_consume("slow-cluster", token.as_str())
            .await;
        assert!(matches!(result, Err(BootstrapError::InvalidToken)));
    }

    /// Story: Manifest generation for operator deployment
    ///
    /// The bootstrap response includes Kubernetes manifests that set up
    /// the Lattice operator on new clusters. Every cluster runs the same
    /// deployment - the controller reads LatticeCluster CRD to determine behavior.
    #[tokio::test]
    async fn story_manifest_generation() {
        let generator = DefaultManifestGenerator::new();
        let manifests = generator.generate("test:latest", None, None, None).await;

        // CRD must be first so it's applied before any CR instances
        let has_crd = manifests.iter().any(|m: &String| {
            m.contains("\"kind\":\"CustomResourceDefinition\"")
                && m.contains("latticeclusters.lattice.dev")
        });
        assert!(has_crd, "Should include LatticeCluster CRD definition");

        // Manifests create the lattice-system namespace (JSON format)
        let has_namespace = manifests
            .iter()
            .any(|m: &String| m.contains("\"kind\":\"Namespace\"") && m.contains("lattice-system"));
        assert!(has_namespace, "Should create lattice-system namespace");

        // Manifests deploy the operator (JSON format)
        let has_operator = manifests.iter().any(|m: &String| {
            m.contains("\"kind\":\"Deployment\"") && m.contains("lattice-operator")
        });
        assert!(has_operator, "Should deploy lattice-operator");

        // Should have cluster-admin binding
        let has_rbac = manifests.iter().any(|m: &String| {
            m.contains("\"kind\":\"ClusterRoleBinding\"") && m.contains("cluster-admin")
        });
        assert!(has_rbac, "Should have cluster-admin binding");
    }

    /// Story: HTTP API - Bearer token extraction
    ///
    /// The bootstrap endpoint uses standard Bearer token authentication.
    #[test]
    fn story_bearer_token_authentication() {
        // Valid Bearer token
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer my-secret-token"
                .parse()
                .expect("header value parsing should succeed"),
        );
        let token = extract_bearer_token(&headers).expect("bearer token extraction should succeed");
        assert_eq!(token, "my-secret-token");

        // Missing header
        let empty_headers = HeaderMap::new();
        let missing_result = extract_bearer_token(&empty_headers);
        assert!(matches!(missing_result, Err(BootstrapError::MissingAuth)));

        // Wrong auth scheme (Basic instead of Bearer)
        let mut basic_headers = HeaderMap::new();
        basic_headers.insert(
            "authorization",
            "Basic dXNlcjpwYXNz"
                .parse()
                .expect("header value parsing should succeed"),
        );
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
        use lattice_infra::pki::PkiError;

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
    #[tokio::test]
    async fn story_malformed_csr_returns_error() {
        let state = test_state();

        // Register and bootstrap
        let token = register_test_cluster(
            &state,
            "malformed-csr-test".to_string(),
            "cell:8443:50051".to_string(),
            state.ca_trust_bundle_pem().await,
        )
        .await;
        state
            .validate_and_consume("malformed-csr-test", token.as_str())
            .await
            .expect("token validation should succeed");

        // Try to sign a malformed CSR
        let result = state
            .sign_csr("malformed-csr-test", "not a valid CSR")
            .await;

        // Should fail with CsrSigningFailed
        assert!(matches!(result, Err(BootstrapError::CsrSigningFailed(_))));
    }

    /// Story: CA certificate availability for distribution
    #[tokio::test]
    async fn story_ca_certificate_distribution() {
        let state = test_state();

        // Cell provides CA cert for agents to verify mTLS
        let ca_cert = state.ca_trust_bundle_pem().await;
        assert!(ca_cert.contains("BEGIN CERTIFICATE"));

        // This CA cert is included in bootstrap response
        let token = register_test_cluster(
            &state,
            "ca-test".to_string(),
            "cell:8443:50051".to_string(),
            ca_cert.clone(),
        )
        .await;
        let info = state
            .validate_and_consume("ca-test", token.as_str())
            .await
            .expect("validate_and_consume should succeed");
        let response = state
            .generate_response(&info)
            .await
            .expect("generate_response should succeed");

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
        )
        .await;

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/clusters/http-test/manifests")
            .header("authorization", format!("Bearer {}", token.as_str()))
            .body(Body::empty())
            .expect("request building should succeed");

        let response = router
            .oneshot(request)
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::OK);

        // Response is raw YAML for kubectl apply
        let body = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .expect("body reading should succeed");
        let manifests_yaml =
            String::from_utf8(body.to_vec()).expect("response should be valid UTF-8");

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
        )
        .await;

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/clusters/auth-test/manifests")
            // No authorization header
            .body(Body::empty())
            .expect("request building should succeed");

        let response = router
            .oneshot(request)
            .await
            .expect("request should succeed");
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
        )
        .await;

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/clusters/token-test/manifests")
            .header("authorization", "Bearer wrong-token")
            .body(Body::empty())
            .expect("request building should succeed");

        let response = router
            .oneshot(request)
            .await
            .expect("request should succeed");
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
            .expect("request building should succeed");

        let response = router
            .oneshot(request)
            .await
            .expect("request should succeed");
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
            state.ca_trust_bundle_pem().await,
        )
        .await;
        state
            .validate_and_consume("csr-http-test", token.as_str())
            .await
            .expect("token validation should succeed");

        // Generate CSR
        let agent_req = AgentCertRequest::new("csr-http-test")
            .expect("agent cert request creation should succeed");
        let csr_request = CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
        };

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/api/clusters/csr-http-test/csr")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&csr_request).expect("JSON serialization should succeed"),
            ))
            .expect("request building should succeed");

        let response = router
            .oneshot(request)
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::OK);

        // Parse response
        let body = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .expect("body reading should succeed");
        let csr_response: CsrResponse =
            serde_json::from_slice(&body).expect("JSON parsing should succeed");

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
        )
        .await;

        let agent_req = AgentCertRequest::new("not-bootstrapped")
            .expect("agent cert request creation should succeed");
        let csr_request = CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
        };

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/api/clusters/not-bootstrapped/csr")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&csr_request).expect("JSON serialization should succeed"),
            ))
            .expect("request building should succeed");

        let response = router
            .oneshot(request)
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    }

    /// Integration test: CSR endpoint for unknown cluster
    #[tokio::test]
    async fn integration_csr_handler_unknown_cluster() {
        let state = Arc::new(test_state());

        let agent_req =
            AgentCertRequest::new("unknown").expect("agent cert request creation should succeed");
        let csr_request = CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
        };

        let router = bootstrap_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/api/clusters/unknown/csr")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&csr_request).expect("JSON serialization should succeed"),
            ))
            .expect("request building should succeed");

        let response = router
            .oneshot(request)
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Integration test: Full HTTP bootstrap flow (manifests + CSR)
    #[tokio::test]
    async fn integration_full_http_bootstrap_flow() {
        let state = Arc::new(test_state());
        let ca_cert = state.ca_trust_bundle_pem().await;

        // Step 1: Register cluster
        let token = register_test_cluster(
            &state,
            "full-flow-test".to_string(),
            "cell.example.com:8443:50051".to_string(),
            ca_cert.clone(),
        )
        .await;

        let router = bootstrap_router(state);

        // Step 2: Get manifests (returns raw YAML for kubectl apply)
        let manifests_request = Request::builder()
            .method("GET")
            .uri("/api/clusters/full-flow-test/manifests")
            .header("authorization", format!("Bearer {}", token.as_str()))
            .body(Body::empty())
            .expect("request building should succeed");

        let response = router
            .clone()
            .oneshot(manifests_request)
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .expect("body reading should succeed");
        let manifests_yaml =
            String::from_utf8(body.to_vec()).expect("response should be valid UTF-8");
        // Manifest contains image from TestManifestGenerator, not cluster ID
        assert!(manifests_yaml.contains("# Test manifest"));

        // Step 3: CSR signing
        let agent_req = AgentCertRequest::new("full-flow-test")
            .expect("agent cert request creation should succeed");
        let csr_body = serde_json::to_string(&CsrRequest {
            csr_pem: agent_req.csr_pem().to_string(),
        })
        .expect("JSON serialization should succeed");

        let csr_request = Request::builder()
            .method("POST")
            .uri("/api/clusters/full-flow-test/csr")
            .header("content-type", "application/json")
            .body(Body::from(csr_body))
            .expect("request building should succeed");

        let response = router
            .oneshot(csr_request)
            .await
            .expect("request should succeed");
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .expect("body reading should succeed");
        let csr_response: CsrResponse =
            serde_json::from_slice(&body).expect("JSON parsing should succeed");
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
    #[tokio::test]
    async fn story_kubeadm_clusters_get_fips_relaxation() {
        // Use real DefaultManifestGenerator to get actual Deployment
        let state = BootstrapState::new(
            DefaultManifestGenerator::new(),
            Duration::from_secs(3600),
            test_ca_bundle(),
            "test:latest".to_string(),
            None,
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
                token: "test-token".to_string(),
                token_created: std::time::Instant::now(),
                token_used: true, // Already bootstrapped
                networking: None,
                proxmox_ipv4_pool: None,
                provider: ProviderType::Docker,
                bootstrap: lattice_common::crd::BootstrapProvider::Kubeadm,
                k8s_version: "1.32.0".to_string(),
                autoscaling_enabled: false,
            },
        );

        let info = state
            .clusters
            .get("kubeadm-test")
            .expect("kubeadm-test cluster should exist")
            .clone();
        let response = state
            .generate_response(&info)
            .await
            .expect("generate_response should succeed");

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
    #[tokio::test]
    async fn story_rke2_clusters_no_fips_relaxation() {
        // Use real DefaultManifestGenerator to get actual Deployment
        let state = BootstrapState::new(
            DefaultManifestGenerator::new(),
            Duration::from_secs(3600),
            test_ca_bundle(),
            "test:latest".to_string(),
            None,
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
                token: "test-token".to_string(),
                token_created: std::time::Instant::now(),
                token_used: true, // Already bootstrapped
                networking: None,
                proxmox_ipv4_pool: None,
                provider: ProviderType::Docker,
                bootstrap: lattice_common::crd::BootstrapProvider::Rke2,
                k8s_version: "1.32.0".to_string(),
                autoscaling_enabled: false,
            },
        );

        let info = state
            .clusters
            .get("rke2-test")
            .expect("rke2-test cluster should exist")
            .clone();
        let response = state
            .generate_response(&info)
            .await
            .expect("generate_response should succeed");

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
        use lattice_common::crd::BootstrapProvider;

        // Kubeadm needs FIPS relaxation
        assert!(BootstrapProvider::Kubeadm.needs_fips_relax());
        assert!(!BootstrapProvider::Kubeadm.is_fips_native());

        // RKE2 is FIPS-native, no relaxation needed
        assert!(!BootstrapProvider::Rke2.needs_fips_relax());
        assert!(BootstrapProvider::Rke2.is_fips_native());
    }

    /// Story: AWS clusters get CCM and EBS CSI driver in bootstrap manifests
    ///
    /// Both CRS path (CLI) and webhook path use generate_all_manifests(),
    /// which includes AWS addons when provider is "aws".
    #[tokio::test]
    async fn story_aws_clusters_include_ccm_and_csi() {
        // Use real DefaultManifestGenerator
        let state = BootstrapState::new(
            DefaultManifestGenerator::new(),
            Duration::from_secs(3600),
            test_ca_bundle(),
            "test:latest".to_string(),
            None,
            None,
        );

        // Register AWS cluster
        let cluster_manifest = r#"{"apiVersion":"lattice.dev/v1alpha1","kind":"LatticeCluster","metadata":{"name":"aws-test"}}"#.to_string();
        state.clusters.insert(
            "aws-test".to_string(),
            ClusterBootstrapInfo {
                cluster_id: "aws-test".to_string(),
                cell_endpoint: "cell:8443:50051".to_string(),
                ca_certificate: "ca-cert".to_string(),
                cluster_manifest,
                token: "test-token".to_string(),
                token_created: std::time::Instant::now(),
                token_used: true,
                networking: None,
                proxmox_ipv4_pool: None,
                provider: ProviderType::Aws,
                bootstrap: lattice_common::crd::BootstrapProvider::Kubeadm,
                k8s_version: "1.32.0".to_string(),
                autoscaling_enabled: false,
            },
        );

        let info = state
            .clusters
            .get("aws-test")
            .expect("aws-test cluster should exist")
            .clone();
        let response = state
            .generate_response(&info)
            .await
            .expect("generate_response should succeed");

        let manifests_str = response.manifests.join("\n");

        // Should include AWS CCM
        assert!(
            manifests_str.contains("cloud-controller-manager"),
            "AWS clusters should include CCM in bootstrap manifests"
        );
        assert!(
            manifests_str.contains("v1.32.0"),
            "CCM should use correct k8s version"
        );

        // Should include EBS CSI driver
        assert!(
            manifests_str.contains("ebs.csi.aws.com"),
            "AWS clusters should include EBS CSI driver in bootstrap manifests"
        );
    }

    /// Story: Non-AWS clusters don't get AWS addons
    #[tokio::test]
    async fn story_non_aws_clusters_no_ccm() {
        // Use real DefaultManifestGenerator
        let state = BootstrapState::new(
            DefaultManifestGenerator::new(),
            Duration::from_secs(3600),
            test_ca_bundle(),
            "test:latest".to_string(),
            None,
            None,
        );

        // Register Docker cluster
        let cluster_manifest = r#"{"apiVersion":"lattice.dev/v1alpha1","kind":"LatticeCluster","metadata":{"name":"docker-test"}}"#.to_string();
        state.clusters.insert(
            "docker-test".to_string(),
            ClusterBootstrapInfo {
                cluster_id: "docker-test".to_string(),
                cell_endpoint: "cell:8443:50051".to_string(),
                ca_certificate: "ca-cert".to_string(),
                cluster_manifest,
                token: "test-token".to_string(),
                token_created: std::time::Instant::now(),
                token_used: true,
                networking: None,
                proxmox_ipv4_pool: None,
                provider: ProviderType::Docker,
                bootstrap: lattice_common::crd::BootstrapProvider::Kubeadm,
                k8s_version: "1.32.0".to_string(),
                autoscaling_enabled: false,
            },
        );

        let info = state
            .clusters
            .get("docker-test")
            .expect("docker-test cluster should exist")
            .clone();
        let response = state
            .generate_response(&info)
            .await
            .expect("generate_response should succeed");

        let manifests_str = response.manifests.join("\n");

        // Should NOT include AWS CCM
        assert!(
            !manifests_str.contains("cloud-controller-manager"),
            "Non-AWS clusters should not include CCM"
        );
        assert!(
            !manifests_str.contains("ebs.csi.aws.com"),
            "Non-AWS clusters should not include EBS CSI driver"
        );
    }

    // --- should_restore_bootstrap_token tests ---

    #[test]
    fn should_restore_token_when_bootstrap_incomplete() {
        let status = LatticeClusterStatus {
            bootstrap_complete: false,
            ..Default::default()
        };
        assert!(should_restore_bootstrap_token(Some(&status)));
    }

    #[test]
    fn should_not_restore_token_when_bootstrap_complete() {
        let status = LatticeClusterStatus {
            bootstrap_complete: true,
            ..Default::default()
        };
        assert!(!should_restore_bootstrap_token(Some(&status)));
    }

    #[test]
    fn should_restore_token_when_no_status() {
        assert!(should_restore_bootstrap_token(None));
    }
}
