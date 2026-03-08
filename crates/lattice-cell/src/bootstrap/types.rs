//! Bootstrap type definitions
//!
//! Core types for the bootstrap protocol: responses, registrations,
//! manifest generator trait, and bundle configuration.

use lattice_common::crd::ProviderType;
use serde::{Deserialize, Serialize};

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
    /// Cilium LB-IPAM CIDR (on-prem providers only, e.g., "172.18.255.0/28")
    pub lb_cidr: Option<String>,
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
    /// Generate CNI and operator manifests for a cluster
    ///
    /// Returns Cilium CNI manifests and operator deployment (namespace, RBAC,
    /// ServiceAccount, Deployment). Called by `generate_bootstrap_bundle()` which
    /// adds LB-IPAM, provider addons, and LatticeCluster CRD/instance on top.
    ///
    /// This is an async function to avoid blocking the tokio runtime during
    /// helm template execution for Cilium manifests.
    async fn generate(
        &self,
        image: &str,
        registry_credentials: Option<&str>,
        cluster_name: Option<&str>,
        provider: Option<ProviderType>,
    ) -> Result<Vec<String>, super::errors::BootstrapError>;
}

/// Configuration for generating a complete bootstrap bundle
///
/// The bootstrap bundle includes only what's essential for the cluster to start:
/// - CNI (Cilium)
/// - Operator deployment + namespace + RBAC
/// - LB-IPAM resources (if configured)
/// - Provider addons (CCM, CSI, local-path-provisioner, cluster-autoscaler)
/// - LatticeCluster CRD definition + instance
///
/// Infrastructure components (Istio, ESO, Velero, VictoriaMetrics, KEDA, GPU stack)
/// are deferred to operator startup via `ensure_infrastructure()`.
#[derive(Debug, Clone)]
pub struct BootstrapBundleConfig<'a> {
    /// Container image for the operator
    pub image: &'a str,
    /// Optional registry credentials (image pull secret)
    pub registry_credentials: Option<&'a str>,
    /// Cilium LB-IPAM CIDR (on-prem providers only, e.g., "172.18.255.0/28")
    pub lb_cidr: Option<&'a str>,
    /// Cluster name
    pub cluster_name: &'a str,
    /// Provider type
    pub provider: ProviderType,
    /// Kubernetes version (e.g., "1.32.0")
    pub k8s_version: &'a str,
    /// Whether cluster has autoscaling-enabled pools
    pub autoscaling_enabled: bool,
    /// The LatticeCluster manifest (JSON or YAML) to include
    pub cluster_manifest: &'a str,
}
