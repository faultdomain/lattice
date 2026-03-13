//! Bootstrap endpoint state management
//!
//! Contains `BootstrapState` which manages cluster registrations, token
//! validation, bootstrap response generation, and CSR signing.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::Patch;
use kube::{Api, Client};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use lattice_common::crd::{LatticeCluster, ProviderType};
use lattice_common::{
    CsrResponse, LATTICE_SYSTEM_NAMESPACE, PARENT_CONFIG_CA_KEY, PARENT_CONFIG_CSR_TOKEN_KEY,
    PARENT_CONFIG_ENDPOINT_KEY, PARENT_CONFIG_SECRET,
};
use lattice_infra::pki::CertificateAuthorityBundle;

use super::bundle::generate_bootstrap_bundle;
use super::errors::BootstrapError;
use super::token::BootstrapToken;
use super::types::{
    BootstrapBundleConfig, BootstrapResponse, ClusterRegistration, ManifestGenerator,
};

/// CSR token TTL — CSR must be signed within this window after bootstrap
const CSR_TOKEN_TTL: Duration = Duration::from_secs(600);

/// Maximum number of cluster registrations to prevent unbounded memory growth.
/// A single cell managing 10k clusters would be extreme — this is a safety net.
const MAX_CLUSTER_REGISTRATIONS: usize = 10_000;

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
    /// SHA-256 hash of the bootstrap token (raw token never stored)
    pub token_hash: String,
    /// When the token was created
    pub token_created: Instant,
    /// Whether the token has been used
    pub token_used: bool,
    /// Cilium LB-IPAM CIDR (on-prem providers only)
    pub lb_cidr: Option<String>,
    /// Infrastructure provider (docker, aws, gcp, azure)
    pub provider: ProviderType,
    /// Bootstrap mechanism (kubeadm or rke2) - determines FIPS relaxation needs
    pub bootstrap: lattice_common::crd::BootstrapProvider,
    /// Kubernetes version (e.g., "1.32.0") - used for provider-specific addons like CCM
    pub k8s_version: String,
    /// Whether any worker pool has autoscaling enabled (min/max set)
    pub autoscaling_enabled: bool,
    /// SHA-256 hash of the one-time CSR token (raw token never stored)
    pub csr_token_hash: Option<String>,
    /// When the CSR token was created (for TTL enforcement)
    pub csr_token_created: Option<Instant>,
    /// Whether the CSR token has been used
    pub csr_token_used: bool,
    /// Raw CSR token (held temporarily until bootstrap response is sent, then cleared)
    pub csr_token_raw: Option<zeroize::Zeroizing<String>>,
}

/// Bootstrap endpoint state
pub struct BootstrapState<G: ManifestGenerator = super::generator::DefaultManifestGenerator> {
    /// Cluster info indexed by cluster_id
    pub(crate) clusters: DashMap<String, ClusterBootstrapInfo>,
    /// Manifest generator
    pub(crate) manifest_generator: G,
    /// Lattice image to deploy
    image: String,
    /// Registry credentials (optional)
    registry_credentials: Option<String>,
    /// Token TTL
    token_ttl: Duration,
    /// Certificate authority bundle for signing CSRs (supports rotation)
    ca_bundle: Arc<RwLock<CertificateAuthorityBundle>>,
    /// Kubernetes client for updating CRD status and fetching distributed resources (None in tests)
    pub(crate) kube_client: Option<Client>,
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

    /// Register a cluster for bootstrap.
    ///
    /// Creates a bootstrap token and stores the registration in memory.
    /// The token is persisted to LatticeCluster.status.bootstrap_token by the
    /// controller, making it atomic with the cluster and moving with it during pivot.
    ///
    /// This method is idempotent — if the cluster is already registered in memory,
    /// it returns the existing token.
    ///
    /// Pass `existing_token` to reuse a token from a previous session (recovery).
    /// Pass `recovery_csr_hash` to restore a persisted CSR token hash (H4 restart survival).
    ///
    /// Uses DashMap's `entry` API to atomically check-and-insert, eliminating
    /// the TOCTOU race between get() and insert() that could destroy a CSR
    /// token if a concurrent operation removes the entry between the two calls.
    pub async fn register_cluster(
        &self,
        registration: ClusterRegistration,
        existing_token: Option<&str>,
        recovery_csr_hash: Option<String>,
    ) -> BootstrapToken {
        let cluster_id = registration.cluster_id.clone();

        // Evict fully-consumed registrations when approaching capacity
        if self.clusters.len() >= MAX_CLUSTER_REGISTRATIONS {
            let to_evict: Vec<String> = self
                .clusters
                .iter()
                .filter(|e| e.token_used && e.csr_token_used)
                .map(|e| e.key().clone())
                .collect();
            for key in to_evict {
                self.clusters.remove(&key);
            }
            if self.clusters.len() >= MAX_CLUSTER_REGISTRATIONS {
                warn!(
                    capacity = MAX_CLUSTER_REGISTRATIONS,
                    "Bootstrap cluster registrations at capacity, evicting oldest unused"
                );
                if let Some(entry) = self.clusters.iter().next() {
                    self.clusters.remove(entry.key());
                }
            }
        }

        // Atomic check-and-insert using entry API — holds write lock for the
        // duration, preventing concurrent removal between check and insert.
        let entry = self.clusters.entry(cluster_id.clone());
        match entry {
            dashmap::Entry::Occupied(mut existing) => {
                // Cluster already registered — generate a fresh token and update
                // the stored hash so re-registration is idempotent. This handles
                // controller re-reconciliation and operator restart recovery.
                debug!(cluster = %cluster_id, "Cluster already registered (in memory), rotating token");
                let token = match existing_token {
                    Some(t) => BootstrapToken::from_string(t).unwrap_or_else(|_| {
                        warn!(cluster = %cluster_id, "Invalid existing token, generating new one");
                        BootstrapToken::generate()
                    }),
                    None => BootstrapToken::generate(),
                };
                let info = existing.get_mut();
                if !info.token_used {
                    info.token_hash = token.hash();
                    info.token_created = Instant::now();
                }
                token
            }
            dashmap::Entry::Vacant(vacant) => {
                let token = match existing_token {
                    Some(t) => BootstrapToken::from_string(t).unwrap_or_else(|_| {
                        warn!(cluster = %cluster_id, "Invalid existing token, generating new one");
                        BootstrapToken::generate()
                    }),
                    None => BootstrapToken::generate(),
                };

                // If recovering with a CSR hash, mark bootstrap token as already used
                let token_used = recovery_csr_hash.is_some();

                let info = ClusterBootstrapInfo {
                    cluster_id: cluster_id.clone(),
                    cell_endpoint: registration.cell_endpoint,
                    ca_certificate: registration.ca_certificate,
                    cluster_manifest: registration.cluster_manifest,
                    token_hash: token.hash(),
                    token_created: Instant::now(),
                    token_used,
                    lb_cidr: registration.lb_cidr,
                    provider: registration.provider,
                    bootstrap: registration.bootstrap,
                    k8s_version: registration.k8s_version,
                    autoscaling_enabled: registration.autoscaling_enabled,
                    csr_token_hash: recovery_csr_hash,
                    csr_token_created: if token_used { Some(Instant::now()) } else { None },
                    csr_token_used: false,
                    csr_token_raw: None,
                };

                vacant.insert(info);
                token
            }
        }
    }

    /// Validate and consume a bootstrap token
    ///
    /// Uses atomic check-and-mark via DashMap::get_mut to prevent TOCTOU races
    /// where two concurrent requests could both pass validation before either
    /// marks the token as consumed.
    ///
    /// This updates the CRD status to set bootstrap_complete=true after atomically
    /// marking the token as used, ensuring the status is persisted even if the
    /// operator restarts.
    pub async fn validate_and_consume(
        &self,
        cluster_id: &str,
        token: &str,
    ) -> Result<ClusterBootstrapInfo, BootstrapError> {
        use subtle::ConstantTimeEq;

        // Atomically validate AND mark as used while holding the mutable reference.
        // This eliminates the TOCTOU window between check and consumption.
        let (info, csr_token_hash) = {
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

            // Parse the provided token and compute its hash for comparison
            let provided_token = BootstrapToken::from_string(token)
                .map_err(|_| BootstrapError::InvalidToken)?;
            let provided_hash = provided_token.hash();

            // Constant-time hash comparison to prevent timing side-channel attacks.
            // We compare hashes (not raw tokens) because raw tokens are never stored.
            // Both hashes are SHA-256 → base64url-no-pad (always 43 bytes). Assert
            // equal length to guarantee ct_eq doesn't short-circuit on length mismatch.
            if provided_hash.len() != info.token_hash.len()
                || provided_hash.as_bytes().ct_eq(info.token_hash.as_bytes()).unwrap_u8() != 1
            {
                return Err(BootstrapError::InvalidToken);
            }

            // Mark as used WHILE still holding the lock — prevents concurrent use
            info.token_used = true;

            // Generate a one-time CSR token for authenticating the subsequent CSR request.
            // Store only the hash; the raw token is held temporarily for the response.
            let csr_token = BootstrapToken::generate();
            let csr_hash = csr_token.hash();
            info.csr_token_hash = Some(csr_hash.clone());
            info.csr_token_created = Some(Instant::now());
            info.csr_token_raw = Some(zeroize::Zeroizing::new(csr_token.as_str().to_string()));

            (info.clone(), csr_hash)
        };

        // Persist bootstrap_complete AND csr_token_hash to CRD status.
        // This ensures the CSR token survives operator restarts (H4) and
        // makes consumption atomic with persistence (L1).
        if let Err(e) = self.persist_bootstrap_status(cluster_id, &csr_token_hash).await {
            warn!(cluster_id = %cluster_id, error = %e, "Failed to persist bootstrap status to CRD");
        }

        Ok(info)
    }

    /// Persist bootstrap_complete and csr_token_hash to the cluster's CRD status
    ///
    /// Persisting the CSR token hash ensures it survives operator restarts (H4)
    /// and makes token consumption atomic with persistence (L1).
    async fn persist_bootstrap_status(&self, cluster_id: &str, csr_token_hash: &str) -> Result<(), kube::Error> {
        let Some(ref client) = self.kube_client else {
            // No client (tests) - skip CRD update
            return Ok(());
        };

        let api: Api<LatticeCluster> = Api::all(client.clone());

        // Get current cluster to preserve existing status
        let cluster = api.get(cluster_id).await?;
        let mut status = cluster.status.unwrap_or_default();
        status.bootstrap_complete = true;
        status.csr_token_hash = Some(csr_token_hash.to_string());
        // Clear the raw bootstrap token now that it's been consumed.
        // This minimizes the exposure window — the token was only needed
        // in CRD status for operator restart recovery before consumption.
        status.bootstrap_token = None;

        let patch = serde_json::json!({
            "status": status
        });

        api.patch_status(
            cluster_id,
            &kube::api::PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await?;

        info!(cluster_id = %cluster_id, "Persisted bootstrap_complete and csr_token_hash to CRD status");
        Ok(())
    }

    /// Generate bootstrap response for a cluster
    ///
    /// Calls [`generate_bootstrap_bundle`] and adds the parent connection config
    /// Secret (webhook-specific). See [`BootstrapBundleConfig`] for what's included.
    pub async fn generate_response(
        &self,
        info: &ClusterBootstrapInfo,
    ) -> Result<BootstrapResponse, BootstrapError> {
        // Use the child's latticeImage from its cluster manifest if available,
        // falling back to the parent's image if not present.
        let child_image = serde_json::from_str::<serde_json::Value>(&info.cluster_manifest)
            .ok()
            .and_then(|v| v["spec"]["latticeImage"].as_str().map(String::from));
        let bootstrap_image = child_image.as_deref().unwrap_or(&self.image);

        // Generate the complete bootstrap bundle (operator, CNI, addons, LatticeCluster)
        let bundle_config = BootstrapBundleConfig {
            image: bootstrap_image,
            registry_credentials: self.registry_credentials.as_deref(),
            lb_cidr: info.lb_cidr.as_deref(),
            cluster_name: &info.cluster_id,
            provider: info.provider,
            k8s_version: &info.k8s_version,
            autoscaling_enabled: info.autoscaling_enabled,
            cluster_manifest: &info.cluster_manifest,
        };
        let mut manifests =
            generate_bootstrap_bundle(&self.manifest_generator, &bundle_config).await?;

        // Add parent connection config Secret (webhook-specific, not needed for installer)
        let mut parent_config_data = BTreeMap::from([
            (
                PARENT_CONFIG_ENDPOINT_KEY.to_string(),
                info.cell_endpoint.clone(),
            ),
            (
                PARENT_CONFIG_CA_KEY.to_string(),
                info.ca_certificate.clone(),
            ),
        ]);

        // Include the CSR token so the agent can authenticate its CSR request
        if let Some(ref csr_token) = info.csr_token_raw {
            parent_config_data.insert(
                PARENT_CONFIG_CSR_TOKEN_KEY.to_string(),
                csr_token.as_str().to_string(),
            );
        }

        let parent_config = Secret {
            metadata: ObjectMeta {
                name: Some(PARENT_CONFIG_SECRET.to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                ..Default::default()
            },
            type_: Some("Opaque".to_string()),
            string_data: Some(parent_config_data),
            ..Default::default()
        };
        manifests.push(serde_json::to_string(&parent_config).map_err(|e| {
            BootstrapError::Internal(format!("failed to serialize parent config Secret: {}", e))
        })?);

        // Note: InfraProvider and SecretProvider resources (with their referenced secrets)
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
    /// Requires a valid one-time CSR token that was issued during bootstrap.
    /// This ensures only the agent that consumed the bootstrap token can get a certificate.
    pub async fn sign_csr(
        &self,
        cluster_id: &str,
        csr_pem: &str,
        csr_token: &str,
    ) -> Result<CsrResponse, BootstrapError> {
        use subtle::ConstantTimeEq;

        // Atomically validate AND consume the CSR token
        {
            let mut entry = self
                .clusters
                .get_mut(cluster_id)
                .ok_or_else(|| BootstrapError::ClusterNotFound(cluster_id.to_string()))?;

            let info = entry.value_mut();

            // Must have completed bootstrap (token consumed)
            if !info.token_used {
                return Err(BootstrapError::ClusterNotBootstrapped(
                    cluster_id.to_string(),
                ));
            }

            // CSR token hash must exist (generated during validate_and_consume)
            let expected_hash = info
                .csr_token_hash
                .as_ref()
                .ok_or(BootstrapError::InvalidCsrToken)?;

            // CSR token must not already be used
            if info.csr_token_used {
                return Err(BootstrapError::CsrTokenAlreadyUsed);
            }

            // Check CSR token TTL
            if let Some(created) = info.csr_token_created {
                if created.elapsed() > CSR_TOKEN_TTL {
                    return Err(BootstrapError::InvalidCsrToken);
                }
            }

            // Parse the provided CSR token and compute its hash
            let provided_token = BootstrapToken::from_string(csr_token)
                .map_err(|_| BootstrapError::InvalidCsrToken)?;
            let provided_hash = provided_token.hash();

            // Constant-time hash comparison with explicit length check
            if provided_hash.len() != expected_hash.len()
                || provided_hash
                    .as_bytes()
                    .ct_eq(expected_hash.as_bytes())
                    .unwrap_u8()
                    != 1
            {
                return Err(BootstrapError::InvalidCsrToken);
            }

            // Mark as consumed
            info.csr_token_used = true;
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

}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_infra::pki::AgentCertRequest;
    use x509_parser::prelude::FromDer;

    use super::super::test_helpers::*;

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

    /// Helper: extract raw CSR token from cluster info after bootstrap
    fn csr_token_from_info(info: &ClusterBootstrapInfo) -> &str {
        info.csr_token_raw
            .as_ref()
            .expect("CSR token should be set after bootstrap")
            .as_str()
    }

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
            .sign_csr("not-bootstrapped", agent_req.csr_pem(), "dummy-token")
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
        let result = state
            .sign_csr("unknown", agent_req.csr_pem(), "dummy-token")
            .await;

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
        let info = state
            .validate_and_consume("csr-test", token.as_str())
            .await
            .expect("token validation should succeed");
        let csr_tok = csr_token_from_info(&info);

        // Now CSR signing should work
        let agent_req =
            AgentCertRequest::new("csr-test").expect("agent cert request creation should succeed");
        let result = state
            .sign_csr("csr-test", agent_req.csr_pem(), csr_tok)
            .await;

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
        let info = state
            .validate_and_consume("cluster-xyz", token.as_str())
            .await
            .expect("token validation should succeed");
        let csr_tok = csr_token_from_info(&info);

        // Sign CSR
        let agent_req = AgentCertRequest::new("cluster-xyz")
            .expect("agent cert request creation should succeed");
        let response = state
            .sign_csr("cluster-xyz", agent_req.csr_pem(), csr_tok)
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

    /// Story: Complete bootstrap flow from registration to certificate
    ///
    /// This test demonstrates the entire bootstrap sequence as experienced
    /// by a newly provisioned workload cluster connecting to its parent cell.
    #[tokio::test]
    async fn complete_bootstrap_flow() {
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

        // The CSR token was generated during bootstrap and delivered via the parent config Secret
        let csr_tok = csr_token_from_info(&info);

        // Chapter 5: Cell signs the CSR (authenticated by one-time CSR token)
        // ------------------------------
        let csr_response = state
            .sign_csr("prod-us-west-001", agent_request.csr_pem(), csr_tok)
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
    async fn token_replay_attack_prevention() {
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
    async fn invalid_token_rejection() {
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
    async fn csr_requires_bootstrap_completion() {
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
            .sign_csr("premature-cluster", agent_request.csr_pem(), "dummy-token")
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
    async fn unknown_cluster_rejection() {
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
            .sign_csr("hacker-cluster", agent_request.csr_pem(), "dummy-token")
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
    async fn expired_token_rejection() {
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

    /// Story: CSR signing with malformed CSR returns proper error
    ///
    /// When an agent submits an invalid CSR (not proper PEM format),
    /// the signing should fail with a descriptive error.
    #[tokio::test]
    async fn malformed_csr_returns_error() {
        let state = test_state();

        // Register and bootstrap
        let token = register_test_cluster(
            &state,
            "malformed-csr-test".to_string(),
            "cell:8443:50051".to_string(),
            state.ca_trust_bundle_pem().await,
        )
        .await;
        let info = state
            .validate_and_consume("malformed-csr-test", token.as_str())
            .await
            .expect("token validation should succeed");
        let csr_tok = csr_token_from_info(&info);

        // Try to sign a malformed CSR
        let result = state
            .sign_csr("malformed-csr-test", "not a valid CSR", csr_tok)
            .await;

        // Should fail with CsrSigningFailed
        assert!(matches!(result, Err(BootstrapError::CsrSigningFailed(_))));
    }

    /// Story: Security - CSR token replay is prevented
    ///
    /// The CSR token is one-time use. An attacker who observes the token
    /// cannot use it to get a second certificate.
    #[tokio::test]
    async fn csr_token_replay_prevention() {
        let state = test_state();
        let ca_cert = state.ca_trust_bundle_pem().await;

        let token = register_test_cluster(
            &state,
            "csr-replay".to_string(),
            "cell:8443:50051".to_string(),
            ca_cert,
        )
        .await;
        let info = state
            .validate_and_consume("csr-replay", token.as_str())
            .await
            .expect("bootstrap should succeed");
        let csr_tok = csr_token_from_info(&info);

        // First CSR signing succeeds
        let agent_req = AgentCertRequest::new("csr-replay")
            .expect("agent cert request creation should succeed");
        state
            .sign_csr("csr-replay", agent_req.csr_pem(), csr_tok)
            .await
            .expect("first CSR signing should succeed");

        // Second attempt with same token fails
        let agent_req2 = AgentCertRequest::new("csr-replay")
            .expect("agent cert request creation should succeed");
        let result = state
            .sign_csr("csr-replay", agent_req2.csr_pem(), csr_tok)
            .await;
        assert!(matches!(result, Err(BootstrapError::CsrTokenAlreadyUsed)));
    }

    /// Story: Security - Wrong CSR token is rejected
    ///
    /// An attacker who knows the cluster ID but not the CSR token cannot
    /// get a certificate signed.
    #[tokio::test]
    async fn wrong_csr_token_rejected() {
        let state = test_state();
        let ca_cert = state.ca_trust_bundle_pem().await;

        let token = register_test_cluster(
            &state,
            "wrong-csr-tok".to_string(),
            "cell:8443:50051".to_string(),
            ca_cert,
        )
        .await;
        state
            .validate_and_consume("wrong-csr-tok", token.as_str())
            .await
            .expect("bootstrap should succeed");

        let agent_req = AgentCertRequest::new("wrong-csr-tok")
            .expect("agent cert request creation should succeed");
        let result = state
            .sign_csr("wrong-csr-tok", agent_req.csr_pem(), "attacker-guessed-token")
            .await;
        assert!(matches!(result, Err(BootstrapError::InvalidCsrToken)));
    }

    /// Story: CA certificate availability for distribution
    #[tokio::test]
    async fn ca_certificate_distribution() {
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

    /// Story: AWS clusters get CCM and EBS CSI driver in bootstrap manifests
    ///
    /// Both CRS path (CLI) and webhook path use generate_bootstrap_bundle(),
    /// which includes AWS addons when provider is "aws".
    #[tokio::test]
    async fn aws_clusters_include_ccm_and_csi() {
        use super::super::generator::DefaultManifestGenerator;

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
                token_hash: "test-token-hash".to_string(),
                token_created: std::time::Instant::now(),
                token_used: true,
                lb_cidr: None,

                provider: ProviderType::Aws,
                bootstrap: lattice_common::crd::BootstrapProvider::Kubeadm,
                k8s_version: "1.32.0".to_string(),
                autoscaling_enabled: false,
                csr_token_hash: None,
                csr_token_created: None,
                csr_token_used: false,
                csr_token_raw: None,
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
    async fn non_aws_clusters_no_ccm() {
        use super::super::generator::DefaultManifestGenerator;

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
                token_hash: "test-token-hash".to_string(),
                token_created: std::time::Instant::now(),
                token_used: true,
                lb_cidr: None,

                provider: ProviderType::Docker,
                bootstrap: lattice_common::crd::BootstrapProvider::Kubeadm,
                k8s_version: "1.32.0".to_string(),
                autoscaling_enabled: false,
                csr_token_hash: None,
                csr_token_created: None,
                csr_token_used: false,
                csr_token_raw: None,
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
        // Check for the actual CSI driver resource name (JSON-serialized), not
        // incidental mentions in helm chart descriptions (e.g. KEDA's CSIMigration docs)
        assert!(
            !manifests_str.contains("\"ebs.csi.aws.com\""),
            "Non-AWS clusters should not include EBS CSI driver"
        );
    }
}
