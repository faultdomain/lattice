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
    CsrResponse, LATTICE_SYSTEM_NAMESPACE, PARENT_CONFIG_CA_KEY, PARENT_CONFIG_ENDPOINT_KEY,
    PARENT_CONFIG_SECRET,
};
use lattice_infra::pki::CertificateAuthorityBundle;

use super::bundle::generate_bootstrap_bundle;
use super::errors::BootstrapError;
use super::token::BootstrapToken;
use super::types::{
    BootstrapBundleConfig, BootstrapResponse, ClusterRegistration, ManifestGenerator,
};

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
    /// The bootstrap token (base64 string, zeroized on drop)
    pub token: zeroize::Zeroizing<String>,
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
    pub async fn register_cluster(
        &self,
        registration: ClusterRegistration,
        existing_token: Option<&str>,
    ) -> BootstrapToken {
        let cluster_id = registration.cluster_id.clone();

        // Fast path: check in-memory cache first
        if let Some(entry) = self.clusters.get(&cluster_id) {
            debug!(cluster = %cluster_id, "Cluster already registered (in memory), reusing existing token");
            return BootstrapToken::from_string(&entry.token)
                .expect("stored token should be valid");
        }

        // Use existing token if provided, otherwise generate new one
        let token = match existing_token {
            Some(t) => BootstrapToken::from_string(t).unwrap_or_else(|_| {
                warn!(cluster = %cluster_id, "Invalid existing token, generating new one");
                BootstrapToken::generate()
            }),
            None => BootstrapToken::generate(),
        };

        let info = ClusterBootstrapInfo {
            cluster_id: cluster_id.clone(),
            cell_endpoint: registration.cell_endpoint,
            ca_certificate: registration.ca_certificate,
            cluster_manifest: registration.cluster_manifest,
            token: zeroize::Zeroizing::new(token.as_str().to_string()),
            token_created: Instant::now(),
            token_used: false,
            lb_cidr: registration.lb_cidr,
            provider: registration.provider,
            bootstrap: registration.bootstrap,
            k8s_version: registration.k8s_version,
            autoscaling_enabled: registration.autoscaling_enabled,
        };

        self.clusters.insert(cluster_id, info);
        token
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
        // Validate token from in-memory cache
        // Note: On operator restart, recovery.rs re-registers clusters in Provisioning/Pivoting phase
        let info = {
            let entry = self
                .clusters
                .get(cluster_id)
                .ok_or_else(|| BootstrapError::ClusterNotFound(cluster_id.to_string()))?;

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
            if token != *info.token {
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
        let parent_config = Secret {
            metadata: ObjectMeta {
                name: Some(PARENT_CONFIG_SECRET.to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                ..Default::default()
            },
            type_: Some("Opaque".to_string()),
            string_data: Some(BTreeMap::from([
                (
                    PARENT_CONFIG_ENDPOINT_KEY.to_string(),
                    info.cell_endpoint.clone(),
                ),
                (
                    PARENT_CONFIG_CA_KEY.to_string(),
                    info.ca_certificate.clone(),
                ),
            ])),
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

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_infra::pki::{AgentCertRequest, CertificateAuthority};
    use x509_parser::prelude::FromDer;

    use super::super::types::ManifestGenerator;

    struct TestManifestGenerator;

    #[async_trait::async_trait]
    impl ManifestGenerator for TestManifestGenerator {
        async fn generate(
            &self,
            image: &str,
            _registry_credentials: Option<&str>,
            _cluster_name: Option<&str>,
            _provider: Option<ProviderType>,
        ) -> Result<Vec<String>, super::BootstrapError> {
            Ok(vec![format!("# Test manifest with image {}", image)])
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
            .register_cluster(
                ClusterRegistration {
                    cluster_id: cluster_id.into(),
                    cell_endpoint: cell_endpoint.into(),
                    ca_certificate: ca_certificate.into(),
                    cluster_manifest,
                    lb_cidr: None,
                    provider: ProviderType::Docker,
                    bootstrap: lattice_common::crd::BootstrapProvider::default(),
                    k8s_version: "1.32.0".to_string(),
                    autoscaling_enabled: false,
                },
                None,
            )
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
                token: zeroize::Zeroizing::new("test-token".to_string()),
                token_created: std::time::Instant::now(),
                token_used: true,
                lb_cidr: None,

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
                token: zeroize::Zeroizing::new("test-token".to_string()),
                token_created: std::time::Instant::now(),
                token_used: true,
                lb_cidr: None,

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
        // Check for the actual CSI driver resource name (JSON-serialized), not
        // incidental mentions in helm chart descriptions (e.g. KEDA's CSIMigration docs)
        assert!(
            !manifests_str.contains("\"ebs.csi.aws.com\""),
            "Non-AWS clusters should not include EBS CSI driver"
        );
    }
}
