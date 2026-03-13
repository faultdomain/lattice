//! Shared test helpers for bootstrap module tests.
#![cfg(test)]

use std::sync::Arc;
use std::time::Duration;

use lattice_common::crd::ProviderType;
use lattice_infra::pki::{CertificateAuthority, CertificateAuthorityBundle};
use tokio::sync::RwLock;

use super::errors::BootstrapError;
use super::state::BootstrapState;
use super::token::BootstrapToken;
use super::types::{ClusterRegistration, ManifestGenerator};

pub struct TestManifestGenerator;

#[async_trait::async_trait]
impl ManifestGenerator for TestManifestGenerator {
    async fn generate(
        &self,
        image: &str,
        _registry_credentials: Option<&str>,
        _cluster_name: Option<&str>,
        _provider: Option<ProviderType>,
    ) -> Result<Vec<String>, BootstrapError> {
        Ok(vec![format!("# Test manifest with image {}", image)])
    }
}

pub fn test_ca_bundle() -> Arc<RwLock<CertificateAuthorityBundle>> {
    let ca = CertificateAuthority::new("Test CA").expect("test CA creation should succeed");
    Arc::new(RwLock::new(CertificateAuthorityBundle::new(ca)))
}

pub fn test_state() -> BootstrapState<TestManifestGenerator> {
    BootstrapState::new(
        TestManifestGenerator,
        Duration::from_secs(3600),
        test_ca_bundle(),
        "test:latest".to_string(),
        None,
        None,
    )
}

pub fn test_state_with_ttl(ttl: Duration) -> BootstrapState<TestManifestGenerator> {
    BootstrapState::new(
        TestManifestGenerator,
        ttl,
        test_ca_bundle(),
        "test:latest".to_string(),
        None,
        None,
    )
}

pub async fn register_test_cluster<G: ManifestGenerator>(
    state: &BootstrapState<G>,
    cluster_id: impl Into<String>,
    cell_endpoint: impl Into<String>,
    ca_certificate: impl Into<String>,
) -> BootstrapToken {
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
