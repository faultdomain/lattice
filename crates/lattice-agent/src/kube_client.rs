//! Kubernetes client provider for dependency injection
//!
//! Provides trait-based access to kube::Client creation,
//! enabling dependency injection and mocking for tests.

use lattice_common::kube_utils::{DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT};

/// Trait for creating Kubernetes clients
///
/// This abstracts kube::Client creation, enabling proper unit testing
/// without requiring a real Kubernetes cluster.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait KubeClientProvider: Send + Sync {
    /// Create a new Kubernetes client
    async fn create(&self) -> Result<kube::Client, kube::Error>;
}

/// Default implementation that creates clients from in-cluster config
#[derive(Clone, Default)]
pub struct InClusterClientProvider;

#[async_trait::async_trait]
impl KubeClientProvider for InClusterClientProvider {
    async fn create(&self) -> Result<kube::Client, kube::Error> {
        let mut config = kube::Config::infer()
            .await
            .map_err(kube::Error::InferConfig)?;
        config.connect_timeout = Some(DEFAULT_CONNECT_TIMEOUT);
        config.read_timeout = Some(DEFAULT_READ_TIMEOUT);
        kube::Client::try_from(config)
    }
}

/// Create a Kubernetes client with logging, returning None on failure.
///
/// Helper for cases where client creation failure should be logged and handled
/// gracefully rather than propagated as an error.
pub async fn create_client_logged(
    provider: &dyn KubeClientProvider,
    purpose: &str,
) -> Option<kube::Client> {
    match provider.create().await {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to create K8s client for {}", purpose);
            None
        }
    }
}

// Tests for actual logic that uses KubeClientProvider would go here.
// The mock is meant to be used by other modules testing their logic,
// not for testing the mock itself.
