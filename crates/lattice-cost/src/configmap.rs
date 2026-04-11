//! ConfigMap-backed cost provider.
//!
//! Reads rates from the `lattice-resource-rates` ConfigMap in `lattice-system`.
//! On-prem operators populate this manually; cloud users can auto-populate it
//! with the same schema via a separate controller (future work).
//!
//! Rates are cached with a TTL to avoid hitting the K8s API on every reconcile.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::Api;
use tokio::sync::watch;

use lattice_core::LATTICE_SYSTEM_NAMESPACE;

use crate::error::CostError;
use crate::rates::CostRates;
use crate::CostProvider;

const CONFIGMAP_NAME: &str = "lattice-resource-rates";
const DATA_KEY: &str = "rates.yaml";
const CACHE_TTL: Duration = Duration::from_secs(60);

/// Loads cost rates from a ConfigMap in `lattice-system`.
///
/// Caches parsed rates for 60s to avoid redundant API calls across reconciles.
pub struct ConfigMapCostProvider {
    client: kube::Client,
    cache: watch::Sender<Option<(CostRates, Instant)>>,
}

impl ConfigMapCostProvider {
    /// Create a new provider that reads from the `lattice-resource-rates` ConfigMap.
    pub fn new(client: kube::Client) -> Self {
        let (tx, _) = watch::channel(None);
        Self { client, cache: tx }
    }
}

#[async_trait]
impl CostProvider for ConfigMapCostProvider {
    async fn load_rates(&self) -> Result<CostRates, CostError> {
        if let Some((rates, fetched_at)) = self.cache.borrow().as_ref() {
            if fetched_at.elapsed() < CACHE_TTL {
                return Ok(rates.clone());
            }
        }

        let cm_api: Api<ConfigMap> = Api::namespaced(self.client.clone(), LATTICE_SYSTEM_NAMESPACE);

        let cm = cm_api
            .get(CONFIGMAP_NAME)
            .await
            .map_err(|e| CostError::ConfigMapNotFound(e.to_string()))?;

        let yaml_str = cm
            .data
            .as_ref()
            .and_then(|d| d.get(DATA_KEY))
            .ok_or_else(|| {
                CostError::InvalidFormat(format!(
                    "missing '{DATA_KEY}' key in ConfigMap '{CONFIGMAP_NAME}'"
                ))
            })?;

        let rates: CostRates =
            serde_yaml::from_str(yaml_str).map_err(|e| CostError::InvalidFormat(e.to_string()))?;

        let _ = self.cache.send(Some((rates.clone(), Instant::now())));
        Ok(rates)
    }
}
