//! Observability configuration for Lattice workloads
//!
//! Provides declarative metric mappings: users declare which Prometheus metric
//! maps to which well-known concept via raw PromQL queries. Controllers execute
//! queries against VictoriaMetrics and write scalar results to CRD status.

use std::collections::BTreeMap;

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Top-level observability configuration for a workload.
///
/// Placed at the spec level of each workload CRD (LatticeService, LatticeModel, LatticeJob).
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ObservabilitySpec {
    /// Metrics scraping and mapping configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsConfig>,
}

/// Metrics configuration: port override and PromQL mappings.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MetricsConfig {
    /// Well-known key to PromQL query template mappings.
    ///
    /// Use `$SELECTORS` for auto-injected label selectors (`namespace` + pod regex).
    /// The controller substitutes `$SELECTORS`, executes the query against VictoriaMetrics,
    /// and writes the scalar result to `status.metrics.values[key]`.
    ///
    /// Example:
    ///   `loss: "avg(training_loss{$SELECTORS})"`
    ///   `throughput: "sum(rate(http_requests_total{$SELECTORS}[1m]))"`
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub mappings: BTreeMap<String, String>,

    /// Explicit metrics port name override.
    ///
    /// Default: auto-detect port named `"metrics"` in `service.ports`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
}

/// A point-in-time snapshot of scraped metric values, written to CRD status.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MetricsSnapshot {
    /// Well-known key to scalar result from the PromQL query.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub values: BTreeMap<String, f64>,
}

impl MetricsConfig {
    /// Returns true if there are any metric mappings defined.
    pub fn has_mappings(&self) -> bool {
        !self.mappings.is_empty()
    }
}

/// Trait for scraping metrics from VictoriaMetrics.
///
/// Implemented by the operator binary; consumed by model/job/service controllers
/// via `Arc<dyn MetricsScraper>`.
#[async_trait]
pub trait MetricsScraper: Send + Sync {
    /// Execute each mapping's PromQL query against VM and return scalar results.
    ///
    /// `$SELECTORS` in query templates is substituted with namespace + pod regex.
    /// Failures are per-key (partial success OK).
    async fn scrape(
        &self,
        mappings: &BTreeMap<String, String>,
        namespace: &str,
        workload_name: &str,
    ) -> MetricsSnapshot;
}

/// No-op implementation for tests — returns empty snapshots.
pub struct NoopMetricsScraper;

#[async_trait]
impl MetricsScraper for NoopMetricsScraper {
    async fn scrape(
        &self,
        _mappings: &BTreeMap<String, String>,
        _namespace: &str,
        _workload_name: &str,
    ) -> MetricsSnapshot {
        MetricsSnapshot::default()
    }
}

/// Scrape metrics and resolve against existing status.
///
/// Returns the metrics snapshot to use in the next status write:
/// - `None` if no mappings are configured (preserves existing status)
/// - The existing snapshot if scrape returned identical values (avoids spurious writes)
/// - The new snapshot if values changed
///
/// Shared by all workload controllers — this is the single scrape entry point.
pub async fn scrape_metrics(
    scraper: &dyn MetricsScraper,
    observability: Option<&ObservabilitySpec>,
    namespace: &str,
    workload_name: &str,
    existing: Option<&MetricsSnapshot>,
) -> Option<MetricsSnapshot> {
    let metrics_config = observability?.metrics.as_ref()?;
    if !metrics_config.has_mappings() {
        return None;
    }
    let snapshot = scraper
        .scrape(&metrics_config.mappings, namespace, workload_name)
        .await;
    if Some(&snapshot) == existing {
        existing.cloned()
    } else {
        Some(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip_full() {
        let spec = ObservabilitySpec {
            metrics: Some(MetricsConfig {
                mappings: BTreeMap::from([
                    (
                        "loss".to_string(),
                        "avg(training_loss{$SELECTORS})".to_string(),
                    ),
                    (
                        "throughput".to_string(),
                        "sum(rate(samples_total{$SELECTORS}[1m]))".to_string(),
                    ),
                ]),
                port: Some("prom".to_string()),
            }),
        };
        let json = serde_json::to_string(&spec).unwrap();
        let deserialized: ObservabilitySpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, deserialized);
    }

    #[test]
    fn serde_round_trip_empty() {
        let spec = ObservabilitySpec::default();
        let json = serde_json::to_string(&spec).unwrap();
        assert_eq!(json, "{}");
        let deserialized: ObservabilitySpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, deserialized);
    }

    #[test]
    fn serde_round_trip_snapshot() {
        let snapshot = MetricsSnapshot {
            values: BTreeMap::from([("loss".to_string(), 0.042)]),
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let deserialized: MetricsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snapshot, deserialized);
    }

    #[test]
    fn empty_snapshot_serializes_compact() {
        let snapshot = MetricsSnapshot::default();
        let json = serde_json::to_string(&snapshot).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn has_mappings() {
        let empty = MetricsConfig::default();
        assert!(!empty.has_mappings());

        let with = MetricsConfig {
            mappings: BTreeMap::from([("k".to_string(), "v".to_string())]),
            port: None,
        };
        assert!(with.has_mappings());
    }

    #[test]
    fn deserialize_from_json() {
        let json = r#"{
            "metrics": {
                "mappings": { "loss": "avg(training_loss{$SELECTORS})" },
                "port": "custom-metrics"
            }
        }"#;
        let spec: ObservabilitySpec = serde_json::from_str(json).unwrap();
        assert_eq!(
            spec.metrics.as_ref().unwrap().port.as_deref(),
            Some("custom-metrics")
        );
        assert_eq!(spec.metrics.as_ref().unwrap().mappings.len(), 1);
    }
}
