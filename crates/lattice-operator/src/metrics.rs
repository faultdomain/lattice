//! Metrics scraper for VictoriaMetrics
//!
//! Queries VictoriaMetrics with PromQL from CRD metric mappings and returns
//! scalar snapshots for writing to CRD status.

use std::collections::BTreeMap;

use async_trait::async_trait;
use lattice_common::crd::MetricsSnapshot;
use lattice_infra::bootstrap::prometheus::{query_path, query_port, query_url};
use tracing::warn;

/// Error type for individual metric query failures.
#[derive(Debug, thiserror::Error)]
enum MetricsError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("VM returned non-success status: {0}")]
    VmStatus(String),
    #[error("no data returned for query")]
    NoData,
    #[error("failed to parse scalar value: {0}")]
    ParseFloat(String),
}

/// Scrapes VictoriaMetrics for metric values defined in CRD mappings.
pub struct MetricsScraper {
    client: reqwest::Client,
    base_url: String,
}

/// Error type for scraper construction failures.
#[derive(Debug, thiserror::Error)]
#[error("failed to build HTTPS client: {0}")]
pub struct ScraperBuildError(#[from] reqwest::Error);

impl MetricsScraper {
    /// Create a new scraper pointing at the cluster's VictoriaMetrics instance.
    pub fn new(ha: bool) -> Result<Self, ScraperBuildError> {
        let base_url = format!(
            "{}:{}{}",
            query_url(ha),
            query_port(ha),
            query_path(ha),
        );
        Ok(Self {
            client: reqwest::Client::builder()
                .use_rustls_tls()
                .build()?,
            base_url,
        })
    }

    /// Execute a single PromQL instant query against VM and extract a scalar.
    async fn query(&self, promql: &str) -> Result<f64, MetricsError> {
        let url = format!("{}/api/v1/query", self.base_url);
        let resp = self
            .client
            .get(&url)
            .query(&[("query", promql)])
            .send()
            .await?;

        let body: serde_json::Value = resp.json().await?;

        let status = body["status"]
            .as_str()
            .ok_or_else(|| MetricsError::VmStatus("response missing 'status' field".to_string()))?;
        if status != "success" {
            let error_msg = body["error"]
                .as_str()
                .ok_or_else(|| MetricsError::VmStatus(format!("status={status}, no error message")))?
                .to_string();
            return Err(MetricsError::VmStatus(error_msg));
        }

        let results = body["data"]["result"]
            .as_array()
            .ok_or(MetricsError::NoData)?;

        if results.is_empty() {
            return Err(MetricsError::NoData);
        }

        if results.len() > 1 {
            warn!(
                count = results.len(),
                "query returned multiple series, using first — consider adding aggregation to your PromQL"
            );
        }

        // VM instant query result: [{"value": [timestamp, "scalar_string"]}]
        let value_str = results[0]["value"][1]
            .as_str()
            .ok_or_else(|| MetricsError::ParseFloat("value is not a string".to_string()))?;

        value_str
            .parse::<f64>()
            .map_err(|e| MetricsError::ParseFloat(e.to_string()))
    }
}

#[async_trait]
impl lattice_common::crd::MetricsScraper for MetricsScraper {
    async fn scrape(
        &self,
        mappings: &BTreeMap<String, String>,
        namespace: &str,
        workload_name: &str,
    ) -> MetricsSnapshot {
        let selectors = format!(
            r#"namespace="{namespace}", pod=~"{workload_name}-.*""#
        );
        let mut values = BTreeMap::new();
        for (key, promql_template) in mappings {
            let promql = promql_template.replace("$SELECTORS", &selectors);
            match self.query(&promql).await {
                Ok(v) => {
                    values.insert(key.clone(), v);
                }
                Err(e) => {
                    warn!(key, error = %e, "metric scrape failed");
                }
            }
        }
        MetricsSnapshot { values }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vm_success_response() {
        let body: serde_json::Value = serde_json::json!({
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{
                    "metric": {"__name__": "training_loss"},
                    "value": [1709712000, "0.042"]
                }]
            }
        });

        let results = body["data"]["result"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        let val: f64 = results[0]["value"][1].as_str().unwrap().parse().unwrap();
        assert!((val - 0.042).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_vm_empty_result() {
        let body: serde_json::Value = serde_json::json!({
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": []
            }
        });

        let results = body["data"]["result"].as_array().unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn parse_vm_error_response() {
        let body: serde_json::Value = serde_json::json!({
            "status": "error",
            "error": "invalid query"
        });

        assert_ne!(body["status"].as_str().unwrap(), "success");
    }

    #[test]
    fn selector_substitution() {
        let template = "avg(training_loss{$SELECTORS})";
        let selectors = r#"namespace="training", pod=~"llama-finetune-.*""#;
        let result = template.replace("$SELECTORS", selectors);
        assert_eq!(
            result,
            r#"avg(training_loss{namespace="training", pod=~"llama-finetune-.*"})"#
        );
    }

    #[test]
    fn no_selectors_template_unchanged() {
        let template = "up{job=\"vllm\"}";
        let selectors = r#"namespace="default", pod=~"svc-.*""#;
        let result = template.replace("$SELECTORS", selectors);
        // No $SELECTORS placeholder → template unchanged
        assert_eq!(result, template);
    }

    #[test]
    fn scraper_url_construction() {
        let scraper = MetricsScraper::new(false).unwrap();
        assert!(scraper.base_url.contains("vmsingle"));
        assert!(scraper.base_url.contains("/prometheus"));

        let scraper_ha = MetricsScraper::new(true).unwrap();
        assert!(scraper_ha.base_url.contains("vmselect"));
        assert!(scraper_ha.base_url.contains("/select/0/prometheus"));
    }
}
