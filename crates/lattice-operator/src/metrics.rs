//! Metrics scraper for VictoriaMetrics
//!
//! Queries VictoriaMetrics with PromQL from CRD metric mappings and returns
//! scalar snapshots for writing to CRD status.

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use lattice_common::crd::MetricsSnapshot;
use lattice_infra::bootstrap::prometheus::{query_path, query_port, query_url};
use tracing::warn;

/// Maximum length for a PromQL template to prevent resource exhaustion.
const MAX_PROMQL_TEMPLATE_LEN: usize = 2048;

/// Timeout for individual HTTP requests to VictoriaMetrics.
const SCRAPE_TIMEOUT: Duration = Duration::from_secs(5);

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
pub struct VmMetricsScraper {
    client: reqwest::Client,
    base_url: String,
}

/// Error type for scraper construction failures.
#[derive(Debug, thiserror::Error)]
#[error("failed to build HTTPS client: {0}")]
pub struct ScraperBuildError(#[from] reqwest::Error);

impl VmMetricsScraper {
    /// Create a new scraper pointing at the cluster's VictoriaMetrics instance.
    pub fn new(ha: bool) -> Result<Self, ScraperBuildError> {
        let base_url = format!("{}:{}{}", query_url(ha), query_port(ha), query_path(ha),);
        Ok(Self {
            client: reqwest::Client::builder()
                .use_rustls_tls()
                .timeout(SCRAPE_TIMEOUT)
                .connect_timeout(Duration::from_secs(2))
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
                .ok_or_else(|| {
                    MetricsError::VmStatus(format!("status={status}, no error message"))
                })?
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

/// Validate that a value is safe to interpolate into a PromQL double-quoted label matcher.
///
/// Rejects values containing characters that could break out of a `"..."` string
/// context in PromQL: double quotes, backslashes, newlines, and control characters.
/// Kubernetes names are already restricted to `[a-zA-Z0-9._-]`, so this is defense
/// in depth against bypassed admission control.
fn validate_promql_label_value(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field} is empty"));
    }
    for ch in value.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' && ch != '.' {
            return Err(format!(
                "{field} contains unsafe character '{}' (only alphanumeric, hyphen, underscore, dot allowed)",
                ch.escape_debug()
            ));
        }
    }
    Ok(())
}

/// Validate that a PromQL template is safe to execute.
///
/// Checks length bounds and character set. This is not a full PromQL parser but
/// prevents obviously malicious payloads like control characters or excessively
/// long queries that could cause resource exhaustion.
fn validate_promql_template(template: &str) -> Result<(), String> {
    if template.len() > MAX_PROMQL_TEMPLATE_LEN {
        return Err(format!(
            "PromQL template exceeds maximum length of {} bytes",
            MAX_PROMQL_TEMPLATE_LEN
        ));
    }
    for ch in template.chars() {
        if ch.is_control() && ch != '\n' && ch != '\t' {
            return Err(format!(
                "PromQL template contains control character U+{:04X}",
                ch as u32
            ));
        }
    }
    Ok(())
}

#[async_trait]
impl lattice_common::crd::MetricsScraper for VmMetricsScraper {
    async fn scrape(
        &self,
        mappings: &BTreeMap<String, String>,
        namespace: &str,
        workload_name: &str,
    ) -> MetricsSnapshot {
        let mut values = BTreeMap::new();

        // Validate label values before interpolation to prevent PromQL injection
        if let Err(e) = validate_promql_label_value(namespace, "namespace") {
            warn!(error = %e, "skipping all metric scrapes due to unsafe namespace");
            return MetricsSnapshot { values };
        }
        if let Err(e) = validate_promql_label_value(workload_name, "workload_name") {
            warn!(error = %e, "skipping all metric scrapes due to unsafe workload name");
            return MetricsSnapshot { values };
        }

        let selectors = format!(r#"namespace="{namespace}", pod=~"{workload_name}-.+""#);
        for (key, promql_template) in mappings {
            if let Err(e) = validate_promql_template(promql_template) {
                warn!(key, error = %e, "skipping metric with invalid PromQL template");
                continue;
            }
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
        let selectors = r#"namespace="training", pod=~"llama-finetune-.+""#;
        let result = template.replace("$SELECTORS", selectors);
        assert_eq!(
            result,
            r#"avg(training_loss{namespace="training", pod=~"llama-finetune-.+"})"#
        );
    }

    #[test]
    fn no_selectors_template_unchanged() {
        let template = "up{job=\"vllm\"}";
        let selectors = r#"namespace="default", pod=~"svc-.+""#;
        let result = template.replace("$SELECTORS", selectors);
        // No $SELECTORS placeholder → template unchanged
        assert_eq!(result, template);
    }

    #[test]
    fn promql_label_value_rejects_quote_injection() {
        let result = validate_promql_label_value(r#"foo", malicious="yes"#, "namespace");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsafe character"));
    }

    #[test]
    fn promql_label_value_rejects_backslash() {
        let result = validate_promql_label_value(r"foo\nbar", "namespace");
        assert!(result.is_err());
    }

    #[test]
    fn promql_label_value_accepts_valid_k8s_name() {
        assert!(validate_promql_label_value("my-namespace", "namespace").is_ok());
        assert!(validate_promql_label_value("app.v1.2", "workload").is_ok());
        assert!(validate_promql_label_value("my_workload", "workload").is_ok());
    }

    #[test]
    fn promql_label_value_rejects_empty() {
        assert!(validate_promql_label_value("", "namespace").is_err());
    }

    #[test]
    fn promql_template_rejects_oversized() {
        let huge = "a".repeat(MAX_PROMQL_TEMPLATE_LEN + 1);
        assert!(validate_promql_template(&huge).is_err());
    }

    #[test]
    fn promql_template_rejects_control_chars() {
        assert!(validate_promql_template("avg(foo{\x00})").is_err());
        assert!(validate_promql_template("avg(foo{\x07})").is_err());
    }

    #[test]
    fn promql_template_accepts_valid() {
        assert!(validate_promql_template("avg(training_loss{$SELECTORS})").is_ok());
        assert!(validate_promql_template("sum(rate(http_requests_total{$SELECTORS}[1m]))").is_ok());
    }

    #[test]
    fn scraper_url_construction() {
        let scraper = VmMetricsScraper::new(false).unwrap();
        assert!(scraper.base_url.contains("vmsingle"));
        assert!(scraper.base_url.contains("/prometheus"));

        let scraper_ha = VmMetricsScraper::new(true).unwrap();
        assert!(scraper_ha.base_url.contains("vmselect"));
        assert!(scraper_ha.base_url.contains("/select/0/prometheus"));
    }
}
