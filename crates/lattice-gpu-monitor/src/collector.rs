//! DCGM Exporter scraper.
//!
//! Scrapes Prometheus text format from the DCGM exporter HTTP endpoint
//! and parses GPU metrics into structured samples.

use std::collections::HashMap;
use std::time::Instant;

use thiserror::Error;
use tracing::debug;

use crate::config::RAW_FEATURES;

#[derive(Debug, Error)]
pub enum CollectorError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("no GPU metrics found in DCGM response")]
    NoGpuMetrics,
}

/// Per-GPU sample of DCGM metrics.
#[derive(Debug, Clone, Default)]
pub struct GpuSample {
    pub gpu_index: u32,
    pub gpu_temp: f32,
    pub memory_temp: f32,
    pub power_usage: f32,
    pub gpu_util: f32,
    pub mem_copy_util: f32,
    pub fb_used: f32,
    pub fb_free: f32,
    pub pcie_tx: f32,
    pub pcie_rx: f32,
    pub sm_clock: f32,
    pub mem_clock: f32,
    pub ecc_sbe: f32,
    pub ecc_dbe: f32,
    pub pcie_replay: f32,
    pub xid_errors: f32,
}

impl GpuSample {
    /// Return raw features as an array for the feature pipeline.
    pub fn as_array(&self) -> [f32; RAW_FEATURES] {
        [
            self.gpu_temp,
            self.memory_temp,
            self.power_usage,
            self.gpu_util,
            self.mem_copy_util,
            self.fb_used,
            self.fb_free,
            self.pcie_tx,
            self.pcie_rx,
            self.sm_clock,
            self.mem_clock,
            self.ecc_sbe,
            self.ecc_dbe,
            self.pcie_replay,
            self.xid_errors,
        ]
    }
}

/// Aggregated sample from all GPUs on a node.
#[derive(Debug, Clone)]
pub struct NodeSample {
    pub gpus: Vec<GpuSample>,
    pub timestamp: Instant,
}

/// Scrapes DCGM exporter metrics.
pub struct DcgmCollector {
    url: String,
    client: reqwest::Client,
}

impl DcgmCollector {
    pub fn new(url: &str) -> Result<Self, CollectorError> {
        // DCGM exporter is always localhost HTTP — no TLS needed.
        // Build explicitly so we never accidentally pull in a non-FIPS TLS backend.
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()?;
        Ok(Self {
            url: url.to_string(),
            client,
        })
    }

    /// Scrape DCGM exporter and parse into a NodeSample.
    pub async fn scrape(&self) -> Result<NodeSample, CollectorError> {
        let body = self.client.get(&self.url).send().await?.text().await?;
        let gpus = parse_prometheus_text(&body)?;
        Ok(NodeSample {
            gpus,
            timestamp: Instant::now(),
        })
    }
}

/// Parse Prometheus text format output from DCGM exporter.
fn parse_prometheus_text(body: &str) -> Result<Vec<GpuSample>, CollectorError> {
    let mut gpu_map: HashMap<u32, GpuSample> = HashMap::new();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Format: metric_name{labels} value [timestamp]
        let Some(brace_start) = line.find('{') else {
            continue;
        };
        let Some(brace_end) = line.find('}') else {
            continue;
        };

        let metric_name = &line[..brace_start];
        let labels_str = &line[brace_start + 1..brace_end];
        let value_str = line[brace_end + 1..].split_whitespace().next();

        let Some(value_str) = value_str else {
            continue;
        };
        let Ok(value) = value_str.parse::<f32>() else {
            continue;
        };

        let Some(gpu_index) = extract_gpu_label(labels_str) else {
            continue;
        };

        let gpu = gpu_map.entry(gpu_index).or_insert_with(|| GpuSample {
            gpu_index,
            ..Default::default()
        });

        match metric_name {
            "DCGM_FI_DEV_GPU_TEMP" => gpu.gpu_temp = value,
            "DCGM_FI_DEV_MEMORY_TEMP" => gpu.memory_temp = value,
            "DCGM_FI_DEV_POWER_USAGE" => gpu.power_usage = value,
            "DCGM_FI_DEV_GPU_UTIL" => gpu.gpu_util = value,
            "DCGM_FI_DEV_MEM_COPY_UTIL" => gpu.mem_copy_util = value,
            "DCGM_FI_DEV_FB_USED" => gpu.fb_used = value,
            "DCGM_FI_DEV_FB_FREE" => gpu.fb_free = value,
            "DCGM_FI_DEV_PCIE_TX_THROUGHPUT" => gpu.pcie_tx = value,
            "DCGM_FI_DEV_PCIE_RX_THROUGHPUT" => gpu.pcie_rx = value,
            "DCGM_FI_DEV_SM_CLOCK" => gpu.sm_clock = value,
            "DCGM_FI_DEV_MEM_CLOCK" => gpu.mem_clock = value,
            "DCGM_FI_DEV_ECC_SBE_VOL_TOTAL" => gpu.ecc_sbe = value,
            "DCGM_FI_DEV_ECC_DBE_VOL_TOTAL" => gpu.ecc_dbe = value,
            "DCGM_FI_DEV_PCIE_REPLAY_COUNTER" => gpu.pcie_replay = value,
            "DCGM_FI_DEV_XID_ERRORS" => gpu.xid_errors = value,
            _ => {}
        }
    }

    if gpu_map.is_empty() {
        return Err(CollectorError::NoGpuMetrics);
    }

    let mut gpus: Vec<GpuSample> = gpu_map.into_values().collect();
    gpus.sort_by_key(|g| g.gpu_index);
    debug!(gpu_count = gpus.len(), "scraped DCGM metrics");
    Ok(gpus)
}

/// Extract the `gpu` label value from a Prometheus label string.
fn extract_gpu_label(labels: &str) -> Option<u32> {
    for part in labels.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("gpu=\"") {
            if let Some(val) = rest.strip_suffix('"') {
                return val.parse().ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_DCGM_OUTPUT: &str = r#"
# HELP DCGM_FI_DEV_GPU_TEMP GPU temperature (in C).
# TYPE DCGM_FI_DEV_GPU_TEMP gauge
DCGM_FI_DEV_GPU_TEMP{gpu="0",UUID="GPU-abc",device="nvidia0"} 45
DCGM_FI_DEV_GPU_TEMP{gpu="1",UUID="GPU-def",device="nvidia1"} 47
# HELP DCGM_FI_DEV_POWER_USAGE Power draw (in W).
# TYPE DCGM_FI_DEV_POWER_USAGE gauge
DCGM_FI_DEV_POWER_USAGE{gpu="0",UUID="GPU-abc",device="nvidia0"} 120.5
DCGM_FI_DEV_POWER_USAGE{gpu="1",UUID="GPU-def",device="nvidia1"} 135.2
# HELP DCGM_FI_DEV_GPU_UTIL GPU utilization (in %).
# TYPE DCGM_FI_DEV_GPU_UTIL gauge
DCGM_FI_DEV_GPU_UTIL{gpu="0",UUID="GPU-abc",device="nvidia0"} 85
DCGM_FI_DEV_GPU_UTIL{gpu="1",UUID="GPU-def",device="nvidia1"} 92
DCGM_FI_DEV_FB_USED{gpu="0",UUID="GPU-abc",device="nvidia0"} 30000
DCGM_FI_DEV_FB_USED{gpu="1",UUID="GPU-def",device="nvidia1"} 35000
DCGM_FI_DEV_FB_FREE{gpu="0",UUID="GPU-abc",device="nvidia0"} 50000
DCGM_FI_DEV_FB_FREE{gpu="1",UUID="GPU-def",device="nvidia1"} 45000
DCGM_FI_DEV_SM_CLOCK{gpu="0",UUID="GPU-abc",device="nvidia0"} 1410
DCGM_FI_DEV_SM_CLOCK{gpu="1",UUID="GPU-def",device="nvidia1"} 1395
DCGM_FI_DEV_MEM_CLOCK{gpu="0",UUID="GPU-abc",device="nvidia0"} 1215
DCGM_FI_DEV_MEM_CLOCK{gpu="1",UUID="GPU-def",device="nvidia1"} 1215
DCGM_FI_DEV_ECC_SBE_VOL_TOTAL{gpu="0",UUID="GPU-abc",device="nvidia0"} 0
DCGM_FI_DEV_ECC_DBE_VOL_TOTAL{gpu="0",UUID="GPU-abc",device="nvidia0"} 0
DCGM_FI_DEV_XID_ERRORS{gpu="0",UUID="GPU-abc",device="nvidia0"} 0
DCGM_FI_DEV_MEMORY_TEMP{gpu="0",UUID="GPU-abc",device="nvidia0"} 40
DCGM_FI_DEV_MEM_COPY_UTIL{gpu="0",UUID="GPU-abc",device="nvidia0"} 30
DCGM_FI_DEV_PCIE_TX_THROUGHPUT{gpu="0",UUID="GPU-abc",device="nvidia0"} 5000
DCGM_FI_DEV_PCIE_RX_THROUGHPUT{gpu="0",UUID="GPU-abc",device="nvidia0"} 3000
DCGM_FI_DEV_PCIE_REPLAY_COUNTER{gpu="0",UUID="GPU-abc",device="nvidia0"} 0
"#;

    #[test]
    fn parses_two_gpus() {
        let gpus = parse_prometheus_text(SAMPLE_DCGM_OUTPUT).unwrap();
        assert_eq!(gpus.len(), 2);
        assert_eq!(gpus[0].gpu_index, 0);
        assert_eq!(gpus[1].gpu_index, 1);
    }

    #[test]
    fn parses_gpu_temp() {
        let gpus = parse_prometheus_text(SAMPLE_DCGM_OUTPUT).unwrap();
        assert!((gpus[0].gpu_temp - 45.0).abs() < f32::EPSILON);
        assert!((gpus[1].gpu_temp - 47.0).abs() < f32::EPSILON);
    }

    #[test]
    fn parses_power_usage() {
        let gpus = parse_prometheus_text(SAMPLE_DCGM_OUTPUT).unwrap();
        assert!((gpus[0].power_usage - 120.5).abs() < 0.1);
        assert!((gpus[1].power_usage - 135.2).abs() < 0.1);
    }

    #[test]
    fn parses_utilization() {
        let gpus = parse_prometheus_text(SAMPLE_DCGM_OUTPUT).unwrap();
        assert!((gpus[0].gpu_util - 85.0).abs() < f32::EPSILON);
    }

    #[test]
    fn parses_memory() {
        let gpus = parse_prometheus_text(SAMPLE_DCGM_OUTPUT).unwrap();
        assert!((gpus[0].fb_used - 30000.0).abs() < f32::EPSILON);
        assert!((gpus[0].fb_free - 50000.0).abs() < f32::EPSILON);
    }

    #[test]
    fn parses_clocks() {
        let gpus = parse_prometheus_text(SAMPLE_DCGM_OUTPUT).unwrap();
        assert!((gpus[0].sm_clock - 1410.0).abs() < f32::EPSILON);
        assert!((gpus[0].mem_clock - 1215.0).abs() < f32::EPSILON);
    }

    #[test]
    fn as_array_returns_raw_features_count() {
        let sample = GpuSample::default();
        assert_eq!(sample.as_array().len(), RAW_FEATURES);
    }

    #[test]
    fn empty_body_returns_error() {
        let result = parse_prometheus_text("");
        assert!(result.is_err());
    }

    #[test]
    fn comment_only_body_returns_error() {
        let result = parse_prometheus_text("# HELP metric desc\n# TYPE metric gauge\n");
        assert!(result.is_err());
    }

    #[test]
    fn extract_gpu_label_works() {
        assert_eq!(
            extract_gpu_label(r#"gpu="0",UUID="GPU-abc""#),
            Some(0)
        );
        assert_eq!(
            extract_gpu_label(r#"UUID="GPU-abc",gpu="3""#),
            Some(3)
        );
        assert_eq!(extract_gpu_label(r#"UUID="GPU-abc""#), None);
    }
}
