//! Cost rate definitions and parsing.

use std::collections::BTreeMap;

use serde::Deserialize;

/// Per-resource-type hourly rates loaded from the `lattice-resource-rates` ConfigMap.
#[derive(Clone, Debug, Deserialize)]
pub struct CostRates {
    /// Cost per vCPU-hour (USD)
    pub cpu: f64,

    /// Cost per GiB memory per hour (USD)
    pub memory: f64,

    /// Cost per GPU per hour by model name (USD).
    /// Keys are vendor model names (e.g. "H100-SXM", "A100-80GB", "L4").
    #[serde(default)]
    pub gpu: BTreeMap<String, f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rates_yaml() {
        let yaml = r#"
cpu: 0.031
memory: 0.004
gpu:
  H100-SXM: 3.50
  A100-80GB: 2.21
  L4: 0.81
  T4: 0.35
"#;
        let rates: CostRates = serde_yaml::from_str(yaml).unwrap();
        assert!((rates.cpu - 0.031).abs() < f64::EPSILON);
        assert!((rates.memory - 0.004).abs() < f64::EPSILON);
        assert_eq!(rates.gpu.len(), 4);
        assert!((rates.gpu["H100-SXM"] - 3.50).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_rates_no_gpu() {
        let yaml = r#"
cpu: 0.05
memory: 0.006
"#;
        let rates: CostRates = serde_yaml::from_str(yaml).unwrap();
        assert!(rates.gpu.is_empty());
    }
}
