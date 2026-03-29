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

impl CostRates {
    /// Create uniform rates where every resource type costs $1/unit/hour.
    ///
    /// Used as a fallback when no cost rates are configured. The solver will
    /// still minimize total node count (since all nodes cost the same per
    /// resource unit), but won't prefer cheaper instance types.
    pub fn uniform() -> Self {
        Self {
            cpu: 1.0,
            memory: 1.0,
            gpu: std::collections::BTreeMap::new(),
        }
    }
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
