//! Kubernetes resource quantity parsing for CRD validation (quota).

/// Error returned when a Kubernetes resource quantity string cannot be parsed.
#[derive(Debug, thiserror::Error)]
#[error("invalid resource quantity: {0}")]
pub struct QuantityParseError(pub String);

/// CPU resource key for quota maps.
pub const CPU_RESOURCE: &str = "cpu";

/// Memory resource key for quota maps.
pub const MEMORY_RESOURCE: &str = "memory";

/// Parse a CPU quantity string to millicores.
///
/// Handles formats: `"1"` (cores), `"500m"` (millicores), `"1.5"` (fractional cores).
pub fn parse_cpu_millis_str(s: &str) -> Result<i64, QuantityParseError> {
    if let Some(millis) = s.strip_suffix('m') {
        millis
            .parse::<i64>()
            .map_err(|_| QuantityParseError(s.to_string()))
    } else {
        s.parse::<f64>()
            .map(|cores| (cores * 1000.0) as i64)
            .map_err(|_| QuantityParseError(s.to_string()))
    }
}

const MEMORY_SUFFIXES: &[(&str, i64)] = &[
    ("Ti", 1024 * 1024 * 1024 * 1024),
    ("Gi", 1024 * 1024 * 1024),
    ("Mi", 1024 * 1024),
    ("Ki", 1024),
    ("T", 1_000_000_000_000),
    ("G", 1_000_000_000),
    ("M", 1_000_000),
    ("k", 1_000),
];

/// Parse a memory quantity string to bytes.
///
/// Handles binary suffixes (`Ki`, `Mi`, `Gi`, `Ti`), decimal suffixes
/// (`k`, `M`, `G`, `T`), and plain byte values.
pub fn parse_memory_bytes_str(s: &str) -> Result<i64, QuantityParseError> {
    let err = || QuantityParseError(s.to_string());

    for (suffix, multiplier) in MEMORY_SUFFIXES {
        if let Some(v) = s.strip_suffix(suffix) {
            return Ok(v.parse::<i64>().map_err(|_| err())? * multiplier);
        }
    }

    s.parse::<i64>().map_err(|_| err())
}

/// Parse a resource quantity from a quota map by key name.
///
/// Dispatches to the appropriate parser based on the resource key:
/// - `cpu` → millicores (i64)
/// - `memory` → bytes (i64)
/// - everything else → plain integer (i64)
pub fn parse_resource_by_key(key: &str, value: &str) -> Result<i64, QuantityParseError> {
    match key {
        CPU_RESOURCE => parse_cpu_millis_str(value),
        MEMORY_RESOURCE => parse_memory_bytes_str(value),
        _ => value
            .parse::<i64>()
            .map_err(|_| QuantityParseError(format!("{key}: {value}"))),
    }
}
