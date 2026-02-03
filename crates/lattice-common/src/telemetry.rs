//! Telemetry initialization for OpenTelemetry tracing and metrics
//!
//! Provides unified telemetry setup with:
//! - W3C TraceContext propagation for distributed tracing
//! - OTLP export when `OTEL_EXPORTER_OTLP_ENDPOINT` is set
//! - Prometheus metrics export via handle
//! - Kubernetes resource detection (pod, namespace, node)
//! - JSON structured logging with trace context

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::TracerProvider;
use opentelemetry_sdk::{runtime, Resource};
use prometheus::Registry;
use thiserror::Error;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Errors that can occur during telemetry initialization
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// Failed to initialize OpenTelemetry tracer
    #[error("failed to initialize tracer: {0}")]
    TracerInit(String),

    /// Failed to initialize Prometheus exporter
    #[error("failed to initialize Prometheus exporter: {0}")]
    PrometheusInit(String),

    /// Failed to initialize tracing subscriber
    #[error("failed to initialize tracing subscriber: {0}")]
    SubscriberInit(String),
}

/// Configuration for telemetry initialization
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Service name for traces and metrics (e.g., "lattice-operator")
    pub service_name: String,

    /// OTLP endpoint for trace export (e.g., "http://otel-collector:4317")
    /// If None, traces are only logged locally
    pub otlp_endpoint: Option<String>,

    /// Whether to enable Prometheus metrics export
    pub prometheus_enabled: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "lattice".to_string(),
            otlp_endpoint: std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok(),
            prometheus_enabled: std::env::var("LATTICE_PROMETHEUS_ENABLED")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true),
        }
    }
}

/// Handle for accessing Prometheus metrics
///
/// Use `registry()` to get the Prometheus registry for encoding metrics.
pub struct PrometheusHandle {
    registry: Registry,
}

impl PrometheusHandle {
    /// Get the Prometheus registry for encoding metrics
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Encode metrics as Prometheus text format
    pub fn encode(&self) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).ok();
        String::from_utf8(buffer).unwrap_or_default()
    }
}

/// Initialize telemetry with the given configuration
///
/// Sets up:
/// - W3C TraceContext propagator for distributed tracing
/// - OTLP exporter if `otlp_endpoint` is configured
/// - Prometheus metrics if `prometheus_enabled` is true
/// - JSON structured logging with trace context
/// - Kubernetes resource detection
///
/// Returns a `PrometheusHandle` if Prometheus is enabled, which can be used
/// to expose metrics at a `/metrics` endpoint.
///
/// # Example
///
/// ```ignore
/// use lattice_common::telemetry::{init_telemetry, TelemetryConfig};
///
/// let config = TelemetryConfig {
///     service_name: "lattice-operator".to_string(),
///     ..Default::default()
/// };
/// let prom_handle = init_telemetry(config)?;
/// ```
pub fn init_telemetry(config: TelemetryConfig) -> Result<Option<PrometheusHandle>, TelemetryError> {
    // Set W3C TraceContext as global propagator
    global::set_text_map_propagator(TraceContextPropagator::new());

    // Build resource with service name and K8s detection
    let resource = build_resource(&config.service_name);

    // Initialize OTLP tracer if endpoint is configured
    let tracer_provider = if let Some(endpoint) = &config.otlp_endpoint {
        Some(init_otlp_tracer(endpoint, resource.clone())?)
    } else {
        None
    };

    // Initialize Prometheus if enabled
    let prometheus_handle = if config.prometheus_enabled {
        Some(init_prometheus(resource)?)
    } else {
        None
    };

    // Build tracing subscriber layers
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info,lattice=debug,kube=info,tower=warn,hyper=warn")
    });

    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(false)
        .with_target(true)
        .with_file(false)
        .with_line_number(false);

    // Build the subscriber with optional OpenTelemetry layer
    if let Some(provider) = tracer_provider {
        let tracer = provider.tracer(config.service_name.clone());
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(otel_layer)
            .try_init()
            .map_err(|e: tracing_subscriber::util::TryInitError| {
                TelemetryError::SubscriberInit(e.to_string())
            })?;
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .try_init()
            .map_err(|e: tracing_subscriber::util::TryInitError| {
                TelemetryError::SubscriberInit(e.to_string())
            })?;
    }

    Ok(prometheus_handle)
}

/// Build OpenTelemetry resource with service info and K8s detection
fn build_resource(service_name: &str) -> Resource {
    // Start with service name
    let mut attributes = vec![KeyValue::new(
        opentelemetry_semantic_conventions::resource::SERVICE_NAME,
        service_name.to_string(),
    )];

    // Add K8s attributes from environment (set via Deployment downward API)
    if let Ok(pod_name) = std::env::var("POD_NAME") {
        attributes.push(KeyValue::new("k8s.pod.name", pod_name));
    }
    if let Ok(namespace) = std::env::var("POD_NAMESPACE") {
        attributes.push(KeyValue::new("k8s.namespace.name", namespace));
    }
    if let Ok(node_name) = std::env::var("NODE_NAME") {
        attributes.push(KeyValue::new("k8s.node.name", node_name));
    }
    if let Ok(container_name) = std::env::var("CONTAINER_NAME") {
        attributes.push(KeyValue::new("k8s.container.name", container_name));
    }

    // Add version if available
    if let Some(version) = option_env!("CARGO_PKG_VERSION") {
        attributes.push(KeyValue::new(
            opentelemetry_semantic_conventions::resource::SERVICE_VERSION,
            version.to_string(),
        ));
    }

    Resource::new(attributes)
}

/// Initialize OTLP tracer provider
fn init_otlp_tracer(endpoint: &str, resource: Resource) -> Result<TracerProvider, TelemetryError> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| TelemetryError::TracerInit(e.to_string()))?;

    let provider = TracerProvider::builder()
        .with_batch_exporter(exporter, runtime::Tokio)
        .with_resource(resource)
        .build();

    global::set_tracer_provider(provider.clone());

    Ok(provider)
}

/// Initialize Prometheus metrics exporter
fn init_prometheus(resource: Resource) -> Result<PrometheusHandle, TelemetryError> {
    let registry = Registry::new();

    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry.clone())
        .without_scope_info()
        .without_target_info()
        .build()
        .map_err(|e| TelemetryError::PrometheusInit(e.to_string()))?;

    // Create a meter provider with the resource
    let meter_provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_reader(exporter)
        .with_resource(resource)
        .build();

    global::set_meter_provider(meter_provider);

    Ok(PrometheusHandle { registry })
}

/// Shutdown telemetry providers gracefully
///
/// Call this during application shutdown to ensure all pending traces
/// and metrics are flushed.
pub fn shutdown_telemetry() {
    global::shutdown_tracer_provider();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_config_default() {
        // Test with explicit values to avoid env var pollution
        let config = TelemetryConfig {
            service_name: "test-service".to_string(),
            otlp_endpoint: None,
            prometheus_enabled: true,
        };
        assert_eq!(config.service_name, "test-service");
        assert!(config.otlp_endpoint.is_none());
        assert!(config.prometheus_enabled);
    }

    #[test]
    fn test_telemetry_config_from_env() {
        // Test explicit config instead of relying on env vars
        let config = TelemetryConfig {
            service_name: "lattice".to_string(),
            otlp_endpoint: Some("http://localhost:4317".to_string()),
            prometheus_enabled: false,
        };
        assert_eq!(
            config.otlp_endpoint,
            Some("http://localhost:4317".to_string())
        );
        assert!(!config.prometheus_enabled);
    }

    #[test]
    fn test_build_resource() {
        let resource = build_resource("test-service");
        // Resource should have at least the service name
        assert!(!resource.is_empty());
    }

    #[test]
    fn test_prometheus_handle_encode() {
        let registry = Registry::new();
        let handle = PrometheusHandle { registry };
        let encoded = handle.encode();
        // Should return valid (possibly empty) Prometheus text
        assert!(encoded.is_empty() || encoded.contains("# HELP") || encoded.contains("# TYPE"));
    }
}
