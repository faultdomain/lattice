//! Telemetry initialization for OpenTelemetry tracing and metrics
//!
//! Provides unified telemetry setup with:
//! - W3C TraceContext propagation for distributed tracing
//! - OTLP export for traces and metrics when `OTEL_EXPORTER_OTLP_ENDPOINT` is set
//! - Prometheus scrape endpoint via returned `Registry`
//! - Kubernetes resource detection (pod, namespace, node)
//! - JSON structured logging with trace context

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::TracerProvider;
use opentelemetry_sdk::{runtime, Resource};
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

    /// Failed to initialize OTLP metrics exporter
    #[error("failed to initialize metrics exporter: {0}")]
    MetricsInit(String),

    /// Failed to initialize tracing subscriber
    #[error("failed to initialize tracing subscriber: {0}")]
    SubscriberInit(String),
}

/// Configuration for telemetry initialization
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Service name for traces and metrics (e.g., "lattice-operator")
    pub service_name: String,

    /// OTLP endpoint for trace and metric export (e.g., "http://otel-collector:4317")
    /// If None, traces and metrics are only logged locally
    pub otlp_endpoint: Option<String>,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "lattice".to_string(),
            otlp_endpoint: std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok(),
        }
    }
}

/// Initialize telemetry with the given configuration
///
/// Sets up:
/// - W3C TraceContext propagator for distributed tracing
/// - Prometheus exporter (always — returned `Registry` serves `/metrics`)
/// - OTLP exporter for traces and metrics if `otlp_endpoint` is configured
/// - JSON structured logging with trace context
/// - Kubernetes resource detection
///
/// Returns a Prometheus `Registry` that should be served on the `/metrics` HTTP endpoint.
pub fn init_telemetry(
    config: TelemetryConfig,
) -> Result<prometheus::Registry, TelemetryError> {
    // Set W3C TraceContext as global propagator
    global::set_text_map_propagator(TraceContextPropagator::new());

    // Build resource with service name and K8s detection
    let resource = build_resource(&config.service_name);

    // Always create Prometheus exporter so metrics are available via /metrics
    let prom_registry = prometheus::Registry::new();
    let prom_exporter = opentelemetry_prometheus::exporter()
        .with_registry(prom_registry.clone())
        .build()
        .map_err(|e| TelemetryError::MetricsInit(e.to_string()))?;

    let mut meter_builder = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_reader(prom_exporter)
        .with_resource(resource.clone());

    // Initialize OTLP tracer and metrics if endpoint is configured
    let otel_layer = if let Some(endpoint) = &config.otlp_endpoint {
        // Add OTLP periodic reader alongside Prometheus reader
        let otlp_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()
            .map_err(|e| TelemetryError::MetricsInit(e.to_string()))?;

        let otlp_reader = opentelemetry_sdk::metrics::PeriodicReader::builder(
            otlp_exporter,
            runtime::Tokio,
        )
        .build();
        meter_builder = meter_builder.with_reader(otlp_reader);

        let provider = init_otlp_tracer(endpoint, resource)?;
        let tracer = provider.tracer(config.service_name.clone());
        Some(tracing_opentelemetry::layer().with_tracer(tracer))
    } else {
        None
    };

    // Build and set the single global meter provider with all readers
    let meter_provider = meter_builder.build();
    global::set_meter_provider(meter_provider);

    // Build tracing subscriber
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,lattice=debug,kube=info,tower=warn,hyper=warn"));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(false)
        .with_target(true)
        .with_file(false)
        .with_line_number(false);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer)
        .try_init()
        .map_err(|e: tracing_subscriber::util::TryInitError| {
            TelemetryError::SubscriberInit(e.to_string())
        })?;

    Ok(prom_registry)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_config_default() {
        let config = TelemetryConfig {
            service_name: "test-service".to_string(),
            otlp_endpoint: None,
        };
        assert_eq!(config.service_name, "test-service");
        assert!(config.otlp_endpoint.is_none());
    }

    #[test]
    fn test_telemetry_config_with_endpoint() {
        let config = TelemetryConfig {
            service_name: "lattice".to_string(),
            otlp_endpoint: Some("http://localhost:4317".to_string()),
        };
        assert_eq!(
            config.otlp_endpoint,
            Some("http://localhost:4317".to_string())
        );
    }

    #[test]
    fn test_build_resource() {
        let resource = build_resource("test-service");
        // Resource should have at least the service name
        assert!(!resource.is_empty());
    }
}
