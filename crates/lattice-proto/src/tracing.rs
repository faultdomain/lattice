//! gRPC trace context propagation utilities
//!
//! Provides functions to inject and extract W3C Trace Context headers
//! for distributed tracing across the agent-cell gRPC stream.
//!
//! # W3C Trace Context
//!
//! The trace context is propagated via two fields:
//! - `traceparent`: Contains trace ID, span ID, and flags
//! - `tracestate`: Contains vendor-specific trace information
//!
//! Format: `00-{trace_id}-{span_id}-{trace_flags}`
//! - trace_id: 32 hex characters (128-bit)
//! - span_id: 16 hex characters (64-bit)
//! - trace_flags: 2 hex characters (8-bit, 01 = sampled)
//!
//! # Example
//!
//! ```ignore
//! use lattice_proto::tracing::{inject_context, extract_context};
//!
//! // In cell (sender): inject current trace context
//! let mut request = KubernetesRequest::default();
//! inject_context(&mut request);
//!
//! // In agent (receiver): extract and set as current
//! let ctx = extract_context(&request);
//! let _guard = ctx.attach();
//! // ... handle request with propagated trace context
//! ```

use opentelemetry::propagation::{Extractor, Injector};
use opentelemetry::{global, Context};

use crate::KubernetesRequest;

/// Carrier for injecting trace context into KubernetesRequest
struct RequestInjector<'a> {
    request: &'a mut KubernetesRequest,
}

impl Injector for RequestInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        match key.to_lowercase().as_str() {
            "traceparent" => self.request.traceparent = value,
            "tracestate" => self.request.tracestate = value,
            _ => {} // Ignore other headers
        }
    }
}

/// Carrier for extracting trace context from KubernetesRequest
struct RequestExtractor<'a> {
    request: &'a KubernetesRequest,
}

impl Extractor for RequestExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        match key.to_lowercase().as_str() {
            "traceparent" => {
                if self.request.traceparent.is_empty() {
                    None
                } else {
                    Some(&self.request.traceparent)
                }
            }
            "tracestate" => {
                if self.request.tracestate.is_empty() {
                    None
                } else {
                    Some(&self.request.tracestate)
                }
            }
            _ => None,
        }
    }

    fn keys(&self) -> Vec<&str> {
        let mut keys = Vec::new();
        if !self.request.traceparent.is_empty() {
            keys.push("traceparent");
        }
        if !self.request.tracestate.is_empty() {
            keys.push("tracestate");
        }
        keys
    }
}

/// Inject the current trace context into a KubernetesRequest
///
/// Uses the global text map propagator (typically W3C TraceContext) to
/// inject the current span's trace context into the request's traceparent
/// and tracestate fields.
///
/// # Example
///
/// ```ignore
/// use lattice_proto::tracing::inject_context;
///
/// let mut request = KubernetesRequest {
///     request_id: "123".to_string(),
///     verb: "GET".to_string(),
///     path: "/api/v1/pods".to_string(),
///     ..Default::default()
/// };
///
/// inject_context(&mut request);
/// // request.traceparent and request.tracestate are now populated
/// ```
pub fn inject_context(request: &mut KubernetesRequest) {
    let cx = Context::current();
    global::get_text_map_propagator(|propagator| {
        let mut injector = RequestInjector { request };
        propagator.inject_context(&cx, &mut injector);
    });
}

/// Extract trace context from a KubernetesRequest
///
/// Uses the global text map propagator (typically W3C TraceContext) to
/// extract trace context from the request's traceparent and tracestate fields.
///
/// Returns an OpenTelemetry Context that can be attached to continue the trace.
///
/// # Example
///
/// ```ignore
/// use lattice_proto::tracing::extract_context;
///
/// let request = KubernetesRequest {
///     traceparent: "00-abc123...-def456...-01".to_string(),
///     ..Default::default()
/// };
///
/// let ctx = extract_context(&request);
/// let _guard = ctx.attach();
/// // ... operations now use the extracted trace context
/// ```
pub fn extract_context(request: &KubernetesRequest) -> Context {
    global::get_text_map_propagator(|propagator| {
        let extractor = RequestExtractor { request };
        propagator.extract(&extractor)
    })
}

/// Check if a request has trace context
///
/// Returns true if the request has a non-empty traceparent field.
pub fn has_trace_context(request: &KubernetesRequest) -> bool {
    !request.traceparent.is_empty()
}

/// Get the trace ID from a request if present
///
/// Extracts the trace ID from the traceparent field if valid.
/// Returns None if no trace context or invalid format.
pub fn get_trace_id(request: &KubernetesRequest) -> Option<String> {
    if request.traceparent.is_empty() {
        return None;
    }

    // traceparent format: version-traceid-spanid-flags
    // Example: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
    let parts: Vec<&str> = request.traceparent.split('-').collect();
    if parts.len() >= 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// Get the span ID from a request if present
///
/// Extracts the parent span ID from the traceparent field if valid.
/// Returns None if no trace context or invalid format.
pub fn get_span_id(request: &KubernetesRequest) -> Option<String> {
    if request.traceparent.is_empty() {
        return None;
    }

    let parts: Vec<&str> = request.traceparent.split('-').collect();
    if parts.len() >= 3 {
        Some(parts[2].to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inject_extract_roundtrip() {
        // Without a real OTel setup, traceparent won't be set
        // This test verifies the carrier implementation works
        let mut request = KubernetesRequest::default();
        inject_context(&mut request);
        let _ctx = extract_context(&request);
        // Context should be valid (even if empty)
    }

    #[test]
    fn test_has_trace_context() {
        let mut request = KubernetesRequest::default();
        assert!(!has_trace_context(&request));

        request.traceparent = "00-abc123-def456-01".to_string();
        assert!(has_trace_context(&request));
    }

    #[test]
    fn test_get_trace_id() {
        let request = KubernetesRequest {
            traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string(),
            ..Default::default()
        };

        assert_eq!(
            get_trace_id(&request),
            Some("0af7651916cd43dd8448eb211c80319c".to_string())
        );
    }

    #[test]
    fn test_get_span_id() {
        let request = KubernetesRequest {
            traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string(),
            ..Default::default()
        };

        assert_eq!(get_span_id(&request), Some("b7ad6b7169203331".to_string()));
    }

    #[test]
    fn test_empty_traceparent() {
        let request = KubernetesRequest::default();
        assert!(get_trace_id(&request).is_none());
        assert!(get_span_id(&request).is_none());
    }

    #[test]
    fn test_extractor_keys() {
        let mut request = KubernetesRequest::default();
        let extractor = RequestExtractor { request: &request };
        assert!(extractor.keys().is_empty());

        request.traceparent = "test".to_string();
        let extractor = RequestExtractor { request: &request };
        assert_eq!(extractor.keys(), vec!["traceparent"]);

        request.tracestate = "test".to_string();
        let extractor = RequestExtractor { request: &request };
        assert_eq!(extractor.keys(), vec!["traceparent", "tracestate"]);
    }
}
