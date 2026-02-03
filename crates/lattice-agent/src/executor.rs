//! K8s API request executor
//!
//! Executes Kubernetes API requests against the local cluster and returns responses.
//! Acts as a pure L4 proxy - forwards raw bytes without parsing.

use http::Request;
use kube::client::Body;
use kube::Client;
use lattice_proto::{is_watch_query, KubernetesRequest, KubernetesResponse};
use tracing::{debug, error, instrument};

use crate::build_grpc_error_response;

/// Check if a request is a streaming request (watch or follow).
pub fn is_watch_request(req: &KubernetesRequest) -> bool {
    is_watch_query(&req.query)
}

/// Build the URL from path and query
pub(crate) fn build_url(path: &str, query: &str) -> String {
    if query.is_empty() {
        path.to_string()
    } else {
        format!("{}?{}", path, query)
    }
}

/// Execute a single (non-watch) K8s API request against the local cluster.
///
/// This is a pure L4 proxy - it forwards raw bytes and preserves response headers.
#[instrument(
    skip(client, req),
    fields(
        request_id = %req.request_id,
        verb = %req.verb,
        path = %req.path,
        trace_id = lattice_proto::tracing::get_trace_id(req).unwrap_or_default(),
        otel.kind = "server"
    )
)]
pub async fn execute_k8s_request(client: &Client, req: &KubernetesRequest) -> KubernetesResponse {
    // Extract trace context from request if present
    let _ctx = lattice_proto::tracing::extract_context(req);
    // Handle cancellation requests
    if req.cancel {
        return KubernetesResponse {
            request_id: req.request_id.clone(),
            status_code: 200,
            streaming: true,
            stream_end: true,
            ..Default::default()
        };
    }

    // Watch requests should be handled by execute_watch, not this function
    if is_watch_request(req) {
        return build_grpc_error_response(
            &req.request_id,
            400,
            "Watch requests should use execute_watch",
        );
    }

    let url = build_url(&req.path, &req.query);

    debug!(
        request_id = %req.request_id,
        verb = %req.verb,
        path = %req.path,
        "Executing K8s API request (L4 proxy)"
    );

    // Build HTTP request
    let method = match req.verb.to_uppercase().as_str() {
        "GET" | "LIST" => http::Method::GET,
        "POST" => http::Method::POST,
        "PUT" => http::Method::PUT,
        "PATCH" => http::Method::PATCH,
        "DELETE" => http::Method::DELETE,
        _ => {
            return build_grpc_error_response(
                &req.request_id,
                400,
                &format!("Unsupported verb: {}", req.verb),
            );
        }
    };

    // Build the request with all headers
    let mut builder = Request::builder().method(method).uri(&url);

    // Add Accept header - critical for content negotiation (aggregated discovery)
    let accept = if req.accept.is_empty() {
        "application/json"
    } else {
        &req.accept
    };
    builder = builder.header(http::header::ACCEPT, accept);

    // Add Content-Type if there's a body
    if !req.body.is_empty() {
        let content_type = if req.content_type.is_empty() {
            "application/json"
        } else {
            &req.content_type
        };
        builder = builder.header(http::header::CONTENT_TYPE, content_type);
    }

    // Build request with kube::client::Body
    let body = Body::from(req.body.clone());
    let http_request = match builder.body(body) {
        Ok(r) => r,
        Err(e) => {
            return build_grpc_error_response(
                &req.request_id,
                400,
                &format!("Failed to build request: {}", e),
            );
        }
    };

    // Use client.send() to get full HTTP response with headers preserved
    match client.send(http_request).await {
        Ok(response) => {
            let status_code = response.status().as_u16() as u32;

            // Preserve the actual Content-Type from the response
            // This is critical for kubectl's aggregated discovery to work
            let content_type = response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_string();

            // Collect the response body
            match response.into_body().collect_bytes().await {
                Ok(bytes) => KubernetesResponse {
                    request_id: req.request_id.clone(),
                    status_code,
                    body: bytes.to_vec(),
                    content_type,
                    ..Default::default()
                },
                Err(e) => {
                    error!(
                        request_id = %req.request_id,
                        error = %e,
                        "Failed to read response body"
                    );
                    build_grpc_error_response(
                        &req.request_id,
                        502,
                        &format!("Failed to read response: {}", e),
                    )
                }
            }
        }
        Err(e) => {
            error!(
                request_id = %req.request_id,
                error = %e,
                "K8s API request failed"
            );
            build_grpc_error_response(&req.request_id, 502, &format!("Request failed: {}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_watch_request_delegates_to_is_watch_query() {
        let req = KubernetesRequest {
            query: "watch=true".to_string(),
            ..Default::default()
        };
        assert!(is_watch_request(&req));

        let req = KubernetesRequest {
            query: String::new(),
            ..Default::default()
        };
        assert!(!is_watch_request(&req));
    }

    #[test]
    fn test_build_url_without_query() {
        assert_eq!(build_url("/api/v1/pods", ""), "/api/v1/pods");
    }

    #[test]
    fn test_build_url_with_query() {
        assert_eq!(
            build_url("/api/v1/pods", "labelSelector=app%3Dtest"),
            "/api/v1/pods?labelSelector=app%3Dtest"
        );
    }
}
