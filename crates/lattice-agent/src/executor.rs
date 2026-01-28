//! K8s API request executor
//!
//! Executes Kubernetes API requests against the local cluster and returns responses.
//! Single requests return immediately, watch requests are handled by the watch module.

use kube::Client;
use lattice_proto::{KubernetesRequest, KubernetesResponse};
use tracing::{debug, error};

/// Check if a request is a watch request
pub fn is_watch_request(req: &KubernetesRequest) -> bool {
    req.query.contains("watch=true") || req.query.contains("watch=1")
}

/// Build the URL from path and query
fn build_url(path: &str, query: &str) -> String {
    if query.is_empty() {
        path.to_string()
    } else {
        format!("{}?{}", path, query)
    }
}

/// Response type for request building
pub enum RequestBuildResult {
    /// Successfully built the request
    Request(http::Request<Vec<u8>>),
    /// Request should return early with this response
    EarlyReturn(KubernetesResponse),
}

/// Build an HTTP request from a KubernetesRequest (pure function)
///
/// Returns either a built request or an early-return response for error/special cases.
pub fn build_http_request(req: &KubernetesRequest) -> RequestBuildResult {
    // Handle cancellation requests
    if req.cancel {
        return RequestBuildResult::EarlyReturn(KubernetesResponse {
            request_id: req.request_id.clone(),
            status_code: 200,
            streaming: true,
            stream_end: true,
            ..Default::default()
        });
    }

    // Watch requests should be handled by execute_watch, not this function
    if is_watch_request(req) {
        return RequestBuildResult::EarlyReturn(KubernetesResponse {
            request_id: req.request_id.clone(),
            status_code: 400,
            error: "Watch requests should use execute_watch".to_string(),
            ..Default::default()
        });
    }

    let url = build_url(&req.path, &req.query);

    // Build HTTP request
    let builder = match req.verb.to_uppercase().as_str() {
        "GET" | "LIST" => http::Request::get(&url),
        "POST" => http::Request::post(&url),
        "PUT" => http::Request::put(&url),
        "PATCH" => http::Request::patch(&url),
        "DELETE" => http::Request::delete(&url),
        _ => {
            return RequestBuildResult::EarlyReturn(KubernetesResponse {
                request_id: req.request_id.clone(),
                status_code: 400,
                error: format!("Unsupported verb: {}", req.verb),
                ..Default::default()
            });
        }
    };

    let request = if !req.body.is_empty() {
        let content_type = if req.content_type.is_empty() {
            "application/json"
        } else {
            &req.content_type
        };
        builder
            .header(http::header::CONTENT_TYPE, content_type)
            .body(req.body.clone())
    } else {
        builder.body(Vec::new())
    };

    match request {
        Ok(r) => RequestBuildResult::Request(r),
        Err(e) => RequestBuildResult::EarlyReturn(KubernetesResponse {
            request_id: req.request_id.clone(),
            status_code: 400,
            error: format!("Failed to build request: {}", e),
            ..Default::default()
        }),
    }
}

/// Build a success response from a JSON value (pure function)
pub fn build_success_response(request_id: &str, value: &serde_json::Value) -> KubernetesResponse {
    let body = serde_json::to_vec(value).unwrap_or_default();
    KubernetesResponse {
        request_id: request_id.to_string(),
        status_code: 200,
        body,
        content_type: "application/json".to_string(),
        ..Default::default()
    }
}

/// Build an error response from a kube error (pure function)
pub fn build_error_response(request_id: &str, e: &kube::Error) -> KubernetesResponse {
    let (status_code, error_body) = match e {
        kube::Error::Api(api_err) => {
            let body = serde_json::to_vec(api_err).unwrap_or_default();
            (api_err.code, body)
        }
        _ => (500, Vec::new()),
    };
    KubernetesResponse {
        request_id: request_id.to_string(),
        status_code: status_code as u32,
        body: error_body,
        content_type: "application/json".to_string(),
        error: e.to_string(),
        ..Default::default()
    }
}

/// Execute a single (non-watch) K8s API request against the local cluster
pub async fn execute_k8s_request(client: &Client, req: &KubernetesRequest) -> KubernetesResponse {
    // Build the request (pure logic)
    let http_request = match build_http_request(req) {
        RequestBuildResult::EarlyReturn(response) => return response,
        RequestBuildResult::Request(r) => r,
    };

    debug!(
        request_id = %req.request_id,
        verb = %req.verb,
        path = %req.path,
        "Executing K8s API request"
    );

    // Execute the request (impure)
    match client.request::<serde_json::Value>(http_request).await {
        Ok(value) => build_success_response(&req.request_id, &value),
        Err(e) => {
            error!(
                request_id = %req.request_id,
                error = %e,
                "K8s API request failed"
            );
            build_error_response(&req.request_id, &e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // is_watch_request Tests
    // =========================================================================

    #[test]
    fn test_is_watch_request() {
        let req = KubernetesRequest {
            query: "watch=true".to_string(),
            ..Default::default()
        };
        assert!(is_watch_request(&req));

        let req = KubernetesRequest {
            query: "watch=1".to_string(),
            ..Default::default()
        };
        assert!(is_watch_request(&req));

        let req = KubernetesRequest {
            query: "labelSelector=app%3Dtest".to_string(),
            ..Default::default()
        };
        assert!(!is_watch_request(&req));
    }

    #[test]
    fn test_is_watch_request_with_other_params() {
        let req = KubernetesRequest {
            query: "labelSelector=app%3Dtest&watch=true".to_string(),
            ..Default::default()
        };
        assert!(is_watch_request(&req));
    }

    #[test]
    fn test_is_watch_request_false_positive() {
        // Make sure "watch=false" doesn't trigger
        let req = KubernetesRequest {
            query: "watch=false".to_string(),
            ..Default::default()
        };
        assert!(!is_watch_request(&req));
    }

    #[test]
    fn test_is_watch_request_empty_query() {
        let req = KubernetesRequest {
            query: String::new(),
            ..Default::default()
        };
        assert!(!is_watch_request(&req));
    }

    // =========================================================================
    // build_url Tests
    // =========================================================================

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

    // =========================================================================
    // build_http_request Tests
    // =========================================================================

    #[test]
    fn test_build_http_request_cancel() {
        let req = KubernetesRequest {
            request_id: "test-123".to_string(),
            cancel: true,
            ..Default::default()
        };

        match build_http_request(&req) {
            RequestBuildResult::EarlyReturn(resp) => {
                assert_eq!(resp.request_id, "test-123");
                assert_eq!(resp.status_code, 200);
                assert!(resp.streaming);
                assert!(resp.stream_end);
            }
            RequestBuildResult::Request(_) => panic!("Expected early return"),
        }
    }

    #[test]
    fn test_build_http_request_watch() {
        let req = KubernetesRequest {
            request_id: "test-watch".to_string(),
            query: "watch=true".to_string(),
            ..Default::default()
        };

        match build_http_request(&req) {
            RequestBuildResult::EarlyReturn(resp) => {
                assert_eq!(resp.request_id, "test-watch");
                assert_eq!(resp.status_code, 400);
                assert!(resp.error.contains("execute_watch"));
            }
            RequestBuildResult::Request(_) => panic!("Expected early return"),
        }
    }

    #[test]
    fn test_build_http_request_unsupported_verb() {
        let req = KubernetesRequest {
            request_id: "test-verb".to_string(),
            verb: "CONNECT".to_string(),
            path: "/api/v1/pods".to_string(),
            ..Default::default()
        };

        match build_http_request(&req) {
            RequestBuildResult::EarlyReturn(resp) => {
                assert_eq!(resp.request_id, "test-verb");
                assert_eq!(resp.status_code, 400);
                assert!(resp.error.contains("Unsupported verb"));
                assert!(resp.error.contains("CONNECT"));
            }
            RequestBuildResult::Request(_) => panic!("Expected early return"),
        }
    }

    #[test]
    fn test_build_http_request_get() {
        let req = KubernetesRequest {
            request_id: "test-get".to_string(),
            verb: "GET".to_string(),
            path: "/api/v1/pods".to_string(),
            ..Default::default()
        };

        match build_http_request(&req) {
            RequestBuildResult::Request(http_req) => {
                assert_eq!(http_req.method(), http::Method::GET);
                assert_eq!(http_req.uri(), "/api/v1/pods");
            }
            RequestBuildResult::EarlyReturn(_) => panic!("Expected request"),
        }
    }

    #[test]
    fn test_build_http_request_post_with_body() {
        let req = KubernetesRequest {
            request_id: "test-post".to_string(),
            verb: "POST".to_string(),
            path: "/api/v1/namespaces/default/pods".to_string(),
            body: b"{\"spec\":{}}".to_vec(),
            content_type: "application/json".to_string(),
            ..Default::default()
        };

        match build_http_request(&req) {
            RequestBuildResult::Request(http_req) => {
                assert_eq!(http_req.method(), http::Method::POST);
                assert_eq!(
                    http_req.headers().get(http::header::CONTENT_TYPE).unwrap(),
                    "application/json"
                );
                assert_eq!(http_req.body(), b"{\"spec\":{}}");
            }
            RequestBuildResult::EarlyReturn(_) => panic!("Expected request"),
        }
    }

    #[test]
    fn test_build_http_request_patch() {
        let req = KubernetesRequest {
            request_id: "test-patch".to_string(),
            verb: "PATCH".to_string(),
            path: "/api/v1/pods/mypod".to_string(),
            body: b"[{\"op\":\"add\"}]".to_vec(),
            content_type: "application/json-patch+json".to_string(),
            ..Default::default()
        };

        match build_http_request(&req) {
            RequestBuildResult::Request(http_req) => {
                assert_eq!(http_req.method(), http::Method::PATCH);
                assert_eq!(
                    http_req.headers().get(http::header::CONTENT_TYPE).unwrap(),
                    "application/json-patch+json"
                );
            }
            RequestBuildResult::EarlyReturn(_) => panic!("Expected request"),
        }
    }

    #[test]
    fn test_build_http_request_delete() {
        let req = KubernetesRequest {
            request_id: "test-delete".to_string(),
            verb: "DELETE".to_string(),
            path: "/api/v1/pods/mypod".to_string(),
            ..Default::default()
        };

        match build_http_request(&req) {
            RequestBuildResult::Request(http_req) => {
                assert_eq!(http_req.method(), http::Method::DELETE);
            }
            RequestBuildResult::EarlyReturn(_) => panic!("Expected request"),
        }
    }

    #[test]
    fn test_build_http_request_put() {
        let req = KubernetesRequest {
            request_id: "test-put".to_string(),
            verb: "PUT".to_string(),
            path: "/api/v1/pods/mypod".to_string(),
            body: b"{\"spec\":{}}".to_vec(),
            ..Default::default()
        };

        match build_http_request(&req) {
            RequestBuildResult::Request(http_req) => {
                assert_eq!(http_req.method(), http::Method::PUT);
                // Default content type should be applied
                assert_eq!(
                    http_req.headers().get(http::header::CONTENT_TYPE).unwrap(),
                    "application/json"
                );
            }
            RequestBuildResult::EarlyReturn(_) => panic!("Expected request"),
        }
    }

    #[test]
    fn test_build_http_request_list() {
        let req = KubernetesRequest {
            request_id: "test-list".to_string(),
            verb: "LIST".to_string(),
            path: "/api/v1/pods".to_string(),
            query: "limit=100".to_string(),
            ..Default::default()
        };

        match build_http_request(&req) {
            RequestBuildResult::Request(http_req) => {
                assert_eq!(http_req.method(), http::Method::GET);
                assert_eq!(http_req.uri(), "/api/v1/pods?limit=100");
            }
            RequestBuildResult::EarlyReturn(_) => panic!("Expected request"),
        }
    }

    #[test]
    fn test_build_http_request_lowercase_verb() {
        let req = KubernetesRequest {
            request_id: "test-lower".to_string(),
            verb: "get".to_string(),
            path: "/api/v1/pods".to_string(),
            ..Default::default()
        };

        match build_http_request(&req) {
            RequestBuildResult::Request(http_req) => {
                assert_eq!(http_req.method(), http::Method::GET);
            }
            RequestBuildResult::EarlyReturn(_) => panic!("Expected request"),
        }
    }

    // =========================================================================
    // build_success_response Tests
    // =========================================================================

    #[test]
    fn test_build_success_response() {
        let value = serde_json::json!({"kind": "Pod", "metadata": {"name": "test"}});
        let resp = build_success_response("req-123", &value);

        assert_eq!(resp.request_id, "req-123");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.content_type, "application/json");
        assert!(!resp.body.is_empty());

        // Verify the body deserializes correctly
        let parsed: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(parsed["kind"], "Pod");
    }

    // =========================================================================
    // Default Tests
    // =========================================================================

    #[test]
    fn test_kubernetes_request_defaults() {
        let req = KubernetesRequest::default();
        assert!(req.request_id.is_empty());
        assert!(req.path.is_empty());
        assert!(req.query.is_empty());
        assert!(req.verb.is_empty());
        assert!(req.body.is_empty());
        assert!(!req.cancel);
    }

    #[test]
    fn test_kubernetes_response_defaults() {
        let resp = KubernetesResponse::default();
        assert!(resp.request_id.is_empty());
        assert_eq!(resp.status_code, 0);
        assert!(resp.body.is_empty());
        assert!(!resp.streaming);
        assert!(!resp.stream_end);
    }
}
