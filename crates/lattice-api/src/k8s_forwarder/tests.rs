use super::*;

fn make_request_with_headers(headers: Vec<(&str, &str)>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri("/test");
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder.body(Body::empty()).unwrap()
}

fn test_identity() -> UserIdentity {
    UserIdentity {
        username: "test-user".to_string(),
        groups: vec!["developers".to_string()],
    }
}

// ========================================================================
// Impersonation Header Stripping Tests
// ========================================================================

#[test]
fn test_strip_impersonation_user_header() {
    let request = make_request_with_headers(vec![
        ("Impersonate-User", "evil-user"),
        ("Content-Type", "application/json"),
    ]);

    let stripped = strip_impersonation_headers(request);

    assert!(stripped.headers().get("Impersonate-User").is_none());
    assert!(stripped.headers().get("Content-Type").is_some());
}

#[test]
fn test_strip_impersonation_group_header() {
    let request = make_request_with_headers(vec![
        ("Impersonate-Group", "admin-group"),
        ("Authorization", "Bearer token"),
    ]);

    let stripped = strip_impersonation_headers(request);

    assert!(stripped.headers().get("Impersonate-Group").is_none());
    assert!(stripped.headers().get("Authorization").is_some());
}

#[test]
fn test_strip_impersonation_uid_header() {
    let request = make_request_with_headers(vec![("Impersonate-Uid", "12345")]);

    let stripped = strip_impersonation_headers(request);

    assert!(stripped.headers().get("Impersonate-Uid").is_none());
}

#[test]
fn test_strip_impersonation_extra_headers() {
    let request = make_request_with_headers(vec![
        ("Impersonate-Extra-scopes", "read:write"),
        ("Impersonate-Extra-token", "secret"),
        ("X-Custom-Header", "keep-me"),
    ]);

    let stripped = strip_impersonation_headers(request);

    assert!(stripped.headers().get("Impersonate-Extra-scopes").is_none());
    assert!(stripped.headers().get("Impersonate-Extra-token").is_none());
    assert!(stripped.headers().get("X-Custom-Header").is_some());
}

#[test]
fn test_strip_all_impersonation_headers() {
    let request = make_request_with_headers(vec![
        ("Impersonate-User", "bad-user"),
        ("Impersonate-Group", "bad-group"),
        ("Impersonate-Uid", "123"),
        ("Impersonate-Extra-foo", "bar"),
        ("Content-Type", "application/json"),
        ("Accept", "application/json"),
    ]);

    let stripped = strip_impersonation_headers(request);

    assert!(stripped.headers().get("Impersonate-User").is_none());
    assert!(stripped.headers().get("Impersonate-Group").is_none());
    assert!(stripped.headers().get("Impersonate-Uid").is_none());
    assert!(stripped.headers().get("Impersonate-Extra-foo").is_none());
    assert!(stripped.headers().get("Content-Type").is_some());
    assert!(stripped.headers().get("Accept").is_some());
}

#[test]
fn test_preserves_non_impersonation_headers() {
    let request = make_request_with_headers(vec![
        ("Authorization", "Bearer token"),
        ("Content-Type", "application/json"),
        ("Accept", "application/json"),
        ("X-Request-Id", "abc123"),
    ]);

    let stripped = strip_impersonation_headers(request);

    assert_eq!(
        stripped.headers().get("Authorization").unwrap(),
        "Bearer token"
    );
    assert_eq!(
        stripped.headers().get("Content-Type").unwrap(),
        "application/json"
    );
    assert_eq!(
        stripped.headers().get("Accept").unwrap(),
        "application/json"
    );
    assert_eq!(stripped.headers().get("X-Request-Id").unwrap(), "abc123");
}

// ========================================================================
// K8s API Forwarding Tests (real business logic with mocked deps)
// ========================================================================

#[tokio::test]
async fn test_forward_to_k8s_api_success() {
    let mut mock_http = MockK8sHttpClient::new();
    let mut mock_token = MockTokenReader::new();

    mock_token
        .expect_read_token()
        .returning(|| Ok("test-sa-token".to_string()));

    mock_http.expect_request().returning(|req| {
        // Verify request was built correctly
        assert_eq!(req.method, "GET");
        assert!(req.url.contains("https://kubernetes.default.svc"));
        assert!(req.url.contains("/api/v1/pods"));
        assert_eq!(&*req.token, "test-sa-token");
        assert_eq!(req.identity.username, "test-user");
        assert!(req.identity.groups.contains(&"developers".to_string()));

        Ok(HttpResponse {
            status: 200,
            content_type: "application/json".to_string(),
            body: br#"{"items":[]}"#.to_vec(),
        })
    });

    let deps = ForwarderDeps {
        http_client: Arc::new(mock_http),
        token_reader: Arc::new(mock_token),
    };

    let request = Request::builder()
        .method("GET")
        .uri("/clusters/my-cluster/api/v1/pods")
        .body(Body::empty())
        .unwrap();

    let response = forward_to_k8s_api(
        "https://kubernetes.default.svc",
        "my-cluster",
        &test_identity(),
        request,
        &deps,
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_forward_to_k8s_api_token_failure() {
    let mock_http = MockK8sHttpClient::new();
    let mut mock_token = MockTokenReader::new();

    mock_token
        .expect_read_token()
        .returning(|| Err(Error::Internal("Token file not found".to_string())));

    let deps = ForwarderDeps {
        http_client: Arc::new(mock_http),
        token_reader: Arc::new(mock_token),
    };

    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/pods")
        .body(Body::empty())
        .unwrap();

    let result = forward_to_k8s_api(
        "https://kubernetes.default.svc",
        "my-cluster",
        &test_identity(),
        request,
        &deps,
    )
    .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::Internal(_)));
}

#[tokio::test]
async fn test_forward_to_k8s_api_http_error() {
    let mut mock_http = MockK8sHttpClient::new();
    let mut mock_token = MockTokenReader::new();

    mock_token
        .expect_read_token()
        .returning(|| Ok("token".to_string()));

    mock_http
        .expect_request()
        .returning(|_| Err(Error::Proxy("Connection refused".to_string())));

    let deps = ForwarderDeps {
        http_client: Arc::new(mock_http),
        token_reader: Arc::new(mock_token),
    };

    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/pods")
        .body(Body::empty())
        .unwrap();

    let result = forward_to_k8s_api(
        "https://kubernetes.default.svc",
        "my-cluster",
        &test_identity(),
        request,
        &deps,
    )
    .await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::Proxy(_)));
}

#[tokio::test]
async fn test_forward_to_k8s_api_with_query_params() {
    let mut mock_http = MockK8sHttpClient::new();
    let mut mock_token = MockTokenReader::new();

    mock_token
        .expect_read_token()
        .returning(|| Ok("token".to_string()));

    mock_http.expect_request().returning(|req| {
        // Verify query params are preserved
        assert!(req.url.contains("labelSelector=app%3Dnginx"));

        Ok(HttpResponse {
            status: 200,
            content_type: "application/json".to_string(),
            body: br#"{"items":[]}"#.to_vec(),
        })
    });

    let deps = ForwarderDeps {
        http_client: Arc::new(mock_http),
        token_reader: Arc::new(mock_token),
    };

    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/pods?labelSelector=app%3Dnginx")
        .body(Body::empty())
        .unwrap();

    let response = forward_to_k8s_api(
        "https://kubernetes.default.svc",
        "my-cluster",
        &test_identity(),
        request,
        &deps,
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_forward_to_k8s_api_with_body() {
    let mut mock_http = MockK8sHttpClient::new();
    let mut mock_token = MockTokenReader::new();

    mock_token
        .expect_read_token()
        .returning(|| Ok("token".to_string()));

    mock_http.expect_request().returning(|req| {
        assert_eq!(req.method, "POST");
        assert_eq!(req.content_type, Some("application/json".to_string()));
        let body_str = String::from_utf8(req.body).unwrap();
        assert!(body_str.contains("my-pod"));

        Ok(HttpResponse {
            status: 201,
            content_type: "application/json".to_string(),
            body: br#"{"metadata":{"name":"my-pod"}}"#.to_vec(),
        })
    });

    let deps = ForwarderDeps {
        http_client: Arc::new(mock_http),
        token_reader: Arc::new(mock_token),
    };

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/namespaces/default/pods")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"metadata":{"name":"my-pod"}}"#))
        .unwrap();

    let response = forward_to_k8s_api(
        "https://kubernetes.default.svc",
        "my-cluster",
        &test_identity(),
        request,
        &deps,
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_forward_to_k8s_api_403_forbidden() {
    let mut mock_http = MockK8sHttpClient::new();
    let mut mock_token = MockTokenReader::new();

    mock_token
        .expect_read_token()
        .returning(|| Ok("token".to_string()));

    mock_http.expect_request().returning(|_| {
        Ok(HttpResponse {
            status: 403,
            content_type: "application/json".to_string(),
            body: br#"{"message":"forbidden"}"#.to_vec(),
        })
    });

    let deps = ForwarderDeps {
        http_client: Arc::new(mock_http),
        token_reader: Arc::new(mock_token),
    };

    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/secrets")
        .body(Body::empty())
        .unwrap();

    let response = forward_to_k8s_api(
        "https://kubernetes.default.svc",
        "my-cluster",
        &test_identity(),
        request,
        &deps,
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ========================================================================
// Response Building Tests (actual logic)
// ========================================================================

#[test]
fn test_build_buffered_response_200() {
    let http_response = HttpResponse {
        status: 200,
        content_type: "application/json".to_string(),
        body: br#"{"items":[]}"#.to_vec(),
    };

    let response = build_buffered_response(http_response).unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("Content-Type").unwrap(),
        "application/json"
    );
}

#[test]
fn test_build_buffered_response_404() {
    let http_response = HttpResponse {
        status: 404,
        content_type: "application/json".to_string(),
        body: br#"{"message":"not found"}"#.to_vec(),
    };

    let response = build_buffered_response(http_response).unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[test]
fn test_build_buffered_response_invalid_status_code() {
    // Status codes must be 100-999; 99 is invalid
    let http_response = HttpResponse {
        status: 99,
        content_type: "application/json".to_string(),
        body: vec![],
    };

    let response = build_buffered_response(http_response).unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ========================================================================
// Error Conversion Tests
// ========================================================================

#[test]
fn test_proxy_error_to_api_error_send_failed() {
    let err = proxy_error_to_api_error(ProxyError::SendFailed("channel full".to_string()));
    assert!(matches!(err, Error::Proxy(_)));
}

#[test]
fn test_proxy_error_to_api_error_agent_disconnected() {
    let err = proxy_error_to_api_error(ProxyError::AgentDisconnected);
    assert!(matches!(err, Error::Proxy(_)));
}

#[test]
fn test_proxy_error_to_api_error_timeout() {
    let err = proxy_error_to_api_error(ProxyError::Timeout);
    assert!(matches!(err, Error::Proxy(_)));
}

#[test]
fn test_proxy_error_to_api_error_agent_error() {
    let err = proxy_error_to_api_error(ProxyError::AgentError("bad request".to_string()));
    assert!(matches!(err, Error::Proxy(_)));
}

#[test]
fn test_proxy_error_to_api_error_response_build() {
    let err = proxy_error_to_api_error(ProxyError::ResponseBuild("invalid".to_string()));
    assert!(matches!(err, Error::Internal(_)));
}

#[test]
fn test_proxy_error_to_api_error_cluster_not_found() {
    let err = proxy_error_to_api_error(ProxyError::ClusterNotFound("test-cluster".to_string()));
    assert!(matches!(err, Error::ClusterNotFound(_)));
}
