//! Integration tests for agent-cell communication stack
//!
//! Tests the full communication flow between agents and cells:
//! - Bootstrap HTTP endpoint
//! - Certificate signing flow
//! - Agent registration via gRPC

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tower::ServiceExt;

use lattice::agent::connection::AgentRegistry;
use lattice::agent::server::AgentServer;
use lattice::bootstrap::{bootstrap_router, BootstrapState, CsrRequest, DefaultManifestGenerator};
use lattice::pki::{AgentCertRequest, CertificateAuthority};
use lattice::proto::agent_message::Payload;
use lattice::proto::lattice_agent_client::LatticeAgentClient;
use lattice::proto::{AgentMessage, AgentReady, AgentState};

// =============================================================================
// Bootstrap HTTP Integration Tests
// =============================================================================

/// Full integration test: Bootstrap HTTP server handles complete flow
#[tokio::test]
async fn integration_bootstrap_http_full_flow() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    let ca = Arc::new(CertificateAuthority::new("Integration Test CA").unwrap());
    let state = Arc::new(BootstrapState::new(
        DefaultManifestGenerator::new().unwrap(),
        Duration::from_secs(3600),
        ca.clone(),
        "test:latest".to_string(),
        None,
    ));

    // Register a cluster
    let cluster_manifest = r#"{"apiVersion":"lattice.dev/v1alpha1","kind":"LatticeCluster","metadata":{"name":"integration-cluster"}}"#.to_string();
    let token = state.register_cluster(
        "integration-cluster".to_string(),
        "cell.test:8443:50051".to_string(),
        ca.ca_cert_pem().to_string(),
        cluster_manifest,
        None,
    );

    let router = bootstrap_router(state.clone());

    // Step 1: Get manifests with valid token (returns JSON for kubectl apply)
    let manifests_req = Request::builder()
        .method("GET")
        .uri("/api/clusters/integration-cluster/manifests")
        .header("authorization", format!("Bearer {}", token.as_str()))
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(manifests_req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let manifests_json = String::from_utf8(body.to_vec()).unwrap();

    // Should contain Kubernetes manifests (namespace, secrets, deployment)
    assert!(manifests_json.contains("\"kind\":\"Namespace\""));
    assert!(manifests_json.contains("lattice-system"));

    // Step 2: CSR signing after bootstrap
    let agent_req = AgentCertRequest::new("integration-cluster").unwrap();
    let csr_request = CsrRequest {
        csr_pem: agent_req.csr_pem().to_string(),
    };

    let csr_req = Request::builder()
        .method("POST")
        .uri("/api/clusters/integration-cluster/csr")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&csr_request).unwrap()))
        .unwrap();

    let response = router.oneshot(csr_req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let csr_response: lattice::bootstrap::CsrResponse = serde_json::from_slice(&body).unwrap();

    assert!(csr_response.certificate_pem.contains("BEGIN CERTIFICATE"));
}

/// Integration test: Bootstrap token replay is blocked
#[tokio::test]
async fn integration_bootstrap_token_replay_blocked() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    let ca = Arc::new(CertificateAuthority::new("Replay Test CA").unwrap());
    let state = Arc::new(BootstrapState::new(
        DefaultManifestGenerator::new().unwrap(),
        Duration::from_secs(3600),
        ca.clone(),
        "test:latest".to_string(),
        None,
    ));

    let cluster_manifest = r#"{"apiVersion":"lattice.dev/v1alpha1","kind":"LatticeCluster","metadata":{"name":"replay-test"}}"#.to_string();
    let token = state.register_cluster(
        "replay-test".to_string(),
        "cell:8443:50051".to_string(),
        ca.ca_cert_pem().to_string(),
        cluster_manifest,
        None,
    );

    let router = bootstrap_router(state);

    // First request succeeds
    let req1 = Request::builder()
        .method("GET")
        .uri("/api/clusters/replay-test/manifests")
        .header("authorization", format!("Bearer {}", token.as_str()))
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(req1).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Second request with same token fails (replay attack blocked)
    let req2 = Request::builder()
        .method("GET")
        .uri("/api/clusters/replay-test/manifests")
        .header("authorization", format!("Bearer {}", token.as_str()))
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req2).await.unwrap();
    assert_eq!(response.status(), StatusCode::GONE); // Token already used
}

// =============================================================================
// Full Stack Integration Test
// =============================================================================

/// Integration test: Complete bootstrap -> gRPC -> ready flow
#[tokio::test]
async fn integration_full_stack_bootstrap_to_ready() {
    // Step 1: Setup bootstrap server
    let ca = Arc::new(CertificateAuthority::new("Full Stack CA").unwrap());
    let bootstrap_state = Arc::new(BootstrapState::new(
        DefaultManifestGenerator::new().unwrap(),
        Duration::from_secs(3600),
        ca.clone(),
        "test:latest".to_string(),
        None,
    ));

    let cluster_manifest = r#"{"apiVersion":"lattice.dev/v1alpha1","kind":"LatticeCluster","metadata":{"name":"full-stack-test"}}"#.to_string();
    let token = bootstrap_state.register_cluster(
        "full-stack-test".to_string(),
        "cell:8443:50051".to_string(),
        ca.ca_cert_pem().to_string(),
        cluster_manifest,
        None,
    );

    // Step 2: Bootstrap (get manifests and CA cert)
    let info = bootstrap_state
        .validate_and_consume("full-stack-test", token.as_str())
        .unwrap();
    let bootstrap_response = bootstrap_state.generate_response(&info);

    assert!(!bootstrap_response.manifests.is_empty());
    assert!(!bootstrap_response.ca_certificate.is_empty());

    // Step 3: Agent generates certificate
    let agent_req = AgentCertRequest::new("full-stack-test").unwrap();
    let csr_response = bootstrap_state
        .sign_csr("full-stack-test", agent_req.csr_pem())
        .unwrap();

    assert!(csr_response.certificate_pem.contains("BEGIN CERTIFICATE"));

    // Step 4: Verify certificate is valid
    let cert_der = lattice::pki::parse_pem(&csr_response.certificate_pem).unwrap();
    let verification = lattice::pki::verify_client_cert(&cert_der, ca.ca_cert_pem()).unwrap();

    assert!(verification.valid);
    assert_eq!(verification.cluster_id, "full-stack-test");

    // Step 5: Setup gRPC server
    let registry = Arc::new(AgentRegistry::new());
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let registry_clone = registry.clone();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual_addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let server = AgentServer::new(registry_clone);
        tonic::transport::Server::builder()
            .add_service(server.into_service())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Step 6: Connect and register via gRPC
    let endpoint = format!("http://{}", actual_addr);
    let channel = Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = LatticeAgentClient::new(channel);

    let (tx, rx) = mpsc::channel::<AgentMessage>(32);
    let outbound = ReceiverStream::new(rx);

    let _response = client.stream_messages(outbound).await.unwrap();

    tx.send(AgentMessage {
        cluster_name: "full-stack-test".to_string(),
        payload: Some(Payload::Ready(AgentReady {
            agent_version: "1.0.0".to_string(),
            kubernetes_version: "1.30.0".to_string(),
            state: AgentState::Provisioning.into(),
            api_server_endpoint: "https://full-stack:6443".to_string(),
        })),
    })
    .await
    .unwrap();

    // Step 7: Verify agent registered
    tokio::time::sleep(Duration::from_millis(100)).await;
    let conn = registry.get("full-stack-test").unwrap();
    assert_eq!(conn.agent_version, "1.0.0");
    assert_eq!(conn.cluster_name, "full-stack-test");

    server_handle.abort();
}
