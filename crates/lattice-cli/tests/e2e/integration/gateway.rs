//! Gateway API integration tests - run against existing cluster
//!
//! Tests Gateway API resource generation and traffic routing through
//! Istio gateway proxies. Can be run standalone or composed by E2E tests.
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_gateway_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use kube::api::{Api, Patch, PatchParams};
use tracing::info;

use lattice_common::crd::LatticeService;

use super::super::gateway_fixtures::{
    create_backend_a, create_backend_b, create_backend_tls, create_gateway_traffic_gen,
    GATEWAY_TEST_NAMESPACE,
};
use super::super::gateway_helpers::{
    get_gateway_https_port, get_gateway_service_ip, verify_certificate, verify_gateway_listeners,
    verify_gateway_traffic, verify_httproute, verify_httproute_deleted, wait_for_gateway_cycles,
    wait_for_gateway_ready,
};
use super::super::helpers::{
    apply_cedar_policies_batch, client_from_kubeconfig, create_with_retry, ensure_fresh_namespace,
    ensure_test_cluster_issuer, patch_with_retry, run_kubectl, setup_regcreds_infrastructure,
    CedarPolicySpec,
};
use super::super::mesh_helpers::{retry_verification, wait_for_services_ready};

// =============================================================================
// Constants
// =============================================================================

const NUM_BACKEND_SERVICES: usize = 3;

// =============================================================================
// Public API
// =============================================================================

/// Run all gateway API integration tests.
///
/// Deploys backend services with ingress specs, verifies Gateway API resources
/// are created correctly, then deploys a traffic generator to verify actual
/// traffic flow through the gateway.
pub async fn run_gateway_tests(kubeconfig: &str) -> Result<(), String> {
    info!("\n========================================");
    info!("Gateway API Integration Tests");
    info!("========================================\n");

    setup_gateway_infrastructure(kubeconfig).await?;
    deploy_backend_services(kubeconfig).await?;
    verify_gateway_resources(kubeconfig).await?;

    let kc = kubeconfig.to_string();
    retry_verification("Gateway traffic", || verify_traffic_flow(&kc)).await?;

    let kc = kubeconfig.to_string();
    retry_verification("Gateway orphan cleanup", || verify_orphan_cleanup(&kc)).await?;

    info!("\n========================================");
    info!("Gateway API Integration Tests: PASSED");
    info!("========================================\n");

    Ok(())
}

// =============================================================================
// Setup
// =============================================================================

async fn setup_gateway_infrastructure(kubeconfig: &str) -> Result<(), String> {
    info!("[Gateway] Setting up test infrastructure...");

    ensure_fresh_namespace(kubeconfig, GATEWAY_TEST_NAMESPACE).await?;
    setup_regcreds_infrastructure(kubeconfig).await?;
    ensure_test_cluster_issuer(kubeconfig, "e2e-selfsigned").await?;

    // Cedar wildcard inbound policy — allows gateway proxy identity to reach backends
    let cedar_policies = vec![CedarPolicySpec {
        name: "permit-gateway-test-inbound".to_string(),
        test_label: "gateway-e2e".to_string(),
        priority: 50,
        cedar_text: format!(
            r#"permit(
  principal,
  action == Lattice::Action::"AccessService",
  resource
) when {{
  resource.namespace == "{ns}"
}};"#,
            ns = GATEWAY_TEST_NAMESPACE,
        ),
    }];

    apply_cedar_policies_batch(kubeconfig, cedar_policies, 5).await?;

    // Label namespace for Istio ambient mesh
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "label",
        "namespace",
        GATEWAY_TEST_NAMESPACE,
        "istio.io/dataplane-mode=ambient",
        "--overwrite",
    ])
    .await?;

    info!("[Gateway] Infrastructure ready");
    Ok(())
}

// =============================================================================
// Service Deployment
// =============================================================================

async fn deploy_backend_services(kubeconfig: &str) -> Result<(), String> {
    info!("[Gateway] Deploying backend services...");

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, GATEWAY_TEST_NAMESPACE);

    let services = vec![create_backend_a(), create_backend_b(), create_backend_tls()];

    for svc in &services {
        let name = svc.metadata.name.as_deref().unwrap_or("unknown");
        info!("[Gateway] Deploying {}...", name);
        create_with_retry(&api, svc, name).await?;
    }

    // Wait for all services to reach Ready
    wait_for_services_ready(kubeconfig, GATEWAY_TEST_NAMESPACE, NUM_BACKEND_SERVICES).await?;
    info!("[Gateway] All {} backend services are Ready", NUM_BACKEND_SERVICES);

    Ok(())
}

// =============================================================================
// Resource Verification
// =============================================================================

async fn verify_gateway_resources(kubeconfig: &str) -> Result<(), String> {
    info!("[Gateway] Verifying Gateway API resources...");

    // Wait for gateway to be ready
    wait_for_gateway_ready(kubeconfig, GATEWAY_TEST_NAMESPACE).await?;

    // Verify Gateway listeners
    // backend-a: public route -> http-0, https-0
    // backend-b: api route -> http-0, https-0; health route -> http-0, https-0
    // backend-tls: public route -> http-0, https-0
    let expected_listeners: Vec<String> = vec![
        // backend-a public route
        "backend-a-public-http-0".to_string(),
        // backend-b api route
        "backend-b-api-http-0".to_string(),
        // backend-b health route
        "backend-b-health-http-0".to_string(),
        // backend-tls public route (HTTP + HTTPS)
        "backend-tls-public-http-0".to_string(),
        "backend-tls-public-https-0".to_string(),
    ];
    let listener_refs: Vec<&str> = expected_listeners.iter().map(|s| s.as_str()).collect();
    verify_gateway_listeners(kubeconfig, GATEWAY_TEST_NAMESPACE, &listener_refs).await?;

    // Verify HTTPRoutes
    // backend-a: catch-all route
    verify_httproute(
        kubeconfig,
        GATEWAY_TEST_NAMESPACE,
        "backend-a-public-route",
        "backend-a.gateway-test.local",
        "backend-a",
        "8080",
    )
    .await?;

    // backend-b: api route
    verify_httproute(
        kubeconfig,
        GATEWAY_TEST_NAMESPACE,
        "backend-b-api-route",
        "backend-b.gateway-test.local",
        "backend-b",
        "8080",
    )
    .await?;

    // backend-b: health route
    verify_httproute(
        kubeconfig,
        GATEWAY_TEST_NAMESPACE,
        "backend-b-health-route",
        "backend-b.gateway-test.local",
        "backend-b",
        "8080",
    )
    .await?;

    // backend-tls: public route
    verify_httproute(
        kubeconfig,
        GATEWAY_TEST_NAMESPACE,
        "backend-tls-public-route",
        "secure.gateway-test.local",
        "backend-tls",
        "8080",
    )
    .await?;

    // Verify Certificate for backend-tls
    verify_certificate(
        kubeconfig,
        GATEWAY_TEST_NAMESPACE,
        "backend-tls-public-cert",
        "secure.gateway-test.local",
        "e2e-selfsigned",
    )
    .await?;

    info!("[Gateway] All Gateway API resources verified");
    Ok(())
}

// =============================================================================
// Traffic Verification
// =============================================================================

async fn verify_traffic_flow(kubeconfig: &str) -> Result<(), String> {
    info!("[Gateway] Deploying traffic generator and verifying traffic flow...");

    let gateway_ip = get_gateway_service_ip(kubeconfig, GATEWAY_TEST_NAMESPACE).await?;
    let gateway_https_port =
        get_gateway_https_port(kubeconfig, GATEWAY_TEST_NAMESPACE)
            .await
            .unwrap_or(443);

    info!(
        "[Gateway] Gateway IP: {}, HTTPS port: {}",
        gateway_ip, gateway_https_port
    );

    // Deploy traffic generator with the discovered gateway IP
    let traffic_gen = create_gateway_traffic_gen(&gateway_ip, gateway_https_port);
    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, GATEWAY_TEST_NAMESPACE);

    // Delete existing traffic gen if present (retry scenario)
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "latticeservice",
        "gateway-traffic-gen",
        "-n",
        GATEWAY_TEST_NAMESPACE,
        "--ignore-not-found",
    ])
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    create_with_retry(&api, &traffic_gen, "gateway-traffic-gen").await?;

    // Wait for traffic generator to complete cycles
    wait_for_gateway_cycles(kubeconfig, GATEWAY_TEST_NAMESPACE, "gateway-traffic-gen", 2).await?;

    // Verify traffic results
    verify_gateway_traffic(kubeconfig, GATEWAY_TEST_NAMESPACE, "gateway-traffic-gen").await?;

    info!("[Gateway] Traffic flow verified");
    Ok(())
}

// =============================================================================
// Orphan Cleanup Verification
// =============================================================================

async fn verify_orphan_cleanup(kubeconfig: &str) -> Result<(), String> {
    info!("[Gateway] Verifying orphan cleanup...");

    // Patch backend-a to remove spec.ingress
    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, GATEWAY_TEST_NAMESPACE);

    let patch = serde_json::json!({
        "spec": {
            "ingress": null
        }
    });

    patch_with_retry(
        &api,
        "backend-a",
        &PatchParams::default(),
        &Patch::Merge(patch),
    )
    .await?;

    info!("[Gateway] Removed ingress from backend-a, waiting for orphan cleanup...");

    // Verify the HTTPRoute for backend-a is deleted
    verify_httproute_deleted(
        kubeconfig,
        GATEWAY_TEST_NAMESPACE,
        "backend-a-public-route",
    )
    .await?;

    // Verify the Gateway still has backend-b and backend-tls listeners
    let remaining_listeners: Vec<String> = vec![
        "backend-b-api-http-0".to_string(),
        "backend-b-health-http-0".to_string(),
        "backend-tls-public-http-0".to_string(),
        "backend-tls-public-https-0".to_string(),
    ];
    let listener_refs: Vec<&str> = remaining_listeners.iter().map(|s| s.as_str()).collect();
    verify_gateway_listeners(kubeconfig, GATEWAY_TEST_NAMESPACE, &listener_refs).await?;

    info!("[Gateway] Orphan cleanup verified — backend-a route removed, others intact");
    Ok(())
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test - run gateway tests on existing cluster
#[tokio::test]
#[ignore]
async fn test_gateway_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_gateway_tests(&resolved.kubeconfig).await.unwrap();
}
