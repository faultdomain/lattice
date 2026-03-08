//! Mesh removal integration tests
//!
//! Tests the operator's garbage-collection behavior when services are modified
//! or deleted. Covers:
//! - Removing all inbound allows from a service
//! - Removing wildcard inbound from a service
//! - Deleting a LatticeService entirely
//! - Removing an external outbound dependency
//!
//! Each step verifies both traffic denial AND Kubernetes resource cleanup.

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;

use futures::future::try_join_all;
use kube::api::Api;
use tracing::info;

use lattice_common::crd::{LatticeService, ParsedEndpoint, ResourceSpec};

use super::helpers::{
    apply_cedar_policies_batch, apply_mesh_wildcard_inbound_policy, client_from_kubeconfig,
    create_with_retry, delete_namespace, ensure_fresh_namespace, setup_regcreds_infrastructure,
    CedarPolicySpec, DEFAULT_TIMEOUT,
};
use super::mesh_fixtures::{
    build_lattice_service, curl_container, external_outbound_dep, inbound_allow, inbound_allow_all,
    nginx_container, outbound_dep,
};
use super::mesh_helpers::{
    delete_lattice_service, generate_test_script, remove_resources, retry_verification,
    verify_resource_absent, wait_for_edges_denied, wait_for_pods_running, wait_for_services_ready,
    DiagnosticContext, RemovedEdge, TestTarget,
};

// =============================================================================
// Constants
// =============================================================================

const NAMESPACE: &str = "mesh-removal";
const EXTERNAL_URL: &str = "https://httpbin.org/status/200";
const EXTERNAL_RESOURCE_KEY: &str = "httpbin";

/// 4 services: rm-client (traffic gen), rm-internal, rm-wildcard, rm-delete-target
const SERVICE_COUNT: usize = 4;

// =============================================================================
// Service Factories
// =============================================================================

fn create_rm_client() -> LatticeService {
    let targets = vec![
        TestTarget::internal("rm-internal", NAMESPACE, true, "bilateral agreement"),
        TestTarget::internal(
            "rm-wildcard",
            NAMESPACE,
            true,
            "wildcard allows all with outbound",
        ),
        TestTarget::internal("rm-delete-target", NAMESPACE, true, "bilateral agreement"),
        TestTarget::with_url("rm-client", EXTERNAL_RESOURCE_KEY, EXTERNAL_URL, true),
    ];

    let script = generate_test_script("rm-client", targets);

    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    // Internal outbound deps
    for name in ["rm-internal", "rm-wildcard", "rm-delete-target"] {
        let (key, spec) = outbound_dep(name);
        resources.insert(key, spec);
    }
    // External outbound dep
    let (key, spec) = external_outbound_dep(EXTERNAL_RESOURCE_KEY, EXTERNAL_URL);
    resources.insert(key, spec);

    build_lattice_service(
        "rm-client",
        NAMESPACE,
        resources,
        false,
        curl_container(script),
    )
}

fn create_rm_internal() -> LatticeService {
    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (key, spec) = inbound_allow("rm-client");
    resources.insert(key, spec);
    build_lattice_service("rm-internal", NAMESPACE, resources, true, nginx_container())
}

fn create_rm_wildcard() -> LatticeService {
    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (key, spec) = inbound_allow_all();
    resources.insert(key, spec);
    build_lattice_service("rm-wildcard", NAMESPACE, resources, true, nginx_container())
}

fn create_rm_delete_target() -> LatticeService {
    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (key, spec) = inbound_allow("rm-client");
    resources.insert(key, spec);
    build_lattice_service(
        "rm-delete-target",
        NAMESPACE,
        resources,
        true,
        nginx_container(),
    )
}

// =============================================================================
// Deployment
// =============================================================================

async fn deploy_removal_services(kubeconfig: &str) -> Result<(), String> {
    ensure_fresh_namespace(kubeconfig, NAMESPACE).await?;
    setup_regcreds_infrastructure(kubeconfig).await?;

    // Cedar policies: wildcard inbound for rm-wildcard + external endpoint for rm-client
    let mut cedar_policies = Vec::new();

    // Wildcard inbound
    apply_mesh_wildcard_inbound_policy(kubeconfig, NAMESPACE, "rm-wildcard").await?;

    // External endpoint access
    if let Some(ep) = ParsedEndpoint::parse(EXTERNAL_URL) {
        cedar_policies.push(CedarPolicySpec {
            name: format!("permit-ext-{}-rm-client", NAMESPACE),
            test_label: "mesh-removal".to_string(),
            priority: 100,
            cedar_text: format!(
                r#"permit(
  principal == Lattice::Service::"{namespace}/rm-client",
  action == Lattice::Action::"AccessExternalEndpoint",
  resource
) when {{
  resource == Lattice::ExternalEndpoint::"{host}:{port}"
}};"#,
                namespace = NAMESPACE,
                host = ep.host,
                port = ep.port,
            ),
        });
    }

    if !cedar_policies.is_empty() {
        apply_cedar_policies_batch(kubeconfig, cedar_policies, 5).await?;
    }

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, NAMESPACE);

    let all_services: Vec<(&str, LatticeService)> = vec![
        ("rm-internal", create_rm_internal()),
        ("rm-wildcard", create_rm_wildcard()),
        ("rm-delete-target", create_rm_delete_target()),
        ("rm-client", create_rm_client()),
    ];

    info!(
        "[Mesh Removal] Deploying {} services...",
        all_services.len()
    );
    try_join_all(all_services.into_iter().map(|(name, svc)| {
        let api = api.clone();
        async move { create_with_retry(&api, &svc, name).await }
    }))
    .await?;

    info!("[Mesh Removal] All services deployed");
    Ok(())
}

// =============================================================================
// Verification Helpers
// =============================================================================

/// Build a RemovedEdge for rm-client -> target using internal log format.
fn removal_edge(target: &str) -> RemovedEdge {
    RemovedEdge {
        source: "rm-client".to_string(),
        allowed_pattern: format!("{}: ALLOWED", target),
        blocked_pattern: format!("{}: BLOCKED", target),
    }
}

/// Build a RemovedEdge for rm-client -> external target using with_url log format.
fn removal_edge_external(target_key: &str) -> RemovedEdge {
    RemovedEdge {
        source: "rm-client".to_string(),
        allowed_pattern: format!("rm-client->{}:ALLOWED", target_key),
        blocked_pattern: format!("rm-client->{}:BLOCKED", target_key),
    }
}

// =============================================================================
// Test Phases
// =============================================================================

/// Phase 1: Verify all connections are ALLOWED at baseline.
async fn verify_baseline(kubeconfig: &str) -> Result<(), String> {
    info!("[Mesh Removal] Phase 1: Verifying baseline — all connections ALLOWED...");

    // All 4 connections: rm-internal, rm-wildcard, rm-delete-target, httpbin
    let edges = vec![
        removal_edge("rm-internal"),
        removal_edge("rm-wildcard"),
        removal_edge("rm-delete-target"),
        removal_edge_external(EXTERNAL_RESOURCE_KEY),
    ];

    // Invert the check: wait for all edges to show ALLOWED (not denied).
    // We reuse retry_verification with a custom check.
    let kc = kubeconfig.to_string();
    let svc_names: Vec<String> = Vec::new();
    let diag = DiagnosticContext {
        kubeconfig,
        namespace: NAMESPACE,
        service_names: &svc_names,
    };
    retry_verification("Mesh Removal Baseline", Some(&diag), || {
        let kc = kc.clone();
        let edges = edges.clone();
        async move {
            use super::helpers::run_kubectl;
            use super::mesh_helpers::parse_traffic_result;

            let logs = run_kubectl(&[
                "--kubeconfig",
                &kc,
                "logs",
                "-n",
                NAMESPACE,
                "-l",
                &format!("{}=rm-client", lattice_common::LABEL_NAME),
                "--tail",
                "500",
            ])
            .await
            .unwrap_or_default();

            let mut failures = Vec::new();
            for edge in &edges {
                match parse_traffic_result(&logs, &edge.allowed_pattern, &edge.blocked_pattern) {
                    Some(true) => {} // ALLOWED — good
                    Some(false) => {
                        failures.push(format!("{}: still BLOCKED", edge.allowed_pattern))
                    }
                    None => failures.push(format!("{}: no result yet", edge.allowed_pattern)),
                }
            }

            if failures.is_empty() {
                Ok(())
            } else {
                Err(format!("Baseline not ready: {}", failures.join("; ")))
            }
        }
    })
    .await?;

    info!("[Mesh Removal] Phase 1: Baseline verified — all connections ALLOWED");
    Ok(())
}

/// Phase 2: Remove all inbound from rm-internal → verify BLOCKED.
async fn test_remove_all_inbound(kubeconfig: &str) -> Result<(), String> {
    info!("[Mesh Removal] Phase 2: Removing all inbound from rm-internal...");

    remove_resources(kubeconfig, NAMESPACE, "rm-internal", &["rm-client"]).await?;

    wait_for_edges_denied(
        kubeconfig,
        NAMESPACE,
        &[removal_edge("rm-internal")],
        "Mesh Removal: remove-all-inbound",
    )
    .await?;

    info!("[Mesh Removal] Phase 2: rm-internal correctly BLOCKED after inbound removal");
    Ok(())
}

/// Phase 3: Remove wildcard inbound from rm-wildcard → verify BLOCKED.
async fn test_remove_wildcard_inbound(kubeconfig: &str) -> Result<(), String> {
    info!("[Mesh Removal] Phase 3: Removing wildcard inbound from rm-wildcard...");

    remove_resources(kubeconfig, NAMESPACE, "rm-wildcard", &["any-caller"]).await?;

    wait_for_edges_denied(
        kubeconfig,
        NAMESPACE,
        &[removal_edge("rm-wildcard")],
        "Mesh Removal: remove-wildcard-inbound",
    )
    .await?;

    info!("[Mesh Removal] Phase 3: rm-wildcard correctly BLOCKED after wildcard removal");
    Ok(())
}

/// Phase 4: Delete rm-delete-target entirely → verify BLOCKED + resource cleanup.
async fn test_delete_service(kubeconfig: &str) -> Result<(), String> {
    info!("[Mesh Removal] Phase 4: Deleting rm-delete-target entirely...");

    delete_lattice_service(kubeconfig, NAMESPACE, "rm-delete-target").await?;

    // Verify traffic is blocked
    wait_for_edges_denied(
        kubeconfig,
        NAMESPACE,
        &[removal_edge("rm-delete-target")],
        "Mesh Removal: delete-service",
    )
    .await?;

    // Verify owned resources are gone
    verify_resource_absent(
        kubeconfig,
        NAMESPACE,
        "latticemeshmember",
        "rm-delete-target",
    )
    .await?;

    info!("[Mesh Removal] Phase 4: rm-delete-target fully deleted and traffic BLOCKED");
    Ok(())
}

/// Phase 5: Remove external dep from rm-client → verify external BLOCKED.
async fn test_remove_external_dep(kubeconfig: &str) -> Result<(), String> {
    info!(
        "[Mesh Removal] Phase 5: Removing external dep '{}' from rm-client...",
        EXTERNAL_RESOURCE_KEY
    );

    remove_resources(kubeconfig, NAMESPACE, "rm-client", &[EXTERNAL_RESOURCE_KEY]).await?;

    wait_for_edges_denied(
        kubeconfig,
        NAMESPACE,
        &[removal_edge_external(EXTERNAL_RESOURCE_KEY)],
        "Mesh Removal: remove-external-dep",
    )
    .await?;

    info!("[Mesh Removal] Phase 5: External dep correctly BLOCKED after removal");
    Ok(())
}

// =============================================================================
// Public API
// =============================================================================

/// Run all mesh removal tests in sequence.
///
/// Deploys a small topology (4 services), verifies baseline, then sequentially
/// tests each removal scenario. Each phase modifies state so they must run in order.
pub async fn run_mesh_removal_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[Mesh Removal] Starting mesh removal tests...");

    deploy_removal_services(kubeconfig).await?;
    wait_for_services_ready(kubeconfig, NAMESPACE, SERVICE_COUNT).await?;

    // +1 pod if external deps trigger waypoint proxy
    let expected_pods = SERVICE_COUNT + 1;
    wait_for_pods_running(
        kubeconfig,
        NAMESPACE,
        expected_pods,
        "Mesh Removal",
        DEFAULT_TIMEOUT,
        Duration::from_secs(5),
    )
    .await?;

    verify_baseline(kubeconfig).await?;
    test_remove_all_inbound(kubeconfig).await?;
    test_remove_wildcard_inbound(kubeconfig).await?;
    test_delete_service(kubeconfig).await?;
    test_remove_external_dep(kubeconfig).await?;

    delete_namespace(kubeconfig, NAMESPACE).await;

    info!("[Mesh Removal] All mesh removal tests passed!");
    Ok(())
}
