//! Network topology integration tests
//!
//! Verifies that topology-aware scheduling works end-to-end:
//! - Node pools have the expected topology labels
//! - LatticeService with topology generates a PodGroup + volcano scheduler
//! - LatticeService without topology has no PodGroup and uses default scheduler
//! - Topology discovery ConfigMap is generated in volcano-system
//!
//! Run standalone:
//! ```
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_topology_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;

use tracing::info;

use super::super::helpers::{
    build_busybox_service, delete_namespace, deploy_and_wait_for_phase, ensure_fresh_namespace,
    run_kubectl, service_pod_selector, setup_regcreds_infrastructure, wait_for_pod_running,
    BUSYBOX_IMAGE, DEFAULT_TIMEOUT,
};

const TOPOLOGY_NS: &str = "topology-test";
const SERVICE_WITH_TOPO: &str = "topo-service";
const SERVICE_WITHOUT_TOPO: &str = "notopo-service";

// =============================================================================
// Service Builders
// =============================================================================

/// Build a LatticeService with topology-aware scheduling enabled (soft, maxTier 2)
fn build_service_with_topology() -> lattice_common::crd::LatticeService {
    use lattice_common::crd::{
        ContainerSpec, ResourceQuantity, ResourceRequirements, SecurityContext, TopologyMode,
        WorkloadNetworkTopology,
    };
    use lattice_common::template::TemplateString;

    let mut variables = BTreeMap::new();
    variables.insert("ROLE".to_string(), TemplateString::new("topology-test"));

    let container = ContainerSpec {
        image: BUSYBOX_IMAGE.clone(),
        command: Some(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo topology-ok && sleep infinity".to_string(),
        ]),
        variables,
        resources: Some(ResourceRequirements {
            limits: Some(ResourceQuantity {
                cpu: Some("100m".to_string()),
                memory: Some("64Mi".to_string()),
            }),
            requests: Some(ResourceQuantity {
                cpu: Some("50m".to_string()),
                memory: Some("32Mi".to_string()),
            }),
        }),
        security: Some(SecurityContext {
            run_as_user: Some(65534),
            apparmor_profile: Some("Unconfined".to_string()),
            allowed_binaries: vec!["*".to_string()],
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut containers = BTreeMap::new();
    containers.insert("main".to_string(), container);

    let mut svc =
        build_busybox_service(SERVICE_WITH_TOPO, TOPOLOGY_NS, containers, BTreeMap::new());
    svc.spec.replicas = 2;
    svc.spec.topology = Some(WorkloadNetworkTopology {
        mode: TopologyMode::Soft,
        max_tier: Some(2),
    });
    svc
}

/// Build a LatticeService without topology (baseline comparison)
fn build_service_without_topology() -> lattice_common::crd::LatticeService {
    use lattice_common::crd::{
        ContainerSpec, ResourceQuantity, ResourceRequirements, SecurityContext,
    };
    use lattice_common::template::TemplateString;

    let mut variables = BTreeMap::new();
    variables.insert("ROLE".to_string(), TemplateString::new("no-topology-test"));

    let container = ContainerSpec {
        image: BUSYBOX_IMAGE.clone(),
        command: Some(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo no-topology && sleep infinity".to_string(),
        ]),
        variables,
        resources: Some(ResourceRequirements {
            limits: Some(ResourceQuantity {
                cpu: Some("100m".to_string()),
                memory: Some("64Mi".to_string()),
            }),
            requests: Some(ResourceQuantity {
                cpu: Some("50m".to_string()),
                memory: Some("32Mi".to_string()),
            }),
        }),
        security: Some(SecurityContext {
            run_as_user: Some(65534),
            apparmor_profile: Some("Unconfined".to_string()),
            allowed_binaries: vec!["*".to_string()],
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut containers = BTreeMap::new();
    containers.insert("main".to_string(), container);

    build_busybox_service(
        SERVICE_WITHOUT_TOPO,
        TOPOLOGY_NS,
        containers,
        BTreeMap::new(),
    )
}

// =============================================================================
// Test Functions
// =============================================================================

/// Verify worker nodes have topology labels from their pool definitions
async fn test_node_topology_labels(kubeconfig: &str) -> Result<(), String> {
    info!("[Topology] Verifying worker nodes have topology labels...");

    // Check that at least one node has the zone label
    let zone_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "nodes",
        "-l",
        "topology.kubernetes.io/zone",
        "-o",
        "jsonpath={range .items[*]}{.metadata.name}={.metadata.labels.topology\\.kubernetes\\.io/zone} {end}",
    ])
    .await?;

    let nodes_with_zones: Vec<&str> = zone_output
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .collect();
    if nodes_with_zones.is_empty() {
        return Err("No nodes found with topology.kubernetes.io/zone label".to_string());
    }

    info!("[Topology] Nodes with zone labels: {:?}", nodes_with_zones);

    // Verify we have nodes in at least 2 different zones
    let zones: std::collections::HashSet<&str> = nodes_with_zones
        .iter()
        .filter_map(|entry| entry.split('=').nth(1))
        .collect();

    if zones.len() < 2 {
        return Err(format!(
            "Expected nodes in at least 2 zones, found {}: {:?}",
            zones.len(),
            zones
        ));
    }

    info!(
        "[Topology] Found nodes across {} zones: {:?}",
        zones.len(),
        zones
    );

    // Check rack labels
    let rack_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "nodes",
        "-l",
        "topology.lattice.dev/rack",
        "-o",
        "jsonpath={range .items[*]}{.metadata.name}={.metadata.labels.topology\\.lattice\\.dev/rack} {end}",
    ])
    .await?;

    let nodes_with_racks: Vec<&str> = rack_output
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .collect();
    if nodes_with_racks.is_empty() {
        return Err("No nodes found with topology.lattice.dev/rack label".to_string());
    }

    info!("[Topology] Nodes with rack labels: {:?}", nodes_with_racks);
    info!("[Topology] Node topology labels verified");
    Ok(())
}

/// Verify topology discovery ConfigMap exists in volcano-system
async fn test_topology_discovery_configmap(kubeconfig: &str) -> Result<(), String> {
    info!("[Topology] Verifying topology discovery ConfigMap...");

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "configmap",
        "volcano-topology-discovery",
        "-n",
        "volcano-system",
        "-o",
        "jsonpath={.data.config\\.yaml}",
    ])
    .await?;

    if output.trim().is_empty() {
        return Err("Topology discovery ConfigMap not found or empty".to_string());
    }

    // Verify it contains label-based discovery config
    if !output.contains("source: label") {
        return Err(format!(
            "Expected 'source: label' in discovery ConfigMap, got: {}",
            output
        ));
    }

    // Verify tier labels are present
    if !output.contains("topology.kubernetes.io/zone") {
        return Err("Discovery ConfigMap missing zone tier label".to_string());
    }

    if !output.contains("topology.lattice.dev/rack") {
        return Err("Discovery ConfigMap missing rack tier label".to_string());
    }

    info!("[Topology] Discovery ConfigMap verified: {}", output.trim());
    Ok(())
}

/// Deploy a service with topology and verify PodGroup + volcano scheduler
async fn test_service_with_topology(kubeconfig: &str) -> Result<(), String> {
    info!("[Topology] Deploying service with topology-aware scheduling...");

    let service = build_service_with_topology();
    deploy_and_wait_for_phase(
        kubeconfig,
        TOPOLOGY_NS,
        service,
        "Ready",
        None,
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!("[Topology] Service with topology reached Ready phase");

    // Verify PodGroup was created
    let pg_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "podgroups.scheduling.volcano.sh",
        SERVICE_WITH_TOPO,
        "-n",
        TOPOLOGY_NS,
        "-o",
        "jsonpath={.spec.minMember}",
    ])
    .await?;

    let min_member = pg_output.trim();
    if min_member != "2" {
        return Err(format!(
            "Expected PodGroup minMember=2, got: '{}'",
            min_member
        ));
    }

    info!("[Topology] PodGroup created with minMember={}", min_member);

    // Verify PodGroup has networkTopology
    let topo_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "podgroups.scheduling.volcano.sh",
        SERVICE_WITH_TOPO,
        "-n",
        TOPOLOGY_NS,
        "-o",
        "jsonpath={.spec.networkTopology.mode}",
    ])
    .await?;

    if topo_output.trim() != "soft" {
        return Err(format!(
            "Expected PodGroup networkTopology.mode='soft', got: '{}'",
            topo_output.trim()
        ));
    }

    let tier_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "podgroups.scheduling.volcano.sh",
        SERVICE_WITH_TOPO,
        "-n",
        TOPOLOGY_NS,
        "-o",
        "jsonpath={.spec.networkTopology.highestTierAllowed}",
    ])
    .await?;

    if tier_output.trim() != "2" {
        return Err(format!(
            "Expected PodGroup networkTopology.highestTierAllowed=2, got: '{}'",
            tier_output.trim()
        ));
    }

    info!("[Topology] PodGroup networkTopology verified (soft, tier 2)");

    // Verify pods have the PodGroup annotation
    let selector = service_pod_selector(SERVICE_WITH_TOPO);
    wait_for_pod_running(kubeconfig, TOPOLOGY_NS, &selector).await?;

    let annotation_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pods",
        "-n",
        TOPOLOGY_NS,
        "-l",
        &selector,
        "-o",
        "jsonpath={.items[0].metadata.annotations.scheduling\\.volcano\\.sh/group-name}",
    ])
    .await?;

    if annotation_output.trim() != SERVICE_WITH_TOPO {
        return Err(format!(
            "Expected pod annotation scheduling.volcano.sh/group-name='{}', got: '{}'",
            SERVICE_WITH_TOPO,
            annotation_output.trim()
        ));
    }

    info!("[Topology] Pod PodGroup annotation verified");

    // Verify pods use volcano scheduler
    let scheduler_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pods",
        "-n",
        TOPOLOGY_NS,
        "-l",
        &selector,
        "-o",
        "jsonpath={.items[0].spec.schedulerName}",
    ])
    .await?;

    if scheduler_output.trim() != "volcano" {
        return Err(format!(
            "Expected schedulerName='volcano', got: '{}'",
            scheduler_output.trim()
        ));
    }

    info!("[Topology] Pod schedulerName=volcano verified");
    Ok(())
}

/// Deploy a service without topology and verify no PodGroup, no volcano scheduler
async fn test_service_without_topology(kubeconfig: &str) -> Result<(), String> {
    info!("[Topology] Deploying service without topology (baseline)...");

    let service = build_service_without_topology();
    deploy_and_wait_for_phase(
        kubeconfig,
        TOPOLOGY_NS,
        service,
        "Ready",
        None,
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!("[Topology] Service without topology reached Ready phase");

    // Verify NO PodGroup was created
    let pg_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "podgroups.scheduling.volcano.sh",
        SERVICE_WITHOUT_TOPO,
        "-n",
        TOPOLOGY_NS,
        "-o",
        "jsonpath={.metadata.name}",
    ])
    .await;

    // Should fail or return empty (resource doesn't exist)
    match pg_output {
        Ok(output) if !output.trim().is_empty() => {
            return Err(format!(
                "Service without topology should NOT have a PodGroup, but found: '{}'",
                output.trim()
            ));
        }
        _ => {
            info!("[Topology] Confirmed: no PodGroup for service without topology");
        }
    }

    // Verify pods do NOT use volcano scheduler
    let selector = service_pod_selector(SERVICE_WITHOUT_TOPO);
    wait_for_pod_running(kubeconfig, TOPOLOGY_NS, &selector).await?;

    let scheduler_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pods",
        "-n",
        TOPOLOGY_NS,
        "-l",
        &selector,
        "-o",
        "jsonpath={.items[0].spec.schedulerName}",
    ])
    .await?;

    let scheduler = scheduler_output.trim();
    if scheduler == "volcano" {
        return Err("Service without topology should NOT use volcano scheduler".to_string());
    }

    info!(
        "[Topology] Confirmed: no volcano scheduler for service without topology (scheduler='{}')",
        scheduler
    );
    Ok(())
}

/// Verify pods with topology land on nodes with expected labels
async fn test_pod_node_placement(kubeconfig: &str) -> Result<(), String> {
    info!("[Topology] Verifying pod placement on topology-labeled nodes...");

    let selector = service_pod_selector(SERVICE_WITH_TOPO);

    // Get nodes where pods are scheduled
    let node_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pods",
        "-n",
        TOPOLOGY_NS,
        "-l",
        &selector,
        "-o",
        "jsonpath={range .items[*]}{.spec.nodeName} {end}",
    ])
    .await?;

    let pod_nodes: Vec<&str> = node_output
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .collect();
    if pod_nodes.is_empty() {
        return Err("No pods found for topology service".to_string());
    }

    info!("[Topology] Pods scheduled on nodes: {:?}", pod_nodes);

    // Verify each node has topology labels
    for node in &pod_nodes {
        let zone = run_kubectl(&[
            "--kubeconfig",
            kubeconfig,
            "get",
            "node",
            node,
            "-o",
            "jsonpath={.metadata.labels.topology\\.kubernetes\\.io/zone}",
        ])
        .await?;

        if zone.trim().is_empty() {
            return Err(format!(
                "Node {} missing topology.kubernetes.io/zone label",
                node
            ));
        }

        info!("[Topology] Node {} has zone={}", node, zone.trim());
    }

    info!("[Topology] Pod node placement verified — all on topology-labeled nodes");
    Ok(())
}

// =============================================================================
// Public Entry Point
// =============================================================================

/// Run all topology integration tests
pub async fn run_topology_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[Topology] Running topology integration tests on {kubeconfig}");

    // Infrastructure checks (no namespace needed)
    test_node_topology_labels(kubeconfig).await?;
    test_topology_discovery_configmap(kubeconfig).await?;

    // Service deployment tests
    setup_regcreds_infrastructure(kubeconfig).await?;

    let result = run_topology_test_sequence(kubeconfig).await;

    delete_namespace(kubeconfig, TOPOLOGY_NS).await;

    result
}

async fn run_topology_test_sequence(kubeconfig: &str) -> Result<(), String> {
    ensure_fresh_namespace(kubeconfig, TOPOLOGY_NS).await?;

    test_service_with_topology(kubeconfig).await?;
    test_service_without_topology(kubeconfig).await?;
    test_pod_node_placement(kubeconfig).await?;

    info!("[Topology] All topology integration tests passed!");
    Ok(())
}

// =============================================================================
// Standalone Test
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_topology_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_topology_tests(&resolved.kubeconfig).await.unwrap();
}
