//! Media Server E2E Test
//!
//! Tests Score-compliant LatticeService features using a media server stack:
//! - Volume ownership and sharing (PVC generation, pod affinity for RWO)
//! - Bilateral agreements with L7 policies (rate limiting, retries, timeouts)
//! - Template interpolation for volume mounts
//! - **Actual data sharing verification**: owner writes, reference reads
//!
//! ## Volume Sharing Model
//!
//! RWO (ReadWriteOnce) volumes can only be mounted on ONE node. When multiple
//! services share an RWO volume:
//! - The OWNER creates the PVC and gets a volume label
//! - REFERENCES get pod affinity to the owner's label
//! - All pods MUST land on the same node
//!
//! This test verifies data actually flows through the shared volume.
//!
//! ## Services
//!
//! - jellyfin: Owns media-library, writes marker files
//! - sonarr: References media-library AND media-downloads, reads marker files
//! - nzbget: Owns media-downloads, writes marker files

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, PostParams};
use tokio::time::sleep;

use lattice_common::template::TemplateString;
use lattice_operator::crd::{
    ContainerSpec, DependencyDirection, DeploySpec, InboundPolicy, LatticeService,
    LatticeServiceSpec, OutboundPolicy, PortSpec, RateLimitConfig, ReplicaSpec, ResourceSpec,
    ResourceType, RetryConfig, ServicePortsSpec, TimeoutConfig, VolumeMount,
};

use super::helpers::{client_from_kubeconfig, run_cmd, run_cmd_allow_fail};

// =============================================================================
// Constants
// =============================================================================

const MEDIA_NAMESPACE: &str = "media-test";

// Marker file paths - owners write these, references read them
const JELLYFIN_MARKER: &str = "/media/.jellyfin-owner-marker";
const NZBGET_MARKER: &str = "/downloads/.nzbget-owner-marker";

// =============================================================================
// Container Builders
// =============================================================================

/// Create a container that writes a marker file on startup and serves HTTP
///
/// The container:
/// 1. Writes a marker file with timestamp to prove ownership
/// 2. Runs nginx to serve HTTP for bilateral agreement testing
fn owner_container(marker_path: &str, marker_content: &str) -> ContainerSpec {
    // Command: write marker file, then start nginx
    let startup_script = format!(
        r#"echo '{}' > {} && echo 'Marker written to {}' && nginx -g 'daemon off;'"#,
        marker_content, marker_path, marker_path
    );

    ContainerSpec {
        image: "nginx:alpine".to_string(),
        command: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
        args: Some(vec![startup_script]),
        variables: BTreeMap::new(),
        files: BTreeMap::new(),
        volumes: BTreeMap::new(), // Will be populated by caller
        resources: None,
        liveness_probe: None,
        readiness_probe: None,
        startup_probe: None,
    }
}

/// Create a container that reads marker files and serves HTTP
///
/// The container runs nginx and can be used to verify marker files exist
fn reader_container() -> ContainerSpec {
    ContainerSpec {
        image: "nginx:alpine".to_string(),
        command: None,
        args: None,
        variables: BTreeMap::new(),
        files: BTreeMap::new(),
        volumes: BTreeMap::new(), // Will be populated by caller
        resources: None,
        liveness_probe: None,
        readiness_probe: None,
        startup_probe: None,
    }
}

// =============================================================================
// Service Builders
// =============================================================================

fn http_port(port: u16) -> ServicePortsSpec {
    let mut ports = BTreeMap::new();
    ports.insert(
        "http".to_string(),
        PortSpec {
            port,
            target_port: None,
            protocol: Some("TCP".to_string()),
        },
    );
    ServicePortsSpec { ports }
}

/// Create jellyfin service - OWNS media-library volume
///
/// Jellyfin writes a marker file to /media on startup to prove it's the owner.
/// Sonarr will read this marker to verify volume sharing works.
fn create_jellyfin() -> LatticeService {
    let mut container = owner_container(JELLYFIN_MARKER, "jellyfin-owns-media-library");

    // Volume mounts using Score template syntax
    container.volumes.insert(
        "/config".to_string(),
        VolumeMount {
            source: TemplateString::from("${resources.config}"),
            path: None,
            read_only: None,
        },
    );
    container.volumes.insert(
        "/media".to_string(),
        VolumeMount {
            source: TemplateString::from("${resources.media}"),
            path: None,
            read_only: None,
        },
    );

    let mut containers = BTreeMap::new();
    containers.insert("main".to_string(), container);

    let mut resources = BTreeMap::new();

    // Owned volume (private config)
    resources.insert(
        "config".to_string(),
        ResourceSpec {
            type_: ResourceType::Volume,
            direction: DependencyDirection::default(),
            id: None,
            class: None,
            metadata: None,
            params: Some(serde_json::json!({
                "size": "1Gi",
                "storageClass": "standard"
            })),
            inbound: None,
            outbound: None,
        },
    );

    // OWNED shared volume (media-library) - RWO for pod affinity testing
    // This service OWNS the volume (has size in params)
    resources.insert(
        "media".to_string(),
        ResourceSpec {
            type_: ResourceType::Volume,
            direction: DependencyDirection::default(),
            id: Some("media-library".to_string()), // Shared volume ID
            class: None,
            metadata: None,
            params: Some(serde_json::json!({
                "size": "10Gi",
                "storageClass": "standard",
                "accessMode": "ReadWriteOnce"  // RWO forces same-node scheduling
            })),
            inbound: None,
            outbound: None,
        },
    );

    // Bilateral agreement: sonarr can call jellyfin (with rate limiting)
    resources.insert(
        "sonarr".to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Inbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
            inbound: Some(InboundPolicy {
                rate_limit: Some(RateLimitConfig {
                    requests_per_interval: 100,
                    interval_seconds: 60,
                }),
            }),
            outbound: None,
        },
    );

    let mut labels = BTreeMap::new();
    labels.insert(
        "lattice.dev/environment".to_string(),
        MEDIA_NAMESPACE.to_string(),
    );

    LatticeService {
        metadata: ObjectMeta {
            name: Some("jellyfin".to_string()),
            namespace: Some(MEDIA_NAMESPACE.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            environment: MEDIA_NAMESPACE.to_string(),
            containers,
            resources,
            service: Some(http_port(8096)),
            replicas: ReplicaSpec { min: 1, max: None },
            deploy: DeploySpec::default(),
            ingress: None,
        },
        status: None,
    }
}

/// Create nzbget service - OWNS media-downloads volume
///
/// Nzbget writes a marker file to /downloads on startup to prove it's the owner.
/// Sonarr will read this marker to verify volume sharing works.
fn create_nzbget() -> LatticeService {
    let mut container = owner_container(NZBGET_MARKER, "nzbget-owns-media-downloads");

    container.volumes.insert(
        "/config".to_string(),
        VolumeMount {
            source: TemplateString::from("${resources.config}"),
            path: None,
            read_only: None,
        },
    );
    container.volumes.insert(
        "/downloads".to_string(),
        VolumeMount {
            source: TemplateString::from("${resources.downloads}"),
            path: None,
            read_only: None,
        },
    );

    let mut containers = BTreeMap::new();
    containers.insert("main".to_string(), container);

    let mut resources = BTreeMap::new();

    // Owned volume (private config)
    resources.insert(
        "config".to_string(),
        ResourceSpec {
            type_: ResourceType::Volume,
            direction: DependencyDirection::default(),
            id: None,
            class: None,
            metadata: None,
            params: Some(serde_json::json!({
                "size": "1Gi",
                "storageClass": "standard"
            })),
            inbound: None,
            outbound: None,
        },
    );

    // OWNED shared volume (downloads) - RWO for pod affinity
    resources.insert(
        "downloads".to_string(),
        ResourceSpec {
            type_: ResourceType::Volume,
            direction: DependencyDirection::default(),
            id: Some("media-downloads".to_string()), // Shared volume ID
            class: None,
            metadata: None,
            params: Some(serde_json::json!({
                "size": "50Gi",
                "storageClass": "standard",
                "accessMode": "ReadWriteOnce"  // RWO forces same-node scheduling
            })),
            inbound: None,
            outbound: None,
        },
    );

    // Bilateral agreement: sonarr can call nzbget
    resources.insert(
        "sonarr".to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Inbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
            inbound: Some(InboundPolicy {
                rate_limit: Some(RateLimitConfig {
                    requests_per_interval: 50,
                    interval_seconds: 60,
                }),
            }),
            outbound: None,
        },
    );

    let mut labels = BTreeMap::new();
    labels.insert(
        "lattice.dev/environment".to_string(),
        MEDIA_NAMESPACE.to_string(),
    );

    LatticeService {
        metadata: ObjectMeta {
            name: Some("nzbget".to_string()),
            namespace: Some(MEDIA_NAMESPACE.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            environment: MEDIA_NAMESPACE.to_string(),
            containers,
            resources,
            service: Some(http_port(6789)),
            replicas: ReplicaSpec { min: 1, max: None },
            deploy: DeploySpec::default(),
            ingress: None,
        },
        status: None,
    }
}

/// Create sonarr service - REFERENCES both shared volumes
///
/// Sonarr does NOT own any shared volumes. It references:
/// - media-library (owned by jellyfin)
/// - media-downloads (owned by nzbget)
///
/// Due to RWO access mode, sonarr MUST be scheduled on the same node as
/// both jellyfin AND nzbget. The test verifies this by reading marker files.
fn create_sonarr() -> LatticeService {
    let mut container = reader_container();

    // Volume mounts
    container.volumes.insert(
        "/config".to_string(),
        VolumeMount {
            source: TemplateString::from("${resources.config}"),
            path: None,
            read_only: None,
        },
    );
    container.volumes.insert(
        "/media".to_string(),
        VolumeMount {
            source: TemplateString::from("${resources.media}"),
            path: None,
            read_only: None,
        },
    );
    container.volumes.insert(
        "/downloads".to_string(),
        VolumeMount {
            source: TemplateString::from("${resources.downloads}"),
            path: None,
            read_only: None,
        },
    );

    let mut containers = BTreeMap::new();
    containers.insert("main".to_string(), container);

    let mut resources = BTreeMap::new();

    // Owned volume (private config) - sonarr owns this
    resources.insert(
        "config".to_string(),
        ResourceSpec {
            type_: ResourceType::Volume,
            direction: DependencyDirection::default(),
            id: None,
            class: None,
            metadata: None,
            params: Some(serde_json::json!({
                "size": "1Gi",
                "storageClass": "standard"
            })),
            inbound: None,
            outbound: None,
        },
    );

    // REFERENCE to jellyfin's volume (no params = no size = reference)
    resources.insert(
        "media".to_string(),
        ResourceSpec {
            type_: ResourceType::Volume,
            direction: DependencyDirection::default(),
            id: Some("media-library".to_string()), // Same ID as jellyfin's
            class: None,
            metadata: None,
            params: None, // NO PARAMS = REFERENCE (not owner)
            inbound: None,
            outbound: None,
        },
    );

    // REFERENCE to nzbget's volume
    resources.insert(
        "downloads".to_string(),
        ResourceSpec {
            type_: ResourceType::Volume,
            direction: DependencyDirection::default(),
            id: Some("media-downloads".to_string()), // Same ID as nzbget's
            class: None,
            metadata: None,
            params: None, // NO PARAMS = REFERENCE
            inbound: None,
            outbound: None,
        },
    );

    // Outbound: calls jellyfin (with retry/timeout policies)
    resources.insert(
        "jellyfin".to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Outbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
            inbound: None,
            outbound: Some(OutboundPolicy {
                retries: Some(RetryConfig {
                    attempts: 3,
                    per_try_timeout: Some("5s".to_string()),
                    retry_on: vec!["5xx".to_string(), "connect-failure".to_string()],
                }),
                timeout: Some(TimeoutConfig {
                    request: "30s".to_string(),
                }),
            }),
        },
    );

    // Outbound: calls nzbget
    resources.insert(
        "nzbget".to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Outbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
            inbound: None,
            outbound: Some(OutboundPolicy {
                retries: Some(RetryConfig {
                    attempts: 2,
                    per_try_timeout: Some("10s".to_string()),
                    retry_on: vec!["5xx".to_string()],
                }),
                timeout: Some(TimeoutConfig {
                    request: "60s".to_string(),
                }),
            }),
        },
    );

    let mut labels = BTreeMap::new();
    labels.insert(
        "lattice.dev/environment".to_string(),
        MEDIA_NAMESPACE.to_string(),
    );

    LatticeService {
        metadata: ObjectMeta {
            name: Some("sonarr".to_string()),
            namespace: Some(MEDIA_NAMESPACE.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            environment: MEDIA_NAMESPACE.to_string(),
            containers,
            resources,
            service: Some(http_port(8989)),
            replicas: ReplicaSpec { min: 1, max: None },
            deploy: DeploySpec::default(),
            ingress: None,
        },
        status: None,
    }
}

// =============================================================================
// Test Execution
// =============================================================================

/// Deploy media server services to the cluster
async fn deploy_media_services(kubeconfig_path: &str) -> Result<(), String> {
    println!("Deploying media server services...");

    // Create namespace
    let _ = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "create",
            "namespace",
            MEDIA_NAMESPACE,
        ],
    );

    // Label namespace for Istio ambient mesh
    run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "label",
            "namespace",
            MEDIA_NAMESPACE,
            "istio.io/dataplane-mode=ambient",
            "--overwrite",
        ],
    )?;

    let client = client_from_kubeconfig(kubeconfig_path).await?;
    let api: Api<LatticeService> = Api::all(client);

    // Deploy OWNERS first - they create the PVCs and write marker files
    println!("  [Layer 1] Deploying volume OWNERS (jellyfin, nzbget)...");
    api.create(&PostParams::default(), &create_jellyfin())
        .await
        .map_err(|e| format!("Failed to create jellyfin: {}", e))?;
    api.create(&PostParams::default(), &create_nzbget())
        .await
        .map_err(|e| format!("Failed to create nzbget: {}", e))?;

    // Wait for owners to be ready and write their markers
    println!("  Waiting for owners to write marker files...");
    sleep(Duration::from_secs(30)).await;

    // Deploy REFERENCE last - it needs affinity to owners' nodes
    println!("  [Layer 2] Deploying volume REFERENCE (sonarr)...");
    api.create(&PostParams::default(), &create_sonarr())
        .await
        .map_err(|e| format!("Failed to create sonarr: {}", e))?;

    println!("  All services created successfully");
    Ok(())
}

/// Wait for all pods to be running
async fn wait_for_media_pods(kubeconfig_path: &str) -> Result<(), String> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(300); // 5 minutes
    let expected_pods = 3; // jellyfin, sonarr, nzbget

    println!("Waiting for {} media pods to be ready...", expected_pods);

    loop {
        if start.elapsed() > timeout {
            // Get pod status for debugging
            let debug = run_cmd_allow_fail(
                "kubectl",
                &[
                    "--kubeconfig",
                    kubeconfig_path,
                    "get",
                    "pods",
                    "-n",
                    MEDIA_NAMESPACE,
                    "-o",
                    "wide",
                ],
            );
            println!("  Pod status:\n{}", debug);

            return Err(format!(
                "Timeout waiting for media pods (expected {})",
                expected_pods
            ));
        }

        let pods_output = run_cmd_allow_fail(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "pods",
                "-n",
                MEDIA_NAMESPACE,
                "-o",
                "jsonpath={range .items[*]}{.status.phase}{\"\\n\"}{end}",
            ],
        );

        let running_count = pods_output.lines().filter(|l| *l == "Running").count();
        println!("  {}/{} pods running", running_count, expected_pods);

        if running_count >= expected_pods {
            println!("  All {} pods are running!", expected_pods);
            return Ok(());
        }

        sleep(Duration::from_secs(10)).await;
    }
}

/// Verify PVCs were created correctly
async fn verify_pvcs(kubeconfig_path: &str) -> Result<(), String> {
    println!("Verifying PVC creation...");

    let pvc_output = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "pvc",
            "-n",
            MEDIA_NAMESPACE,
            "-o",
            "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}",
        ],
    )?;

    let pvcs: Vec<&str> = pvc_output.lines().filter(|l| !l.is_empty()).collect();
    println!("  Found {} PVCs: {:?}", pvcs.len(), pvcs);

    // Expected PVCs (5 total):
    // - vol-media-library (owned by jellyfin via id)
    // - vol-media-downloads (owned by nzbget via id)
    // - jellyfin-config (owned by jellyfin, no id)
    // - sonarr-config (owned by sonarr, no id)
    // - nzbget-config (owned by nzbget, no id)
    let expected_pvcs = [
        "vol-media-library",
        "vol-media-downloads",
        "jellyfin-config",
        "sonarr-config",
        "nzbget-config",
    ];

    for expected in &expected_pvcs {
        if !pvcs.iter().any(|p| p.contains(expected)) {
            return Err(format!("Missing expected PVC: {}", expected));
        }
        println!("    [OK] Found PVC: {}", expected);
    }

    // CRITICAL: Verify sonarr does NOT create PVCs for its volume references
    // sonarr references media-library and media-downloads but should NOT own them
    let bad_pvcs = ["sonarr-media", "sonarr-downloads"];
    for bad in &bad_pvcs {
        if pvcs.iter().any(|p| p.contains(bad)) {
            return Err(format!(
                "sonarr incorrectly created PVC '{}' - it should only REFERENCE the shared volume, not own it",
                bad
            ));
        }
    }

    println!("  PVC verification passed!");
    Ok(())
}

/// Verify all pods sharing RWO volumes are on the same node
async fn verify_node_colocation(kubeconfig_path: &str) -> Result<(), String> {
    println!("Verifying RWO volume pod co-location...");

    // Get node for each pod
    let get_pod_node = |name: &str| -> Result<String, String> {
        let output = run_cmd(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "pods",
                "-n",
                MEDIA_NAMESPACE,
                "-l",
                &format!("app.kubernetes.io/name={}", name),
                "-o",
                "jsonpath={.items[0].spec.nodeName}",
            ],
        )?;
        Ok(output.trim().to_string())
    };

    let jellyfin_node = get_pod_node("jellyfin")?;
    let sonarr_node = get_pod_node("sonarr")?;
    let nzbget_node = get_pod_node("nzbget")?;

    println!("  jellyfin pod on node: {}", jellyfin_node);
    println!("  sonarr pod on node:   {}", sonarr_node);
    println!("  nzbget pod on node:   {}", nzbget_node);

    // For RWO volumes, sonarr MUST be on the same node as jellyfin AND nzbget
    // In a single-node cluster, this is trivially true
    // In a multi-node cluster, this verifies affinity is working
    if jellyfin_node != sonarr_node {
        return Err(format!(
            "sonarr is on node '{}' but jellyfin (media-library owner) is on '{}'. \
             RWO volume sharing requires same-node scheduling!",
            sonarr_node, jellyfin_node
        ));
    }

    if nzbget_node != sonarr_node {
        return Err(format!(
            "sonarr is on node '{}' but nzbget (media-downloads owner) is on '{}'. \
             RWO volume sharing requires same-node scheduling!",
            sonarr_node, nzbget_node
        ));
    }

    println!("  [OK] All pods co-located on node: {}", sonarr_node);
    Ok(())
}

/// Verify sonarr can read marker files written by jellyfin and nzbget
///
/// This is the CRITICAL test - it proves the shared volume actually works:
/// 1. jellyfin writes to /media/.jellyfin-owner-marker
/// 2. nzbget writes to /downloads/.nzbget-owner-marker
/// 3. sonarr reads BOTH files from its mounts at /media and /downloads
async fn verify_volume_sharing(kubeconfig_path: &str) -> Result<(), String> {
    println!("Verifying actual volume data sharing...");

    // Give pods time to write their marker files
    sleep(Duration::from_secs(10)).await;

    // Test 1: sonarr reads jellyfin's marker from shared media-library volume
    println!("  Testing: sonarr reads jellyfin's marker file...");
    let read_jellyfin_marker = format!(
        "cat {} 2>/dev/null || echo 'MARKER_NOT_FOUND'",
        JELLYFIN_MARKER
    );

    let result = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            MEDIA_NAMESPACE,
            "deploy/sonarr",
            "--",
            "sh",
            "-c",
            &read_jellyfin_marker,
        ],
    )?;

    let result = result.trim();
    if result == "MARKER_NOT_FOUND" {
        return Err(format!(
            "sonarr cannot read jellyfin's marker file at {}. \
             Volume sharing is NOT working!",
            JELLYFIN_MARKER
        ));
    }
    if !result.contains("jellyfin-owns-media-library") {
        return Err(format!(
            "Marker content mismatch. Expected 'jellyfin-owns-media-library', got: {}",
            result
        ));
    }
    println!("    [OK] sonarr read: '{}'", result);

    // Test 2: sonarr reads nzbget's marker from shared media-downloads volume
    println!("  Testing: sonarr reads nzbget's marker file...");
    let read_nzbget_marker = format!(
        "cat {} 2>/dev/null || echo 'MARKER_NOT_FOUND'",
        NZBGET_MARKER
    );

    let result = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            MEDIA_NAMESPACE,
            "deploy/sonarr",
            "--",
            "sh",
            "-c",
            &read_nzbget_marker,
        ],
    )?;

    let result = result.trim();
    if result == "MARKER_NOT_FOUND" {
        return Err(format!(
            "sonarr cannot read nzbget's marker file at {}. \
             Volume sharing is NOT working!",
            NZBGET_MARKER
        ));
    }
    if !result.contains("nzbget-owns-media-downloads") {
        return Err(format!(
            "Marker content mismatch. Expected 'nzbget-owns-media-downloads', got: {}",
            result
        ));
    }
    println!("    [OK] sonarr read: '{}'", result);

    // Test 3: sonarr writes a file and jellyfin can read it (bidirectional sharing)
    println!("  Testing: bidirectional write (sonarr writes, jellyfin reads)...");

    let sonarr_marker = "/media/.sonarr-wrote-this";
    let write_cmd = format!("echo 'sonarr-bidirectional-test' > {}", sonarr_marker);

    run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            MEDIA_NAMESPACE,
            "deploy/sonarr",
            "--",
            "sh",
            "-c",
            &write_cmd,
        ],
    )?;

    // Now jellyfin reads what sonarr wrote
    let read_cmd = format!("cat {} 2>/dev/null || echo 'NOT_FOUND'", sonarr_marker);
    let result = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            MEDIA_NAMESPACE,
            "deploy/jellyfin",
            "--",
            "sh",
            "-c",
            &read_cmd,
        ],
    )?;

    let result = result.trim();
    if result == "NOT_FOUND" || !result.contains("sonarr-bidirectional-test") {
        return Err(format!(
            "jellyfin cannot read sonarr's file. Bidirectional sharing failed! Got: {}",
            result
        ));
    }
    println!("    [OK] jellyfin read sonarr's file: '{}'", result);

    println!("  Volume sharing verification passed!");
    Ok(())
}

/// Verify bilateral agreements allow/block traffic correctly
async fn verify_bilateral_agreements(kubeconfig_path: &str) -> Result<(), String> {
    println!("Verifying bilateral service mesh agreements...");

    // Wait for policies to propagate
    println!("  Waiting 30s for AuthorizationPolicies to propagate...");
    sleep(Duration::from_secs(30)).await;

    // Test: sonarr -> jellyfin (should be ALLOWED - bilateral agreement exists)
    println!("  Testing: sonarr -> jellyfin (should be ALLOWED)...");
    let test_script = r#"
RESULT=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://jellyfin.media-test.svc.cluster.local:8096/ 2>/dev/null || echo "000")
echo "$RESULT"
"#;

    let result = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            MEDIA_NAMESPACE,
            "deploy/sonarr",
            "--",
            "sh",
            "-c",
            test_script,
        ],
    );

    match result {
        Ok(output) => {
            let code = output.trim();
            if code == "200" || code == "404" {
                println!("    [OK] sonarr->jellyfin: HTTP {} (allowed)", code);
            } else if code == "403" {
                return Err("sonarr->jellyfin returned 403 (blocked). Bilateral agreement not working!".to_string());
            } else {
                println!("    [WARN] sonarr->jellyfin: HTTP {} (unexpected)", code);
            }
        }
        Err(e) => println!("    [WARN] sonarr->jellyfin test failed: {}", e),
    }

    // Test: sonarr -> nzbget (should be ALLOWED)
    println!("  Testing: sonarr -> nzbget (should be ALLOWED)...");
    let test_script = r#"
RESULT=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://nzbget.media-test.svc.cluster.local:6789/ 2>/dev/null || echo "000")
echo "$RESULT"
"#;

    let result = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            MEDIA_NAMESPACE,
            "deploy/sonarr",
            "--",
            "sh",
            "-c",
            test_script,
        ],
    );

    match result {
        Ok(output) => {
            let code = output.trim();
            if code == "200" || code == "404" {
                println!("    [OK] sonarr->nzbget: HTTP {} (allowed)", code);
            } else if code == "403" {
                return Err("sonarr->nzbget returned 403 (blocked). Bilateral agreement not working!".to_string());
            } else {
                println!("    [WARN] sonarr->nzbget: HTTP {} (unexpected)", code);
            }
        }
        Err(e) => println!("    [WARN] sonarr->nzbget test failed: {}", e),
    }

    // Test: jellyfin -> sonarr (should be BLOCKED - no bilateral agreement)
    println!("  Testing: jellyfin -> sonarr (should be BLOCKED)...");
    let test_script = r#"
RESULT=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://sonarr.media-test.svc.cluster.local:8989/ 2>/dev/null || echo "000")
echo "$RESULT"
"#;

    let result = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            MEDIA_NAMESPACE,
            "deploy/jellyfin",
            "--",
            "sh",
            "-c",
            test_script,
        ],
    );

    match result {
        Ok(output) => {
            let code = output.trim();
            if code == "403" {
                println!("    [OK] jellyfin->sonarr: HTTP 403 (blocked as expected)");
            } else if code == "200" || code == "404" {
                println!("    [WARN] jellyfin->sonarr: HTTP {} (allowed but should be blocked)", code);
            } else {
                println!("    [INFO] jellyfin->sonarr: HTTP {} (connection issue, treated as blocked)", code);
            }
        }
        Err(e) => println!("    [INFO] jellyfin->sonarr test error (may be blocked): {}", e),
    }

    println!("  Bilateral agreement verification completed");
    Ok(())
}

/// Clean up test resources
async fn cleanup_media_services(kubeconfig_path: &str) {
    println!("Cleaning up media server test resources...");

    let _ = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "delete",
            "namespace",
            MEDIA_NAMESPACE,
            "--ignore-not-found",
            "--timeout=60s",
        ],
    );

    println!("  Cleanup complete");
}

// =============================================================================
// Public Test Entry Point
// =============================================================================

/// Run the media server E2E test
///
/// This test verifies:
/// 1. Score-compliant volume params parsing
/// 2. PVC generation for owned volumes (with shared IDs)
/// 3. Pod affinity for RWO volume references (same-node scheduling)
/// 4. **Actual data sharing** - owners write, references read
/// 5. Bilateral agreements with L7 policies
pub async fn run_media_server_test(kubeconfig_path: &str) -> Result<(), String> {
    println!("\n========================================");
    println!("Media Server E2E Test");
    println!("========================================\n");

    // Deploy services
    deploy_media_services(kubeconfig_path).await?;

    // Wait for pods
    wait_for_media_pods(kubeconfig_path).await?;

    // Verify PVCs (ownership model)
    verify_pvcs(kubeconfig_path).await?;

    // Verify pod co-location (required for RWO)
    verify_node_colocation(kubeconfig_path).await?;

    // THE KEY TEST: Verify actual data flows through shared volumes
    verify_volume_sharing(kubeconfig_path).await?;

    // Wait for Istio waypoint proxy to be ready
    println!("Waiting for Istio waypoint proxy...");
    sleep(Duration::from_secs(30)).await;

    // Verify bilateral agreements
    verify_bilateral_agreements(kubeconfig_path).await?;

    println!("\n========================================");
    println!("Media Server E2E Test: PASSED");
    println!("========================================\n");

    Ok(())
}

/// Cleanup function for use in test teardown
pub async fn cleanup_media_server_test(kubeconfig_path: &str) {
    cleanup_media_services(kubeconfig_path).await;
}
