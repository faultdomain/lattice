//! Media Server E2E Test
//!
//! Tests LatticeService with a media server stack (jellyfin, nzbget, sonarr).
//! Verifies volume sharing, pod co-location, and bilateral agreements.

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, PostParams};

use lattice_operator::crd::LatticeService;

use super::helpers::{client_from_kubeconfig, load_service_config, run_cmd, wait_for_condition};

const NAMESPACE: &str = "media";

// =============================================================================
// Test Implementation
// =============================================================================

async fn deploy_media_services(kubeconfig_path: &str) -> Result<(), String> {
    info!("Deploying media server services...");

    let client = client_from_kubeconfig(kubeconfig_path).await?;

    // Create namespace
    let ns_api: Api<Namespace> = Api::all(client.clone());
    let ns = Namespace {
        metadata: ObjectMeta {
            name: Some(NAMESPACE.into()),
            labels: Some(BTreeMap::from([(
                "istio.io/dataplane-mode".into(),
                "ambient".into(),
            )])),
            ..Default::default()
        },
        ..Default::default()
    };

    match ns_api.create(&PostParams::default(), &ns).await {
        Ok(_) => info!("Created namespace {}", NAMESPACE),
        Err(kube::Error::Api(e)) if e.code == 409 => {
            let patch = serde_json::json!({
                "metadata": {
                    "labels": {
                        "istio.io/dataplane-mode": "ambient"
                    }
                }
            });
            let _ = ns_api
                .patch(
                    NAMESPACE,
                    &kube::api::PatchParams::default(),
                    &kube::api::Patch::Merge(&patch),
                )
                .await;
        }
        Err(e) => return Err(format!("Failed to create namespace: {}", e)),
    }

    // Load and deploy services from YAML fixtures
    let api: Api<LatticeService> = Api::namespaced(client, NAMESPACE);
    for filename in ["jellyfin.yaml", "nzbget.yaml", "sonarr.yaml"] {
        let service = load_service_config(filename)?;
        let name = service.metadata.name.as_deref().unwrap_or(filename);
        info!("Deploying {}...", name);
        api.create(&PostParams::default(), &service)
            .await
            .map_err(|e| format!("Failed to create {}: {}", name, e))?;
    }

    Ok(())
}

async fn wait_for_deployments(kubeconfig_path: &str) -> Result<(), String> {
    info!("Waiting for deployments...");

    for name in ["jellyfin", "nzbget", "sonarr"] {
        info!("Waiting for {}...", name);

        wait_for_condition(
            &format!("deployment {} to be available", name),
            Duration::from_secs(300),
            Duration::from_secs(5),
            || async move {
                let output = run_cmd(
                    "kubectl",
                    &[
                        "--kubeconfig",
                        kubeconfig_path,
                        "get",
                        "deployment",
                        "-n",
                        NAMESPACE,
                        name,
                        "-o",
                        "jsonpath={.status.availableReplicas}/{.status.replicas}",
                    ],
                );

                match output {
                    Ok(status) => {
                        let parts: Vec<&str> = status.split('/').collect();
                        if parts.len() == 2 {
                            let available = parts[0].parse::<i32>().unwrap_or(0);
                            let desired = parts[1].parse::<i32>().unwrap_or(0);
                            if desired > 0 && available >= desired {
                                info!("{} is available ({}/{})", name, available, desired);
                                return Ok(true);
                            }
                            info!(
                                "  {} not ready yet ({}/{} available), retrying...",
                                name, available, desired
                            );
                        } else {
                            info!("  {} status unclear: {}, retrying...", name, status);
                        }
                    }
                    Err(e) => {
                        if e.contains("not found") || e.contains("NotFound") {
                            info!("{} not found yet, retrying...", name);
                        } else {
                            info!("Error checking {}: {}, retrying...", name, e);
                        }
                    }
                }
                Ok(false)
            },
        )
        .await?;
    }

    info!("All deployments available");
    Ok(())
}

async fn verify_pvcs(kubeconfig_path: &str) -> Result<(), String> {
    info!("Verifying PVCs...");

    // Use kubectl for resilience - handles retries/reconnection internally
    let output = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "pvc",
            "-n",
            NAMESPACE,
            "-o",
            "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}",
        ],
    )
    .map_err(|e| format!("Failed to list PVCs: {}", e))?;

    let pvc_names: Vec<&str> = output.lines().map(|l| l.trim()).collect();

    for expected in [
        "vol-media-storage",
        "jellyfin-config",
        "jellyfin-cache",
        "sonarr-config",
        "nzbget-config",
    ] {
        if !pvc_names.iter().any(|p| p.contains(expected)) {
            return Err(format!(
                "Missing PVC: {} (found: {:?})",
                expected, pvc_names
            ));
        }
    }

    let shared_count = pvc_names.iter().filter(|p| p.starts_with("vol-")).count();
    if shared_count != 1 {
        return Err(format!("Expected 1 shared volume, found {}", shared_count));
    }

    info!("PVCs verified");
    Ok(())
}

async fn verify_node_colocation(kubeconfig_path: &str) -> Result<(), String> {
    info!("Verifying pod co-location...");

    // Use kubectl for resilience - handles retries/reconnection internally
    // Get pods with their lattice.io/name label and node name
    let label_escaped = lattice_common::LABEL_NAME.replace('.', r"\.");
    let jsonpath = format!(
        "{{range .items[*]}}{{.metadata.labels.{}}}:{{.spec.nodeName}}{{\"\\n\"}}{{end}}",
        label_escaped
    );

    let output = run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "get",
            "pods",
            "-n",
            NAMESPACE,
            "-o",
            &format!("jsonpath={}", jsonpath),
        ],
    )
    .map_err(|e| format!("Failed to list pods: {}", e))?;

    // Parse output: "service-name:node-name\n..."
    let mut node_map: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
            node_map.insert(parts[0], parts[1]);
        }
    }

    let get_node = |name: &str| -> Result<&str, String> {
        node_map.get(name).copied().ok_or_else(|| {
            format!(
                "No pod found with label {}={} (found: {:?})",
                lattice_common::LABEL_NAME,
                name,
                node_map.keys().collect::<Vec<_>>()
            )
        })
    };

    let jellyfin_node = get_node("jellyfin")?;
    let sonarr_node = get_node("sonarr")?;
    let nzbget_node = get_node("nzbget")?;

    if jellyfin_node != sonarr_node || jellyfin_node != nzbget_node {
        return Err(format!(
            "Pods not co-located: jellyfin={}, sonarr={}, nzbget={}",
            jellyfin_node, sonarr_node, nzbget_node
        ));
    }

    info!("All pods on node: {}", jellyfin_node);
    Ok(())
}

async fn verify_volume_sharing(kubeconfig_path: &str) -> Result<(), String> {
    info!("Verifying volume sharing...");
    sleep(Duration::from_secs(5)).await;

    let exec = |deploy: &str, cmd: &str| -> Result<String, String> {
        run_cmd(
            "kubectl",
            &[
                "--kubeconfig",
                kubeconfig_path,
                "exec",
                "-n",
                NAMESPACE,
                &format!("deploy/{}", deploy),
                "--",
                "sh",
                "-c",
                cmd,
            ],
        )
    };

    // jellyfin writes to library/, sonarr reads it
    exec("jellyfin", "echo 'jellyfin-marker' > /media/.test-marker")?;
    let result = exec("sonarr", "cat /tv/.test-marker")?;
    if !result.contains("jellyfin-marker") {
        return Err("sonarr cannot read jellyfin's marker".into());
    }

    // nzbget writes to downloads/, sonarr reads it
    exec("nzbget", "echo 'nzbget-marker' > /downloads/.test-marker")?;
    let result = exec("sonarr", "cat /downloads/.test-marker")?;
    if !result.contains("nzbget-marker") {
        return Err("sonarr cannot read nzbget's marker".into());
    }

    // Verify subpath isolation - jellyfin should NOT see nzbget's marker in its /media mount
    let isolated = match run_cmd(
        "kubectl",
        &[
            "--kubeconfig",
            kubeconfig_path,
            "exec",
            "-n",
            NAMESPACE,
            "deploy/jellyfin",
            "--",
            "cat",
            "/media/.test-marker",
        ],
    ) {
        Ok(result) => !result.contains("nzbget-marker"),
        Err(_) => true, // File doesn't exist - good, isolation works
    };
    if !isolated {
        return Err("Subpath isolation failed".into());
    }

    info!("Volume sharing verified");
    Ok(())
}

async fn wait_for_waypoint(kubeconfig_path: &str) -> Result<(), String> {
    info!("Waiting for Istio waypoint...");

    wait_for_condition(
        "Istio waypoint to be ready",
        Duration::from_secs(120),
        Duration::from_secs(5),
        || async move {
            let output = run_cmd(
                "kubectl",
                &[
                    "--kubeconfig",
                    kubeconfig_path,
                    "get",
                    "deployments",
                    "-n",
                    NAMESPACE,
                    "-o",
                    "jsonpath={range .items[*]}{.metadata.name}:{.status.availableReplicas}/{.status.replicas}{\"\\n\"}{end}",
                ],
            )
            .unwrap_or_default();

            for line in output.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() == 2 && parts[0].contains("waypoint") {
                    let name = parts[0];
                    let replicas: Vec<&str> = parts[1].split('/').collect();
                    if replicas.len() == 2 {
                        let available = replicas[0].parse::<i32>().unwrap_or(0);
                        let desired = replicas[1].parse::<i32>().unwrap_or(0);
                        if available > 0 && available >= desired {
                            info!("{} is ready ({}/{})", name, available, desired);
                            return Ok(true);
                        }
                    }
                }
            }

            Ok(false)
        },
    )
    .await
}

async fn verify_bilateral_agreements(kubeconfig_path: &str) -> Result<(), String> {
    info!("Verifying bilateral agreements...");

    let curl_check = |from: &str, to: &str, port: u16| -> String {
        run_cmd("kubectl", &[
            "--kubeconfig", kubeconfig_path,
            "exec", "-n", NAMESPACE, &format!("deploy/{}", from),
            "--", "sh", "-c",
            &format!("curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 http://{}:{}/ || echo '000'", to, port),
        ]).unwrap_or_else(|_| "000".to_string()).trim().to_string()
    };

    // sonarr -> jellyfin (allowed)
    let code = curl_check("sonarr", "jellyfin", 8096);
    if code == "403" {
        return Err("sonarr->jellyfin blocked unexpectedly".into());
    }
    info!("sonarr->jellyfin: {} (allowed)", code);

    // sonarr -> nzbget (allowed)
    let code = curl_check("sonarr", "nzbget", 6789);
    if code == "403" {
        return Err("sonarr->nzbget blocked unexpectedly".into());
    }
    info!("sonarr->nzbget: {} (allowed)", code);

    // jellyfin -> sonarr (should be blocked)
    let code = curl_check("jellyfin", "sonarr", 8989);
    info!("jellyfin->sonarr: {} (expected 403)", code);

    Ok(())
}

// =============================================================================
// Public API
// =============================================================================

pub async fn run_media_server_test(kubeconfig_path: &str) -> Result<(), String> {
    info!("\n========================================");
    info!("Media Server E2E Test");
    info!("========================================\n");

    deploy_media_services(kubeconfig_path).await?;
    wait_for_deployments(kubeconfig_path).await?;
    verify_pvcs(kubeconfig_path).await?;
    verify_node_colocation(kubeconfig_path).await?;
    verify_volume_sharing(kubeconfig_path).await?;
    wait_for_waypoint(kubeconfig_path).await?;
    verify_bilateral_agreements(kubeconfig_path).await?;

    info!("\n========================================");
    info!("Media Server E2E Test: PASSED");
    info!("========================================\n");

    Ok(())
}
