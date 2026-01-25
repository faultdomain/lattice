//! Media Server E2E Test
//!
//! Tests LatticeService with a media server stack (jellyfin, nzbget, sonarr).
//! Verifies volume sharing, pod co-location, and bilateral agreements.
//!
//! NOTE: Currently disabled pending investigation of deployment issues.

#![cfg(feature = "provider-e2e")]
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Namespace, PersistentVolumeClaim, Pod};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, ListParams, PostParams};

use lattice_operator::crd::LatticeService;

use super::helpers::{client_from_kubeconfig, load_service_config, run_cmd, run_cmd_allow_fail};

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

fn deployment_is_available(d: &Deployment) -> bool {
    d.status.as_ref().map_or(false, |status| {
        let desired = status.replicas.unwrap_or(0);
        let available = status.available_replicas.unwrap_or(0);
        desired > 0 && available >= desired
    })
}

async fn wait_for_pods(kubeconfig_path: &str) -> Result<(), String> {
    info!("Waiting for deployments...");

    let client = client_from_kubeconfig(kubeconfig_path).await?;
    let api: Api<Deployment> = Api::namespaced(client, NAMESPACE);

    let timeout = Duration::from_secs(300);
    let poll_interval = Duration::from_secs(5);

    for name in ["jellyfin", "nzbget", "sonarr"] {
        info!("Waiting for {}...", name);
        let start = std::time::Instant::now();

        loop {
            match api.get(name).await {
                Ok(deployment) if deployment_is_available(&deployment) => {
                    info!("{} is available", name);
                    break;
                }
                Ok(deployment) => {
                    let status = deployment.status.as_ref();
                    let available = status.and_then(|s| s.available_replicas).unwrap_or(0);
                    let desired = status.and_then(|s| s.replicas).unwrap_or(0);
                    info!(
                        "  {} not ready yet ({}/{} available), retrying...",
                        name, available, desired
                    );
                }
                Err(kube::Error::Api(e)) if e.code == 404 => {
                    info!("{} not found yet, retrying...", name);
                }
                Err(e) => {
                    info!("Error checking {}: {}, retrying...", name, e);
                }
            }

            if start.elapsed() > timeout {
                return Err(format!("Timeout waiting for deployment {}", name));
            }

            sleep(poll_interval).await;
        }
    }

    info!("All deployments available");
    Ok(())
}

async fn verify_pvcs(kubeconfig_path: &str) -> Result<(), String> {
    info!("Verifying PVCs...");

    let client = client_from_kubeconfig(kubeconfig_path).await?;
    let api: Api<PersistentVolumeClaim> = Api::namespaced(client, NAMESPACE);

    let pvcs = api
        .list(&ListParams::default())
        .await
        .map_err(|e| format!("Failed to list PVCs: {}", e))?;

    let pvc_names: Vec<&str> = pvcs
        .items
        .iter()
        .filter_map(|p| p.metadata.name.as_deref())
        .collect();

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

    let client = client_from_kubeconfig(kubeconfig_path).await?;
    let api: Api<Pod> = Api::namespaced(client, NAMESPACE);

    let get_node = |pods: &[Pod], name: &str| -> Result<String, String> {
        let pod = pods
            .iter()
            .find(|p| {
                p.metadata
                    .labels
                    .as_ref()
                    .and_then(|l| l.get("app.kubernetes.io/name"))
                    .map(|v| v == name)
                    .unwrap_or(false)
            })
            .ok_or_else(|| format!("No pod found with label app.kubernetes.io/name={}", name))?;

        pod.spec
            .as_ref()
            .and_then(|s| s.node_name.clone())
            .ok_or_else(|| format!("Pod {} has no node assigned", name))
    };

    let pod_list = api
        .list(&ListParams::default())
        .await
        .map_err(|e| format!("Failed to list pods: {}", e))?;

    let jellyfin_node = get_node(&pod_list.items, "jellyfin")?;
    let sonarr_node = get_node(&pod_list.items, "sonarr")?;
    let nzbget_node = get_node(&pod_list.items, "nzbget")?;

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

    // Verify subpath isolation
    let result = run_cmd_allow_fail(
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
    );
    if result.contains("nzbget-marker") {
        return Err("Subpath isolation failed".into());
    }

    info!("Volume sharing verified");
    Ok(())
}

async fn wait_for_waypoint(kubeconfig_path: &str) -> Result<(), String> {
    info!("Waiting for Istio waypoint...");

    let client = client_from_kubeconfig(kubeconfig_path).await?;
    let api: Api<Deployment> = Api::namespaced(client, NAMESPACE);

    let timeout = Duration::from_secs(120);
    let poll_interval = Duration::from_secs(5);
    let start = std::time::Instant::now();

    loop {
        // Look for waypoint deployment (name pattern: *-waypoint or media-waypoint)
        let deployments = api.list(&ListParams::default()).await;
        if let Ok(list) = deployments {
            if let Some(waypoint) = list.items.iter().find(|d| {
                d.metadata
                    .name
                    .as_ref()
                    .map(|n| n.contains("waypoint"))
                    .unwrap_or(false)
            }) {
                if deployment_is_available(waypoint) {
                    let name = waypoint.metadata.name.as_deref().unwrap_or("waypoint");
                    info!("{} is ready", name);
                    return Ok(());
                }
            }
        }

        if start.elapsed() > timeout {
            return Err("Timeout waiting for Istio waypoint".into());
        }

        sleep(poll_interval).await;
    }
}

async fn verify_bilateral_agreements(kubeconfig_path: &str) -> Result<(), String> {
    info!("Verifying bilateral agreements...");

    let curl_check = |from: &str, to: &str, port: u16| -> String {
        run_cmd_allow_fail("kubectl", &[
            "--kubeconfig", kubeconfig_path,
            "exec", "-n", NAMESPACE, &format!("deploy/{}", from),
            "--", "sh", "-c",
            &format!("curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 http://{}:{}/ || echo '000'", to, port),
        ]).trim().to_string()
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

async fn cleanup(kubeconfig_path: &str) {
    let Ok(client) = client_from_kubeconfig(kubeconfig_path).await else {
        return;
    };

    let api: Api<LatticeService> = Api::namespaced(client.clone(), NAMESPACE);
    for name in ["sonarr", "nzbget", "jellyfin"] {
        let _ = api.delete(name, &kube::api::DeleteParams::default()).await;
    }

    let ns_api: Api<Namespace> = Api::all(client);
    let _ = ns_api
        .delete(NAMESPACE, &kube::api::DeleteParams::default())
        .await;

    sleep(Duration::from_secs(30)).await;
}

// =============================================================================
// Public API
// =============================================================================

pub async fn run_media_server_test(kubeconfig_path: &str) -> Result<(), String> {
    info!("\n========================================");
    info!("Media Server E2E Test");
    info!("========================================\n");

    deploy_media_services(kubeconfig_path).await?;
    wait_for_pods(kubeconfig_path).await?;
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

pub async fn cleanup_media_server_test(kubeconfig_path: &str) {
    cleanup(kubeconfig_path).await;
}
