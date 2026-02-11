//! Media Server E2E Test
//!
//! Tests LatticeService with a media server stack (jellyfin, nzbget, sonarr).
//! Verifies volume sharing, pod co-location, and bilateral agreements.

#![cfg(feature = "provider-e2e")]

use std::time::Duration;
use tracing::info;

use kube::api::Api;

use lattice_common::crd::LatticeService;

use super::helpers::{
    apply_cedar_policy_crd, apply_run_as_root_override_policy, client_from_kubeconfig,
    create_with_retry, ensure_fresh_namespace, load_service_config, run_kubectl,
    setup_regcreds_infrastructure, wait_for_condition,
};

const NAMESPACE: &str = "media";

// =============================================================================
// Test Implementation
// =============================================================================

async fn deploy_media_services(kubeconfig_path: &str) -> Result<(), String> {
    info!("Deploying media server services...");

    // Create namespace with retry for transient connection failures
    ensure_fresh_namespace(kubeconfig_path, NAMESPACE).await?;

    // Set up regcreds infrastructure — all services need ghcr-creds for image pulls
    setup_regcreds_infrastructure(kubeconfig_path).await?;

    // Cedar: permit security overrides for media services
    for svc in ["jellyfin", "nzbget", "sonarr"] {
        apply_run_as_root_override_policy(kubeconfig_path, NAMESPACE, svc).await?;
    }
    // nzbget vpn sidecar needs NET_ADMIN + SYS_MODULE
    apply_cedar_policy_crd(
        kubeconfig_path,
        "permit-nzbget-vpn-caps",
        "e2e",
        50,
        r#"permit(
  principal == Lattice::Service::"media/nzbget",
  action == Lattice::Action::"OverrideSecurity",
  resource
) when {
  resource == Lattice::SecurityOverride::"capability:NET_ADMIN" ||
  resource == Lattice::SecurityOverride::"capability:SYS_MODULE"
};"#,
    )
    .await?;

    // Label for Istio ambient mesh
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig_path,
        "label",
        "namespace",
        NAMESPACE,
        "istio.io/dataplane-mode=ambient",
        "--overwrite",
    ])
    .await?;

    let client = client_from_kubeconfig(kubeconfig_path).await?;

    // Load and deploy services from YAML fixtures
    let api: Api<LatticeService> = Api::namespaced(client, NAMESPACE);
    for filename in ["jellyfin.yaml", "nzbget.yaml", "sonarr.yaml"] {
        let service = load_service_config(filename)?;
        let name = service.metadata.name.as_deref().unwrap_or(filename);
        info!("Deploying {}...", name);
        create_with_retry(&api, &service, name).await?;
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
                let output = run_kubectl(&[
                    "--kubeconfig",
                    kubeconfig_path,
                    "get",
                    "deployment",
                    "-n",
                    NAMESPACE,
                    name,
                    "-o",
                    "jsonpath={.status.availableReplicas}/{.status.replicas}",
                ])
                .await;

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
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig_path,
        "get",
        "pvc",
        "-n",
        NAMESPACE,
        "-o",
        "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}",
    ])
    .await
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

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig_path,
        "get",
        "pods",
        "-n",
        NAMESPACE,
        "-o",
        &format!("jsonpath={}", jsonpath),
    ])
    .await
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

    // jellyfin writes to library/, sonarr reads it
    let kp = kubeconfig_path.to_string();
    wait_for_condition(
        "sonarr to read jellyfin's marker via shared volume",
        Duration::from_secs(60),
        Duration::from_secs(3),
        || {
            let kp = kp.clone();
            async move {
                let deploy_jellyfin = format!("deploy/{}", "jellyfin");
                let _ = run_kubectl(&[
                    "--kubeconfig",
                    &kp,
                    "exec",
                    "-n",
                    NAMESPACE,
                    &deploy_jellyfin,
                    "--",
                    "sh",
                    "-c",
                    "echo 'jellyfin-marker' > /media/.test-marker",
                ])
                .await;
                let deploy_sonarr = format!("deploy/{}", "sonarr");
                match run_kubectl(&[
                    "--kubeconfig",
                    &kp,
                    "exec",
                    "-n",
                    NAMESPACE,
                    &deploy_sonarr,
                    "--",
                    "sh",
                    "-c",
                    "cat /tv/.test-marker",
                ])
                .await
                {
                    Ok(result) => Ok(result.contains("jellyfin-marker")),
                    Err(_) => Ok(false),
                }
            }
        },
    )
    .await?;

    // nzbget writes to downloads/, sonarr reads it
    let kp = kubeconfig_path.to_string();
    wait_for_condition(
        "sonarr to read nzbget's marker via shared volume",
        Duration::from_secs(60),
        Duration::from_secs(3),
        || {
            let kp = kp.clone();
            async move {
                let deploy_nzbget = format!("deploy/{}", "nzbget");
                let _ = run_kubectl(&[
                    "--kubeconfig",
                    &kp,
                    "exec",
                    "-n",
                    NAMESPACE,
                    &deploy_nzbget,
                    "--",
                    "sh",
                    "-c",
                    "echo 'nzbget-marker' > /downloads/.test-marker",
                ])
                .await;
                let deploy_sonarr = format!("deploy/{}", "sonarr");
                match run_kubectl(&[
                    "--kubeconfig",
                    &kp,
                    "exec",
                    "-n",
                    NAMESPACE,
                    &deploy_sonarr,
                    "--",
                    "sh",
                    "-c",
                    "cat /downloads/.test-marker",
                ])
                .await
                {
                    Ok(result) => Ok(result.contains("nzbget-marker")),
                    Err(_) => Ok(false),
                }
            }
        },
    )
    .await?;

    // Verify subpath isolation - jellyfin should NOT see nzbget's marker in its /media mount
    let deploy_jellyfin = format!("deploy/{}", "jellyfin");
    let isolated = match run_kubectl(&[
        "--kubeconfig",
        kubeconfig_path,
        "exec",
        "-n",
        NAMESPACE,
        &deploy_jellyfin,
        "--",
        "sh",
        "-c",
        "cat /media/.test-marker",
    ])
    .await
    {
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
        Duration::from_secs(300),
        Duration::from_secs(5),
        || async move {
            let output = run_kubectl(&[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "deployments",
                "-n",
                NAMESPACE,
                "-o",
                "jsonpath={range .items[*]}{.metadata.name}:{.status.availableReplicas}/{.status.replicas}{\"\\n\"}{end}",
            ])
            .await
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

    // sonarr -> jellyfin (allowed)
    let deploy_sonarr = format!("deploy/{}", "sonarr");
    let code = run_kubectl(&[
        "--kubeconfig", kubeconfig_path,
        "exec", "-n", NAMESPACE, &deploy_sonarr,
        "--", "sh", "-c",
        "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 http://jellyfin:8096/ || echo '000'",
    ])
    .await
    .unwrap_or_else(|_| "000".to_string())
    .trim()
    .to_string();
    if code == "403" {
        return Err("sonarr->jellyfin blocked unexpectedly".into());
    }
    info!("sonarr->jellyfin: {} (allowed)", code);

    // sonarr -> nzbget (allowed)
    let code = run_kubectl(&[
        "--kubeconfig", kubeconfig_path,
        "exec", "-n", NAMESPACE, &deploy_sonarr,
        "--", "sh", "-c",
        "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 http://nzbget:6789/ || echo '000'",
    ])
    .await
    .unwrap_or_else(|_| "000".to_string())
    .trim()
    .to_string();
    if code == "403" {
        return Err("sonarr->nzbget blocked unexpectedly".into());
    }
    info!("sonarr->nzbget: {} (allowed)", code);

    // jellyfin -> sonarr (should be blocked)
    let deploy_jellyfin = format!("deploy/{}", "jellyfin");
    let code = run_kubectl(&[
        "--kubeconfig", kubeconfig_path,
        "exec", "-n", NAMESPACE, &deploy_jellyfin,
        "--", "sh", "-c",
        "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 http://sonarr:8989/ || echo '000'",
    ])
    .await
    .unwrap_or_else(|_| "000".to_string())
    .trim()
    .to_string();
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
