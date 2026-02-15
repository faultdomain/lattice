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
    create_with_retry, ensure_fresh_namespace, ensure_test_cluster_issuer, load_service_config,
    run_kubectl, setup_regcreds_infrastructure, wait_for_condition,
    wait_for_service_phase_with_message,
};
use super::mesh_helpers::retry_verification;

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

    // Ensure cert-manager has a self-signed issuer matching the fixture references
    ensure_test_cluster_issuer(kubeconfig_path, "letsencrypt-prod").await?;

    // Cedar: permit security overrides for media services (including plex)
    for svc in ["jellyfin", "nzbget", "sonarr", "plex"] {
        apply_run_as_root_override_policy(kubeconfig_path, NAMESPACE, svc).await?;
    }
    // sonarr main container needs SETUID + SETGID for s6-overlay
    apply_cedar_policy_crd(
        kubeconfig_path,
        "permit-sonarr-caps",
        "e2e",
        50,
        r#"permit(
  principal == Lattice::Service::"media/sonarr",
  action == Lattice::Action::"OverrideSecurity",
  resource
) when {
  resource == Lattice::SecurityOverride::"capability:SETUID" ||
  resource == Lattice::SecurityOverride::"capability:SETGID"
};"#,
    )
    .await?;
    // nzbget: main needs SETUID + SETGID (s6-overlay), vpn sidecar needs NET_ADMIN + SYS_MODULE
    apply_cedar_policy_crd(
        kubeconfig_path,
        "permit-nzbget-caps",
        "e2e",
        50,
        r#"permit(
  principal == Lattice::Service::"media/nzbget",
  action == Lattice::Action::"OverrideSecurity",
  resource
) when {
  resource == Lattice::SecurityOverride::"capability:NET_ADMIN" ||
  resource == Lattice::SecurityOverride::"capability:SYS_MODULE" ||
  resource == Lattice::SecurityOverride::"capability:SETUID" ||
  resource == Lattice::SecurityOverride::"capability:SETGID"
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
    for filename in ["jellyfin.yaml", "nzbget.yaml", "sonarr.yaml", "plex.yaml"] {
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

async fn verify_gateway_routes(kubeconfig_path: &str) -> Result<(), String> {
    info!("Verifying Gateway API routes...");

    // Expected: one HTTPRoute per service, each with a hostname and backend
    let expected_routes: [(&str, &str, &str); 3] = [
        ("jellyfin", "jellyfin.home.local", "8096"),
        ("sonarr", "sonarr.home.local", "8989"),
        ("nzbget", "nzbget.home.local", "6789"),
    ];

    // 1. Wait for Gateway with correct listeners
    wait_for_condition(
        "Gateway media-ingress to have all listeners",
        Duration::from_secs(120),
        Duration::from_secs(5),
        || async {
            let output = run_kubectl(&[
                "--kubeconfig",
                kubeconfig_path,
                "get",
                "gateway",
                "media-ingress",
                "-n",
                NAMESPACE,
                "--ignore-not-found",
                "-o",
                "jsonpath={.spec.listeners[*].name}",
            ])
            .await
            .unwrap_or_default();

            let listeners: Vec<&str> = output.split_whitespace().collect();
            for (svc, _, _) in &expected_routes {
                for proto in ["http", "https"] {
                    let expected = format!("{}-public-{}-0", svc, proto);
                    if !listeners.iter().any(|l| *l == expected) {
                        info!(
                            "Gateway media-ingress: waiting for listener {} (have: {:?})",
                            expected, listeners
                        );
                        return Ok(false);
                    }
                }
            }
            info!(
                "Gateway media-ingress: {} listeners verified",
                listeners.len()
            );
            Ok(true)
        },
    )
    .await?;

    // 2. Wait for HTTPRoutes with correct hostnames and backends
    for (svc, host, port) in &expected_routes {
        let route_name = format!("{}-public-route", svc);
        let expected_host = host.to_string();
        let expected_backend = format!("{}:{}", svc, port);

        wait_for_condition(
            &format!("HTTPRoute {} to be correct", route_name),
            Duration::from_secs(120),
            Duration::from_secs(5),
            || {
                let route_name = route_name.clone();
                let expected_host = expected_host.clone();
                let expected_backend = expected_backend.clone();
                async move {
                    let output = run_kubectl(&[
                        "--kubeconfig",
                        kubeconfig_path,
                        "get",
                        "httproute",
                        &route_name,
                        "-n",
                        NAMESPACE,
                        "--ignore-not-found",
                        "-o",
                        "jsonpath={.spec.hostnames[0]} {.spec.rules[0].backendRefs[0].name}:{.spec.rules[0].backendRefs[0].port}",
                    ])
                    .await
                    .unwrap_or_default();

                    let parts: Vec<&str> = output.split_whitespace().collect();
                    if parts.len() != 2 {
                        info!("HTTPRoute {} not ready yet", route_name);
                        return Ok(false);
                    }
                    if parts[0] != expected_host || parts[1] != expected_backend {
                        info!(
                            "HTTPRoute {} mismatch: host={} backend={} (expected {} {})",
                            route_name, parts[0], parts[1], expected_host, expected_backend
                        );
                        return Ok(false);
                    }
                    info!("HTTPRoute {} -> {} (backend {})", route_name, expected_host, expected_backend);
                    Ok(true)
                }
            },
        )
        .await?;
    }

    // 3. Wait for Certificates with correct DNS names and issuer
    for (svc, host, _) in &expected_routes {
        let cert_name = format!("{}-public-cert", svc);
        let expected_host = host.to_string();

        wait_for_condition(
            &format!("Certificate {} to be correct", cert_name),
            Duration::from_secs(120),
            Duration::from_secs(5),
            || {
                let cert_name = cert_name.clone();
                let expected_host = expected_host.clone();
                async move {
                    let output = run_kubectl(&[
                        "--kubeconfig",
                        kubeconfig_path,
                        "get",
                        "certificate",
                        &cert_name,
                        "-n",
                        NAMESPACE,
                        "--ignore-not-found",
                        "-o",
                        "jsonpath={.spec.dnsNames[0]} {.spec.issuerRef.name}",
                    ])
                    .await
                    .unwrap_or_default();

                    let parts: Vec<&str> = output.split_whitespace().collect();
                    if parts.len() != 2 {
                        info!("Certificate {} not ready yet", cert_name);
                        return Ok(false);
                    }
                    if parts[0] != expected_host || parts[1] != "letsencrypt-prod" {
                        info!(
                            "Certificate {} mismatch: dns={} issuer={} (expected {} letsencrypt-prod)",
                            cert_name, parts[0], parts[1], expected_host
                        );
                        return Ok(false);
                    }
                    info!("Certificate {} -> {} (issuer: letsencrypt-prod)", cert_name, expected_host);
                    Ok(true)
                }
            },
        )
        .await?;
    }

    info!("Gateway API routes verified");
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

/// Write a marker file in one deploy, then poll-read it from another deploy.
async fn verify_volume_marker(
    kubeconfig_path: &str,
    writer_deploy: &str,
    writer_path: &str,
    reader_deploy: &str,
    reader_path: &str,
    marker: &str,
) -> Result<(), String> {
    let kp = kubeconfig_path.to_string();
    let writer_target = format!("deploy/{}", writer_deploy);
    let reader_target = format!("deploy/{}", reader_deploy);
    let write_cmd = format!("echo '{}' > {}", marker, writer_path);
    let read_cmd = format!("cat {}", reader_path);
    let marker = marker.to_string();

    wait_for_condition(
        &format!(
            "{} to read {}'s marker via shared volume",
            reader_deploy, writer_deploy
        ),
        Duration::from_secs(180),
        Duration::from_secs(3),
        || {
            let kp = kp.clone();
            let writer_target = writer_target.clone();
            let reader_target = reader_target.clone();
            let write_cmd = write_cmd.clone();
            let read_cmd = read_cmd.clone();
            let marker = marker.clone();
            async move {
                let _ = run_kubectl(&[
                    "--kubeconfig",
                    &kp,
                    "exec",
                    "-n",
                    NAMESPACE,
                    &writer_target,
                    "--",
                    "sh",
                    "-c",
                    &write_cmd,
                ])
                .await;
                match run_kubectl(&[
                    "--kubeconfig",
                    &kp,
                    "exec",
                    "-n",
                    NAMESPACE,
                    &reader_target,
                    "--",
                    "sh",
                    "-c",
                    &read_cmd,
                ])
                .await
                {
                    Ok(result) => Ok(result.contains(&marker)),
                    Err(_) => Ok(false),
                }
            }
        },
    )
    .await
}

async fn verify_volume_sharing(kubeconfig_path: &str) -> Result<(), String> {
    info!("Verifying volume sharing...");

    // jellyfin writes to library/, sonarr reads it
    verify_volume_marker(
        kubeconfig_path,
        "jellyfin",
        "/media/.test-marker",
        "sonarr",
        "/tv/.test-marker",
        "jellyfin-marker",
    )
    .await?;

    // nzbget writes to downloads/, sonarr reads it
    verify_volume_marker(
        kubeconfig_path,
        "nzbget",
        "/downloads/.test-marker",
        "sonarr",
        "/downloads/.test-marker",
        "nzbget-marker",
    )
    .await?;

    // Verify subpath isolation - jellyfin should NOT see nzbget's marker in its /media mount
    let deploy_jellyfin = "deploy/jellyfin".to_string();
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

async fn verify_unauthorized_volume_access_denied(kubeconfig_path: &str) -> Result<(), String> {
    info!("Verifying unauthorized volume access is denied...");

    // plex was deployed alongside the other services in deploy_media_services().
    // It references media-storage but is NOT in jellyfin's allowedConsumers —
    // the compiler should reject it with a volume access denied error.
    wait_for_service_phase_with_message(
        kubeconfig_path,
        NAMESPACE,
        "plex",
        "Failed",
        "volume access denied",
        Duration::from_secs(120),
    )
    .await?;

    // Clean up — delete the rejected service so it doesn't interfere with other tests
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig_path,
        "delete",
        "latticeservice",
        "plex",
        "-n",
        NAMESPACE,
        "--ignore-not-found",
    ])
    .await?;

    info!("Unauthorized volume access correctly denied");
    Ok(())
}

/// Execute a curl from one deployment to another and return the HTTP status code.
async fn exec_curl(
    kubeconfig_path: &str,
    from_deploy: &str,
    url: &str,
) -> String {
    let target = format!("deploy/{}", from_deploy);
    let cmd = format!(
        "curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 5 --max-time 10 {} || echo '000'",
        url
    );
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig_path,
        "exec",
        "-n",
        NAMESPACE,
        &target,
        "--",
        "sh",
        "-c",
        &cmd,
    ])
    .await
    .unwrap_or_else(|_| "000".to_string())
    .trim()
    .to_string()
}

/// Check if a status code indicates a successful (allowed) response.
fn is_allowed_code(code: &str) -> bool {
    matches!(code, "200" | "201" | "204" | "301" | "302")
}

/// Check if a status code indicates a policy block.
fn is_blocked_code(code: &str) -> bool {
    code == "403"
}


async fn verify_bilateral_agreements(kubeconfig_path: &str) -> Result<(), String> {
    info!("Verifying bilateral agreements...");

    // sonarr -> jellyfin (allowed: bilateral agreement)
    let code = exec_curl(kubeconfig_path, "sonarr", "http://jellyfin:8096/").await;
    if !is_allowed_code(&code) {
        return Err(format!("sonarr->jellyfin should be allowed but got {}", code));
    }
    info!("sonarr->jellyfin: {} (allowed)", code);

    // sonarr -> nzbget (allowed: bilateral agreement)
    let code = exec_curl(kubeconfig_path, "sonarr", "http://nzbget:6789/").await;
    if !is_allowed_code(&code) {
        return Err(format!("sonarr->nzbget should be allowed but got {}", code));
    }
    info!("sonarr->nzbget: {} (allowed)", code);

    // jellyfin -> sonarr (blocked: no bilateral agreement)
    let code = exec_curl(kubeconfig_path, "jellyfin", "http://sonarr:8989/").await;
    if !is_blocked_code(&code) {
        return Err(format!(
            "jellyfin->sonarr should be blocked at L4 (000) but got {}",
            code
        ));
    }
    info!("jellyfin->sonarr: {} (blocked at L4 as expected)", code);

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
    verify_gateway_routes(kubeconfig_path).await?;
    verify_pvcs(kubeconfig_path).await?;
    verify_node_colocation(kubeconfig_path).await?;
    verify_volume_sharing(kubeconfig_path).await?;
    verify_unauthorized_volume_access_denied(kubeconfig_path).await?;

    let kc = kubeconfig_path.to_string();
    retry_verification("Media Server", || verify_bilateral_agreements(&kc)).await?;

    info!("\n========================================");
    info!("Media Server E2E Test: PASSED");
    info!("========================================\n");

    Ok(())
}
