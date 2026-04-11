//! DNS integration tests — external-dns + CoreDNS forwarding
//!
//! Tests the full pipeline: DNSProvider CRD → external-dns deployment →
//! LatticeService with ingress → Gateway API HTTPRoute → external-dns
//! creates PiHole record → CoreDNS forwards queries → pod resolves hostname.
//!
//! Requires: LATTICE_PIHOLE_URL, LATTICE_PIHOLE_RESOLVER env vars set.
//! Assumes: a workload cluster with the Lattice operator running.

use tracing::info;

use super::super::helpers::cedar::apply_yaml;
use super::super::helpers::docker::run_kubectl;
use super::super::helpers::pihole::{pihole_resolver, pihole_url, PIHOLE_PASSWORD};
use super::super::helpers::{
    wait_for_condition, wait_for_resource_phase, DEFAULT_TIMEOUT, POLL_INTERVAL,
};

const TEST_ZONE: &str = "e2e.internal";
const DNS_TEST_NAMESPACE: &str = "dns-test";
const LATTICE_NS: &str = "lattice-system";
const SECRETS_NS: &str = "lattice-secrets";
const PIHOLE_DNS_PROVIDER: &str = "pihole-e2e";
const PIHOLE_SECRET_REMOTE_KEY: &str = "pihole-credentials";

/// Run all DNS integration tests.
pub async fn run_dns_tests(kubeconfig: &str) -> Result<(), String> {
    info!("========================================");
    info!("DNS INTEGRATION TESTS");
    info!("========================================");

    super::super::helpers::ensure_namespace(kubeconfig, DNS_TEST_NAMESPACE).await?;

    setup_dns_provider(kubeconfig).await?;
    test_external_dns_deployment(kubeconfig).await?;
    test_dns_end_to_end(kubeconfig).await?;

    cleanup(kubeconfig).await;
    Ok(())
}

// =============================================================================
// Setup: DNSProvider CRD
// =============================================================================

async fn setup_dns_provider(kubeconfig: &str) -> Result<(), String> {
    info!("[DNS] Creating DNSProvider '{PIHOLE_DNS_PROVIDER}'...");

    let pihole = pihole_url();
    let resolver = pihole_resolver();

    // Create ESO source secret with PiHole password
    let secret_yaml = format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: {PIHOLE_SECRET_REMOTE_KEY}
  namespace: {SECRETS_NS}
  labels:
    lattice.dev/secret-source: "true"
type: Opaque
stringData:
  EXTERNAL_DNS_PIHOLE_PASSWORD: "{PIHOLE_PASSWORD}""#
    );
    apply_yaml(kubeconfig, &secret_yaml).await?;

    let dns_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: DNSProvider
metadata:
  name: {PIHOLE_DNS_PROVIDER}
  namespace: {LATTICE_NS}
spec:
  type: pihole
  zone: {TEST_ZONE}
  resolver: "{resolver}"
  credentials:
    id: {PIHOLE_SECRET_REMOTE_KEY}
    provider: lattice-local
    keys:
      - EXTERNAL_DNS_PIHOLE_PASSWORD
  pihole:
    url: "{pihole}""#
    );
    apply_yaml(kubeconfig, &dns_yaml).await?;

    wait_for_resource_phase(
        kubeconfig,
        "dnsprovider",
        LATTICE_NS,
        PIHOLE_DNS_PROVIDER,
        "Ready",
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!("[DNS] DNSProvider '{PIHOLE_DNS_PROVIDER}' is Ready");
    Ok(())
}

// =============================================================================
// Test: external-dns deployment
// =============================================================================

async fn test_external_dns_deployment(kubeconfig: &str) -> Result<(), String> {
    info!("[DNS] Testing external-dns deployment...");

    let pihole = pihole_url();

    // Wait for external-dns deployment to become available
    let kc = kubeconfig.to_string();
    wait_for_condition(
        &format!("external-dns-{PIHOLE_DNS_PROVIDER} deployment to be available"),
        std::time::Duration::from_secs(600),
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                let result = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "deployment",
                    &format!("external-dns-{PIHOLE_DNS_PROVIDER}"),
                    "-n",
                    "external-dns",
                    "-o",
                    "jsonpath={.status.availableReplicas}",
                ])
                .await;
                Ok(result.map(|s| s.trim() == "1").unwrap_or(false))
            }
        },
    )
    .await?;

    // Verify correct provider args
    let args = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "deployment",
        &format!("external-dns-{PIHOLE_DNS_PROVIDER}"),
        "-n",
        "external-dns",
        "-o",
        "jsonpath={.spec.template.spec.containers[0].args}",
    ])
    .await?;

    if !args.contains("--provider=pihole") {
        return Err(format!("external-dns missing --provider=pihole: {args}"));
    }
    if !args.contains(&format!("--pihole-server={pihole}")) {
        return Err(format!("external-dns missing pihole-server: {args}"));
    }
    if !args.contains("--source=gateway-httproute") {
        return Err(format!(
            "external-dns missing gateway-httproute source: {args}"
        ));
    }

    info!("[DNS] external-dns is running with correct config");
    Ok(())
}

// =============================================================================
// Test: End-to-end DNS resolution via LatticeService → external-dns → PiHole
// =============================================================================

async fn test_dns_end_to_end(kubeconfig: &str) -> Result<(), String> {
    info!("[DNS] Testing end-to-end: LatticeService → external-dns → PiHole → CoreDNS...");

    let resolver = pihole_resolver();
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        % 100_000;
    let svc_name = format!("dns-{suffix}");
    let dns_hostname = format!("{svc_name}.{TEST_ZONE}");

    // Verify CoreDNS Corefile has the forward block
    let corefile = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "configmap",
        "-n",
        "kube-system",
        "-l",
        "k8s-app=kube-dns",
        "-o",
        "jsonpath={.items[0].data.Corefile}",
    ])
    .await?;

    if !corefile.contains(TEST_ZONE) || !corefile.contains(&resolver) {
        return Err(format!(
            "CoreDNS Corefile missing forwarding for {TEST_ZONE} -> {resolver}, got:\n{}",
            super::super::helpers::truncate(&corefile, 500)
        ));
    }
    info!("[DNS] CoreDNS Corefile has forward block for {TEST_ZONE} -> {resolver}");

    // Deploy a LatticeService with an ingress route in the test zone.
    // external-dns watches the resulting HTTPRoute and creates the PiHole record.
    let svc_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: {svc_name}
  namespace: {DNS_TEST_NAMESPACE}
spec:
  workload:
    containers:
      main:
        image: nginx:latest
        resources:
          limits:
            cpu: 100m
            memory: 64Mi
    service:
      ports:
        http:
          port: 80
  ingress:
    routes:
      public:
        kind: HTTPRoute
        hosts:
          - {dns_hostname}"#
    );
    apply_yaml(kubeconfig, &svc_yaml).await?;
    info!("[DNS] Deployed LatticeService with ingress host {dns_hostname}");

    // Wait for the service to reach Ready
    wait_for_resource_phase(
        kubeconfig,
        "latticeservice",
        DNS_TEST_NAMESPACE,
        &svc_name,
        "Ready",
        DEFAULT_TIMEOUT,
    )
    .await?;
    info!("[DNS] LatticeService is Ready");

    // Wait for external-dns to sync the HTTPRoute → PiHole record,
    // then verify CoreDNS resolves the hostname from inside the cluster.
    let kc = kubeconfig.to_string();
    wait_for_condition(
        &format!("DNS resolution of {dns_hostname}"),
        std::time::Duration::from_secs(180),
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            let hostname = dns_hostname.clone();
            async move {
                let _ = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "delete",
                    "pod",
                    "-n",
                    "kube-system",
                    "dns-resolve-test",
                    "--ignore-not-found",
                ])
                .await;

                let result = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "run",
                    "dns-resolve-test",
                    "-n",
                    "kube-system",
                    "--rm",
                    "-i",
                    "--restart=Never",
                    "--image=busybox:1.36",
                    "--",
                    "nslookup",
                    &hostname,
                ])
                .await;

                match result {
                    Ok(output) if output.contains("Address") && !output.contains("NXDOMAIN") => {
                        Ok(true)
                    }
                    Ok(_) => Ok(false),
                    Err(_) => Ok(false),
                }
            }
        },
    )
    .await
    .map_err(|e| {
        format!("DNS resolution failed for {dns_hostname} (external-dns may not have synced): {e}")
    })?;

    info!("[DNS] external-dns created record, CoreDNS resolved {dns_hostname}");
    Ok(())
}

// =============================================================================
// Cleanup
// =============================================================================

async fn cleanup(kubeconfig: &str) {
    info!("[DNS/Cleanup] Cleaning up DNS test resources...");

    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "pod",
        "-n",
        "kube-system",
        "dns-resolve-test",
        "--ignore-not-found",
    ])
    .await;

    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "namespace",
        DNS_TEST_NAMESPACE,
        "--ignore-not-found",
    ])
    .await;

    for (kind, name) in [("dnsprovider", PIHOLE_DNS_PROVIDER)] {
        let _ = run_kubectl(&[
            "--kubeconfig",
            kubeconfig,
            "delete",
            kind,
            name,
            "-n",
            LATTICE_NS,
            "--ignore-not-found",
        ])
        .await;
    }

    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "secret",
        PIHOLE_SECRET_REMOTE_KEY,
        "-n",
        SECRETS_NS,
        "--ignore-not-found",
    ])
    .await;

    info!("[DNS/Cleanup] Done");
}

// =============================================================================
// Standalone Test
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_dns_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_dns_tests(&resolved.kubeconfig).await.unwrap();
}
