//! Cert-manager and DNS integration tests
//!
//! Tests the full flow from CRD creation through to cert-manager ClusterIssuer
//! materialization, certificate issuance, external-dns record creation, and
//! CoreDNS resolution of private zones.
//!
//! ## Prerequisites
//!
//! - PiHole running at 10.0.0.131 (docker-compose `lattice-pihole`, password: "lattice")
//! - cert-manager installed on the cluster
//! - Lattice operator running
//!
//! ## Running
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_cert_manager_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use tracing::info;

use super::super::helpers::cedar::apply_yaml;
use super::super::helpers::docker::run_kubectl;
use super::super::helpers::pihole::{
    pihole_resolver, pihole_url, PIHOLE_API_TOKEN, PIHOLE_PASSWORD,
};
use super::super::helpers::{
    wait_for_condition, wait_for_resource_phase, DEFAULT_TIMEOUT, POLL_INTERVAL,
};

// =============================================================================
// Constants
// =============================================================================

const TEST_ZONE: &str = "e2e.local";
const CERT_TEST_NAMESPACE: &str = "cert-manager-test";
const LATTICE_NS: &str = "lattice-system";
const SECRETS_NS: &str = "lattice-secrets";
const PIHOLE_DNS_PROVIDER: &str = "pihole-e2e";
const PIHOLE_SECRET_REMOTE_KEY: &str = "pihole-credentials";
const SELF_SIGNED_ISSUER: &str = "e2e-selfsigned";
const ACME_HTTP_ISSUER: &str = "e2e-acme-http";
const EXPECTED_CLUSTER_ISSUER: &str = "lattice-dev";

// Must match lattice_common::LATTICE_MANAGED_BY_*
const MANAGED_BY_LABEL: &str = "lattice.dev/managed-by";
const MANAGED_BY_VALUE: &str = "lattice-operator";

// =============================================================================
// Main Test Runner
// =============================================================================

/// Run the full cert-manager and DNS integration test suite.
pub async fn run_cert_manager_tests(kubeconfig: &str) -> Result<(), String> {
    info!("========================================");
    info!("CERT-MANAGER & DNS INTEGRATION TESTS");
    info!("========================================");

    super::super::helpers::ensure_fresh_namespace(kubeconfig, CERT_TEST_NAMESPACE).await?;

    // Delete stale ClusterIssuer from previous failed runs
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "clusterissuer",
        EXPECTED_CLUSTER_ISSUER,
        "--ignore-not-found",
    ])
    .await;

    test_dns_provider_lifecycle(kubeconfig).await?;
    test_cert_issuer_lifecycle(kubeconfig).await?;
    test_cluster_issuer_materialization(kubeconfig).await?;
    test_certificate_issuance(kubeconfig).await?;
    test_external_dns_deployment(kubeconfig).await?;
    test_coredns_forwarding(kubeconfig).await?;
    test_cluster_issuer_cleanup(kubeconfig).await?;

    cleanup_test_resources(kubeconfig).await;
    Ok(())
}

// =============================================================================
// Test: DNSProvider CRD Lifecycle
// =============================================================================

async fn test_dns_provider_lifecycle(kubeconfig: &str) -> Result<(), String> {
    info!("[DNS] Testing DNSProvider CRD lifecycle...");

    let pihole = pihole_url();
    let resolver = pihole_resolver();

    // Create the source secret in lattice-secrets namespace for the local
    // webhook ESO backend. The webhook serves secrets with the source label.
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

    // Create a PiHole DNSProvider with ESO-managed credentials.
    // The DNS provider controller creates an ExternalSecret in the
    // external-dns namespace; ESO syncs it so the pod can read it.
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
    info!(
        "[DNS] DNSProvider '{}' created with ESO credentials, waiting for Ready...",
        PIHOLE_DNS_PROVIDER
    );

    wait_for_resource_phase(
        kubeconfig,
        "dnsprovider",
        LATTICE_NS,
        PIHOLE_DNS_PROVIDER,
        "Ready",
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!("[DNS] DNSProvider '{}' is Ready", PIHOLE_DNS_PROVIDER);
    Ok(())
}

// =============================================================================
// Test: CertIssuer CRD Lifecycle
// =============================================================================

async fn test_cert_issuer_lifecycle(kubeconfig: &str) -> Result<(), String> {
    info!("[Cert] Testing CertIssuer CRD lifecycle...");

    let selfsigned_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: CertIssuer
metadata:
  name: {SELF_SIGNED_ISSUER}
  namespace: {LATTICE_NS}
spec:
  type: selfSigned"#
    );
    apply_yaml(kubeconfig, &selfsigned_yaml).await?;

    wait_for_resource_phase(
        kubeconfig,
        "certissuer",
        LATTICE_NS,
        SELF_SIGNED_ISSUER,
        "Ready",
        DEFAULT_TIMEOUT,
    )
    .await?;
    info!(
        "[Cert] CertIssuer '{}' (selfSigned) is Ready",
        SELF_SIGNED_ISSUER
    );

    let acme_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: CertIssuer
metadata:
  name: {ACME_HTTP_ISSUER}
  namespace: {LATTICE_NS}
spec:
  type: acme
  acme:
    email: e2e-test@lattice.dev
    server: https://acme-staging-v02.api.letsencrypt.org/directory"#
    );
    apply_yaml(kubeconfig, &acme_yaml).await?;

    wait_for_resource_phase(
        kubeconfig,
        "certissuer",
        LATTICE_NS,
        ACME_HTTP_ISSUER,
        "Ready",
        DEFAULT_TIMEOUT,
    )
    .await?;
    info!(
        "[Cert] CertIssuer '{}' (ACME HTTP-01) is Ready",
        ACME_HTTP_ISSUER
    );

    Ok(())
}

// =============================================================================
// Test: ClusterIssuer Materialization
// =============================================================================

async fn test_cluster_issuer_materialization(kubeconfig: &str) -> Result<(), String> {
    info!("[Cert] Testing ClusterIssuer materialization...");

    let cluster_name = super::super::helpers::get_workload_cluster_name();
    let patch = format!(r#"{{"spec":{{"issuers":{{"dev":"{SELF_SIGNED_ISSUER}"}}}}}}"#);

    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "patch",
        "latticecluster",
        &cluster_name,
        "--type=merge",
        "-p",
        &patch,
    ])
    .await
    .map_err(|e| format!("Failed to patch LatticeCluster: {e}"))?;

    info!(
        "[Cert] Patched cluster '{}' with issuers.dev='{}'",
        cluster_name, SELF_SIGNED_ISSUER
    );

    // Wait for ClusterIssuer to appear
    let kc = kubeconfig.to_string();
    wait_for_condition(
        &format!("ClusterIssuer '{}' to exist", EXPECTED_CLUSTER_ISSUER),
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                Ok(run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "clusterissuer",
                    EXPECTED_CLUSTER_ISSUER,
                    "-o",
                    "name",
                ])
                .await
                .is_ok())
            }
        },
    )
    .await?;

    // Verify selfSigned spec
    let spec = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "clusterissuer",
        EXPECTED_CLUSTER_ISSUER,
        "-o",
        "jsonpath={.spec}",
    ])
    .await?;

    if !spec.contains("selfSigned") {
        return Err(format!("ClusterIssuer spec missing selfSigned: {spec}"));
    }

    // Verify managed-by label
    // Dots in label keys must be escaped in jsonpath expressions
    let escaped_label = MANAGED_BY_LABEL.replace('.', r"\.");
    let label_path = format!("jsonpath={{.metadata.labels.{escaped_label}}}");
    let label = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "clusterissuer",
        EXPECTED_CLUSTER_ISSUER,
        "-o",
        &label_path,
    ])
    .await?;

    if label.trim() != MANAGED_BY_VALUE {
        return Err(format!(
            "Wrong managed-by label: expected '{}', got '{}'",
            MANAGED_BY_VALUE,
            label.trim()
        ));
    }

    info!(
        "[Cert] ClusterIssuer '{}' materialized correctly",
        EXPECTED_CLUSTER_ISSUER
    );
    Ok(())
}

// =============================================================================
// Test: Certificate Issuance
// =============================================================================

async fn test_certificate_issuance(kubeconfig: &str) -> Result<(), String> {
    info!("[Cert] Testing certificate issuance...");

    let cert_yaml = format!(
        r#"apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: e2e-test-cert
  namespace: {CERT_TEST_NAMESPACE}
spec:
  secretName: e2e-test-cert-tls
  issuerRef:
    name: {EXPECTED_CLUSTER_ISSUER}
    kind: ClusterIssuer
    group: cert-manager.io
  commonName: e2e-test.local
  dnsNames:
    - e2e-test.local
    - "*.e2e-test.local""#
    );
    apply_yaml(kubeconfig, &cert_yaml).await?;

    // Wait for Certificate Ready
    let kc = kubeconfig.to_string();
    wait_for_condition(
        "Certificate 'e2e-test-cert' to be Ready",
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                let status = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "certificate",
                    "e2e-test-cert",
                    "-n",
                    CERT_TEST_NAMESPACE,
                    "-o",
                    "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}",
                ])
                .await;
                Ok(status.map(|s| s.trim() == "True").unwrap_or(false))
            }
        },
    )
    .await?;

    // Verify TLS secret
    let secret_type = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "secret",
        "e2e-test-cert-tls",
        "-n",
        CERT_TEST_NAMESPACE,
        "-o",
        "jsonpath={.type}",
    ])
    .await?;

    if secret_type.trim() != "kubernetes.io/tls" {
        return Err(format!("TLS secret wrong type: {}", secret_type.trim()));
    }

    info!("[Cert] Certificate issued, TLS secret created");
    Ok(())
}

// =============================================================================
// Test: External-DNS Deployment
// =============================================================================

async fn test_external_dns_deployment(kubeconfig: &str) -> Result<(), String> {
    info!("[DNS] Testing external-dns deployment...");
    let pihole = pihole_url();

    // The operator should have deployed external-dns for the PiHole provider
    // when we added the dns config to the cluster. First, patch the cluster
    // to reference the PiHole DNSProvider.
    let cluster_name = super::super::helpers::get_workload_cluster_name();
    let patch =
        format!(r#"{{"spec":{{"dns":{{"providers":{{"local":"{PIHOLE_DNS_PROVIDER}"}}}}}}}}"#);

    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "patch",
        "latticecluster",
        &cluster_name,
        "--type=merge",
        "-p",
        &patch,
    ])
    .await
    .map_err(|e| format!("Failed to patch LatticeCluster with dns: {e}"))?;

    info!(
        "[DNS] Patched cluster with dns.providers.local='{}'",
        PIHOLE_DNS_PROVIDER
    );

    // Wait for external-dns deployment to appear
    let kc = kubeconfig.to_string();
    wait_for_condition(
        &format!("external-dns-{PIHOLE_DNS_PROVIDER} deployment to be available"),
        DEFAULT_TIMEOUT,
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

    // Verify the deployment has correct PiHole args
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
        return Err(format!(
            "external-dns missing --provider=pihole in args: {args}"
        ));
    }
    if !args.contains(&format!("--pihole-server={pihole}")) {
        return Err(format!("external-dns missing pihole-server arg: {args}"));
    }

    info!("[DNS] external-dns deployment is running with correct PiHole config");
    Ok(())
}

// =============================================================================
// Test: CoreDNS Forwarding
// =============================================================================

async fn test_coredns_forwarding(kubeconfig: &str) -> Result<(), String> {
    info!("[DNS] Testing CoreDNS forwarding for private zone...");

    let resolver = pihole_resolver();
    let pihole = pihole_url();

    // The operator patches the CoreDNS Corefile with a forward block for
    // the private zone. Verify the Corefile contains our zone + resolver.
    // The ConfigMap name varies by distribution (kubeadm vs RKE2), so list
    // by label and find the one with a Corefile key.
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
            "CoreDNS Corefile missing forwarding for {} -> {}, got:\n{}",
            TEST_ZONE,
            resolver,
            super::super::helpers::truncate(&corefile, 500)
        ));
    }

    info!(
        "[DNS] CoreDNS Corefile has forward block for {} -> {}",
        TEST_ZONE, resolver
    );

    // Add a test record to PiHole via its API
    // Run ephemeral pods in kube-system to bypass Cilium default-deny policies.
    let _ = run_kubectl(&[
        "--kubeconfig", kubeconfig,
        "delete", "pod", "-n", "kube-system", "dns-test", "--ignore-not-found",
    ]).await;

    let add_result = run_kubectl(&[
        "--kubeconfig", kubeconfig,
        "run", "dns-test", "-n", "kube-system", "--rm", "-i", "--restart=Never",
        "--image=curlimages/curl:8.5.0",
        "--", "curl", "-s", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}",
        "-d", "",
        &format!(
            "{pihole}/admin/api.php?customdns&action=add&domain=test-svc.{TEST_ZONE}&ip=10.99.99.99&auth={PIHOLE_API_TOKEN}"
        ),
    ]).await?;

    // kubectl run --rm appends 'pod "name" deleted' to stdout; check prefix
    if !add_result.starts_with("200") {
        return Err(format!(
            "PiHole API returned {} (expected 200) when adding test record",
            add_result.trim()
        ));
    }
    info!("[DNS] Added test record test-svc.{TEST_ZONE} -> 10.99.99.99 in PiHole");

    // Wait for CoreDNS to reload the patched Corefile, then verify resolution.
    let _ = run_kubectl(&[
        "--kubeconfig", kubeconfig,
        "delete", "pod", "-n", "kube-system", "dns-resolve-test", "--ignore-not-found",
    ]).await;

    let kc = kubeconfig.to_string();
    let resolve_ok = wait_for_condition(
        &format!("DNS resolution of test-svc.{TEST_ZONE}"),
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                let _ = run_kubectl(&[
                    "--kubeconfig", &kc,
                    "delete", "pod", "-n", "kube-system", "dns-resolve-test", "--ignore-not-found",
                ]).await;

                let result = run_kubectl(&[
                    "--kubeconfig", &kc,
                    "run", "dns-resolve-test", "-n", "kube-system", "--rm", "-i", "--restart=Never",
                    "--image=busybox:1.36",
                    "--", "nslookup", &format!("test-svc.{TEST_ZONE}"),
                ]).await;

                match result {
                    Ok(output) if output.contains("10.99.99.99") => Ok(true),
                    Ok(_) => Ok(false),
                    Err(_) => Ok(false),
                }
            }
        },
    )
    .await;

    match resolve_ok {
        Ok(()) => {
            info!("[DNS] CoreDNS resolved test-svc.{TEST_ZONE} -> 10.99.99.99");
        }
        Err(e) => {
            return Err(format!(
                "DNS resolution failed for test-svc.{TEST_ZONE}: {e}"
            ));
        }
    }

    Ok(())
}

// =============================================================================
// Test: ClusterIssuer Garbage Collection
// =============================================================================

async fn test_cluster_issuer_cleanup(kubeconfig: &str) -> Result<(), String> {
    info!("[Cert] Testing ClusterIssuer garbage collection...");

    let cluster_name = super::super::helpers::get_workload_cluster_name();

    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "patch",
        "latticecluster",
        &cluster_name,
        "--type=merge",
        "-p",
        r#"{"spec":{"issuers":null}}"#,
    ])
    .await
    .map_err(|e| format!("Failed to remove issuers: {e}"))?;

    let kc = kubeconfig.to_string();
    wait_for_condition(
        &format!("ClusterIssuer '{}' to be GC'd", EXPECTED_CLUSTER_ISSUER),
        DEFAULT_TIMEOUT,
        POLL_INTERVAL,
        || {
            let kc = kc.clone();
            async move {
                Ok(run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "clusterissuer",
                    EXPECTED_CLUSTER_ISSUER,
                    "-o",
                    "name",
                ])
                .await
                .is_err())
            }
        },
    )
    .await?;

    info!(
        "[Cert] ClusterIssuer '{}' garbage collected",
        EXPECTED_CLUSTER_ISSUER
    );
    Ok(())
}

// =============================================================================
// Cleanup
// =============================================================================

async fn cleanup_test_resources(kubeconfig: &str) {
    info!("[Cleanup] Cleaning up test resources...");

    // Remove DNS config from cluster
    let cluster_name = super::super::helpers::get_workload_cluster_name();
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "patch",
        "latticecluster",
        &cluster_name,
        "--type=merge",
        "-p",
        r#"{"spec":{"dns":null,"issuers":null}}"#,
    ])
    .await;

    super::super::helpers::delete_namespace(kubeconfig, CERT_TEST_NAMESPACE).await;

    for (kind, name) in [
        ("certissuer", SELF_SIGNED_ISSUER),
        ("certissuer", ACME_HTTP_ISSUER),
        ("dnsprovider", PIHOLE_DNS_PROVIDER),
    ] {
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
        "clusterissuer",
        EXPECTED_CLUSTER_ISSUER,
        "--ignore-not-found",
    ])
    .await;

    // Clean up ESO source secret
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

    // Clean up PiHole test record and leftover pods
    let pihole = pihole_url();
    let _ = run_kubectl(&[
        "--kubeconfig", kubeconfig,
        "delete", "pod", "-n", "kube-system",
        "dns-test", "dns-resolve-test", "dns-cleanup",
        "--ignore-not-found",
    ]).await;
    let _ = run_kubectl(&[
        "--kubeconfig", kubeconfig,
        "run", "dns-cleanup", "-n", "kube-system", "--rm", "-i", "--restart=Never",
        "--image=curlimages/curl:8.5.0",
        "--", "curl", "-s", "-m", "10", "-d", "",
        &format!(
            "{pihole}/admin/api.php?customdns&action=delete&domain=test-svc.{TEST_ZONE}&ip=10.99.99.99&auth={PIHOLE_API_TOKEN}"
        ),
    ]).await;

    info!("[Cleanup] Done");
}

// =============================================================================
// Standalone Test
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_cert_manager_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_cert_manager_tests(&resolved.kubeconfig).await.unwrap();
}
