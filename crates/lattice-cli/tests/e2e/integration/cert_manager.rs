//! Cert-manager integration tests — DNSProvider, CertIssuer, and ClusterIssuer materialization
//!
//! Tests the full flow from CRD creation through to cert-manager ClusterIssuer
//! materialization and certificate issuance.
//!
//! ## Test Coverage
//!
//! - DNSProvider CRD lifecycle (PiHole provider)
//! - CertIssuer CRD lifecycle (SelfSigned, ACME HTTP-01)
//! - ClusterIssuer materialization from CertIssuer
//! - Certificate issuance via self-signed ClusterIssuer
//! - ClusterIssuer garbage collection on CertIssuer removal
//!
//! # Running
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_cert_manager_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::super::helpers::cedar::apply_yaml;
use super::super::helpers::docker::run_kubectl;
use super::super::helpers::{wait_for_condition, wait_for_resource_phase, DEFAULT_TIMEOUT};

use lattice_common::LATTICE_SYSTEM_NAMESPACE;

// =============================================================================
// Constants
// =============================================================================

/// Namespace for cert-manager test resources
const CERT_TEST_NAMESPACE: &str = "cert-manager-test";

/// Name of the PiHole DNSProvider CRD
const PIHOLE_DNS_PROVIDER: &str = "pihole-e2e";

/// Name of the self-signed CertIssuer CRD
const SELF_SIGNED_ISSUER: &str = "e2e-selfsigned";

/// Name of the ACME CertIssuer CRD (HTTP-01)
const ACME_HTTP_ISSUER: &str = "e2e-acme-http";

/// Name that the operator generates for the ClusterIssuer: `lattice-{key}`
const EXPECTED_CLUSTER_ISSUER: &str = "lattice-dev";

/// Managed-by label applied to operator-created ClusterIssuers
const MANAGED_BY_LABEL: &str = "lattice.dev/managed-by";
const MANAGED_BY_VALUE: &str = "lattice-operator";

// =============================================================================
// Main Test Runner
// =============================================================================

/// Run the full cert-manager integration test suite.
///
/// This tests the complete flow:
/// - DNSProvider CRD creation and readiness
/// - CertIssuer CRD creation and readiness (SelfSigned + ACME HTTP-01)
/// - ClusterIssuer materialization from CertIssuer
/// - Certificate issuance via self-signed issuer
/// - ClusterIssuer garbage collection on CertIssuer deletion
pub async fn run_cert_manager_tests(kubeconfig: &str) -> Result<(), String> {
    info!("========================================");
    info!("CERT-MANAGER INTEGRATION TESTS");
    info!("========================================");

    // Set up a fresh namespace for test Certificate resources
    super::super::helpers::ensure_fresh_namespace(kubeconfig, CERT_TEST_NAMESPACE).await?;

    let result = async {
        test_dns_provider_lifecycle(kubeconfig).await?;
        test_cert_issuer_lifecycle(kubeconfig).await?;
        test_cluster_issuer_materialization(kubeconfig).await?;
        test_certificate_issuance(kubeconfig).await?;
        test_cluster_issuer_cleanup(kubeconfig).await?;
        Ok(())
    }
    .await;

    // Clean up test resources regardless of outcome
    cleanup_test_resources(kubeconfig).await;

    result
}

// =============================================================================
// Test: DNSProvider CRD Lifecycle
// =============================================================================

async fn test_dns_provider_lifecycle(kubeconfig: &str) -> Result<(), String> {
    info!("[CertManager] Testing DNSProvider CRD lifecycle...");

    // Create a PiHole DNSProvider pointing at the docker-compose PiHole service.
    // The PiHole service is accessible at lattice-pihole:80 on the lattice Docker network,
    // or at host port 8053.
    let pihole_dns_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: DNSProvider
metadata:
  name: {name}
  namespace: {ns}
spec:
  type: pihole
  zone: e2e.local
  credentialsSecretRef:
    name: pihole-api-key
  pihole:
    url: http://lattice-pihole:80"#,
        name = PIHOLE_DNS_PROVIDER,
        ns = LATTICE_SYSTEM_NAMESPACE,
    );

    apply_yaml(kubeconfig, &pihole_dns_yaml).await?;
    info!(
        "[CertManager] DNSProvider '{}' created, waiting for Ready...",
        PIHOLE_DNS_PROVIDER
    );

    // Wait for the DNSProvider to reach Ready phase
    wait_for_resource_phase(
        kubeconfig,
        "dnsprovider",
        LATTICE_SYSTEM_NAMESPACE,
        PIHOLE_DNS_PROVIDER,
        "Ready",
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Verify status fields are populated
    let status_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "dnsprovider",
        PIHOLE_DNS_PROVIDER,
        "-n",
        LATTICE_SYSTEM_NAMESPACE,
        "-o",
        "jsonpath={.status}",
    ])
    .await?;

    if status_output.is_empty() {
        return Err(format!(
            "DNSProvider '{}' status is empty after reaching Ready",
            PIHOLE_DNS_PROVIDER
        ));
    }

    info!(
        "[CertManager] DNSProvider '{}' is Ready with status: {}",
        PIHOLE_DNS_PROVIDER,
        super::super::helpers::truncate(&status_output, 200)
    );

    Ok(())
}

// =============================================================================
// Test: CertIssuer CRD Lifecycle
// =============================================================================

async fn test_cert_issuer_lifecycle(kubeconfig: &str) -> Result<(), String> {
    info!("[CertManager] Testing CertIssuer CRD lifecycle...");

    // Create a SelfSigned CertIssuer
    let selfsigned_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: CertIssuer
metadata:
  name: {name}
  namespace: {ns}
spec:
  type: selfSigned"#,
        name = SELF_SIGNED_ISSUER,
        ns = LATTICE_SYSTEM_NAMESPACE,
    );

    apply_yaml(kubeconfig, &selfsigned_yaml).await?;
    info!(
        "[CertManager] CertIssuer '{}' (selfSigned) created, waiting for Ready...",
        SELF_SIGNED_ISSUER
    );

    wait_for_resource_phase(
        kubeconfig,
        "certissuer",
        LATTICE_SYSTEM_NAMESPACE,
        SELF_SIGNED_ISSUER,
        "Ready",
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!(
        "[CertManager] CertIssuer '{}' (selfSigned) is Ready",
        SELF_SIGNED_ISSUER
    );

    // Create an ACME HTTP-01 CertIssuer (Let's Encrypt staging, no DNS provider ref)
    let acme_http_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: CertIssuer
metadata:
  name: {name}
  namespace: {ns}
spec:
  type: acme
  acme:
    email: e2e-test@lattice.dev
    server: https://acme-staging-v02.api.letsencrypt.org/directory"#,
        name = ACME_HTTP_ISSUER,
        ns = LATTICE_SYSTEM_NAMESPACE,
    );

    apply_yaml(kubeconfig, &acme_http_yaml).await?;
    info!(
        "[CertManager] CertIssuer '{}' (ACME HTTP-01) created, waiting for Ready...",
        ACME_HTTP_ISSUER
    );

    wait_for_resource_phase(
        kubeconfig,
        "certissuer",
        LATTICE_SYSTEM_NAMESPACE,
        ACME_HTTP_ISSUER,
        "Ready",
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!(
        "[CertManager] CertIssuer '{}' (ACME HTTP-01) is Ready",
        ACME_HTTP_ISSUER
    );

    Ok(())
}

// =============================================================================
// Test: ClusterIssuer Materialization
// =============================================================================

async fn test_cluster_issuer_materialization(kubeconfig: &str) -> Result<(), String> {
    info!("[CertManager] Testing ClusterIssuer materialization...");

    // Patch the workload LatticeCluster to add an issuer reference.
    // This should cause the operator to create a cert-manager ClusterIssuer
    // named `lattice-dev` based on the `e2e-selfsigned` CertIssuer.
    let cluster_name = super::super::helpers::get_workload_cluster_name();
    let patch_yaml = format!(
        r#"{{"spec":{{"issuers":{{"dev":"{issuer}"}}}}}}"#,
        issuer = SELF_SIGNED_ISSUER,
    );

    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "patch",
        "latticecluster",
        &cluster_name,
        "--type=merge",
        "-p",
        &patch_yaml,
    ])
    .await
    .map_err(|e| format!("Failed to patch LatticeCluster with issuer: {}", e))?;

    info!(
        "[CertManager] Patched LatticeCluster '{}' with issuers.dev='{}'",
        cluster_name, SELF_SIGNED_ISSUER
    );

    // Wait for the ClusterIssuer to appear
    let kc = kubeconfig.to_string();
    let issuer_name = EXPECTED_CLUSTER_ISSUER.to_string();
    wait_for_condition(
        &format!("ClusterIssuer '{}' to exist", EXPECTED_CLUSTER_ISSUER),
        DEFAULT_TIMEOUT,
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let issuer_name = issuer_name.clone();
            async move {
                let result = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "clusterissuer",
                    &issuer_name,
                    "-o",
                    "name",
                ])
                .await;
                Ok(result.is_ok())
            }
        },
    )
    .await?;

    info!(
        "[CertManager] ClusterIssuer '{}' exists",
        EXPECTED_CLUSTER_ISSUER
    );

    // Verify it has the correct spec (selfSigned)
    let spec_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "clusterissuer",
        EXPECTED_CLUSTER_ISSUER,
        "-o",
        "jsonpath={.spec}",
    ])
    .await?;

    if !spec_output.contains("selfSigned") {
        return Err(format!(
            "ClusterIssuer '{}' spec does not contain selfSigned: {}",
            EXPECTED_CLUSTER_ISSUER, spec_output
        ));
    }

    info!(
        "[CertManager] ClusterIssuer '{}' has correct selfSigned spec",
        EXPECTED_CLUSTER_ISSUER
    );

    // Verify it has the managed-by label
    // The label key contains dots and slashes, so use bracket notation in jsonpath
    let label_jsonpath = format!(
        "jsonpath={{.metadata.labels['{}']}}",
        MANAGED_BY_LABEL
    );
    let label_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "clusterissuer",
        EXPECTED_CLUSTER_ISSUER,
        "-o",
        &label_jsonpath,
    ])
    .await?;

    if label_output.trim() != MANAGED_BY_VALUE {
        return Err(format!(
            "ClusterIssuer '{}' missing or wrong managed-by label: expected '{}', got '{}'",
            EXPECTED_CLUSTER_ISSUER, MANAGED_BY_VALUE, label_output
        ));
    }

    info!(
        "[CertManager] ClusterIssuer '{}' has correct {} label",
        EXPECTED_CLUSTER_ISSUER, MANAGED_BY_LABEL
    );

    Ok(())
}

// =============================================================================
// Test: Certificate Issuance (Self-Signed)
// =============================================================================

async fn test_certificate_issuance(kubeconfig: &str) -> Result<(), String> {
    info!("[CertManager] Testing certificate issuance via self-signed ClusterIssuer...");

    let cert_name = "e2e-test-cert";
    let secret_name = "e2e-test-cert-tls";

    // Create a cert-manager Certificate referencing the materialized ClusterIssuer
    let cert_yaml = format!(
        r#"apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: {cert_name}
  namespace: {namespace}
spec:
  secretName: {secret_name}
  issuerRef:
    name: {issuer}
    kind: ClusterIssuer
    group: cert-manager.io
  commonName: e2e-test.local
  dnsNames:
    - e2e-test.local
    - "*.e2e-test.local""#,
        cert_name = cert_name,
        namespace = CERT_TEST_NAMESPACE,
        secret_name = secret_name,
        issuer = EXPECTED_CLUSTER_ISSUER,
    );

    apply_yaml(kubeconfig, &cert_yaml).await?;
    info!(
        "[CertManager] Certificate '{}' created, waiting for Ready...",
        cert_name
    );

    // Wait for the Certificate to become Ready
    let kc = kubeconfig.to_string();
    let cert_name_owned = cert_name.to_string();
    let ns = CERT_TEST_NAMESPACE.to_string();
    wait_for_condition(
        &format!("Certificate '{}/{}' to be Ready", CERT_TEST_NAMESPACE, cert_name),
        DEFAULT_TIMEOUT,
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let cert_name = cert_name_owned.clone();
            let ns = ns.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "certificate",
                    &cert_name,
                    "-n",
                    &ns,
                    "-o",
                    "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}",
                ])
                .await;
                match output {
                    Ok(status) => {
                        let ready = status.trim() == "True";
                        info!("[CertManager] Certificate Ready status: {}", status.trim());
                        Ok(ready)
                    }
                    Err(e) => {
                        info!("[CertManager] Certificate not yet available: {}", e);
                        Ok(false)
                    }
                }
            }
        },
    )
    .await?;

    info!(
        "[CertManager] Certificate '{}' is Ready",
        cert_name
    );

    // Verify the TLS secret was created
    let secret_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "secret",
        secret_name,
        "-n",
        CERT_TEST_NAMESPACE,
        "-o",
        "jsonpath={.type}",
    ])
    .await
    .map_err(|e| format!("TLS secret '{}' not found after Certificate became Ready: {}", secret_name, e))?;

    if secret_output.trim() != "kubernetes.io/tls" {
        return Err(format!(
            "TLS secret '{}' has unexpected type: expected 'kubernetes.io/tls', got '{}'",
            secret_name,
            secret_output.trim()
        ));
    }

    // Verify the secret contains tls.crt and tls.key
    let keys_output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "secret",
        secret_name,
        "-n",
        CERT_TEST_NAMESPACE,
        "-o",
        "jsonpath={.data}",
    ])
    .await?;

    if !keys_output.contains("tls.crt") || !keys_output.contains("tls.key") {
        return Err(format!(
            "TLS secret '{}' missing tls.crt or tls.key: {}",
            secret_name, keys_output
        ));
    }

    info!(
        "[CertManager] TLS secret '{}' created with tls.crt and tls.key",
        secret_name
    );

    Ok(())
}

// =============================================================================
// Test: ClusterIssuer Garbage Collection
// =============================================================================

async fn test_cluster_issuer_cleanup(kubeconfig: &str) -> Result<(), String> {
    info!("[CertManager] Testing ClusterIssuer garbage collection...");

    // Remove the issuer from the cluster spec by patching with empty issuers
    let cluster_name = super::super::helpers::get_workload_cluster_name();
    let patch_yaml = r#"{"spec":{"issuers":{}}}"#;

    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "patch",
        "latticecluster",
        &cluster_name,
        "--type=merge",
        "-p",
        patch_yaml,
    ])
    .await
    .map_err(|e| format!("Failed to remove issuer from LatticeCluster: {}", e))?;

    info!(
        "[CertManager] Removed issuers from LatticeCluster '{}', waiting for ClusterIssuer GC...",
        cluster_name
    );

    // Wait for the ClusterIssuer to be garbage collected
    let kc = kubeconfig.to_string();
    let issuer_name = EXPECTED_CLUSTER_ISSUER.to_string();
    wait_for_condition(
        &format!(
            "ClusterIssuer '{}' to be garbage collected",
            EXPECTED_CLUSTER_ISSUER
        ),
        DEFAULT_TIMEOUT,
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let issuer_name = issuer_name.clone();
            async move {
                let result = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "clusterissuer",
                    &issuer_name,
                    "-o",
                    "name",
                ])
                .await;
                // Gone means GC succeeded
                let gone = result.is_err();
                if !gone {
                    info!(
                        "[CertManager] ClusterIssuer '{}' still exists, waiting for GC...",
                        issuer_name
                    );
                }
                Ok(gone)
            }
        },
    )
    .await?;

    info!(
        "[CertManager] ClusterIssuer '{}' garbage collected successfully",
        EXPECTED_CLUSTER_ISSUER
    );

    Ok(())
}

// =============================================================================
// Cleanup
// =============================================================================

async fn cleanup_test_resources(kubeconfig: &str) {
    info!("[CertManager] Cleaning up test resources...");

    // Delete the test namespace (non-blocking)
    super::super::helpers::delete_namespace(kubeconfig, CERT_TEST_NAMESPACE).await;

    // Delete the CertIssuer CRDs
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "certissuer",
        SELF_SIGNED_ISSUER,
        "-n",
        LATTICE_SYSTEM_NAMESPACE,
        "--ignore-not-found",
    ])
    .await;

    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "certissuer",
        ACME_HTTP_ISSUER,
        "-n",
        LATTICE_SYSTEM_NAMESPACE,
        "--ignore-not-found",
    ])
    .await;

    // Delete the DNSProvider CRD
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "dnsprovider",
        PIHOLE_DNS_PROVIDER,
        "-n",
        LATTICE_SYSTEM_NAMESPACE,
        "--ignore-not-found",
    ])
    .await;

    // Delete the materialized ClusterIssuer (in case GC test was skipped)
    let _ = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "delete",
        "clusterissuer",
        EXPECTED_CLUSTER_ISSUER,
        "--ignore-not-found",
    ])
    .await;

    info!("[CertManager] Cleanup complete");
}

// =============================================================================
// Standalone Tests
// =============================================================================

/// Standalone test -- run all cert-manager tests on existing cluster
///
/// Uses `LATTICE_KUBECONFIG` for direct access, or falls back to
/// `LATTICE_MGMT_KUBECONFIG` + `LATTICE_WORKLOAD_KUBECONFIG` with proxy + Cedar policy.
#[tokio::test]
#[ignore]
async fn test_cert_manager_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_cert_manager_tests(&resolved.kubeconfig)
        .await
        .unwrap();
}
