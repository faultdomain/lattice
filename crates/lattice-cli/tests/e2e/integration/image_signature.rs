//! Image signature verification E2E tests
//!
//! Tests the full pipeline: ImageProvider with trust policy → cosign key
//! resolution via ESO → WorkloadCompiler verifies signatures → Cedar
//! SkipImageVerification fallback.
//!
//! Test flow:
//! 1. Generate a cosign keypair
//! 2. Build, push, and sign a test image
//! 3. Create ImageProvider with trust policy pointing to the public key
//! 4. Deploy signed image → should reach Ready
//! 5. Deploy unsigned image → should reach Failed
//! 6. Apply Cedar SkipImageVerification policy → unsigned image should recover

use tracing::info;

use super::super::helpers::cedar::{apply_cedar_policy_crd, apply_yaml};
use super::super::helpers::docker::run_kubectl;
use super::super::helpers::{
    ensure_namespace, wait_for_resource_phase, wait_for_service_phase, DEFAULT_TIMEOUT,
    POLL_INTERVAL,
};

const SIG_TEST_NS: &str = "image-sig-test";
const LATTICE_NS: &str = "lattice-system";
const SECRETS_NS: &str = "lattice-secrets";
const IMAGE_PROVIDER_NAME: &str = "sig-test-registry";
const LOCAL_REGISTRY: &str = "10.0.0.131:5555";

/// Run all image signature verification tests.
pub async fn run_image_signature_tests(kubeconfig: &str) -> Result<(), String> {
    info!("========================================");
    info!("IMAGE SIGNATURE VERIFICATION TESTS");
    info!("========================================");

    ensure_namespace(kubeconfig, SIG_TEST_NS).await?;

    let test_ctx = setup_cosign_infrastructure(kubeconfig).await?;
    test_signed_image_accepted(kubeconfig, &test_ctx).await?;
    test_unsigned_image_rejected(kubeconfig, &test_ctx).await?;
    test_cedar_skip_allows_unsigned(kubeconfig, &test_ctx).await?;

    cleanup(kubeconfig).await;
    info!("[ImageSignature] All tests passed!");
    Ok(())
}

struct TestContext {
    signed_image: String,
    unsigned_image: String,
}

// =============================================================================
// Setup: cosign keypair, signed image, ImageProvider with trust policy
// =============================================================================

async fn setup_cosign_infrastructure(kubeconfig: &str) -> Result<TestContext, String> {
    info!("[ImageSignature] Setting up cosign infrastructure...");

    // Generate ephemeral cosign keypair (no password)
    let keypair_dir = format!("/tmp/lattice-sig-test-{}", std::process::id());
    run_kubectl(&["--kubeconfig", kubeconfig, "version", "--client"]).await?; // warm up
    std::fs::create_dir_all(&keypair_dir)
        .map_err(|e| format!("failed to create keypair dir: {e}"))?;

    let gen_result = tokio::process::Command::new("cosign")
        .args(["generate-key-pair"])
        .env("COSIGN_PASSWORD", "")
        .current_dir(&keypair_dir)
        .output()
        .await
        .map_err(|e| format!("cosign generate-key-pair failed: {e}"))?;

    if !gen_result.status.success() {
        return Err(format!(
            "cosign generate-key-pair failed: {}",
            String::from_utf8_lossy(&gen_result.stderr)
        ));
    }
    info!("[ImageSignature] Generated cosign keypair");

    let pub_key = std::fs::read_to_string(format!("{keypair_dir}/cosign.pub"))
        .map_err(|e| format!("failed to read cosign.pub: {e}"))?;
    let priv_key_path = format!("{keypair_dir}/cosign.key");

    // Build a trivial test image, push to local registry
    let signed_tag = format!(
        "{LOCAL_REGISTRY}/sig-test:signed-{}",
        std::process::id()
    );
    let unsigned_tag = format!(
        "{LOCAL_REGISTRY}/sig-test:unsigned-{}",
        std::process::id()
    );

    // Create and push signed image
    let dockerfile = format!("{keypair_dir}/Dockerfile");
    std::fs::write(&dockerfile, "FROM busybox:latest\nCMD [\"sleep\", \"infinity\"]\n")
        .map_err(|e| format!("failed to write Dockerfile: {e}"))?;

    run_docker_build(&keypair_dir, &signed_tag).await?;
    run_docker_push(&signed_tag).await?;
    info!("[ImageSignature] Pushed signed image: {signed_tag}");

    // Sign the image
    let sign_result = tokio::process::Command::new("cosign")
        .args(["sign", "--key", &priv_key_path, "--yes", &signed_tag])
        .env("COSIGN_PASSWORD", "")
        .output()
        .await
        .map_err(|e| format!("cosign sign failed: {e}"))?;

    if !sign_result.status.success() {
        return Err(format!(
            "cosign sign failed: {}",
            String::from_utf8_lossy(&sign_result.stderr)
        ));
    }
    info!("[ImageSignature] Signed image with cosign");

    // Push unsigned image (same content, different tag, no signature)
    run_docker_tag(&signed_tag, &unsigned_tag).await?;
    run_docker_push(&unsigned_tag).await?;
    info!("[ImageSignature] Pushed unsigned image: {unsigned_tag}");

    // Seed the cosign public key as a source secret for ESO
    let secret_yaml = format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: cosign-sig-test-key
  namespace: {SECRETS_NS}
  labels:
    lattice.dev/secret-source: "true"
type: Opaque
stringData:
  cosign.pub: |
{}"#,
        pub_key
            .lines()
            .map(|l| format!("    {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    apply_yaml(kubeconfig, &secret_yaml).await?;
    info!("[ImageSignature] Seeded cosign public key secret");

    // Create ImageProvider with trust policy
    let provider_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: ImageProvider
metadata:
  name: {IMAGE_PROVIDER_NAME}
  namespace: {LATTICE_NS}
spec:
  type: generic
  registry: "{LOCAL_REGISTRY}"
  trust:
    enforce: true
    authorities:
      - name: e2e-cosign
        key:
          id: cosign-sig-test-key
          provider: lattice-local
          keys:
            - cosign.pub"#
    );
    apply_yaml(kubeconfig, &provider_yaml).await?;

    wait_for_resource_phase(
        kubeconfig,
        "imageprovider",
        LATTICE_NS,
        IMAGE_PROVIDER_NAME,
        "Ready",
        DEFAULT_TIMEOUT,
    )
    .await?;
    info!("[ImageSignature] ImageProvider with trust policy is Ready");

    Ok(TestContext {
        signed_image: signed_tag,
        unsigned_image: unsigned_tag,
    })
}

// =============================================================================
// Test: Signed image accepted
// =============================================================================

async fn test_signed_image_accepted(
    kubeconfig: &str,
    ctx: &TestContext,
) -> Result<(), String> {
    info!("[ImageSignature] Testing: signed image should be accepted...");

    let svc_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: signed-svc
  namespace: {SIG_TEST_NS}
spec:
  workload:
    containers:
      main:
        image: "{}"
        resources:
          limits:
            cpu: 100m
            memory: 32Mi
    service:
      ports:
        http:
          port: 8080"#,
        ctx.signed_image
    );
    apply_yaml(kubeconfig, &svc_yaml).await?;

    wait_for_service_phase(
        kubeconfig,
        SIG_TEST_NS,
        "signed-svc",
        "Ready",
        None,
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!("[ImageSignature] PASSED: signed image reached Ready");
    Ok(())
}

// =============================================================================
// Test: Unsigned image rejected
// =============================================================================

async fn test_unsigned_image_rejected(
    kubeconfig: &str,
    ctx: &TestContext,
) -> Result<(), String> {
    info!("[ImageSignature] Testing: unsigned image should be rejected...");

    let svc_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: unsigned-svc
  namespace: {SIG_TEST_NS}
spec:
  workload:
    containers:
      main:
        image: "{}"
        resources:
          limits:
            cpu: 100m
            memory: 32Mi
    service:
      ports:
        http:
          port: 8080"#,
        ctx.unsigned_image
    );
    apply_yaml(kubeconfig, &svc_yaml).await?;

    wait_for_service_phase(
        kubeconfig,
        SIG_TEST_NS,
        "unsigned-svc",
        "Failed",
        Some("image verification denied"),
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!("[ImageSignature] PASSED: unsigned image rejected");
    Ok(())
}

// =============================================================================
// Test: Cedar SkipImageVerification allows unsigned
// =============================================================================

async fn test_cedar_skip_allows_unsigned(
    kubeconfig: &str,
    ctx: &TestContext,
) -> Result<(), String> {
    info!("[ImageSignature] Testing: Cedar SkipImageVerification should allow unsigned...");

    // Apply Cedar policy to allow skipping verification for this namespace
    apply_cedar_policy_crd(
        kubeconfig,
        "permit-skip-sig-test",
        "image-sig",
        50,
        &format!(
            r#"permit(
  principal,
  action == Lattice::Action::"SkipImageVerification",
  resource
) when {{
  principal.namespace == "{SIG_TEST_NS}"
}};"#
        ),
    )
    .await?;
    info!("[ImageSignature] Applied Cedar SkipImageVerification policy");

    // Delete and recreate the unsigned service so the compiler re-evaluates
    let _ = run_kubectl(&[
        "--kubeconfig", kubeconfig,
        "delete", "latticeservice", "unsigned-svc",
        "-n", SIG_TEST_NS, "--ignore-not-found",
    ]).await;

    let svc_yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeService
metadata:
  name: unsigned-svc-skip
  namespace: {SIG_TEST_NS}
spec:
  workload:
    containers:
      main:
        image: "{}"
        resources:
          limits:
            cpu: 100m
            memory: 32Mi
    service:
      ports:
        http:
          port: 8080"#,
        ctx.unsigned_image
    );
    apply_yaml(kubeconfig, &svc_yaml).await?;

    wait_for_service_phase(
        kubeconfig,
        SIG_TEST_NS,
        "unsigned-svc-skip",
        "Ready",
        None,
        DEFAULT_TIMEOUT,
    )
    .await?;

    info!("[ImageSignature] PASSED: Cedar policy allowed unsigned image");
    Ok(())
}

// =============================================================================
// Docker helpers
// =============================================================================

async fn run_docker_build(context_dir: &str, tag: &str) -> Result<(), String> {
    let output = tokio::process::Command::new("docker")
        .args(["build", "-t", tag, context_dir])
        .output()
        .await
        .map_err(|e| format!("docker build failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "docker build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

async fn run_docker_push(tag: &str) -> Result<(), String> {
    let output = tokio::process::Command::new("docker")
        .args(["push", tag])
        .output()
        .await
        .map_err(|e| format!("docker push failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "docker push failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

async fn run_docker_tag(src: &str, dst: &str) -> Result<(), String> {
    let output = tokio::process::Command::new("docker")
        .args(["tag", src, dst])
        .output()
        .await
        .map_err(|e| format!("docker tag failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "docker tag failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

// =============================================================================
// Cleanup
// =============================================================================

async fn cleanup(kubeconfig: &str) {
    info!("[ImageSignature/Cleanup] Cleaning up...");

    let _ = run_kubectl(&[
        "--kubeconfig", kubeconfig,
        "delete", "namespace", SIG_TEST_NS, "--ignore-not-found",
    ]).await;

    for (kind, name, ns) in [
        ("imageprovider", IMAGE_PROVIDER_NAME, LATTICE_NS),
        ("secret", "cosign-sig-test-key", SECRETS_NS),
        ("cedarpolicy", "permit-skip-sig-test", LATTICE_NS),
    ] {
        let _ = run_kubectl(&[
            "--kubeconfig", kubeconfig,
            "delete", kind, name, "-n", ns, "--ignore-not-found",
        ]).await;
    }

    info!("[ImageSignature/Cleanup] Done");
}

// =============================================================================
// Standalone Test
// =============================================================================

#[tokio::test]
#[ignore]
async fn test_image_signature_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();

    super::super::helpers::setup_regcreds_infrastructure(&resolved.kubeconfig)
        .await
        .unwrap();
    run_image_signature_tests(&resolved.kubeconfig)
        .await
        .unwrap();
}
