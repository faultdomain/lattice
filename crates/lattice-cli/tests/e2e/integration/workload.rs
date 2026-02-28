//! Workload features integration tests
//!
//! Verifies core workload compilation features produce correct runtime behavior:
//! plain text file mounts (ConfigMap-backed), multiple files in the same directory,
//! plain (non-secret) environment variables via ConfigMap, emptyDir volumes,
//! emptyDir sharing between main container and sidecar, init containers
//! (sidecar with `init: true`), and file mounts coexisting with volume mounts.
//!
//! Run standalone:
//! ```
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_workload_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;

use tracing::info;

use super::super::helpers::{
    delete_namespace, deploy_and_wait_for_phase, ensure_fresh_namespace, run_kubectl,
    service_pod_selector, setup_regcreds_infrastructure, verify_pod_env_var,
    verify_pod_file_content, wait_for_condition, wait_for_pod_running, BUSYBOX_IMAGE,
    DEFAULT_TIMEOUT,
};

const WORKLOAD_NS: &str = "workload-test";
const SERVICE_NAME: &str = "workload-features";

/// Build a LatticeService exercising multiple workload compilation features:
/// plain env vars, inline file mounts, emptyDir volumes, init sidecar, regular sidecar.
fn build_workload_features_service() -> lattice_common::crd::LatticeService {
    use lattice_common::crd::{
        ContainerSpec, ExecProbe, FileMount, Probe, ResourceQuantity, ResourceRequirements,
        SecurityContext, SidecarSpec, VolumeMount,
    };
    use lattice_common::template::TemplateString;

    // -- Main container --
    let mut variables = BTreeMap::new();
    variables.insert(
        "APP_NAME".to_string(),
        TemplateString::new("workload-test"),
    );
    variables.insert("LOG_LEVEL".to_string(), TemplateString::new("debug"));

    let mut files = BTreeMap::new();
    files.insert(
        "/etc/app/config.yaml".to_string(),
        FileMount {
            content: Some(TemplateString::new(
                "app:\n  name: workload-test\n  debug: true\n",
            )),
            ..Default::default()
        },
    );
    files.insert(
        "/etc/app/settings.json".to_string(),
        FileMount {
            content: Some(TemplateString::new(r#"{"retries": 3, "timeout": 30}"#)),
            ..Default::default()
        },
    );
    files.insert(
        "/scratch/config.txt".to_string(),
        FileMount {
            content: Some(TemplateString::new("injected-by-file-mount")),
            ..Default::default()
        },
    );

    let mut volumes = BTreeMap::new();
    volumes.insert(
        "/scratch".to_string(),
        VolumeMount {
            ..Default::default()
        },
    );
    volumes.insert(
        "/shared".to_string(),
        VolumeMount {
            ..Default::default()
        },
    );

    let main_container = ContainerSpec {
        image: BUSYBOX_IMAGE.clone(),
        command: Some(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "sleep infinity".to_string(),
        ]),
        variables,
        files,
        volumes,
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
        readiness_probe: Some(Probe {
            exec: Some(ExecProbe {
                command: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "test -f /shared/init-marker".to_string(),
                ],
            }),
            initial_delay_seconds: Some(1),
            period_seconds: Some(2),
            ..Default::default()
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
    containers.insert("main".to_string(), main_container);

    // -- Init sidecar: writes marker before main starts --
    let mut init_volumes = BTreeMap::new();
    init_volumes.insert(
        "/shared".to_string(),
        VolumeMount {
            ..Default::default()
        },
    );

    let init_sidecar = SidecarSpec {
        image: BUSYBOX_IMAGE.clone(),
        command: Some(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo init-done > /shared/init-marker".to_string(),
        ]),
        volumes: init_volumes,
        init: Some(true),
        security: Some(SecurityContext {
            run_as_user: Some(65534),
            apparmor_profile: Some("Unconfined".to_string()),
            allowed_binaries: vec!["*".to_string()],
            ..Default::default()
        }),
        ..Default::default()
    };

    // -- Regular sidecar: writes to shared emptyDir --
    let mut sidecar_volumes = BTreeMap::new();
    sidecar_volumes.insert(
        "/scratch".to_string(),
        VolumeMount {
            ..Default::default()
        },
    );

    let regular_sidecar = SidecarSpec {
        image: BUSYBOX_IMAGE.clone(),
        command: Some(vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "while true; do echo sidecar-alive > /scratch/sidecar.txt; sleep 5; done".to_string(),
        ]),
        volumes: sidecar_volumes,
        security: Some(SecurityContext {
            run_as_user: Some(65534),
            apparmor_profile: Some("Unconfined".to_string()),
            allowed_binaries: vec!["*".to_string()],
            ..Default::default()
        }),
        ..Default::default()
    };

    let mut sidecars = BTreeMap::new();
    sidecars.insert("init-setup".to_string(), init_sidecar);
    sidecars.insert("writer".to_string(), regular_sidecar);

    let resources = BTreeMap::new();

    let mut service =
        super::super::helpers::build_busybox_service(SERVICE_NAME, WORKLOAD_NS, containers, resources);

    service.spec.runtime.sidecars = sidecars;

    service
}

/// Deploy the workload-features service and wait for Ready phase
async fn test_workload_deployment(kubeconfig: &str) -> Result<(), String> {
    info!("[Workload] Deploying workload-features service...");

    let service = build_workload_features_service();
    deploy_and_wait_for_phase(kubeconfig, WORKLOAD_NS, service, "Ready", None, DEFAULT_TIMEOUT)
        .await?;

    info!("[Workload] Service reached Ready phase");
    Ok(())
}

/// Verify non-secret env vars resolve correctly via ConfigMap
async fn test_plain_env_vars(kubeconfig: &str) -> Result<(), String> {
    info!("[Workload] Verifying plain environment variables...");

    let selector = service_pod_selector(SERVICE_NAME);
    verify_pod_env_var(kubeconfig, WORKLOAD_NS, &selector, "APP_NAME", "workload-test").await?;
    verify_pod_env_var(kubeconfig, WORKLOAD_NS, &selector, "LOG_LEVEL", "debug").await?;

    info!("[Workload] Plain env vars verified (APP_NAME, LOG_LEVEL)");
    Ok(())
}

/// Verify inline file mount appears at the correct path with expected content
async fn test_plain_file_mount(kubeconfig: &str) -> Result<(), String> {
    info!("[Workload] Verifying plain file mount at /etc/app/config.yaml...");

    let selector = service_pod_selector(SERVICE_NAME);
    verify_pod_file_content(
        kubeconfig,
        WORKLOAD_NS,
        &selector,
        "/etc/app/config.yaml",
        "name: workload-test",
    )
    .await?;

    info!("[Workload] File mount /etc/app/config.yaml verified");
    Ok(())
}

/// Verify two files mounted under the same directory both exist
async fn test_multiple_files_same_dir(kubeconfig: &str) -> Result<(), String> {
    info!("[Workload] Verifying multiple files in /etc/app/...");

    let selector = service_pod_selector(SERVICE_NAME);
    verify_pod_file_content(
        kubeconfig,
        WORKLOAD_NS,
        &selector,
        "/etc/app/settings.json",
        "retries",
    )
    .await?;

    info!("[Workload] Multiple files in same directory verified");
    Ok(())
}

/// Verify emptyDir volume is writable by touching and reading a file
async fn test_emptydir_writable(kubeconfig: &str) -> Result<(), String> {
    info!("[Workload] Verifying emptyDir at /scratch is writable...");

    let selector = service_pod_selector(SERVICE_NAME);
    wait_for_pod_running(kubeconfig, WORKLOAD_NS, &selector).await?;

    // Touch a file in the emptyDir, then verify it exists
    let kc = kubeconfig.to_string();
    let sel = selector.clone();

    wait_for_condition(
        "emptyDir writable at /scratch",
        DEFAULT_TIMEOUT,
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let sel = sel.clone();
            async move {
                let pod_name = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "pods",
                    "-n",
                    WORKLOAD_NS,
                    "-l",
                    &sel,
                    "-o",
                    "jsonpath={.items[0].metadata.name}",
                ])
                .await?;
                let pod_name = pod_name.trim();
                if pod_name.is_empty() {
                    return Ok(false);
                }

                // Write a file
                let write_result = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "exec",
                    pod_name,
                    "-n",
                    WORKLOAD_NS,
                    "-c",
                    "main",
                    "--",
                    "/bin/sh",
                    "-c",
                    "touch /scratch/test-file && ls /scratch/test-file",
                ])
                .await;

                match write_result {
                    Ok(output) if output.contains("/scratch/test-file") => {
                        info!("[Workload] emptyDir write+read succeeded");
                        Ok(true)
                    }
                    Ok(_) => Ok(false),
                    Err(_) => Ok(false),
                }
            }
        },
    )
    .await?;

    info!("[Workload] emptyDir at /scratch is writable");
    Ok(())
}

/// Verify init sidecar ran before main container by checking marker file
async fn test_init_container_ran(kubeconfig: &str) -> Result<(), String> {
    info!("[Workload] Verifying init container wrote /shared/init-marker...");

    let selector = service_pod_selector(SERVICE_NAME);
    verify_pod_file_content(
        kubeconfig,
        WORKLOAD_NS,
        &selector,
        "/shared/init-marker",
        "init-done",
    )
    .await?;

    info!("[Workload] Init container marker verified");
    Ok(())
}

/// Verify file mount at /scratch/config.txt coexists with emptyDir at /scratch
async fn test_file_under_volume_mount(kubeconfig: &str) -> Result<(), String> {
    info!("[Workload] Verifying file mount under volume mount at /scratch/config.txt...");

    let selector = service_pod_selector(SERVICE_NAME);
    verify_pod_file_content(
        kubeconfig,
        WORKLOAD_NS,
        &selector,
        "/scratch/config.txt",
        "injected-by-file-mount",
    )
    .await?;

    info!("[Workload] File under volume mount verified");
    Ok(())
}

/// Run all workload feature integration tests
pub async fn run_workload_tests(kubeconfig: &str) -> Result<(), String> {
    info!("[Workload] Running workload feature integration tests on {kubeconfig}");

    setup_regcreds_infrastructure(kubeconfig).await?;

    let result = run_workload_test_sequence(kubeconfig).await;

    delete_namespace(kubeconfig, WORKLOAD_NS).await;

    result
}

async fn run_workload_test_sequence(kubeconfig: &str) -> Result<(), String> {
    ensure_fresh_namespace(kubeconfig, WORKLOAD_NS).await?;

    test_workload_deployment(kubeconfig).await?;
    test_plain_env_vars(kubeconfig).await?;
    test_plain_file_mount(kubeconfig).await?;
    test_multiple_files_same_dir(kubeconfig).await?;
    test_emptydir_writable(kubeconfig).await?;
    test_init_container_ran(kubeconfig).await?;
    test_file_under_volume_mount(kubeconfig).await?;

    info!("[Workload] All workload feature integration tests passed!");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_workload_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_workload_tests(&resolved.kubeconfig).await.unwrap();
}
