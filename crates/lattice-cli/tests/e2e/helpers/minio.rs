//! MinIO deployment helper for Velero backup storage in tests
//!
//! Deploys MinIO as an in-cluster S3 backend so Velero has somewhere to store
//! file-system backups. Uses Kubernetes DNS (`minio.velero.svc.cluster.local`)
//! so Velero pods can reach it without Docker network cross-access.

#![cfg(feature = "provider-e2e")]

use std::time::Duration;

use tracing::info;

use super::{apply_yaml, run_kubectl, wait_for_condition, VELERO_NAMESPACE};
const MINIO_BUCKET: &str = "velero-backups";

/// Deploy MinIO and configure a Velero BackupStorageLocation.
///
/// Idempotent — safe to call multiple times. Creates:
/// - MinIO Deployment (1 pod, emptyDir storage)
/// - MinIO Service (ClusterIP, port 9000)
/// - Velero credential Secret (`cloud-credentials`)
/// - Velero BackupStorageLocation `minio`
///
/// Waits for the MinIO pod to be Ready and the BSL to become Available.
pub async fn setup_minio_backup_storage(kubeconfig: &str) -> Result<(), String> {
    info!("[MinIO] Setting up MinIO backup storage...");

    deploy_minio(kubeconfig).await?;
    wait_for_minio_ready(kubeconfig).await?;
    create_minio_bucket(kubeconfig).await?;
    create_velero_credentials(kubeconfig).await?;
    create_backup_storage_location(kubeconfig).await?;
    wait_for_bsl_available(kubeconfig).await?;

    info!("[MinIO] MinIO backup storage ready");
    Ok(())
}

/// Clean up MinIO resources from the velero namespace.
pub async fn cleanup_minio_backup_storage(kubeconfig: &str) {
    info!("[MinIO] Cleaning up MinIO resources...");

    for (kind, name) in [
        ("backupstoragelocation.velero.io", "minio"),
        ("deployment", "minio"),
        ("service", "minio"),
        ("secret", "cloud-credentials"),
    ] {
        let _ = run_kubectl(&[
            "--kubeconfig",
            kubeconfig,
            "delete",
            kind,
            name,
            "-n",
            VELERO_NAMESPACE,
            "--ignore-not-found",
        ])
        .await;
    }
}

async fn deploy_minio(kubeconfig: &str) -> Result<(), String> {
    let manifest = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "minio",
            "namespace": VELERO_NAMESPACE,
            "labels": {
                "app": "minio"
            }
        },
        "spec": {
            "replicas": 1,
            "selector": {
                "matchLabels": {
                    "app": "minio"
                }
            },
            "template": {
                "metadata": {
                    "labels": {
                        "app": "minio"
                    }
                },
                "spec": {
                    "containers": [{
                        "name": "minio",
                        "image": "minio/minio:latest",
                        "args": ["server", "/data"],
                        "env": [
                            {"name": "MINIO_ROOT_USER", "value": "minio"},
                            {"name": "MINIO_ROOT_PASSWORD", "value": "minio123"}
                        ],
                        "ports": [{"containerPort": 9000}],
                        "readinessProbe": {
                            "httpGet": {
                                "path": "/minio/health/ready",
                                "port": 9000
                            },
                            "initialDelaySeconds": 5,
                            "periodSeconds": 5
                        },
                        "volumeMounts": [{
                            "name": "data",
                            "mountPath": "/data"
                        }]
                    }],
                    "volumes": [{
                        "name": "data",
                        "emptyDir": {}
                    }]
                }
            }
        }
    });

    let svc_manifest = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "minio",
            "namespace": VELERO_NAMESPACE
        },
        "spec": {
            "selector": {
                "app": "minio"
            },
            "ports": [{
                "port": 9000,
                "targetPort": 9000
            }]
        }
    });

    let deployment_json = serde_json::to_string(&manifest)
        .map_err(|e| format!("Failed to serialize MinIO deployment: {e}"))?;
    apply_yaml(kubeconfig, &deployment_json).await?;

    let svc_json = serde_json::to_string(&svc_manifest)
        .map_err(|e| format!("Failed to serialize MinIO service: {e}"))?;
    apply_yaml(kubeconfig, &svc_json).await?;

    info!("[MinIO] Deployment and Service applied");
    Ok(())
}

async fn wait_for_minio_ready(kubeconfig: &str) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    wait_for_condition(
        "MinIO pod to be Ready",
        Duration::from_secs(120),
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "pods",
                    "-n",
                    VELERO_NAMESPACE,
                    "-l",
                    "app=minio",
                    "--field-selector=status.phase=Running",
                    "-o",
                    "jsonpath={.items[0].status.containerStatuses[0].ready}",
                ])
                .await
                .unwrap_or_default();

                Ok(output.trim() == "true")
            }
        },
    )
    .await?;

    info!("[MinIO] Pod is Ready");
    Ok(())
}

async fn create_minio_bucket(kubeconfig: &str) -> Result<(), String> {
    // MinIO stores buckets as directories — create via exec
    let minio_pod = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pods",
        "-n",
        VELERO_NAMESPACE,
        "-l",
        "app=minio",
        "-o",
        "jsonpath={.items[0].metadata.name}",
    ])
    .await?;

    let pod_name = minio_pod.trim();
    if pod_name.is_empty() {
        return Err("No MinIO pod found".to_string());
    }

    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "exec",
        pod_name,
        "-n",
        VELERO_NAMESPACE,
        "--",
        "mkdir",
        "-p",
        &format!("/data/{}", MINIO_BUCKET),
    ])
    .await?;

    info!("[MinIO] Bucket '{}' created", MINIO_BUCKET);
    Ok(())
}

async fn create_velero_credentials(kubeconfig: &str) -> Result<(), String> {
    // Velero expects AWS-style credentials in a file-like format
    let credentials = "[default]\naws_access_key_id = minio\naws_secret_access_key = minio123\n";

    let secret = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "cloud-credentials",
            "namespace": VELERO_NAMESPACE
        },
        "type": "Opaque",
        "stringData": {
            "cloud": credentials
        }
    });

    let json =
        serde_json::to_string(&secret).map_err(|e| format!("Failed to serialize secret: {e}"))?;
    apply_yaml(kubeconfig, &json).await?;

    info!("[MinIO] Velero credentials secret created");
    Ok(())
}

async fn create_backup_storage_location(kubeconfig: &str) -> Result<(), String> {
    let bsl = serde_json::json!({
        "apiVersion": "velero.io/v1",
        "kind": "BackupStorageLocation",
        "metadata": {
            "name": "minio",
            "namespace": VELERO_NAMESPACE
        },
        "spec": {
            "provider": "aws",
            "objectStorage": {
                "bucket": MINIO_BUCKET
            },
            "credential": {
                "name": "cloud-credentials",
                "key": "cloud"
            },
            "config": {
                "region": "us-east-1",
                "s3ForcePathStyle": "true",
                "s3Url": "http://minio.velero.svc.cluster.local:9000"
            }
        }
    });

    let json =
        serde_json::to_string(&bsl).map_err(|e| format!("Failed to serialize BSL: {e}"))?;
    apply_yaml(kubeconfig, &json).await?;

    info!("[MinIO] BackupStorageLocation 'minio' created");
    Ok(())
}

async fn wait_for_bsl_available(kubeconfig: &str) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    wait_for_condition(
        "BackupStorageLocation 'minio' to be Available",
        Duration::from_secs(120),
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "backupstoragelocation.velero.io",
                    "minio",
                    "-n",
                    VELERO_NAMESPACE,
                    "-o",
                    "jsonpath={.status.phase}",
                ])
                .await
                .unwrap_or_default();

                let phase = output.trim();
                if phase == "Available" {
                    Ok(true)
                } else {
                    info!("[MinIO] BSL phase: {}", phase);
                    Ok(false)
                }
            }
        },
    )
    .await?;

    info!("[MinIO] BackupStorageLocation is Available");
    Ok(())
}
