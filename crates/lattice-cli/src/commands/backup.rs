//! `lattice backup` — trigger an on-demand Velero backup.

use clap::Args;
use kube::api::{Api, DynamicObject, Patch, PatchParams};
use tracing::info;

use lattice_common::kube_utils::build_api_resource;

use crate::{Error, Result};

/// Trigger an on-demand backup
#[derive(Args, Debug)]
pub struct BackupArgs {
    /// Name of the LatticeBackupPolicy to create backup from (default: "default")
    #[arg(long, default_value = "default")]
    pub policy: String,

    /// Namespace of the LatticeBackupPolicy
    #[arg(long, default_value = "lattice-system")]
    pub namespace: String,

    /// Path to kubeconfig file (overrides resolution chain)
    #[arg(long)]
    pub kubeconfig: Option<String>,

    /// Target cluster name
    #[arg(long, short = 'c')]
    pub cluster: Option<String>,
}

const VELERO_BACKUP_API_VERSION: &str = "velero.io/v1";
const VELERO_BACKUP_KIND: &str = "Backup";
const VELERO_NAMESPACE: &str = "velero";

/// Run the backup create command.
pub async fn run(args: BackupArgs) -> Result<()> {
    let (client, _pf) =
        crate::commands::resolve_kube_client(args.kubeconfig.as_deref(), args.cluster.as_deref())
            .await?;

    let backup_name = format!(
        "lattice-{}-manual-{}",
        args.policy,
        chrono::Utc::now().format("%Y%m%d%H%M%S")
    );

    info!(
        policy = %args.policy,
        backup = %backup_name,
        "Creating on-demand backup"
    );

    let schedule_name = format!("lattice-{}", args.policy);
    let backup = serde_json::json!({
        "apiVersion": VELERO_BACKUP_API_VERSION,
        "kind": VELERO_BACKUP_KIND,
        "metadata": {
            "name": backup_name,
            "namespace": VELERO_NAMESPACE,
            "labels": {
                "lattice.dev/managed-by": "lattice",
                "lattice.dev/backup-policy": args.policy,
            }
        },
        "spec": {
            "storageLocation": schedule_name,
        }
    });

    let ar = build_api_resource(VELERO_BACKUP_API_VERSION, VELERO_BACKUP_KIND);
    let api: Api<DynamicObject> = Api::namespaced_with(client, VELERO_NAMESPACE, &ar);
    let params = PatchParams::apply("lattice-cli").force();

    api.patch(&backup_name, &params, &Patch::Apply(&backup))
        .await
        .map_err(|e| Error::command_failed(format!("failed to create backup: {}", e)))?;

    println!("Backup '{}' created successfully.", backup_name);
    println!(
        "Use 'kubectl get backups.velero.io -n velero {}' to check status.",
        backup_name
    );

    Ok(())
}
