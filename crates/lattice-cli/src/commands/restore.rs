//! `lattice restore` — create a LatticeRestore to restore from a backup.

use clap::Args;
use kube::api::{Api, Patch, PatchParams};
use lattice_common::crd::LatticeRestore;
use tracing::info;

use crate::{Error, Result};

/// Restore from a Velero backup
#[derive(Args, Debug)]
pub struct RestoreArgs {
    /// Name of the Velero backup to restore from
    pub backup_name: String,

    /// Reference to the LatticeBackupPolicy that created the backup
    #[arg(long)]
    pub policy: Option<String>,

    /// Namespace for the LatticeRestore resource
    #[arg(long, default_value = "lattice-system")]
    pub namespace: String,

    /// Use LatticeAware two-phase ordering (dependencies first)
    #[arg(long)]
    pub lattice_aware: bool,

    /// Skip restoring persistent volumes
    #[arg(long)]
    pub skip_volumes: bool,

    /// Path to kubeconfig file (overrides resolution chain)
    #[arg(long)]
    pub kubeconfig: Option<String>,

    /// Target cluster name
    #[arg(long, short = 'c')]
    pub cluster: Option<String>,
}

/// Run the restore command.
pub async fn run(args: RestoreArgs) -> Result<()> {
    let (client, _pf) =
        crate::commands::resolve_kube_client(args.kubeconfig.as_deref(), args.cluster.as_deref())
            .await?;

    let restore_name = format!("restore-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"));

    let ordering = if args.lattice_aware {
        "LatticeAware"
    } else {
        "VeleroDefault"
    };

    info!(
        backup = %args.backup_name,
        restore = %restore_name,
        ordering,
        "Creating LatticeRestore"
    );

    let mut restore_spec = serde_json::json!({
        "backupName": args.backup_name,
        "restoreVolumes": !args.skip_volumes,
        "ordering": ordering,
    });

    if let Some(ref policy) = args.policy {
        restore_spec["backupPolicyRef"] = serde_json::Value::String(policy.clone());
    }

    let restore = serde_json::json!({
        "apiVersion": "lattice.dev/v1alpha1",
        "kind": "LatticeRestore",
        "metadata": {
            "name": restore_name,
            "namespace": args.namespace,
        },
        "spec": restore_spec,
    });

    let api: Api<LatticeRestore> = Api::namespaced(client, &args.namespace);
    let params = PatchParams::apply("lattice-cli").force();

    api.patch(&restore_name, &params, &Patch::Apply(&restore))
        .await
        .map_err(|e| Error::command_failed(format!("failed to create restore: {}", e)))?;

    println!("Restore '{}' created successfully.", restore_name);
    println!(
        "Use 'lattice get restores' or 'kubectl get latticerestores -n {}' to check status.",
        args.namespace
    );

    Ok(())
}
