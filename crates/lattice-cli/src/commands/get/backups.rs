//! `lattice get backups` — list LatticeBackupPolicy resources and recent backups.

use kube::api::ListParams;
use kube::Api;
use lattice_common::crd::LatticeBackupPolicy;

use crate::{Error, Result};

use super::format::{format_age, print_table};
use super::OutputFormat;

pub async fn run(
    explicit_kubeconfig: Option<&str>,
    policy_name: Option<&str>,
    cluster: Option<&str>,
    output: &OutputFormat,
) -> Result<()> {
    let (client, _pf) = crate::commands::resolve_kube_client(explicit_kubeconfig, cluster).await?;

    let api: Api<LatticeBackupPolicy> = Api::all(client);
    let policies: Vec<LatticeBackupPolicy> = api
        .list(&ListParams::default())
        .await
        .map_err(|e| Error::command_failed(format!("failed to list backup policies: {}", e)))?
        .items;

    let policies: Vec<&LatticeBackupPolicy> = if let Some(name) = policy_name {
        policies
            .iter()
            .filter(|p| p.metadata.name.as_deref() == Some(name))
            .collect()
    } else {
        policies.iter().collect()
    };

    if policies.is_empty() {
        println!("No backup policies found.");
        return Ok(());
    }

    match output {
        OutputFormat::Table => print_policies_table(&policies),
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&policies)
                .map_err(|e| Error::command_failed(format!("json serialization failed: {}", e)))?;
            println!("{}", json);
        }
    }

    Ok(())
}

fn print_policies_table(policies: &[&LatticeBackupPolicy]) {
    let headers = &[
        "NAMESPACE",
        "NAME",
        "SCHEDULE",
        "PHASE",
        "PAUSED",
        "BACKUPS",
        "LAST BACKUP",
        "AGE",
    ];

    let rows: Vec<Vec<String>> = policies
        .iter()
        .map(|policy| {
            let ns = policy.metadata.namespace.as_deref().unwrap_or("-");
            let name = policy.metadata.name.as_deref().unwrap_or("-");
            let schedule = &policy.spec.schedule;
            let phase = policy
                .status
                .as_ref()
                .map(|s| s.phase.to_string())
                .unwrap_or_else(|| "Pending".to_string());
            let paused = if policy.spec.paused {
                "true".to_string()
            } else {
                "false".to_string()
            };
            let backup_count = policy
                .status
                .as_ref()
                .map(|s| s.backup_count.to_string())
                .unwrap_or_else(|| "0".to_string());
            let last_backup = policy
                .status
                .as_ref()
                .and_then(|s| s.last_backup_time.as_ref())
                .map(format_age)
                .unwrap_or_else(|| "-".to_string());
            let age = policy
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|t| format_age(&t.0))
                .unwrap_or_else(|| "-".to_string());

            vec![
                ns.to_string(),
                name.to_string(),
                schedule.clone(),
                phase,
                paused,
                backup_count,
                last_backup,
                age,
            ]
        })
        .collect();

    print_table(headers, &rows);
}
