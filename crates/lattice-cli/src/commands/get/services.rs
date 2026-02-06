//! `lattice get services` - list LatticeService resources on the current cluster

use kube::api::ListParams;
use kube::Api;
use lattice_operator::crd::LatticeService;

use crate::{Error, Result};

use super::format::{format_age, print_table};
use super::OutputFormat;

pub async fn run(
    kubeconfig_path: Option<&str>,
    namespace: Option<&str>,
    output: &OutputFormat,
) -> Result<()> {
    let client = crate::commands::kube_client(kubeconfig_path).await?;

    let services: Vec<LatticeService> = match namespace {
        Some(ns) => {
            let api: Api<LatticeService> = Api::namespaced(client, ns);
            api.list(&ListParams::default())
                .await
                .map_err(|e| Error::command_failed(format!("failed to list services: {}", e)))?
                .items
        }
        None => {
            let api: Api<LatticeService> = Api::all(client);
            api.list(&ListParams::default())
                .await
                .map_err(|e| Error::command_failed(format!("failed to list services: {}", e)))?
                .items
        }
    };

    if services.is_empty() {
        println!("No services found.");
        return Ok(());
    }

    match output {
        OutputFormat::Table => print_services_table(&services),
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&services)
                .map_err(|e| Error::command_failed(format!("json serialization failed: {}", e)))?;
            println!("{}", json);
        }
    }

    Ok(())
}

fn print_services_table(services: &[LatticeService]) {
    let headers = &["NAMESPACE", "NAME", "PHASE", "INBOUND", "OUTBOUND", "AGE"];

    let rows: Vec<Vec<String>> = services
        .iter()
        .map(|svc| {
            let ns = svc.metadata.namespace.as_deref().unwrap_or("-");
            let name = svc.metadata.name.as_deref().unwrap_or("-");
            let phase = svc
                .status
                .as_ref()
                .map(|s| s.phase.to_string())
                .unwrap_or_else(|| "Pending".to_string());

            let inbound_count = svc
                .spec
                .resources
                .values()
                .filter(|r| r.direction.is_inbound())
                .count();
            let outbound_count = svc
                .spec
                .resources
                .values()
                .filter(|r| r.direction.is_outbound())
                .count();

            let age = svc
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|t| format_age(&t.0))
                .unwrap_or_else(|| "-".to_string());

            vec![
                ns.to_string(),
                name.to_string(),
                phase,
                inbound_count.to_string(),
                outbound_count.to_string(),
                age,
            ]
        })
        .collect();

    print_table(headers, &rows);
}
