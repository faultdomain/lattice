//! `lattice get services` — list LatticeService resources.
//!
//! Supports `--cluster` for targeting a specific cluster and `--all-clusters`
//! for cross-cluster queries (adds a CLUSTER column to output).

use kube::api::ListParams;
use kube::Api;
use lattice_operator::crd::LatticeService;

use crate::{Error, Result};

use super::format::{format_age, print_table};
use super::OutputFormat;

pub async fn run(
    explicit_kubeconfig: Option<&str>,
    namespace: Option<&str>,
    cluster: Option<&str>,
    all_clusters: bool,
    output: &OutputFormat,
) -> Result<()> {
    if all_clusters {
        return run_all_clusters(explicit_kubeconfig, namespace, output).await;
    }

    let (client, _pf) = crate::commands::resolve_kube_client(explicit_kubeconfig, cluster).await?;

    let services = list_services(client, namespace).await?;

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

/// Query all clusters in the proxy kubeconfig and aggregate results.
async fn run_all_clusters(
    explicit_kubeconfig: Option<&str>,
    namespace: Option<&str>,
    output: &OutputFormat,
) -> Result<()> {
    if crate::config::resolve_kubeconfig(explicit_kubeconfig).is_none() {
        return Err(Error::command_failed(
            "no kubeconfig found for --all-clusters. Run `lattice login` first.",
        ));
    }

    let (kc, _pf) = crate::commands::load_kubeconfig(explicit_kubeconfig).await?;

    let context_names: Vec<String> = kc
        .contexts
        .iter()
        .filter_map(|c| c.name.clone().into())
        .collect();

    let mut all_rows: Vec<(String, LatticeService)> = Vec::new();

    for ctx in &context_names {
        let opts = kube::config::KubeConfigOptions {
            context: Some(ctx.clone()),
            ..Default::default()
        };
        let client = match crate::commands::kube_client_from_kubeconfig(kc.clone(), &opts).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Warning: failed to connect to cluster '{}': {}", ctx, e);
                continue;
            }
        };

        match list_services(client, namespace).await {
            Ok(svcs) => {
                for svc in svcs {
                    all_rows.push((ctx.clone(), svc));
                }
            }
            Err(e) => {
                eprintln!("Warning: failed to list services on '{}': {}", ctx, e);
            }
        }
    }

    if all_rows.is_empty() {
        println!("No services found across any cluster.");
        return Ok(());
    }

    match output {
        OutputFormat::Table => print_services_table_with_cluster(&all_rows),
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&all_rows)
                .map_err(|e| Error::command_failed(format!("json serialization failed: {}", e)))?;
            println!("{}", json);
        }
    }

    Ok(())
}

async fn list_services(
    client: kube::Client,
    namespace: Option<&str>,
) -> Result<Vec<LatticeService>> {
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
    Ok(services)
}

fn service_row(svc: &LatticeService) -> Vec<String> {
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
}

fn print_services_table(services: &[LatticeService]) {
    let headers = &["NAMESPACE", "NAME", "PHASE", "INBOUND", "OUTBOUND", "AGE"];
    let rows: Vec<Vec<String>> = services.iter().map(service_row).collect();
    print_table(headers, &rows);
}

fn print_services_table_with_cluster(entries: &[(String, LatticeService)]) {
    let headers = &[
        "CLUSTER",
        "NAMESPACE",
        "NAME",
        "PHASE",
        "INBOUND",
        "OUTBOUND",
        "AGE",
    ];
    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|(cluster, svc)| {
            let mut row = vec![cluster.clone()];
            row.extend(service_row(svc));
            row
        })
        .collect();
    print_table(headers, &rows);
}
