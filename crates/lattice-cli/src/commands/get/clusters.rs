//! `lattice get clusters` - list all clusters from kubeconfig contexts

use crate::Result;

use super::format::{format_age, print_table};
use super::tree::discover_tree;
use super::OutputFormat;

pub async fn run(kubeconfig: Option<&str>, output: &OutputFormat) -> Result<()> {
    let (tree, _port_forward) = discover_tree(kubeconfig).await?;

    if tree.clusters.is_empty() {
        println!("No clusters found.");
        return Ok(());
    }

    match output {
        OutputFormat::Table => print_clusters_table(&tree),
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&tree.clusters).map_err(|e| {
                crate::Error::command_failed(format!("json serialization failed: {}", e))
            })?;
            println!("{}", json);
        }
    }

    Ok(())
}

fn print_clusters_table(tree: &super::tree::ClusterTree) {
    let headers = &[
        "NAME", "PHASE", "PROVIDER", "K8S", "CP", "WORKERS", "ROLE", "AGE",
    ];

    // Sort clusters: roots first (sorted), then by depth, then alphabetical
    let mut names: Vec<&String> = tree.clusters.keys().collect();
    names.sort_by(|a, b| {
        let da = tree.depth(a);
        let db = tree.depth(b);
        da.cmp(&db).then(a.cmp(b))
    });

    let rows: Vec<Vec<String>> = names
        .iter()
        .map(|name| {
            let info = &tree.clusters[*name];
            let cp = format!("{}/{}", info.control_plane_ready, info.control_plane_total);
            let workers = format!("{}/{}", info.workers_ready, info.workers_total);
            let role = if info.is_parent { "parent" } else { "leaf" };
            let age = info
                .creation_timestamp
                .as_ref()
                .map(format_age)
                .unwrap_or_else(|| "-".to_string());
            let phase = if info.connected {
                info.phase.clone()
            } else {
                "[disconnected]".to_string()
            };

            vec![
                name.to_string(),
                phase,
                info.provider.clone(),
                info.k8s_version.clone(),
                cp,
                workers,
                role.to_string(),
                age,
            ]
        })
        .collect();

    print_table(headers, &rows);
}
