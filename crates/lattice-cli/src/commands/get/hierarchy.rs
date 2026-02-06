//! `lattice get hierarchy` - ASCII tree visualization of the cluster hierarchy

use crate::Result;

use super::tree::{discover_tree, ClusterTree};
use super::OutputFormat;

pub async fn run(kubeconfig: Option<&str>, output: &OutputFormat) -> Result<()> {
    let tree = discover_tree(kubeconfig).await?;

    if tree.clusters.is_empty() {
        println!("No clusters found.");
        return Ok(());
    }

    match output {
        OutputFormat::Table => print_hierarchy_tree(&tree),
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&tree).map_err(|e| {
                crate::Error::command_failed(format!("json serialization failed: {}", e))
            })?;
            println!("{}", json);
        }
    }

    Ok(())
}

fn print_hierarchy_tree(tree: &ClusterTree) {
    println!("Cluster Hierarchy:\n");

    let mut roots: Vec<&String> = tree.roots.iter().collect();
    roots.sort();

    for (i, root) in roots.iter().enumerate() {
        let is_last = i == roots.len() - 1;
        let prefix = if roots.len() == 1 {
            ""
        } else if is_last {
            "└── "
        } else {
            "├── "
        };
        let child_prefix = if roots.len() == 1 {
            ""
        } else if is_last {
            "    "
        } else {
            "│   "
        };

        print_node(tree, root, prefix, child_prefix);
    }
}

fn print_node(tree: &ClusterTree, name: &str, prefix: &str, child_prefix: &str) {
    let info = tree.clusters.get(name);

    let phase = info
        .map(|i| {
            if i.connected {
                i.phase.clone()
            } else {
                "disconnected".to_string()
            }
        })
        .unwrap_or_else(|| "unknown".to_string());

    let role_marker = if info.is_some_and(|i| i.is_parent) {
        " (parent)"
    } else {
        ""
    };

    println!("{}{}  [{}]{}", prefix, name, phase, role_marker);

    let children = tree.children_of(name);
    if children.is_empty() {
        return;
    }

    let mut sorted_children: Vec<&String> = children.iter().collect();
    sorted_children.sort();

    for (i, child) in sorted_children.iter().enumerate() {
        let is_last = i == sorted_children.len() - 1;
        let connector = if is_last { "└── " } else { "├── " };
        let next_prefix = if is_last { "    " } else { "│   " };

        let full_prefix = format!("{}{}", child_prefix, connector);
        let full_child_prefix = format!("{}{}", child_prefix, next_prefix);

        print_node(tree, child, &full_prefix, &full_child_prefix);
    }
}
