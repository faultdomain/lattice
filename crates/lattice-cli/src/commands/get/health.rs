//! `lattice get health` - Fleet health overview with node status and heartbeat info

use crate::Result;

use super::tree::{discover_tree, ClusterTree};
use super::OutputFormat;

pub async fn run(kubeconfig: Option<&str>, output: &OutputFormat) -> Result<()> {
    let (tree, _port_forward) = discover_tree(kubeconfig).await?;

    if tree.clusters.is_empty() {
        println!("No clusters found.");
        return Ok(());
    }

    match output {
        OutputFormat::Table => print_health_tree(&tree),
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&tree).map_err(|e| {
                crate::Error::command_failed(format!("json serialization failed: {}", e))
            })?;
            println!("{}", json);
        }
    }

    Ok(())
}

fn print_health_tree(tree: &ClusterTree) {
    println!("Fleet Health\n");

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

        print_health_node(tree, root, prefix, child_prefix, true);
    }
}

fn print_health_node(
    tree: &ClusterTree,
    name: &str,
    prefix: &str,
    child_prefix: &str,
    is_root: bool,
) {
    let info = tree.clusters.get(name);

    // Cluster header line: name (phase) status_icon
    let phase = info
        .map(|i| {
            if i.connected {
                i.phase.clone()
            } else {
                "disconnected".to_string()
            }
        })
        .unwrap_or_else(|| "unknown".to_string());

    let status_icon = match phase.as_str() {
        "Ready" => "✓",
        "Failed" => "✗",
        "Provisioning" | "Pivoting" | "Pending" => "⟳",
        "disconnected" => "?",
        _ => "·",
    };

    println!("{}{} ({}) {}", prefix, name, phase, status_icon);

    if let Some(info) = info {
        // Node counts
        let cp_str = format!("{}/{}", info.control_plane_ready, info.control_plane_total);
        let workers_str = format!("{}/{}", info.workers_ready, info.workers_total);
        println!(
            "{}    Nodes: {} CP, {} workers",
            child_prefix, cp_str, workers_str
        );

        // Agent status
        if is_root {
            println!("{}    Agent: n/a (root)", child_prefix);
        } else if info.connected {
            println!("{}    Agent: connected", child_prefix);
        } else {
            println!("{}    Agent: disconnected", child_prefix);
        }

        // Children summary (for parent clusters)
        let children = tree.children_of(name);
        if !children.is_empty() {
            let connected = children
                .iter()
                .filter(|c| tree.clusters.get(c.as_str()).is_some_and(|i| i.connected))
                .count();
            let disconnected = children.len() - connected;
            println!(
                "{}    Children: {} connected, {} disconnected",
                child_prefix, connected, disconnected
            );
        }

        // Conditions (non-Ready conditions that are True, indicating issues)
        let problem_conditions: Vec<&str> = info
            .conditions
            .iter()
            .filter(|c| c.type_ != "Ready" && c.status == "True")
            .map(|c| c.type_.as_str())
            .collect();
        if !problem_conditions.is_empty() {
            println!(
                "{}    Conditions: {}",
                child_prefix,
                problem_conditions.join(", ")
            );
        } else if phase == "Ready" {
            println!("{}    Conditions: all healthy", child_prefix);
        }
    }

    // Recurse into children
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

        print_health_node(tree, child, &full_prefix, &full_child_prefix, false);
    }
}
