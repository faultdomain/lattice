//! `lattice get cluster <name>` - detailed view of a single cluster

use crate::{Error, Result};

use super::format::format_age;
use super::tree::discover_tree;
use super::OutputFormat;

pub async fn run(kubeconfig: Option<&str>, name: &str, output: &OutputFormat) -> Result<()> {
    let (tree, _port_forward) = discover_tree(kubeconfig).await?;

    let info = tree.clusters.get(name).ok_or_else(|| {
        Error::command_failed(format!(
            "cluster '{}' not found. Available clusters: {}",
            name,
            tree.clusters.keys().cloned().collect::<Vec<_>>().join(", ")
        ))
    })?;

    match output {
        OutputFormat::Table => print_cluster_detail(info, &tree),
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(info)
                .map_err(|e| Error::command_failed(format!("json serialization failed: {}", e)))?;
            println!("{}", json);
        }
    }

    Ok(())
}

fn print_cluster_detail(info: &super::tree::ClusterInfo, tree: &super::tree::ClusterTree) {
    println!("Name:          {}", info.name);
    println!("Phase:         {}", info.phase);
    println!("Provider:      {}", info.provider);
    println!("K8s Version:   {}", info.k8s_version);
    println!(
        "Role:          {}",
        if info.is_parent { "parent" } else { "leaf" }
    );
    println!(
        "Control Plane: {}/{}",
        info.control_plane_ready, info.control_plane_total
    );
    println!(
        "Workers:       {}/{}",
        info.workers_ready, info.workers_total
    );

    if let Some(endpoint) = &info.endpoint {
        println!("Endpoint:      {}", endpoint);
    }

    if let Some(msg) = &info.message {
        println!("Message:       {}", msg);
    }

    println!(
        "Pivot:         {}",
        if info.pivot_complete {
            "complete"
        } else {
            "pending"
        }
    );
    println!(
        "Bootstrap:     {}",
        if info.bootstrap_complete {
            "complete"
        } else {
            "pending"
        }
    );

    if let Some(ts) = &info.creation_timestamp {
        println!("Age:           {}", format_age(ts));
    }

    println!("Context:       {}", info.context);

    // Children
    let children = tree.children_of(&info.name);
    if !children.is_empty() {
        println!("\nChildren:");
        for child in children {
            let child_phase = tree
                .clusters
                .get(child)
                .map(|c| c.phase.as_str())
                .unwrap_or("unknown");
            println!("  - {} [{}]", child, child_phase);
        }
    }

    // Worker pools
    if !info.worker_pools.is_empty() {
        println!("\nWorker Pools:");
        for (pool_name, pool) in &info.worker_pools {
            let autoscale = if pool.autoscaling_enabled {
                " (autoscaling)"
            } else {
                ""
            };
            println!(
                "  {}: {}/{} ready{}",
                pool_name, pool.ready_replicas, pool.desired_replicas, autoscale
            );
            if let Some(msg) = &pool.message {
                println!("    {}", msg);
            }
        }
    }

    // Conditions
    if !info.conditions.is_empty() {
        println!("\nConditions:");
        for cond in &info.conditions {
            println!(
                "  {} = {} ({}): {}",
                cond.type_, cond.status, cond.reason, cond.message
            );
        }
    }
}
