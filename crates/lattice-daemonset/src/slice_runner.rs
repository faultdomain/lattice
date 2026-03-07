//! Slice lifecycle management.
//!
//! Spawns monitoring slice futures and handles graceful shutdown.

use tracing::info;

/// Run only the GPU monitoring slice.
pub async fn run_gpu_slice(client: &kube::Client, node_name: &str) -> anyhow::Result<()> {
    run_with_shutdown("GPU monitoring slice", client, node_name).await
}

/// Run all monitoring slices.
///
/// Currently only GPU monitoring. Future slices (network, disk) will be
/// spawned here as additional futures in the select.
pub async fn run_all_slices(client: &kube::Client, node_name: &str) -> anyhow::Result<()> {
    run_with_shutdown("all monitoring slices", client, node_name).await
}

async fn run_with_shutdown(
    label: &str,
    client: &kube::Client,
    node_name: &str,
) -> anyhow::Result<()> {
    info!("running {label}");

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("received shutdown signal");
    };

    let gpu_future = lattice_gpu_monitor::run(client.clone(), node_name.to_string());

    tokio::select! {
        result = gpu_future => {
            if let Err(e) = result {
                tracing::error!(error = %e, "GPU monitor slice exited with error");
                return Err(e);
            }
        }
        _ = shutdown => {}
    }

    info!("{label} shutdown complete");
    Ok(())
}
