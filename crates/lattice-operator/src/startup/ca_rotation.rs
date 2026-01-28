//! CA certificate rotation background task

use std::sync::Arc;
use std::time::Duration;

use crate::bootstrap::ManifestGenerator;
use crate::parent::ParentServers;

/// Start background CA rotation task (checks daily)
pub fn start_ca_rotation<G: ManifestGenerator + 'static>(parent_servers: Arc<ParentServers<G>>) {
    tokio::spawn(async move {
        // Check immediately on startup
        if let Err(e) = parent_servers.rotate_ca_if_needed().await {
            tracing::error!(error = %e, "CA rotation check failed on startup");
        }

        // Then check once per day
        let mut interval = tokio::time::interval(Duration::from_secs(86400));
        interval.tick().await; // Skip first tick (we just checked)
        loop {
            interval.tick().await;
            match parent_servers.rotate_ca_if_needed().await {
                Ok(true) => tracing::info!("CA rotated successfully"),
                Ok(false) => tracing::debug!("CA rotation not needed"),
                Err(e) => tracing::error!(error = %e, "CA rotation check failed"),
            }
        }
    });
}
