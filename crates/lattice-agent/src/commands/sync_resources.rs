//! Sync resources command handler.

use lattice_proto::SyncDistributedResourcesCommand;
use tracing::{debug, info, warn};

use crate::distributable_resources_from_proto;
use crate::pivot::apply_distributed_resources;

use super::CommandContext;

/// Handle a sync resources command from the cell.
pub async fn handle(cmd: &SyncDistributedResourcesCommand, ctx: &CommandContext) {
    let resources = distributable_resources_from_proto(cmd.resources.clone().unwrap_or_default());

    info!(
        cloud_providers = resources.cloud_providers.len(),
        secrets_providers = resources.secrets_providers.len(),
        cedar_policies = resources.cedar_policies.len(),
        oidc_providers = resources.oidc_providers.len(),
        image_providers = resources.image_providers.len(),
        secrets = resources.secrets.len(),
        full_sync = cmd.full_sync,
        "Received sync resources command"
    );

    let full_sync = cmd.full_sync;
    let provider = ctx.kube_provider.clone();

    tokio::spawn(async move {
        let Some(client) =
            crate::kube_client::create_client_logged(provider.as_ref(), "synced resources").await
        else {
            return;
        };

        if let Err(e) = apply_distributed_resources(&client, &resources).await {
            warn!(error = %e, "Failed to apply synced resources");
        } else {
            info!(
                cloud_providers = resources.cloud_providers.len(),
                secrets_providers = resources.secrets_providers.len(),
                cedar_policies = resources.cedar_policies.len(),
                oidc_providers = resources.oidc_providers.len(),
                secrets = resources.secrets.len(),
                full_sync,
                "Synced resources applied"
            );
        }

        if full_sync {
            debug!("Full sync requested - cleanup of removed resources not yet implemented");
        }
    });
}
