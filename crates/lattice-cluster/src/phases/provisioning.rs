//! Provisioning phase handler.
//!
//! Waits for CAPI infrastructure to be ready, then patches kubeconfig for proxy access.

use std::time::Duration;

use chrono::Utc;
use kube::runtime::controller::Action;
use kube::runtime::events::EventType;
use kube::{Resource, ResourceExt};
use tracing::{debug, info, warn};

use lattice_cell::patch_kubeconfig_for_proxy;
use lattice_common::crd::{ClusterPhase, LatticeCluster};
use lattice_common::events::{actions, reasons};
use lattice_common::{
    capi_namespace, lattice_svc_dns, Error, CELL_SERVICE_NAME, DEFAULT_PROXY_PORT,
};

use crate::controller::Context;
use crate::phases::update_status;

/// Maximum time a cluster can stay in Provisioning before transitioning to Failed.
/// Cloud provisioning typically completes in 10-20 minutes; 60 minutes is generous.
const MAX_PROVISIONING_DURATION: Duration = Duration::from_secs(3600);

/// Handle a cluster in the Provisioning phase.
///
/// This phase waits for CAPI infrastructure to become ready, then:
/// - Patches the kubeconfig to use the K8s API proxy
/// - Transitions to Pivoting phase
pub async fn handle_provisioning(cluster: &LatticeCluster, ctx: &Context) -> Result<Action, Error> {
    let name = cluster.name_any();
    let capi_namespace = capi_namespace(&name);

    // Copy the CAPI kubeconfig BEFORE patching it for proxy access.
    // Istiod needs the original direct API server kubeconfig for multi-cluster
    // discovery. After patch_kubeconfig_for_proxy_access rewrites the server
    // URL, the original is lost.
    if let Some(ref client) = ctx.client {
        let _ = copy_kubeconfig_for_istiod(client, &name, &capi_namespace).await;
    }

    // Patch kubeconfig to use proxy as soon as the secret exists.
    // CAPI needs this to reach the child cluster through the gRPC tunnel
    // when clusters are on separate networks.
    if !lattice_common::is_bootstrap_cluster() {
        let _ = patch_kubeconfig_for_proxy_access(cluster, ctx, &name, &capi_namespace).await;
    }

    debug!("checking infrastructure status");

    let bootstrap = cluster.spec.provider.kubernetes.bootstrap.clone();
    let is_ready = ctx
        .capi
        .is_infrastructure_ready(&name, &capi_namespace, bootstrap)
        .await?;

    if !is_ready {
        // Check if provisioning has exceeded max duration
        if let Some(status) = &cluster.status {
            if let Some(condition) = status.conditions.iter().find(|c| c.type_ == "Provisioning") {
                let elapsed = Utc::now() - condition.last_transition_time;
                if elapsed.to_std().unwrap_or_default() > MAX_PROVISIONING_DURATION {
                    warn!(
                        elapsed_mins = elapsed.num_minutes(),
                        "Provisioning exceeded max duration, transitioning to Failed"
                    );
                    update_status(
                        cluster,
                        ctx,
                        ClusterPhase::Failed,
                        Some("Provisioning timed out after 60 minutes"),
                        false,
                    )
                    .await?;
                    return Ok(Action::requeue(Duration::from_secs(60)));
                }
            }
        }

        debug!("infrastructure not ready yet");
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

    // Infrastructure is ready
    ctx.events
        .publish(
            &cluster.object_ref(&()),
            EventType::Normal,
            reasons::INFRASTRUCTURE_READY,
            actions::PROVISION,
            Some("Infrastructure ready, starting pivot".to_string()),
        )
        .await;

    // Transition to Pivoting
    info!("infrastructure ready, transitioning to Pivoting phase");
    update_status(cluster, ctx, ClusterPhase::Pivoting, None, false).await?;
    Ok(Action::requeue(Duration::from_secs(5)))
}

/// Patch kubeconfig to use the K8s API proxy for child cluster access.
///
/// Returns Ok(()) on success, or Err with a requeue Action if not ready or failed.
async fn patch_kubeconfig_for_proxy_access(
    cluster: &LatticeCluster,
    ctx: &Context,
    name: &str,
    capi_namespace: &str,
) -> Result<(), Result<Action, Error>> {
    let (Some(ref parent_servers), Some(ref client)) = (&ctx.parent_servers, &ctx.client) else {
        return Ok(());
    };

    // Build proxy URL from parent config
    let proxy_url = build_proxy_url(cluster);
    let ca_cert_pem = parent_servers.ca_trust_bundle_pem().await;

    match patch_kubeconfig_for_proxy(client, name, capi_namespace, &proxy_url, &ca_cert_pem).await {
        Ok(true) => {
            info!("kubeconfig patched for proxy, transitioning to Pivoting");
            Ok(())
        }
        Ok(false) => {
            // Kubeconfig Secret not ready yet, wait
            debug!("kubeconfig Secret not ready yet, waiting...");
            Err(Ok(Action::requeue(Duration::from_secs(5))))
        }
        Err(e) => {
            warn!(error = %e, "Failed to patch kubeconfig for proxy, will retry");
            Err(Ok(Action::requeue(Duration::from_secs(5))))
        }
    }
}

/// Build the proxy URL from cluster's parent config.
fn build_proxy_url(cluster: &LatticeCluster) -> String {
    let proxy_port = cluster
        .spec
        .parent_config
        .as_ref()
        .map(|e| e.proxy_port)
        .unwrap_or(DEFAULT_PROXY_PORT);
    format!(
        "https://{}:{}",
        lattice_svc_dns(CELL_SERVICE_NAME),
        proxy_port
    )
}

/// Copy the CAPI kubeconfig to istio-system for direct istiod access.
///
/// Istiod uses this kubeconfig for multi-cluster endpoint discovery via the
/// direct API server connection (not the auth proxy).
async fn copy_kubeconfig_for_istiod(
    client: &kube::Client,
    cluster_name: &str,
    capi_namespace: &str,
) -> Result<(), lattice_common::Error> {
    use k8s_openapi::api::core::v1::Secret;
    use kube::api::{Api, Patch, PatchParams};

    let dest_name = format!("istiod-direct-kubeconfig-{}", cluster_name);
    let dest_api: Api<Secret> = Api::namespaced(client.clone(), "istio-system");

    // Only copy once — if the destination already exists, the original
    // kubeconfig has already been captured before the proxy patch.
    if dest_api
        .get_opt(&dest_name)
        .await
        .map_err(|e| {
            lattice_common::Error::internal(format!("failed to check istiod kubeconfig: {e}"))
        })?
        .is_some()
    {
        return Ok(());
    }

    let secret_name = lattice_common::kubeconfig_secret_name(cluster_name);
    let src_api: Api<Secret> = Api::namespaced(client.clone(), capi_namespace);

    let src_secret = src_api.get(&secret_name).await.map_err(|e| {
        lattice_common::Error::internal(format!(
            "failed to read CAPI kubeconfig secret {}/{}: {}",
            capi_namespace, secret_name, e
        ))
    })?;

    let kubeconfig_data = src_secret
        .data
        .as_ref()
        .and_then(|d| d.get("value"))
        .ok_or_else(|| {
            lattice_common::Error::internal(
                "CAPI kubeconfig secret missing 'value' key".to_string(),
            )
        })?;

    let dest_secret = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": dest_name,
            "namespace": "istio-system",
            "labels": {
                "app.kubernetes.io/managed-by": "lattice",
                "lattice.dev/cluster": cluster_name
            }
        },
        "data": {
            "kubeconfig": kubeconfig_data
        }
    });

    let api: Api<Secret> = Api::namespaced(client.clone(), "istio-system");
    let params = PatchParams::apply("lattice-cluster-controller").force();
    api.patch(&dest_name, &params, &Patch::Apply(&dest_secret))
        .await
        .map_err(|e| {
            lattice_common::Error::internal(format!(
                "failed to create istiod kubeconfig secret: {}",
                e
            ))
        })?;

    info!(cluster = %cluster_name, secret = %dest_name, "copied CAPI kubeconfig to istio-system for istiod");
    Ok(())
}
