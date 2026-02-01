//! Crash recovery utilities
//!
//! Provides functions for recovering state after operator restarts.

use std::sync::Arc;
use std::time::{Duration, Instant};

use kube::api::ListParams;
use kube::{Api, Client};

use crate::bootstrap::{BootstrapState, ClusterRegistration, ManifestGenerator};
use crate::crd::{ClusterPhase, LatticeCluster};
use crate::parent::ParentServers;

use super::cell::discover_cell_host;
use super::polling::{wait_for_resource, DEFAULT_POLL_INTERVAL};

/// Wait for the API server to be responsive after infrastructure installation
///
/// After installing CRDs, Istio, and CAPI, the API server needs time to:
/// - Register webhooks
/// - Process CRD schemas
/// - Settle etcd writes
///
/// This function does a quick health check by listing our CRD and verifying
/// the response time is reasonable. This prevents race conditions where
/// controllers start before the API server is ready.
pub async fn wait_for_api_ready(client: &Client) -> anyhow::Result<()> {
    let api: Api<LatticeCluster> = Api::all(client.clone());
    let max_wait = Duration::from_secs(30);

    tracing::info!("Waiting for API server to be ready...");

    let result = wait_for_resource(
        "API server readiness",
        max_wait,
        DEFAULT_POLL_INTERVAL,
        || {
            let api = api.clone();
            async move {
                let op_start = Instant::now();
                match tokio::time::timeout(Duration::from_secs(5), api.list(&ListParams::default()))
                    .await
                {
                    Ok(Ok(_)) => {
                        let elapsed = op_start.elapsed();
                        if elapsed < Duration::from_millis(500) {
                            tracing::info!(
                                response_time_ms = elapsed.as_millis(),
                                "API server ready"
                            );
                            Ok(Some(()))
                        } else {
                            tracing::debug!(
                                response_time_ms = elapsed.as_millis(),
                                "API slow, waiting for it to settle..."
                            );
                            Ok(None)
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(error = %e, "API request failed, retrying...");
                        Ok(None)
                    }
                    Err(_) => {
                        tracing::debug!("API request timed out, retrying...");
                        Ok(None)
                    }
                }
            }
        },
    )
    .await;

    if result.is_err() {
        tracing::warn!("API server still slow after 30s, proceeding anyway");
    }

    Ok(())
}

/// Re-register clusters that completed bootstrap before operator restart
///
/// BootstrapState is in-memory and lost on restart. This reads status.bootstrap_complete
/// from the CRD and re-registers clusters so CSR signing works immediately.
pub async fn re_register_existing_clusters<G: ManifestGenerator>(
    client: &Client,
    bootstrap_state: &Arc<BootstrapState<G>>,
    self_cluster_name: &Option<String>,
    parent_servers: &Arc<ParentServers<G>>,
) {
    let clusters: Api<LatticeCluster> = Api::all(client.clone());
    let list = match clusters.list(&ListParams::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to list clusters for re-registration");
            return;
        }
    };

    for cluster in list.items {
        let name = match cluster.metadata.name.as_ref() {
            Some(n) => n,
            None => continue,
        };

        // Skip self-cluster
        if self_cluster_name.as_ref() == Some(name) {
            continue;
        }

        // Re-register clusters that need bootstrap (Provisioning, Pivoting, or bootstrap_complete)
        // BootstrapState is in-memory, so we must re-register on operator restart
        let phase = cluster
            .status
            .as_ref()
            .map(|s| &s.phase)
            .cloned()
            .unwrap_or_default();

        let needs_registration =
            matches!(phase, ClusterPhase::Provisioning | ClusterPhase::Pivoting)
                || cluster
                    .status
                    .as_ref()
                    .map(|s| s.bootstrap_complete)
                    .unwrap_or(false);

        if !needs_registration {
            tracing::debug!(cluster = %name, phase = ?phase, "Skipping re-registration (not in Provisioning/Pivoting)");
            continue;
        }

        // Skip if already registered
        if bootstrap_state.is_cluster_registered(name) {
            continue;
        }

        // Get self cluster for endpoints
        let self_name = match self_cluster_name {
            Some(n) => n,
            None => {
                tracing::warn!(cluster = %name, "Cannot re-register cluster: no self_cluster_name");
                continue;
            }
        };

        let self_cluster = match clusters.get(self_name).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to get self cluster for re-registration");
                continue;
            }
        };

        let endpoints = match self_cluster.spec.parent_config.as_ref() {
            Some(e) => e,
            None => {
                tracing::warn!("Self cluster has no endpoints, cannot re-register");
                continue;
            }
        };

        let ca_cert = parent_servers.ca_trust_bundle_pem().await;

        // Get the cell host from the LoadBalancer Service
        let cell_host = match discover_cell_host(client).await {
            Ok(Some(h)) => h,
            Ok(None) => {
                tracing::warn!(cluster = %name, "Cell host not yet assigned by cloud provider, cannot re-register");
                continue;
            }
            Err(e) => {
                tracing::warn!(cluster = %name, error = %e, "Failed to discover cell host, cannot re-register");
                continue;
            }
        };
        let cell_endpoint = format!(
            "{}:{}:{}",
            cell_host, endpoints.bootstrap_port, endpoints.grpc_port
        );

        // Serialize cluster manifest for export
        let cluster_manifest = match serde_json::to_string(&cluster.for_export()) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, cluster = %name, "Failed to serialize cluster for re-registration");
                continue;
            }
        };

        let autoscaling_enabled = cluster
            .spec
            .nodes
            .worker_pools
            .values()
            .any(|p| p.is_autoscaling_enabled());
        let registration = ClusterRegistration {
            cluster_id: name.clone(),
            cell_endpoint,
            ca_certificate: ca_cert,
            cluster_manifest,
            networking: cluster.spec.networking.clone(),
            proxmox_ipv4_pool: cluster
                .spec
                .provider
                .config
                .proxmox
                .as_ref()
                .map(|p| p.ipv4_pool.clone()),
            provider: cluster.spec.provider.provider_type(),
            bootstrap: cluster.spec.provider.kubernetes.bootstrap.clone(),
            k8s_version: cluster.spec.provider.kubernetes.version.clone(),
            autoscaling_enabled,
        };

        // Use token from LatticeCluster.status if available (source of truth)
        let existing_token = cluster
            .status
            .as_ref()
            .and_then(|s| s.bootstrap_token.as_deref());

        bootstrap_state
            .register_cluster_with_token(registration, existing_token)
            .await;
        tracing::info!(cluster = %name, "re-registered cluster after operator restart");
    }
}
