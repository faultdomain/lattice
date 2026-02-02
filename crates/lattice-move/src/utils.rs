//! Shared utility functions for move operations
//!
//! This module contains functions used by both cell.rs and agent.rs to avoid duplication.

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, DynamicObject, ListParams, Patch, PatchParams};
use kube::Client;
use tracing::debug;

use crate::error::MoveError;
use crate::{MOVE_HIERARCHY_LABEL, MOVE_LABEL};

/// Information about a discovered CRD type for move operations
#[derive(Debug, Clone)]
pub struct DiscoveredCrdType {
    /// API version (e.g., "cluster.x-k8s.io/v1beta1")
    pub api_version: String,
    /// Kind (e.g., "Cluster")
    pub kind: String,
    /// Plural name (e.g., "clusters")
    pub plural: String,
    /// Whether this type has the move-hierarchy label
    pub move_hierarchy: bool,
}

/// Discover CRDs with move labels.
///
/// This is shared logic used by:
/// - ObjectGraph::discover_types (cell-side discovery)
/// - AgentMover::discover_move_types (agent-side UID map rebuild)
///
/// Returns a list of discovered CRD types with their API information.
pub async fn discover_move_crds(client: &Client) -> Result<Vec<DiscoveredCrdType>, MoveError> {
    let crd_api: Api<CustomResourceDefinition> = Api::all(client.clone());
    let crds = crd_api
        .list(&ListParams::default())
        .await
        .map_err(|e| MoveError::Discovery(format!("failed to list CRDs: {}", e)))?;

    let mut types = Vec::new();

    for crd in crds.items {
        let labels = crd.metadata.labels.as_ref();

        // Check for move label or move-hierarchy label
        let has_move = labels.is_some_and(|l| l.contains_key(MOVE_LABEL));
        let has_move_hierarchy = labels.is_some_and(|l| l.contains_key(MOVE_HIERARCHY_LABEL));

        if !has_move && !has_move_hierarchy {
            continue;
        }

        // Skip CRDs without a singular name
        if crd.spec.names.singular.is_none() {
            continue;
        }

        let group = &crd.spec.group;
        let kind = &crd.spec.names.kind;
        let plural = &crd.spec.names.plural;

        // Use the storage version (the one with storage: true)
        let storage_version = crd
            .spec
            .versions
            .iter()
            .find(|v| v.storage)
            .or_else(|| crd.spec.versions.first());

        if let Some(version) = storage_version {
            let api_version = if group.is_empty() {
                version.name.clone()
            } else {
                format!("{}/{}", group, version.name)
            };

            debug!(
                kind = %kind,
                api_version = %api_version,
                move_hierarchy = has_move_hierarchy,
                "Discovered move CRD type"
            );

            types.push(DiscoveredCrdType {
                api_version,
                kind: kind.clone(),
                plural: plural.clone(),
                move_hierarchy: has_move_hierarchy,
            });
        }
    }

    Ok(types)
}

/// Patch resources of a specific type to set the paused state.
///
/// This is shared logic used by:
/// - cell.rs::set_resource_paused
/// - agent.rs::unpause_resource
///
/// Returns the count of resources patched.
pub async fn patch_resources_paused(
    client: &Client,
    namespace: &str,
    group: &str,
    kind: &str,
    paused: bool,
) -> Result<u32, MoveError> {
    // Use discovery to find the correct API version
    let api_resource =
        lattice_common::kube_utils::build_api_resource_with_discovery(client, group, kind)
            .await
            .map_err(|e| {
                MoveError::Discovery(format!("Failed to discover {}/{}: {}", group, kind, e))
            })?;

    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, &api_resource);
    let list = api
        .list(&Default::default())
        .await
        .map_err(MoveError::Kube)?;

    let mut count = 0u32;
    for obj in list.items {
        let name = match &obj.metadata.name {
            Some(n) => n.clone(),
            None => continue,
        };

        let patch = serde_json::json!({ "spec": { "paused": paused } });
        api.patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
            .map_err(|e| {
                MoveError::PauseFailed(format!(
                    "Failed to {} {} {}: {}",
                    if paused { "pause" } else { "unpause" },
                    kind,
                    name,
                    e
                ))
            })?;

        debug!(kind = %kind, name = %name, paused = paused, "Set paused state");
        count += 1;
    }

    Ok(count)
}

/// Common suffixes used for CAPI secret naming conventions
pub(crate) const CAPI_SECRET_SUFFIXES: &[&str] = &["-kubeconfig", "-ca", "-etcd", "-sa"];

/// Check if a secret name belongs to a cluster based on CAPI naming conventions.
///
/// Returns Some(cluster_uid) if the secret belongs to a cluster, None otherwise.
pub(crate) fn find_cluster_owner_for_secret<'a>(
    secret_name: &str,
    cluster_names: impl Iterator<Item = (&'a str, &'a str)>,
) -> Option<String> {
    for (cluster_name, cluster_uid) in cluster_names {
        // Precompute the prefix once
        let prefix = format!("{}-", cluster_name);

        // Check if secret name starts with cluster prefix
        if secret_name.starts_with(&prefix) {
            // Check for known CAPI secret suffixes
            for suffix in CAPI_SECRET_SUFFIXES {
                if secret_name == format!("{}{}", cluster_name, suffix) {
                    return Some(cluster_uid.to_string());
                }
            }
            // Also match any secret starting with cluster-name prefix
            return Some(cluster_uid.to_string());
        }
    }
    None
}

/// Check if an error indicates a "not found" condition.
///
/// This provides structured error checking instead of fragile string matching.
pub(crate) fn is_not_found_error(err: &kube::Error) -> bool {
    match err {
        kube::Error::Api(api_err) => api_err.code == 404,
        _ => {
            // Fallback to string checking for other error types
            let err_str = err.to_string();
            err_str.contains("404") || err_str.contains("not found")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_cluster_owner_for_secret() {
        let clusters = [("my-cluster", "uid-1"), ("other-cluster", "uid-2")];

        // Test kubeconfig secret
        assert_eq!(
            find_cluster_owner_for_secret(
                "my-cluster-kubeconfig",
                clusters.iter().map(|(n, u)| (*n, *u))
            ),
            Some("uid-1".to_string())
        );

        // Test ca secret
        assert_eq!(
            find_cluster_owner_for_secret("my-cluster-ca", clusters.iter().map(|(n, u)| (*n, *u))),
            Some("uid-1".to_string())
        );

        // Test arbitrary secret with cluster prefix
        assert_eq!(
            find_cluster_owner_for_secret(
                "other-cluster-foo-bar",
                clusters.iter().map(|(n, u)| (*n, *u))
            ),
            Some("uid-2".to_string())
        );

        // Test non-matching secret
        assert_eq!(
            find_cluster_owner_for_secret(
                "unrelated-secret",
                clusters.iter().map(|(n, u)| (*n, *u))
            ),
            None
        );
    }
}
