//! Volume authorization — owner consent + Cedar policy

use lattice_cedar::{PolicyEngine, VolumeAuthzRequest};
use lattice_common::crd::WorkloadSpec;
use lattice_common::graph::ServiceGraph;

use crate::error::CompilationError;

/// Authorize volume access for shared volume references.
///
/// Two-layer authorization:
/// 1. **Owner consent**: The volume owner must list this service in `allowedConsumers`
/// 2. **Cedar policy**: If Cedar policies exist, they must permit `AccessVolume`
pub(crate) async fn authorize_volumes(
    cedar: &PolicyEngine,
    graph: &ServiceGraph,
    name: &str,
    namespace: &str,
    workload: &WorkloadSpec,
) -> Result<(), CompilationError> {
    let volume_refs: Vec<_> = workload
        .resources
        .iter()
        .filter(|(_, r)| r.is_volume_reference())
        .filter_map(|(resource_name, r)| {
            let volume_id = r.id.as_ref()?;
            let vol_ns = r.namespace.as_deref().unwrap_or(namespace);
            Some((resource_name.clone(), vol_ns.to_string(), volume_id.clone()))
        })
        .collect();

    if volume_refs.is_empty() {
        return Ok(());
    }

    // Layer 1: Owner consent via graph
    let mut denied = Vec::new();
    for (resource_name, vol_ns, volume_id) in &volume_refs {
        let Some(ownership) = graph.get_volume_owner(vol_ns, volume_id) else {
            denied.push(format!(
                "'{}': no owner found for volume '{}' in namespace '{}' \
                 (owner service may not exist or hasn't declared size)",
                resource_name, volume_id, vol_ns,
            ));
            continue;
        };

        let consumer_key_short = name.to_string();
        let consumer_key_qualified = format!("{}/{}", namespace, name);

        let allowed = ownership
            .params
            .allowed_consumers
            .as_ref()
            .map(|consumers| {
                consumers.iter().any(|c| {
                    c == &consumer_key_qualified
                        || (c == &consumer_key_short && namespace == vol_ns)
                })
            })
            .unwrap_or(false);

        if !allowed {
            denied.push(format!(
                "'{}': not in allowedConsumers of volume '{}' owned by '{}/{}'",
                resource_name, volume_id, ownership.owner_namespace, ownership.owner_name,
            ));
        }
    }

    if !denied.is_empty() {
        return Err(CompilationError::volume_access_denied(denied.join("; ")));
    }

    // Layer 2: Cedar policy authorization
    let result = cedar
        .authorize_volumes(&VolumeAuthzRequest {
            service_name: name.to_string(),
            namespace: namespace.to_string(),
            volume_refs,
        })
        .await;

    if !result.is_allowed() {
        let details = result
            .denied
            .iter()
            .map(|d| {
                format!(
                    "'{}' (volume '{}'): {}",
                    d.resource_name, d.volume_id, d.reason
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(CompilationError::volume_access_denied(details));
    }

    Ok(())
}
