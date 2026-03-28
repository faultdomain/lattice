//! External endpoint authorization via Cedar policies

use lattice_cedar::{ExternalEndpointAuthzRequest, PolicyEngine};
use lattice_common::crd::WorkloadSpec;

use crate::error::CompilationError;

/// Authorize external endpoint access via Cedar policies (default-deny).
///
/// Collects all external-service resources, parses their endpoints, builds a
/// batch authorization request, and evaluates it. Returns an error if any
/// endpoint is denied.
pub(crate) async fn authorize_external_endpoints(
    cedar: &PolicyEngine,
    name: &str,
    namespace: &str,
    kind: &str,
    workload: &WorkloadSpec,
) -> Result<(), CompilationError> {
    let endpoints: Vec<_> = workload
        .resources
        .iter()
        .filter(|(_, r)| r.type_.is_external_service() && r.direction.is_outbound())
        .flat_map(|(resource_name, r)| {
            let params = match r.params.as_external_service() {
                Some(p) => p,
                None => return vec![],
            };
            params
                .parsed_endpoints()
                .into_values()
                .map(|ep| (resource_name.clone(), ep.host, ep.port, ep.protocol))
                .collect::<Vec<_>>()
        })
        .collect();

    if endpoints.is_empty() {
        return Ok(());
    }

    let result = cedar
        .authorize_external_endpoints(&ExternalEndpointAuthzRequest {
            service_name: name.to_string(),
            namespace: namespace.to_string(),
            kind: kind.to_string(),
            endpoints,
        })
        .await;

    if !result.is_allowed() {
        let details = result
            .denied
            .iter()
            .map(|d| {
                format!(
                    "'{}' ({}:{}): {}",
                    d.resource_name, d.host, d.port, d.reason
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(CompilationError::external_endpoint_access_denied(details));
    }

    Ok(())
}
