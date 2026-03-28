//! Secret authorization via Cedar policies

use lattice_cedar::{PolicyEngine, SecretAuthzRequest};
use lattice_common::crd::WorkloadSpec;

use crate::error::CompilationError;

/// Authorize secret access via Cedar policies (default-deny).
///
/// Collects all secret resources, builds a batch authorization request,
/// and evaluates it. Returns an error if any path is denied.
pub(crate) async fn authorize_secrets(
    cedar: &PolicyEngine,
    name: &str,
    namespace: &str,
    kind: &str,
    workload: &WorkloadSpec,
) -> Result<(), CompilationError> {
    let secret_paths: Vec<_> = workload
        .resources
        .iter()
        .filter(|(_, r)| r.type_.is_secret())
        .filter_map(|(resource_name, r)| {
            let remote_key = r.secret_remote_key()?.to_string();
            let provider = r.params.as_secret()?.provider.clone();
            Some((resource_name.clone(), remote_key, provider))
        })
        .collect();

    if secret_paths.is_empty() {
        return Ok(());
    }

    let result = cedar
        .authorize_secrets(&SecretAuthzRequest {
            service_name: name.to_string(),
            namespace: namespace.to_string(),
            kind: kind.to_string(),
            secret_paths,
        })
        .await;

    if !result.is_allowed() {
        let details = result
            .denied
            .iter()
            .map(|d| format!("'{}': {}", d.resource_name, d.reason))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(CompilationError::secret_access_denied(details));
    }

    Ok(())
}
