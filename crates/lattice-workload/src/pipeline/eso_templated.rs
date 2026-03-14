//! ESO-templated env var compilation
//!
//! Handles mixed-content env vars that contain both literal text and secret
//! references (e.g., `postgres://${secret.db.user}:${secret.db.pass}@host`).
//! Creates ExternalSecrets with Go templates that ESO renders at sync time.

use std::collections::BTreeMap;

use lattice_common::template::EsoTemplatedEnvVar;
use lattice_secret_provider::eso::ExternalSecret;

use crate::error::CompilationError;
use crate::k8s::{EnvFromSource, SecretEnvSource};
use crate::pipeline::secrets::{resolve_eso_data, resolve_single_store, SecretRef};

/// Compile ESO-templated env vars into ExternalSecrets + envFrom references.
///
/// Each env var's secret refs must all come from the same store, but different
/// env vars may use different stores. Creates one ExternalSecret per store group.
pub(crate) fn compile_eso_templated_env_vars(
    service_name: &str,
    container_name: &str,
    namespace: &str,
    eso_templated_variables: &BTreeMap<String, EsoTemplatedEnvVar>,
    secret_refs: &BTreeMap<String, SecretRef>,
) -> Result<(Vec<ExternalSecret>, Vec<EnvFromSource>), CompilationError> {
    // Validate per-var store consistency and group vars by store
    let mut by_store: BTreeMap<String, Vec<(&String, &EsoTemplatedEnvVar)>> = BTreeMap::new();

    for (var_name, templated) in eso_templated_variables {
        let store = resolve_single_store(
            &templated.secret_refs,
            secret_refs,
            &format!("env var '{}'", var_name),
        )?;
        by_store
            .entry(store)
            .or_default()
            .push((var_name, templated));
    }

    let mut external_secrets = Vec::new();
    let mut env_from_refs = Vec::new();

    for (idx, (store_name, vars)) in by_store.iter().enumerate() {
        let suffix = if by_store.len() == 1 {
            String::new()
        } else {
            format!("-{}", idx)
        };
        let es_name = format!("{}-{}-env-eso{}", service_name, container_name, suffix);

        let mut template_data = BTreeMap::new();
        let mut all_refs = Vec::new();

        for (var_name, templated) in vars {
            template_data.insert((*var_name).clone(), templated.rendered_template.clone());
            all_refs.extend(templated.secret_refs.iter().map(|r| (var_name.as_str(), r)));
        }

        let flat_refs: Vec<_> = all_refs.iter().map(|(_, r)| (*r).clone()).collect();
        let context = format!("env var(s) in {}", es_name);
        let eso_data = resolve_eso_data(&flat_refs, secret_refs, &context)?;

        let mut es =
            ExternalSecret::templated(&es_name, namespace, store_name, template_data, eso_data);
        // Label with owning service for cleanup on Cedar policy revocation
        es.metadata.labels.insert(
            lattice_common::LABEL_SERVICE_OWNER.to_string(),
            service_name.to_string(),
        );
        external_secrets.push(es);

        env_from_refs.push(EnvFromSource {
            config_map_ref: None,
            secret_ref: Some(SecretEnvSource { name: es_name }),
        });
    }

    Ok((external_secrets, env_from_refs))
}
