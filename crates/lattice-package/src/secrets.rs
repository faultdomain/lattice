//! Secret processing for LatticePackage
//!
//! Processes `$secret` directives from the expanded values tree:
//! - Validates each directive's resource references against the resources block
//! - Builds Cedar authorization requests from referenced resources
//! - Generates ExternalSecrets with key mappings

use std::collections::{BTreeMap, BTreeSet};

use lattice_cedar::{PolicyEngine, SecretAuthzRequest};
use lattice_common::crd::ResourceSpec;
use lattice_secret_provider::eso::{self, ExternalSecret, ExternalSecretData, RemoteRef};
use lattice_template::SecretDirective;

use crate::error::PackageError;

/// Validate directive key mappings against the resources block.
///
/// Returns the set of resource names that are actually referenced.
pub fn validate_directive_refs(
    directives: &[SecretDirective],
    resources: &BTreeMap<String, ResourceSpec>,
) -> Result<BTreeSet<String>, PackageError> {
    let mut referenced = BTreeSet::new();

    for directive in directives {
        for mapping in &directive.keys {
            let spec = resources.get(&mapping.resource_name).ok_or_else(|| {
                PackageError::UndeclaredResource {
                    resource: mapping.resource_name.clone(),
                }
            })?;

            if !spec.type_.is_secret() {
                return Err(PackageError::Validation(format!(
                    "resource '{}' referenced in $secret directive at '{}' is not type: secret",
                    mapping.resource_name, directive.path
                )));
            }

            // Validate the key exists if the resource declares explicit keys
            if let Some(params) = spec.params.as_secret() {
                if let Some(ref keys) = params.keys {
                    if !keys.contains(&mapping.resource_key) {
                        return Err(PackageError::Validation(format!(
                            "$secret at '{}': resource '{}' does not declare key '{}' (available: {:?})",
                            directive.path, mapping.resource_name, mapping.resource_key, keys
                        )));
                    }
                }
            }

            referenced.insert(mapping.resource_name.clone());
        }
    }

    Ok(referenced)
}

/// Authorize secret access via Cedar for referenced resources only.
pub async fn authorize(
    cedar: &PolicyEngine,
    package_name: &str,
    namespace: &str,
    referenced: &BTreeSet<String>,
    resources: &BTreeMap<String, ResourceSpec>,
) -> Result<(), PackageError> {
    let secret_paths: Vec<_> = referenced
        .iter()
        .filter_map(|name| {
            let spec = resources.get(name)?;
            let remote_key = spec.secret_remote_key()?.to_string();
            let provider = spec.params.as_secret()?.provider.clone();
            Some((name.clone(), remote_key, provider))
        })
        .collect();

    if secret_paths.is_empty() {
        return Ok(());
    }

    let result = cedar
        .authorize_secrets(&SecretAuthzRequest {
            service_name: package_name.to_string(),
            namespace: namespace.to_string(),
            kind: "package".to_string(),
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
        return Err(PackageError::SecretAccessDenied(details));
    }

    Ok(())
}

/// Generate ExternalSecrets from $secret directives.
///
/// Each directive produces one ExternalSecret. Key mappings are resolved
/// against the resources block to get the remote path and store name.
pub fn generate_external_secrets(
    package_name: &str,
    namespace: &str,
    directives: &[SecretDirective],
    resources: &BTreeMap<String, ResourceSpec>,
) -> Result<Vec<ExternalSecret>, PackageError> {
    let mut result = Vec::with_capacity(directives.len());

    for directive in directives {
        let mut data = Vec::new();
        let mut store_name: Option<String> = None;

        for mapping in &directive.keys {
            let spec = resources.get(&mapping.resource_name).ok_or_else(|| {
                PackageError::UndeclaredResource {
                    resource: mapping.resource_name.clone(),
                }
            })?;
            let params = spec.params.as_secret().ok_or_else(|| {
                PackageError::Validation(format!(
                    "resource '{}': missing secret params",
                    mapping.resource_name
                ))
            })?;
            let remote_key = spec
                .secret_remote_key()
                .ok_or_else(|| {
                    PackageError::Validation(format!(
                        "resource '{}': missing 'id' field",
                        mapping.resource_name
                    ))
                })?
                .to_string();

            // All mappings in one directive must use the same store
            // (ESO requires one store per ExternalSecret)
            match &store_name {
                None => store_name = Some(params.provider.clone()),
                Some(existing) if existing != &params.provider => {
                    return Err(PackageError::Validation(format!(
                        "$secret at '{}' references resources from multiple stores ('{}' and '{}')",
                        directive.path, existing, params.provider
                    )));
                }
                Some(_) => {}
            }

            data.push(ExternalSecretData::new(
                &mapping.target_key,
                RemoteRef::with_property(&remote_key, &mapping.resource_key),
            ));
        }

        let store = store_name.ok_or_else(|| {
            PackageError::Validation(format!(
                "$secret at '{}' has no key mappings",
                directive.path
            ))
        })?;

        let mut es = eso::build_external_secret(
            &directive.secret_name,
            namespace,
            &store,
            "", // remote_key not used — we use explicit data entries
            None,
            None,
        );
        // Override with our explicit key-mapped data entries
        es.spec.data = data;
        es.spec.data_from = None;

        // Label with owning package for cleanup
        es.metadata.labels.insert(
            lattice_common::LABEL_SERVICE_OWNER.to_string(),
            package_name.to_string(),
        );

        result.push(es);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{ResourceParams, ResourceType, SecretParams};
    use lattice_template::DirectiveKeyMapping;

    fn make_secret_resource(provider: &str, id: &str, keys: &[&str]) -> ResourceSpec {
        ResourceSpec {
            type_: ResourceType::Secret,
            id: Some(id.to_string()),
            class: None,
            metadata: None,
            direction: Default::default(),
            namespace: None,
            params: ResourceParams::Secret(SecretParams {
                provider: provider.to_string(),
                keys: Some(keys.iter().map(|k| k.to_string()).collect()),
                refresh_interval: None,
                secret_type: None,
            }),
        }
    }

    fn make_directive(
        path: &str,
        secret_name: &str,
        mappings: &[(&str, &str, &str)],
    ) -> SecretDirective {
        SecretDirective {
            secret_name: secret_name.to_string(),
            path: path.to_string(),
            keys: mappings
                .iter()
                .map(|(target, resource, key)| DirectiveKeyMapping {
                    target_key: target.to_string(),
                    resource_name: resource.to_string(),
                    resource_key: key.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn validate_valid_refs() {
        let resources = BTreeMap::from([(
            "db-creds".to_string(),
            make_secret_resource("vault", "db/prod", &["password", "username"]),
        )]);
        let directives = vec![make_directive(
            "auth.existingSecret",
            "test-auth",
            &[("db-password", "db-creds", "password")],
        )];

        let referenced = validate_directive_refs(&directives, &resources).unwrap();
        assert!(referenced.contains("db-creds"));
    }

    #[test]
    fn validate_undeclared_resource_errors() {
        let resources = BTreeMap::new();
        let directives = vec![make_directive(
            "auth.existingSecret",
            "test-auth",
            &[("pw", "missing-resource", "password")],
        )];

        let err = validate_directive_refs(&directives, &resources).unwrap_err();
        assert!(err.to_string().contains("missing-resource"));
    }

    #[test]
    fn validate_invalid_key_errors() {
        let resources = BTreeMap::from([(
            "db-creds".to_string(),
            make_secret_resource("vault", "db/prod", &["password"]),
        )]);
        let directives = vec![make_directive(
            "auth.existingSecret",
            "test-auth",
            &[("pw", "db-creds", "nonexistent-key")],
        )];

        let err = validate_directive_refs(&directives, &resources).unwrap_err();
        assert!(err.to_string().contains("nonexistent-key"));
    }

    #[test]
    fn generate_single_directive() {
        let resources = BTreeMap::from([(
            "db-creds".to_string(),
            make_secret_resource("vault-prod", "db/prod/creds", &["password", "username"]),
        )]);
        let directives = vec![make_directive(
            "auth.existingSecret",
            "myapp-auth",
            &[
                ("db-password", "db-creds", "password"),
                ("db-username", "db-creds", "username"),
            ],
        )];

        let result =
            generate_external_secrets("myapp", "default", &directives, &resources).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].metadata.name.as_str(), "myapp-auth");
        assert_eq!(result[0].spec.data.len(), 2);
    }

    #[test]
    fn generate_mixed_stores_errors() {
        let resources = BTreeMap::from([
            (
                "creds-a".to_string(),
                make_secret_resource("vault-a", "a/creds", &["pw"]),
            ),
            (
                "creds-b".to_string(),
                make_secret_resource("vault-b", "b/creds", &["pw"]),
            ),
        ]);
        let directives = vec![make_directive(
            "auth.secret",
            "test",
            &[("a", "creds-a", "pw"), ("b", "creds-b", "pw")],
        )];

        let err = generate_external_secrets("pkg", "ns", &directives, &resources).unwrap_err();
        assert!(err.to_string().contains("multiple stores"));
    }
}
