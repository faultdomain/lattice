//! Secrets compiler for LatticeService
//!
//! This module handles:
//! - ExternalSecret generation for secret resources
//! - SecretRef mapping for template resolution (${secret.*})

use std::collections::BTreeMap;

use lattice_secrets_provider::{
    ExternalSecret, ExternalSecretData, ExternalSecretDataFrom, ExternalSecretExtract,
    ExternalSecretSpec, ExternalSecretTarget, RemoteRef, SecretStoreRef,
};

use crate::crd::LatticeServiceSpec;

// =============================================================================
// Generated Secrets Container
// =============================================================================

/// Collection of secret-related resources generated for a service
#[derive(Clone, Debug, Default)]
pub struct GeneratedSecrets {
    /// ExternalSecrets to create (syncs from ClusterSecretStore)
    pub external_secrets: Vec<ExternalSecret>,
    /// Secret references for template resolution
    /// Maps resource name -> SecretRef (K8s secret name and available keys)
    pub secret_refs: BTreeMap<String, SecretRef>,
}

/// Reference to a synced Kubernetes Secret for template resolution
#[derive(Clone, Debug)]
pub struct SecretRef {
    /// Name of the K8s Secret (created by ESO)
    pub secret_name: String,
    /// Available keys in the secret (if explicitly specified)
    pub keys: Option<Vec<String>>,
}

impl GeneratedSecrets {
    /// Create empty generated secrets
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if no secrets were generated
    pub fn is_empty(&self) -> bool {
        self.external_secrets.is_empty() && self.secret_refs.is_empty()
    }
}

// =============================================================================
// Secrets Compiler
// =============================================================================

/// Compiler for generating ESO ExternalSecret resources from LatticeService secret dependencies
pub struct SecretsCompiler;

impl SecretsCompiler {
    /// Compile secret resources for a LatticeService
    ///
    /// For each secret resource in the spec:
    /// 1. Validates the resource has required fields (id for Vault path, params.provider)
    /// 2. Generates an ExternalSecret that syncs from the ClusterSecretStore
    /// 3. Registers the secret reference for template resolution
    ///
    /// # Arguments
    /// * `service_name` - Name of the service
    /// * `namespace` - Target namespace
    /// * `spec` - LatticeService spec
    ///
    /// # Returns
    /// Generated secrets including ExternalSecrets and secret references for templating.
    pub fn compile(
        service_name: &str,
        namespace: &str,
        spec: &LatticeServiceSpec,
    ) -> Result<GeneratedSecrets, String> {
        let mut output = GeneratedSecrets::new();

        // Collect all secret resources
        let secret_resources: Vec<_> = spec
            .resources
            .iter()
            .filter(|(_, r)| r.is_secret())
            .collect();

        if secret_resources.is_empty() {
            return Ok(output);
        }

        // Process each secret resource
        for (resource_name, resource_spec) in secret_resources {
            // Validate and parse params
            let params = resource_spec
                .secret_params()
                .map_err(|e| format!("secret resource '{}': {}", resource_name, e))?
                .ok_or_else(|| format!("secret resource '{}': missing params", resource_name))?;

            // Get the Vault path from the id field
            let vault_path = resource_spec
                .secret_vault_path()
                .ok_or_else(|| {
                    format!(
                        "secret resource '{}': missing 'id' field (Vault path)",
                        resource_name
                    )
                })?
                .to_string();

            // Generate K8s secret name
            let k8s_secret_name = resource_spec
                .secret_k8s_name(service_name, resource_name)
                .unwrap_or_else(|| format!("{}-{}", service_name, resource_name));

            // Build ExternalSecret data mappings
            let data = match &params.keys {
                Some(keys) => {
                    // Explicit key mappings
                    keys.iter()
                        .map(|key| {
                            ExternalSecretData::new(
                                key.clone(),
                                RemoteRef::with_property(&vault_path, key),
                            )
                        })
                        .collect()
                }
                None => {
                    // No explicit keys - use dataFrom to extract all
                    vec![]
                }
            };

            // Build dataFrom if no explicit keys
            let data_from = if params.keys.is_none() {
                Some(vec![ExternalSecretDataFrom {
                    extract: Some(ExternalSecretExtract {
                        key: vault_path.clone(),
                    }),
                }])
            } else {
                None
            };

            // Create ExternalSecret
            let external_secret = ExternalSecret::new(
                &k8s_secret_name,
                namespace,
                ExternalSecretSpec {
                    secret_store_ref: SecretStoreRef::cluster_secret_store(&params.provider),
                    target: ExternalSecretTarget::new(&k8s_secret_name),
                    data,
                    data_from,
                    refresh_interval: params.refresh_interval,
                },
            );

            output.external_secrets.push(external_secret);

            // Register secret reference for template resolution
            output.secret_refs.insert(
                resource_name.clone(),
                SecretRef {
                    secret_name: k8s_secret_name,
                    keys: params.keys,
                },
            );
        }

        Ok(output)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        ContainerSpec, DependencyDirection, DeploySpec, ReplicaSpec, ResourceSpec, ResourceType,
    };
    use std::collections::BTreeMap;

    fn make_spec_with_secrets(
        secrets: Vec<(&str, &str, &str, Option<Vec<&str>>, Option<&str>)>, // (name, vault_path, provider, keys, refresh_interval)
    ) -> LatticeServiceSpec {
        let mut resources = BTreeMap::new();

        for (name, vault_path, provider, keys, refresh_interval) in secrets {
            let mut params = BTreeMap::new();
            params.insert("provider".to_string(), serde_json::json!(provider));
            if let Some(ks) = keys {
                params.insert("keys".to_string(), serde_json::json!(ks));
            }
            if let Some(ri) = refresh_interval {
                params.insert("refreshInterval".to_string(), serde_json::json!(ri));
            }

            resources.insert(
                name.to_string(),
                ResourceSpec {
                    type_: ResourceType::Secret,
                    direction: DependencyDirection::default(),
                    id: Some(vault_path.to_string()),
                    class: None,
                    metadata: None,
                    params: Some(params),
                    namespace: None,
                    inbound: None,
                    outbound: None,
                },
            );
        }

        let mut containers = BTreeMap::new();
        containers.insert(
            "main".to_string(),
            ContainerSpec {
                image: "nginx:latest".to_string(),
                command: None,
                args: None,
                variables: BTreeMap::new(),
                files: BTreeMap::new(),
                volumes: BTreeMap::new(),
                resources: None,
                liveness_probe: None,
                readiness_probe: None,
                startup_probe: None,
                security: None,
            },
        );

        LatticeServiceSpec {
            containers,
            resources,
            service: None,
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
            ingress: None,
            sidecars: BTreeMap::new(),
            sysctls: BTreeMap::new(),
            host_network: None,
            share_process_namespace: None,
            backup: None,
        }
    }

    // =========================================================================
    // Story: Generate ExternalSecret for Secret Resource
    // =========================================================================

    #[test]
    fn story_generates_external_secret() {
        let spec = make_spec_with_secrets(vec![(
            "db-creds",
            "database/prod/credentials",
            "vault-prod",
            Some(vec!["username", "password"]),
            Some("1h"),
        )]);

        let output = SecretsCompiler::compile("myapp", "prod", &spec).unwrap();

        assert_eq!(output.external_secrets.len(), 1);
        let es = &output.external_secrets[0];

        assert_eq!(es.metadata.name, "myapp-db-creds");
        assert_eq!(es.metadata.namespace, "prod");
        assert_eq!(es.spec.secret_store_ref.name, "vault-prod");
        assert_eq!(es.spec.secret_store_ref.kind, "ClusterSecretStore");
        assert_eq!(es.spec.target.name, "myapp-db-creds");
        assert_eq!(es.spec.refresh_interval, Some("1h".to_string()));

        // Should have explicit data mappings
        assert_eq!(es.spec.data.len(), 2);
        assert_eq!(es.spec.data[0].secret_key, "username");
        assert_eq!(es.spec.data[0].remote_ref.key, "database/prod/credentials");
        assert_eq!(
            es.spec.data[0].remote_ref.property,
            Some("username".to_string())
        );
    }

    #[test]
    fn story_generates_secret_ref_for_templating() {
        let spec = make_spec_with_secrets(vec![(
            "db-creds",
            "database/prod/credentials",
            "vault-prod",
            Some(vec!["username", "password"]),
            None,
        )]);

        let output = SecretsCompiler::compile("myapp", "prod", &spec).unwrap();

        let secret_ref = output
            .secret_refs
            .get("db-creds")
            .expect("should have secret ref");
        assert_eq!(secret_ref.secret_name, "myapp-db-creds");
        assert_eq!(
            secret_ref.keys,
            Some(vec!["username".to_string(), "password".to_string()])
        );
    }

    #[test]
    fn story_uses_data_from_when_no_explicit_keys() {
        let spec = make_spec_with_secrets(vec![(
            "api-keys",
            "services/api-keys",
            "vault",
            None, // No explicit keys
            None,
        )]);

        let output = SecretsCompiler::compile("myapp", "prod", &spec).unwrap();

        let es = &output.external_secrets[0];

        // Should use dataFrom instead of data
        assert!(es.spec.data.is_empty());
        assert!(es.spec.data_from.is_some());

        let data_from = es.spec.data_from.as_ref().unwrap();
        assert_eq!(data_from.len(), 1);
        assert_eq!(
            data_from[0].extract.as_ref().unwrap().key,
            "services/api-keys"
        );
    }

    // =========================================================================
    // Story: Validate Secret Resource Fields
    // =========================================================================

    #[test]
    fn story_error_when_missing_id() {
        let mut spec = make_spec_with_secrets(vec![(
            "db-creds",
            "database/prod/credentials",
            "vault-prod",
            None,
            None,
        )]);

        // Remove the id
        if let Some(resource) = spec.resources.get_mut("db-creds") {
            resource.id = None;
        }

        let result = SecretsCompiler::compile("myapp", "prod", &spec);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'id' field"));
    }

    #[test]
    fn story_error_when_missing_provider() {
        let mut spec = make_spec_with_secrets(vec![(
            "db-creds",
            "database/prod/credentials",
            "vault-prod",
            None,
            None,
        )]);

        // Remove the provider from params
        if let Some(resource) = spec.resources.get_mut("db-creds") {
            if let Some(params) = resource.params.as_mut() {
                params.remove("provider");
            }
        }

        let result = SecretsCompiler::compile("myapp", "prod", &spec);
        assert!(result.is_err());
    }

    // =========================================================================
    // Story: Multiple Secrets
    // =========================================================================

    #[test]
    fn story_multiple_secrets() {
        let spec = make_spec_with_secrets(vec![
            (
                "db-creds",
                "database/prod/credentials",
                "vault-prod",
                Some(vec!["username", "password"]),
                Some("1h"),
            ),
            (
                "api-key",
                "services/api-key",
                "vault-prod",
                Some(vec!["key"]),
                None,
            ),
        ]);

        let output = SecretsCompiler::compile("myapp", "prod", &spec).unwrap();

        assert_eq!(output.external_secrets.len(), 2);
        assert_eq!(output.secret_refs.len(), 2);

        assert!(output.secret_refs.contains_key("db-creds"));
        assert!(output.secret_refs.contains_key("api-key"));
    }

    // =========================================================================
    // Story: No Secrets Returns Empty
    // =========================================================================

    #[test]
    fn story_no_secrets_returns_empty() {
        let spec = LatticeServiceSpec {
            containers: BTreeMap::new(),
            resources: BTreeMap::new(),
            service: None,
            replicas: ReplicaSpec::default(),
            deploy: DeploySpec::default(),
            ingress: None,
            sidecars: BTreeMap::new(),
            sysctls: BTreeMap::new(),
            host_network: None,
            share_process_namespace: None,
            backup: None,
        };

        let output = SecretsCompiler::compile("myapp", "prod", &spec).unwrap();

        assert!(output.is_empty());
    }
}
