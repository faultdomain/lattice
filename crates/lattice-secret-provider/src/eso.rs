//! External Secrets Operator (ESO) types
//!
//! Typed structs for ESO ClusterSecretStore resources. These implement
//! `HasApiResource` for consistent API version handling.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use lattice_common::kube_utils::{HasApiResource, ObjectMeta};

// =============================================================================
// ClusterSecretStore
// =============================================================================

/// ESO ClusterSecretStore resource
///
/// A cluster-scoped SecretStore that can be referenced by ExternalSecrets
/// across all namespaces.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClusterSecretStore {
    /// API version
    #[serde(default = "ClusterSecretStore::default_api_version")]
    pub api_version: String,
    /// Resource kind
    #[serde(default = "ClusterSecretStore::default_kind")]
    pub kind: String,
    /// Resource metadata
    pub metadata: ClusterSecretStoreMetadata,
    /// Store specification
    pub spec: ClusterSecretStoreSpec,
}

impl HasApiResource for ClusterSecretStore {
    const API_VERSION: &'static str = "external-secrets.io/v1";
    const KIND: &'static str = "ClusterSecretStore";
}

impl ClusterSecretStore {
    fn default_api_version() -> String {
        <Self as HasApiResource>::API_VERSION.to_string()
    }
    fn default_kind() -> String {
        <Self as HasApiResource>::KIND.to_string()
    }

    /// Create a new ClusterSecretStore
    pub fn new(name: impl Into<String>, spec: ClusterSecretStoreSpec) -> Self {
        Self {
            api_version: Self::default_api_version(),
            kind: Self::default_kind(),
            metadata: ClusterSecretStoreMetadata::new(name),
            spec,
        }
    }
}

/// Metadata for ClusterSecretStore (cluster-scoped, no namespace)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ClusterSecretStoreMetadata {
    /// Resource name
    pub name: String,
    /// Labels
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

impl ClusterSecretStoreMetadata {
    /// Create new metadata with standard Lattice labels
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        let mut labels = BTreeMap::new();
        labels.insert(
            lattice_common::LABEL_MANAGED_BY.to_string(),
            lattice_common::LABEL_MANAGED_BY_LATTICE.to_string(),
        );
        labels.insert("lattice.dev/secrets-provider".to_string(), name.clone());
        Self { name, labels }
    }
}

/// ClusterSecretStore spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ClusterSecretStoreSpec {
    /// Provider configuration
    pub provider: ProviderSpec,
}

/// Provider specification (webhook backend for local infrastructure)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProviderSpec {
    /// Webhook provider configuration (used by local backend)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook: Option<WebhookProvider>,
}

/// Webhook provider configuration for ESO ClusterSecretStore
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WebhookProvider {
    /// Webhook URL with template placeholders (e.g., `{{ .remoteRef.key }}`)
    pub url: String,
    /// HTTP method (GET, POST, etc.)
    #[serde(default = "default_get")]
    pub method: String,
    /// Result extraction configuration
    pub result: WebhookResult,
}

fn default_get() -> String {
    "GET".to_string()
}

/// Result extraction for webhook provider
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WebhookResult {
    /// JSONPath expression to extract data from response
    pub json_path: String,
}

// =============================================================================
// ExternalSecret
// =============================================================================

/// ESO ExternalSecret resource
///
/// A namespace-scoped resource that syncs secrets from an external provider
/// (via ClusterSecretStore) into a Kubernetes Secret.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSecret {
    /// API version
    #[serde(default = "ExternalSecret::default_api_version")]
    pub api_version: String,
    /// Resource kind
    #[serde(default = "ExternalSecret::default_kind")]
    pub kind: String,
    /// Resource metadata
    pub metadata: ObjectMeta,
    /// ExternalSecret specification
    pub spec: ExternalSecretSpec,
}

impl HasApiResource for ExternalSecret {
    const API_VERSION: &'static str = "external-secrets.io/v1";
    const KIND: &'static str = "ExternalSecret";
}

impl ExternalSecret {
    fn default_api_version() -> String {
        <Self as HasApiResource>::API_VERSION.to_string()
    }
    fn default_kind() -> String {
        <Self as HasApiResource>::KIND.to_string()
    }

    /// Create a new ExternalSecret
    pub fn new(
        name: impl Into<String>,
        namespace: impl Into<String>,
        spec: ExternalSecretSpec,
    ) -> Self {
        Self {
            api_version: Self::default_api_version(),
            kind: Self::default_kind(),
            metadata: ObjectMeta::new(name, namespace),
            spec,
        }
    }

    /// Create a templated ExternalSecret (the most common pattern).
    ///
    /// Constructs an ExternalSecret backed by a ClusterSecretStore with a Go template
    /// target, 1h refresh interval, and no `dataFrom`. Used whenever file mounts or
    /// env vars contain `${secret.*}` placeholders that ESO renders at sync time.
    pub fn templated(
        name: impl Into<String>,
        namespace: impl Into<String>,
        store: &str,
        template_data: BTreeMap<String, String>,
        data: Vec<ExternalSecretData>,
    ) -> Self {
        let name = name.into();
        Self::new(
            &name,
            namespace,
            ExternalSecretSpec {
                secret_store_ref: SecretStoreRef::cluster_secret_store(store),
                target: ExternalSecretTarget::with_template(
                    &name,
                    ExternalSecretTemplate::new(template_data),
                ),
                data,
                data_from: None,
                refresh_interval: Some("1h".to_string()),
            },
        )
    }

    /// Set the K8s Secret type on the target (e.g., `kubernetes.io/dockerconfigjson`)
    pub fn with_secret_type(mut self, secret_type: impl Into<String>) -> Self {
        match &mut self.spec.target.template {
            Some(t) => t.type_ = Some(secret_type.into()),
            None => {
                self.spec.target.template = Some(ExternalSecretTemplate::with_type(secret_type));
            }
        }
        self
    }
}

/// ExternalSecret spec
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSecretSpec {
    /// Reference to the secret store
    pub secret_store_ref: SecretStoreRef,
    /// Target Kubernetes Secret configuration
    pub target: ExternalSecretTarget,
    /// Key mappings from external secret to K8s secret
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data: Vec<ExternalSecretData>,
    /// Alternative: fetch all keys matching a path pattern
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_from: Option<Vec<ExternalSecretDataFrom>>,
    /// Refresh interval for syncing (e.g., "1h", "30m")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_interval: Option<String>,
}

/// Reference to a SecretStore or ClusterSecretStore
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretStoreRef {
    /// Name of the SecretStore/ClusterSecretStore
    pub name: String,
    /// Kind: "SecretStore" or "ClusterSecretStore"
    #[serde(default = "SecretStoreRef::default_kind")]
    pub kind: String,
}

impl SecretStoreRef {
    fn default_kind() -> String {
        "ClusterSecretStore".to_string()
    }

    /// Create a reference to a ClusterSecretStore
    pub fn cluster_secret_store(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: "ClusterSecretStore".to_string(),
        }
    }
}

/// Target Kubernetes Secret configuration
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSecretTarget {
    /// Name of the Kubernetes Secret to create
    pub name: String,
    /// Creation policy: Owner, Orphan, Merge, None
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_policy: Option<String>,
    /// Deletion policy: Retain, Delete, Merge
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion_policy: Option<String>,
    /// Template for rendering secret data using Go templates
    ///
    /// When set, ESO uses this template to construct the K8s Secret data.
    /// This enables files with `${secret.*}` placeholders to be rendered
    /// at secret-sync time using ESO's Go template engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<ExternalSecretTemplate>,
}

impl ExternalSecretTarget {
    /// Create a new target with just the name
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            creation_policy: None,
            deletion_policy: None,
            template: None,
        }
    }

    /// Create a new target with a template
    pub fn with_template(name: impl Into<String>, template: ExternalSecretTemplate) -> Self {
        Self {
            name: name.into(),
            creation_policy: None,
            deletion_policy: None,
            template: Some(template),
        }
    }
}

/// Template for rendering ESO secret data using Go templates
///
/// ESO evaluates Go templates in `data` against the fetched secret values,
/// producing the final K8s Secret content. This allows files containing
/// `${secret.*}` placeholders to be rendered at sync time.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSecretTemplate {
    /// Template engine version (default "v2")
    #[serde(default = "ExternalSecretTemplate::default_engine_version")]
    pub engine_version: String,
    /// K8s Secret type (e.g., `kubernetes.io/dockerconfigjson` for imagePullSecrets)
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub type_: Option<String>,
    /// Template data: key -> Go template content
    ///
    /// Each key becomes a key in the resulting K8s Secret.
    /// Values can use Go template syntax like `{{ .secret_key }}` to
    /// reference fetched secret values from `spec.data`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, String>,
}

impl ExternalSecretTemplate {
    fn default_engine_version() -> String {
        "v2".to_string()
    }

    /// Create a new template with the given data
    pub fn new(data: BTreeMap<String, String>) -> Self {
        Self {
            engine_version: Self::default_engine_version(),
            type_: None,
            data,
        }
    }

    /// Create a template that only sets the K8s Secret type (no data templates)
    pub fn with_type(secret_type: impl Into<String>) -> Self {
        Self {
            engine_version: Self::default_engine_version(),
            type_: Some(secret_type.into()),
            data: BTreeMap::new(),
        }
    }
}

/// Individual key mapping from external secret to K8s secret
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSecretData {
    /// Key in the resulting Kubernetes Secret
    pub secret_key: String,
    /// Reference to the external secret
    pub remote_ref: RemoteRef,
}

impl ExternalSecretData {
    /// Create a new data mapping
    pub fn new(secret_key: impl Into<String>, remote_ref: RemoteRef) -> Self {
        Self {
            secret_key: secret_key.into(),
            remote_ref,
        }
    }
}

/// Reference to a key in the external secret store
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RemoteRef {
    /// Path/key in the external secret store (e.g., Vault path)
    pub key: String,
    /// Specific property within the secret (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
}

impl RemoteRef {
    /// Create a reference to a specific property within a secret
    pub fn with_property(key: impl Into<String>, property: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            property: Some(property.into()),
        }
    }
}

/// Fetch all keys from a path (alternative to explicit data mappings)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSecretDataFrom {
    /// Extract from a specific path
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extract: Option<ExternalSecretExtract>,
}

/// Extract configuration for dataFrom
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSecretExtract {
    /// Path to extract from
    pub key: String,
}

// =============================================================================
// Shared ExternalSecret Builders
// =============================================================================

use lattice_common::template::FileSecretRef;

/// Build an ExternalSecret that syncs from a ClusterSecretStore.
///
/// - `keys` is `Some` → `spec.data` entries with `RemoteRef::with_property()` per key
/// - `keys` is `None` → `spec.dataFrom` extract (all keys)
pub fn build_external_secret(
    name: &str,
    namespace: &str,
    store_name: &str,
    remote_key: &str,
    keys: Option<&[String]>,
    refresh_interval: Option<String>,
) -> ExternalSecret {
    let data = match keys {
        Some(keys) => keys
            .iter()
            .map(|key| {
                ExternalSecretData::new(key.clone(), RemoteRef::with_property(remote_key, key))
            })
            .collect(),
        None => vec![],
    };

    let data_from = if keys.is_none() {
        Some(vec![ExternalSecretDataFrom {
            extract: Some(ExternalSecretExtract {
                key: remote_key.to_string(),
            }),
        }])
    } else {
        None
    };

    ExternalSecret::new(
        name,
        namespace,
        ExternalSecretSpec {
            secret_store_ref: SecretStoreRef::cluster_secret_store(store_name),
            target: ExternalSecretTarget::new(name),
            data,
            data_from,
            refresh_interval,
        },
    )
}

/// Build an ExternalSecret with `target.template` for `${secret.*}` rendering.
///
/// `template_data`: key → rendered Go template content (e.g., `"password: {{ .creds_password }}"`)
/// `file_refs`: parsed `FileSecretRef`s from `extract_secret_refs()`
/// `available_keys`: if `Some`, validates each ref's key exists in this list
pub fn build_templated_external_secret(
    name: &str,
    namespace: &str,
    store_name: &str,
    remote_key: &str,
    available_keys: Option<&[String]>,
    template_data: BTreeMap<String, String>,
    file_refs: &[FileSecretRef],
) -> Result<ExternalSecret, String> {
    let mut eso_data: Vec<ExternalSecretData> = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();

    for fref in file_refs {
        if !seen_keys.insert(fref.eso_data_key.clone()) {
            continue;
        }

        if let Some(keys) = available_keys {
            if !keys.contains(&fref.key) {
                return Err(format!(
                    "secret reference uses key '{}' but available keys are: {:?}",
                    fref.key, keys
                ));
            }
        }

        eso_data.push(ExternalSecretData::new(
            &fref.eso_data_key,
            RemoteRef::with_property(remote_key, &fref.key),
        ));
    }

    Ok(ExternalSecret::templated(
        name,
        namespace,
        store_name,
        template_data,
        eso_data,
    ))
}

/// Apply an ExternalSecret to the cluster via server-side apply.
pub async fn apply_external_secret(
    client: &kube::Client,
    external_secret: &ExternalSecret,
    field_manager: &str,
) -> Result<(), lattice_common::ReconcileError> {
    use kube::api::{Api, DynamicObject, Patch, PatchParams};
    use lattice_common::kube_utils::HasApiResource;

    let es_json = serde_json::to_value(external_secret).map_err(|e| {
        lattice_common::ReconcileError::Internal(format!("failed to serialize ExternalSecret: {e}"))
    })?;

    let api_resource = ExternalSecret::api_resource();
    let es_api: Api<DynamicObject> = Api::namespaced_with(
        client.clone(),
        &external_secret.metadata.namespace,
        &api_resource,
    );
    let es_obj: DynamicObject = serde_json::from_value(es_json).map_err(|e| {
        lattice_common::ReconcileError::Internal(format!("failed to build ExternalSecret: {e}"))
    })?;

    let params = PatchParams::apply(field_manager).force();
    es_api
        .patch(
            &external_secret.metadata.name,
            &params,
            &Patch::Apply(&es_obj),
        )
        .await
        .map_err(|e| {
            lattice_common::ReconcileError::Kube(format!(
                "failed to apply ExternalSecret '{}': {e}",
                external_secret.metadata.name
            ))
        })?;

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_secret_serialization() {
        let secret = ExternalSecret::new(
            "my-api-db-creds",
            "default",
            ExternalSecretSpec {
                secret_store_ref: SecretStoreRef::cluster_secret_store("vault-prod"),
                target: ExternalSecretTarget::new("my-api-db-creds"),
                data: vec![
                    ExternalSecretData::new(
                        "username",
                        RemoteRef::with_property("database/prod/credentials", "username"),
                    ),
                    ExternalSecretData::new(
                        "password",
                        RemoteRef::with_property("database/prod/credentials", "password"),
                    ),
                ],
                data_from: None,
                refresh_interval: Some("1h".to_string()),
            },
        );

        let json = serde_json::to_string_pretty(&secret).unwrap();
        assert!(json.contains("external-secrets.io/v1"));
        assert!(json.contains("ExternalSecret"));
        assert!(json.contains("vault-prod"));
        assert!(json.contains("ClusterSecretStore"));
        assert!(json.contains("database/prod/credentials"));

        // Verify round-trip
        let parsed: ExternalSecret = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, secret);
    }

    #[test]
    fn test_external_secret_data_from() {
        let secret = ExternalSecret::new(
            "all-secrets",
            "default",
            ExternalSecretSpec {
                secret_store_ref: SecretStoreRef::cluster_secret_store("vault"),
                target: ExternalSecretTarget::new("all-secrets"),
                data: vec![],
                data_from: Some(vec![ExternalSecretDataFrom {
                    extract: Some(ExternalSecretExtract {
                        key: "path/to/secrets".to_string(),
                    }),
                }]),
                refresh_interval: None,
            },
        );

        let json = serde_json::to_string_pretty(&secret).unwrap();
        assert!(json.contains("dataFrom"));
        assert!(json.contains("extract"));
        assert!(json.contains("path/to/secrets"));
    }

    #[test]
    fn test_secret_store_ref_default_kind() {
        let store_ref = SecretStoreRef::cluster_secret_store("my-store");
        assert_eq!(store_ref.kind, "ClusterSecretStore");
    }

    #[test]
    fn test_external_secret_with_template() {
        let mut template_data = BTreeMap::new();
        template_data.insert(
            "config.yaml".to_string(),
            "database:\n  host: db.svc\n  password: {{ .db_password }}".to_string(),
        );

        let secret = ExternalSecret::new(
            "my-api-files",
            "prod",
            ExternalSecretSpec {
                secret_store_ref: SecretStoreRef::cluster_secret_store("vault-prod"),
                target: ExternalSecretTarget::with_template(
                    "my-api-files",
                    ExternalSecretTemplate::new(template_data),
                ),
                data: vec![ExternalSecretData::new(
                    "db_password",
                    RemoteRef::with_property("database/prod/credentials", "password"),
                )],
                data_from: None,
                refresh_interval: Some("1h".to_string()),
            },
        );

        let json = serde_json::to_string_pretty(&secret).unwrap();
        assert!(json.contains("template"));
        assert!(json.contains("engineVersion"));
        assert!(json.contains("v2"));
        assert!(json.contains("{{ .db_password }}"));
        assert!(json.contains("config.yaml"));

        // Verify round-trip
        let parsed: ExternalSecret = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, secret);
        assert!(parsed.spec.target.template.is_some());

        let template = parsed.spec.target.template.unwrap();
        assert_eq!(template.engine_version, "v2");
        assert_eq!(template.data.len(), 1);
    }

    #[test]
    fn test_external_secret_target_no_template_omits_field() {
        let target = ExternalSecretTarget::new("my-secret");
        let json = serde_json::to_string(&target).unwrap();
        // template should not appear in JSON when None
        assert!(!json.contains("template"));
    }

    #[test]
    fn test_provider_spec_webhook_only() {
        let spec = ProviderSpec {
            webhook: Some(WebhookProvider {
                url: "http://lattice-local-secrets.lattice-system.svc:8787/secret/{{ .remoteRef.key }}".to_string(),
                method: "GET".to_string(),
                result: WebhookResult {
                    json_path: "$".to_string(),
                },
            }),
        };
        let json = serde_json::to_string_pretty(&spec).unwrap();
        assert!(json.contains("webhook"));
        assert!(json.contains("remoteRef.key"));
        assert!(json.contains("jsonPath"));

        let parsed: ProviderSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, spec);
    }

    #[test]
    fn test_webhook_provider_default_method() {
        let json = r#"{"url":"http://example.com","result":{"jsonPath":"$"}}"#;
        let parsed: WebhookProvider = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.method, "GET");
    }

    // =========================================================================
    // Shared Builder Tests
    // =========================================================================

    #[test]
    fn test_build_external_secret_with_keys() {
        let keys = vec!["username".to_string(), "password".to_string()];
        let es = build_external_secret(
            "my-secret",
            "prod",
            "vault-prod",
            "database/prod/creds",
            Some(&keys),
            Some("1h".to_string()),
        );

        assert_eq!(es.metadata.name, "my-secret");
        assert_eq!(es.metadata.namespace, "prod");
        assert_eq!(es.spec.secret_store_ref.name, "vault-prod");
        assert_eq!(es.spec.data.len(), 2);
        assert_eq!(es.spec.data[0].secret_key, "username");
        assert_eq!(es.spec.data[0].remote_ref.key, "database/prod/creds");
        assert_eq!(
            es.spec.data[0].remote_ref.property,
            Some("username".to_string())
        );
        assert!(es.spec.data_from.is_none());
        assert_eq!(es.spec.refresh_interval, Some("1h".to_string()));
    }

    #[test]
    fn test_build_external_secret_without_keys() {
        let es = build_external_secret("my-secret", "prod", "vault", "path/to/secrets", None, None);

        assert!(es.spec.data.is_empty());
        assert!(es.spec.data_from.is_some());
        let data_from = es.spec.data_from.as_ref().unwrap();
        assert_eq!(data_from.len(), 1);
        assert_eq!(
            data_from[0].extract.as_ref().unwrap().key,
            "path/to/secrets"
        );
        assert!(es.spec.refresh_interval.is_none());
    }

    #[test]
    fn test_build_templated_external_secret() {
        let mut template_data = BTreeMap::new();
        template_data.insert(
            "config.yaml".to_string(),
            "password: {{ .creds_password }}".to_string(),
        );

        let refs = vec![FileSecretRef {
            resource_name: "creds".to_string(),
            key: "password".to_string(),
            eso_data_key: "creds_password".to_string(),
        }];

        let es = build_templated_external_secret(
            "my-files",
            "prod",
            "vault",
            "database/prod/creds",
            None,
            template_data,
            &refs,
        )
        .unwrap();

        assert_eq!(es.metadata.name, "my-files");
        assert_eq!(es.spec.data.len(), 1);
        assert_eq!(es.spec.data[0].secret_key, "creds_password");
        assert!(es.spec.target.template.is_some());
        let template = es.spec.target.template.as_ref().unwrap();
        assert!(template.data.contains_key("config.yaml"));
    }

    #[test]
    fn test_build_templated_validates_keys() {
        let mut template_data = BTreeMap::new();
        template_data.insert("key".to_string(), "{{ .creds_badkey }}".to_string());

        let refs = vec![FileSecretRef {
            resource_name: "creds".to_string(),
            key: "badkey".to_string(),
            eso_data_key: "creds_badkey".to_string(),
        }];

        let available = vec!["password".to_string()];
        let result = build_templated_external_secret(
            "my-files",
            "prod",
            "vault",
            "database/prod/creds",
            Some(&available),
            template_data,
            &refs,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("badkey"));
    }

    #[test]
    fn test_build_templated_deduplicates_refs() {
        let mut template_data = BTreeMap::new();
        template_data.insert(
            "config".to_string(),
            "{{ .db_pass }} and {{ .db_pass }}".to_string(),
        );

        let refs = vec![
            FileSecretRef {
                resource_name: "db".to_string(),
                key: "pass".to_string(),
                eso_data_key: "db_pass".to_string(),
            },
            FileSecretRef {
                resource_name: "db".to_string(),
                key: "pass".to_string(),
                eso_data_key: "db_pass".to_string(),
            },
        ];

        let es = build_templated_external_secret(
            "my-files",
            "prod",
            "vault",
            "db/creds",
            None,
            template_data,
            &refs,
        )
        .unwrap();

        // Should deduplicate to 1 data entry
        assert_eq!(es.spec.data.len(), 1);
    }
}
