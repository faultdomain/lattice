//! File mount compilation
//!
//! Compiles rendered file mounts into Kubernetes resources with three-way routing:
//! - Text content (no secret refs) → ConfigMap
//! - Binary content → K8s Secret
//! - Text content with `${secret.*}` refs → ESO ExternalSecret with template

use std::collections::{BTreeMap, HashSet};

use lattice_common::template::{FileSecretRef, RenderedFile};
use lattice_secret_provider::{
    ExternalSecret, ExternalSecretData, ExternalSecretSpec, ExternalSecretTarget,
    ExternalSecretTemplate, RemoteRef, SecretStoreRef,
};

use super::error::CompilationError;
use super::secrets::SecretRef;
use super::{ConfigMap, ConfigMapVolumeSource, Secret, SecretVolumeSource, Volume, VolumeMount};

/// Result of compiling file mounts
#[derive(Debug, Default)]
pub struct CompiledFiles {
    /// ConfigMap for text file content without secret refs (if any)
    pub config_map: Option<ConfigMap>,
    /// Secret for binary file content (if any)
    pub secret: Option<Secret>,
    /// ESO ExternalSecrets for files containing `${secret.*}` references
    pub file_external_secrets: Vec<ExternalSecret>,
    /// Volumes to add to the pod spec
    pub volumes: Vec<Volume>,
    /// Volume mounts for the container
    pub volume_mounts: Vec<VolumeMount>,
}

/// Compile rendered file mounts into ConfigMap/Secret/ExternalSecret + Volume/VolumeMount
///
/// Routes files based on content type and secret references:
/// 1. Text content, no secret refs → ConfigMap (`{service}-{container}-files`)
/// 2. Binary content → K8s Secret (`{service}-{container}-files-bin`)
/// 3. Text content with secret refs → ESO ExternalSecret with `spec.target.template`
pub fn compile(
    service_name: &str,
    container_name: &str,
    namespace: &str,
    files: &BTreeMap<String, RenderedFile>,
    secret_refs: &BTreeMap<String, SecretRef>,
) -> Result<CompiledFiles, CompilationError> {
    let mut text_files: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut binary_files: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut secret_files: BTreeMap<String, (String, String, Vec<FileSecretRef>)> = BTreeMap::new();
    let mut seen_keys: HashSet<String> = HashSet::new();

    for (path, file) in files {
        let key = path_to_key(path);
        if !seen_keys.insert(key.clone()) {
            return Err(CompilationError::file_compilation(format!(
                "file path '{}' produces key '{}' which collides with another path \
                 (paths differing only by '/', '.', or '-' will collide)",
                path, key
            )));
        }

        if let Some(ref content) = file.content {
            if file.secret_refs.is_empty() {
                text_files.insert(key, (content.clone(), path.to_string()));
            } else {
                secret_files.insert(
                    key,
                    (content.clone(), path.to_string(), file.secret_refs.clone()),
                );
            }
        } else if let Some(ref binary) = file.binary_content {
            binary_files.insert(key, (binary.clone(), path.to_string()));
        }
        // source files are handled differently (mounted from external sources)
    }

    let mut result = CompiledFiles::default();
    let base_name = format!("{}-{}", service_name, container_name);

    compile_text_files(&base_name, namespace, &text_files, &mut result);
    compile_binary_files(&base_name, namespace, &binary_files, &mut result);
    compile_secret_files(
        &base_name,
        namespace,
        &secret_files,
        secret_refs,
        &mut result,
    )?;

    Ok(result)
}

/// Compile text files (no secret refs) into a ConfigMap + volumes
fn compile_text_files(
    base_name: &str,
    namespace: &str,
    text_files: &BTreeMap<String, (String, String)>,
    result: &mut CompiledFiles,
) {
    if text_files.is_empty() {
        return;
    }

    let cm_name = format!("{}-files", base_name);
    let vol_name = cm_name.clone();
    let mut cm = ConfigMap::new(&cm_name, namespace);

    for (key, (content, _)) in text_files {
        cm.data.insert(key.clone(), content.clone());
    }

    result.config_map = Some(cm);
    result.volumes.push(Volume {
        name: vol_name.clone(),
        config_map: Some(ConfigMapVolumeSource { name: cm_name }),
        secret: None,
        empty_dir: None,
        persistent_volume_claim: None,
    });

    for (key, (_, mount_path)) in text_files {
        result.volume_mounts.push(VolumeMount {
            name: vol_name.clone(),
            mount_path: mount_path.clone(),
            sub_path: Some(key.clone()),
            read_only: Some(true),
        });
    }
}

/// Compile binary files into a K8s Secret + volumes
fn compile_binary_files(
    base_name: &str,
    namespace: &str,
    binary_files: &BTreeMap<String, (String, String)>,
    result: &mut CompiledFiles,
) {
    if binary_files.is_empty() {
        return;
    }

    let secret_name = format!("{}-files-bin", base_name);
    let vol_name = secret_name.clone();
    let mut secret = Secret::new(&secret_name, namespace);

    for (key, (content, _)) in binary_files {
        secret.string_data.insert(key.clone(), content.clone());
    }

    result.secret = Some(secret);
    result.volumes.push(Volume {
        name: vol_name.clone(),
        config_map: None,
        secret: Some(SecretVolumeSource { secret_name }),
        empty_dir: None,
        persistent_volume_claim: None,
    });

    for (key, (_, mount_path)) in binary_files {
        result.volume_mounts.push(VolumeMount {
            name: vol_name.clone(),
            mount_path: mount_path.clone(),
            sub_path: Some(key.clone()),
            read_only: Some(true),
        });
    }
}

/// Compile files with `${secret.*}` refs into ESO ExternalSecrets + volumes.
///
/// Each secret file gets its own ExternalSecret. A single file's secret refs must
/// all come from the same ClusterSecretStore (validated here), but different files
/// may use different stores.
fn compile_secret_files(
    base_name: &str,
    namespace: &str,
    secret_files: &BTreeMap<String, (String, String, Vec<FileSecretRef>)>,
    secret_refs: &BTreeMap<String, SecretRef>,
    result: &mut CompiledFiles,
) -> Result<(), CompilationError> {
    for (key, (content, mount_path, file_refs)) in secret_files {
        let store = resolve_store_for_refs(file_refs, secret_refs, &format!("file '{}'", key))?;

        let es_name = format!("{}-file-{}", base_name, key);
        let vol_name = es_name.clone();

        let mut eso_data: Vec<ExternalSecretData> = Vec::new();
        let mut seen_eso_keys = std::collections::HashSet::new();

        for fref in file_refs {
            if !seen_eso_keys.insert(fref.eso_data_key.clone()) {
                continue;
            }

            let sr = secret_refs.get(&fref.resource_name).ok_or_else(|| {
                CompilationError::file_compilation(format!(
                    "file '{}' references secret resource '{}' but no SecretRef was compiled \
                     (is it declared as a type: secret resource?)",
                    key, fref.resource_name
                ))
            })?;

            if let Some(ref keys) = sr.keys {
                if !keys.contains(&fref.key) {
                    return Err(CompilationError::file_compilation(format!(
                        "file '{}' references key '{}' in secret '{}' but available keys are: {:?}",
                        key, fref.key, fref.resource_name, keys
                    )));
                }
            }

            eso_data.push(ExternalSecretData::new(
                &fref.eso_data_key,
                RemoteRef::with_property(&sr.remote_key, &fref.key),
            ));
        }

        let mut template_data = BTreeMap::new();
        template_data.insert(key.clone(), content.clone());

        let external_secret = ExternalSecret::new(
            &es_name,
            namespace,
            ExternalSecretSpec {
                secret_store_ref: SecretStoreRef::cluster_secret_store(&store),
                target: ExternalSecretTarget::with_template(
                    &es_name,
                    ExternalSecretTemplate::new(template_data),
                ),
                data: eso_data,
                data_from: None,
                refresh_interval: Some("1h".to_string()),
            },
        );

        result.file_external_secrets.push(external_secret);

        result.volumes.push(Volume {
            name: vol_name.clone(),
            config_map: None,
            secret: Some(SecretVolumeSource {
                secret_name: es_name,
            }),
            empty_dir: None,
            persistent_volume_claim: None,
        });

        result.volume_mounts.push(VolumeMount {
            name: vol_name,
            mount_path: mount_path.clone(),
            sub_path: Some(key.clone()),
            read_only: Some(true),
        });
    }

    Ok(())
}

/// Resolve and validate the store for a set of secret refs.
///
/// All refs must come from the same ClusterSecretStore. Returns an error
/// if refs span multiple stores.
fn resolve_store_for_refs(
    refs: &[FileSecretRef],
    secret_refs: &BTreeMap<String, SecretRef>,
    context: &str,
) -> Result<String, CompilationError> {
    let mut store: Option<String> = None;

    for fref in refs {
        let sr = secret_refs.get(&fref.resource_name).ok_or_else(|| {
            CompilationError::file_compilation(format!(
                "{} references secret resource '{}' but no SecretRef was compiled",
                context, fref.resource_name
            ))
        })?;

        match &store {
            None => store = Some(sr.store_name.clone()),
            Some(existing) if existing != &sr.store_name => {
                return Err(CompilationError::file_compilation(format!(
                    "{} references secrets from multiple stores ('{}' and '{}'); \
                     a single file or env var can only use one store",
                    context, existing, sr.store_name
                )));
            }
            Some(_) => {} // Same store, OK
        }
    }

    store.ok_or_else(|| {
        CompilationError::file_compilation(format!("{} has no secret references", context))
    })
}

/// Convert a file path to a valid ConfigMap/Secret key
fn path_to_key(path: &str) -> String {
    path.trim_start_matches('/')
        .chars()
        .map(|c| if c == '/' || c == '.' { '-' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_secret_refs() -> BTreeMap<String, SecretRef> {
        BTreeMap::new()
    }

    #[test]
    fn test_compile_text_files() {
        let mut files = BTreeMap::new();
        files.insert(
            "/etc/app/config.yaml".to_string(),
            RenderedFile {
                content: Some("key: value".to_string()),
                binary_content: None,
                source: None,
                mode: Some("0644".to_string()),
                secret_refs: vec![],
            },
        );

        let result = compile("api", "main", "prod", &files, &empty_secret_refs()).unwrap();

        assert!(result.config_map.is_some());
        assert!(result.secret.is_none());
        assert!(result.file_external_secrets.is_empty());

        let cm = result.config_map.expect("config_map should be set");
        assert_eq!(cm.metadata.name, "api-main-files");

        assert_eq!(result.volumes.len(), 1);
        assert_eq!(result.volume_mounts.len(), 1);
        assert_eq!(result.volume_mounts[0].mount_path, "/etc/app/config.yaml");
    }

    #[test]
    fn test_compile_binary_files() {
        let mut files = BTreeMap::new();
        files.insert(
            "/etc/app/cert.pem".to_string(),
            RenderedFile {
                content: None,
                binary_content: Some("base64encodedcontent".to_string()),
                source: None,
                mode: Some("0600".to_string()),
                secret_refs: vec![],
            },
        );

        let result = compile("api", "main", "prod", &files, &empty_secret_refs()).unwrap();

        assert!(result.config_map.is_none());
        assert!(result.secret.is_some());
        assert!(result.file_external_secrets.is_empty());

        let secret = result.secret.expect("secret should be set");
        assert_eq!(secret.metadata.name, "api-main-files-bin");

        assert_eq!(result.volumes.len(), 1);
        assert_eq!(result.volume_mounts.len(), 1);
    }

    #[test]
    fn test_compile_mixed_files() {
        let mut files = BTreeMap::new();
        files.insert(
            "/etc/config.yaml".to_string(),
            RenderedFile {
                content: Some("config: true".to_string()),
                binary_content: None,
                source: None,
                mode: None,
                secret_refs: vec![],
            },
        );
        files.insert(
            "/etc/secret.bin".to_string(),
            RenderedFile {
                content: None,
                binary_content: Some("binary".to_string()),
                source: None,
                mode: None,
                secret_refs: vec![],
            },
        );

        let result = compile("api", "main", "prod", &files, &empty_secret_refs()).unwrap();

        assert!(result.config_map.is_some());
        assert!(result.secret.is_some());
        assert_eq!(result.volumes.len(), 2);
        assert_eq!(result.volume_mounts.len(), 2);
    }

    #[test]
    fn test_compile_files_with_secret_refs() {
        let mut files = BTreeMap::new();
        files.insert(
            "/etc/app/config.yaml".to_string(),
            RenderedFile {
                content: Some("password: {{ .db_creds_password }}".to_string()),
                binary_content: None,
                source: None,
                mode: None,
                secret_refs: vec![FileSecretRef {
                    resource_name: "db-creds".to_string(),
                    key: "password".to_string(),
                    eso_data_key: "db_creds_password".to_string(),
                }],
            },
        );

        let mut secret_refs = BTreeMap::new();
        secret_refs.insert(
            "db-creds".to_string(),
            SecretRef {
                secret_name: "myapp-db-creds".to_string(),
                remote_key: "database/prod/credentials".to_string(),
                keys: Some(vec!["username".to_string(), "password".to_string()]),
                store_name: "vault".to_string(),
            },
        );

        let result = compile("api", "main", "prod", &files, &secret_refs).unwrap();

        // Should NOT create a plain ConfigMap (it has secret refs)
        assert!(result.config_map.is_none());
        assert!(result.secret.is_none());

        // Should create an ESO ExternalSecret
        assert_eq!(result.file_external_secrets.len(), 1);

        let es = &result.file_external_secrets[0];
        assert_eq!(es.metadata.name, "api-main-file-etc-app-config-yaml");
        assert_eq!(es.metadata.namespace, "prod");

        // Should have template data
        let template = es
            .spec
            .target
            .template
            .as_ref()
            .expect("should have template");
        assert!(template.data.contains_key("etc-app-config-yaml"));

        // Should have data entry for fetching the secret
        assert_eq!(es.spec.data.len(), 1);
        assert_eq!(es.spec.data[0].secret_key, "db_creds_password");

        // Should have volume and mount pointing at the ESO-created secret
        assert_eq!(result.volumes.len(), 1);
        assert_eq!(result.volume_mounts.len(), 1);
    }

    #[test]
    fn test_compile_secret_files_missing_ref() {
        let mut files = BTreeMap::new();
        files.insert(
            "/etc/config.yaml".to_string(),
            RenderedFile {
                content: Some("{{ .db_pass }}".to_string()),
                binary_content: None,
                source: None,
                mode: None,
                secret_refs: vec![FileSecretRef {
                    resource_name: "nonexistent".to_string(),
                    key: "pass".to_string(),
                    eso_data_key: "nonexistent_pass".to_string(),
                }],
            },
        );

        let result = compile("api", "main", "prod", &files, &empty_secret_refs());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonexistent"));
    }

    #[test]
    fn test_compile_secret_files_invalid_key() {
        let mut files = BTreeMap::new();
        files.insert(
            "/etc/config.yaml".to_string(),
            RenderedFile {
                content: Some("{{ .db_badkey }}".to_string()),
                binary_content: None,
                source: None,
                mode: None,
                secret_refs: vec![FileSecretRef {
                    resource_name: "db".to_string(),
                    key: "badkey".to_string(),
                    eso_data_key: "db_badkey".to_string(),
                }],
            },
        );

        let mut secret_refs = BTreeMap::new();
        secret_refs.insert(
            "db".to_string(),
            SecretRef {
                secret_name: "myapp-db".to_string(),
                remote_key: "database/prod/db".to_string(),
                keys: Some(vec!["password".to_string()]),
                store_name: "vault".to_string(),
            },
        );

        let result = compile("api", "main", "prod", &files, &secret_refs);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("badkey"));
    }

    #[test]
    fn test_path_key_collision_error() {
        let mut files = BTreeMap::new();
        files.insert(
            "/a/b".to_string(),
            RenderedFile {
                content: Some("first".to_string()),
                binary_content: None,
                source: None,
                mode: None,
                secret_refs: vec![],
            },
        );
        files.insert(
            "/a-b".to_string(),
            RenderedFile {
                content: Some("second".to_string()),
                binary_content: None,
                source: None,
                mode: None,
                secret_refs: vec![],
            },
        );

        let result = compile("api", "main", "prod", &files, &empty_secret_refs());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("collides"),
            "error should mention collision: {}",
            err
        );
    }

    #[test]
    fn test_path_key_no_collision() {
        let mut files = BTreeMap::new();
        files.insert(
            "/etc/config.yaml".to_string(),
            RenderedFile {
                content: Some("config1".to_string()),
                binary_content: None,
                source: None,
                mode: None,
                secret_refs: vec![],
            },
        );
        files.insert(
            "/var/data.txt".to_string(),
            RenderedFile {
                content: Some("config2".to_string()),
                binary_content: None,
                source: None,
                mode: None,
                secret_refs: vec![],
            },
        );

        let result = compile("api", "main", "prod", &files, &empty_secret_refs());
        assert!(result.is_ok());
    }

    #[test]
    fn test_path_to_key() {
        assert_eq!(path_to_key("/etc/app/config.yaml"), "etc-app-config-yaml");
        assert_eq!(path_to_key("file.txt"), "file-txt");
        assert_eq!(path_to_key("/a/b/c"), "a-b-c");
    }

    #[test]
    fn test_compile_empty() {
        let files = BTreeMap::new();

        let result = compile("api", "main", "prod", &files, &empty_secret_refs()).unwrap();

        assert!(result.config_map.is_none());
        assert!(result.secret.is_none());
        assert!(result.file_external_secrets.is_empty());
        assert!(result.volumes.is_empty());
        assert!(result.volume_mounts.is_empty());
    }

    #[test]
    fn test_compile_all_three_types() {
        let mut files = BTreeMap::new();
        // Text file (no secrets)
        files.insert(
            "/etc/plain.conf".to_string(),
            RenderedFile {
                content: Some("plain config".to_string()),
                binary_content: None,
                source: None,
                mode: None,
                secret_refs: vec![],
            },
        );
        // Binary file
        files.insert(
            "/etc/cert.pem".to_string(),
            RenderedFile {
                content: None,
                binary_content: Some("base64data".to_string()),
                source: None,
                mode: None,
                secret_refs: vec![],
            },
        );
        // Secret file
        files.insert(
            "/etc/secret.conf".to_string(),
            RenderedFile {
                content: Some("pass={{ .db_pass }}".to_string()),
                binary_content: None,
                source: None,
                mode: None,
                secret_refs: vec![FileSecretRef {
                    resource_name: "db".to_string(),
                    key: "pass".to_string(),
                    eso_data_key: "db_pass".to_string(),
                }],
            },
        );

        let mut secret_refs = BTreeMap::new();
        secret_refs.insert(
            "db".to_string(),
            SecretRef {
                secret_name: "myapp-db".to_string(),
                remote_key: "database/prod/db".to_string(),
                keys: None,
                store_name: "vault".to_string(),
            },
        );

        let result = compile("api", "main", "prod", &files, &secret_refs).unwrap();

        assert!(result.config_map.is_some());
        assert!(result.secret.is_some());
        assert_eq!(result.file_external_secrets.len(), 1);
        assert_eq!(result.volumes.len(), 3);
        assert_eq!(result.volume_mounts.len(), 3);
    }
}
