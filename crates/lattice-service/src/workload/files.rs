//! File mount compilation
//!
//! Compiles rendered file mounts into ConfigMap (text content)
//! and Secret (binary content) resources, plus Volume/VolumeMount definitions.

use std::collections::BTreeMap;

use lattice_common::template::RenderedFile;

use super::{ConfigMap, ConfigMapVolumeSource, Secret, SecretVolumeSource, Volume, VolumeMount};

/// Result of compiling file mounts
#[derive(Debug, Default)]
pub struct CompiledFiles {
    /// ConfigMap for text file content (if any)
    pub config_map: Option<ConfigMap>,
    /// Secret for binary file content (if any)
    pub secret: Option<Secret>,
    /// Volumes to add to the pod spec
    pub volumes: Vec<Volume>,
    /// Volume mounts for the container
    pub volume_mounts: Vec<VolumeMount>,
}

/// Compile rendered file mounts into ConfigMap/Secret and Volume/VolumeMount
///
/// Routes files based on content type:
/// - Text content -> ConfigMap
/// - Binary content -> Secret
pub fn compile(
    service_name: &str,
    namespace: &str,
    files: &BTreeMap<String, RenderedFile>,
) -> CompiledFiles {
    let mut text_files: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut binary_files: BTreeMap<String, (String, String)> = BTreeMap::new();

    for (path, file) in files {
        // Generate a safe key from the path
        let key = path_to_key(path);

        if let Some(ref content) = file.content {
            text_files.insert(key, (content.clone(), path.to_string()));
        } else if let Some(ref binary) = file.binary_content {
            binary_files.insert(key, (binary.clone(), path.to_string()));
        }
        // source files are handled differently (mounted from external sources)
    }

    let mut result = CompiledFiles::default();

    // Create ConfigMap for text files
    if !text_files.is_empty() {
        let cm_name = format!("{}-files", service_name);
        let mut cm = ConfigMap::new(&cm_name, namespace);

        for (key, (content, _)) in &text_files {
            cm.data.insert(key.clone(), content.clone());
        }

        result.config_map = Some(cm.clone());

        // Create volume
        result.volumes.push(Volume {
            name: format!("{}-files", service_name),
            config_map: Some(ConfigMapVolumeSource {
                name: cm_name.clone(),
            }),
            secret: None,
            empty_dir: None,
            persistent_volume_claim: None,
        });

        // Create volume mounts for each file
        for (key, (_, mount_path)) in &text_files {
            result.volume_mounts.push(VolumeMount {
                name: format!("{}-files", service_name),
                mount_path: mount_path.clone(),
                sub_path: Some(key.clone()),
                read_only: Some(true),
            });
        }
    }

    // Create Secret for binary files
    if !binary_files.is_empty() {
        let secret_name = format!("{}-files-bin", service_name);
        let mut secret = Secret::new(&secret_name, namespace);

        for (key, (content, _)) in &binary_files {
            // Binary content is already base64 encoded
            secret.string_data.insert(key.clone(), content.clone());
        }

        result.secret = Some(secret);

        // Create volume
        result.volumes.push(Volume {
            name: format!("{}-files-bin", service_name),
            config_map: None,
            secret: Some(SecretVolumeSource {
                secret_name: secret_name.clone(),
            }),
            empty_dir: None,
            persistent_volume_claim: None,
        });

        // Create volume mounts for each file
        for (key, (_, mount_path)) in &binary_files {
            result.volume_mounts.push(VolumeMount {
                name: format!("{}-files-bin", service_name),
                mount_path: mount_path.clone(),
                sub_path: Some(key.clone()),
                read_only: Some(true),
            });
        }
    }

    result
}

/// Convert a file path to a valid ConfigMap/Secret key
fn path_to_key(path: &str) -> String {
    // Remove leading slash and replace slashes/dots with dashes
    path.trim_start_matches('/')
        .chars()
        .map(|c| if c == '/' || c == '.' { '-' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
            },
        );

        let result = compile("api", "prod", &files);

        // Should create ConfigMap
        assert!(result.config_map.is_some());
        assert!(result.secret.is_none());

        let cm = result.config_map.expect("config_map should be set");
        assert_eq!(cm.metadata.name, "api-files");

        // Should have volume and volume mount
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
            },
        );

        let result = compile("api", "prod", &files);

        // Should create Secret
        assert!(result.config_map.is_none());
        assert!(result.secret.is_some());

        let secret = result.secret.expect("secret should be set");
        assert_eq!(secret.metadata.name, "api-files-bin");

        // Should have volume and volume mount
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
            },
        );
        files.insert(
            "/etc/secret.bin".to_string(),
            RenderedFile {
                content: None,
                binary_content: Some("binary".to_string()),
                source: None,
                mode: None,
            },
        );

        let result = compile("api", "prod", &files);

        // Should create both
        assert!(result.config_map.is_some());
        assert!(result.secret.is_some());

        // Should have two volumes and two mounts
        assert_eq!(result.volumes.len(), 2);
        assert_eq!(result.volume_mounts.len(), 2);
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

        let result = compile("api", "prod", &files);

        assert!(result.config_map.is_none());
        assert!(result.secret.is_none());
        assert!(result.volumes.is_empty());
        assert!(result.volume_mounts.is_empty());
    }
}
