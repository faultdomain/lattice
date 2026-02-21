//! Registry mirror configuration for CAPI-provisioned nodes.
//!
//! Generates containerd hosts.toml files (kubeadm) or RKE2 registries.yaml
//! so that all image pulls are redirected through private mirrors.

use std::collections::{BTreeMap, HashSet};

use lattice_common::crd::RegistryMirror;

/// A resolved mirror entry with credentials already read from secrets.
#[derive(Clone, Debug)]
pub struct ResolvedMirror {
    /// Upstream registry host (e.g., "docker.io")
    pub upstream: String,
    /// Mirror endpoint host (e.g., "harbor.corp.com")
    pub mirror: String,
    /// Resolved dockerconfigjson content (read from the secret at reconcile time)
    pub credentials: Option<String>,
}

/// Resolve registry mirrors from the CRD spec, expanding `@infra` and `*`.
///
/// Resolution priority (highest to lowest):
/// - Explicit entries (e.g., `upstream: "docker.io"`)
/// - `@infra` — expands to all build-time infrastructure registries not explicitly listed
/// - `*` — catch-all for ANY registry not covered by explicit entries or `@infra`.
///   Emits explicit entries for remaining infra registries AND a `_default` entry
///   that containerd/RKE2 use to catch all unknown registries (essential for air-gapped).
pub fn resolve_mirrors(
    spec_mirrors: &[RegistryMirror],
    resolved_credentials: &std::collections::HashMap<String, String>,
) -> Vec<ResolvedMirror> {
    let mut result: Vec<ResolvedMirror> = Vec::new();
    let mut covered_upstreams: HashSet<String> = HashSet::new();

    let infra_entry = spec_mirrors.iter().find(|m| m.upstream == "@infra");
    let wildcard_entry = spec_mirrors.iter().find(|m| m.upstream == "*");

    // Pass 1: explicit entries (not @infra, not *)
    for mirror in spec_mirrors {
        if mirror.upstream == "@infra" || mirror.upstream == "*" {
            continue;
        }
        covered_upstreams.insert(mirror.upstream.clone());
        let creds = mirror
            .credentials_ref
            .as_ref()
            .and_then(|r| resolved_credentials.get(&r.name))
            .cloned();
        result.push(ResolvedMirror {
            upstream: mirror.upstream.clone(),
            mirror: mirror.mirror.clone(),
            credentials: creds,
        });
    }

    // Pass 2: expand @infra for build-time registries not already covered
    if let Some(infra) = infra_entry {
        let infra_creds = infra
            .credentials_ref
            .as_ref()
            .and_then(|r| resolved_credentials.get(&r.name))
            .cloned();
        for reg in lattice_infra::upstream_registries() {
            if !covered_upstreams.contains(reg) {
                covered_upstreams.insert(reg.to_string());
                result.push(ResolvedMirror {
                    upstream: reg.to_string(),
                    mirror: infra.mirror.clone(),
                    credentials: infra_creds.clone(),
                });
            }
        }
    }

    // Pass 3: * catch-all for ANY registry not already covered
    if let Some(wildcard) = wildcard_entry {
        let wildcard_creds = wildcard
            .credentials_ref
            .as_ref()
            .and_then(|r| resolved_credentials.get(&r.name))
            .cloned();

        // Fill remaining infra registries with explicit entries
        for reg in lattice_infra::upstream_registries() {
            if !covered_upstreams.contains(reg) {
                covered_upstreams.insert(reg.to_string());
                result.push(ResolvedMirror {
                    upstream: reg.to_string(),
                    mirror: wildcard.mirror.clone(),
                    credentials: wildcard_creds.clone(),
                });
            }
        }

        // Emit _default catch-all for all unknown registries (air-gapped support).
        // containerd uses _default as the fallback hosts directory;
        // RKE2 uses "*" as the mirror key — generators handle the mapping.
        result.push(ResolvedMirror {
            upstream: "_default".to_string(),
            mirror: wildcard.mirror.clone(),
            credentials: wildcard_creds,
        });
    }

    result
}

/// Generate containerd hosts.toml files for all resolved mirrors.
///
/// Returns CAPI file entries for `/etc/containerd/certs.d/{registry}/hosts.toml`.
pub fn generate_containerd_mirror_files(mirrors: &[ResolvedMirror]) -> Vec<serde_json::Value> {
    let mut files: Vec<serde_json::Value> = Vec::new();
    let mut creds_written: HashSet<String> = HashSet::new();

    for m in mirrors {
        let content = format!(
            "[host.\"https://{}\"]\n  capabilities = [\"pull\", \"resolve\"]\n",
            m.mirror
        );
        files.push(serde_json::json!({
            "content": content,
            "owner": "root:root",
            "path": format!("/etc/containerd/certs.d/{}/hosts.toml", m.upstream),
            "permissions": "0644"
        }));

        // Write credentials file once per unique mirror that has creds
        if let Some(ref creds) = m.credentials {
            if creds_written.insert(m.mirror.clone()) {
                files.push(serde_json::json!({
                    "content": creds,
                    "owner": "root:root",
                    "path": "/var/lib/kubelet/config.json",
                    "permissions": "0600"
                }));
            }
        }
    }

    files
}

/// Generate preKubeadmCommands to enable containerd mirror config_path + restart.
pub fn generate_containerd_mirror_commands() -> Vec<String> {
    vec![
        r#"sed -i 's|config_path = ""|config_path = "/etc/containerd/certs.d"|' /etc/containerd/config.toml && systemctl restart containerd"#.to_string()
    ]
}

/// Generate RKE2 registries.yaml file entry for mirror config.
pub fn generate_rke2_registries_file(mirrors: &[ResolvedMirror]) -> serde_json::Value {
    // Build the YAML string manually to avoid a serde_yaml dependency.
    let mut yaml = String::from("mirrors:\n");
    for m in mirrors {
        // RKE2 uses "*" for catch-all; containerd uses _default
        let key = if m.upstream == "_default" {
            "*"
        } else {
            &m.upstream
        };
        yaml.push_str(&format!("  \"{}\":\n", key));
        yaml.push_str(&format!(
            "    endpoint:\n      - \"https://{}\"\n",
            m.mirror
        ));
    }

    // Collect unique mirrors with credentials for configs section
    let mut creds_map: BTreeMap<&str, &str> = BTreeMap::new();
    for m in mirrors {
        if let Some(ref creds) = m.credentials {
            creds_map.entry(&m.mirror).or_insert(creds);
        }
    }
    if !creds_map.is_empty() {
        yaml.push_str("configs:\n");
        for (mirror, creds) in &creds_map {
            yaml.push_str(&format!("  \"{}\":\n", mirror));
            yaml.push_str("    auth:\n");
            yaml.push_str(&format!("      identitytoken: \"{}\"\n", creds));
        }
    }

    serde_json::json!({
        "content": yaml,
        "owner": "root:root",
        "path": "/etc/rancher/rke2/registries.yaml",
        "permissions": "0644"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mirror(upstream: &str, mirror_host: &str) -> ResolvedMirror {
        ResolvedMirror {
            upstream: upstream.to_string(),
            mirror: mirror_host.to_string(),
            credentials: None,
        }
    }

    fn mirror_with_creds(upstream: &str, mirror_host: &str, creds: &str) -> ResolvedMirror {
        ResolvedMirror {
            upstream: upstream.to_string(),
            mirror: mirror_host.to_string(),
            credentials: Some(creds.to_string()),
        }
    }

    #[test]
    fn containerd_mirror_files_per_registry() {
        let mirrors = vec![
            mirror("docker.io", "mirror.example.com"),
            mirror("quay.io", "mirror.example.com"),
            mirror("ghcr.io", "mirror.example.com"),
        ];
        let files = generate_containerd_mirror_files(&mirrors);

        assert_eq!(files.len(), 3);
        for (i, m) in mirrors.iter().enumerate() {
            let path = files[i]["path"].as_str().unwrap();
            assert_eq!(
                path,
                format!("/etc/containerd/certs.d/{}/hosts.toml", m.upstream)
            );
            let content = files[i]["content"].as_str().unwrap();
            assert!(content.contains("mirror.example.com"));
            assert!(content.contains("pull"));
            assert!(content.contains("resolve"));
        }
    }

    #[test]
    fn containerd_mirror_files_with_credentials() {
        let mirrors = vec![mirror_with_creds(
            "docker.io",
            "mirror.example.com",
            r#"{"auths":{}}"#,
        )];
        let files = generate_containerd_mirror_files(&mirrors);

        assert_eq!(files.len(), 2);
        // Second file should be kubelet config.json
        assert_eq!(
            files[1]["path"].as_str().unwrap(),
            "/var/lib/kubelet/config.json"
        );
        assert_eq!(files[1]["permissions"].as_str().unwrap(), "0600");
    }

    #[test]
    fn containerd_mirror_files_dedup_credentials() {
        // Two mirrors pointing to same host with same creds should only write config.json once
        let mirrors = vec![
            mirror_with_creds("docker.io", "mirror.example.com", r#"{"auths":{}}"#),
            mirror_with_creds("quay.io", "mirror.example.com", r#"{"auths":{}}"#),
        ];
        let files = generate_containerd_mirror_files(&mirrors);

        // 2 hosts.toml files + 1 config.json (deduped)
        assert_eq!(files.len(), 3);
        let config_json_count = files
            .iter()
            .filter(|f| f["path"].as_str().unwrap() == "/var/lib/kubelet/config.json")
            .count();
        assert_eq!(config_json_count, 1);
    }

    #[test]
    fn containerd_mirror_commands_enable_config_path() {
        let commands = generate_containerd_mirror_commands();
        assert_eq!(commands.len(), 1);
        assert!(commands[0].contains("config_path"));
        assert!(commands[0].contains("/etc/containerd/certs.d"));
        assert!(commands[0].contains("systemctl restart containerd"));
    }

    #[test]
    fn rke2_registries_file_has_mirror_entries() {
        let mirrors = vec![
            mirror("docker.io", "mirror.example.com"),
            mirror("quay.io", "mirror.example.com"),
        ];
        let file = generate_rke2_registries_file(&mirrors);

        assert_eq!(
            file["path"].as_str().unwrap(),
            "/etc/rancher/rke2/registries.yaml"
        );
        let content = file["content"].as_str().unwrap();
        assert!(content.contains("docker.io"));
        assert!(content.contains("quay.io"));
        assert!(content.contains("https://mirror.example.com"));
        assert!(!content.contains("configs:"));
    }

    #[test]
    fn rke2_registries_file_with_credentials() {
        let mirrors = vec![mirror_with_creds(
            "docker.io",
            "mirror.example.com",
            "my-token",
        )];
        let file = generate_rke2_registries_file(&mirrors);

        let content = file["content"].as_str().unwrap();
        assert!(content.contains("configs:"));
        assert!(content.contains("mirror.example.com"));
        assert!(content.contains("my-token"));
    }

    #[test]
    fn no_mirrors_produces_empty_files() {
        let files = generate_containerd_mirror_files(&[]);
        assert!(files.is_empty());
    }

    #[test]
    fn resolve_mirrors_explicit_only_no_expansion() {
        // Explicit entry without @infra or * should only mirror that one registry
        let spec_mirrors = vec![RegistryMirror {
            upstream: "docker.io".to_string(),
            mirror: "harbor.corp.com".to_string(),
            credentials_ref: None,
        }];
        let resolved = resolve_mirrors(&spec_mirrors, &std::collections::HashMap::new());

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].upstream, "docker.io");
        assert_eq!(resolved[0].mirror, "harbor.corp.com");
    }

    #[test]
    fn resolve_mirrors_infra_expands_to_all_infra_registries() {
        let spec_mirrors = vec![RegistryMirror {
            upstream: "@infra".to_string(),
            mirror: "harbor.corp.com".to_string(),
            credentials_ref: None,
        }];
        let resolved = resolve_mirrors(&spec_mirrors, &std::collections::HashMap::new());

        // All build-time infra registries should be covered
        for reg in lattice_infra::upstream_registries() {
            assert!(
                resolved.iter().any(|m| m.upstream == reg),
                "infra registry {} should be covered",
                reg
            );
        }
        // All should use the @infra mirror
        for m in &resolved {
            assert_eq!(m.mirror, "harbor.corp.com");
        }
    }

    #[test]
    fn resolve_mirrors_wildcard_catch_all() {
        let spec_mirrors = vec![RegistryMirror {
            upstream: "*".to_string(),
            mirror: "wildcard-mirror.com".to_string(),
            credentials_ref: None,
        }];
        let resolved = resolve_mirrors(&spec_mirrors, &std::collections::HashMap::new());

        // All entries should use the wildcard mirror
        for m in &resolved {
            assert_eq!(m.mirror, "wildcard-mirror.com");
        }

        // Should have infra registries + _default catch-all
        assert!(
            resolved.iter().any(|m| m.upstream == "_default"),
            "_default catch-all entry must be present for air-gapped"
        );
        for reg in lattice_infra::upstream_registries() {
            assert!(resolved.iter().any(|m| m.upstream == reg));
        }
    }

    #[test]
    fn resolve_mirrors_explicit_overrides_infra() {
        // Explicit docker.io entry should take priority over @infra
        let spec_mirrors = vec![
            RegistryMirror {
                upstream: "docker.io".to_string(),
                mirror: "docker-specific.com".to_string(),
                credentials_ref: None,
            },
            RegistryMirror {
                upstream: "@infra".to_string(),
                mirror: "harbor.corp.com".to_string(),
                credentials_ref: None,
            },
        ];
        let resolved = resolve_mirrors(&spec_mirrors, &std::collections::HashMap::new());

        let docker = resolved.iter().find(|m| m.upstream == "docker.io").unwrap();
        assert_eq!(docker.mirror, "docker-specific.com");

        // Other infra registries should use harbor.corp.com
        for m in &resolved {
            if m.upstream != "docker.io" {
                assert_eq!(m.mirror, "harbor.corp.com");
            }
        }
    }

    #[test]
    fn resolve_mirrors_infra_overrides_wildcard() {
        // @infra should take priority over * for infra registries
        let spec_mirrors = vec![
            RegistryMirror {
                upstream: "@infra".to_string(),
                mirror: "infra-mirror.com".to_string(),
                credentials_ref: None,
            },
            RegistryMirror {
                upstream: "*".to_string(),
                mirror: "wildcard-mirror.com".to_string(),
                credentials_ref: None,
            },
        ];
        let resolved = resolve_mirrors(&spec_mirrors, &std::collections::HashMap::new());

        // Infra registries should use infra-mirror.com (not wildcard)
        for m in &resolved {
            if m.upstream == "_default" {
                assert_eq!(m.mirror, "wildcard-mirror.com");
            } else {
                assert_eq!(m.mirror, "infra-mirror.com");
            }
        }

        // _default catch-all should still be present from *
        assert!(resolved.iter().any(|m| m.upstream == "_default"));
    }

    #[test]
    fn resolve_mirrors_credentials_propagation() {
        use lattice_common::crd::SecretRef;

        let spec_mirrors = vec![
            RegistryMirror {
                upstream: "docker.io".to_string(),
                mirror: "harbor.corp.com".to_string(),
                credentials_ref: Some(SecretRef {
                    name: "harbor-creds".to_string(),
                    namespace: "lattice-system".to_string(),
                }),
            },
            RegistryMirror {
                upstream: "*".to_string(),
                mirror: "default-mirror.com".to_string(),
                credentials_ref: None,
            },
        ];

        let mut creds_map = std::collections::HashMap::new();
        creds_map.insert(
            "harbor-creds".to_string(),
            r#"{"auths":{"harbor.corp.com":{}}}"#.to_string(),
        );

        let resolved = resolve_mirrors(&spec_mirrors, &creds_map);

        // docker.io should use harbor.corp.com with credentials
        let docker_mirror = resolved.iter().find(|m| m.upstream == "docker.io").unwrap();
        assert_eq!(docker_mirror.mirror, "harbor.corp.com");
        assert!(docker_mirror.credentials.is_some());

        // Other entries (infra + _default catch-all) should use default-mirror.com
        for m in &resolved {
            if m.upstream != "docker.io" {
                assert_eq!(m.mirror, "default-mirror.com");
                assert!(m.credentials.is_none());
            }
        }
        assert!(resolved.iter().any(|m| m.upstream == "_default"));
    }

    #[test]
    fn resolve_mirrors_empty_returns_empty() {
        let resolved = resolve_mirrors(&[], &std::collections::HashMap::new());
        assert!(resolved.is_empty());
    }
}
