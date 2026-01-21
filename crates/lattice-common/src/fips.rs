//! FIPS compliance utilities
//!
//! This module provides shared functions for FIPS 140 compliance handling.
//! Production clusters run with `GODEBUG=fips140=only` (strict FIPS),
//! but bootstrap clusters may need `fips140=on` (relaxed FIPS) to communicate
//! with non-FIPS kind clusters.
//!
//! # FIPS Modes
//!
//! - `fips140=only` (default in container): Only FIPS-approved algorithms allowed
//! - `fips140=on`: FIPS mode enabled but fallback to non-FIPS algorithms allowed
//!
//! # When to Relax FIPS
//!
//! - Bootstrap cluster deploying to non-FIPS kind cluster
//! - Kubeadm-based clusters (kubeadm itself may use non-FIPS crypto)
//!
//! # When NOT to Relax FIPS
//!
//! - RKE2-based clusters (RKE2 is FIPS-compliant out of the box)
//! - Production workload clusters
//! - Any cluster where FIPS is required by compliance

/// Add GODEBUG=fips140=on environment variable to a Kubernetes Deployment JSON
///
/// This function parses a deployment manifest, adds the GODEBUG env var to all
/// containers, and returns the modified JSON. Used for bootstrap clusters that
/// need to communicate with non-FIPS API servers.
///
/// # Arguments
///
/// * `deployment_json` - A JSON string representing a Kubernetes Deployment
///
/// # Returns
///
/// The modified deployment JSON with GODEBUG env var added to all containers.
/// If parsing fails, returns the original JSON unchanged.
pub fn add_fips_relax_env(deployment_json: &str) -> String {
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(deployment_json) {
        if let Some(containers) = value
            .pointer_mut("/spec/template/spec/containers")
            .and_then(|c| c.as_array_mut())
        {
            for container in containers {
                let container_obj = match container.as_object_mut() {
                    Some(obj) => obj,
                    None => continue,
                };

                // Get or create env array
                let env = container_obj
                    .entry("env")
                    .or_insert_with(|| serde_json::json!([]))
                    .as_array_mut();

                if let Some(env) = env {
                    // Only add if not already present
                    let has_godebug = env.iter().any(|e| {
                        e.get("name")
                            .and_then(|n| n.as_str())
                            .map(|n| n == "GODEBUG")
                            .unwrap_or(false)
                    });
                    if !has_godebug {
                        env.push(serde_json::json!({
                            "name": "GODEBUG",
                            "value": "fips140=on"
                        }));
                    }
                }
            }
        }
        serde_json::to_string(&value).unwrap_or_else(|_| deployment_json.to_string())
    } else {
        deployment_json.to_string()
    }
}

/// Add LATTICE_ROOT_INSTALL=true environment variable to a Kubernetes Deployment JSON
///
/// This marks the deployment as running during root cluster installation,
/// which skips bootstrap script generation (root clusters don't connect to a parent).
pub fn add_root_install_env(deployment_json: &str) -> String {
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(deployment_json) {
        if let Some(containers) = value
            .pointer_mut("/spec/template/spec/containers")
            .and_then(|c| c.as_array_mut())
        {
            for container in containers {
                let container_obj = match container.as_object_mut() {
                    Some(obj) => obj,
                    None => continue,
                };

                let env = container_obj
                    .entry("env")
                    .or_insert_with(|| serde_json::json!([]))
                    .as_array_mut();

                if let Some(env) = env {
                    let has_root_install = env.iter().any(|e| {
                        e.get("name")
                            .and_then(|n| n.as_str())
                            .map(|n| n == "LATTICE_ROOT_INSTALL")
                            .unwrap_or(false)
                    });
                    if !has_root_install {
                        env.push(serde_json::json!({
                            "name": "LATTICE_ROOT_INSTALL",
                            "value": "true"
                        }));
                    }
                }
            }
        }
        serde_json::to_string(&value).unwrap_or_else(|_| deployment_json.to_string())
    } else {
        deployment_json.to_string()
    }
}

/// Check if a manifest is a Kubernetes Deployment
pub fn is_deployment(manifest: &str) -> bool {
    // Handle different JSON formatting (with or without spaces after colons)
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(manifest) {
        value.get("kind").and_then(|k| k.as_str()) == Some("Deployment")
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_deployment() -> String {
        serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "test-deployment",
                "namespace": "test-ns"
            },
            "spec": {
                "replicas": 1,
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "test",
                            "image": "test:latest",
                            "env": [{
                                "name": "RUST_LOG",
                                "value": "info"
                            }]
                        }]
                    }
                }
            }
        })
        .to_string()
    }

    #[test]
    fn add_fips_relax_env_adds_godebug() {
        let original = sample_deployment();
        let modified = add_fips_relax_env(&original);

        let parsed: serde_json::Value =
            serde_json::from_str(&modified).expect("modified JSON should parse successfully");
        let env = parsed
            .pointer("/spec/template/spec/containers/0/env")
            .expect("env pointer should resolve")
            .as_array()
            .expect("env should be an array");

        let has_godebug = env.iter().any(|e| {
            e.get("name").and_then(|n| n.as_str()) == Some("GODEBUG")
                && e.get("value").and_then(|v| v.as_str()) == Some("fips140=on")
        });
        assert!(has_godebug, "Should have GODEBUG=fips140=on env var");
    }

    #[test]
    fn add_fips_relax_env_does_not_duplicate() {
        // Add once
        let original = sample_deployment();
        let modified = add_fips_relax_env(&original);

        // Try to add again
        let double_modified = add_fips_relax_env(&modified);

        let parsed: serde_json::Value = serde_json::from_str(&double_modified)
            .expect("double modified JSON should parse successfully");
        let env = parsed
            .pointer("/spec/template/spec/containers/0/env")
            .expect("env pointer should resolve")
            .as_array()
            .expect("env should be an array");

        let godebug_count = env
            .iter()
            .filter(|e| e.get("name").and_then(|n| n.as_str()) == Some("GODEBUG"))
            .count();
        assert_eq!(godebug_count, 1, "Should only have one GODEBUG env var");
    }

    #[test]
    fn add_fips_relax_env_handles_invalid_json() {
        let invalid = "not valid json";
        let result = add_fips_relax_env(invalid);
        assert_eq!(result, invalid, "Should return original on parse error");
    }

    #[test]
    fn add_fips_relax_env_handles_non_deployment() {
        let namespace = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "test-ns"
            }
        })
        .to_string();

        let result = add_fips_relax_env(&namespace);
        // Should return unchanged (no containers to modify)
        assert_eq!(result, namespace);
    }

    #[test]
    fn is_deployment_returns_true_for_deployments() {
        let deployment = sample_deployment();
        assert!(is_deployment(&deployment));
    }

    #[test]
    fn is_deployment_returns_false_for_non_deployments() {
        let namespace = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": "test" }
        })
        .to_string();
        assert!(!is_deployment(&namespace));
    }
}
