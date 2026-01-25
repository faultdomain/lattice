//! External Secrets Operator (ESO) manifest generation
//!
//! Generates ESO manifests for secret synchronization from external providers.

use tokio::process::Command;
use tracing::debug;

use super::{charts_dir, find_chart, inject_namespace, namespace_yaml, split_yaml_documents};

/// Generate ESO manifests using helm template
pub async fn generate_eso() -> Result<Vec<String>, String> {
    let charts_dir = charts_dir();
    let chart_path = find_chart(&charts_dir, "external-secrets")?;

    let output = Command::new("helm")
        .args([
            "template",
            "external-secrets",
            &chart_path,
            "--namespace",
            "external-secrets",
            "--set",
            "installCRDs=true",
        ])
        .output()
        .await
        .map_err(|e| format!("helm: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let yaml = String::from_utf8_lossy(&output.stdout);
    let mut manifests = vec![namespace_yaml("external-secrets")];
    for m in split_yaml_documents(&yaml) {
        manifests.push(inject_namespace(&m, "external-secrets"));
    }

    debug!(count = manifests.len(), "generated ESO manifests");
    Ok(manifests)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_is_first_manifest() {
        let ns = namespace_yaml("external-secrets");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: external-secrets"));
    }
}
