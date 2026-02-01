//! External Secrets Operator (ESO) manifest generation
//!
//! Generates ESO manifests for secret synchronization from external providers.

use tokio::sync::OnceCell;
use tracing::info;

use super::{charts_dir, namespace_yaml, run_helm_template};

/// Cached ESO manifests to avoid repeated helm template calls
static ESO_MANIFESTS: OnceCell<Result<Vec<String>, String>> = OnceCell::const_new();

/// ESO version (pinned at build time)
pub fn eso_version() -> &'static str {
    env!("EXTERNAL_SECRETS_VERSION")
}

/// Generate ESO manifests using helm template
///
/// Renders via `helm template` on-demand with caching. The first call executes helm
/// and caches the result; subsequent calls return the cached manifests.
pub async fn generate_eso() -> Result<Vec<String>, String> {
    ESO_MANIFESTS
        .get_or_init(|| async { render_eso_helm().await })
        .await
        .clone()
}

/// Internal function to render ESO manifests via helm template
async fn render_eso_helm() -> Result<Vec<String>, String> {
    let version = eso_version();
    let charts = charts_dir();
    let chart_path = format!("{}/external-secrets-{}.tgz", charts, version);

    info!(version, "Rendering ESO chart");

    let helm_manifests = run_helm_template(
        "external-secrets",
        &chart_path,
        "external-secrets",
        &["--set", "installCRDs=true"],
    )
    .await?;

    let mut manifests = vec![namespace_yaml("external-secrets")];
    manifests.extend(helm_manifests);

    info!(count = manifests.len(), "Rendered ESO manifests");
    Ok(manifests)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_set() {
        let version = eso_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn namespace_is_correct() {
        let ns = namespace_yaml("external-secrets");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: external-secrets"));
    }
}
