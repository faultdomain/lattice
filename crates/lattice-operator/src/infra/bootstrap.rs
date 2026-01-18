//! Infrastructure manifest generation
//!
//! Single source of truth for ALL infrastructure manifests. Used by:
//! - Bootstrap webhook: pre-installs everything in parallel with operator
//! - Operator startup: re-applies (idempotent via server-side apply)
//!
//! Server-side apply handles idempotency - no need to check if installed.

use std::process::Command;
use tracing::{debug, info, warn};

use super::{FluxReconciler, IstioReconciler, KgatewayReconciler};
use crate::crd::BootstrapProvider;

/// Configuration for infrastructure manifest generation
#[derive(Debug, Clone)]
pub struct InfrastructureConfig {
    /// Infrastructure provider type (docker, proxmox, aws, etc.)
    pub provider: String,
    /// Bootstrap mechanism (kubeadm or rke2)
    pub bootstrap: BootstrapProvider,
    /// Skip Cilium policies (true for kind/bootstrap clusters without Cilium)
    pub skip_cilium_policies: bool,
}

/// Generate ALL infrastructure manifests for a self-managing cluster
///
/// Includes: cert-manager, CAPI, Istio, Flux, kgateway
pub fn generate_all(config: &InfrastructureConfig) -> Vec<String> {
    let mut manifests = Vec::new();

    // cert-manager (CAPI prerequisite)
    if let Ok(cm) = generate_certmanager() {
        debug!(count = cm.len(), "generated cert-manager manifests");
        manifests.extend(cm);
    } else {
        warn!("failed to generate cert-manager manifests");
    }

    // CAPI providers
    if let Ok(capi) = generate_capi(&config.provider, &config.bootstrap) {
        debug!(count = capi.len(), "generated CAPI manifests");
        manifests.extend(capi);
    } else {
        warn!("failed to generate CAPI manifests");
    }

    // Istio ambient
    manifests.extend(generate_istio(config.skip_cilium_policies));

    // Flux
    manifests.extend(generate_flux());

    // kgateway
    manifests.extend(generate_kgateway());

    info!(total = manifests.len(), "generated infrastructure manifests");
    manifests
}

/// Generate cert-manager manifests
pub fn generate_certmanager() -> Result<Vec<String>, String> {
    let charts_dir = charts_dir();
    let chart_path = find_chart(&charts_dir, "cert-manager")?;

    let output = Command::new("helm")
        .args([
            "template",
            "cert-manager",
            &chart_path,
            "--namespace",
            "cert-manager",
            "--set",
            "crds.enabled=true",
        ])
        .output()
        .map_err(|e| format!("helm: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    let yaml = String::from_utf8_lossy(&output.stdout);
    let mut manifests = vec![namespace_yaml("cert-manager")];
    manifests.extend(split_yaml(&yaml));
    Ok(manifests)
}

/// Generate CAPI provider manifests
pub fn generate_capi(provider: &str, _bootstrap: &BootstrapProvider) -> Result<Vec<String>, String> {
    let infra = match provider.to_lowercase().as_str() {
        "docker" => "docker",
        "proxmox" => "proxmox",
        "aws" => "aws",
        "gcp" => "gcp",
        "azure" => "azure",
        p => return Err(format!("unknown provider: {}", p)),
    };

    // Always include both kubeadm and rke2 for clusterctl move compatibility
    let output = Command::new("clusterctl")
        .args([
            "generate",
            "provider",
            "--infrastructure",
            infra,
            "--bootstrap",
            "kubeadm,rke2",
            "--control-plane",
            "kubeadm,rke2",
        ])
        .output()
        .map_err(|e| format!("clusterctl: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    Ok(split_yaml(&String::from_utf8_lossy(&output.stdout)))
}

/// Generate Istio manifests
pub fn generate_istio(skip_cilium_policies: bool) -> Vec<String> {
    let mut manifests = vec![namespace_yaml("istio-system")];

    let reconciler = IstioReconciler::new();
    if let Ok(istio) = reconciler.manifests() {
        manifests.extend(istio.iter().cloned());
    }

    // Istio policies
    manifests.push(IstioReconciler::generate_peer_authentication());
    manifests.push(IstioReconciler::generate_default_deny());
    manifests.push(IstioReconciler::generate_operator_allow_policy());

    // Cilium policies (skip on kind/bootstrap clusters)
    if !skip_cilium_policies {
        manifests.push(super::generate_ztunnel_allowlist());
        manifests.push(super::generate_default_deny());
    }

    manifests
}

/// Generate Flux manifests including allow policy
pub fn generate_flux() -> Vec<String> {
    let mut manifests = match FluxReconciler::new() {
        Ok(r) => r.manifests().to_vec(),
        Err(e) => {
            warn!(error = %e, "failed to create Flux reconciler");
            vec![]
        }
    };
    // Add Istio allow policy for Flux
    manifests.push(generate_flux_allow_policy());
    manifests
}

/// Generate kgateway manifests including allow policy
pub fn generate_kgateway() -> Vec<String> {
    let reconciler = KgatewayReconciler::new();
    let mut manifests = match reconciler.manifests() {
        Ok(m) => m.to_vec(),
        Err(e) => {
            warn!(error = %e, "failed to generate kgateway manifests");
            vec![]
        }
    };
    // Add Istio allow policy for kgateway
    manifests.push(generate_kgateway_allow_policy());
    manifests
}

fn generate_flux_allow_policy() -> String {
    r#"apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: flux-allow-all
  namespace: flux-system
  labels:
    app.kubernetes.io/managed-by: lattice
spec:
  action: ALLOW
  rules:
  - {}"#
        .to_string()
}

fn generate_kgateway_allow_policy() -> String {
    r#"apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: kgateway-allow-all
  namespace: kgateway-system
  labels:
    app.kubernetes.io/managed-by: lattice
spec:
  action: ALLOW
  rules:
  - {}"#
        .to_string()
}

// Helpers

fn charts_dir() -> String {
    std::env::var("LATTICE_CHARTS_DIR")
        .unwrap_or_else(|_| option_env!("LATTICE_CHARTS_DIR").unwrap_or("/charts").to_string())
}

fn find_chart(dir: &str, name: &str) -> Result<String, String> {
    let exact = format!("{}/{}", dir, name);
    if std::path::Path::new(&exact).exists() {
        return Ok(exact);
    }

    // Try versioned (e.g., cert-manager-v1.14.0)
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let f = entry.file_name().to_string_lossy().to_string();
            if f.starts_with(&format!("{}-", name)) || f == name {
                return Ok(entry.path().to_string_lossy().to_string());
            }
        }
    }

    Err(format!("chart {} not found in {}", name, dir))
}

fn namespace_yaml(name: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {}",
        name
    )
}

fn split_yaml(yaml: &str) -> Vec<String> {
    yaml.split("\n---")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.contains("kind:"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_yaml() {
        let yaml = "kind: A\n---\nkind: B\n---\n";
        let docs = split_yaml(yaml);
        assert_eq!(docs.len(), 2);
    }

    #[test]
    fn test_namespace_yaml() {
        let ns = namespace_yaml("test");
        assert!(ns.contains("kind: Namespace"));
        assert!(ns.contains("name: test"));
    }
}
