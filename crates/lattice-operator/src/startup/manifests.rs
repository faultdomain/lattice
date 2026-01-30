//! Manifest application utilities
//!
//! Provides functions for applying YAML manifests to a Kubernetes cluster,
//! handling proper ordering and API discovery.

use kube::Client;

/// Get priority for a Kubernetes resource kind (lower = apply first)
pub fn kind_priority(kind: &str) -> u8 {
    match kind {
        "Namespace" => 0,
        "CustomResourceDefinition" => 1,
        "ServiceAccount" => 2,
        "ClusterRole" | "Role" => 3,
        "ClusterRoleBinding" | "RoleBinding" => 4,
        "ConfigMap" | "Secret" => 5,
        "Service" => 6,
        "Deployment" | "DaemonSet" | "StatefulSet" => 7,
        "HorizontalPodAutoscaler" => 8,
        _ => 10, // webhooks, policies, etc. come last
    }
}

/// Extract kind from a YAML manifest
pub fn extract_kind(manifest: &str) -> &str {
    manifest
        .lines()
        .find(|line| line.starts_with("kind:"))
        .and_then(|line| line.strip_prefix("kind:"))
        .map(|k| k.trim())
        .unwrap_or("")
}

/// Apply multiple YAML manifests to the cluster
///
/// Applies in two phases:
/// 1. Namespaces and CRDs (foundational resources)
/// 2. Re-run discovery to learn new CRD types
/// 3. Everything else (sorted by kind priority)
pub async fn apply_manifests(client: &Client, manifests: &[impl AsRef<str>]) -> anyhow::Result<()> {
    use kube::api::PatchParams;
    use kube::discovery::Discovery;

    if manifests.is_empty() {
        return Ok(());
    }

    // Split into foundational (Namespace, CRD) and rest
    let (mut foundational, mut rest): (Vec<&str>, Vec<&str>) =
        manifests.iter().map(|m| m.as_ref()).partition(|m| {
            let kind = extract_kind(m);
            kind == "Namespace" || kind == "CustomResourceDefinition"
        });

    // Sort each group by priority
    foundational.sort_by_key(|m| kind_priority(extract_kind(m)));
    rest.sort_by_key(|m| kind_priority(extract_kind(m)));

    let params = PatchParams::apply("lattice").force();

    // Phase 1: Apply foundational resources (Namespaces, CRDs)
    if !foundational.is_empty() {
        let discovery = Discovery::new(client.clone())
            .run()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to run API discovery: {}", e))?;

        for manifest in &foundational {
            apply_single_manifest(client, &discovery, manifest, &params).await?;
        }
    }

    // Phase 2: Re-run discovery to learn new CRD types, then apply rest
    if !rest.is_empty() {
        let discovery = Discovery::new(client.clone())
            .run()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to refresh API discovery: {}", e))?;

        for manifest in &rest {
            apply_single_manifest(client, &discovery, manifest, &params).await?;
        }
    }

    Ok(())
}

/// Apply a single manifest using the provided discovery cache
async fn apply_single_manifest(
    client: &Client,
    discovery: &kube::discovery::Discovery,
    manifest: &str,
    params: &kube::api::PatchParams,
) -> anyhow::Result<()> {
    use kube::api::{Api, DynamicObject, Patch};

    let obj: serde_json::Value = lattice_common::yaml::parse_yaml(manifest)
        .map_err(|e| anyhow::anyhow!("Invalid YAML: {}", e))?;

    let kind = obj
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing kind"))?;
    let api_version = obj
        .get("apiVersion")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing apiVersion"))?;
    let name = obj
        .pointer("/metadata/name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing metadata.name"))?;
    let namespace = obj.pointer("/metadata/namespace").and_then(|v| v.as_str());

    // Parse apiVersion into group/version
    let (group, version) = if let Some((g, v)) = api_version.split_once('/') {
        (g, v)
    } else {
        ("", api_version)
    };

    let gvk = kube::api::GroupVersionKind {
        group: group.to_string(),
        version: version.to_string(),
        kind: kind.to_string(),
    };

    let (api_resource, _) = discovery
        .resolve_gvk(&gvk)
        .ok_or_else(|| anyhow::anyhow!("Unknown resource type: {}/{}", api_version, kind))?;

    let api: Api<DynamicObject> = match namespace {
        Some(ns) => Api::namespaced_with(client.clone(), ns, &api_resource),
        None => Api::all_with(client.clone(), &api_resource),
    };

    api.patch(name, params, &Patch::Apply(&obj))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to apply {}/{}: {}", kind, name, e))?;

    tracing::debug!(kind = %kind, name = %name, namespace = ?namespace, "Applied manifest");
    Ok(())
}
