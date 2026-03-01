//! Pod template JSON serialization for batch/serving workloads
//!
//! Converts a `CompiledPodTemplate` into a JSON value suitable for use in
//! Volcano VCJob task templates and Kthena ModelServing role templates.

use crate::CompiledPodTemplate;

/// Convert a `CompiledPodTemplate` into a JSON value for batch/serving workload templates.
///
/// Produces a pod template spec structure as JSON, avoiding dependency on the service
/// crate's serialization types. Returns `serde_json::Error` on serialization failure.
pub fn pod_template_to_json(
    pt: CompiledPodTemplate,
) -> Result<serde_json::Value, serde_json::Error> {
    use serde::de::Error as _;

    let mut spec = serde_json::json!({
        "serviceAccountName": pt.service_account_name,
        "automountServiceAccountToken": false,
        "containers": pt.containers,
    });

    let spec_obj = spec
        .as_object_mut()
        .ok_or_else(|| serde_json::Error::custom("pod spec is not a JSON object"))?;

    if !pt.init_containers.is_empty() {
        spec_obj.insert(
            "initContainers".to_string(),
            serde_json::to_value(&pt.init_containers).unwrap_or_default(),
        );
    }
    if !pt.volumes.is_empty() {
        spec_obj.insert(
            "volumes".to_string(),
            serde_json::to_value(&pt.volumes).unwrap_or_default(),
        );
    }
    if let Some(ref sc) = pt.security_context {
        spec_obj.insert(
            "securityContext".to_string(),
            serde_json::to_value(sc).unwrap_or_default(),
        );
    }
    if let Some(hn) = pt.host_network {
        spec_obj.insert("hostNetwork".to_string(), serde_json::Value::Bool(hn));
    }
    if let Some(spn) = pt.share_process_namespace {
        spec_obj.insert(
            "shareProcessNamespace".to_string(),
            serde_json::Value::Bool(spn),
        );
    }
    if !pt.topology_spread_constraints.is_empty() {
        spec_obj.insert(
            "topologySpreadConstraints".to_string(),
            serde_json::to_value(&pt.topology_spread_constraints).unwrap_or_default(),
        );
    }
    if let Some(ref ns) = pt.node_selector {
        spec_obj.insert(
            "nodeSelector".to_string(),
            serde_json::to_value(ns).unwrap_or_default(),
        );
    }
    if !pt.tolerations.is_empty() {
        spec_obj.insert(
            "tolerations".to_string(),
            serde_json::to_value(&pt.tolerations).unwrap_or_default(),
        );
    }
    if let Some(ref rcn) = pt.runtime_class_name {
        spec_obj.insert(
            "runtimeClassName".to_string(),
            serde_json::Value::String(rcn.clone()),
        );
    }
    if !pt.scheduling_gates.is_empty() {
        spec_obj.insert(
            "schedulingGates".to_string(),
            serde_json::to_value(&pt.scheduling_gates).unwrap_or_default(),
        );
    }
    if !pt.image_pull_secrets.is_empty() {
        spec_obj.insert(
            "imagePullSecrets".to_string(),
            serde_json::to_value(&pt.image_pull_secrets).unwrap_or_default(),
        );
    }
    if let Some(ref affinity) = pt.affinity {
        spec_obj.insert(
            "affinity".to_string(),
            serde_json::to_value(affinity).unwrap_or_default(),
        );
    }

    Ok(serde_json::json!({
        "metadata": {
            "labels": pt.labels
        },
        "spec": spec
    }))
}
