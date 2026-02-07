//! Scheduling gate removal for model-ready pods
//!
//! When a ModelArtifact transitions to Ready, Deployments that reference
//! the same PVC need their `lattice.dev/model-ready` scheduling gate removed
//! so pods can be scheduled.

use k8s_openapi::api::apps::v1::Deployment;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::Client;
use tracing::info;

use lattice_common::crd::MODEL_READY_GATE;
use lattice_common::ReconcileError;

/// Remove the model-ready scheduling gate from Deployments that reference the given PVC.
///
/// Scans all Deployments in the namespace for ones that:
/// 1. Have the `lattice.dev/model-ready` scheduling gate
/// 2. Mount a volume backed by the specified PVC
///
/// For matching Deployments, removes the scheduling gate so pods can be scheduled.
pub async fn remove_gates_for_pvc(
    client: &Client,
    namespace: &str,
    pvc_name: &str,
) -> Result<(), ReconcileError> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let list = deployments
        .list(&ListParams::default())
        .await
        .map_err(|e| ReconcileError::Kube(format!("failed to list deployments: {}", e)))?;

    for deploy in &list.items {
        if should_remove_gate(deploy, pvc_name) {
            let name = deploy.metadata.name.as_deref().unwrap_or_default();

            info!(
                deployment = %name,
                namespace = %namespace,
                pvc = %pvc_name,
                "Removing model-ready scheduling gate"
            );

            let gates = remaining_gates(deploy);
            let patch = serde_json::json!({
                "spec": {
                    "template": {
                        "spec": {
                            "schedulingGates": gates
                        }
                    }
                }
            });

            deployments
                .patch(
                    name,
                    &PatchParams::apply("lattice-model-cache"),
                    &Patch::Merge(&patch),
                )
                .await
                .map_err(|e| {
                    ReconcileError::Kube(format!(
                        "failed to remove scheduling gate from {}: {}",
                        name, e
                    ))
                })?;
        }
    }

    Ok(())
}

/// Check if a Deployment has the model-ready gate AND references the given PVC
fn should_remove_gate(deploy: &Deployment, pvc_name: &str) -> bool {
    let has_gate = has_model_ready_gate(deploy);
    let has_pvc = references_pvc(deploy, pvc_name);
    has_gate && has_pvc
}

/// Check if a Deployment's pod template has the model-ready scheduling gate
fn has_model_ready_gate(deploy: &Deployment) -> bool {
    deploy
        .spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .and_then(|ps| ps.scheduling_gates.as_ref())
        .map(|gates| gates.iter().any(|g| g.name == MODEL_READY_GATE))
        .unwrap_or(false)
}

/// Check if a Deployment's pod template mounts a volume backed by the given PVC
fn references_pvc(deploy: &Deployment, pvc_name: &str) -> bool {
    deploy
        .spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .and_then(|ps| ps.volumes.as_ref())
        .map(|volumes| {
            volumes.iter().any(|v| {
                v.persistent_volume_claim
                    .as_ref()
                    .map(|pvc| pvc.claim_name == pvc_name)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Compute the remaining scheduling gates after removing the model-ready gate
fn remaining_gates(deploy: &Deployment) -> Vec<serde_json::Value> {
    deploy
        .spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .and_then(|ps| ps.scheduling_gates.as_ref())
        .map(|gates| {
            gates
                .iter()
                .filter(|g| g.name != MODEL_READY_GATE)
                .map(|g| serde_json::json!({"name": g.name}))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::apps::v1::DeploymentSpec;
    use k8s_openapi::api::core::v1::{
        Container, PersistentVolumeClaimVolumeSource, PodSchedulingGate, PodSpec, PodTemplateSpec,
        Volume,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};

    fn make_deployment(name: &str, pvc_name: Option<&str>, gates: Vec<&str>) -> Deployment {
        let volumes = pvc_name.map(|pvc| {
            vec![Volume {
                name: "model-store".to_string(),
                persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                    claim_name: pvc.to_string(),
                    read_only: Some(true),
                }),
                ..Default::default()
            }]
        });

        let scheduling_gates = if gates.is_empty() {
            None
        } else {
            Some(
                gates
                    .iter()
                    .map(|g| PodSchedulingGate {
                        name: g.to_string(),
                    })
                    .collect(),
            )
        };

        Deployment {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(DeploymentSpec {
                selector: LabelSelector::default(),
                template: PodTemplateSpec {
                    spec: Some(PodSpec {
                        containers: vec![Container {
                            name: "main".to_string(),
                            ..Default::default()
                        }],
                        volumes,
                        scheduling_gates,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn has_model_ready_gate_detects_gate() {
        let deploy = make_deployment("test", None, vec![MODEL_READY_GATE]);
        assert!(has_model_ready_gate(&deploy));
    }

    #[test]
    fn has_model_ready_gate_false_without_gate() {
        let deploy = make_deployment("test", None, vec![]);
        assert!(!has_model_ready_gate(&deploy));
    }

    #[test]
    fn has_model_ready_gate_false_with_other_gates() {
        let deploy = make_deployment("test", None, vec!["some.other/gate"]);
        assert!(!has_model_ready_gate(&deploy));
    }

    #[test]
    fn references_pvc_detects_matching_pvc() {
        let deploy = make_deployment("test", Some("model-cache-abc"), vec![]);
        assert!(references_pvc(&deploy, "model-cache-abc"));
    }

    #[test]
    fn references_pvc_false_for_different_pvc() {
        let deploy = make_deployment("test", Some("model-cache-abc"), vec![]);
        assert!(!references_pvc(&deploy, "model-cache-xyz"));
    }

    #[test]
    fn references_pvc_false_without_volumes() {
        let deploy = make_deployment("test", None, vec![]);
        assert!(!references_pvc(&deploy, "model-cache-abc"));
    }

    #[test]
    fn should_remove_gate_true_when_both_match() {
        let deploy = make_deployment("test", Some("model-cache-abc"), vec![MODEL_READY_GATE]);
        assert!(should_remove_gate(&deploy, "model-cache-abc"));
    }

    #[test]
    fn should_remove_gate_false_without_gate() {
        let deploy = make_deployment("test", Some("model-cache-abc"), vec![]);
        assert!(!should_remove_gate(&deploy, "model-cache-abc"));
    }

    #[test]
    fn should_remove_gate_false_without_pvc() {
        let deploy = make_deployment("test", None, vec![MODEL_READY_GATE]);
        assert!(!should_remove_gate(&deploy, "model-cache-abc"));
    }

    #[test]
    fn should_remove_gate_false_with_wrong_pvc() {
        let deploy = make_deployment("test", Some("model-cache-xyz"), vec![MODEL_READY_GATE]);
        assert!(!should_remove_gate(&deploy, "model-cache-abc"));
    }

    #[test]
    fn remaining_gates_removes_model_gate() {
        let deploy = make_deployment("test", None, vec![MODEL_READY_GATE, "some.other/gate"]);
        let gates = remaining_gates(&deploy);
        assert_eq!(gates.len(), 1);
        assert_eq!(gates[0]["name"], "some.other/gate");
    }

    #[test]
    fn remaining_gates_empty_when_only_model_gate() {
        let deploy = make_deployment("test", None, vec![MODEL_READY_GATE]);
        let gates = remaining_gates(&deploy);
        assert!(gates.is_empty());
    }

    #[test]
    fn remaining_gates_empty_when_no_gates() {
        let deploy = make_deployment("test", None, vec![]);
        let gates = remaining_gates(&deploy);
        assert!(gates.is_empty());
    }
}
