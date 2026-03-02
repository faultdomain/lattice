//! ModelServing compilation from LatticeModel specs
//!
//! Maps LatticeModel fields to Kthena ModelServing resources for disaggregated
//! inference serving with gang scheduling.

use std::collections::BTreeMap;

use lattice_common::crd::{KvConnectorType, LatticeModel, TopologyMode, WorkloadNetworkTopology};

use lattice_common::kube_utils::OwnerReference;

use crate::types::{
    self, GangPolicy, ModelServing, ModelServingRole, ModelServingSpec, ServingGroupTemplate,
    VolcanoMetadata,
};

/// Result of model serving compilation, including any auto-injected topology.
pub struct ModelServingCompilation {
    pub model_serving: ModelServing,
    /// Topology that was auto-injected from kv_connector (None if explicit or absent).
    pub auto_topology: Option<WorkloadNetworkTopology>,
}

/// Pre-compiled pod templates for a single role (entry + optional worker)
pub struct RoleTemplates {
    pub entry_template: serde_json::Value,
    pub worker_template: Option<serde_json::Value>,
}

/// Compile a LatticeModel into a Kthena ModelServing resource.
///
/// Takes the LatticeModel and pre-compiled entry/worker pod templates for each role.
/// The caller (lattice-model compiler) is responsible for compiling workload specs
/// into pod templates via `WorkloadCompiler` and serializing them.
///
/// `role_suffix` is appended to the resource name so that a role-set change
/// (e.g. prefill+decode → decode only) produces a different ModelServing name,
/// avoiding PodGroup name collisions with still-Terminating old resources.
/// When the role set is unchanged the suffix is stable and SSA updates work normally.
pub fn compile_model_serving(
    model: &LatticeModel,
    role_templates: &BTreeMap<String, RoleTemplates>,
    role_suffix: &str,
) -> ModelServingCompilation {
    let model_name = model.metadata.name.as_deref().unwrap_or_default();
    let serving_name = format!("{}-{}", model_name, role_suffix);
    let namespace = model.metadata.namespace.as_deref().unwrap_or("default");
    let uid = model.metadata.uid.as_deref().unwrap_or_default();

    let roles = compile_roles(&model.spec.roles, role_templates);
    let gang_policy = compute_gang_policy(&model.spec.roles);

    // Resolve topology: explicit spec > auto-inject from kv_connector > None
    let (resolved_topology, auto_topology) = resolve_topology(model);
    // ModelServing uses a nested schema: {"groupPolicy": {"mode": ..., "highestTierAllowed": N}}
    let network_topology = resolved_topology
        .as_ref()
        .map(|topo| serde_json::json!({ "groupPolicy": types::network_topology_value(topo) }));

    let model_serving = ModelServing {
        api_version: "workload.serving.volcano.sh/v1alpha1".to_string(),
        kind: "ModelServing".to_string(),
        metadata: VolcanoMetadata {
            name: serving_name,
            namespace: namespace.to_string(),
            labels: BTreeMap::from([
                (
                    "app.kubernetes.io/managed-by".to_string(),
                    "lattice".to_string(),
                ),
                ("app.kubernetes.io/name".to_string(), model_name.to_string()),
            ]),
            owner_references: vec![OwnerReference {
                api_version: "lattice.dev/v1alpha1".to_string(),
                kind: "LatticeModel".to_string(),
                name: model_name.to_string(),
                uid: uid.to_string(),
                controller: Some(true),
                block_owner_deletion: Some(true),
            }],
        },
        spec: ModelServingSpec {
            scheduler_name: model.spec.scheduler_name.clone(),
            replicas: 1,
            template: ServingGroupTemplate {
                roles,
                gang_policy: Some(gang_policy),
                restart_grace_period_seconds: model
                    .spec
                    .restart_grace_period_seconds
                    .map(|v| v as i64),
                network_topology,
            },
            recovery_policy: model.spec.recovery_policy.clone(),
            rollout_strategy: None,
        },
    };

    ModelServingCompilation {
        model_serving,
        auto_topology,
    }
}

/// Resolve the effective topology for a model.
///
/// Returns `(resolved, auto_injected)`:
/// - If the spec has an explicit topology, use it (auto_injected = None).
/// - If no explicit topology but kv_connector is set, auto-inject soft mode
///   with a tier based on the connector type.
/// - Otherwise, both are None.
fn resolve_topology(
    model: &LatticeModel,
) -> (
    Option<WorkloadNetworkTopology>,
    Option<WorkloadNetworkTopology>,
) {
    // Explicit topology from spec takes priority
    if model.spec.topology.is_some() {
        return (model.spec.topology.clone(), None);
    }

    // Auto-inject from kv_connector if routing is configured
    if let Some(ref routing) = model.spec.routing {
        if let Some(ref kv) = routing.kv_connector {
            let max_tier = match kv.type_ {
                KvConnectorType::Nixl => 2,
                KvConnectorType::Lmcache => 2,
                KvConnectorType::Mooncake => 3,
                _ => 2,
            };
            let auto = WorkloadNetworkTopology {
                mode: TopologyMode::Soft,
                max_tier: Some(max_tier),
            };
            return (Some(auto.clone()), Some(auto));
        }
    }

    (None, None)
}

fn compile_roles(
    role_specs: &BTreeMap<String, lattice_common::crd::ModelRoleSpec>,
    role_templates: &BTreeMap<String, RoleTemplates>,
) -> Vec<ModelServingRole> {
    role_specs
        .iter()
        .filter_map(|(role_name, role_spec)| {
            let templates = role_templates.get(role_name)?;
            Some(ModelServingRole {
                name: role_name.clone(),
                replicas: role_spec.replicas(),
                entry_template: templates.entry_template.clone(),
                worker_replicas: role_spec.worker_replicas.unwrap_or(0),
                worker_template: templates.worker_template.clone(),
            })
        })
        .collect()
}

/// Compute the gang scheduling policy for a ModelServing.
///
/// Sets `minRoleReplicas` to 1 for each role. This means the serving group can
/// start as soon as at least one replica of each role is ready, then scales up
/// to the full replica count. Using 1 instead of `spec.replicas` avoids
/// conflicts with Kthena's immutability constraint on `minRoleReplicas` — the
/// value stays stable across replica changes, so SSA updates never hit a 422.
fn compute_gang_policy(
    role_specs: &BTreeMap<String, lattice_common::crd::ModelRoleSpec>,
) -> GangPolicy {
    let min_role_replicas = role_specs.keys().map(|name| (name.clone(), 1)).collect();
    GangPolicy { min_role_replicas }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{
        LatticeModelSpec, ModelRoleSpec, RecoveryPolicy, RuntimeSpec, TopologyMode,
        WorkloadNetworkTopology, WorkloadSpec,
    };

    fn test_model(roles: BTreeMap<String, ModelRoleSpec>) -> LatticeModel {
        let spec = LatticeModelSpec {
            roles,
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("test-uid-456".to_string());
        model
    }

    use crate::test_utils::test_pod_template;

    fn make_role(replicas: u32) -> ModelRoleSpec {
        ModelRoleSpec {
            replicas: Some(replicas),
            entry_workload: WorkloadSpec::default(),
            entry_runtime: RuntimeSpec::default(),
            worker_replicas: None,
            worker_workload: None,
            worker_runtime: None,
            autoscaling: None,
        }
    }

    fn make_entry_only_templates(image: &str) -> RoleTemplates {
        RoleTemplates {
            entry_template: test_pod_template(image),
            worker_template: None,
        }
    }

    #[test]
    fn single_role_model_serving() {
        let mut roles = BTreeMap::new();
        roles.insert("decode".to_string(), make_role(2));

        let model = test_model(roles);
        let templates = BTreeMap::from([(
            "decode".to_string(),
            make_entry_only_templates("decoder:latest"),
        )]);

        let result = compile_model_serving(&model, &templates, "abc123");
        let ms = &result.model_serving;

        assert_eq!(ms.api_version, "workload.serving.volcano.sh/v1alpha1");
        assert_eq!(ms.kind, "ModelServing");
        assert_eq!(ms.metadata.name, "test-model-abc123");
        assert_eq!(ms.spec.scheduler_name, "volcano");
        assert_eq!(ms.spec.template.roles.len(), 1);
        assert_eq!(ms.spec.template.roles[0].name, "decode");
        assert_eq!(ms.spec.template.roles[0].replicas, 2);
        assert!(ms.spec.template.roles[0].worker_template.is_none());
        assert!(result.auto_topology.is_none());
    }

    #[test]
    fn single_role_with_workers() {
        let mut roles = BTreeMap::new();
        roles.insert(
            "decode".to_string(),
            ModelRoleSpec {
                replicas: Some(1),
                entry_workload: WorkloadSpec::default(),
                entry_runtime: RuntimeSpec::default(),
                worker_replicas: Some(4),
                worker_workload: Some(WorkloadSpec::default()),
                worker_runtime: None,
                autoscaling: None,
            },
        );

        let model = test_model(roles);
        let templates = BTreeMap::from([(
            "decode".to_string(),
            RoleTemplates {
                entry_template: test_pod_template("decoder:latest"),
                worker_template: Some(test_pod_template("decoder-worker:latest")),
            },
        )]);

        let result = compile_model_serving(&model, &templates, "test");
        let ms = &result.model_serving;

        assert_eq!(ms.spec.template.roles.len(), 1);
        let role = &ms.spec.template.roles[0];
        assert_eq!(role.name, "decode");
        assert_eq!(role.replicas, 1);
        assert_eq!(role.worker_replicas, 4);
        assert!(role.worker_template.is_some());
    }

    #[test]
    fn multi_role_model_serving() {
        let mut roles = BTreeMap::new();
        roles.insert("prefill".to_string(), make_role(1));
        roles.insert("decode".to_string(), make_role(4));

        let model = test_model(roles);
        let templates = BTreeMap::from([
            (
                "prefill".to_string(),
                make_entry_only_templates("prefill:latest"),
            ),
            (
                "decode".to_string(),
                make_entry_only_templates("decode:latest"),
            ),
        ]);

        let result = compile_model_serving(&model, &templates, "test");
        let ms = &result.model_serving;

        assert_eq!(ms.spec.template.roles.len(), 2);
        // BTreeMap iteration is sorted, so "decode" comes before "prefill"
        assert_eq!(ms.spec.template.roles[0].name, "decode");
        assert_eq!(ms.spec.template.roles[0].replicas, 4);
        assert_eq!(ms.spec.template.roles[1].name, "prefill");
        assert_eq!(ms.spec.template.roles[1].replicas, 1);
    }

    #[test]
    fn owner_reference_set() {
        let model = test_model(BTreeMap::new());
        let result = compile_model_serving(&model, &BTreeMap::new(), "test");
        let ms = &result.model_serving;

        assert_eq!(ms.metadata.owner_references.len(), 1);
        let oref = &ms.metadata.owner_references[0];
        assert_eq!(oref.kind, "LatticeModel");
        assert_eq!(oref.name, "test-model");
        assert_eq!(oref.controller, Some(true));
        assert_eq!(oref.block_owner_deletion, Some(true));
    }

    #[test]
    fn gang_policy_computed_from_replicas() {
        let mut roles = BTreeMap::new();
        roles.insert("prefill".to_string(), make_role(1));
        roles.insert("decode".to_string(), make_role(3));

        let model = test_model(roles);
        let templates = BTreeMap::from([
            (
                "prefill".to_string(),
                make_entry_only_templates("prefill:latest"),
            ),
            (
                "decode".to_string(),
                make_entry_only_templates("decode:latest"),
            ),
        ]);

        let result = compile_model_serving(&model, &templates, "test");
        let ms = &result.model_serving;

        let gang = ms.spec.template.gang_policy.as_ref().unwrap();
        // minRoleReplicas is always 1 (start serving with partial capacity)
        assert_eq!(gang.min_role_replicas["prefill"], 1);
        assert_eq!(gang.min_role_replicas["decode"], 1);
    }

    #[test]
    fn recovery_policy_propagated() {
        let spec = LatticeModelSpec {
            recovery_policy: Some(RecoveryPolicy::ServingGroupRecreate),
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid".to_string());

        let result = compile_model_serving(&model, &BTreeMap::new(), "test");
        assert_eq!(
            result.model_serving.spec.recovery_policy,
            Some(RecoveryPolicy::ServingGroupRecreate)
        );
    }

    #[test]
    fn restart_grace_period_compiled_to_template() {
        let spec = LatticeModelSpec {
            restart_grace_period_seconds: Some(30),
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid".to_string());

        let result = compile_model_serving(&model, &BTreeMap::new(), "test");
        assert_eq!(
            result
                .model_serving
                .spec
                .template
                .restart_grace_period_seconds,
            Some(30)
        );
    }

    #[test]
    fn explicit_topology_used_no_auto_inject() {
        let spec = LatticeModelSpec {
            topology: Some(WorkloadNetworkTopology {
                mode: TopologyMode::Hard,
                max_tier: Some(1),
            }),
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid".to_string());

        let result = compile_model_serving(&model, &BTreeMap::new(), "test");
        let ms = &result.model_serving;

        // Explicit topology should be used, wrapped in groupPolicy for ModelServing
        let topo = ms.spec.template.network_topology.as_ref().unwrap();
        assert_eq!(topo["groupPolicy"]["mode"], "hard");
        assert_eq!(topo["groupPolicy"]["highestTierAllowed"], 1);
        // No auto-injection
        assert!(result.auto_topology.is_none());
    }

    #[test]
    fn kv_connector_auto_injects_topology() {
        use lattice_common::crd::{
            InferenceEngine, KvConnector, KvConnectorType, ModelRoutingSpec,
        };

        let spec = LatticeModelSpec {
            routing: Some(ModelRoutingSpec {
                inference_engine: InferenceEngine::VLlm,
                model: "test-model".to_string(),
                kv_connector: Some(KvConnector {
                    type_: KvConnectorType::Nixl,
                    port: None,
                }),
                port: None,
                protocol: None,
                traffic_policy: None,
                routes: Default::default(),
            }),
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid".to_string());

        let result = compile_model_serving(&model, &BTreeMap::new(), "test");
        let ms = &result.model_serving;

        // Auto-injected soft topology with tier 2 for nixl, wrapped in groupPolicy
        let topo = ms.spec.template.network_topology.as_ref().unwrap();
        assert_eq!(topo["groupPolicy"]["mode"], "soft");
        assert_eq!(topo["groupPolicy"]["highestTierAllowed"], 2);
        // Auto-topology is recorded
        let auto = result.auto_topology.as_ref().unwrap();
        assert_eq!(auto.mode, TopologyMode::Soft);
        assert_eq!(auto.max_tier, Some(2));
    }

    #[test]
    fn mooncake_connector_auto_injects_tier_3() {
        use lattice_common::crd::{
            InferenceEngine, KvConnector, KvConnectorType, ModelRoutingSpec,
        };

        let spec = LatticeModelSpec {
            routing: Some(ModelRoutingSpec {
                inference_engine: InferenceEngine::VLlm,
                model: "test-model".to_string(),
                kv_connector: Some(KvConnector {
                    type_: KvConnectorType::Mooncake,
                    port: None,
                }),
                port: None,
                protocol: None,
                traffic_policy: None,
                routes: Default::default(),
            }),
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid".to_string());

        let result = compile_model_serving(&model, &BTreeMap::new(), "test");

        let auto = result.auto_topology.as_ref().unwrap();
        assert_eq!(auto.max_tier, Some(3));
    }

    #[test]
    fn no_topology_no_auto_inject() {
        let model = test_model(BTreeMap::new());
        let result = compile_model_serving(&model, &BTreeMap::new(), "test");

        assert!(result
            .model_serving
            .spec
            .template
            .network_topology
            .is_none());
        assert!(result.auto_topology.is_none());
    }
}
