//! Routing compiler for LatticeModel inference traffic
//!
//! Compiles `ModelRoutingSpec` into Kthena `ModelServer` + `ModelRoute` resources
//! in the `networking.serving.volcano.sh/v1alpha1` API group.
//!
//! The routing compiler also detects PD disaggregation when both prefill and
//! decode roles are present with a `kv_connector` configured.

use std::collections::BTreeMap;

use lattice_common::crd::{LatticeModel, ModelRoutingSpec};

use lattice_common::kube_utils::OwnerReference;

use crate::types::{
    KthenaHeaderMatch, KthenaKvConnector, KthenaModelMatch, KthenaModelRoute, KthenaModelRouteSpec,
    KthenaModelServer, KthenaModelServerSpec, KthenaParentRef, KthenaRateLimit, KthenaRetryPolicy,
    KthenaRouteRule, KthenaTargetModel, KthenaTrafficPolicy, PdGroup, VolcanoMetadata,
    WorkloadPort, WorkloadSelector,
};

const NETWORKING_API_VERSION: &str = "networking.serving.volcano.sh/v1alpha1";
const MODEL_SERVING_LABEL: &str = "modelserving.volcano.sh/name";
const ROLE_LABEL: &str = "modelserving.volcano.sh/role";
const GROUP_KEY: &str = "modelserving.volcano.sh/group-name";

/// Compiled routing resources for a LatticeModel
#[derive(Debug)]
pub struct CompiledRouting {
    pub model_server: KthenaModelServer,
    pub model_routes: Vec<KthenaModelRoute>,
}

/// Compile a ModelRoutingSpec into Kthena networking resources.
///
/// `serving_name` is the ModelServing resource name (model name + role suffix).
/// The ModelServer's workload_selector uses `modelserving.volcano.sh/name` to
/// match pods, which Kthena labels with the ModelServing name.
pub fn compile_model_routing(
    model: &LatticeModel,
    routing: &ModelRoutingSpec,
    serving_name: &str,
) -> CompiledRouting {
    let model_server = compile_model_server(model, routing, serving_name);

    let model_routes: Vec<KthenaModelRoute> = routing
        .routes
        .iter()
        .map(|(route_name, route_spec)| compile_model_route(model, routing, route_name, route_spec))
        .collect();

    CompiledRouting {
        model_server,
        model_routes,
    }
}

fn compile_model_server(
    model: &LatticeModel,
    routing: &ModelRoutingSpec,
    serving_name: &str,
) -> KthenaModelServer {
    let name = model.metadata.name.as_deref().unwrap_or_default();
    let namespace = model.metadata.namespace.as_deref().unwrap_or("default");
    let uid = model.metadata.uid.as_deref().unwrap_or_default();

    let pd_group = detect_pd_group(model, routing);

    KthenaModelServer {
        api_version: NETWORKING_API_VERSION.to_string(),
        kind: "ModelServer".to_string(),
        metadata: VolcanoMetadata {
            name: name.to_string(),
            namespace: namespace.to_string(),
            labels: BTreeMap::from([
                (
                    "app.kubernetes.io/managed-by".to_string(),
                    "lattice".to_string(),
                ),
                ("app.kubernetes.io/name".to_string(), name.to_string()),
            ]),
            owner_references: vec![owner_reference(name, uid)],
        },
        spec: KthenaModelServerSpec {
            model: Some(routing.model.clone()),
            inference_engine: routing.inference_engine.to_string(),
            workload_selector: WorkloadSelector {
                match_labels: BTreeMap::from([(
                    MODEL_SERVING_LABEL.to_string(),
                    serving_name.to_string(),
                )]),
                pd_group,
            },
            workload_port: WorkloadPort {
                port: routing.port.unwrap_or(8000),
                protocol: routing.protocol.clone(),
            },
            traffic_policy: routing
                .traffic_policy
                .as_ref()
                .map(|tp| KthenaTrafficPolicy {
                    retry: tp.retry.as_ref().map(|r| KthenaRetryPolicy {
                        attempts: r.attempts,
                    }),
                }),
            kv_connector: routing.kv_connector.as_ref().map(|kv| KthenaKvConnector {
                type_: kv.type_.clone(),
            }),
        },
    }
}

fn compile_model_route(
    model: &LatticeModel,
    routing: &ModelRoutingSpec,
    route_name: &str,
    route_spec: &lattice_common::crd::ModelRouteSpec,
) -> KthenaModelRoute {
    let name = model.metadata.name.as_deref().unwrap_or_default();
    let namespace = model.metadata.namespace.as_deref().unwrap_or("default");
    let uid = model.metadata.uid.as_deref().unwrap_or_default();

    let resource_name = format!("{}-{}", name, route_name);

    let rules: Vec<KthenaRouteRule> = route_spec
        .rules
        .iter()
        .map(|rule| {
            let model_match = rule.model_match.as_ref().map(|mm| KthenaModelMatch {
                headers: mm
                    .headers
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            KthenaHeaderMatch {
                                exact: v.exact.clone(),
                            },
                        )
                    })
                    .collect(),
            });

            let target_models: Vec<KthenaTargetModel> = rule
                .target_models
                .iter()
                .map(|tm| KthenaTargetModel {
                    model_server_name: tm
                        .model_server_name
                        .clone()
                        .unwrap_or_else(|| name.to_string()),
                    weight: tm.weight,
                })
                .collect();

            KthenaRouteRule {
                name: rule.name.clone(),
                model_match,
                target_models,
            }
        })
        .collect();

    let parent_refs = route_spec.parent_refs.as_ref().map(|refs| {
        refs.iter()
            .map(|pr| KthenaParentRef {
                name: pr.name.clone(),
                namespace: pr.namespace.clone(),
                kind: pr.kind.clone(),
            })
            .collect()
    });

    let rate_limit = route_spec.rate_limit.as_ref().map(|rl| KthenaRateLimit {
        input_tokens_per_unit: rl.input_tokens_per_unit,
        output_tokens_per_unit: rl.output_tokens_per_unit,
        unit: rl.unit.clone(),
    });

    KthenaModelRoute {
        api_version: NETWORKING_API_VERSION.to_string(),
        kind: "ModelRoute".to_string(),
        metadata: VolcanoMetadata {
            name: resource_name,
            namespace: namespace.to_string(),
            labels: BTreeMap::from([
                (
                    "app.kubernetes.io/managed-by".to_string(),
                    "lattice".to_string(),
                ),
                ("app.kubernetes.io/name".to_string(), name.to_string()),
            ]),
            owner_references: vec![owner_reference(name, uid)],
        },
        spec: KthenaModelRouteSpec {
            model_name: route_spec
                .model_name
                .clone()
                .or_else(|| Some(routing.model.clone())),
            lora_adapters: route_spec.lora_adapters.clone(),
            parent_refs,
            rules,
            rate_limit,
        },
    }
}

/// The exact role names required for PD disaggregation.
///
/// Kthena PdGroup labels use these as literal values (`modelserving.volcano.sh/role=prefill`),
/// so role names must match exactly. Substring matching (e.g. "fast-prefill") would silently
/// break PD routing because pods would have `role=fast-prefill` but Kthena looks for `role=prefill`.
pub const PD_ROLE_PREFILL: &str = "prefill";
pub const PD_ROLE_DECODE: &str = "decode";

/// Auto-detect PD disaggregation from roles.
///
/// Requires roles named exactly "prefill" and "decode" with a `kv_connector` configured.
/// Roles must use these exact names because Kthena PdGroup labels reference them literally.
fn detect_pd_group(model: &LatticeModel, routing: &ModelRoutingSpec) -> Option<PdGroup> {
    routing.kv_connector.as_ref()?;

    if !has_pd_roles(&model.spec.roles) {
        return None;
    }

    Some(PdGroup {
        group_key: GROUP_KEY.to_string(),
        prefill_labels: BTreeMap::from([(ROLE_LABEL.to_string(), PD_ROLE_PREFILL.to_string())]),
        decode_labels: BTreeMap::from([(ROLE_LABEL.to_string(), PD_ROLE_DECODE.to_string())]),
    })
}

/// Check whether a model has PD disaggregation roles (exactly "prefill" + "decode").
pub fn has_pd_roles(roles: &BTreeMap<String, lattice_common::crd::ModelRoleSpec>) -> bool {
    roles.contains_key(PD_ROLE_PREFILL) && roles.contains_key(PD_ROLE_DECODE)
}

pub(crate) fn owner_reference(name: &str, uid: &str) -> OwnerReference {
    OwnerReference {
        api_version: "lattice.dev/v1alpha1".to_string(),
        kind: "LatticeModel".to_string(),
        name: name.to_string(),
        uid: uid.to_string(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{
        HeaderMatchValue, InferenceEngine, KvConnector, KvConnectorType, LatticeModelSpec,
        ModelMatch, ModelParentRef, ModelRoleSpec, ModelRouteRule, ModelRouteSpec,
        ModelRoutingSpec, RateLimit, RateLimitUnit, RuntimeSpec, TargetModel, TrafficPolicy,
        WorkloadSpec,
    };

    fn test_model(roles: BTreeMap<String, ModelRoleSpec>) -> LatticeModel {
        let spec = LatticeModelSpec {
            roles,
            ..Default::default()
        };
        let mut model = LatticeModel::new("test-model", spec);
        model.metadata.namespace = Some("default".to_string());
        model.metadata.uid = Some("uid-123".to_string());
        model
    }

    fn make_role(replicas: u32) -> ModelRoleSpec {
        ModelRoleSpec {
            replicas,
            entry_workload: WorkloadSpec::default(),
            entry_runtime: RuntimeSpec::default(),
            worker_replicas: None,
            worker_workload: None,
            worker_runtime: None,
            autoscaling: None,
        }
    }

    fn basic_routing() -> ModelRoutingSpec {
        ModelRoutingSpec {
            inference_engine: InferenceEngine::VLlm,
            model: "test-org/test-model".to_string(),
            port: None,
            protocol: None,
            traffic_policy: None,
            kv_connector: None,
            routes: BTreeMap::from([(
                "default".to_string(),
                ModelRouteSpec {
                    model_name: None,
                    lora_adapters: None,
                    rules: vec![ModelRouteRule {
                        name: "default".to_string(),
                        model_match: None,
                        target_models: vec![TargetModel {
                            model_server_name: None,
                            weight: Some(100),
                        }],
                    }],
                    rate_limit: None,
                    parent_refs: None,
                },
            )]),
        }
    }

    #[test]
    fn single_route_default_model_server_name() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = basic_routing();

        let compiled = compile_model_routing(&model, &routing, "test-model-test");

        assert_eq!(compiled.model_server.metadata.name, "test-model");
        assert_eq!(compiled.model_server.spec.inference_engine, "vLLM");
        assert_eq!(
            compiled.model_server.spec.model,
            Some("test-org/test-model".to_string())
        );
        assert_eq!(compiled.model_server.spec.workload_port.port, 8000);
        assert!(compiled
            .model_server
            .spec
            .workload_selector
            .pd_group
            .is_none());

        assert_eq!(compiled.model_routes.len(), 1);
        let route = &compiled.model_routes[0];
        assert_eq!(route.metadata.name, "test-model-default");
        assert_eq!(
            route.spec.model_name,
            Some("test-org/test-model".to_string())
        );
        assert_eq!(
            route.spec.rules[0].target_models[0].model_server_name,
            "test-model"
        );
    }

    #[test]
    fn pd_disaggregation_auto_detected() {
        let model = test_model(BTreeMap::from([
            ("prefill".to_string(), make_role(1)),
            ("decode".to_string(), make_role(4)),
        ]));
        let mut routing = basic_routing();
        routing.kv_connector = Some(KvConnector {
            type_: KvConnectorType::Nixl,
        });

        let compiled = compile_model_routing(&model, &routing, "test-model-test");

        let pd = compiled
            .model_server
            .spec
            .workload_selector
            .pd_group
            .as_ref()
            .expect("PdGroup should be set");
        assert_eq!(pd.group_key, GROUP_KEY);
        assert_eq!(pd.prefill_labels[ROLE_LABEL], "prefill");
        assert_eq!(pd.decode_labels[ROLE_LABEL], "decode");
        assert_eq!(
            compiled
                .model_server
                .spec
                .kv_connector
                .as_ref()
                .unwrap()
                .type_,
            KvConnectorType::Nixl
        );
    }

    #[test]
    fn no_pd_without_kv_connector() {
        let model = test_model(BTreeMap::from([
            ("prefill".to_string(), make_role(1)),
            ("decode".to_string(), make_role(4)),
        ]));
        let routing = basic_routing();

        let compiled = compile_model_routing(&model, &routing, "test-model-test");
        assert!(compiled
            .model_server
            .spec
            .workload_selector
            .pd_group
            .is_none());
    }

    #[test]
    fn no_pd_without_both_roles() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let mut routing = basic_routing();
        routing.kv_connector = Some(KvConnector {
            type_: KvConnectorType::Nixl,
        });

        let compiled = compile_model_routing(&model, &routing, "test-model-test");
        assert!(compiled
            .model_server
            .spec
            .workload_selector
            .pd_group
            .is_none());
    }

    #[test]
    fn weighted_canary_split() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = ModelRoutingSpec {
            inference_engine: InferenceEngine::VLlm,
            model: "org/model".to_string(),
            port: None,
            protocol: None,
            traffic_policy: None,
            kv_connector: None,
            routes: BTreeMap::from([(
                "canary".to_string(),
                ModelRouteSpec {
                    model_name: None,
                    lora_adapters: None,
                    rules: vec![ModelRouteRule {
                        name: "split".to_string(),
                        model_match: None,
                        target_models: vec![
                            TargetModel {
                                model_server_name: Some("model-stable".to_string()),
                                weight: Some(90),
                            },
                            TargetModel {
                                model_server_name: Some("model-canary".to_string()),
                                weight: Some(10),
                            },
                        ],
                    }],
                    rate_limit: None,
                    parent_refs: None,
                },
            )]),
        };

        let compiled = compile_model_routing(&model, &routing, "test-model-test");
        let route = &compiled.model_routes[0];
        assert_eq!(route.spec.rules[0].target_models.len(), 2);
        assert_eq!(
            route.spec.rules[0].target_models[0].model_server_name,
            "model-stable"
        );
        assert_eq!(route.spec.rules[0].target_models[0].weight, Some(90));
        assert_eq!(
            route.spec.rules[0].target_models[1].model_server_name,
            "model-canary"
        );
        assert_eq!(route.spec.rules[0].target_models[1].weight, Some(10));
    }

    #[test]
    fn header_based_routing() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = ModelRoutingSpec {
            inference_engine: InferenceEngine::SGLang,
            model: "org/model".to_string(),
            port: Some(9000),
            protocol: Some("grpc".to_string()),
            traffic_policy: None,
            kv_connector: None,
            routes: BTreeMap::from([(
                "versioned".to_string(),
                ModelRouteSpec {
                    model_name: None,
                    lora_adapters: None,
                    rules: vec![ModelRouteRule {
                        name: "v2-header".to_string(),
                        model_match: Some(ModelMatch {
                            headers: BTreeMap::from([(
                                "x-model-version".to_string(),
                                HeaderMatchValue {
                                    exact: Some("v2".to_string()),
                                },
                            )]),
                        }),
                        target_models: vec![TargetModel {
                            model_server_name: None,
                            weight: Some(100),
                        }],
                    }],
                    rate_limit: None,
                    parent_refs: None,
                },
            )]),
        };

        let compiled = compile_model_routing(&model, &routing, "test-model-test");

        assert_eq!(compiled.model_server.spec.inference_engine, "SGLang");
        assert_eq!(compiled.model_server.spec.workload_port.port, 9000);
        assert_eq!(
            compiled.model_server.spec.workload_port.protocol,
            Some("grpc".to_string())
        );

        let rule = &compiled.model_routes[0].spec.rules[0];
        let headers = &rule.model_match.as_ref().unwrap().headers;
        assert_eq!(headers["x-model-version"].exact, Some("v2".to_string()));
    }

    #[test]
    fn lora_adapter_routing() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = ModelRoutingSpec {
            inference_engine: InferenceEngine::VLlm,
            model: "org/model".to_string(),
            port: None,
            protocol: None,
            traffic_policy: None,
            kv_connector: None,
            routes: BTreeMap::from([(
                "lora".to_string(),
                ModelRouteSpec {
                    model_name: Some("custom-model".to_string()),
                    lora_adapters: Some(vec!["adapter-a".to_string(), "adapter-b".to_string()]),
                    rules: vec![ModelRouteRule {
                        name: "default".to_string(),
                        model_match: None,
                        target_models: vec![TargetModel {
                            model_server_name: None,
                            weight: Some(100),
                        }],
                    }],
                    rate_limit: None,
                    parent_refs: None,
                },
            )]),
        };

        let compiled = compile_model_routing(&model, &routing, "test-model-test");
        let route = &compiled.model_routes[0];
        assert_eq!(route.spec.model_name, Some("custom-model".to_string()));
        assert_eq!(
            route.spec.lora_adapters,
            Some(vec!["adapter-a".to_string(), "adapter-b".to_string()])
        );
    }

    #[test]
    fn rate_limit_propagated() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = ModelRoutingSpec {
            inference_engine: InferenceEngine::VLlm,
            model: "org/model".to_string(),
            port: None,
            protocol: None,
            traffic_policy: Some(TrafficPolicy {
                retry: Some(lattice_common::crd::RetryPolicy { attempts: Some(3) }),
            }),
            kv_connector: None,
            routes: BTreeMap::from([(
                "default".to_string(),
                ModelRouteSpec {
                    model_name: None,
                    lora_adapters: None,
                    rules: vec![ModelRouteRule {
                        name: "default".to_string(),
                        model_match: None,
                        target_models: vec![TargetModel {
                            model_server_name: None,
                            weight: Some(100),
                        }],
                    }],
                    rate_limit: Some(RateLimit {
                        input_tokens_per_unit: Some(1000),
                        output_tokens_per_unit: Some(500),
                        unit: Some(RateLimitUnit::Minute),
                    }),
                    parent_refs: None,
                },
            )]),
        };

        let compiled = compile_model_routing(&model, &routing, "test-model-test");

        assert_eq!(
            compiled
                .model_server
                .spec
                .traffic_policy
                .as_ref()
                .unwrap()
                .retry
                .as_ref()
                .unwrap()
                .attempts,
            Some(3)
        );

        let rl = compiled.model_routes[0].spec.rate_limit.as_ref().unwrap();
        assert_eq!(rl.input_tokens_per_unit, Some(1000));
        assert_eq!(rl.output_tokens_per_unit, Some(500));
        assert_eq!(rl.unit, Some(RateLimitUnit::Minute));
    }

    #[test]
    fn owner_references_set() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = basic_routing();

        let compiled = compile_model_routing(&model, &routing, "test-model-test");

        let ms_oref = &compiled.model_server.metadata.owner_references[0];
        assert_eq!(ms_oref.kind, "LatticeModel");
        assert_eq!(ms_oref.name, "test-model");
        assert_eq!(ms_oref.uid, "uid-123");
        assert_eq!(ms_oref.controller, Some(true));

        let mr_oref = &compiled.model_routes[0].metadata.owner_references[0];
        assert_eq!(mr_oref.kind, "LatticeModel");
        assert_eq!(mr_oref.name, "test-model");
    }

    #[test]
    fn parent_refs_propagated() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = ModelRoutingSpec {
            inference_engine: InferenceEngine::VLlm,
            model: "org/model".to_string(),
            port: None,
            protocol: None,
            traffic_policy: None,
            kv_connector: None,
            routes: BTreeMap::from([(
                "default".to_string(),
                ModelRouteSpec {
                    model_name: None,
                    lora_adapters: None,
                    rules: vec![ModelRouteRule {
                        name: "default".to_string(),
                        model_match: None,
                        target_models: vec![TargetModel {
                            model_server_name: None,
                            weight: Some(100),
                        }],
                    }],
                    rate_limit: None,
                    parent_refs: Some(vec![ModelParentRef {
                        name: "inference-gw".to_string(),
                        namespace: Some("istio-system".to_string()),
                        kind: Some("Gateway".to_string()),
                    }]),
                },
            )]),
        };

        let compiled = compile_model_routing(&model, &routing, "test-model-test");
        let refs = compiled.model_routes[0].spec.parent_refs.as_ref().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "inference-gw");
        assert_eq!(refs[0].namespace, Some("istio-system".to_string()));
        assert_eq!(refs[0].kind, Some("Gateway".to_string()));
    }

    #[test]
    fn has_pd_roles_detection() {
        let with_pd = BTreeMap::from([
            ("prefill".to_string(), make_role(1)),
            ("decode".to_string(), make_role(4)),
        ]);
        assert!(has_pd_roles(&with_pd));

        let without_pd = BTreeMap::from([("decode".to_string(), make_role(2))]);
        assert!(!has_pd_roles(&without_pd));

        let partial = BTreeMap::from([("prefill".to_string(), make_role(1))]);
        assert!(!has_pd_roles(&partial));
    }

    #[test]
    fn has_pd_roles_requires_exact_names() {
        // Substring matches should NOT trigger PD detection
        let substring_match = BTreeMap::from([
            ("fast-prefill".to_string(), make_role(1)),
            ("decode".to_string(), make_role(4)),
        ]);
        assert!(!has_pd_roles(&substring_match));

        let substring_both = BTreeMap::from([
            ("prefill-v2".to_string(), make_role(1)),
            ("predecode".to_string(), make_role(4)),
        ]);
        assert!(!has_pd_roles(&substring_both));
    }

    #[test]
    fn pd_not_detected_for_non_exact_role_names() {
        let model = test_model(BTreeMap::from([
            ("fast-prefill".to_string(), make_role(1)),
            ("decode".to_string(), make_role(4)),
        ]));
        let mut routing = basic_routing();
        routing.kv_connector = Some(KvConnector {
            type_: KvConnectorType::Nixl,
        });

        let compiled = compile_model_routing(&model, &routing, "test-model-test");
        assert!(
            compiled
                .model_server
                .spec
                .workload_selector
                .pd_group
                .is_none(),
            "PD should not be detected for non-exact role names"
        );
    }

    #[test]
    fn workload_selector_matches_serving_name() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = basic_routing();

        let compiled = compile_model_routing(&model, &routing, "test-model-test");
        assert_eq!(
            compiled.model_server.spec.workload_selector.match_labels[MODEL_SERVING_LABEL],
            "test-model-test"
        );
    }
}
