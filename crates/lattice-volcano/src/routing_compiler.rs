//! Routing compiler for LatticeModel inference traffic
//!
//! Compiles `ModelRoutingSpec` into Kthena `ModelServer` + `ModelRoute` resources
//! in the `networking.serving.volcano.sh/v1alpha1` API group.
//!
//! The routing compiler also detects PD disaggregation when both prefill and
//! decode roles are present with a `kv_connector` configured.

use std::collections::BTreeMap;

use lattice_common::crd::{LatticeModel, ModelIngressSpec, ModelRoutingSpec};
use lattice_common::kube_utils::OwnerReference;
use lattice_common::mesh;
use lattice_common::network::gateway_api::{
    AllowedRoutes, Certificate, CertificateRef, Gateway, GatewayListener, GatewaySpec,
    GatewayTlsConfig, IssuerRef,
};
use lattice_common::{LABEL_MANAGED_BY, LABEL_MANAGED_BY_LATTICE, LABEL_NAME};

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
    /// Gateway for external access (only when ingress is configured)
    pub gateway: Option<Gateway>,
    /// TLS certificate (only when ingress uses cert-manager auto mode)
    pub certificate: Option<Certificate>,
}

/// Compile a ModelRoutingSpec into Kthena networking resources.
///
/// `serving_name` is the ModelServing resource name (model name + role suffix).
/// The ModelServer's workload_selector uses `modelserving.volcano.sh/name` to
/// match pods, which Kthena labels with the ModelServing name.
///
/// When `ingress` is provided, creates a Gateway with TLS listeners and
/// auto-populates `parentRefs` on ModelRoutes that don't have explicit ones.
pub fn compile_model_routing(
    model: &LatticeModel,
    routing: &ModelRoutingSpec,
    serving_name: &str,
    ingress: Option<&ModelIngressSpec>,
) -> CompiledRouting {
    let name = model.metadata.name.as_deref().unwrap_or_default();
    let namespace = model.metadata.namespace.as_deref().unwrap_or("default");

    let model_server = compile_model_server(model, routing, serving_name);

    let (gateway, certificate, gateway_parent_ref) = match ingress {
        Some(ingress_spec) => {
            let (gw, cert) = compile_ingress_gateway(name, namespace, ingress_spec);
            let parent_ref = KthenaParentRef {
                name: gw.metadata.name.clone(),
                namespace: Some(namespace.to_string()),
                kind: Some("Gateway".to_string()),
            };
            (Some(gw), cert, Some(parent_ref))
        }
        None => (None, None, None),
    };

    let model_routes: Vec<KthenaModelRoute> = routing
        .routes
        .iter()
        .map(|(route_name, route_spec)| {
            let mut route = compile_model_route(model, routing, route_name, route_spec);
            // Auto-inject gateway parentRef if ingress is set and route has no explicit parentRefs
            if route.spec.parent_refs.is_none() {
                if let Some(ref pr) = gateway_parent_ref {
                    route.spec.parent_refs = Some(vec![pr.clone()]);
                }
            }
            route
        })
        .collect();

    CompiledRouting {
        model_server,
        model_routes,
        gateway,
        certificate,
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
                    LABEL_MANAGED_BY.to_string(),
                    LABEL_MANAGED_BY_LATTICE.to_string(),
                ),
                (LABEL_NAME.to_string(), name.to_string()),
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
                    LABEL_MANAGED_BY.to_string(),
                    LABEL_MANAGED_BY_LATTICE.to_string(),
                ),
                (LABEL_NAME.to_string(), name.to_string()),
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

/// Compile a ModelIngressSpec into a Gateway + optional Certificate.
///
/// The Gateway gets HTTPS listeners for each hostname. The Certificate is
/// created only when TLS uses cert-manager auto mode (issuerRef).
fn compile_ingress_gateway(
    model_name: &str,
    namespace: &str,
    ingress: &ModelIngressSpec,
) -> (Gateway, Option<Certificate>) {
    let gateway_name = mesh::ingress_gateway_name(namespace);
    let listen_port = ingress.listen_port();
    let secret_name = format!("{}-tls", model_name);

    let listeners: Vec<GatewayListener> = ingress
        .hosts
        .iter()
        .enumerate()
        .map(|(i, host)| {
            let listener_name = format!("{}-https-{}", model_name, i);
            let tls_config = ingress.tls.as_ref().map(|tls| {
                let cert_ref_name = if tls.is_auto() {
                    secret_name.clone()
                } else if let Some(ref sn) = tls.secret_name {
                    sn.clone()
                } else {
                    secret_name.clone()
                };
                GatewayTlsConfig {
                    mode: "Terminate".to_string(),
                    certificate_refs: vec![CertificateRef {
                        kind: None,
                        name: cert_ref_name,
                    }],
                }
            });

            GatewayListener {
                name: listener_name,
                hostname: Some(host.clone()),
                port: listen_port,
                protocol: if tls_config.is_some() {
                    "HTTPS".to_string()
                } else {
                    "HTTP".to_string()
                },
                tls: tls_config,
                allowed_routes: Some(AllowedRoutes::same_namespace()),
            }
        })
        .collect();

    let metadata = lattice_common::kube_utils::ObjectMeta::new(&gateway_name, namespace);
    let gateway = Gateway::new(
        metadata,
        GatewaySpec {
            gateway_class_name: ingress.gateway_class().to_string(),
            listeners,
            tls: None,
        },
    )
    .with_external_dns(&ingress.hosts);

    let certificate = ingress
        .tls
        .as_ref()
        .and_then(|tls| tls.issuer_ref.as_ref())
        .map(|issuer_ref| Certificate {
            api_version: "cert-manager.io/v1".to_string(),
            kind: "Certificate".to_string(),
            metadata: lattice_common::kube_utils::ObjectMeta::new(
                format!("{}-cert", model_name),
                namespace,
            ),
            spec: lattice_common::network::gateway_api::CertificateSpec {
                secret_name: secret_name.clone(),
                dns_names: ingress.hosts.clone(),
                issuer_ref: IssuerRef {
                    name: issuer_ref.name.clone(),
                    kind: issuer_ref
                        .kind
                        .clone()
                        .unwrap_or_else(|| "ClusterIssuer".to_string()),
                    group: Some("cert-manager.io".to_string()),
                },
            },
        });

    (gateway, certificate)
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
    use lattice_common::crd::workload::ingress::{CertIssuerRef, IngressTls};
    use lattice_common::crd::{
        HeaderMatchValue, InferenceEngine, KvConnector, KvConnectorType, LatticeModelSpec,
        ModelIngressSpec, ModelMatch, ModelParentRef, ModelRoleSpec, ModelRouteRule,
        ModelRouteSpec, ModelRoutingSpec, RateLimit, RateLimitUnit, RuntimeSpec, TargetModel,
        TrafficPolicy, WorkloadSpec,
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
            replicas: Some(replicas),
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

        let compiled = compile_model_routing(&model, &routing, "test-model-test", None);

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
            port: None,
        });

        let compiled = compile_model_routing(&model, &routing, "test-model-test", None);

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

        let compiled = compile_model_routing(&model, &routing, "test-model-test", None);
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
            port: None,
        });

        let compiled = compile_model_routing(&model, &routing, "test-model-test", None);
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

        let compiled = compile_model_routing(&model, &routing, "test-model-test", None);
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

        let compiled = compile_model_routing(&model, &routing, "test-model-test", None);

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

        let compiled = compile_model_routing(&model, &routing, "test-model-test", None);
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

        let compiled = compile_model_routing(&model, &routing, "test-model-test", None);

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

        let compiled = compile_model_routing(&model, &routing, "test-model-test", None);

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

        let compiled = compile_model_routing(&model, &routing, "test-model-test", None);
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
            port: None,
        });

        let compiled = compile_model_routing(&model, &routing, "test-model-test", None);
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

        let compiled = compile_model_routing(&model, &routing, "test-model-test", None);
        assert_eq!(
            compiled.model_server.spec.workload_selector.match_labels[MODEL_SERVING_LABEL],
            "test-model-test"
        );
    }

    // ========================================================================
    // Ingress Tests
    // ========================================================================

    fn basic_ingress() -> ModelIngressSpec {
        ModelIngressSpec {
            hosts: vec!["llama-70b.us-east.lattice.gpu".to_string()],
            tls: Some(IngressTls {
                secret_name: None,
                issuer_ref: Some(CertIssuerRef {
                    name: "letsencrypt-prod".to_string(),
                    kind: None,
                }),
            }),
            gateway_class: None,
            listen_port: None,
        }
    }

    #[test]
    fn no_ingress_produces_no_gateway() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = basic_routing();

        let compiled = compile_model_routing(&model, &routing, "test-model-test", None);

        assert!(compiled.gateway.is_none());
        assert!(compiled.certificate.is_none());
        assert!(compiled.model_routes[0].spec.parent_refs.is_none());
    }

    #[test]
    fn ingress_creates_gateway_with_listeners() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = basic_routing();
        let ingress = basic_ingress();

        let compiled = compile_model_routing(&model, &routing, "test-model-test", Some(&ingress));

        let gateway = compiled.gateway.as_ref().expect("gateway should be set");
        assert_eq!(gateway.spec.gateway_class_name, "istio");
        assert_eq!(gateway.spec.listeners.len(), 1);

        let listener = &gateway.spec.listeners[0];
        assert_eq!(
            listener.hostname,
            Some("llama-70b.us-east.lattice.gpu".to_string())
        );
        assert_eq!(listener.port, 443);
        assert_eq!(listener.protocol, "HTTPS");
        assert!(listener.tls.is_some());
    }

    #[test]
    fn ingress_creates_certificate_for_auto_tls() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = basic_routing();
        let ingress = basic_ingress();

        let compiled = compile_model_routing(&model, &routing, "test-model-test", Some(&ingress));

        let cert = compiled
            .certificate
            .as_ref()
            .expect("certificate should be set");
        assert_eq!(cert.spec.dns_names, vec!["llama-70b.us-east.lattice.gpu"]);
        assert_eq!(cert.spec.issuer_ref.name, "letsencrypt-prod");
        assert_eq!(cert.spec.issuer_ref.kind, "ClusterIssuer");
        assert_eq!(cert.spec.secret_name, "test-model-tls");
    }

    #[test]
    fn ingress_no_certificate_for_manual_tls() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = basic_routing();
        let ingress = ModelIngressSpec {
            hosts: vec!["llama.lattice.gpu".to_string()],
            tls: Some(IngressTls {
                secret_name: Some("my-tls-secret".to_string()),
                issuer_ref: None,
            }),
            gateway_class: None,
            listen_port: None,
        };

        let compiled = compile_model_routing(&model, &routing, "test-model-test", Some(&ingress));

        assert!(compiled.gateway.is_some());
        assert!(compiled.certificate.is_none());

        let listener = &compiled.gateway.as_ref().unwrap().spec.listeners[0];
        let tls = listener.tls.as_ref().unwrap();
        assert_eq!(tls.certificate_refs[0].name, "my-tls-secret");
    }

    #[test]
    fn ingress_auto_injects_parent_refs_on_model_routes() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = basic_routing();
        let ingress = basic_ingress();

        let compiled = compile_model_routing(&model, &routing, "test-model-test", Some(&ingress));

        let route = &compiled.model_routes[0];
        let parent_refs = route
            .spec
            .parent_refs
            .as_ref()
            .expect("parentRefs should be set");
        assert_eq!(parent_refs.len(), 1);
        assert_eq!(parent_refs[0].name, "default-ingress");
        assert_eq!(parent_refs[0].kind, Some("Gateway".to_string()));
    }

    #[test]
    fn ingress_does_not_override_explicit_parent_refs() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let mut routing = basic_routing();

        // Set explicit parentRefs on the route
        routing.routes.get_mut("default").unwrap().parent_refs = Some(vec![ModelParentRef {
            name: "custom-gateway".to_string(),
            namespace: Some("custom-ns".to_string()),
            kind: None,
        }]);

        let ingress = basic_ingress();

        let compiled = compile_model_routing(&model, &routing, "test-model-test", Some(&ingress));

        let route = &compiled.model_routes[0];
        let parent_refs = route.spec.parent_refs.as_ref().unwrap();
        assert_eq!(parent_refs.len(), 1);
        assert_eq!(parent_refs[0].name, "custom-gateway");
    }

    #[test]
    fn ingress_external_dns_annotation_on_gateway() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = basic_routing();
        let ingress = ModelIngressSpec {
            hosts: vec![
                "llama.lattice.gpu".to_string(),
                "llama.us-east.lattice.gpu".to_string(),
            ],
            tls: None,
            gateway_class: None,
            listen_port: None,
        };

        let compiled = compile_model_routing(&model, &routing, "test-model-test", Some(&ingress));

        let gw = compiled.gateway.as_ref().unwrap();
        let dns_annotation = gw
            .metadata
            .annotations
            .get("external-dns.alpha.kubernetes.io/hostname")
            .expect("external-dns annotation should be set");
        assert_eq!(
            dns_annotation,
            "llama.lattice.gpu,llama.us-east.lattice.gpu"
        );
    }

    #[test]
    fn ingress_multiple_hosts_create_multiple_listeners() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = basic_routing();
        let ingress = ModelIngressSpec {
            hosts: vec![
                "a.lattice.gpu".to_string(),
                "b.lattice.gpu".to_string(),
                "c.lattice.gpu".to_string(),
            ],
            tls: Some(IngressTls {
                secret_name: None,
                issuer_ref: Some(CertIssuerRef {
                    name: "letsencrypt".to_string(),
                    kind: None,
                }),
            }),
            gateway_class: None,
            listen_port: None,
        };

        let compiled = compile_model_routing(&model, &routing, "test-model-test", Some(&ingress));

        let gw = compiled.gateway.as_ref().unwrap();
        assert_eq!(gw.spec.listeners.len(), 3);
        assert_eq!(
            gw.spec.listeners[0].hostname,
            Some("a.lattice.gpu".to_string())
        );
        assert_eq!(
            gw.spec.listeners[1].hostname,
            Some("b.lattice.gpu".to_string())
        );
        assert_eq!(
            gw.spec.listeners[2].hostname,
            Some("c.lattice.gpu".to_string())
        );

        let cert = compiled.certificate.as_ref().unwrap();
        assert_eq!(cert.spec.dns_names.len(), 3);
    }

    #[test]
    fn ingress_custom_gateway_class_and_port() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = basic_routing();
        let ingress = ModelIngressSpec {
            hosts: vec!["model.example.com".to_string()],
            tls: None,
            gateway_class: Some("nginx".to_string()),
            listen_port: Some(8443),
        };

        let compiled = compile_model_routing(&model, &routing, "test-model-test", Some(&ingress));

        let gw = compiled.gateway.as_ref().unwrap();
        assert_eq!(gw.spec.gateway_class_name, "nginx");
        assert_eq!(gw.spec.listeners[0].port, 8443);
        assert_eq!(gw.spec.listeners[0].protocol, "HTTP");
    }

    #[test]
    fn ingress_no_tls_uses_http_protocol() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));
        let routing = basic_routing();
        let ingress = ModelIngressSpec {
            hosts: vec!["model.internal".to_string()],
            tls: None,
            gateway_class: None,
            listen_port: None,
        };

        let compiled = compile_model_routing(&model, &routing, "test-model-test", Some(&ingress));

        let listener = &compiled.gateway.as_ref().unwrap().spec.listeners[0];
        assert_eq!(listener.protocol, "HTTP");
        assert!(listener.tls.is_none());
        assert!(compiled.certificate.is_none());
    }
}
