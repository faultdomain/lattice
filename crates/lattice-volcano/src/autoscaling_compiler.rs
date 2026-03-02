//! Autoscaling compiler for LatticeModel roles
//!
//! Compiles per-role `AutoscalingSpec` into Kthena `AutoscalingPolicy` +
//! `AutoscalingPolicyBinding` resources in the `workload.serving.volcano.sh/v1alpha1`
//! API group.

use std::collections::BTreeMap;

use lattice_common::crd::LatticeModel;

use crate::routing_compiler::owner_reference;
use crate::types::{
    KthenaAutoscalingBehavior, KthenaAutoscalingMetric, KthenaAutoscalingPolicy,
    KthenaAutoscalingPolicyBinding, KthenaAutoscalingPolicyBindingSpec,
    KthenaAutoscalingPolicySpec, KthenaAutoscalingTarget, KthenaHomogeneousTarget,
    KthenaMetricEndpoint, KthenaPanicPolicy, KthenaPolicyRef, KthenaScaleDownBehavior,
    KthenaScaleUpBehavior, KthenaStablePolicy, KthenaSubTarget, KthenaTargetRef, VolcanoMetadata,
};

const WORKLOAD_API_VERSION: &str = "workload.serving.volcano.sh/v1alpha1";

/// Compiled autoscaling resources for a LatticeModel
#[derive(Debug)]
pub struct CompiledAutoscaling {
    pub policies: Vec<KthenaAutoscalingPolicy>,
    pub bindings: Vec<KthenaAutoscalingPolicyBinding>,
}

/// Format an f64 as a Kubernetes resource.Quantity string.
///
/// Integers are rendered without a decimal point (e.g. `5.0` → `"5"`),
/// floats keep their decimal representation (e.g. `0.8` → `"0.8"`).
fn format_quantity(v: f64) -> String {
    if v.fract() == 0.0 {
        format!("{}", v as i64)
    } else {
        format!("{}", v)
    }
}

/// Compile autoscaling resources from a LatticeModel's per-role autoscaling specs.
///
/// For each role with `autoscaling: Some(...)`, generates:
/// - A `KthenaAutoscalingPolicy` named `{model}-{role}-scaling`
/// - A `KthenaAutoscalingPolicyBinding` named `{model}-{role}-scaling`
///   that targets the ModelServing `{model}` with subTarget `Role` / `{role}`
pub fn compile_model_autoscaling(model: &LatticeModel) -> CompiledAutoscaling {
    let name = model.metadata.name.as_deref().unwrap_or_default();
    let namespace = model.metadata.namespace.as_deref().unwrap_or("default");
    let uid = model.metadata.uid.as_deref().unwrap_or_default();

    let mut policies = Vec::new();
    let mut bindings = Vec::new();

    for (role_name, role_spec) in &model.spec.roles {
        let autoscaling = match &role_spec.autoscaling {
            Some(a) => a,
            None => continue,
        };

        let resource_name = format!("{}-{}-scaling", name, role_name);

        let metrics: Vec<KthenaAutoscalingMetric> = autoscaling
            .metrics
            .iter()
            .map(|m| KthenaAutoscalingMetric {
                metric_name: m.metric.clone(),
                target_value: format_quantity(m.target),
            })
            .collect();

        let behavior = autoscaling
            .behavior
            .as_ref()
            .map(|b| KthenaAutoscalingBehavior {
                scale_up: b.scale_up.as_ref().map(|su| {
                    let panic_policy =
                        if su.panic_threshold_percent.is_some() || su.panic_mode_hold.is_some() {
                            Some(KthenaPanicPolicy {
                                period: su.period.clone().unwrap_or_else(|| "30s".to_string()),
                                panic_threshold_percent: su.panic_threshold_percent,
                                panic_mode_hold: su.panic_mode_hold.clone(),
                            })
                        } else {
                            None
                        };

                    let stable_policy = if su.stabilization_window.is_some() || su.period.is_some()
                    {
                        Some(KthenaStablePolicy {
                            stabilization_window: su.stabilization_window.clone(),
                            period: su.period.clone(),
                        })
                    } else {
                        None
                    };

                    KthenaScaleUpBehavior {
                        panic_policy,
                        stable_policy,
                    }
                }),
                scale_down: b.scale_down.as_ref().map(|sd| KthenaScaleDownBehavior {
                    stabilization_window: sd.stabilization_window.clone(),
                    period: sd.period.clone(),
                }),
            });

        let metadata = VolcanoMetadata {
            name: resource_name.clone(),
            namespace: namespace.to_string(),
            labels: BTreeMap::from([
                (
                    "app.kubernetes.io/managed-by".to_string(),
                    "lattice".to_string(),
                ),
                ("app.kubernetes.io/name".to_string(), name.to_string()),
            ]),
            owner_references: vec![owner_reference(name, uid)],
        };

        let policy = KthenaAutoscalingPolicy {
            api_version: WORKLOAD_API_VERSION.to_string(),
            kind: "AutoscalingPolicy".to_string(),
            metadata: metadata.clone(),
            spec: KthenaAutoscalingPolicySpec {
                metrics,
                tolerance_percent: autoscaling.tolerance_percent,
                behavior,
            },
        };

        let metric_endpoint = role_spec
            .entry_workload
            .service
            .as_ref()
            .and_then(|svc| svc.ports.get("metrics"))
            .map(|port_spec| KthenaMetricEndpoint {
                uri: Some("/metrics".to_string()),
                port: Some(port_spec.port),
            });

        let binding = KthenaAutoscalingPolicyBinding {
            api_version: WORKLOAD_API_VERSION.to_string(),
            kind: "AutoscalingPolicyBinding".to_string(),
            metadata,
            spec: KthenaAutoscalingPolicyBindingSpec {
                policy_ref: KthenaPolicyRef {
                    name: resource_name,
                },
                homogeneous_target: KthenaHomogeneousTarget {
                    target: KthenaAutoscalingTarget {
                        target_ref: KthenaTargetRef {
                            kind: "ModelServing".to_string(),
                            name: name.to_string(),
                        },
                        sub_targets: Some(KthenaSubTarget {
                            kind: "Role".to_string(),
                            name: role_name.clone(),
                        }),
                        metric_endpoint,
                    },
                    min_replicas: role_spec.replicas(),
                    max_replicas: autoscaling.max,
                },
            },
        };

        policies.push(policy);
        bindings.push(binding);
    }

    CompiledAutoscaling { policies, bindings }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{
        AutoscalingMetric, LatticeModelSpec, ModelAutoscalingBehavior, ModelAutoscalingSpec,
        ModelRoleSpec, ModelScaleDownBehavior, ModelScaleUpBehavior, PortSpec, RuntimeSpec,
        ServicePortsSpec, WorkloadSpec,
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
        make_role_with_service(replicas, None)
    }

    fn make_role_with_service(replicas: u32, service: Option<ServicePortsSpec>) -> ModelRoleSpec {
        ModelRoleSpec {
            replicas: Some(replicas),
            entry_workload: WorkloadSpec {
                service,
                ..Default::default()
            },
            entry_runtime: RuntimeSpec::default(),
            worker_replicas: None,
            worker_workload: None,
            worker_runtime: None,
            autoscaling: None,
        }
    }

    fn basic_autoscaling() -> ModelAutoscalingSpec {
        ModelAutoscalingSpec {
            max: 10,
            metrics: vec![AutoscalingMetric {
                metric: "gpu_kv_cache_usage".to_string(),
                target: 0.8,
            }],
            tolerance_percent: Some(10),
            behavior: None,
        }
    }

    #[test]
    fn no_autoscaling_produces_empty() {
        let model = test_model(BTreeMap::from([("decode".to_string(), make_role(2))]));

        let compiled = compile_model_autoscaling(&model);
        assert!(compiled.policies.is_empty());
        assert!(compiled.bindings.is_empty());
    }

    #[test]
    fn single_role_autoscaling() {
        let mut role = make_role(2);
        role.autoscaling = Some(basic_autoscaling());

        let model = test_model(BTreeMap::from([("decode".to_string(), role)]));
        let compiled = compile_model_autoscaling(&model);

        assert_eq!(compiled.policies.len(), 1);
        assert_eq!(compiled.bindings.len(), 1);

        let policy = &compiled.policies[0];
        assert_eq!(policy.metadata.name, "test-model-decode-scaling");
        assert_eq!(policy.api_version, WORKLOAD_API_VERSION);
        assert_eq!(policy.kind, "AutoscalingPolicy");
        assert_eq!(policy.spec.metrics.len(), 1);
        assert_eq!(policy.spec.metrics[0].metric_name, "gpu_kv_cache_usage");
        assert_eq!(policy.spec.metrics[0].target_value, "0.8");
        assert_eq!(policy.spec.tolerance_percent, Some(10));

        let binding = &compiled.bindings[0];
        assert_eq!(binding.metadata.name, "test-model-decode-scaling");
        assert_eq!(binding.kind, "AutoscalingPolicyBinding");
        assert_eq!(binding.spec.policy_ref.name, "test-model-decode-scaling");
        assert_eq!(
            binding.spec.homogeneous_target.target.target_ref.kind,
            "ModelServing"
        );
        assert_eq!(
            binding.spec.homogeneous_target.target.target_ref.name,
            "test-model"
        );
        let sub = binding
            .spec
            .homogeneous_target
            .target
            .sub_targets
            .as_ref()
            .unwrap();
        assert_eq!(sub.kind, "Role");
        assert_eq!(sub.name, "decode");
        assert_eq!(binding.spec.homogeneous_target.min_replicas, 2);
        assert_eq!(binding.spec.homogeneous_target.max_replicas, 10);
    }

    #[test]
    fn multi_role_autoscaling() {
        let mut prefill = make_role(1);
        prefill.autoscaling = Some(ModelAutoscalingSpec {
            max: 4,
            metrics: vec![AutoscalingMetric {
                metric: "prefill_queue_depth".to_string(),
                target: 5.0,
            }],
            tolerance_percent: None,
            behavior: None,
        });

        let mut decode = make_role(4);
        decode.autoscaling = Some(basic_autoscaling());

        let model = test_model(BTreeMap::from([
            ("decode".to_string(), decode),
            ("prefill".to_string(), prefill),
        ]));

        let compiled = compile_model_autoscaling(&model);
        assert_eq!(compiled.policies.len(), 2);
        assert_eq!(compiled.bindings.len(), 2);

        // BTreeMap orders alphabetically: decode, prefill
        assert_eq!(
            compiled.policies[0].metadata.name,
            "test-model-decode-scaling"
        );
        assert_eq!(
            compiled.policies[1].metadata.name,
            "test-model-prefill-scaling"
        );
    }

    #[test]
    fn mixed_roles_only_autoscaled_roles_produce_resources() {
        let mut decode = make_role(2);
        decode.autoscaling = Some(basic_autoscaling());
        let prefill = make_role(1); // no autoscaling

        let model = test_model(BTreeMap::from([
            ("decode".to_string(), decode),
            ("prefill".to_string(), prefill),
        ]));

        let compiled = compile_model_autoscaling(&model);
        assert_eq!(compiled.policies.len(), 1);
        assert_eq!(
            compiled.policies[0].metadata.name,
            "test-model-decode-scaling"
        );
    }

    #[test]
    fn behavior_with_panic_mode() {
        let mut role = make_role(2);
        role.autoscaling = Some(ModelAutoscalingSpec {
            max: 20,
            metrics: vec![AutoscalingMetric {
                metric: "requests_per_second".to_string(),
                target: 100.0,
            }],
            tolerance_percent: None,
            behavior: Some(ModelAutoscalingBehavior {
                scale_up: Some(ModelScaleUpBehavior {
                    panic_threshold_percent: Some(200),
                    panic_mode_hold: Some("5m".to_string()),
                    stabilization_window: Some("1m".to_string()),
                    period: Some("30s".to_string()),
                }),
                scale_down: Some(ModelScaleDownBehavior {
                    stabilization_window: Some("5m".to_string()),
                    period: Some("1m".to_string()),
                }),
            }),
        });

        let model = test_model(BTreeMap::from([("decode".to_string(), role)]));
        let compiled = compile_model_autoscaling(&model);

        let behavior = compiled.policies[0].spec.behavior.as_ref().unwrap();
        let scale_up = behavior.scale_up.as_ref().unwrap();
        let panic = scale_up.panic_policy.as_ref().unwrap();
        assert_eq!(panic.panic_threshold_percent, Some(200));
        assert_eq!(panic.panic_mode_hold, Some("5m".to_string()));

        let stable = scale_up.stable_policy.as_ref().unwrap();
        assert_eq!(stable.stabilization_window, Some("1m".to_string()));
        assert_eq!(stable.period, Some("30s".to_string()));

        let scale_down = behavior.scale_down.as_ref().unwrap();
        assert_eq!(scale_down.stabilization_window, Some("5m".to_string()));
    }

    #[test]
    fn metrics_port_discovered_from_service() {
        let mut ports = BTreeMap::new();
        ports.insert(
            "metrics".to_string(),
            PortSpec {
                port: 9090,
                target_port: None,
                protocol: None,
            },
        );
        let mut role = make_role_with_service(2, Some(ServicePortsSpec { ports }));
        role.autoscaling = Some(ModelAutoscalingSpec {
            max: 5,
            metrics: vec![AutoscalingMetric {
                metric: "custom_metric".to_string(),
                target: 50.0,
            }],
            tolerance_percent: None,
            behavior: None,
        });

        let model = test_model(BTreeMap::from([("decode".to_string(), role)]));
        let compiled = compile_model_autoscaling(&model);

        let ep = compiled.bindings[0]
            .spec
            .homogeneous_target
            .target
            .metric_endpoint
            .as_ref()
            .unwrap();
        assert_eq!(ep.uri, Some("/metrics".to_string()));
        assert_eq!(ep.port, Some(9090));
    }

    #[test]
    fn owner_references_set() {
        let mut role = make_role(2);
        role.autoscaling = Some(basic_autoscaling());

        let model = test_model(BTreeMap::from([("decode".to_string(), role)]));
        let compiled = compile_model_autoscaling(&model);

        let oref = &compiled.policies[0].metadata.owner_references[0];
        assert_eq!(oref.kind, "LatticeModel");
        assert_eq!(oref.name, "test-model");
        assert_eq!(oref.uid, "uid-123");
        assert_eq!(oref.controller, Some(true));

        let boref = &compiled.bindings[0].metadata.owner_references[0];
        assert_eq!(boref.kind, "LatticeModel");
        assert_eq!(boref.name, "test-model");
    }

    #[test]
    fn no_metric_endpoint_when_no_metrics_port() {
        let mut role = make_role(2);
        role.autoscaling = Some(basic_autoscaling());

        let model = test_model(BTreeMap::from([("decode".to_string(), role)]));
        let compiled = compile_model_autoscaling(&model);

        assert!(compiled.bindings[0]
            .spec
            .homogeneous_target
            .target
            .metric_endpoint
            .is_none());
    }
}
