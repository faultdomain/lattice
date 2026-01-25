//! Cluster Autoscaler manifests
//!
//! Generates CAPI-provider cluster-autoscaler deployment for self-managing clusters.
//! Only deployed when at least one worker pool has autoscaling enabled (min/max set).

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy};
use k8s_openapi::api::core::v1::{
    Container, PodSpec, PodTemplateSpec, ResourceRequirements, ServiceAccount,
};
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, PolicyRule, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};

/// Cluster autoscaler version
const AUTOSCALER_VERSION: &str = "v1.31.0";

/// Namespace for autoscaler deployment
const AUTOSCALER_NAMESPACE: &str = "lattice-system";

fn labels() -> BTreeMap<String, String> {
    BTreeMap::from([("app".to_string(), "cluster-autoscaler".to_string())])
}

fn service_account() -> ServiceAccount {
    ServiceAccount {
        metadata: ObjectMeta {
            name: Some("cluster-autoscaler".to_string()),
            namespace: Some(AUTOSCALER_NAMESPACE.to_string()),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn cluster_role() -> ClusterRole {
    ClusterRole {
        metadata: ObjectMeta {
            name: Some("cluster-autoscaler".to_string()),
            ..Default::default()
        },
        rules: Some(vec![
            // CAPI resources
            PolicyRule {
                api_groups: Some(vec!["cluster.x-k8s.io".to_string()]),
                resources: Some(vec![
                    "machinedeployments".to_string(),
                    "machinedeployments/scale".to_string(),
                    "machinesets".to_string(),
                    "machinesets/scale".to_string(),
                    "machinepools".to_string(),
                    "machinepools/scale".to_string(),
                ]),
                verbs: vec![
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "patch".to_string(),
                    "update".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["cluster.x-k8s.io".to_string()]),
                resources: Some(vec!["machines".to_string()]),
                verbs: vec![
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "delete".to_string(),
                ],
                ..Default::default()
            },
            // Core resources (read)
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec![
                    "nodes".to_string(),
                    "pods".to_string(),
                    "services".to_string(),
                    "replicationcontrollers".to_string(),
                    "persistentvolumeclaims".to_string(),
                    "persistentvolumes".to_string(),
                    "namespaces".to_string(),
                ]),
                verbs: vec![
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                ],
                ..Default::default()
            },
            // Node management
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["nodes".to_string()]),
                verbs: vec![
                    "delete".to_string(),
                    "patch".to_string(),
                    "update".to_string(),
                ],
                ..Default::default()
            },
            // Apps resources
            PolicyRule {
                api_groups: Some(vec!["apps".to_string()]),
                resources: Some(vec![
                    "daemonsets".to_string(),
                    "replicasets".to_string(),
                    "statefulsets".to_string(),
                ]),
                verbs: vec![
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                ],
                ..Default::default()
            },
            // PDB
            PolicyRule {
                api_groups: Some(vec!["policy".to_string()]),
                resources: Some(vec!["poddisruptionbudgets".to_string()]),
                verbs: vec![
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                ],
                ..Default::default()
            },
            // Events
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["events".to_string()]),
                verbs: vec!["create".to_string(), "patch".to_string()],
                ..Default::default()
            },
            // Leader election
            PolicyRule {
                api_groups: Some(vec!["coordination.k8s.io".to_string()]),
                resources: Some(vec!["leases".to_string()]),
                verbs: vec![
                    "get".to_string(),
                    "create".to_string(),
                    "update".to_string(),
                ],
                ..Default::default()
            },
        ]),
        ..Default::default()
    }
}

fn cluster_role_binding() -> ClusterRoleBinding {
    ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some("cluster-autoscaler".to_string()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: "cluster-autoscaler".to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: "cluster-autoscaler".to_string(),
            namespace: Some(AUTOSCALER_NAMESPACE.to_string()),
            ..Default::default()
        }]),
    }
}

fn deployment(capi_namespace: &str) -> Deployment {
    let image = format!(
        "registry.k8s.io/autoscaling/cluster-autoscaler:{}",
        AUTOSCALER_VERSION
    );

    Deployment {
        metadata: ObjectMeta {
            name: Some("cluster-autoscaler".to_string()),
            namespace: Some(AUTOSCALER_NAMESPACE.to_string()),
            labels: Some(labels()),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: Some(labels()),
                ..Default::default()
            },
            strategy: Some(DeploymentStrategy {
                type_: Some("Recreate".to_string()),
                ..Default::default()
            }),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels()),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    service_account_name: Some("cluster-autoscaler".to_string()),
                    priority_class_name: Some("system-cluster-critical".to_string()),
                    containers: vec![Container {
                        name: "cluster-autoscaler".to_string(),
                        image: Some(image),
                        command: Some(vec![
                            "/cluster-autoscaler".to_string(),
                            "--cloud-provider=clusterapi".to_string(),
                            format!("--node-group-auto-discovery=clusterapi:namespace={}", capi_namespace),
                            "--scale-down-delay-after-add=5m".to_string(),
                            "--scale-down-unneeded-time=5m".to_string(),
                            "--skip-nodes-with-local-storage=false".to_string(),
                            "--v=2".to_string(),
                        ]),
                        resources: Some(ResourceRequirements {
                            requests: Some(BTreeMap::from([
                                ("cpu".to_string(), Quantity("100m".to_string())),
                                ("memory".to_string(), Quantity("300Mi".to_string())),
                            ])),
                            limits: Some(BTreeMap::from([
                                ("memory".to_string(), Quantity("600Mi".to_string())),
                            ])),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Generate cluster-autoscaler manifests for CAPI-managed clusters.
///
/// The autoscaler uses in-cluster config for both CAPI and workload APIs
/// since post-pivot clusters are self-managing.
pub fn generate_autoscaler_manifests(capi_namespace: &str) -> String {
    let resources: Vec<String> = vec![
        serde_yaml::to_string(&service_account()).expect("ServiceAccount serialization"),
        serde_yaml::to_string(&cluster_role()).expect("ClusterRole serialization"),
        serde_yaml::to_string(&cluster_role_binding()).expect("ClusterRoleBinding serialization"),
        serde_yaml::to_string(&deployment(capi_namespace)).expect("Deployment serialization"),
    ];
    resources.join("---\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_yaml() {
        let yaml = generate_autoscaler_manifests("capi-test");
        assert!(yaml.contains("cluster-autoscaler"));
        assert!(yaml.contains("ServiceAccount"));
        assert!(yaml.contains("ClusterRole"));
        assert!(yaml.contains("Deployment"));
    }

    #[test]
    fn deployment_uses_correct_namespace_discovery() {
        let yaml = generate_autoscaler_manifests("capi-my-cluster");
        assert!(yaml.contains("--node-group-auto-discovery=clusterapi:namespace=capi-my-cluster"));
    }

    #[test]
    fn deployment_has_priority_class() {
        let yaml = generate_autoscaler_manifests("capi-test");
        assert!(yaml.contains("system-cluster-critical"));
    }

    #[test]
    fn cluster_role_has_capi_permissions() {
        let role = cluster_role();
        let rules = role.rules.unwrap();

        let capi_rule = rules.iter().find(|r| {
            r.api_groups.as_ref().map(|g| g.contains(&"cluster.x-k8s.io".to_string())).unwrap_or(false)
        });

        assert!(capi_rule.is_some());
        let resources = capi_rule.unwrap().resources.as_ref().unwrap();
        assert!(resources.contains(&"machinedeployments".to_string()));
        assert!(resources.contains(&"machinedeployments/scale".to_string()));
    }
}
