//! AWS-specific addon manifests
//!
//! Generates AWS Cloud Controller Manager (CCM) and EBS CSI Driver manifests
//! using typed k8s_openapi structs for type safety and maintainability.

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{
    DaemonSet, DaemonSetSpec, DaemonSetUpdateStrategy, Deployment, DeploymentSpec,
    RollingUpdateDaemonSet,
};
use k8s_openapi::api::core::v1::{
    Affinity, Container, ContainerPort, EnvVar, EnvVarSource, HTTPGetAction, HostPathVolumeSource,
    NodeAffinity, NodeSelector, NodeSelectorRequirement, NodeSelectorTerm, PodSpec,
    PodTemplateSpec, Probe, ResourceRequirements, Secret, SecretKeySelector, SecurityContext,
    ServiceAccount, Toleration, Volume, VolumeMount,
};
use k8s_openapi::api::policy::v1::{PodDisruptionBudget, PodDisruptionBudgetSpec};
use k8s_openapi::api::rbac::v1::{
    ClusterRole, ClusterRoleBinding, PolicyRule, RoleBinding, RoleRef, Subject,
};
use k8s_openapi::api::storage::v1::{CSIDriver, CSIDriverSpec, StorageClass};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

/// AWS EBS CSI Driver version (not tied to Kubernetes version)
const AWS_EBS_CSI_VERSION: &str = "v1.54.0";

/// Convert Kubernetes version to CCM image tag.
/// CCM releases match Kubernetes versions. "1.32.0" -> "v1.32.0"
fn ccm_version_from_k8s(k8s_version: &str) -> String {
    let version = k8s_version.trim_start_matches('v');
    format!("v{version}")
}

// =============================================================================
// AWS Cloud Controller Manager
// =============================================================================

fn ccm_service_account() -> ServiceAccount {
    ServiceAccount {
        metadata: ObjectMeta {
            name: Some("cloud-controller-manager".to_string()),
            namespace: Some("kube-system".to_string()),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn ccm_role_binding() -> RoleBinding {
    RoleBinding {
        metadata: ObjectMeta {
            name: Some("cloud-controller-manager:apiserver-authentication-reader".to_string()),
            namespace: Some("kube-system".to_string()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "Role".to_string(),
            name: "extension-apiserver-authentication-reader".to_string(),
        },
        subjects: Some(vec![Subject {
            api_group: Some(String::new()),
            kind: "ServiceAccount".to_string(),
            name: "cloud-controller-manager".to_string(),
            namespace: Some("kube-system".to_string()),
        }]),
    }
}

fn ccm_cluster_role() -> ClusterRole {
    ClusterRole {
        metadata: ObjectMeta {
            name: Some("system:cloud-controller-manager".to_string()),
            ..Default::default()
        },
        rules: Some(vec![
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["events".to_string()]),
                verbs: vec![
                    "create".to_string(),
                    "patch".to_string(),
                    "update".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["nodes".to_string()]),
                verbs: vec!["*".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["nodes/status".to_string()]),
                verbs: vec!["patch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["services".to_string()]),
                verbs: vec![
                    "list".to_string(),
                    "patch".to_string(),
                    "update".to_string(),
                    "watch".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["services/status".to_string()]),
                verbs: vec![
                    "list".to_string(),
                    "patch".to_string(),
                    "update".to_string(),
                    "watch".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["serviceaccounts".to_string()]),
                verbs: vec![
                    "create".to_string(),
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["persistentvolumes".to_string()]),
                verbs: vec![
                    "get".to_string(),
                    "list".to_string(),
                    "update".to_string(),
                    "watch".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["configmaps".to_string()]),
                verbs: vec!["list".to_string(), "watch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["endpoints".to_string()]),
                verbs: vec![
                    "create".to_string(),
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "update".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["coordination.k8s.io".to_string()]),
                resources: Some(vec!["leases".to_string()]),
                verbs: vec![
                    "create".to_string(),
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "update".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["serviceaccounts/token".to_string()]),
                verbs: vec!["create".to_string()],
                ..Default::default()
            },
        ]),
        ..Default::default()
    }
}

fn ccm_cluster_role_binding() -> ClusterRoleBinding {
    ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some("system:cloud-controller-manager".to_string()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: "system:cloud-controller-manager".to_string(),
        },
        subjects: Some(vec![Subject {
            api_group: Some(String::new()),
            kind: "ServiceAccount".to_string(),
            name: "cloud-controller-manager".to_string(),
            namespace: Some("kube-system".to_string()),
        }]),
    }
}

fn ccm_daemonset(version: &str) -> DaemonSet {
    let labels = BTreeMap::from([(
        "k8s-app".to_string(),
        "aws-cloud-controller-manager".to_string(),
    )]);

    DaemonSet {
        metadata: ObjectMeta {
            name: Some("aws-cloud-controller-manager".to_string()),
            namespace: Some("kube-system".to_string()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        spec: Some(DaemonSetSpec {
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            update_strategy: Some(DaemonSetUpdateStrategy {
                type_: Some("RollingUpdate".to_string()),
                ..Default::default()
            }),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    node_selector: Some(BTreeMap::from([(
                        "node-role.kubernetes.io/control-plane".to_string(),
                        String::new(),
                    )])),
                    tolerations: Some(vec![
                        Toleration {
                            key: Some("node.cloudprovider.kubernetes.io/uninitialized".to_string()),
                            value: Some("true".to_string()),
                            effect: Some("NoSchedule".to_string()),
                            ..Default::default()
                        },
                        Toleration {
                            key: Some("node-role.kubernetes.io/control-plane".to_string()),
                            effect: Some("NoSchedule".to_string()),
                            ..Default::default()
                        },
                    ]),
                    affinity: Some(Affinity {
                        node_affinity: Some(NodeAffinity {
                            required_during_scheduling_ignored_during_execution: Some(
                                NodeSelector {
                                    node_selector_terms: vec![NodeSelectorTerm {
                                        match_expressions: Some(vec![NodeSelectorRequirement {
                                            key: "node-role.kubernetes.io/control-plane"
                                                .to_string(),
                                            operator: "Exists".to_string(),
                                            ..Default::default()
                                        }]),
                                        ..Default::default()
                                    }],
                                },
                            ),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    service_account_name: Some("cloud-controller-manager".to_string()),
                    containers: vec![Container {
                        name: "aws-cloud-controller-manager".to_string(),
                        image: Some(format!(
                            "registry.k8s.io/provider-aws/cloud-controller-manager:{version}"
                        )),
                        args: Some(vec![
                            "--v=2".to_string(),
                            "--cloud-provider=aws".to_string(),
                            "--use-service-account-credentials=true".to_string(),
                            "--configure-cloud-routes=false".to_string(),
                        ]),
                        resources: Some(ResourceRequirements {
                            requests: Some(BTreeMap::from([(
                                "cpu".to_string(),
                                k8s_openapi::apimachinery::pkg::api::resource::Quantity(
                                    "200m".to_string(),
                                ),
                            )])),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    host_network: Some(true),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

// =============================================================================
// AWS EBS CSI Driver
// =============================================================================

fn ebs_csi_secret() -> Secret {
    Secret {
        metadata: ObjectMeta {
            name: Some("aws-secret".to_string()),
            namespace: Some("kube-system".to_string()),
            ..Default::default()
        },
        string_data: Some(BTreeMap::from([
            ("key_id".to_string(), String::new()),
            ("access_key".to_string(), String::new()),
        ])),
        ..Default::default()
    }
}

fn ebs_csi_controller_service_account() -> ServiceAccount {
    ServiceAccount {
        metadata: ObjectMeta {
            name: Some("ebs-csi-controller-sa".to_string()),
            namespace: Some("kube-system".to_string()),
            labels: Some(BTreeMap::from([(
                "app.kubernetes.io/name".to_string(),
                "aws-ebs-csi-driver".to_string(),
            )])),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn ebs_csi_node_service_account() -> ServiceAccount {
    ServiceAccount {
        metadata: ObjectMeta {
            name: Some("ebs-csi-node-sa".to_string()),
            namespace: Some("kube-system".to_string()),
            labels: Some(BTreeMap::from([(
                "app.kubernetes.io/name".to_string(),
                "aws-ebs-csi-driver".to_string(),
            )])),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn ebs_csi_labels() -> BTreeMap<String, String> {
    BTreeMap::from([(
        "app.kubernetes.io/name".to_string(),
        "aws-ebs-csi-driver".to_string(),
    )])
}

fn ebs_csi_attacher_role() -> ClusterRole {
    ClusterRole {
        metadata: ObjectMeta {
            name: Some("ebs-external-attacher-role".to_string()),
            labels: Some(ebs_csi_labels()),
            ..Default::default()
        },
        rules: Some(vec![
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["persistentvolumes".to_string()]),
                verbs: vec![
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "update".to_string(),
                    "patch".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["nodes".to_string()]),
                verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["csi.storage.k8s.io".to_string()]),
                resources: Some(vec!["csinodeinfos".to_string()]),
                verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["storage.k8s.io".to_string()]),
                resources: Some(vec!["volumeattachments".to_string()]),
                verbs: vec![
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "update".to_string(),
                    "patch".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["storage.k8s.io".to_string()]),
                resources: Some(vec!["volumeattachments/status".to_string()]),
                verbs: vec!["patch".to_string()],
                ..Default::default()
            },
        ]),
        ..Default::default()
    }
}

fn ebs_csi_node_role() -> ClusterRole {
    ClusterRole {
        metadata: ObjectMeta {
            name: Some("ebs-csi-node".to_string()),
            labels: Some(ebs_csi_labels()),
            ..Default::default()
        },
        rules: Some(vec![
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["pods".to_string()]),
                verbs: vec!["get".to_string(), "patch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["nodes".to_string()]),
                verbs: vec!["get".to_string()],
                ..Default::default()
            },
        ]),
        ..Default::default()
    }
}

fn ebs_csi_provisioner_role() -> ClusterRole {
    ClusterRole {
        metadata: ObjectMeta {
            name: Some("ebs-external-provisioner-role".to_string()),
            labels: Some(ebs_csi_labels()),
            ..Default::default()
        },
        rules: Some(vec![
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["persistentvolumes".to_string()]),
                verbs: vec![
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "create".to_string(),
                    "delete".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["persistentvolumeclaims".to_string()]),
                verbs: vec![
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "update".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["storage.k8s.io".to_string()]),
                resources: Some(vec!["storageclasses".to_string()]),
                verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["events".to_string()]),
                verbs: vec![
                    "list".to_string(),
                    "watch".to_string(),
                    "create".to_string(),
                    "update".to_string(),
                    "patch".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["snapshot.storage.k8s.io".to_string()]),
                resources: Some(vec!["volumesnapshots".to_string()]),
                verbs: vec!["get".to_string(), "list".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["snapshot.storage.k8s.io".to_string()]),
                resources: Some(vec!["volumesnapshotcontents".to_string()]),
                verbs: vec!["get".to_string(), "list".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["storage.k8s.io".to_string()]),
                resources: Some(vec!["csinodes".to_string()]),
                verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["nodes".to_string()]),
                verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["coordination.k8s.io".to_string()]),
                resources: Some(vec!["leases".to_string()]),
                verbs: vec![
                    "get".to_string(),
                    "watch".to_string(),
                    "list".to_string(),
                    "delete".to_string(),
                    "update".to_string(),
                    "create".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["storage.k8s.io".to_string()]),
                resources: Some(vec!["volumeattachments".to_string()]),
                verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                ..Default::default()
            },
        ]),
        ..Default::default()
    }
}

fn ebs_csi_resizer_role() -> ClusterRole {
    ClusterRole {
        metadata: ObjectMeta {
            name: Some("ebs-external-resizer-role".to_string()),
            labels: Some(ebs_csi_labels()),
            ..Default::default()
        },
        rules: Some(vec![
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["persistentvolumes".to_string()]),
                verbs: vec![
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "update".to_string(),
                    "patch".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["persistentvolumeclaims".to_string()]),
                verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["persistentvolumeclaims/status".to_string()]),
                verbs: vec!["update".to_string(), "patch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["storage.k8s.io".to_string()]),
                resources: Some(vec!["storageclasses".to_string()]),
                verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["events".to_string()]),
                verbs: vec![
                    "list".to_string(),
                    "watch".to_string(),
                    "create".to_string(),
                    "update".to_string(),
                    "patch".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["pods".to_string()]),
                verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                ..Default::default()
            },
        ]),
        ..Default::default()
    }
}

fn ebs_csi_snapshotter_role() -> ClusterRole {
    ClusterRole {
        metadata: ObjectMeta {
            name: Some("ebs-external-snapshotter-role".to_string()),
            labels: Some(ebs_csi_labels()),
            ..Default::default()
        },
        rules: Some(vec![
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["events".to_string()]),
                verbs: vec![
                    "list".to_string(),
                    "watch".to_string(),
                    "create".to_string(),
                    "update".to_string(),
                    "patch".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["secrets".to_string()]),
                verbs: vec!["get".to_string(), "list".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["snapshot.storage.k8s.io".to_string()]),
                resources: Some(vec!["volumesnapshotclasses".to_string()]),
                verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["snapshot.storage.k8s.io".to_string()]),
                resources: Some(vec!["volumesnapshotcontents".to_string()]),
                verbs: vec![
                    "create".to_string(),
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["snapshot.storage.k8s.io".to_string()]),
                resources: Some(vec!["volumesnapshotcontents/status".to_string()]),
                verbs: vec!["update".to_string()],
                ..Default::default()
            },
        ]),
        ..Default::default()
    }
}

fn ebs_csi_cluster_role_binding(name: &str, role_name: &str) -> ClusterRoleBinding {
    ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(ebs_csi_labels()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: role_name.to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: "ebs-csi-controller-sa".to_string(),
            namespace: Some("kube-system".to_string()),
            ..Default::default()
        }]),
    }
}

fn ebs_csi_node_cluster_role_binding() -> ClusterRoleBinding {
    ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some("ebs-csi-node-binding".to_string()),
            labels: Some(ebs_csi_labels()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: "ebs-csi-node".to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: "ebs-csi-node-sa".to_string(),
            namespace: Some("kube-system".to_string()),
            ..Default::default()
        }]),
    }
}

fn secret_env_var(name: &str, key: &str) -> EnvVar {
    EnvVar {
        name: name.to_string(),
        value_from: Some(EnvVarSource {
            secret_key_ref: Some(SecretKeySelector {
                name: "aws-secret".to_string(),
                key: key.to_string(),
                optional: Some(true),
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn ebs_csi_controller_deployment(version: &str) -> Deployment {
    let labels = BTreeMap::from([
        ("app".to_string(), "ebs-csi-controller".to_string()),
        (
            "app.kubernetes.io/name".to_string(),
            "aws-ebs-csi-driver".to_string(),
        ),
    ]);

    Deployment {
        metadata: ObjectMeta {
            name: Some("ebs-csi-controller".to_string()),
            namespace: Some("kube-system".to_string()),
            labels: Some(ebs_csi_labels()),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(2),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![
                        Container {
                            name: "ebs-plugin".to_string(),
                            image: Some(format!(
                                "registry.k8s.io/provider-aws/aws-ebs-csi-driver:{version}"
                            )),
                            image_pull_policy: Some("IfNotPresent".to_string()),
                            args: Some(vec![
                                "--endpoint=$(CSI_ENDPOINT)".to_string(),
                                "--logtostderr".to_string(),
                                "--v=2".to_string(),
                            ]),
                            env: Some(vec![
                                EnvVar {
                                    name: "CSI_ENDPOINT".to_string(),
                                    value: Some(
                                        "unix:///var/lib/csi/sockets/pluginproxy/csi.sock"
                                            .to_string(),
                                    ),
                                    ..Default::default()
                                },
                                EnvVar {
                                    name: "CSI_NODE_NAME".to_string(),
                                    value_from: Some(EnvVarSource {
                                        field_ref: Some(
                                            k8s_openapi::api::core::v1::ObjectFieldSelector {
                                                field_path: "spec.nodeName".to_string(),
                                                ..Default::default()
                                            },
                                        ),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                },
                                secret_env_var("AWS_ACCESS_KEY_ID", "key_id"),
                                secret_env_var("AWS_SECRET_ACCESS_KEY", "access_key"),
                            ]),
                            ports: Some(vec![ContainerPort {
                                name: Some("healthz".to_string()),
                                container_port: 9808,
                                protocol: Some("TCP".to_string()),
                                ..Default::default()
                            }]),
                            liveness_probe: Some(Probe {
                                http_get: Some(HTTPGetAction {
                                    path: Some("/healthz".to_string()),
                                    port: IntOrString::String("healthz".to_string()),
                                    ..Default::default()
                                }),
                                initial_delay_seconds: Some(10),
                                period_seconds: Some(10),
                                timeout_seconds: Some(3),
                                failure_threshold: Some(5),
                                ..Default::default()
                            }),
                            readiness_probe: Some(Probe {
                                http_get: Some(HTTPGetAction {
                                    path: Some("/healthz".to_string()),
                                    port: IntOrString::String("healthz".to_string()),
                                    ..Default::default()
                                }),
                                initial_delay_seconds: Some(10),
                                period_seconds: Some(10),
                                timeout_seconds: Some(3),
                                failure_threshold: Some(5),
                                ..Default::default()
                            }),
                            volume_mounts: Some(vec![VolumeMount {
                                name: "socket-dir".to_string(),
                                mount_path: "/var/lib/csi/sockets/pluginproxy/".to_string(),
                                ..Default::default()
                            }]),
                            ..Default::default()
                        },
                        sidecar_container(
                            "csi-provisioner",
                            "registry.k8s.io/sig-storage/csi-provisioner:v3.6.2",
                            vec![
                                "--csi-address=$(ADDRESS)",
                                "--v=2",
                                "--feature-gates=Topology=true",
                                "--extra-create-metadata",
                                "--leader-election=true",
                                "--default-fstype=ext4",
                            ],
                        ),
                        sidecar_container(
                            "csi-attacher",
                            "registry.k8s.io/sig-storage/csi-attacher:v4.4.2",
                            vec![
                                "--csi-address=$(ADDRESS)",
                                "--v=2",
                                "--leader-election=true",
                            ],
                        ),
                        sidecar_container(
                            "csi-snapshotter",
                            "registry.k8s.io/sig-storage/csi-snapshotter:v6.3.2",
                            vec!["--csi-address=$(ADDRESS)", "--leader-election=true"],
                        ),
                        Container {
                            name: "csi-resizer".to_string(),
                            image: Some(
                                "registry.k8s.io/sig-storage/csi-resizer:v1.9.2".to_string(),
                            ),
                            image_pull_policy: Some("Always".to_string()),
                            args: Some(vec![
                                "--csi-address=$(ADDRESS)".to_string(),
                                "--v=2".to_string(),
                            ]),
                            env: Some(vec![EnvVar {
                                name: "ADDRESS".to_string(),
                                value: Some(
                                    "/var/lib/csi/sockets/pluginproxy/csi.sock".to_string(),
                                ),
                                ..Default::default()
                            }]),
                            volume_mounts: Some(vec![VolumeMount {
                                name: "socket-dir".to_string(),
                                mount_path: "/var/lib/csi/sockets/pluginproxy/".to_string(),
                                ..Default::default()
                            }]),
                            ..Default::default()
                        },
                        Container {
                            name: "liveness-probe".to_string(),
                            image: Some(
                                "registry.k8s.io/sig-storage/livenessprobe:v2.11.0".to_string(),
                            ),
                            args: Some(vec!["--csi-address=/csi/csi.sock".to_string()]),
                            volume_mounts: Some(vec![VolumeMount {
                                name: "socket-dir".to_string(),
                                mount_path: "/csi".to_string(),
                                ..Default::default()
                            }]),
                            ..Default::default()
                        },
                    ],
                    node_selector: Some(BTreeMap::from([(
                        "kubernetes.io/os".to_string(),
                        "linux".to_string(),
                    )])),
                    priority_class_name: Some("system-cluster-critical".to_string()),
                    service_account_name: Some("ebs-csi-controller-sa".to_string()),
                    tolerations: Some(vec![
                        Toleration {
                            key: Some("CriticalAddonsOnly".to_string()),
                            operator: Some("Exists".to_string()),
                            ..Default::default()
                        },
                        Toleration {
                            effect: Some("NoExecute".to_string()),
                            operator: Some("Exists".to_string()),
                            toleration_seconds: Some(300),
                            ..Default::default()
                        },
                        Toleration {
                            key: Some("node-role.kubernetes.io/master".to_string()),
                            effect: Some("NoSchedule".to_string()),
                            ..Default::default()
                        },
                        Toleration {
                            key: Some("node-role.kubernetes.io/control-plane".to_string()),
                            effect: Some("NoSchedule".to_string()),
                            ..Default::default()
                        },
                    ]),
                    affinity: Some(Affinity {
                        node_affinity: Some(NodeAffinity {
                            required_during_scheduling_ignored_during_execution: Some(
                                NodeSelector {
                                    node_selector_terms: vec![
                                        NodeSelectorTerm {
                                            match_expressions: Some(vec![
                                                NodeSelectorRequirement {
                                                    key: "node-role.kubernetes.io/control-plane"
                                                        .to_string(),
                                                    operator: "Exists".to_string(),
                                                    ..Default::default()
                                                },
                                            ]),
                                            ..Default::default()
                                        },
                                        NodeSelectorTerm {
                                            match_expressions: Some(vec![
                                                NodeSelectorRequirement {
                                                    key: "node-role.kubernetes.io/master"
                                                        .to_string(),
                                                    operator: "Exists".to_string(),
                                                    ..Default::default()
                                                },
                                            ]),
                                            ..Default::default()
                                        },
                                    ],
                                },
                            ),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    volumes: Some(vec![Volume {
                        name: "socket-dir".to_string(),
                        empty_dir: Some(k8s_openapi::api::core::v1::EmptyDirVolumeSource::default()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn sidecar_container(name: &str, image: &str, args: Vec<&str>) -> Container {
    Container {
        name: name.to_string(),
        image: Some(image.to_string()),
        args: Some(args.iter().map(|s| s.to_string()).collect()),
        env: Some(vec![EnvVar {
            name: "ADDRESS".to_string(),
            value: Some("/var/lib/csi/sockets/pluginproxy/csi.sock".to_string()),
            ..Default::default()
        }]),
        volume_mounts: Some(vec![VolumeMount {
            name: "socket-dir".to_string(),
            mount_path: "/var/lib/csi/sockets/pluginproxy/".to_string(),
            ..Default::default()
        }]),
        ..Default::default()
    }
}

fn ebs_csi_controller_pdb() -> PodDisruptionBudget {
    PodDisruptionBudget {
        metadata: ObjectMeta {
            name: Some("ebs-csi-controller".to_string()),
            namespace: Some("kube-system".to_string()),
            labels: Some(ebs_csi_labels()),
            ..Default::default()
        },
        spec: Some(PodDisruptionBudgetSpec {
            max_unavailable: Some(IntOrString::Int(1)),
            selector: Some(LabelSelector {
                match_labels: Some(BTreeMap::from([
                    ("app".to_string(), "ebs-csi-controller".to_string()),
                    (
                        "app.kubernetes.io/name".to_string(),
                        "aws-ebs-csi-driver".to_string(),
                    ),
                ])),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn ebs_csi_node_daemonset(version: &str) -> DaemonSet {
    let labels = BTreeMap::from([
        ("app".to_string(), "ebs-csi-node".to_string()),
        (
            "app.kubernetes.io/name".to_string(),
            "aws-ebs-csi-driver".to_string(),
        ),
    ]);

    DaemonSet {
        metadata: ObjectMeta {
            name: Some("ebs-csi-node".to_string()),
            namespace: Some("kube-system".to_string()),
            labels: Some(ebs_csi_labels()),
            ..Default::default()
        },
        spec: Some(DaemonSetSpec {
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            update_strategy: Some(DaemonSetUpdateStrategy {
                type_: Some("RollingUpdate".to_string()),
                rolling_update: Some(RollingUpdateDaemonSet {
                    max_unavailable: Some(IntOrString::String("10%".to_string())),
                    ..Default::default()
                }),
            }),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    affinity: Some(Affinity {
                        node_affinity: Some(NodeAffinity {
                            required_during_scheduling_ignored_during_execution: Some(
                                NodeSelector {
                                    node_selector_terms: vec![NodeSelectorTerm {
                                        match_expressions: Some(vec![NodeSelectorRequirement {
                                            key: "eks.amazonaws.com/compute-type".to_string(),
                                            operator: "NotIn".to_string(),
                                            values: Some(vec!["fargate".to_string()]),
                                        }]),
                                        ..Default::default()
                                    }],
                                },
                            ),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    containers: vec![
                        Container {
                            name: "ebs-plugin".to_string(),
                            image: Some(format!(
                                "registry.k8s.io/provider-aws/aws-ebs-csi-driver:{version}"
                            )),
                            args: Some(vec![
                                "node".to_string(),
                                "--endpoint=$(CSI_ENDPOINT)".to_string(),
                                "--logtostderr".to_string(),
                                "--v=2".to_string(),
                            ]),
                            env: Some(vec![
                                EnvVar {
                                    name: "CSI_ENDPOINT".to_string(),
                                    value: Some("unix:/csi/csi.sock".to_string()),
                                    ..Default::default()
                                },
                                EnvVar {
                                    name: "CSI_NODE_NAME".to_string(),
                                    value_from: Some(EnvVarSource {
                                        field_ref: Some(
                                            k8s_openapi::api::core::v1::ObjectFieldSelector {
                                                field_path: "spec.nodeName".to_string(),
                                                ..Default::default()
                                            },
                                        ),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                },
                            ]),
                            ports: Some(vec![ContainerPort {
                                name: Some("healthz".to_string()),
                                container_port: 9808,
                                protocol: Some("TCP".to_string()),
                                ..Default::default()
                            }]),
                            liveness_probe: Some(Probe {
                                http_get: Some(HTTPGetAction {
                                    path: Some("/healthz".to_string()),
                                    port: IntOrString::String("healthz".to_string()),
                                    ..Default::default()
                                }),
                                initial_delay_seconds: Some(10),
                                period_seconds: Some(10),
                                timeout_seconds: Some(3),
                                failure_threshold: Some(5),
                                ..Default::default()
                            }),
                            security_context: Some(SecurityContext {
                                privileged: Some(true),
                                ..Default::default()
                            }),
                            volume_mounts: Some(vec![
                                VolumeMount {
                                    name: "kubelet-dir".to_string(),
                                    mount_path: "/var/lib/kubelet".to_string(),
                                    mount_propagation: Some("Bidirectional".to_string()),
                                    ..Default::default()
                                },
                                VolumeMount {
                                    name: "plugin-dir".to_string(),
                                    mount_path: "/csi".to_string(),
                                    ..Default::default()
                                },
                                VolumeMount {
                                    name: "device-dir".to_string(),
                                    mount_path: "/dev".to_string(),
                                    ..Default::default()
                                },
                            ]),
                            ..Default::default()
                        },
                        Container {
                            name: "node-driver-registrar".to_string(),
                            image: Some(
                                "registry.k8s.io/sig-storage/csi-node-driver-registrar:v2.9.2"
                                    .to_string(),
                            ),
                            args: Some(vec![
                                "--csi-address=$(ADDRESS)".to_string(),
                                "--kubelet-registration-path=$(DRIVER_REG_SOCK_PATH)".to_string(),
                                "--v=2".to_string(),
                            ]),
                            env: Some(vec![
                                EnvVar {
                                    name: "ADDRESS".to_string(),
                                    value: Some("/csi/csi.sock".to_string()),
                                    ..Default::default()
                                },
                                EnvVar {
                                    name: "DRIVER_REG_SOCK_PATH".to_string(),
                                    value: Some(
                                        "/var/lib/kubelet/plugins/ebs.csi.aws.com/csi.sock"
                                            .to_string(),
                                    ),
                                    ..Default::default()
                                },
                            ]),
                            volume_mounts: Some(vec![
                                VolumeMount {
                                    name: "plugin-dir".to_string(),
                                    mount_path: "/csi".to_string(),
                                    ..Default::default()
                                },
                                VolumeMount {
                                    name: "registration-dir".to_string(),
                                    mount_path: "/registration".to_string(),
                                    ..Default::default()
                                },
                            ]),
                            ..Default::default()
                        },
                        Container {
                            name: "liveness-probe".to_string(),
                            image: Some(
                                "registry.k8s.io/sig-storage/livenessprobe:v2.11.0".to_string(),
                            ),
                            args: Some(vec!["--csi-address=/csi/csi.sock".to_string()]),
                            volume_mounts: Some(vec![VolumeMount {
                                name: "plugin-dir".to_string(),
                                mount_path: "/csi".to_string(),
                                ..Default::default()
                            }]),
                            ..Default::default()
                        },
                    ],
                    node_selector: Some(BTreeMap::from([(
                        "kubernetes.io/os".to_string(),
                        "linux".to_string(),
                    )])),
                    priority_class_name: Some("system-node-critical".to_string()),
                    service_account_name: Some("ebs-csi-node-sa".to_string()),
                    tolerations: Some(vec![
                        Toleration {
                            key: Some("CriticalAddonsOnly".to_string()),
                            operator: Some("Exists".to_string()),
                            ..Default::default()
                        },
                        Toleration {
                            effect: Some("NoExecute".to_string()),
                            operator: Some("Exists".to_string()),
                            toleration_seconds: Some(300),
                            ..Default::default()
                        },
                    ]),
                    volumes: Some(vec![
                        Volume {
                            name: "kubelet-dir".to_string(),
                            host_path: Some(HostPathVolumeSource {
                                path: "/var/lib/kubelet".to_string(),
                                type_: Some("Directory".to_string()),
                            }),
                            ..Default::default()
                        },
                        Volume {
                            name: "plugin-dir".to_string(),
                            host_path: Some(HostPathVolumeSource {
                                path: "/var/lib/kubelet/plugins/ebs.csi.aws.com/".to_string(),
                                type_: Some("DirectoryOrCreate".to_string()),
                            }),
                            ..Default::default()
                        },
                        Volume {
                            name: "registration-dir".to_string(),
                            host_path: Some(HostPathVolumeSource {
                                path: "/var/lib/kubelet/plugins_registry/".to_string(),
                                type_: Some("Directory".to_string()),
                            }),
                            ..Default::default()
                        },
                        Volume {
                            name: "device-dir".to_string(),
                            host_path: Some(HostPathVolumeSource {
                                path: "/dev".to_string(),
                                type_: Some("Directory".to_string()),
                            }),
                            ..Default::default()
                        },
                    ]),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn ebs_csi_driver() -> CSIDriver {
    CSIDriver {
        metadata: ObjectMeta {
            name: Some("ebs.csi.aws.com".to_string()),
            labels: Some(ebs_csi_labels()),
            ..Default::default()
        },
        spec: CSIDriverSpec {
            attach_required: Some(true),
            pod_info_on_mount: Some(false),
            ..Default::default()
        },
    }
}

fn ebs_storage_class() -> StorageClass {
    StorageClass {
        metadata: ObjectMeta {
            name: Some("gp3".to_string()),
            annotations: Some(BTreeMap::from([(
                "storageclass.kubernetes.io/is-default-class".to_string(),
                "true".to_string(),
            )])),
            ..Default::default()
        },
        provisioner: "ebs.csi.aws.com".to_string(),
        parameters: Some(BTreeMap::from([
            ("type".to_string(), "gp3".to_string()),
            ("encrypted".to_string(), "true".to_string()),
        ])),
        reclaim_policy: Some("Delete".to_string()),
        volume_binding_mode: Some("WaitForFirstConsumer".to_string()),
        allow_volume_expansion: Some(true),
        ..Default::default()
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Serialize a Kubernetes resource to YAML
fn to_yaml<T: serde::Serialize>(resource: &T) -> String {
    serde_yaml::to_string(resource).expect("Failed to serialize resource")
}

/// Generate all AWS addon manifests (CCM + EBS CSI + StorageClass) as raw YAML.
///
/// Returns a single YAML string with all resources separated by `---`.
pub fn generate_aws_addon_manifests(k8s_version: &str) -> String {
    let ccm_version = ccm_version_from_k8s(k8s_version);

    let resources: Vec<String> = vec![
        // CCM resources
        to_yaml(&ccm_daemonset(&ccm_version)),
        to_yaml(&ccm_service_account()),
        to_yaml(&ccm_role_binding()),
        to_yaml(&ccm_cluster_role()),
        to_yaml(&ccm_cluster_role_binding()),
        // EBS CSI resources
        to_yaml(&ebs_csi_secret()),
        to_yaml(&ebs_csi_controller_service_account()),
        to_yaml(&ebs_csi_node_service_account()),
        to_yaml(&ebs_csi_attacher_role()),
        to_yaml(&ebs_csi_node_role()),
        to_yaml(&ebs_csi_provisioner_role()),
        to_yaml(&ebs_csi_resizer_role()),
        to_yaml(&ebs_csi_snapshotter_role()),
        to_yaml(&ebs_csi_cluster_role_binding(
            "ebs-csi-attacher-binding",
            "ebs-external-attacher-role",
        )),
        to_yaml(&ebs_csi_cluster_role_binding(
            "ebs-csi-provisioner-binding",
            "ebs-external-provisioner-role",
        )),
        to_yaml(&ebs_csi_cluster_role_binding(
            "ebs-csi-resizer-binding",
            "ebs-external-resizer-role",
        )),
        to_yaml(&ebs_csi_cluster_role_binding(
            "ebs-csi-snapshotter-binding",
            "ebs-external-snapshotter-role",
        )),
        to_yaml(&ebs_csi_node_cluster_role_binding()),
        to_yaml(&ebs_csi_controller_deployment(AWS_EBS_CSI_VERSION)),
        to_yaml(&ebs_csi_controller_pdb()),
        to_yaml(&ebs_csi_node_daemonset(AWS_EBS_CSI_VERSION)),
        to_yaml(&ebs_csi_driver()),
        to_yaml(&ebs_storage_class()),
    ];

    resources.join("---\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ccm_version_extraction() {
        assert_eq!(ccm_version_from_k8s("1.32.0"), "v1.32.0");
        assert_eq!(ccm_version_from_k8s("v1.32.0"), "v1.32.0");
        assert_eq!(ccm_version_from_k8s("1.30.5"), "v1.30.5");
    }

    #[test]
    fn ccm_daemonset_has_correct_image() {
        let ds = ccm_daemonset("v1.32.0");
        let container = &ds
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers[0];
        assert_eq!(
            container.image.as_ref().unwrap(),
            "registry.k8s.io/provider-aws/cloud-controller-manager:v1.32.0"
        );
    }

    #[test]
    fn ccm_cluster_role_has_required_permissions() {
        let role = ccm_cluster_role();
        let rules = role.rules.as_ref().unwrap();

        // Check nodes permission
        let nodes_rule = rules
            .iter()
            .find(|r| {
                r.resources
                    .as_ref()
                    .map_or(false, |res| res.contains(&"nodes".to_string()))
            })
            .unwrap();
        assert!(nodes_rule.verbs.contains(&"*".to_string()));
    }

    #[test]
    fn ebs_csi_controller_has_all_sidecars() {
        let deployment = ebs_csi_controller_deployment("v1.54.0");
        let containers = &deployment
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers;

        let container_names: Vec<&str> = containers.iter().map(|c| c.name.as_str()).collect();

        assert!(container_names.contains(&"ebs-plugin"));
        assert!(container_names.contains(&"csi-provisioner"));
        assert!(container_names.contains(&"csi-attacher"));
        assert!(container_names.contains(&"csi-snapshotter"));
        assert!(container_names.contains(&"csi-resizer"));
        assert!(container_names.contains(&"liveness-probe"));
    }

    #[test]
    fn ebs_csi_node_daemonset_is_privileged() {
        let ds = ebs_csi_node_daemonset("v1.54.0");
        let ebs_plugin = &ds
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers[0];
        assert!(ebs_plugin
            .security_context
            .as_ref()
            .unwrap()
            .privileged
            .unwrap());
    }

    #[test]
    fn storage_class_is_default() {
        let sc = ebs_storage_class();
        let annotations = sc.metadata.annotations.as_ref().unwrap();
        assert_eq!(
            annotations.get("storageclass.kubernetes.io/is-default-class"),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn storage_class_uses_gp3_encrypted() {
        let sc = ebs_storage_class();
        let params = sc.parameters.as_ref().unwrap();
        assert_eq!(params.get("type"), Some(&"gp3".to_string()));
        assert_eq!(params.get("encrypted"), Some(&"true".to_string()));
    }

    #[test]
    fn combined_manifest_contains_all_resources() {
        let manifest = generate_aws_addon_manifests("1.32.0");

        // CCM resources
        assert!(manifest.contains("cloud-controller-manager"));
        assert!(manifest.contains("v1.32.0"));

        // EBS CSI resources
        assert!(manifest.contains("ebs.csi.aws.com"));
        assert!(manifest.contains("ebs-csi-controller"));
        assert!(manifest.contains("ebs-csi-node"));

        // StorageClass
        assert!(manifest.contains("gp3"));
        assert!(manifest.contains("WaitForFirstConsumer"));
    }

    #[test]
    fn manifest_has_document_separators() {
        let manifest = generate_aws_addon_manifests("1.32.0");
        assert!(manifest.contains("---"));
    }
}
