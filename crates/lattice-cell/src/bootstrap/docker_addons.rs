//! Docker-specific addon manifests
//!
//! Generates local-path-provisioner for Docker/kind clusters
//! using typed k8s_openapi structs for type safety and maintainability.

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    ConfigMap, ConfigMapVolumeSource, Container, EnvVar, EnvVarSource, Namespace, PodSpec,
    PodTemplateSpec, ServiceAccount, Volume, VolumeMount,
};
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, PolicyRule, RoleRef, Subject};
use k8s_openapi::api::storage::v1::StorageClass;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};

/// Local path provisioner version
const LOCAL_PATH_PROVISIONER_VERSION: &str = "v0.0.30";

const NAMESPACE: &str = "local-path-storage";

fn namespace() -> Namespace {
    Namespace {
        metadata: ObjectMeta {
            name: Some(NAMESPACE.to_string()),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn service_account() -> ServiceAccount {
    ServiceAccount {
        metadata: ObjectMeta {
            name: Some("local-path-provisioner-service-account".to_string()),
            namespace: Some(NAMESPACE.to_string()),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn cluster_role() -> ClusterRole {
    ClusterRole {
        metadata: ObjectMeta {
            name: Some("local-path-provisioner-role".to_string()),
            ..Default::default()
        },
        rules: Some(vec![
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec![
                    "nodes".to_string(),
                    "persistentvolumeclaims".to_string(),
                    "configmaps".to_string(),
                ]),
                verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["pods".to_string(), "pods/log".to_string()]),
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
                resources: Some(vec!["persistentvolumes".to_string()]),
                verbs: vec![
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "create".to_string(),
                    "patch".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec![String::new()]),
                resources: Some(vec!["events".to_string()]),
                verbs: vec!["create".to_string(), "patch".to_string()],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["storage.k8s.io".to_string()]),
                resources: Some(vec!["storageclasses".to_string()]),
                verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                ..Default::default()
            },
        ]),
        ..Default::default()
    }
}

fn cluster_role_binding() -> ClusterRoleBinding {
    ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some("local-path-provisioner-bind".to_string()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: "local-path-provisioner-role".to_string(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: "local-path-provisioner-service-account".to_string(),
            namespace: Some(NAMESPACE.to_string()),
            ..Default::default()
        }]),
    }
}

fn deployment() -> Deployment {
    let labels = BTreeMap::from([("app".to_string(), "local-path-provisioner".to_string())]);

    Deployment {
        metadata: ObjectMeta {
            name: Some("local-path-provisioner".to_string()),
            namespace: Some(NAMESPACE.to_string()),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
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
                    service_account_name: Some(
                        "local-path-provisioner-service-account".to_string(),
                    ),
                    containers: vec![Container {
                        name: "local-path-provisioner".to_string(),
                        image: Some(format!(
                            "rancher/local-path-provisioner:{LOCAL_PATH_PROVISIONER_VERSION}"
                        )),
                        image_pull_policy: Some("IfNotPresent".to_string()),
                        command: Some(vec![
                            "local-path-provisioner".to_string(),
                            "--debug".to_string(),
                            "start".to_string(),
                            "--config".to_string(),
                            "/etc/config/config.json".to_string(),
                        ]),
                        volume_mounts: Some(vec![VolumeMount {
                            name: "config-volume".to_string(),
                            mount_path: "/etc/config/".to_string(),
                            ..Default::default()
                        }]),
                        env: Some(vec![EnvVar {
                            name: "POD_NAMESPACE".to_string(),
                            value_from: Some(EnvVarSource {
                                field_ref: Some(k8s_openapi::api::core::v1::ObjectFieldSelector {
                                    field_path: "metadata.namespace".to_string(),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    }],
                    volumes: Some(vec![Volume {
                        name: "config-volume".to_string(),
                        config_map: Some(ConfigMapVolumeSource {
                            name: "local-path-config".to_string(),
                            ..Default::default()
                        }),
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

fn storage_class() -> StorageClass {
    StorageClass {
        metadata: ObjectMeta {
            name: Some("standard".to_string()),
            annotations: Some(BTreeMap::from([(
                "storageclass.kubernetes.io/is-default-class".to_string(),
                "true".to_string(),
            )])),
            ..Default::default()
        },
        provisioner: "rancher.io/local-path".to_string(),
        volume_binding_mode: Some("WaitForFirstConsumer".to_string()),
        reclaim_policy: Some("Delete".to_string()),
        ..Default::default()
    }
}

fn config_map() -> ConfigMap {
    let config_json = r#"{
  "nodePathMap": [
    {
      "node": "DEFAULT_PATH_FOR_NON_LISTED_NODES",
      "paths": ["/opt/local-path-provisioner"]
    }
  ]
}"#;

    let setup_script = r#"#!/bin/sh
set -eu
mkdir -m 0777 -p "$VOL_DIR""#;

    let teardown_script = r#"#!/bin/sh
set -eu
rm -rf "$VOL_DIR""#;

    let helper_pod = r#"apiVersion: v1
kind: Pod
metadata:
  name: helper-pod
spec:
  containers:
    - name: helper-pod
      image: busybox:latest
      imagePullPolicy: IfNotPresent"#;

    ConfigMap {
        metadata: ObjectMeta {
            name: Some("local-path-config".to_string()),
            namespace: Some(NAMESPACE.to_string()),
            ..Default::default()
        },
        data: Some(BTreeMap::from([
            ("config.json".to_string(), config_json.to_string()),
            ("setup".to_string(), setup_script.to_string()),
            ("teardown".to_string(), teardown_script.to_string()),
            ("helperPod.yaml".to_string(), helper_pod.to_string()),
        ])),
        ..Default::default()
    }
}

/// Serialize a Kubernetes resource to JSON
fn to_json<T: serde::Serialize>(resource: &T) -> String {
    serde_json::to_string(resource).expect("Failed to serialize resource")
}

/// Generate all Docker addon manifests (local-path-provisioner).
///
/// Returns a Vec of JSON strings, one per resource.
pub fn generate_docker_addon_manifests() -> Vec<String> {
    vec![
        to_json(&namespace()),
        to_json(&service_account()),
        to_json(&cluster_role()),
        to_json(&cluster_role_binding()),
        to_json(&deployment()),
        to_json(&storage_class()),
        to_json(&config_map()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_has_correct_image() {
        let dep = deployment();
        let container = &dep
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
            &format!("rancher/local-path-provisioner:{LOCAL_PATH_PROVISIONER_VERSION}")
        );
    }

    #[test]
    fn storage_class_is_default() {
        let sc = storage_class();
        let annotations = sc.metadata.annotations.as_ref().unwrap();
        assert_eq!(
            annotations.get("storageclass.kubernetes.io/is-default-class"),
            Some(&"true".to_string())
        );
    }

    #[test]
    fn storage_class_has_correct_provisioner() {
        let sc = storage_class();
        assert_eq!(sc.provisioner, "rancher.io/local-path");
    }

    #[test]
    fn cluster_role_has_required_permissions() {
        let role = cluster_role();
        let rules = role.rules.as_ref().unwrap();

        // Check persistentvolumes permissions
        let pv_rule = rules
            .iter()
            .find(|r| {
                r.resources
                    .as_ref()
                    .map_or(false, |res| res.contains(&"persistentvolumes".to_string()))
            })
            .unwrap();
        assert!(pv_rule.verbs.contains(&"create".to_string()));
        assert!(pv_rule.verbs.contains(&"delete".to_string()));
    }

    #[test]
    fn config_map_has_required_data() {
        let cm = config_map();
        let data = cm.data.as_ref().unwrap();
        assert!(data.contains_key("config.json"));
        assert!(data.contains_key("setup"));
        assert!(data.contains_key("teardown"));
        assert!(data.contains_key("helperPod.yaml"));
    }

    #[test]
    fn manifests_contain_all_resources() {
        let manifests = generate_docker_addon_manifests();
        let combined = manifests.join("\n");

        assert_eq!(manifests.len(), 7); // 7 resources
        assert!(combined.contains("local-path-storage")); // Namespace
        assert!(combined.contains("local-path-provisioner-service-account")); // ServiceAccount
        assert!(combined.contains("local-path-provisioner-role")); // ClusterRole
        assert!(combined.contains("local-path-provisioner-bind")); // ClusterRoleBinding
        assert!(combined.contains("rancher/local-path-provisioner")); // Deployment image
        assert!(combined.contains("rancher.io/local-path")); // StorageClass provisioner
        assert!(combined.contains("local-path-config")); // ConfigMap
    }
}
