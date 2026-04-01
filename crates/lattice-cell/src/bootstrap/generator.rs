//! Default manifest generator for bootstrap bundles
//!
//! Generates Cilium CNI manifests and operator deployment manifests
//! (namespace, RBAC, ServiceAccount, Deployment) for new clusters.

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, ContainerPort, EnvVar, EnvVarSource, HTTPGetAction, LocalObjectReference,
    Namespace, ObjectFieldSelector, PodSpec, PodTemplateSpec, Probe, Secret, ServiceAccount,
    Toleration,
};
use k8s_openapi::api::rbac::v1::{ClusterRoleBinding, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use k8s_openapi::ByteString;

use kube::CustomResourceExt;
use lattice_common::crd::{LatticeCluster, ProviderType};
use lattice_common::{
    LATTICE_SYSTEM_NAMESPACE, OPERATOR_NAME, REGISTRY_CREDENTIALS_SECRET, SECRET_TYPE_DOCKERCONFIG,
};

use super::types::ManifestGenerator;

/// Default manifest generator that creates CNI and operator manifests
///
/// Generates Cilium manifests on-demand based on provider, then adds operator deployment.
#[derive(Clone, Default)]
pub struct DefaultManifestGenerator;

impl DefaultManifestGenerator {
    /// Create a new manifest generator
    pub fn new() -> Self {
        Self
    }

    /// Generate the Lattice operator manifests (non-Cilium)
    ///
    /// Every cluster runs the same deployment - the controller reads its
    /// LatticeCluster CRD to determine behavior (cell vs leaf, parent connection, etc.)
    ///
    /// Environment variables set:
    /// - LATTICE_CLUSTER_NAME: So controller knows which cluster it's on
    /// - LATTICE_PROVIDER: So agent knows which infrastructure provider to install
    fn generate_operator_manifests(
        &self,
        image: &str,
        registry_credentials: Option<&str>,
        cluster_name: Option<&str>,
        provider: Option<ProviderType>,
    ) -> Result<Vec<String>, serde_json::Error> {
        let registry_creds = registry_credentials.map(|s| s.to_string());

        // 1. Namespace
        let namespace = Namespace {
            metadata: ObjectMeta {
                name: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        // Certificate blocklist ConfigMap (empty).
        // Must exist before the gRPC server starts (fail-closed).
        let cert_blocklist_cm = ConfigMap {
            metadata: ObjectMeta {
                name: Some("lattice-cert-blocklist".to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                ..Default::default()
            },
            data: Some(BTreeMap::from([(
                "fingerprints".to_string(),
                String::new(),
            )])),
            ..Default::default()
        };

        // 2. Registry credentials secret (bootstrap seed for initial image pull).
        // Labeled for distribution so child clusters receive it via fetch_distributable_resources.
        let registry_secret = registry_creds.as_ref().map(|creds| Secret {
            metadata: ObjectMeta {
                name: Some(REGISTRY_CREDENTIALS_SECRET.to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                labels: Some(BTreeMap::from([(
                    "lattice.dev/distribute".to_string(),
                    "true".to_string(),
                )])),
                ..Default::default()
            },
            type_: Some(SECRET_TYPE_DOCKERCONFIG.to_string()),
            data: Some(BTreeMap::from([(
                ".dockerconfigjson".to_string(),
                ByteString(creds.as_bytes().to_vec()),
            )])),
            ..Default::default()
        });

        // 3. ServiceAccount
        let service_account = ServiceAccount {
            metadata: ObjectMeta {
                name: Some(OPERATOR_NAME.to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        // 4. ClusterRoleBinding (cluster-admin - we manage everything)
        let cluster_role_binding = ClusterRoleBinding {
            metadata: ObjectMeta {
                name: Some(OPERATOR_NAME.to_string()),
                ..Default::default()
            },
            role_ref: RoleRef {
                api_group: "rbac.authorization.k8s.io".to_string(),
                kind: "ClusterRole".to_string(),
                name: "cluster-admin".to_string(),
            },
            subjects: Some(vec![Subject {
                kind: "ServiceAccount".to_string(),
                name: OPERATOR_NAME.to_string(),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                ..Default::default()
            }]),
        };

        // 5. Operator Deployment
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), OPERATOR_NAME.to_string());

        let operator_deployment = Deployment {
            metadata: ObjectMeta {
                name: Some(OPERATOR_NAME.to_string()),
                namespace: Some(LATTICE_SYSTEM_NAMESPACE.to_string()),
                ..Default::default()
            },
            spec: Some(DeploymentSpec {
                // HA: 2 replicas with leader election - only leader runs controllers
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
                        service_account_name: Some(OPERATOR_NAME.to_string()),
                        image_pull_secrets: if registry_secret.is_some() {
                            Some(vec![LocalObjectReference {
                                name: REGISTRY_CREDENTIALS_SECRET.to_string(),
                            }])
                        } else {
                            None
                        },
                        volumes: None,
                        containers: vec![Container {
                            name: "operator".to_string(),
                            image: Some(image.to_string()),
                            image_pull_policy: Some("Always".to_string()),
                            // No args needed - controller is default mode
                            // Controller reads LatticeCluster CRD to determine behavior
                            env: Some({
                                let mut envs = vec![
                                    EnvVar {
                                        name: "RUST_LOG".to_string(),
                                        value: Some("info,lattice=debug".to_string()),
                                        ..Default::default()
                                    },
                                    // Downward API env vars for leader election identity
                                    EnvVar {
                                        name: "POD_NAME".to_string(),
                                        value_from: Some(EnvVarSource {
                                            field_ref: Some(ObjectFieldSelector {
                                                field_path: "metadata.name".to_string(),
                                                ..Default::default()
                                            }),
                                            ..Default::default()
                                        }),
                                        ..Default::default()
                                    },
                                    EnvVar {
                                        name: "POD_NAMESPACE".to_string(),
                                        value_from: Some(EnvVarSource {
                                            field_ref: Some(ObjectFieldSelector {
                                                field_path: "metadata.namespace".to_string(),
                                                ..Default::default()
                                            }),
                                            ..Default::default()
                                        }),
                                        ..Default::default()
                                    },
                                ];
                                if let Some(name) = cluster_name {
                                    envs.push(EnvVar {
                                        name: "LATTICE_CLUSTER_NAME".to_string(),
                                        value: Some(name.to_string()),
                                        ..Default::default()
                                    });
                                }
                                // Provider set for debugging visibility (operator reads from CRD)
                                if let Some(prov) = provider {
                                    envs.push(EnvVar {
                                        name: "LATTICE_PROVIDER".to_string(),
                                        value: Some(prov.to_string()),
                                        ..Default::default()
                                    });
                                }
                                envs
                            }),
                            volume_mounts: None,
                            // Expose cell server ports for LoadBalancer Service
                            ports: Some(vec![
                                ContainerPort {
                                    name: Some("bootstrap".to_string()),
                                    container_port: lattice_common::DEFAULT_BOOTSTRAP_PORT as i32,
                                    protocol: Some("TCP".to_string()),
                                    ..Default::default()
                                },
                                ContainerPort {
                                    name: Some("grpc".to_string()),
                                    container_port: lattice_common::DEFAULT_GRPC_PORT as i32,
                                    protocol: Some("TCP".to_string()),
                                    ..Default::default()
                                },
                                ContainerPort {
                                    name: Some("health".to_string()),
                                    container_port: lattice_common::DEFAULT_HEALTH_PORT as i32,
                                    protocol: Some("TCP".to_string()),
                                    ..Default::default()
                                },
                            ]),
                            // Health probes for HA leader election
                            liveness_probe: Some(Probe {
                                http_get: Some(HTTPGetAction {
                                    path: Some("/healthz".to_string()),
                                    port: IntOrString::Int(
                                        lattice_common::DEFAULT_HEALTH_PORT as i32,
                                    ),
                                    ..Default::default()
                                }),
                                initial_delay_seconds: Some(5),
                                period_seconds: Some(10),
                                ..Default::default()
                            }),
                            readiness_probe: Some(Probe {
                                http_get: Some(HTTPGetAction {
                                    path: Some("/readyz".to_string()),
                                    port: IntOrString::Int(
                                        lattice_common::DEFAULT_HEALTH_PORT as i32,
                                    ),
                                    ..Default::default()
                                }),
                                initial_delay_seconds: Some(5),
                                period_seconds: Some(5),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }],
                        tolerations: Some(vec![Toleration {
                            key: Some("node-role.kubernetes.io/control-plane".to_string()),
                            effect: Some("NoSchedule".to_string()),
                            operator: Some("Exists".to_string()),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    }),
                },
                ..Default::default()
            }),
            ..Default::default()
        };

        // Serialize all resources to JSON
        // Start with the LatticeCluster CRD definition so it's applied first
        let crd = LatticeCluster::crd();
        let mut manifests = vec![serde_json::to_string(&crd)?];

        manifests.push(serde_json::to_string(&namespace)?);
        manifests.push(serde_json::to_string(&cert_blocklist_cm)?);
        if let Some(ref reg_secret) = registry_secret {
            manifests.push(serde_json::to_string(reg_secret)?);
        }
        manifests.extend([
            serde_json::to_string(&service_account)?,
            serde_json::to_string(&cluster_role_binding)?,
            serde_json::to_string(&operator_deployment)?,
        ]);
        Ok(manifests)
    }
}

#[async_trait::async_trait]
impl ManifestGenerator for DefaultManifestGenerator {
    async fn generate(
        &self,
        image: &str,
        registry_credentials: Option<&str>,
        cluster_name: Option<&str>,
        provider: Option<ProviderType>,
    ) -> Result<Vec<String>, super::errors::BootstrapError> {
        let mut manifests = Vec::new();

        // CNI manifests first (Cilium) - embedded at build time
        manifests.extend(
            lattice_infra::bootstrap::cilium::generate_cilium_manifests()
                .iter()
                .cloned(),
        );

        // Then operator manifests
        let operator_manifests = self
            .generate_operator_manifests(image, registry_credentials, cluster_name, provider)
            .map_err(|e| {
                super::errors::BootstrapError::ManifestGeneration(format!(
                    "failed to serialize operator manifests: {e}"
                ))
            })?;
        manifests.extend(operator_manifests);

        Ok(manifests)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::LATTICE_SYSTEM_NAMESPACE;

    #[tokio::test]
    async fn default_generator_creates_namespace() {
        let generator = DefaultManifestGenerator::new();
        let manifests = generator
            .generate("test:latest", None, None, None)
            .await
            .unwrap();

        // Operator manifests are JSON, check for JSON format
        let has_namespace = manifests.iter().any(|m: &String| {
            m.contains("\"kind\":\"Namespace\"") && m.contains(LATTICE_SYSTEM_NAMESPACE)
        });
        assert!(has_namespace);
    }

    #[tokio::test]
    async fn default_generator_creates_operator_deployment() {
        let generator = DefaultManifestGenerator::new();
        let manifests = generator
            .generate("test:latest", None, None, None)
            .await
            .unwrap();

        // Operator manifests are JSON, check for JSON format
        let has_deployment = manifests.iter().any(|m: &String| {
            m.contains("\"kind\":\"Deployment\"") && m.contains("lattice-operator")
        });
        assert!(has_deployment);
    }

    #[tokio::test]
    async fn default_generator_creates_service_account() {
        let generator = DefaultManifestGenerator::new();
        let manifests = generator
            .generate("test:latest", None, None, None)
            .await
            .unwrap();

        // Should have ServiceAccount for operator
        let has_sa = manifests.iter().any(|m: &String| {
            m.contains("\"kind\":\"ServiceAccount\"") && m.contains("lattice-operator")
        });
        assert!(has_sa);
    }

    #[tokio::test]
    async fn default_generator_creates_cilium_cni() {
        let generator = DefaultManifestGenerator::new();
        let manifests = generator
            .generate("test:latest", None, None, None)
            .await
            .unwrap();

        // Should include Cilium DaemonSet (rendered from helm template)
        let has_cilium_daemonset = manifests
            .iter()
            .any(|m: &String| m.contains("kind: DaemonSet") && m.contains("cilium"));
        assert!(has_cilium_daemonset, "Should include Cilium DaemonSet");

        // Should include Cilium ConfigMap
        let has_cilium_config = manifests
            .iter()
            .any(|m: &String| m.contains("kind: ConfigMap") && m.contains("cilium"));
        assert!(has_cilium_config, "Should include Cilium ConfigMap");
    }

    /// Story: Manifest generation for operator deployment
    ///
    /// The bootstrap response includes Kubernetes manifests that set up
    /// the Lattice operator on new clusters. Every cluster runs the same
    /// deployment - the controller reads LatticeCluster CRD to determine behavior.
    #[tokio::test]
    async fn manifest_generation() {
        let generator = DefaultManifestGenerator::new();
        let manifests = generator
            .generate("test:latest", None, None, None)
            .await
            .unwrap();

        // CRD must be first so it's applied before any CR instances
        let has_crd = manifests.iter().any(|m: &String| {
            m.contains("\"kind\":\"CustomResourceDefinition\"")
                && m.contains("latticeclusters.lattice.dev")
        });
        assert!(has_crd, "Should include LatticeCluster CRD definition");

        // Manifests create the lattice-system namespace (JSON format)
        let has_namespace = manifests.iter().any(|m: &String| {
            m.contains("\"kind\":\"Namespace\"") && m.contains(LATTICE_SYSTEM_NAMESPACE)
        });
        assert!(has_namespace, "Should create lattice-system namespace");

        // Manifests deploy the operator (JSON format)
        let has_operator = manifests.iter().any(|m: &String| {
            m.contains("\"kind\":\"Deployment\"") && m.contains("lattice-operator")
        });
        assert!(has_operator, "Should deploy lattice-operator");

        // Should have cluster-admin binding
        let has_rbac = manifests.iter().any(|m: &String| {
            m.contains("\"kind\":\"ClusterRoleBinding\"") && m.contains("cluster-admin")
        });
        assert!(has_rbac, "Should have cluster-admin binding");
    }
}
