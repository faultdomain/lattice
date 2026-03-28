//! External-dns deployment reconciliation.
//!
//! Generates and applies external-dns Deployments for each DNSProvider referenced
//! by a LatticeCluster. External-dns watches Services/Ingresses and creates DNS
//! records in the configured provider.

use kube::api::{Api, Patch, PatchParams};
use kube::{Client, ResourceExt};
use serde_json::{json, Value};
use tracing::{debug, info, warn};

use lattice_common::crd::{DNSProvider, DNSProviderSpec, DNSProviderType, LatticeCluster};
use lattice_common::{Error, LATTICE_MANAGED_BY_LABEL, LATTICE_MANAGED_BY_VALUE, LATTICE_SYSTEM_NAMESPACE};

/// Container image for external-dns deployments.
const EXTERNAL_DNS_IMAGE: &str = "registry.k8s.io/external-dns/external-dns:v0.15.1";

/// Namespace where external-dns resources are deployed.
const EXTERNAL_DNS_NAMESPACE: &str = "external-dns";

/// Field manager for server-side apply.
const FIELD_MANAGER: &str = "lattice-cluster-controller";

/// Reconcile external-dns deployments for all DNS providers configured on the cluster.
///
/// For each DNSProvider referenced in `spec.dns`, generates and applies the necessary
/// Kubernetes resources (Namespace, ServiceAccount, RBAC, Deployment) via SSA.
pub async fn reconcile_external_dns(
    client: &Client,
    cluster: &LatticeCluster,
) -> Result<(), Error> {
    let dns_config = match &cluster.spec.dns {
        Some(dns) if !dns.providers.is_empty() => dns,
        _ => return Ok(()),
    };

    let cluster_name = cluster.name_any();
    let ns = cluster
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());
    let dns_api: Api<DNSProvider> = Api::namespaced(client.clone(), &ns);

    // Ensure the shared namespace exists first
    let ns_manifest = build_namespace();
    let ns_api: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());
    ns_api
        .patch(
            EXTERNAL_DNS_NAMESPACE,
            &PatchParams::apply(FIELD_MANAGER),
            &Patch::Apply(&ns_manifest),
        )
        .await
        .map_err(|e| Error::internal(format!("failed to apply external-dns namespace: {e}")))?;

    for (_key, provider_name) in &dns_config.providers {
        let provider = match dns_api.get(provider_name).await {
            Ok(p) => p,
            Err(e) => {
                warn!(provider = %provider_name, error = %e, "failed to fetch DNSProvider for external-dns, skipping");
                continue;
            }
        };

        let manifests = build_external_dns_manifests(&provider.spec, provider_name, &cluster_name);

        for manifest in &manifests {
            apply_manifest(client, manifest).await?;
        }

        debug!(provider = %provider_name, "external-dns resources applied");
    }

    info!(
        cluster = %cluster_name,
        providers = dns_config.providers.len(),
        "external-dns deployments reconciled"
    );

    Ok(())
}

/// Apply a single manifest via SSA, routing to the correct API based on kind.
async fn apply_manifest(client: &Client, manifest: &Value) -> Result<(), Error> {
    let kind = manifest["kind"].as_str().unwrap_or("");
    let name = manifest["metadata"]["name"].as_str().unwrap_or("");
    let namespace = manifest["metadata"]["namespace"].as_str();

    let patch_params = PatchParams::apply(FIELD_MANAGER);

    match kind {
        "ServiceAccount" => {
            let api: Api<k8s_openapi::api::core::v1::ServiceAccount> =
                Api::namespaced(client.clone(), namespace.unwrap_or(EXTERNAL_DNS_NAMESPACE));
            api.patch(name, &patch_params, &Patch::Apply(manifest))
                .await
                .map_err(|e| Error::internal(format!("failed to apply ServiceAccount {name}: {e}")))?;
        }
        "ClusterRole" => {
            let api: Api<k8s_openapi::api::rbac::v1::ClusterRole> = Api::all(client.clone());
            api.patch(name, &patch_params, &Patch::Apply(manifest))
                .await
                .map_err(|e| Error::internal(format!("failed to apply ClusterRole {name}: {e}")))?;
        }
        "ClusterRoleBinding" => {
            let api: Api<k8s_openapi::api::rbac::v1::ClusterRoleBinding> =
                Api::all(client.clone());
            api.patch(name, &patch_params, &Patch::Apply(manifest))
                .await
                .map_err(|e| {
                    Error::internal(format!("failed to apply ClusterRoleBinding {name}: {e}"))
                })?;
        }
        "Deployment" => {
            let api: Api<k8s_openapi::api::apps::v1::Deployment> =
                Api::namespaced(client.clone(), namespace.unwrap_or(EXTERNAL_DNS_NAMESPACE));
            api.patch(name, &patch_params, &Patch::Apply(manifest))
                .await
                .map_err(|e| Error::internal(format!("failed to apply Deployment {name}: {e}")))?;
        }
        _ => {
            return Err(Error::internal(format!(
                "unexpected manifest kind for external-dns: {kind}"
            )));
        }
    }

    Ok(())
}

/// Build the shared external-dns Namespace manifest.
fn build_namespace() -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": EXTERNAL_DNS_NAMESPACE,
            "labels": {
                LATTICE_MANAGED_BY_LABEL: LATTICE_MANAGED_BY_VALUE
            }
        }
    })
}

/// Build all Kubernetes resource manifests for a single external-dns provider instance.
///
/// Returns a Vec of `serde_json::Value` containing:
/// - ServiceAccount
/// - ClusterRole (read access to services, ingresses, nodes, endpoints)
/// - ClusterRoleBinding
/// - Deployment with provider-specific args and credential env vars / mounts
pub fn build_external_dns_manifests(
    spec: &DNSProviderSpec,
    provider_name: &str,
    cluster_name: &str,
) -> Vec<Value> {
    let sa_name = format!("external-dns-{provider_name}");
    let deployment_name = format!("external-dns-{provider_name}");
    let cr_name = format!("external-dns-{provider_name}");
    let crb_name = format!("external-dns-{provider_name}");

    let sa = build_service_account(&sa_name);
    let cr = build_cluster_role(&cr_name);
    let crb = build_cluster_role_binding(&crb_name, &cr_name, &sa_name);
    let deployment = build_deployment(spec, &deployment_name, &sa_name, cluster_name);

    vec![sa, cr, crb, deployment]
}

fn build_service_account(name: &str) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {
            "name": name,
            "namespace": EXTERNAL_DNS_NAMESPACE,
            "labels": {
                LATTICE_MANAGED_BY_LABEL: LATTICE_MANAGED_BY_VALUE
            }
        }
    })
}

fn build_cluster_role(name: &str) -> Value {
    json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {
            "name": name,
            "labels": {
                LATTICE_MANAGED_BY_LABEL: LATTICE_MANAGED_BY_VALUE
            }
        },
        "rules": [
            {
                "apiGroups": [""],
                "resources": ["services", "endpoints", "nodes"],
                "verbs": ["get", "list", "watch"]
            },
            {
                "apiGroups": ["extensions", "networking.k8s.io"],
                "resources": ["ingresses"],
                "verbs": ["get", "list", "watch"]
            }
        ]
    })
}

fn build_cluster_role_binding(name: &str, role_name: &str, sa_name: &str) -> Value {
    json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {
            "name": name,
            "labels": {
                LATTICE_MANAGED_BY_LABEL: LATTICE_MANAGED_BY_VALUE
            }
        },
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": role_name
        },
        "subjects": [
            {
                "kind": "ServiceAccount",
                "name": sa_name,
                "namespace": EXTERNAL_DNS_NAMESPACE
            }
        ]
    })
}

/// Build common args shared by all provider types.
fn common_args(cluster_name: &str) -> Vec<String> {
    vec![
        "--policy=upsert-only".to_string(),
        "--registry=txt".to_string(),
        format!("--txt-owner-id=lattice-{cluster_name}"),
        "--interval=30s".to_string(),
        "--source=service".to_string(),
        "--source=ingress".to_string(),
    ]
}

/// Build provider-specific args, env vars, and volume mounts for the container.
fn provider_config(spec: &DNSProviderSpec) -> (Vec<String>, Vec<Value>, Vec<Value>, Vec<Value>) {
    let mut args = Vec::new();
    let mut env = Vec::new();
    let mut volume_mounts = Vec::new();
    let mut volumes = Vec::new();

    match spec.provider_type {
        DNSProviderType::Pihole => {
            let url = spec
                .pihole
                .as_ref()
                .map(|p| p.url.as_str())
                .unwrap_or("http://pihole.local");
            args.push("--provider=pihole".to_string());
            args.push(format!("--pihole-server={url}"));
            args.push("--pihole-password=$(PIHOLE_PASSWORD)".to_string());

            if let Some(ref secret_ref) = spec.credentials_secret_ref {
                env.push(json!({
                    "name": "EXTERNAL_DNS_PIHOLE_PASSWORD",
                    "valueFrom": {
                        "secretKeyRef": {
                            "name": secret_ref.name,
                            "key": "EXTERNAL_DNS_PIHOLE_PASSWORD"
                        }
                    }
                }));
            }
        }
        DNSProviderType::Route53 => {
            args.push("--provider=aws".to_string());
            args.push("--aws-zone-type=public".to_string());
            args.push(format!("--domain-filter={}", spec.zone));

            if let Some(ref secret_ref) = spec.credentials_secret_ref {
                env.push(json!({
                    "name": "AWS_ACCESS_KEY_ID",
                    "valueFrom": {
                        "secretKeyRef": {
                            "name": secret_ref.name,
                            "key": "AWS_ACCESS_KEY_ID"
                        }
                    }
                }));
                env.push(json!({
                    "name": "AWS_SECRET_ACCESS_KEY",
                    "valueFrom": {
                        "secretKeyRef": {
                            "name": secret_ref.name,
                            "key": "AWS_SECRET_ACCESS_KEY"
                        }
                    }
                }));
            }
        }
        DNSProviderType::Cloudflare => {
            let proxied = spec
                .cloudflare
                .as_ref()
                .map(|c| c.proxied)
                .unwrap_or(false);
            args.push("--provider=cloudflare".to_string());
            args.push(format!("--cloudflare-proxied={proxied}"));
            args.push(format!("--domain-filter={}", spec.zone));

            if let Some(ref secret_ref) = spec.credentials_secret_ref {
                env.push(json!({
                    "name": "CF_API_TOKEN",
                    "valueFrom": {
                        "secretKeyRef": {
                            "name": secret_ref.name,
                            "key": "CF_API_TOKEN"
                        }
                    }
                }));
            }
        }
        DNSProviderType::Google => {
            let project = spec
                .google
                .as_ref()
                .map(|g| g.project.as_str())
                .unwrap_or("");
            args.push("--provider=google".to_string());
            args.push(format!("--google-project={project}"));
            args.push(format!("--domain-filter={}", spec.zone));

            // Mount the service account key file
            env.push(json!({
                "name": "GOOGLE_APPLICATION_CREDENTIALS",
                "value": "/etc/google/credentials.json"
            }));

            if let Some(ref secret_ref) = spec.credentials_secret_ref {
                volume_mounts.push(json!({
                    "name": "google-credentials",
                    "mountPath": "/etc/google",
                    "readOnly": true
                }));
                volumes.push(json!({
                    "name": "google-credentials",
                    "secret": {
                        "secretName": secret_ref.name
                    }
                }));
            }
        }
        DNSProviderType::Azure => {
            let (sub_id, rg) = spec
                .azure
                .as_ref()
                .map(|a| (a.subscription_id.as_str(), a.resource_group.as_str()))
                .unwrap_or(("", ""));
            args.push("--provider=azure".to_string());
            args.push(format!("--azure-subscription-id={sub_id}"));
            args.push(format!("--azure-resource-group={rg}"));
            args.push(format!("--domain-filter={}", spec.zone));

            // Mount azure.json from secret
            if let Some(ref secret_ref) = spec.credentials_secret_ref {
                volume_mounts.push(json!({
                    "name": "azure-config",
                    "mountPath": "/etc/kubernetes",
                    "readOnly": true
                }));
                volumes.push(json!({
                    "name": "azure-config",
                    "secret": {
                        "secretName": secret_ref.name
                    }
                }));
                env.push(json!({
                    "name": "AZURE_AUTH_LOCATION",
                    "value": "/etc/kubernetes/azure.json"
                }));
            }
        }
        DNSProviderType::Designate => {
            args.push("--provider=designate".to_string());
            args.push(format!("--domain-filter={}", spec.zone));

            if let Some(ref secret_ref) = spec.credentials_secret_ref {
                for key in &[
                    "OS_AUTH_URL",
                    "OS_USERNAME",
                    "OS_PASSWORD",
                    "OS_PROJECT_NAME",
                    "OS_USER_DOMAIN_NAME",
                    "OS_PROJECT_DOMAIN_NAME",
                ] {
                    env.push(json!({
                        "name": key,
                        "valueFrom": {
                            "secretKeyRef": {
                                "name": secret_ref.name,
                                "key": key
                            }
                        }
                    }));
                }
            }
        }
        _ => {
            // Future provider types — add args as needed
            args.push(format!("--domain-filter={}", spec.zone));
        }
    }

    (args, env, volume_mounts, volumes)
}

fn build_deployment(
    spec: &DNSProviderSpec,
    name: &str,
    sa_name: &str,
    cluster_name: &str,
) -> Value {
    let mut all_args = common_args(cluster_name);
    let (provider_args, env, volume_mounts, volumes) = provider_config(spec);
    all_args.extend(provider_args);

    let mut container = json!({
        "name": "external-dns",
        "image": EXTERNAL_DNS_IMAGE,
        "args": all_args
    });

    if !env.is_empty() {
        container["env"] = json!(env);
    }
    if !volume_mounts.is_empty() {
        container["volumeMounts"] = json!(volume_mounts);
    }

    let mut pod_spec = json!({
        "serviceAccountName": sa_name,
        "containers": [container]
    });

    if !volumes.is_empty() {
        pod_spec["volumes"] = json!(volumes);
    }

    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": name,
            "namespace": EXTERNAL_DNS_NAMESPACE,
            "labels": {
                LATTICE_MANAGED_BY_LABEL: LATTICE_MANAGED_BY_VALUE
            }
        },
        "spec": {
            "replicas": 1,
            "selector": {
                "matchLabels": {
                    "app": name
                }
            },
            "template": {
                "metadata": {
                    "labels": {
                        "app": name
                    }
                },
                "spec": pod_spec
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_common::crd::{
        AzureDnsConfig, CloudflareConfig, DesignateConfig, GoogleDnsConfig, PiholeConfig,
        SecretRef,
    };

    fn make_spec(provider_type: DNSProviderType, zone: &str) -> DNSProviderSpec {
        DNSProviderSpec {
            provider_type,
            zone: zone.to_string(),
            resolver: None,
            credentials_secret_ref: Some(SecretRef {
                name: "test-creds".to_string(),
                namespace: "lattice-system".to_string(),
            }),
            pihole: None,
            route53: None,
            cloudflare: None,
            google: None,
            azure: None,
            designate: None,
        }
    }

    fn find_deployment(manifests: &[Value]) -> &Value {
        manifests
            .iter()
            .find(|m| m["kind"] == "Deployment")
            .expect("deployment manifest should exist")
    }

    fn deployment_args(deployment: &Value) -> Vec<&str> {
        deployment["spec"]["template"]["spec"]["containers"][0]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect()
    }

    fn deployment_env(deployment: &Value) -> Vec<&str> {
        deployment["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array()
            .map(|arr| arr.iter().map(|v| v["name"].as_str().unwrap()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn pihole_manifests() {
        let spec = DNSProviderSpec {
            pihole: Some(PiholeConfig {
                url: "http://pihole.home".to_string(),
            }),
            ..make_spec(DNSProviderType::Pihole, "home.local")
        };
        let manifests = build_external_dns_manifests(&spec, "pihole-local", "test-cluster");

        assert_eq!(manifests.len(), 4);
        assert_eq!(manifests[0]["kind"], "ServiceAccount");
        assert_eq!(manifests[1]["kind"], "ClusterRole");
        assert_eq!(manifests[2]["kind"], "ClusterRoleBinding");
        assert_eq!(manifests[3]["kind"], "Deployment");

        let dep = find_deployment(&manifests);
        let args = deployment_args(dep);
        assert!(args.contains(&"--provider=pihole"));
        assert!(args.contains(&"--pihole-server=http://pihole.home"));
        assert!(args.contains(&"--pihole-password=$(PIHOLE_PASSWORD)"));
        assert!(args.contains(&"--policy=upsert-only"));
        assert!(args.contains(&"--txt-owner-id=lattice-test-cluster"));
        assert!(args.contains(&"--source=service"));
        assert!(args.contains(&"--source=ingress"));

        let env_names = deployment_env(dep);
        assert!(env_names.contains(&"EXTERNAL_DNS_PIHOLE_PASSWORD"));
    }

    #[test]
    fn route53_manifests() {
        let spec = make_spec(DNSProviderType::Route53, "example.com");
        let manifests = build_external_dns_manifests(&spec, "route53-prod", "prod-cluster");

        let dep = find_deployment(&manifests);
        let args = deployment_args(dep);
        assert!(args.contains(&"--provider=aws"));
        assert!(args.contains(&"--aws-zone-type=public"));
        assert!(args.contains(&"--domain-filter=example.com"));
        assert!(args.contains(&"--registry=txt"));
        assert!(args.contains(&"--interval=30s"));

        let env_names = deployment_env(dep);
        assert!(env_names.contains(&"AWS_ACCESS_KEY_ID"));
        assert!(env_names.contains(&"AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn cloudflare_manifests_proxied() {
        let spec = DNSProviderSpec {
            cloudflare: Some(CloudflareConfig { proxied: true }),
            ..make_spec(DNSProviderType::Cloudflare, "example.com")
        };
        let manifests = build_external_dns_manifests(&spec, "cf-prod", "prod-cluster");

        let dep = find_deployment(&manifests);
        let args = deployment_args(dep);
        assert!(args.contains(&"--provider=cloudflare"));
        assert!(args.contains(&"--cloudflare-proxied=true"));
        assert!(args.contains(&"--domain-filter=example.com"));

        let env_names = deployment_env(dep);
        assert!(env_names.contains(&"CF_API_TOKEN"));
    }

    #[test]
    fn cloudflare_manifests_not_proxied() {
        let spec = DNSProviderSpec {
            cloudflare: Some(CloudflareConfig { proxied: false }),
            ..make_spec(DNSProviderType::Cloudflare, "example.com")
        };
        let manifests = build_external_dns_manifests(&spec, "cf-prod", "prod-cluster");

        let dep = find_deployment(&manifests);
        let args = deployment_args(dep);
        assert!(args.contains(&"--cloudflare-proxied=false"));
    }

    #[test]
    fn google_manifests() {
        let spec = DNSProviderSpec {
            google: Some(GoogleDnsConfig {
                project: "my-gcp-project".to_string(),
            }),
            ..make_spec(DNSProviderType::Google, "example.com")
        };
        let manifests = build_external_dns_manifests(&spec, "google-prod", "prod-cluster");

        let dep = find_deployment(&manifests);
        let args = deployment_args(dep);
        assert!(args.contains(&"--provider=google"));
        assert!(args.contains(&"--google-project=my-gcp-project"));
        assert!(args.contains(&"--domain-filter=example.com"));

        let env_names = deployment_env(dep);
        assert!(env_names.contains(&"GOOGLE_APPLICATION_CREDENTIALS"));

        // Check volume mount exists
        let vol_mounts = &dep["spec"]["template"]["spec"]["containers"][0]["volumeMounts"];
        assert!(vol_mounts.is_array());
        assert_eq!(vol_mounts[0]["mountPath"], "/etc/google");

        let volumes = &dep["spec"]["template"]["spec"]["volumes"];
        assert!(volumes.is_array());
        assert_eq!(volumes[0]["secret"]["secretName"], "test-creds");
    }

    #[test]
    fn azure_manifests() {
        let spec = DNSProviderSpec {
            azure: Some(AzureDnsConfig {
                subscription_id: "sub-123".to_string(),
                resource_group: "rg-dns".to_string(),
            }),
            ..make_spec(DNSProviderType::Azure, "example.com")
        };
        let manifests = build_external_dns_manifests(&spec, "azure-prod", "prod-cluster");

        let dep = find_deployment(&manifests);
        let args = deployment_args(dep);
        assert!(args.contains(&"--provider=azure"));
        assert!(args.contains(&"--azure-subscription-id=sub-123"));
        assert!(args.contains(&"--azure-resource-group=rg-dns"));
        assert!(args.contains(&"--domain-filter=example.com"));

        let env_names = deployment_env(dep);
        assert!(env_names.contains(&"AZURE_AUTH_LOCATION"));

        // Check azure.json volume mount
        let vol_mounts = &dep["spec"]["template"]["spec"]["containers"][0]["volumeMounts"];
        assert!(vol_mounts.is_array());
        assert_eq!(vol_mounts[0]["mountPath"], "/etc/kubernetes");
    }

    #[test]
    fn designate_manifests() {
        let spec = DNSProviderSpec {
            designate: Some(DesignateConfig {
                zone_id: Some("zone-abc".to_string()),
                region: Some("RegionOne".to_string()),
            }),
            ..make_spec(DNSProviderType::Designate, "internal.cloud")
        };
        let manifests = build_external_dns_manifests(&spec, "designate-prod", "prod-cluster");

        let dep = find_deployment(&manifests);
        let args = deployment_args(dep);
        assert!(args.contains(&"--provider=designate"));
        assert!(args.contains(&"--domain-filter=internal.cloud"));

        let env_names = deployment_env(dep);
        assert!(env_names.contains(&"OS_AUTH_URL"));
        assert!(env_names.contains(&"OS_USERNAME"));
        assert!(env_names.contains(&"OS_PASSWORD"));
        assert!(env_names.contains(&"OS_PROJECT_NAME"));
        assert!(env_names.contains(&"OS_USER_DOMAIN_NAME"));
        assert!(env_names.contains(&"OS_PROJECT_DOMAIN_NAME"));
    }

    #[test]
    fn managed_by_labels_on_all_resources() {
        let spec = make_spec(DNSProviderType::Route53, "example.com");
        let manifests = build_external_dns_manifests(&spec, "route53-prod", "test");

        for manifest in &manifests {
            let label = manifest["metadata"]["labels"][LATTICE_MANAGED_BY_LABEL]
                .as_str()
                .unwrap_or("");
            assert_eq!(
                label, LATTICE_MANAGED_BY_VALUE,
                "missing managed-by label on {}",
                manifest["kind"]
            );
        }
    }

    #[test]
    fn service_account_names_match() {
        let spec = make_spec(DNSProviderType::Route53, "example.com");
        let manifests = build_external_dns_manifests(&spec, "my-provider", "cluster");

        let sa_name = manifests[0]["metadata"]["name"].as_str().unwrap();
        assert_eq!(sa_name, "external-dns-my-provider");

        let dep_sa = manifests[3]["spec"]["template"]["spec"]["serviceAccountName"]
            .as_str()
            .unwrap();
        assert_eq!(dep_sa, sa_name);
    }

    #[test]
    fn cluster_role_has_correct_rules() {
        let spec = make_spec(DNSProviderType::Route53, "example.com");
        let manifests = build_external_dns_manifests(&spec, "test", "cluster");

        let cr = &manifests[1];
        let rules = cr["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);

        let core_resources: Vec<&str> = rules[0]["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(core_resources.contains(&"services"));
        assert!(core_resources.contains(&"endpoints"));
        assert!(core_resources.contains(&"nodes"));

        let ingress_resources: Vec<&str> = rules[1]["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(ingress_resources.contains(&"ingresses"));
    }

    #[test]
    fn no_credentials_omits_env() {
        let spec = DNSProviderSpec {
            credentials_secret_ref: None,
            ..make_spec(DNSProviderType::Route53, "example.com")
        };
        let manifests = build_external_dns_manifests(&spec, "test", "cluster");

        let dep = find_deployment(&manifests);
        // env key should not exist (no credentials)
        assert!(dep["spec"]["template"]["spec"]["containers"][0]["env"].is_null());
    }

    #[test]
    fn deployment_image_is_correct() {
        let spec = make_spec(DNSProviderType::Route53, "example.com");
        let manifests = build_external_dns_manifests(&spec, "test", "cluster");

        let dep = find_deployment(&manifests);
        let image = dep["spec"]["template"]["spec"]["containers"][0]["image"]
            .as_str()
            .unwrap();
        assert_eq!(image, EXTERNAL_DNS_IMAGE);
    }
}
