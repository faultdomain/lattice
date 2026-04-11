//! External-dns deployment reconciliation.
//!
//! Generates and applies external-dns Deployments for each DNSProvider referenced
//! by a LatticeCluster. External-dns watches Services/Ingresses and creates DNS
//! records in the configured provider.

use kube::api::{Api, Patch, PatchParams};
use kube::{Client, ResourceExt};
use serde_json::{json, Value};
use tracing::{debug, info, warn};

use lattice_common::{Error, LATTICE_MANAGED_BY_LABEL, LATTICE_MANAGED_BY_VALUE};
use lattice_core::{EXTERNAL_DNS_NAMESPACE, LATTICE_SYSTEM_NAMESPACE};
use lattice_crd::crd::{DNSProvider, DNSProviderSpec, DNSProviderType, LatticeCluster, SecretRef};

/// Container image for external-dns deployments.
const EXTERNAL_DNS_IMAGE: &str = "registry.k8s.io/external-dns/external-dns:v0.15.1";

/// Field manager for server-side apply.
const FIELD_MANAGER: &str = "lattice-cluster-controller";

/// Reconcile external-dns deployments for all DNS providers configured on the cluster.
///
/// For each DNSProvider referenced in `spec.dns`, generates and applies the necessary
/// Kubernetes resources (Namespace, ServiceAccount, RBAC, Deployment) via SSA.
pub async fn reconcile_external_dns(
    client: &Client,
    cluster: &LatticeCluster,
    cache: &lattice_cache::ResourceCache,
) -> Result<(), Error> {
    let dns_config = match &cluster.spec.dns {
        Some(dns) if !dns.providers.is_empty() => dns,
        _ => return Ok(()),
    };

    let cluster_name = cluster.name_any();
    let ns = cluster
        .namespace()
        .unwrap_or_else(|| LATTICE_SYSTEM_NAMESPACE.to_string());

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

    for provider_name in dns_config.providers.values() {
        let provider = match cache.get_namespaced::<DNSProvider>(provider_name, &ns) {
            Some(p) => p,
            None => {
                warn!(provider = %provider_name, "DNSProvider not found in cache for external-dns, skipping");
                continue;
            }
        };

        // Create ESO ExternalSecret for the provider's credentials in external-dns namespace
        if let Some(ref credentials) = provider.spec.credentials {
            lattice_secret_provider::credentials::ensure_credentials(
                client,
                &provider.name_any(),
                credentials,
                provider.spec.credential_data.as_ref(),
                EXTERNAL_DNS_NAMESPACE,
                "lattice-cluster-controller",
            )
            .await
            .map_err(|e| {
                Error::internal(format!(
                    "failed to sync DNS credentials for {provider_name}: {e}"
                ))
            })?;
        }

        let resolved_secret_ref = provider.k8s_secret_ref();
        let manifests = build_external_dns_manifests(
            &provider.spec,
            provider_name,
            &cluster_name,
            resolved_secret_ref.as_ref(),
        );

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
                .map_err(|e| {
                    Error::internal(format!("failed to apply ServiceAccount {name}: {e}"))
                })?;
        }
        "ClusterRole" => {
            let api: Api<k8s_openapi::api::rbac::v1::ClusterRole> = Api::all(client.clone());
            api.patch(name, &patch_params, &Patch::Apply(manifest))
                .await
                .map_err(|e| Error::internal(format!("failed to apply ClusterRole {name}: {e}")))?;
        }
        "ClusterRoleBinding" => {
            let api: Api<k8s_openapi::api::rbac::v1::ClusterRoleBinding> = Api::all(client.clone());
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
/// `secret_ref` is the resolved ESO credential reference from `k8s_secret_ref()`,
/// pointing to the synced secret in the external-dns namespace.
pub fn build_external_dns_manifests(
    spec: &DNSProviderSpec,
    provider_name: &str,
    cluster_name: &str,
    secret_ref: Option<&SecretRef>,
) -> Vec<Value> {
    let sa_name = format!("external-dns-{provider_name}");
    let deployment_name = format!("external-dns-{provider_name}");
    let cr_name = format!("external-dns-{provider_name}");
    let crb_name = format!("external-dns-{provider_name}");

    let sa = build_service_account(&sa_name);
    let cr = build_cluster_role(&cr_name);
    let crb = build_cluster_role_binding(&crb_name, &cr_name, &sa_name);
    let deployment = build_deployment(spec, &deployment_name, &sa_name, cluster_name, secret_ref);

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
                "resources": ["namespaces"],
                "verbs": ["get", "list", "watch"]
            },
            {
                "apiGroups": ["gateway.networking.k8s.io"],
                "resources": ["gateways", "httproutes", "grpcroutes"],
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
        "--request-timeout=120s".to_string(),
        "--interval=30s".to_string(),
        "--source=gateway-httproute".to_string(),
        "--source=gateway-grpcroute".to_string(),
    ]
}

/// Provider-specific container configuration for an external-dns Deployment.
struct ProviderConfig {
    args: Vec<String>,
    env: Vec<Value>,
    volume_mounts: Vec<Value>,
    volumes: Vec<Value>,
}

/// Build a secretKeyRef env var entry.
fn secret_env(name: &str, secret_name: &str, key: &str) -> Value {
    json!({
        "name": name,
        "valueFrom": {
            "secretKeyRef": {
                "name": secret_name,
                "key": key
            }
        }
    })
}

/// Build a volume + volume mount pair from a secret.
fn secret_volume(volume_name: &str, secret_name: &str, mount_path: &str) -> (Value, Value) {
    let volume = json!({
        "name": volume_name,
        "secret": {
            "secretName": secret_name
        }
    });
    let mount = json!({
        "name": volume_name,
        "mountPath": mount_path,
        "readOnly": true
    });
    (volume, mount)
}

/// Build provider-specific args, env vars, and volume mounts for the container.
fn provider_config(spec: &DNSProviderSpec, secret_ref: Option<&SecretRef>) -> ProviderConfig {
    match spec.provider_type {
        DNSProviderType::Pihole => pihole_config(spec, secret_ref),
        DNSProviderType::Route53 => route53_config(spec, secret_ref),
        DNSProviderType::Cloudflare => cloudflare_config(spec, secret_ref),
        DNSProviderType::Google => google_config(spec, secret_ref),
        DNSProviderType::Azure => azure_config(spec, secret_ref),
        DNSProviderType::Designate => designate_config(spec, secret_ref),
        _ => fallback_config(spec),
    }
}

fn pihole_config(spec: &DNSProviderSpec, secret_ref: Option<&SecretRef>) -> ProviderConfig {
    let url = spec
        .pihole
        .as_ref()
        .map(|p| p.url.as_str())
        .unwrap_or("http://pihole.local");

    let env = secret_ref
        .map(|sr| {
            vec![secret_env(
                "EXTERNAL_DNS_PIHOLE_PASSWORD",
                &sr.name,
                "EXTERNAL_DNS_PIHOLE_PASSWORD",
            )]
        })
        .unwrap_or_default();

    ProviderConfig {
        args: vec![
            "--provider=pihole".to_string(),
            format!("--pihole-server={url}"),
            "--pihole-password=$(EXTERNAL_DNS_PIHOLE_PASSWORD)".to_string(),
        ],
        env,
        volume_mounts: Vec::new(),
        volumes: Vec::new(),
    }
}

fn route53_config(spec: &DNSProviderSpec, secret_ref: Option<&SecretRef>) -> ProviderConfig {
    let env = secret_ref
        .map(|sr| {
            vec![
                secret_env("AWS_ACCESS_KEY_ID", &sr.name, "AWS_ACCESS_KEY_ID"),
                secret_env("AWS_SECRET_ACCESS_KEY", &sr.name, "AWS_SECRET_ACCESS_KEY"),
            ]
        })
        .unwrap_or_default();

    ProviderConfig {
        args: vec![
            "--provider=aws".to_string(),
            "--aws-zone-type=public".to_string(),
            format!("--domain-filter={}", spec.zone),
        ],
        env,
        volume_mounts: Vec::new(),
        volumes: Vec::new(),
    }
}

fn cloudflare_config(spec: &DNSProviderSpec, secret_ref: Option<&SecretRef>) -> ProviderConfig {
    let proxied = spec.cloudflare.as_ref().map(|c| c.proxied).unwrap_or(false);

    let env = secret_ref
        .map(|sr| vec![secret_env("CF_API_TOKEN", &sr.name, "CF_API_TOKEN")])
        .unwrap_or_default();

    ProviderConfig {
        args: vec![
            "--provider=cloudflare".to_string(),
            format!("--cloudflare-proxied={proxied}"),
            format!("--domain-filter={}", spec.zone),
        ],
        env,
        volume_mounts: Vec::new(),
        volumes: Vec::new(),
    }
}

fn google_config(spec: &DNSProviderSpec, secret_ref: Option<&SecretRef>) -> ProviderConfig {
    let project = spec
        .google
        .as_ref()
        .map(|g| g.project.as_str())
        .unwrap_or("");

    let env = vec![json!({
        "name": "GOOGLE_APPLICATION_CREDENTIALS",
        "value": "/etc/google/credentials.json"
    })];

    let mut volume_mounts = Vec::new();
    let mut volumes = Vec::new();
    if let Some(sr) = secret_ref {
        let (vol, mount) = secret_volume("google-credentials", &sr.name, "/etc/google");
        volumes.push(vol);
        volume_mounts.push(mount);
    }

    ProviderConfig {
        args: vec![
            "--provider=google".to_string(),
            format!("--google-project={project}"),
            format!("--domain-filter={}", spec.zone),
        ],
        env,
        volume_mounts,
        volumes,
    }
}

fn azure_config(spec: &DNSProviderSpec, secret_ref: Option<&SecretRef>) -> ProviderConfig {
    let (sub_id, rg) = spec
        .azure
        .as_ref()
        .map(|a| (a.subscription_id.as_str(), a.resource_group.as_str()))
        .unwrap_or(("", ""));

    let mut env = Vec::new();
    let mut volume_mounts = Vec::new();
    let mut volumes = Vec::new();
    if let Some(sr) = secret_ref {
        let (vol, mount) = secret_volume("azure-config", &sr.name, "/etc/kubernetes");
        volumes.push(vol);
        volume_mounts.push(mount);
        env.push(json!({
            "name": "AZURE_AUTH_LOCATION",
            "value": "/etc/kubernetes/azure.json"
        }));
    }

    ProviderConfig {
        args: vec![
            "--provider=azure".to_string(),
            format!("--azure-subscription-id={sub_id}"),
            format!("--azure-resource-group={rg}"),
            format!("--domain-filter={}", spec.zone),
        ],
        env,
        volume_mounts,
        volumes,
    }
}

fn designate_config(spec: &DNSProviderSpec, secret_ref: Option<&SecretRef>) -> ProviderConfig {
    let env = secret_ref
        .map(|sr| {
            [
                "OS_AUTH_URL",
                "OS_USERNAME",
                "OS_PASSWORD",
                "OS_PROJECT_NAME",
                "OS_USER_DOMAIN_NAME",
                "OS_PROJECT_DOMAIN_NAME",
            ]
            .iter()
            .map(|key| secret_env(key, &sr.name, key))
            .collect()
        })
        .unwrap_or_default();

    ProviderConfig {
        args: vec![
            "--provider=designate".to_string(),
            format!("--domain-filter={}", spec.zone),
        ],
        env,
        volume_mounts: Vec::new(),
        volumes: Vec::new(),
    }
}

/// Fallback for future provider types.
fn fallback_config(spec: &DNSProviderSpec) -> ProviderConfig {
    ProviderConfig {
        args: vec![format!("--domain-filter={}", spec.zone)],
        env: Vec::new(),
        volume_mounts: Vec::new(),
        volumes: Vec::new(),
    }
}

fn build_deployment(
    spec: &DNSProviderSpec,
    name: &str,
    sa_name: &str,
    cluster_name: &str,
    secret_ref: Option<&SecretRef>,
) -> Value {
    let mut all_args = common_args(cluster_name);
    let ProviderConfig {
        args: provider_args,
        env,
        volume_mounts,
        volumes,
    } = provider_config(spec, secret_ref);
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
    use lattice_crd::crd::{
        AzureDnsConfig, CloudflareConfig, DesignateConfig, GoogleDnsConfig, PiholeConfig,
    };

    fn test_secret_ref() -> SecretRef {
        SecretRef {
            name: "test-creds".to_string(),
            namespace: "external-dns".to_string(),
        }
    }

    fn make_spec(provider_type: DNSProviderType, zone: &str) -> DNSProviderSpec {
        DNSProviderSpec::new(provider_type, zone)
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
        let sr = test_secret_ref();
        let manifests =
            build_external_dns_manifests(&spec, "pihole-local", "test-cluster", Some(&sr));

        assert_eq!(manifests.len(), 4);
        assert_eq!(manifests[0]["kind"], "ServiceAccount");
        assert_eq!(manifests[1]["kind"], "ClusterRole");
        assert_eq!(manifests[2]["kind"], "ClusterRoleBinding");
        assert_eq!(manifests[3]["kind"], "Deployment");

        let dep = find_deployment(&manifests);
        let args = deployment_args(dep);
        assert!(args.contains(&"--provider=pihole"));
        assert!(args.contains(&"--pihole-server=http://pihole.home"));
        assert!(args.contains(&"--pihole-password=$(EXTERNAL_DNS_PIHOLE_PASSWORD)"));
        assert!(args.contains(&"--policy=upsert-only"));
        assert!(args.contains(&"--txt-owner-id=lattice-test-cluster"));
        assert!(args.contains(&"--source=gateway-httproute"));
        assert!(args.contains(&"--source=gateway-grpcroute"));

        let env_names = deployment_env(dep);
        assert!(env_names.contains(&"EXTERNAL_DNS_PIHOLE_PASSWORD"));
    }

    #[test]
    fn route53_manifests() {
        let spec = make_spec(DNSProviderType::Route53, "example.com");
        let sr = test_secret_ref();
        let manifests =
            build_external_dns_manifests(&spec, "route53-prod", "prod-cluster", Some(&sr));

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
        let sr = test_secret_ref();
        let manifests = build_external_dns_manifests(&spec, "cf-prod", "prod-cluster", Some(&sr));

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
        let sr = test_secret_ref();
        let manifests = build_external_dns_manifests(&spec, "cf-prod", "prod-cluster", Some(&sr));

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
        let sr = test_secret_ref();
        let manifests =
            build_external_dns_manifests(&spec, "google-prod", "prod-cluster", Some(&sr));

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
        let sr = test_secret_ref();
        let manifests =
            build_external_dns_manifests(&spec, "azure-prod", "prod-cluster", Some(&sr));

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
        let sr = test_secret_ref();
        let manifests =
            build_external_dns_manifests(&spec, "designate-prod", "prod-cluster", Some(&sr));

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
        let sr = test_secret_ref();
        let manifests = build_external_dns_manifests(&spec, "route53-prod", "test", Some(&sr));

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
        let sr = test_secret_ref();
        let manifests = build_external_dns_manifests(&spec, "my-provider", "cluster", Some(&sr));

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
        let sr = test_secret_ref();
        let manifests = build_external_dns_manifests(&spec, "test", "cluster", Some(&sr));

        let cr = &manifests[1];
        let rules = cr["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);

        let core_resources: Vec<&str> = rules[0]["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(core_resources.contains(&"namespaces"));

        let gateway_resources: Vec<&str> = rules[1]["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(gateway_resources.contains(&"gateways"));
        assert!(gateway_resources.contains(&"httproutes"));
        assert!(gateway_resources.contains(&"grpcroutes"));
    }

    #[test]
    fn no_credentials_omits_env() {
        let spec = make_spec(DNSProviderType::Route53, "example.com");
        let manifests = build_external_dns_manifests(&spec, "test", "cluster", None);

        let dep = find_deployment(&manifests);
        // env key should not exist (no credentials)
        assert!(dep["spec"]["template"]["spec"]["containers"][0]["env"].is_null());
    }

    #[test]
    fn deployment_image_is_correct() {
        let spec = make_spec(DNSProviderType::Route53, "example.com");
        let sr = test_secret_ref();
        let manifests = build_external_dns_manifests(&spec, "test", "cluster", Some(&sr));

        let dep = find_deployment(&manifests);
        let image = dep["spec"]["template"]["spec"]["containers"][0]["image"]
            .as_str()
            .unwrap();
        assert_eq!(image, EXTERNAL_DNS_IMAGE);
    }

    // =========================================================================
    // Credential key mapping: ESO secret keys must match deployment secretKeyRef
    // =========================================================================

    /// Extract all secretKeyRef key names from deployment env vars
    fn env_secret_keys(deployment: &Value) -> Vec<String> {
        deployment["spec"]["template"]["spec"]["containers"][0]["env"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v["valueFrom"]["secretKeyRef"]["key"].as_str())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Extract the secret name from a volume mount
    fn volume_secret_name(deployment: &Value) -> Option<String> {
        deployment["spec"]["template"]["spec"]["volumes"]
            .as_array()
            .and_then(|vols| vols.first())
            .and_then(|v| v["secret"]["secretName"].as_str())
            .map(String::from)
    }

    #[test]
    fn pihole_eso_keys_match_deployment() {
        // User declares: keys: [EXTERNAL_DNS_PIHOLE_PASSWORD]
        // ESO syncs that key into the secret
        // Deployment reads: secretKeyRef.key = "EXTERNAL_DNS_PIHOLE_PASSWORD"
        let eso_keys = vec!["EXTERNAL_DNS_PIHOLE_PASSWORD"];

        let sr = SecretRef {
            name: "pihole-e2e-credentials".to_string(),
            namespace: "external-dns".to_string(),
        };
        let spec = DNSProviderSpec {
            pihole: Some(PiholeConfig {
                url: "http://pihole.home".to_string(),
            }),
            ..make_spec(DNSProviderType::Pihole, "home.local")
        };
        let manifests = build_external_dns_manifests(&spec, "pihole-e2e", "cluster", Some(&sr));
        let dep = find_deployment(&manifests);

        let dep_keys = env_secret_keys(dep);
        for key in &eso_keys {
            assert!(dep_keys.contains(&key.to_string()),
                "deployment expects key '{key}' but ESO would sync keys: {eso_keys:?}, deployment reads: {dep_keys:?}");
        }
        assert_eq!(
            dep["spec"]["template"]["spec"]["containers"][0]["env"][0]["valueFrom"]["secretKeyRef"]
                ["name"],
            "pihole-e2e-credentials"
        );
    }

    #[test]
    fn route53_eso_keys_match_deployment() {
        let eso_keys = vec!["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"];

        let sr = SecretRef {
            name: "route53-prod-credentials".to_string(),
            namespace: "external-dns".to_string(),
        };
        let spec = make_spec(DNSProviderType::Route53, "example.com");
        let manifests = build_external_dns_manifests(&spec, "route53-prod", "cluster", Some(&sr));
        let dep = find_deployment(&manifests);

        let dep_keys = env_secret_keys(dep);
        for key in &eso_keys {
            assert!(
                dep_keys.contains(&key.to_string()),
                "deployment expects key '{key}' from ESO secret"
            );
        }
    }

    #[test]
    fn cloudflare_eso_keys_match_deployment() {
        let eso_keys = vec!["CF_API_TOKEN"];

        let sr = SecretRef {
            name: "cf-prod-credentials".to_string(),
            namespace: "external-dns".to_string(),
        };
        let spec = DNSProviderSpec {
            cloudflare: Some(CloudflareConfig { proxied: false }),
            ..make_spec(DNSProviderType::Cloudflare, "example.com")
        };
        let manifests = build_external_dns_manifests(&spec, "cf-prod", "cluster", Some(&sr));
        let dep = find_deployment(&manifests);

        let dep_keys = env_secret_keys(dep);
        for key in &eso_keys {
            assert!(
                dep_keys.contains(&key.to_string()),
                "deployment expects key '{key}' from ESO secret"
            );
        }
    }

    #[test]
    fn google_eso_secret_mounted_as_volume() {
        // Google uses a volume mount, not env secretKeyRef
        let sr = SecretRef {
            name: "google-prod-credentials".to_string(),
            namespace: "external-dns".to_string(),
        };
        let spec = DNSProviderSpec {
            google: Some(GoogleDnsConfig {
                project: "my-project".to_string(),
            }),
            ..make_spec(DNSProviderType::Google, "example.com")
        };
        let manifests = build_external_dns_manifests(&spec, "google-prod", "cluster", Some(&sr));
        let dep = find_deployment(&manifests);

        // Volume references the ESO-synced secret
        assert_eq!(
            volume_secret_name(dep).as_deref(),
            Some("google-prod-credentials")
        );
        // GOOGLE_APPLICATION_CREDENTIALS points to the mount
        let env_names = deployment_env(dep);
        assert!(env_names.contains(&"GOOGLE_APPLICATION_CREDENTIALS"));
    }

    #[test]
    fn designate_eso_keys_match_deployment() {
        let eso_keys = vec![
            "OS_AUTH_URL",
            "OS_USERNAME",
            "OS_PASSWORD",
            "OS_PROJECT_NAME",
            "OS_USER_DOMAIN_NAME",
            "OS_PROJECT_DOMAIN_NAME",
        ];

        let sr = SecretRef {
            name: "designate-prod-credentials".to_string(),
            namespace: "external-dns".to_string(),
        };
        let spec = DNSProviderSpec {
            designate: Some(DesignateConfig {
                zone_id: Some("zone-abc".to_string()),
                region: Some("RegionOne".to_string()),
            }),
            ..make_spec(DNSProviderType::Designate, "internal.cloud")
        };
        let manifests = build_external_dns_manifests(&spec, "designate-prod", "cluster", Some(&sr));
        let dep = find_deployment(&manifests);

        let dep_keys = env_secret_keys(dep);
        for key in &eso_keys {
            assert!(
                dep_keys.contains(&key.to_string()),
                "deployment expects key '{key}' from ESO secret"
            );
        }
    }

    #[test]
    fn azure_eso_secret_mounted_as_volume() {
        let sr = SecretRef {
            name: "azure-prod-credentials".to_string(),
            namespace: "external-dns".to_string(),
        };
        let spec = DNSProviderSpec {
            azure: Some(AzureDnsConfig {
                subscription_id: "sub-123".to_string(),
                resource_group: "rg-dns".to_string(),
            }),
            ..make_spec(DNSProviderType::Azure, "example.com")
        };
        let manifests = build_external_dns_manifests(&spec, "azure-prod", "cluster", Some(&sr));
        let dep = find_deployment(&manifests);

        assert_eq!(
            volume_secret_name(dep).as_deref(),
            Some("azure-prod-credentials")
        );
        let env_names = deployment_env(dep);
        assert!(env_names.contains(&"AZURE_AUTH_LOCATION"));
    }
}
