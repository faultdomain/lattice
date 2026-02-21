//! LatticeService helpers: builders, deploy/wait, secrets, pod verification, regcreds, cert-manager.
#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;

use kube::api::Api;
use lattice_common::crd::LatticeService;
use lattice_common::LOCAL_SECRETS_NAMESPACE;
use tracing::info;

use super::cedar::{
    apply_apparmor_override_policy, apply_binary_wildcard_override_policy, apply_cedar_policy_crd,
    apply_test_binaries_override_policy,
};
use super::cluster::load_registry_credentials;
use super::docker::run_kubectl;
use super::kubernetes::{client_from_kubeconfig, create_with_retry};
use super::{wait_for_condition, BUSYBOX_IMAGE, REGCREDS_PROVIDER, REGCREDS_REMOTE_KEY};

// =============================================================================
// LatticeService Test Helpers
// =============================================================================

/// Build a LatticeService with busybox boilerplate: ghcr-creds, ports (http:8080),
/// ObjectMeta, RuntimeSpec with imagePullSecrets.
///
/// Callers provide their own `containers` and `resources`; this helper adds
/// ghcr-creds to `resources` and wraps everything in the standard shell.
pub fn build_busybox_service(
    name: &str,
    namespace: &str,
    containers: BTreeMap<String, lattice_common::crd::ContainerSpec>,
    mut resources: BTreeMap<String, lattice_common::crd::ResourceSpec>,
) -> LatticeService {
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use lattice_common::crd::{
        LatticeServiceSpec, PortSpec, ResourceSpec, ResourceType, RuntimeSpec, ServicePortsSpec,
        WorkloadSpec,
    };

    // Add ghcr-creds only if not already provided by the caller
    if !resources.contains_key("ghcr-creds") {
        let mut reg_params = BTreeMap::new();
        reg_params.insert("provider".to_string(), serde_json::json!(REGCREDS_PROVIDER));
        reg_params.insert("refreshInterval".to_string(), serde_json::json!("1h"));
        resources.insert(
            "ghcr-creds".to_string(),
            ResourceSpec {
                type_: ResourceType::Secret,
                id: Some(REGCREDS_REMOTE_KEY.to_string()),
                params: Some(reg_params),
                ..Default::default()
            },
        );
    }

    let mut ports = BTreeMap::new();
    ports.insert(
        "http".to_string(),
        PortSpec {
            port: 8080,
            target_port: None,
            protocol: None,
        },
    );

    LatticeService {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            workload: WorkloadSpec {
                containers,
                resources,
                service: Some(ServicePortsSpec { ports }),
            },
            runtime: RuntimeSpec {
                image_pull_secrets: vec!["ghcr-creds".to_string()],
                ..Default::default()
            },
            ..Default::default()
        },
        status: None,
    }
}

/// Create a LatticeService with secret resources for testing.
///
/// This is the canonical builder for test services with secrets.
/// Used by both Cedar secret tests and ESO pipeline tests.
///
/// # Arguments
/// * `name` - Service name
/// * `namespace` - Target namespace
/// * `secrets` - Vec of (resource_name, remote_key, provider, optional_keys)
pub fn create_service_with_secrets(
    name: &str,
    namespace: &str,
    secrets: Vec<(&str, &str, &str, Option<Vec<&str>>)>,
) -> LatticeService {
    use lattice_common::crd::{
        ContainerSpec, ResourceQuantity, ResourceRequirements, ResourceSpec, ResourceType,
    };

    let mut resources = BTreeMap::new();
    for (resource_name, remote_key, provider, keys) in secrets {
        let mut params = BTreeMap::new();
        params.insert("provider".to_string(), serde_json::json!(provider));
        if let Some(ks) = keys {
            params.insert("keys".to_string(), serde_json::json!(ks));
        }
        params.insert("refreshInterval".to_string(), serde_json::json!("1h"));

        resources.insert(
            resource_name.to_string(),
            ResourceSpec {
                type_: ResourceType::Secret,
                id: Some(remote_key.to_string()),
                params: Some(params),
                ..Default::default()
            },
        );
    }

    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: BUSYBOX_IMAGE.to_string(),
            command: Some(vec!["/bin/sleep".to_string(), "infinity".to_string()]),
            resources: Some(ResourceRequirements {
                requests: Some(ResourceQuantity {
                    cpu: Some("50m".to_string()),
                    memory: Some("64Mi".to_string()),
                }),
                limits: Some(ResourceQuantity {
                    cpu: Some("200m".to_string()),
                    memory: Some("128Mi".to_string()),
                }),
            }),
            security: Some(lattice_common::crd::SecurityContext {
                apparmor_profile: Some("Unconfined".to_string()),
                allowed_binaries: vec!["/bin/printenv".to_string(), "/bin/cat".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    build_busybox_service(name, namespace, containers, resources)
}

/// Set the main container to run as root (busybox needs this).
pub fn with_run_as_root(mut service: LatticeService) -> LatticeService {
    if let Some(container) = service.spec.workload.containers.get_mut("main") {
        let security = container
            .security
            .get_or_insert_with(lattice_common::crd::SecurityContext::default);
        security.run_as_user = Some(0);
    }
    service
}

/// Create a test LatticeService with security overrides.
///
/// Builds a minimal service with the specified security context on the main container
/// and optional pod-level settings. Used by Cedar security override integration tests.
/// Always sets `apparmor_profile: Unconfined` if not already specified, since Docker
/// KIND clusters don't have AppArmor.
pub fn create_service_with_security_overrides(
    name: &str,
    namespace: &str,
    mut security: lattice_common::crd::SecurityContext,
    host_network: Option<bool>,
) -> LatticeService {
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use lattice_common::crd::{
        ContainerSpec, LatticeServiceSpec, PortSpec, RuntimeSpec, ServicePortsSpec, WorkloadSpec,
    };

    // Docker KIND clusters don't have AppArmor — ensure Unconfined
    if security.apparmor_profile.is_none() {
        security.apparmor_profile = Some("Unconfined".to_string());
    }

    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: BUSYBOX_IMAGE.to_string(),
            command: Some(vec!["/bin/sleep".to_string(), "infinity".to_string()]),
            security: Some(security),
            ..Default::default()
        },
    );

    let mut ports = BTreeMap::new();
    ports.insert(
        "http".to_string(),
        PortSpec {
            port: 8080,
            target_port: None,
            protocol: None,
        },
    );

    LatticeService {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            workload: WorkloadSpec {
                containers,
                service: Some(ServicePortsSpec { ports }),
                ..Default::default()
            },
            runtime: RuntimeSpec {
                host_network,
                ..Default::default()
            },
            ..Default::default()
        },
        status: None,
    }
}

/// Wait for a LatticeService to reach the expected phase.
///
/// Polls the service status via kubectl until the phase matches or timeout expires.
/// Used by Cedar secret tests, ESO pipeline tests, and secrets integration tests.
pub async fn wait_for_service_phase(
    kubeconfig: &str,
    namespace: &str,
    name: &str,
    phase: &str,
    timeout: Duration,
) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let ns = namespace.to_string();
    let svc_name = name.to_string();
    let expected_phase = phase.to_string();

    wait_for_condition(
        &format!("LatticeService {}/{} to reach {}", namespace, name, phase),
        timeout,
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let ns = ns.clone();
            let svc_name = svc_name.clone();
            let expected_phase = expected_phase.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "latticeservice",
                    &svc_name,
                    "-n",
                    &ns,
                    "-o",
                    "jsonpath={.status.phase}",
                ])
                .await;

                match output {
                    Ok(current_phase) => {
                        let current = current_phase.trim();
                        info!("LatticeService {}/{} phase: {}", ns, svc_name, current);
                        Ok(current == expected_phase)
                    }
                    Err(e) => {
                        info!(
                            "Error checking LatticeService {}/{} phase: {}",
                            ns, svc_name, e
                        );
                        Ok(false)
                    }
                }
            }
        },
    )
    .await
}

/// Wait for a LatticeService to reach the given phase AND have a condition
/// message containing `message_substring`. Phase and message are read atomically
/// in a single kubectl call to avoid races with phase transitions.
pub async fn wait_for_service_phase_with_message(
    kubeconfig: &str,
    namespace: &str,
    name: &str,
    phase: &str,
    message_substring: &str,
    timeout: Duration,
) -> Result<(), String> {
    let kc = kubeconfig.to_string();
    let ns = namespace.to_string();
    let svc_name = name.to_string();
    let expected_phase = phase.to_string();
    let expected_msg = message_substring.to_string();

    wait_for_condition(
        &format!(
            "LatticeService {}/{} to reach {} with '{}'",
            namespace, name, phase, message_substring
        ),
        timeout,
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let ns = ns.clone();
            let svc_name = svc_name.clone();
            let expected_phase = expected_phase.clone();
            let expected_msg = expected_msg.clone();
            async move {
                let output = run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "get",
                    "latticeservice",
                    &svc_name,
                    "-n",
                    &ns,
                    "-o",
                    "jsonpath={.status.phase} {.status.conditions[0].message}",
                ])
                .await;

                match output {
                    Ok(raw) => {
                        let raw = raw.trim();
                        let current_phase = raw.split_whitespace().next().unwrap_or("");
                        info!(
                            "LatticeService {}/{} phase: {}",
                            ns, svc_name, current_phase
                        );
                        Ok(current_phase == expected_phase && raw.contains(&expected_msg))
                    }
                    Err(_) => Ok(false),
                }
            }
        },
    )
    .await
}

/// Deploy a LatticeService and wait until it reaches the expected phase.
///
/// Encapsulates the common pattern of creating a kube client, creating the service
/// via the API, and waiting for the status phase to match. When `expected_message`
/// is provided, also asserts that the status condition message contains the substring.
pub async fn deploy_and_wait_for_phase(
    kubeconfig: &str,
    namespace: &str,
    service: LatticeService,
    expected_phase: &str,
    expected_message: Option<&str>,
    timeout: Duration,
) -> Result<(), String> {
    let name = service
        .metadata
        .name
        .as_deref()
        .ok_or("service missing metadata.name")?
        .to_string();

    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, namespace);

    create_with_retry(&api, &service, &name).await?;

    match expected_message {
        Some(substring) => {
            wait_for_service_phase_with_message(
                kubeconfig,
                namespace,
                &name,
                expected_phase,
                substring,
                timeout,
            )
            .await
        }
        None => wait_for_service_phase(kubeconfig, namespace, &name, expected_phase, timeout).await,
    }
}

// =============================================================================
// Local Secrets Helpers
// =============================================================================

/// Seed a K8s Secret in the `lattice-secrets` namespace with the source label.
///
/// The secret will be labeled with `lattice.dev/secret-source: "true"` so the
/// webhook handler will serve it.
pub async fn seed_local_secret(
    kubeconfig: &str,
    secret_name: &str,
    data: &BTreeMap<String, String>,
) -> Result<(), String> {
    info!("[LocalSecrets] Seeding source secret '{}'...", secret_name);

    // Ensure the namespace exists
    ensure_namespace(kubeconfig, LOCAL_SECRETS_NAMESPACE).await?;

    // Build stringData entries
    let string_data: String = data
        .iter()
        .map(|(k, v)| format!("  {}: \"{}\"", k, v.replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join("\n");

    let secret_yaml = format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    lattice.dev/secret-source: "true"
type: Opaque
stringData:
{string_data}
"#,
        name = secret_name,
        namespace = LOCAL_SECRETS_NAMESPACE,
        string_data = string_data,
    );

    super::cedar::apply_yaml_with_retry(kubeconfig, &secret_yaml).await?;

    info!("[LocalSecrets] Source secret '{}' seeded", secret_name);
    Ok(())
}

/// Ensure a namespace exists (creates if missing, no-op if present)
pub async fn ensure_namespace(kubeconfig: &str, namespace: &str) -> Result<(), String> {
    let ns_yaml = format!(
        r#"apiVersion: v1
kind: Namespace
metadata:
  name: {namespace}
"#,
        namespace = namespace,
    );

    super::cedar::apply_yaml_with_retry(kubeconfig, &ns_yaml).await
}

/// Wait for a ClusterSecretStore to exist in the cluster.
///
/// The operator creates `lattice-local` at startup via
/// `ensure_local_webhook_infrastructure()`. This polls until the object
/// exists, which means the operator has completed its startup sequence.
pub async fn wait_for_cluster_secret_store_ready(
    kubeconfig: &str,
    store_name: &str,
) -> Result<(), String> {
    info!(
        "[ClusterSecretStore] Waiting for '{}' to exist...",
        store_name
    );

    wait_for_condition(
        &format!("ClusterSecretStore '{}' to exist", store_name),
        Duration::from_secs(120),
        Duration::from_secs(3),
        || async move {
            let output = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "get",
                "clustersecretstore",
                store_name,
                "-o",
                "jsonpath={.metadata.name}",
            ])
            .await;

            match output {
                Ok(name) if name.trim() == store_name => {
                    info!("[ClusterSecretStore] '{}' exists", store_name);
                    Ok(true)
                }
                Ok(_) => Ok(false),
                Err(e) => {
                    info!("[ClusterSecretStore] '{}' not found yet: {}", store_name, e);
                    Ok(false)
                }
            }
        },
    )
    .await
}

// =============================================================================
// Local Secrets Route Test Helpers
// =============================================================================

/// Seed GHCR registry credentials as a local secret for imagePullSecrets.
///
/// Uses `load_registry_credentials()` to get the `.dockerconfigjson` payload
/// and stores it as a labeled K8s Secret in the `lattice-secrets` namespace
/// so the webhook can serve it to ESO.
async fn seed_local_regcreds(kubeconfig: &str, secret_name: &str) -> Result<(), String> {
    let docker_config = load_registry_credentials()
        .ok_or("No GHCR credentials (check .env or GHCR_USER/GHCR_TOKEN env vars)")?;
    let mut data = BTreeMap::new();
    data.insert(".dockerconfigjson".to_string(), docker_config);
    seed_local_secret(kubeconfig, secret_name, &data).await
}

/// Seed all source secrets needed for the 5-route secret tests.
///
/// Seeds:
/// - `local-db-creds` (Routes 1, 2, 3): username + password
/// - `local-api-key` (Route 3 file mount): key
/// - `local-database-config` (Route 5 dataFrom): host, port, name, ssl
/// - `local-regcreds` (Route 4 imagePullSecrets): .dockerconfigjson from GHCR creds
pub async fn seed_all_local_test_secrets(kubeconfig: &str) -> Result<(), String> {
    info!("[LocalSecrets] Seeding all local test secrets...");

    // db-creds (Routes 1, 2, 3)
    seed_local_secret(
        kubeconfig,
        "local-db-creds",
        &BTreeMap::from([
            ("username".to_string(), "admin".to_string()),
            ("password".to_string(), "s3cret-p@ss".to_string()),
        ]),
    )
    .await?;

    // api-key (Route 3 file mount)
    seed_local_secret(
        kubeconfig,
        "local-api-key",
        &BTreeMap::from([("key".to_string(), "ak-test-12345".to_string())]),
    )
    .await?;

    // database-config (Route 5 dataFrom — all keys)
    seed_local_secret(
        kubeconfig,
        "local-database-config",
        &BTreeMap::from([
            ("host".to_string(), "db.prod".to_string()),
            ("port".to_string(), "5432".to_string()),
            ("name".to_string(), "appdb".to_string()),
            ("ssl".to_string(), "true".to_string()),
        ]),
    )
    .await?;

    // regcreds (imagePullSecrets — needed by every service)
    seed_local_regcreds(kubeconfig, "local-regcreds").await?;

    info!("[LocalSecrets] All local test secrets seeded");
    Ok(())
}

/// Build a LatticeService exercising all 5 secret routes programmatically.
///
/// Build a LatticeService with a runtime-configurable provider name exercising
/// all 5 secret routes. Every service includes `ghcr-creds` for imagePullSecrets
/// since all images come from GHCR.
pub fn create_service_with_all_secret_routes(
    name: &str,
    namespace: &str,
    provider: &str,
) -> LatticeService {
    use lattice_common::crd::{
        ContainerSpec, FileMount, ResourceQuantity, ResourceRequirements, ResourceSpec,
        ResourceType,
    };
    use lattice_common::template::TemplateString;

    // Container with env vars and file mounts exercising routes 1-3
    let mut variables = BTreeMap::new();
    // Route 1: Pure secret env vars → secretKeyRef
    variables.insert(
        "DB_PASSWORD".to_string(),
        TemplateString::new("${secret.db-creds.password}"),
    );
    variables.insert(
        "DB_USERNAME".to_string(),
        TemplateString::new("${secret.db-creds.username}"),
    );
    // Route 2: Mixed-content env var → ESO templated secret
    variables.insert(
        "DATABASE_URL".to_string(),
        TemplateString::new(
            "postgres://${secret.db-creds.username}:${secret.db-creds.password}@db.svc:5432/mydb",
        ),
    );
    // Plain env var (contrast)
    variables.insert(
        "APP_NAME".to_string(),
        TemplateString::new("secret-routes-test"),
    );

    // Route 3: File mount with secret templates
    let mut files = BTreeMap::new();
    files.insert(
        "/etc/app/config.yaml".to_string(),
        FileMount {
            content: Some(TemplateString::new(
                "database:\n  password: ${secret.db-creds.password}\n  username: ${secret.db-creds.username}\napi_key: ${secret.api-key.key}\n",
            )),
            ..Default::default()
        },
    );

    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: BUSYBOX_IMAGE.to_string(),
            command: Some(vec!["/bin/sleep".to_string(), "infinity".to_string()]),
            variables,
            files,
            resources: Some(ResourceRequirements {
                requests: Some(ResourceQuantity {
                    cpu: Some("50m".to_string()),
                    memory: Some("64Mi".to_string()),
                }),
                limits: Some(ResourceQuantity {
                    cpu: Some("200m".to_string()),
                    memory: Some("128Mi".to_string()),
                }),
            }),
            security: Some(lattice_common::crd::SecurityContext {
                apparmor_profile: Some("Unconfined".to_string()),
                allowed_binaries: vec!["/bin/printenv".to_string(), "/bin/cat".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    // Resources: 4 secret resources covering all 5 routes
    let mut resources = BTreeMap::new();

    // Routes 1, 2, 3: db-creds with explicit keys
    let mut db_params = BTreeMap::new();
    db_params.insert("provider".to_string(), serde_json::json!(provider));
    db_params.insert(
        "keys".to_string(),
        serde_json::json!(["username", "password"]),
    );
    db_params.insert("refreshInterval".to_string(), serde_json::json!("1h"));
    resources.insert(
        "db-creds".to_string(),
        ResourceSpec {
            type_: ResourceType::Secret,
            id: Some("local-db-creds".to_string()),
            params: Some(db_params),
            ..Default::default()
        },
    );

    // Route 3: api-key with explicit key
    let mut api_params = BTreeMap::new();
    api_params.insert("provider".to_string(), serde_json::json!(provider));
    api_params.insert("keys".to_string(), serde_json::json!(["key"]));
    api_params.insert("refreshInterval".to_string(), serde_json::json!("1h"));
    resources.insert(
        "api-key".to_string(),
        ResourceSpec {
            type_: ResourceType::Secret,
            id: Some("local-api-key".to_string()),
            params: Some(api_params),
            ..Default::default()
        },
    );

    // Route 5: dataFrom (all keys, no explicit keys param)
    let mut all_params = BTreeMap::new();
    all_params.insert("provider".to_string(), serde_json::json!(provider));
    all_params.insert("refreshInterval".to_string(), serde_json::json!("1h"));
    resources.insert(
        "all-db-config".to_string(),
        ResourceSpec {
            type_: ResourceType::Secret,
            id: Some("local-database-config".to_string()),
            params: Some(all_params),
            ..Default::default()
        },
    );

    // Route 4: ghcr-creds for imagePullSecrets (custom provider)
    let mut reg_params = BTreeMap::new();
    reg_params.insert("provider".to_string(), serde_json::json!(provider));
    reg_params.insert("refreshInterval".to_string(), serde_json::json!("1h"));
    resources.insert(
        "ghcr-creds".to_string(),
        ResourceSpec {
            type_: ResourceType::Secret,
            id: Some("local-regcreds".to_string()),
            params: Some(reg_params),
            ..Default::default()
        },
    );

    build_busybox_service(name, namespace, containers, resources)
}

// =============================================================================
// Pod Verification Helpers
// =============================================================================

/// Wait for a pod matching `label_selector` to be Running, then exec `printenv`
/// and verify the specified env var has the expected value.
pub async fn verify_pod_env_var(
    kubeconfig: &str,
    namespace: &str,
    label_selector: &str,
    var_name: &str,
    expected_value: &str,
) -> Result<(), String> {
    info!(
        "[PodVerify] Checking env var {} in pod (label={}) in {}",
        var_name, label_selector, namespace
    );

    // Wait for pod to be Running
    wait_for_pod_running(kubeconfig, namespace, label_selector).await?;

    // Exec printenv inside the pod (retry to handle proxy/exec transient failures)
    let kc = kubeconfig.to_string();
    let ns = namespace.to_string();
    let ls = label_selector.to_string();
    let vn = var_name.to_string();
    let ev = expected_value.to_string();

    wait_for_condition(
        &format!("env var {} = '{}'", var_name, expected_value),
        Duration::from_secs(60),
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let ns = ns.clone();
            let ls = ls.clone();
            let vn = vn.clone();
            let ev = ev.clone();
            async move {
                let pod_name = get_pod_name(&kc, &ns, &ls).await?;
                let actual = match run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "exec",
                    &pod_name,
                    "-n",
                    &ns,
                    "--",
                    "printenv",
                    &vn,
                ])
                .await
                {
                    Ok(v) => v,
                    Err(_) => return Ok(false), // transient exec failure
                };
                let actual = actual.trim();
                if actual == ev {
                    info!("[PodVerify] Env var {} = '{}' (correct)", vn, actual);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        },
    )
    .await
}

/// Wait for a pod matching `label_selector` to be Running, then exec `cat`
/// and verify the file content contains the expected substring.
pub async fn verify_pod_file_content(
    kubeconfig: &str,
    namespace: &str,
    label_selector: &str,
    file_path: &str,
    expected_substr: &str,
) -> Result<(), String> {
    info!(
        "[PodVerify] Checking file {} in pod (label={}) in {}",
        file_path, label_selector, namespace
    );

    wait_for_pod_running(kubeconfig, namespace, label_selector).await?;

    // Retry to handle proxy/exec transient failures
    let kc = kubeconfig.to_string();
    let ns = namespace.to_string();
    let ls = label_selector.to_string();
    let fp = file_path.to_string();
    let es = expected_substr.to_string();

    wait_for_condition(
        &format!("file {} contains '{}'", file_path, expected_substr),
        Duration::from_secs(60),
        Duration::from_secs(5),
        || {
            let kc = kc.clone();
            let ns = ns.clone();
            let ls = ls.clone();
            let fp = fp.clone();
            let es = es.clone();
            async move {
                let pod_name = get_pod_name(&kc, &ns, &ls).await?;
                let content = match run_kubectl(&[
                    "--kubeconfig",
                    &kc,
                    "exec",
                    &pod_name,
                    "-n",
                    &ns,
                    "--",
                    "cat",
                    &fp,
                ])
                .await
                {
                    Ok(v) => v,
                    Err(_) => return Ok(false), // transient exec failure
                };
                if content.contains(&*es) {
                    info!("[PodVerify] File {} contains expected content", fp);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        },
    )
    .await
}

/// Check pod spec `imagePullSecrets` via jsonpath and verify the expected
/// secret name is present.
pub async fn verify_pod_image_pull_secrets(
    kubeconfig: &str,
    namespace: &str,
    label_selector: &str,
    expected_secret: &str,
) -> Result<(), String> {
    info!(
        "[PodVerify] Checking imagePullSecrets for '{}' in pod (label={}) in {}",
        expected_secret, label_selector, namespace
    );

    wait_for_pod_running(kubeconfig, namespace, label_selector).await?;
    let pod_name = get_pod_name(kubeconfig, namespace, label_selector).await?;

    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pod",
        &pod_name,
        "-n",
        namespace,
        "-o",
        "jsonpath={.spec.imagePullSecrets[*].name}",
    ])
    .await?;

    if !output.contains(expected_secret) {
        return Err(format!(
            "Pod {} imagePullSecrets does not contain '{}'. Found: '{}'",
            pod_name,
            expected_secret,
            output.trim()
        ));
    }

    info!(
        "[PodVerify] Pod {} has imagePullSecret '{}'",
        pod_name, expected_secret
    );
    Ok(())
}

/// Wait for at least one pod matching `label_selector` to reach the Running phase.
pub async fn wait_for_pod_running(
    kubeconfig: &str,
    namespace: &str,
    label_selector: &str,
) -> Result<(), String> {
    wait_for_condition(
        &format!(
            "pod (label={}) in {} to be Running",
            label_selector, namespace
        ),
        Duration::from_secs(300),
        Duration::from_secs(5),
        || async move {
            let output = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "get",
                "pods",
                "-n",
                namespace,
                "-l",
                label_selector,
                "-o",
                "jsonpath={.items[0].status.phase}",
            ])
            .await;
            match output {
                Ok(phase) => {
                    let phase = phase.trim();
                    info!("[PodVerify] Pod phase: {}", phase);
                    Ok(phase == "Running")
                }
                Err(_) => Ok(false),
            }
        },
    )
    .await
}

/// Get the name of the first pod matching `label_selector`.
async fn get_pod_name(
    kubeconfig: &str,
    namespace: &str,
    label_selector: &str,
) -> Result<String, String> {
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "pods",
        "-n",
        namespace,
        "-l",
        label_selector,
        "-o",
        "jsonpath={.items[0].metadata.name}",
    ])
    .await?;

    let name = output.trim().to_string();
    if name.is_empty() {
        return Err(format!(
            "No pod found matching label '{}' in namespace '{}'",
            label_selector, namespace
        ));
    }
    Ok(name)
}

/// Verify a synced K8s Secret has all the expected data keys.
///
/// Waits for the secret to appear (ESO may take a moment to sync),
/// then checks all expected keys are present.
pub async fn verify_synced_secret_keys(
    kubeconfig: &str,
    namespace: &str,
    secret_name: &str,
    expected_keys: &[&str],
) -> Result<(), String> {
    info!(
        "[PodVerify] Verifying synced secret '{}' has keys {:?}",
        secret_name, expected_keys
    );

    wait_for_condition(
        &format!("secret {} in {} to be synced", secret_name, namespace),
        Duration::from_secs(300),
        Duration::from_secs(5),
        || async move {
            let output = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "get",
                "secret",
                secret_name,
                "-n",
                namespace,
                "-o",
                "jsonpath={.data}",
            ])
            .await;
            match output {
                Ok(data) if !data.trim().is_empty() => Ok(true),
                _ => Ok(false),
            }
        },
    )
    .await?;

    // Now verify the keys
    let output = run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "get",
        "secret",
        secret_name,
        "-n",
        namespace,
        "-o",
        "json",
    ])
    .await?;

    let json: serde_json::Value =
        serde_json::from_str(&output).map_err(|e| format!("Failed to parse secret JSON: {}", e))?;

    let data = json["data"]
        .as_object()
        .ok_or_else(|| format!("Secret {} has no data field", secret_name))?;

    for key in expected_keys {
        if !data.contains_key(*key) {
            return Err(format!(
                "Secret {} missing expected key '{}'. Found: {:?}",
                secret_name,
                key,
                data.keys().collect::<Vec<_>>()
            ));
        }
    }

    info!(
        "[PodVerify] Secret '{}' has all expected keys: {:?}",
        secret_name, expected_keys
    );
    Ok(())
}

// =============================================================================
// Regcreds Infrastructure Setup
// =============================================================================

/// Wait for the operator's built-in ClusterSecretStore, seed GHCR regcreds,
/// and apply a broad Cedar policy permitting all services to access them.
///
/// Call this before deploying any LatticeService in a test — every service
/// declares `ghcr-creds` as an imagePullSecret resource pointing at
/// `local-regcreds`, so the local webhook must be ready to serve it.
pub async fn setup_regcreds_infrastructure(kubeconfig: &str) -> Result<(), String> {
    // Wait for the operator's built-in lattice-local ClusterSecretStore
    wait_for_cluster_secret_store_ready(kubeconfig, REGCREDS_PROVIDER).await?;

    // Seed the GHCR credentials as a source secret for the webhook
    seed_local_regcreds(kubeconfig, REGCREDS_REMOTE_KEY).await?;

    // Broad Cedar policy: permit all services to access regcreds
    apply_cedar_policy_crd(
        kubeconfig,
        "permit-regcreds",
        "regcreds",
        50,
        r#"permit(
  principal,
  action == Lattice::Action::"AccessSecret",
  resource
) when {
  resource.path == "local-regcreds"
};"#,
    )
    .await?;

    // KIND clusters don't have AppArmor
    apply_apparmor_override_policy(kubeconfig).await?;

    // Permit binary wildcard for containers without explicit command or with allowedBinaries: ["*"]
    apply_binary_wildcard_override_policy(kubeconfig).await?;

    // Permit test utility binaries (printenv, cat) for verification via kubectl exec
    apply_test_binaries_override_policy(kubeconfig).await?;

    info!("[Regcreds] Infrastructure ready (provider + source secret + Cedar policies)");
    Ok(())
}

// =============================================================================
// Cert-Manager Test Infrastructure
// =============================================================================

/// Ensure a self-signed ClusterIssuer exists for cert-manager Certificate testing.
///
/// In production this would be a real ACME issuer (e.g. letsencrypt-prod).
/// For E2E tests a self-signed issuer lets cert-manager issue certificates
/// without external dependencies.
pub async fn ensure_test_cluster_issuer(kubeconfig: &str, name: &str) -> Result<(), String> {
    let yaml = format!(
        r#"apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: {name}
spec:
  selfSigned: {{}}"#,
    );

    super::cedar::apply_yaml_with_retry(kubeconfig, &yaml).await?;
    info!(
        "[CertManager] ClusterIssuer '{}' ensured (self-signed)",
        name
    );
    Ok(())
}
