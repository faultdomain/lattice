//! Third-Party Mesh Onboarding integration test (3 LatticeServices + 1 external)
//!
//! Deploys a third-party nginx server via raw K8s Deployment+Service (simulating
//! a helm-installed operator like CloudNativePG or Prometheus), then onboards it
//! to the Lattice mesh via a LatticeMeshMember CRD. Verifies that bilateral
//! agreements work between the onboarded workload and regular LatticeServices.
//!
//! Architecture:
//!   api-client (LatticeService, traffic generator)
//!       | outbound
//!       v
//!   external-nginx (raw Deployment+Service, onboarded via LatticeMeshMember)
//!       ^ inbound from api-client
//!       | outbound (dependency)
//!       v
//!   backend-svc (LatticeService, nginx)
//!       ^ inbound from external-nginx
//!
//!   blocked-client (LatticeService, traffic generator)
//!       | outbound to external-nginx (but external-nginx does NOT allow it)
//!       x BLOCKED
//!
//! Features exercised:
//! - LatticeMeshMember CRD for third-party workload onboarding
//! - Raw K8s Deployment+Service (not managed by Lattice compiler)
//! - Bilateral agreements between LatticeService and LatticeMeshMember
//! - Denied access from a service NOT in allowed_callers
//! - LatticeMeshMember declaring outbound dependencies to LatticeServices
//!
//! # Running Standalone
//!
//! ```bash
//! LATTICE_KUBECONFIG=/path/to/cluster-kubeconfig \
//! cargo test --features provider-e2e --test e2e test_mesh_onboarding_standalone -- --ignored --nocapture
//! ```

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;
use std::time::Duration;

use futures::future::try_join_all;
use kube::api::Api;
use lattice_common::crd::{LatticeService, ResourceSpec};
use tracing::info;

use super::super::helpers::{
    apply_yaml, client_from_kubeconfig, create_with_retry, delete_namespace,
    ensure_fresh_namespace, run_kubectl, setup_regcreds_infrastructure, test_image,
    wait_for_condition, DEFAULT_TIMEOUT,
};
use super::super::mesh_fixtures::{
    build_lattice_service, curl_container, inbound_allow, nginx_container, outbound_dep,
};
use super::super::mesh_helpers::{
    generate_test_script, parse_traffic_result, retry_verification, wait_for_services_ready,
    TestTarget,
};

const NAMESPACE: &str = "mesh-onboarding-test";

// =============================================================================
// External (third-party) workload — raw K8s resources
// =============================================================================

/// Deploy a plain nginx Deployment + Service via raw YAML, simulating a
/// helm-installed third-party component (like CloudNativePG, Prometheus, etc.).
async fn deploy_external_nginx(kubeconfig: &str) -> Result<(), String> {
    info!("[MeshOnboard] Deploying external nginx (raw K8s resources)...");

    let image = test_image("docker.io/nginxinc/nginx-unprivileged:alpine");

    let yaml = format!(
        r#"---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-nginx
  namespace: {ns}
  labels:
    app: external-nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: external-nginx
  template:
    metadata:
      labels:
        app: external-nginx
    spec:
      containers:
        - name: nginx
          image: {image}
          ports:
            - containerPort: 8080
          command: ["/bin/sh"]
          args:
            - "-c"
            - |
              printf 'server {{ listen 8080; location / {{ return 200 "ok\n"; add_header Content-Type text/plain; }} }}' > /etc/nginx/conf.d/default.conf && nginx -g 'daemon off;'
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 200m
              memory: 128Mi
      imagePullSecrets:
        - name: ghcr-creds-synced
---
apiVersion: v1
kind: Service
metadata:
  name: external-nginx
  namespace: {ns}
spec:
  selector:
    app: external-nginx
  ports:
    - port: 8080
      targetPort: 8080
      name: http
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: external-nginx
  namespace: {ns}
"#,
        ns = NAMESPACE,
        image = image,
    );

    apply_yaml(kubeconfig, &yaml).await?;
    info!("[MeshOnboard] External nginx deployed");
    Ok(())
}

/// Create a LatticeMeshMember to onboard the external nginx into the mesh.
///
/// Declares:
/// - target: selector `app: external-nginx`
/// - ports: [8080/http]
/// - allowed_callers: [api-client] (NOT blocked-client)
/// - dependencies: [backend-svc] (outbound to a LatticeService)
async fn apply_mesh_member(kubeconfig: &str) -> Result<(), String> {
    info!("[MeshOnboard] Applying LatticeMeshMember for external-nginx...");

    let yaml = format!(
        r#"apiVersion: lattice.dev/v1alpha1
kind: LatticeMeshMember
metadata:
  name: external-nginx
  namespace: {ns}
spec:
  target:
    selector:
      app: external-nginx
  serviceAccount: external-nginx
  ports:
    - port: 8080
      name: http
  allowedCallers:
    - name: api-client
  dependencies:
    - name: backend-svc
"#,
        ns = NAMESPACE,
    );

    apply_yaml(kubeconfig, &yaml).await?;

    // Wait for the LatticeMeshMember to reach Ready
    wait_for_condition(
        "LatticeMeshMember external-nginx to be Ready",
        DEFAULT_TIMEOUT,
        Duration::from_secs(5),
        || async move {
            let output = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "get",
                "latticemeshmember",
                "external-nginx",
                "-n",
                NAMESPACE,
                "-o",
                "jsonpath={.status.phase}",
            ])
            .await;

            match output {
                Ok(phase) => {
                    let phase = phase.trim();
                    info!("[MeshOnboard] LatticeMeshMember phase: {}", phase);
                    Ok(phase == "Ready")
                }
                Err(_) => Ok(false),
            }
        },
    )
    .await?;

    info!("[MeshOnboard] LatticeMeshMember Ready");
    Ok(())
}

// =============================================================================
// LatticeService Construction
// =============================================================================

/// api-client: traffic generator, outbound to external-nginx and others.
///
/// Tests ALLOWED path to external-nginx (port 8080) and BLOCKED paths
/// to backend-svc and blocked-client.
fn build_api_client() -> LatticeService {
    let targets = vec![
        TestTarget {
            url: format!(
                "http://external-nginx.{}.svc.cluster.local:8080/",
                NAMESPACE
            ),
            expected_allowed: true,
            success_msg: "external-nginx: ALLOWED (api->external allowed)".to_string(),
            fail_msg: "external-nginx: BLOCKED (UNEXPECTED - api->external allowed)".to_string(),
        },
        TestTarget::internal("backend-svc", NAMESPACE, false, "api->backend blocked"),
        TestTarget::internal("blocked-client", NAMESPACE, false, "api->blocked blocked"),
    ];

    let container = curl_container(generate_test_script("api-client", targets));

    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (k, v) = outbound_dep("external-nginx");
    resources.insert(k, v);
    let (k, v) = outbound_dep("backend-svc");
    resources.insert(k, v);
    let (k, v) = outbound_dep("blocked-client");
    resources.insert(k, v);

    build_lattice_service("api-client", NAMESPACE, resources, false, container)
}

/// backend-svc: nginx server, inbound from external-nginx only.
fn build_backend_svc() -> LatticeService {
    let container = nginx_container();

    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (k, v) = inbound_allow("external-nginx");
    resources.insert(k, v);

    build_lattice_service("backend-svc", NAMESPACE, resources, true, container)
}

/// blocked-client: traffic generator that tries to reach external-nginx but is
/// NOT in external-nginx's allowed_callers — should be denied.
fn build_blocked_client() -> LatticeService {
    let targets = vec![
        TestTarget {
            url: format!(
                "http://external-nginx.{}.svc.cluster.local:8080/",
                NAMESPACE
            ),
            expected_allowed: false,
            success_msg: "external-nginx: ALLOWED (UNEXPECTED - blocked->external blocked)"
                .to_string(),
            fail_msg: "external-nginx: BLOCKED (blocked->external blocked)".to_string(),
        },
        TestTarget::internal("backend-svc", NAMESPACE, false, "blocked->backend blocked"),
        TestTarget::internal("api-client", NAMESPACE, false, "blocked->api blocked"),
    ];

    let container = curl_container(generate_test_script("blocked-client", targets));

    let mut resources: BTreeMap<String, ResourceSpec> = BTreeMap::new();
    let (k, v) = outbound_dep("external-nginx");
    resources.insert(k, v);
    let (k, v) = outbound_dep("backend-svc");
    resources.insert(k, v);
    let (k, v) = outbound_dep("api-client");
    resources.insert(k, v);

    build_lattice_service("blocked-client", NAMESPACE, resources, false, container)
}

// =============================================================================
// Deploy & Verify
// =============================================================================

async fn deploy_services(kubeconfig: &str) -> Result<(), String> {
    info!("[MeshOnboard] Deploying mesh onboarding test stack...");

    ensure_fresh_namespace(kubeconfig, NAMESPACE).await?;
    setup_regcreds_infrastructure(kubeconfig).await?;

    // Seed a synced imagePullSecret for the external deployment.
    // In real life this would come from ESO; here we create it directly from the
    // same registry credentials the operator uses.
    let docker_config = super::super::helpers::load_registry_credentials()
        .ok_or("No GHCR credentials (check .env or GHCR_USER/GHCR_TOKEN env vars)")?;
    let secret_yaml = format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: ghcr-creds-synced
  namespace: {ns}
type: kubernetes.io/dockerconfigjson
stringData:
  .dockerconfigjson: '{docker_config}'
"#,
        ns = NAMESPACE,
        docker_config = docker_config.replace('\'', "'\"'\"'"),
    );
    apply_yaml(kubeconfig, &secret_yaml).await?;

    // Label namespace for Istio ambient mesh
    run_kubectl(&[
        "--kubeconfig",
        kubeconfig,
        "label",
        "namespace",
        NAMESPACE,
        "istio.io/dataplane-mode=ambient",
        "--overwrite",
    ])
    .await?;

    // Deploy the external (non-Lattice) nginx first
    deploy_external_nginx(kubeconfig).await?;

    // Wait for the external deployment to be available
    wait_for_condition(
        "external-nginx deployment available",
        DEFAULT_TIMEOUT,
        Duration::from_secs(5),
        || async move {
            let output = run_kubectl(&[
                "--kubeconfig",
                kubeconfig,
                "get",
                "deployment",
                "-n",
                NAMESPACE,
                "external-nginx",
                "-o",
                "jsonpath={.status.availableReplicas}",
            ])
            .await;
            match output {
                Ok(replicas) => Ok(replicas.trim().parse::<i32>().unwrap_or(0) >= 1),
                Err(_) => Ok(false),
            }
        },
    )
    .await?;

    // Apply LatticeMeshMember BEFORE LatticeServices so external-nginx is in the
    // service graph when the compiler processes api-client and blocked-client
    // (they declare outbound_dep("external-nginx")).
    apply_mesh_member(kubeconfig).await?;

    // Deploy LatticeServices
    let client = client_from_kubeconfig(kubeconfig).await?;
    let api: Api<LatticeService> = Api::namespaced(client, NAMESPACE);

    let services = [
        build_api_client(),
        build_backend_svc(),
        build_blocked_client(),
    ];
    let futs: Vec<_> = services
        .iter()
        .map(|svc| {
            let name = svc.metadata.name.as_deref().unwrap_or("unknown");
            info!("[MeshOnboard] Deploying LatticeService {}...", name);
            create_with_retry(&api, svc, name)
        })
        .collect();
    try_join_all(futs).await?;

    // Wait for LatticeServices to be Ready
    wait_for_services_ready(kubeconfig, NAMESPACE, 3).await?;

    Ok(())
}

async fn verify_traffic_logs(kubeconfig: &str) -> Result<(), String> {
    info!("[MeshOnboard] Verifying traffic patterns from logs...");

    let generators: &[(&str, &[(&str, bool)])] = &[
        (
            "api-client",
            &[
                ("external-nginx", true),
                ("backend-svc", false),
                ("blocked-client", false),
            ],
        ),
        (
            "blocked-client",
            &[
                ("external-nginx", false),
                ("backend-svc", false),
                ("api-client", false),
            ],
        ),
    ];

    let mut failures: Vec<String> = Vec::new();
    let mut total = 0;

    for (generator, expectations) in generators {
        let logs = run_kubectl(&[
            "--kubeconfig",
            kubeconfig,
            "logs",
            "-n",
            NAMESPACE,
            "-l",
            &format!("{}={}", lattice_common::LABEL_NAME, generator),
            "--tail",
            "200",
        ])
        .await?;

        for (target, expected_allowed) in *expectations {
            total += 1;
            let expected_str = if *expected_allowed {
                "ALLOWED"
            } else {
                "BLOCKED"
            };
            let allowed_pattern = format!("{}: ALLOWED", target);
            let blocked_pattern = format!("{}: BLOCKED", target);

            let actual_str = match parse_traffic_result(&logs, &allowed_pattern, &blocked_pattern) {
                Some(true) => "ALLOWED",
                Some(false) => "BLOCKED",
                None => "UNKNOWN",
            };

            if actual_str != expected_str {
                failures.push(format!(
                    "{}->{}: got {}, expected {}",
                    generator, target, actual_str, expected_str
                ));
            } else {
                info!(
                    "[MeshOnboard]   {} -> {}: {} (OK)",
                    generator, target, actual_str
                );
            }
        }
    }

    if !failures.is_empty() {
        return Err(format!(
            "[MeshOnboard] {} of {} checks failed: {}",
            failures.len(),
            total,
            failures.join("; ")
        ));
    }

    info!("[MeshOnboard] All {} traffic checks passed!", total);
    Ok(())
}

// =============================================================================
// Public API
// =============================================================================

pub async fn run_mesh_onboarding_tests(kubeconfig: &str) -> Result<(), String> {
    info!("\n========================================");
    info!("Third-Party Mesh Onboarding Test");
    info!("========================================\n");

    deploy_services(kubeconfig).await?;

    let kc = kubeconfig.to_string();
    retry_verification("MeshOnboard", || verify_traffic_logs(&kc)).await?;

    info!("\n========================================");
    info!("Third-Party Mesh Onboarding: PASSED");
    info!("========================================\n");

    delete_namespace(kubeconfig, NAMESPACE).await;
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_mesh_onboarding_standalone() {
    use super::super::context::{init_e2e_test, StandaloneKubeconfig};

    init_e2e_test();
    let resolved = StandaloneKubeconfig::resolve().await.unwrap();
    run_mesh_onboarding_tests(&resolved.kubeconfig)
        .await
        .unwrap();
}
