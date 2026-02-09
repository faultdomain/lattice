//! Service builders for mesh bilateral agreement tests
//!
//! Provides factory functions for creating LatticeService specs used in both
//! the fixed 9-service mesh test and the randomized mesh test.

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

use lattice_common::crd::{
    ContainerSpec, DependencyDirection, LatticeService, LatticeServiceSpec, PortSpec, ResourceSpec,
    ResourceType, ServicePortsSpec, VolumeMount, WorkloadSpec,
};

use super::helpers::{CURL_IMAGE, NGINX_IMAGE, REGCREDS_PROVIDER, REGCREDS_REMOTE_KEY};
use super::mesh_helpers::{generate_test_script, TestTarget};

// =============================================================================
// Constants
// =============================================================================

pub const TEST_SERVICES_NAMESPACE: &str = "mesh-test";
pub const TOTAL_SERVICES: usize = 10; // 9 original + 1 public-api (wildcard)

// =============================================================================
// Shared Builders
// =============================================================================

/// EmptyDir volume mount (no source = emptyDir).
///
/// Used to make paths writable under read-only rootfs (the secure default).
fn emptydir(medium: Option<&str>, size_limit: Option<&str>) -> VolumeMount {
    VolumeMount {
        source: None,
        path: None,
        read_only: None,
        medium: medium.map(String::from),
        size_limit: size_limit.map(String::from),
    }
}

/// Nginx container with emptyDir volumes for writable paths.
///
/// Nginx needs `/var/cache/nginx`, `/var/run`, and `/tmp` writable.
/// With read-only rootfs (our secure default), these must be emptyDir mounts.
pub fn nginx_container() -> ContainerSpec {
    let mut volumes = BTreeMap::new();
    volumes.insert("/var/cache/nginx".to_string(), emptydir(None, None));
    volumes.insert("/var/run".to_string(), emptydir(None, None));
    volumes.insert("/tmp".to_string(), emptydir(None, None));

    ContainerSpec {
        image: NGINX_IMAGE.to_string(),
        volumes,
        ..Default::default()
    }
}

/// Curl container with emptyDir for `/tmp`.
///
/// Curl writes temp files during HTTP operations. With read-only rootfs,
/// `/tmp` must be an emptyDir mount.
pub fn curl_container(script: String) -> ContainerSpec {
    let mut volumes = BTreeMap::new();
    volumes.insert("/tmp".to_string(), emptydir(None, None));

    ContainerSpec {
        image: CURL_IMAGE.to_string(),
        command: Some(vec!["/bin/sh".to_string()]),
        args: Some(vec!["-c".to_string(), script]),
        volumes,
        ..Default::default()
    }
}

fn http_port() -> ServicePortsSpec {
    let mut ports = BTreeMap::new();
    ports.insert(
        "http".to_string(),
        PortSpec {
            port: 80,
            target_port: None,
            protocol: None,
        },
    );
    ServicePortsSpec { ports }
}

pub fn outbound_dep(name: &str) -> (String, ResourceSpec) {
    (
        name.to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Outbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
            namespace: None,
            inbound: None,
            outbound: None,
        },
    )
}

pub fn inbound_allow(name: &str) -> (String, ResourceSpec) {
    (
        name.to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Inbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
            namespace: None,
            inbound: None,
            outbound: None,
        },
    )
}

pub fn inbound_allow_all() -> (String, ResourceSpec) {
    (
        "any-caller".to_string(),
        ResourceSpec {
            type_: ResourceType::Service,
            direction: DependencyDirection::Inbound,
            id: Some("*".to_string()),
            class: None,
            metadata: None,
            params: None,
            namespace: None,
            inbound: None,
            outbound: None,
        },
    )
}

pub fn external_outbound_dep(name: &str) -> (String, ResourceSpec) {
    (
        name.to_string(),
        ResourceSpec {
            type_: ResourceType::ExternalService,
            direction: DependencyDirection::Outbound,
            id: None,
            class: None,
            metadata: None,
            params: None,
            namespace: None,
            inbound: None,
            outbound: None,
        },
    )
}

// =============================================================================
// Registry Credentials Resource
// =============================================================================

/// Build the `ghcr-creds` secret resource that every service needs for imagePullSecrets.
///
/// All test images come from GHCR, so every LatticeService must declare this
/// resource and reference it in `image_pull_secrets`. The resource points at the
/// seeded `local-regcreds` K8s Secret via the local SecretProvider.
fn ghcr_creds_resource() -> (String, ResourceSpec) {
    let mut params = BTreeMap::new();
    params.insert("provider".to_string(), serde_json::json!(REGCREDS_PROVIDER));
    params.insert("refreshInterval".to_string(), serde_json::json!("1h"));

    (
        "ghcr-creds".to_string(),
        ResourceSpec {
            type_: ResourceType::Secret,
            id: Some(REGCREDS_REMOTE_KEY.to_string()),
            params: Some(params),
            ..Default::default()
        },
    )
}

// =============================================================================
// Generic Service Construction
// =============================================================================

/// Build a LatticeService from its component parts.
///
/// Used by both the fixed mesh test (via convenience wrappers below) and the
/// random mesh generator to avoid duplicating the spec-assembly boilerplate.
///
/// Every service automatically includes `ghcr-creds` as an imagePullSecret
/// since all test images come from GHCR.
pub fn build_lattice_service(
    name: &str,
    namespace: &str,
    mut resources: BTreeMap<String, ResourceSpec>,
    has_port: bool,
    container: ContainerSpec,
) -> LatticeService {
    let mut containers = BTreeMap::new();
    containers.insert("main".to_string(), container);

    let mut labels = BTreeMap::new();
    labels.insert("lattice.dev/environment".to_string(), namespace.to_string());

    // Every service needs ghcr-creds for pulling GHCR images
    let (creds_key, creds_spec) = ghcr_creds_resource();
    resources.insert(creds_key, creds_spec);

    LatticeService {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: LatticeServiceSpec {
            workload: WorkloadSpec {
                containers,
                resources,
                service: if has_port { Some(http_port()) } else { None },
                image_pull_secrets: vec!["ghcr-creds".to_string()],
                ..Default::default()
            },
            ..Default::default()
        },
        status: None,
    }
}

fn create_service(
    name: &str,
    outbound: Vec<&str>,
    inbound: Vec<&str>,
    allows_all_inbound: bool,
    has_port: bool,
    container: ContainerSpec,
) -> LatticeService {
    let mut resources: BTreeMap<String, ResourceSpec> =
        outbound.iter().map(|s| outbound_dep(s)).collect();

    if allows_all_inbound {
        let (key, spec) = inbound_allow_all();
        resources.insert(key, spec);
    } else {
        resources.extend(inbound.iter().map(|s| inbound_allow(s)));
    }

    build_lattice_service(
        name,
        TEST_SERVICES_NAMESPACE,
        resources,
        has_port,
        container,
    )
}

// =============================================================================
// Fixed Mesh Service Factories
// =============================================================================

pub fn create_frontend_web() -> LatticeService {
    let ns = TEST_SERVICES_NAMESPACE;
    let targets = vec![
        TestTarget::internal("api-gateway", ns, true, "bilateral agreement"),
        TestTarget::internal("api-users", ns, true, "bilateral agreement"),
        TestTarget::internal("api-orders", ns, false, "web not allowed by orders"),
        TestTarget::internal("db-users", ns, false, "no direct DB access"),
        TestTarget::internal("db-orders", ns, false, "no direct DB access"),
        TestTarget::internal("cache", ns, false, "no direct cache access"),
        TestTarget::internal("frontend-mobile", ns, false, "no peer access"),
        TestTarget::internal("frontend-admin", ns, false, "no peer access"),
        TestTarget::internal("public-api", ns, true, "wildcard allows all with outbound"),
    ];

    let script = generate_test_script("frontend-web", targets);

    create_service(
        "frontend-web",
        vec![
            "api-gateway",
            "api-users",
            "api-orders",
            "db-users",
            "db-orders",
            "cache",
            "frontend-mobile",
            "frontend-admin",
            "public-api",
        ],
        vec![],
        false, // allows_all_inbound
        false, // has_port
        curl_container(script),
    )
}

pub fn create_frontend_mobile() -> LatticeService {
    let ns = TEST_SERVICES_NAMESPACE;
    let targets = vec![
        TestTarget::internal("api-gateway", ns, true, "bilateral agreement"),
        TestTarget::internal("api-users", ns, false, "mobile not allowed by users"),
        TestTarget::internal("api-orders", ns, true, "bilateral agreement"),
        TestTarget::internal("db-users", ns, false, "no direct DB access"),
        TestTarget::internal("db-orders", ns, false, "no direct DB access"),
        TestTarget::internal("cache", ns, false, "no direct cache access"),
        TestTarget::internal("frontend-web", ns, false, "no peer access"),
        TestTarget::internal("frontend-admin", ns, false, "no peer access"),
        // Wildcard service - mobile does NOT declare outbound, should be BLOCKED
        TestTarget::internal("public-api", ns, false, "no outbound declared to wildcard"),
    ];

    let script = generate_test_script("frontend-mobile", targets);

    create_service(
        "frontend-mobile",
        vec![
            "api-gateway",
            "api-users",
            "api-orders",
            "db-users",
            "db-orders",
            "cache",
            "frontend-web",
            "frontend-admin",
            // NOTE: Intentionally NOT including "public-api" to test wildcard still requires outbound
        ],
        vec![],
        false, // allows_all_inbound
        false, // has_port
        curl_container(script),
    )
}

pub fn create_frontend_admin() -> LatticeService {
    let ns = TEST_SERVICES_NAMESPACE;
    let targets = vec![
        TestTarget::internal("api-gateway", ns, true, "bilateral agreement"),
        TestTarget::internal("api-users", ns, true, "bilateral agreement"),
        TestTarget::internal("api-orders", ns, true, "bilateral agreement"),
        TestTarget::internal("db-users", ns, false, "no direct DB access"),
        TestTarget::internal("db-orders", ns, false, "no direct DB access"),
        TestTarget::internal("cache", ns, false, "no direct cache access"),
        TestTarget::internal("frontend-web", ns, false, "no peer access"),
        TestTarget::internal("frontend-mobile", ns, false, "no peer access"),
        TestTarget::internal("public-api", ns, true, "wildcard allows all with outbound"),
    ];

    let script = generate_test_script("frontend-admin", targets);

    create_service(
        "frontend-admin",
        vec![
            "api-gateway",
            "api-users",
            "api-orders",
            "db-users",
            "db-orders",
            "cache",
            "frontend-web",
            "frontend-mobile",
            "public-api",
        ],
        vec![],
        false, // allows_all_inbound
        false, // has_port
        curl_container(script),
    )
}

pub fn create_api_gateway() -> LatticeService {
    create_service(
        "api-gateway",
        vec!["db-users", "db-orders", "cache"],
        vec!["frontend-web", "frontend-mobile", "frontend-admin"],
        false,
        true,
        nginx_container(),
    )
}

pub fn create_api_users() -> LatticeService {
    create_service(
        "api-users",
        vec!["db-users", "cache"],
        vec!["frontend-web", "frontend-admin"],
        false,
        true,
        nginx_container(),
    )
}

pub fn create_api_orders() -> LatticeService {
    create_service(
        "api-orders",
        vec!["db-orders", "cache"],
        vec!["frontend-mobile", "frontend-admin"],
        false,
        true,
        nginx_container(),
    )
}

pub fn create_db_users() -> LatticeService {
    create_service(
        "db-users",
        vec![],
        vec!["api-gateway", "api-users"],
        false,
        true,
        nginx_container(),
    )
}

pub fn create_db_orders() -> LatticeService {
    create_service(
        "db-orders",
        vec![],
        vec!["api-gateway", "api-orders"],
        false,
        true,
        nginx_container(),
    )
}

pub fn create_cache() -> LatticeService {
    create_service(
        "cache",
        vec![],
        vec!["api-gateway", "api-users", "api-orders"],
        false,
        true,
        nginx_container(),
    )
}

pub fn create_public_api() -> LatticeService {
    create_service(
        "public-api",
        vec![],
        vec![],
        true, // allows_all_inbound (wildcard)
        true, // has_port
        nginx_container(),
    )
}
