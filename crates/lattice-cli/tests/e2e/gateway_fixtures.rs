//! Service builders for Gateway API integration tests
//!
//! Factory functions producing LatticeService objects with `spec.ingress` set.
//! Reuses container and resource builders from `mesh_fixtures.rs`.

#![cfg(feature = "provider-e2e")]

use std::collections::BTreeMap;

use lattice_common::crd::{
    CertIssuerRef, IngressSpec, IngressTls, PathMatch, PathMatchType, RouteKind, RouteMatch,
    RouteRule, RouteSpec,
};

use super::gateway_helpers::{generate_gateway_test_script, GatewayTestTarget};
use super::mesh_fixtures::{
    build_lattice_service, curl_container, entity_egress, inbound_allow_all, nginx_container,
    outbound_dep,
};

// =============================================================================
// Constants
// =============================================================================

pub const GATEWAY_TEST_NAMESPACE: &str = "gateway-test";

// =============================================================================
// Backend Services
// =============================================================================

/// Backend A: nginx with a catch-all HTTPRoute on `backend-a.gateway-test.local`.
pub fn create_backend_a() -> lattice_common::crd::LatticeService {
    let mut resources = BTreeMap::new();
    let (key, spec) = inbound_allow_all();
    resources.insert(key, spec);

    let mut svc = build_lattice_service(
        "backend-a",
        GATEWAY_TEST_NAMESPACE,
        resources,
        true,
        nginx_container(),
    );

    let mut routes = BTreeMap::new();
    routes.insert(
        "public".to_string(),
        RouteSpec {
            kind: RouteKind::HTTPRoute,
            hosts: vec!["backend-a.gateway-test.local".to_string()],
            port: None,
            listen_port: None,
            rules: None, // catch-all
            tls: None,
        },
    );

    svc.spec.ingress = Some(IngressSpec {
        gateway_class: None,
        routes,
    });

    svc
}

/// Backend B: nginx with a single HTTPRoute on `backend-b.gateway-test.local`
/// containing two match rules:
///
/// - PathPrefix `/api` (matches `/api`, `/api/v1/users`, etc.)
/// - Exact `/health`
///
/// Requests to other paths (e.g. `/other`) should get 404 from the gateway.
/// Both rules are in one route to avoid duplicate Gateway listeners (Gateway API
/// requires unique port+protocol+hostname per listener).
pub fn create_backend_b() -> lattice_common::crd::LatticeService {
    let mut resources = BTreeMap::new();
    let (key, spec) = inbound_allow_all();
    resources.insert(key, spec);

    let mut svc = build_lattice_service(
        "backend-b",
        GATEWAY_TEST_NAMESPACE,
        resources,
        true,
        nginx_container(),
    );

    let mut routes = BTreeMap::new();

    // Single route with two match rules: PathPrefix /api + Exact /health
    routes.insert(
        "public".to_string(),
        RouteSpec {
            kind: RouteKind::HTTPRoute,
            hosts: vec!["backend-b.gateway-test.local".to_string()],
            port: None,
            listen_port: None,
            rules: Some(vec![
                RouteRule {
                    matches: vec![RouteMatch {
                        path: Some(PathMatch {
                            type_: PathMatchType::PathPrefix,
                            value: "/api".to_string(),
                        }),
                        headers: vec![],
                        method: None,
                        grpc_method: None,
                    }],
                },
                RouteRule {
                    matches: vec![RouteMatch {
                        path: Some(PathMatch {
                            type_: PathMatchType::Exact,
                            value: "/health".to_string(),
                        }),
                        headers: vec![],
                        method: None,
                        grpc_method: None,
                    }],
                },
            ]),
            tls: None,
        },
    );

    svc.spec.ingress = Some(IngressSpec {
        gateway_class: None,
        routes,
    });

    svc
}

/// Backend TLS: nginx with HTTPRoute on `secure.gateway-test.local` with auto TLS.
pub fn create_backend_tls() -> lattice_common::crd::LatticeService {
    let mut resources = BTreeMap::new();
    let (key, spec) = inbound_allow_all();
    resources.insert(key, spec);

    let mut svc = build_lattice_service(
        "backend-tls",
        GATEWAY_TEST_NAMESPACE,
        resources,
        true,
        nginx_container(),
    );

    let mut routes = BTreeMap::new();
    routes.insert(
        "public".to_string(),
        RouteSpec {
            kind: RouteKind::HTTPRoute,
            hosts: vec!["secure.gateway-test.local".to_string()],
            port: None,
            listen_port: None,
            rules: None, // catch-all
            tls: Some(IngressTls {
                secret_name: None,
                issuer_ref: Some(CertIssuerRef {
                    name: "e2e-selfsigned".to_string(),
                    kind: None,
                }),
            }),
        },
    );

    svc.spec.ingress = Some(IngressSpec {
        gateway_class: None,
        routes,
    });

    svc
}

/// Traffic generator that curls the gateway ClusterIP with Host headers.
///
/// Uses cycle-based script pattern for reliable verification.
pub fn create_gateway_traffic_gen(
    gateway_ip: &str,
    gateway_https_port: u16,
) -> lattice_common::crd::LatticeService {
    let targets = vec![
        // backend-a catch-all
        GatewayTestTarget {
            host: "backend-a.gateway-test.local".to_string(),
            path: "/".to_string(),
            use_https: false,
            expected_status: ExpectedStatus::Success,
            label: "backend-a catch-all".to_string(),
        },
        // backend-b PathPrefix /api
        GatewayTestTarget {
            host: "backend-b.gateway-test.local".to_string(),
            path: "/api".to_string(),
            use_https: false,
            expected_status: ExpectedStatus::Success,
            label: "backend-b /api prefix".to_string(),
        },
        // backend-b PathPrefix /api/v1/users (sub-path of /api)
        GatewayTestTarget {
            host: "backend-b.gateway-test.local".to_string(),
            path: "/api/v1/users".to_string(),
            use_https: false,
            expected_status: ExpectedStatus::Success,
            label: "backend-b /api/v1/users prefix".to_string(),
        },
        // backend-b Exact /health
        GatewayTestTarget {
            host: "backend-b.gateway-test.local".to_string(),
            path: "/health".to_string(),
            use_https: false,
            expected_status: ExpectedStatus::Success,
            label: "backend-b /health exact".to_string(),
        },
        // backend-b /other — no matching rule, expect 404
        GatewayTestTarget {
            host: "backend-b.gateway-test.local".to_string(),
            path: "/other".to_string(),
            use_https: false,
            expected_status: ExpectedStatus::NotFound,
            label: "backend-b /other no-match".to_string(),
        },
        // nonexistent host — expect 404
        GatewayTestTarget {
            host: "nonexistent.gateway-test.local".to_string(),
            path: "/".to_string(),
            use_https: false,
            expected_status: ExpectedStatus::NotFound,
            label: "nonexistent host".to_string(),
        },
        // backend-tls via HTTPS
        GatewayTestTarget {
            host: "secure.gateway-test.local".to_string(),
            path: "/".to_string(),
            use_https: true,
            expected_status: ExpectedStatus::Success,
            label: "backend-tls HTTPS".to_string(),
        },
    ];

    let script = generate_gateway_test_script(
        "gateway-traffic-gen",
        gateway_ip,
        gateway_https_port,
        targets,
    );

    // The traffic-gen needs two types of Cilium egress:
    //
    // 1. HBONE egress (port 15008): ztunnel wraps mesh-to-mesh traffic in HBONE.
    //    Any outbound dependency triggers the HBONE egress rule in the CNP.
    //
    // 2. Direct TCP egress (ports 80, 443): the gateway proxy has
    //    `istio.io/dataplane-mode: none`, so ztunnel does passthrough (plain TCP).
    //    Cilium sees port 80/443, not 15008, so entity egress rules are needed.
    let resources = BTreeMap::from([
        outbound_dep("backend-a"),
        entity_egress("cluster", 80),
        entity_egress("cluster", 443),
    ]);

    build_lattice_service(
        "gateway-traffic-gen",
        GATEWAY_TEST_NAMESPACE,
        resources,
        false,
        curl_container(script),
    )
}

// =============================================================================
// Types (used by gateway_helpers)
// =============================================================================

/// Expected HTTP status category for a gateway traffic target.
#[derive(Clone, Debug, PartialEq)]
pub enum ExpectedStatus {
    /// 2xx response (route matched, backend reachable)
    Success,
    /// 404 response (no matching route or host)
    NotFound,
}
