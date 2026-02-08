//! Criterion benchmarks for ServiceCompiler::compile()
//!
//! Measures end-to-end compilation performance across service configurations:
//! - Baseline: minimal service
//! - With mesh: service dependencies and bilateral agreements
//! - With secrets: secret resources with Cedar permit-all policy
//! - With ingress: Gateway API resources
//! - Full: all features combined

use std::collections::BTreeMap;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use lattice_cedar::PolicyEngine;
use lattice_common::crd::{
    CertIssuerRef, ContainerSpec, DependencyDirection, IngressSpec, IngressTls, LatticeService,
    LatticeServiceSpec, PortSpec, ProviderType, ResourceSpec, ResourceType, ServicePortsSpec,
    TlsMode,
};
use lattice_common::graph::ServiceGraph;
use lattice_service::compiler::ServiceCompiler;

// =============================================================================
// Fixtures
// =============================================================================

fn simple_container() -> ContainerSpec {
    ContainerSpec {
        image: "nginx:latest".to_string(),
        ..Default::default()
    }
}

fn default_ports() -> ServicePortsSpec {
    let mut ports = BTreeMap::new();
    ports.insert(
        "http".to_string(),
        PortSpec {
            port: 8080,
            target_port: None,
            protocol: None,
        },
    );
    ServicePortsSpec { ports }
}

fn make_service(name: &str, namespace: &str, spec: LatticeServiceSpec) -> LatticeService {
    LatticeService {
        metadata: kube::api::ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec,
        status: None,
    }
}

fn baseline_spec() -> LatticeServiceSpec {
    let mut containers = BTreeMap::new();
    containers.insert("main".to_string(), simple_container());

    LatticeServiceSpec {
        containers,
        service: Some(default_ports()),
        ..Default::default()
    }
}

fn mesh_spec(num_deps: usize, num_callers: usize) -> LatticeServiceSpec {
    let mut spec = baseline_spec();

    for i in 0..num_deps {
        spec.resources.insert(
            format!("dep-{}", i),
            ResourceSpec {
                direction: DependencyDirection::Outbound,
                ..Default::default()
            },
        );
    }
    for i in 0..num_callers {
        spec.resources.insert(
            format!("caller-{}", i),
            ResourceSpec {
                direction: DependencyDirection::Inbound,
                ..Default::default()
            },
        );
    }

    spec
}

fn secrets_spec(num_secrets: usize, keys_per_secret: usize) -> LatticeServiceSpec {
    let mut spec = baseline_spec();

    for i in 0..num_secrets {
        let mut params = BTreeMap::new();
        params.insert("provider".to_string(), serde_json::json!("vault-prod"));
        if keys_per_secret > 0 {
            let keys: Vec<String> = (0..keys_per_secret).map(|k| format!("key-{}", k)).collect();
            params.insert("keys".to_string(), serde_json::json!(keys));
        }

        spec.resources.insert(
            format!("secret-{}", i),
            ResourceSpec {
                type_: ResourceType::Secret,
                id: Some(format!("path/to/secret-{}", i)),
                params: Some(params),
                ..Default::default()
            },
        );
    }

    spec
}

fn ingress_spec() -> LatticeServiceSpec {
    let mut spec = baseline_spec();
    spec.ingress = Some(IngressSpec {
        hosts: vec!["api.example.com".to_string()],
        paths: None,
        tls: Some(IngressTls {
            mode: TlsMode::Auto,
            secret_name: None,
            issuer_ref: Some(CertIssuerRef {
                name: "letsencrypt-prod".to_string(),
                kind: None,
            }),
        }),
        gateway_class: None,
    });
    spec
}

fn full_spec(num_deps: usize, num_callers: usize, num_secrets: usize) -> LatticeServiceSpec {
    let mut spec = mesh_spec(num_deps, num_callers);

    // Add secrets
    for i in 0..num_secrets {
        let mut params = BTreeMap::new();
        params.insert("provider".to_string(), serde_json::json!("vault-prod"));
        let keys: Vec<String> = (0..3).map(|k| format!("key-{}", k)).collect();
        params.insert("keys".to_string(), serde_json::json!(keys));

        spec.resources.insert(
            format!("secret-{}", i),
            ResourceSpec {
                type_: ResourceType::Secret,
                id: Some(format!("path/to/secret-{}", i)),
                params: Some(params),
                ..Default::default()
            },
        );
    }

    // Add ingress
    spec.ingress = Some(IngressSpec {
        hosts: vec!["api.example.com".to_string()],
        paths: None,
        tls: Some(IngressTls {
            mode: TlsMode::Auto,
            secret_name: None,
            issuer_ref: Some(CertIssuerRef {
                name: "letsencrypt-prod".to_string(),
                kind: None,
            }),
        }),
        gateway_class: None,
    });

    spec
}

/// Populate the service graph with bilateral agreements for a target service
fn setup_graph(graph: &ServiceGraph, namespace: &str, spec: &LatticeServiceSpec) {
    graph.put_service(namespace, "target", spec);

    // Register dependency services so active edges exist
    for (name, res) in &spec.resources {
        if res.type_ == ResourceType::Service && res.direction.is_outbound() {
            // dep allows target as caller
            let dep_spec = mesh_spec(0, 0);
            let mut dep_resources = dep_spec.resources;
            dep_resources.insert(
                "target".to_string(),
                ResourceSpec {
                    direction: DependencyDirection::Inbound,
                    ..Default::default()
                },
            );
            let mut dep = baseline_spec();
            dep.resources = dep_resources;
            graph.put_service(namespace, name, &dep);
        }
        if res.type_ == ResourceType::Service && res.direction.is_inbound() {
            // caller declares target as outbound dep
            let mut caller = baseline_spec();
            caller.resources.insert(
                "target".to_string(),
                ResourceSpec {
                    direction: DependencyDirection::Outbound,
                    ..Default::default()
                },
            );
            graph.put_service(namespace, name, &caller);
        }
    }
}

fn cedar_permit_all_secrets() -> PolicyEngine {
    PolicyEngine::with_policies(
        r#"permit(
            principal,
            action == Lattice::Action::"AccessSecret",
            resource
        );"#,
    )
    .expect("valid cedar policy")
}

// =============================================================================
// Benchmarks
// =============================================================================

fn bench_baseline(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("compile_baseline");

    let graph = ServiceGraph::new();
    let cedar = PolicyEngine::new();
    let spec = baseline_spec();
    graph.put_service("default", "target", &spec);
    let service = make_service("target", "default", spec);
    let compiler =
        ServiceCompiler::new(&graph, "bench-cluster", ProviderType::Docker, &cedar, true);

    group.bench_function("minimal", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(compiler.compile(&service).await.unwrap());
            });
        });
    });

    group.finish();
}

fn bench_mesh(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("compile_mesh");

    for (deps, callers) in [(2, 2), (5, 5), (10, 10), (20, 10)] {
        let graph = ServiceGraph::new();
        let cedar = PolicyEngine::new();
        let spec = mesh_spec(deps, callers);
        setup_graph(&graph, "default", &spec);
        let service = make_service("target", "default", spec);
        let compiler =
            ServiceCompiler::new(&graph, "bench-cluster", ProviderType::Docker, &cedar, true);

        group.bench_with_input(
            BenchmarkId::new("deps_callers", format!("{}d_{}c", deps, callers)),
            &(),
            |b, _| {
                b.iter(|| {
                    rt.block_on(async {
                        black_box(compiler.compile(&service).await.unwrap());
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_secrets(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("compile_secrets");

    for num_secrets in [1, 3, 5, 10] {
        let graph = ServiceGraph::new();
        let cedar = cedar_permit_all_secrets();
        let spec = secrets_spec(num_secrets, 3);
        graph.put_service("default", "target", &spec);
        let service = make_service("target", "default", spec);
        let compiler =
            ServiceCompiler::new(&graph, "bench-cluster", ProviderType::Docker, &cedar, true);

        group.bench_with_input(BenchmarkId::new("count", num_secrets), &(), |b, _| {
            b.iter(|| {
                rt.block_on(async {
                    black_box(compiler.compile(&service).await.unwrap());
                });
            });
        });
    }

    group.finish();
}

fn bench_ingress(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("compile_ingress");

    let graph = ServiceGraph::new();
    let cedar = PolicyEngine::new();
    let spec = ingress_spec();
    graph.put_service("default", "target", &spec);
    let service = make_service("target", "default", spec);
    let compiler =
        ServiceCompiler::new(&graph, "bench-cluster", ProviderType::Docker, &cedar, true);

    group.bench_function("with_tls", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(compiler.compile(&service).await.unwrap());
            });
        });
    });

    group.finish();
}

fn bench_full(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("compile_full");

    for (deps, callers, secrets) in [(5, 5, 3), (10, 10, 5), (20, 10, 10)] {
        let graph = ServiceGraph::new();
        let cedar = cedar_permit_all_secrets();
        let spec = full_spec(deps, callers, secrets);
        setup_graph(&graph, "default", &spec);
        let service = make_service("target", "default", spec);
        let compiler =
            ServiceCompiler::new(&graph, "bench-cluster", ProviderType::Docker, &cedar, true);

        group.bench_with_input(
            BenchmarkId::new("full", format!("{}d_{}c_{}s", deps, callers, secrets)),
            &(),
            |b, _| {
                b.iter(|| {
                    rt.block_on(async {
                        black_box(compiler.compile(&service).await.unwrap());
                    });
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Criterion Groups
// =============================================================================

criterion_group!(
    benches,
    bench_baseline,
    bench_mesh,
    bench_secrets,
    bench_ingress,
    bench_full,
);
criterion_main!(benches);
