//! Criterion benchmarks for mesh policy compilation
//!
//! Measures end-to-end PolicyCompiler::compile() performance across graph
//! topologies and service configurations, scaled to find the ceiling for
//! a 5000-node K8s cluster (10K–50K services).
//!
//! Benchmark groups:
//! - Realistic topology: random bilateral agreements at increasing scale
//! - depends_all worst case: O(n²) bilateral edge resolution
//! - Egress-heavy services: FQDN + CIDR rules
//! - Full reconciliation wave: compile every service in the graph
//! - Extreme scale: 5K, 10K, 25K, 50K services

use std::collections::BTreeMap;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::prelude::*;

use lattice_crd::crd::{
    ContainerSpec, DependencyDirection, EgressRule, EgressTarget, LatticeServiceSpec,
    MeshMemberPort, MeshMemberTarget, NetworkProtocol, PeerAuth, PortSpec, ResourceSpec,
    ServicePortsSpec, ServiceRef, WorkloadSpec,
};
use lattice_graph::ServiceGraph;
use lattice_mesh_member::policy::PolicyCompiler;

// =============================================================================
// Fixtures
// =============================================================================

fn service_spec(deps: &[&str], callers: &[&str]) -> LatticeServiceSpec {
    let mut resources = BTreeMap::new();
    for dep in deps {
        resources.insert(
            dep.to_string(),
            ResourceSpec {
                direction: DependencyDirection::Outbound,
                ..Default::default()
            },
        );
    }
    for caller in callers {
        resources.insert(
            caller.to_string(),
            ResourceSpec {
                direction: DependencyDirection::Inbound,
                ..Default::default()
            },
        );
    }

    let mut containers = BTreeMap::new();
    containers.insert(
        "main".to_string(),
        ContainerSpec {
            image: "test:latest".to_string(),
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

    LatticeServiceSpec {
        workload: WorkloadSpec {
            containers,
            resources,
            service: Some(ServicePortsSpec { ports }),
        },
        ..Default::default()
    }
}

// =============================================================================
// Graph Builders
// =============================================================================

/// Realistic microservices topology: each service has 2-4 deps and bilateral
/// agreements fully wired so active edges form. Uses index-based naming to
/// keep allocation overhead low at large N.
fn build_realistic_graph(n: usize) -> ServiceGraph {
    let graph = ServiceGraph::new("lattice.bench");
    let mut rng = StdRng::seed_from_u64(42);

    // First pass: compute deps for each service
    let mut all_deps: Vec<Vec<usize>> = Vec::with_capacity(n);
    for i in 0..n {
        let max_deps = 4.min(n.saturating_sub(1));
        let num_deps = if max_deps > 0 {
            rng.gen_range(1..=max_deps)
        } else {
            0
        };
        let dep_indices: Vec<usize> = (0..n)
            .filter(|&j| j != i)
            .choose_multiple(&mut rng, num_deps);
        all_deps.push(dep_indices);
    }

    // Second pass: compute callers from deps (if A depends on B, A is a caller of B)
    let mut all_callers: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, deps) in all_deps.iter().enumerate() {
        for &dep in deps {
            all_callers[dep].push(i);
        }
    }

    // Third pass: register services with bilateral agreements
    for i in 0..n {
        let dep_names: Vec<String> = all_deps[i].iter().map(|j| format!("svc-{}", j)).collect();
        let caller_names: Vec<String> = all_callers[i]
            .iter()
            .map(|j| format!("svc-{}", j))
            .collect();
        let dep_refs: Vec<&str> = dep_names.iter().map(|s| s.as_str()).collect();
        let caller_refs: Vec<&str> = caller_names.iter().map(|s| s.as_str()).collect();

        let spec = service_spec(&dep_refs, &caller_refs);
        graph.put_service("default", &format!("svc-{}", i), &spec);
    }

    graph
}

/// Graph where some services have depends_all=true (O(n²) worst case).
fn build_depends_all_graph(n: usize, num_depends_all: usize) -> ServiceGraph {
    let graph = ServiceGraph::new("lattice.bench");
    let mut rng = StdRng::seed_from_u64(42);

    for i in 0..n {
        let max_deps = 3.min(n.saturating_sub(1));
        let num_deps = if max_deps > 0 {
            rng.gen_range(1..=max_deps)
        } else {
            0
        };
        let dep_indices: Vec<usize> = (0..n)
            .filter(|&j| j != i)
            .choose_multiple(&mut rng, num_deps);

        let dep_names: Vec<String> = dep_indices.iter().map(|j| format!("svc-{}", j)).collect();
        let dep_refs: Vec<&str> = dep_names.iter().map(|s| s.as_str()).collect();

        let max_callers = 4.min(n.saturating_sub(1));
        let num_callers = if max_callers > 0 {
            rng.gen_range(1..=max_callers)
        } else {
            0
        };
        let caller_indices: Vec<usize> = (0..n)
            .filter(|&j| j != i)
            .choose_multiple(&mut rng, num_callers);
        let caller_names: Vec<String> = caller_indices
            .iter()
            .map(|j| format!("svc-{}", j))
            .collect();
        let caller_refs: Vec<&str> = caller_names.iter().map(|s| s.as_str()).collect();

        let spec = service_spec(&dep_refs, &caller_refs);
        graph.put_service("default", &format!("svc-{}", i), &spec);
    }

    // Override some services with depends_all via mesh member spec
    for i in 0..num_depends_all {
        let name = format!("svc-{}", i);
        let mm_spec = lattice_crd::crd::LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([("app".to_string(), name.clone())])),
            ports: vec![MeshMemberPort {
                port: 8080,
                service_port: None,
                name: "http".to_string(),
                peer_auth: PeerAuth::Strict,
            }],
            allowed_callers: Vec::new(),
            dependencies: Vec::new(),
            egress: Vec::new(),
            allow_peer_traffic: false,
            depends_all: true,
            ingress: None,
            service_account: None,
            ambient: true, advertise: None,
        };
        graph.put_mesh_member("default", &name, &mm_spec);
    }

    graph
}

/// Graph with services that have FQDN/CIDR egress rules for external traffic.
fn build_egress_graph(n: usize, egress_per_service: usize) -> ServiceGraph {
    let graph = ServiceGraph::new("lattice.bench");

    for i in 0..n {
        let dep_name = format!("svc-{}", (i + 1) % n);
        let caller_name = format!("svc-{}", (i + n - 1) % n);
        let spec = service_spec(&[&dep_name], &[&caller_name]);
        graph.put_service("default", &format!("svc-{}", i), &spec);

        let egress: Vec<EgressRule> = (0..egress_per_service)
            .map(|e| EgressRule {
                target: if e % 2 == 0 {
                    EgressTarget::Fqdn(format!("api-{}.example.com", e))
                } else {
                    EgressTarget::Cidr(format!("10.{}.0.0/16", e))
                },
                ports: vec![443],
                protocol: NetworkProtocol::default(),
            })
            .collect();

        let mm_spec = lattice_crd::crd::LatticeMeshMemberSpec {
            target: MeshMemberTarget::Selector(BTreeMap::from([(
                "app".to_string(),
                format!("svc-{}", i),
            )])),
            ports: vec![MeshMemberPort {
                port: 8080,
                service_port: None,
                name: "http".to_string(),
                peer_auth: PeerAuth::Strict,
            }],
            allowed_callers: vec![ServiceRef::local(&caller_name)],
            dependencies: vec![ServiceRef::local(&dep_name)],
            egress,
            allow_peer_traffic: false,
            depends_all: false,
            ingress: None,
            service_account: None,
            ambient: true, advertise: None,
        };
        graph.put_mesh_member("default", &format!("svc-{}", i), &mm_spec);
    }

    graph
}

// =============================================================================
// Benchmarks: Single service compile at increasing graph scale
// =============================================================================

fn bench_compile_realistic(c: &mut Criterion) {
    let mut group = c.benchmark_group("mesh_policy_compile");

    for size in [10usize, 50, 200, 1_000, 5_000, 10_000] {
        let graph = build_realistic_graph(size);
        let compiler = PolicyCompiler::new(&graph, vec![]);
        let mut rng = StdRng::seed_from_u64(99);

        group.bench_with_input(BenchmarkId::new("realistic", size), &size, |b, &size| {
            b.iter(|| {
                let idx = rng.gen_range(0..size);
                black_box(compiler.compile(&format!("svc-{}", idx), "default"));
            });
        });
    }

    group.finish();
}

// =============================================================================
// Benchmarks: depends_all O(n²) worst case
// =============================================================================

fn bench_compile_depends_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("mesh_policy_depends_all");

    // (total services, depends_all count)
    for (total, da_count) in [
        (50, 5),
        (200, 20),
        (1_000, 100),
        (5_000, 500),
        (10_000, 1_000),
    ] {
        let graph = build_depends_all_graph(total, da_count);
        let compiler = PolicyCompiler::new(&graph, vec![]);

        // Bench a depends_all service (worst case: scans all vertices)
        group.bench_with_input(
            BenchmarkId::new("da_service", format!("{}total_{}da", total, da_count)),
            &(),
            |b, _| {
                b.iter(|| {
                    black_box(compiler.compile("svc-0", "default"));
                });
            },
        );

        // Bench a normal service in a graph with depends_all nodes
        group.bench_with_input(
            BenchmarkId::new("normal_service", format!("{}total_{}da", total, da_count)),
            &total,
            |b, &total| {
                b.iter(|| {
                    let idx = total - 1;
                    black_box(compiler.compile(&format!("svc-{}", idx), "default"));
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Egress-heavy services
// =============================================================================

fn bench_compile_egress(c: &mut Criterion) {
    let mut group = c.benchmark_group("mesh_policy_egress");

    for (n, egress_count) in [(20, 5), (20, 20), (50, 10), (200, 50)] {
        let graph = build_egress_graph(n, egress_count);
        let compiler = PolicyCompiler::new(&graph, vec![]);

        group.bench_with_input(
            BenchmarkId::new("fqdn_cidr", format!("{}svc_{}egress", n, egress_count)),
            &(),
            |b, _| {
                b.iter(|| {
                    black_box(compiler.compile("svc-0", "default"));
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Full reconciliation wave (compile every service)
// =============================================================================

fn bench_compile_full_wave(c: &mut Criterion) {
    let mut group = c.benchmark_group("mesh_policy_wave");
    group.sample_size(10);

    for size in [10usize, 50, 200, 1_000] {
        let graph = build_realistic_graph(size);
        let compiler = PolicyCompiler::new(&graph, vec![]);

        group.bench_with_input(BenchmarkId::new("all_services", size), &size, |b, &size| {
            b.iter(|| {
                for i in 0..size {
                    black_box(compiler.compile(&format!("svc-{}", i), "default"));
                }
            });
        });
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Extreme scale — 5000-node cluster territory (10K–50K services)
// =============================================================================

fn bench_compile_extreme(c: &mut Criterion) {
    let mut group = c.benchmark_group("mesh_policy_extreme");
    group.sample_size(10);

    for size in [5_000usize, 10_000, 25_000, 50_000] {
        let graph = build_realistic_graph(size);
        let compiler = PolicyCompiler::new(&graph, vec![]);
        let mut rng = StdRng::seed_from_u64(77);

        // Single service compile in a massive graph
        group.bench_with_input(
            BenchmarkId::new("single_compile", size),
            &size,
            |b, &size| {
                b.iter(|| {
                    let idx = rng.gen_range(0..size);
                    black_box(compiler.compile(&format!("svc-{}", idx), "default"));
                });
            },
        );
    }

    // Wave of 100 services in a 50K graph (simulates a busy reconciliation burst)
    {
        let size = 50_000;
        let graph = build_realistic_graph(size);
        let compiler = PolicyCompiler::new(&graph, vec![]);

        group.bench_function("wave_100_in_50k", |b| {
            b.iter(|| {
                for i in 0..100 {
                    black_box(compiler.compile(&format!("svc-{}", i), "default"));
                }
            });
        });
    }

    // depends_all in a 10K graph — the real danger zone
    {
        let graph = build_depends_all_graph(10_000, 100);
        let compiler = PolicyCompiler::new(&graph, vec![]);

        group.bench_function("da_in_10k", |b| {
            b.iter(|| {
                black_box(compiler.compile("svc-0", "default"));
            });
        });
    }

    group.finish();
}

// =============================================================================
// Criterion Groups
// =============================================================================

criterion_group!(
    benches,
    bench_compile_realistic,
    bench_compile_depends_all,
    bench_compile_egress,
    bench_compile_full_wave,
    bench_compile_extreme,
);
criterion_main!(benches);
