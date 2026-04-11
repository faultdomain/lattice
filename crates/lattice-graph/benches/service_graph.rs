//! Criterion benchmarks for ServiceGraph
//!
//! Measures performance of ServiceGraph operations used during reconciliation
//! and network policy generation, scaled to find the ceiling for a 5000-node
//! K8s cluster (10K–50K services).
//!
//! Benchmark groups:
//! - Single operations (put, get, delete) up to 50K services
//! - Dependency/dependent lookups at scale
//! - Active edge computation (bilateral agreements) — the hot path
//! - depends_all worst case (O(n²) scan)
//! - Concurrent read/write under contention at scale
//! - Full reconciliation pattern at scale

use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::prelude::*;

use lattice_crd::crd::{
    ContainerSpec, DependencyDirection, LatticeMeshMemberSpec, LatticeServiceSpec, MeshMemberPort,
    MeshMemberTarget, PeerAuth, PortSpec, ResourceParams, ResourceSpec, ResourceType,
    ServicePortsSpec, WorkloadSpec,
};
use lattice_graph::ServiceGraph;

// =============================================================================
// Test Fixtures
// =============================================================================

fn simple_container() -> ContainerSpec {
    ContainerSpec {
        image: "nginx:latest".to_string(),
        command: Some(vec!["/usr/sbin/nginx".to_string()]),
        ..Default::default()
    }
}

fn service_spec_with_deps(deps: &[&str], callers: &[&str]) -> LatticeServiceSpec {
    let mut containers = BTreeMap::new();
    containers.insert("main".to_string(), simple_container());

    let mut resources = BTreeMap::new();
    for dep in deps {
        resources.insert(
            dep.to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Outbound,
                id: None,
                class: None,
                metadata: None,
                params: ResourceParams::None,
                namespace: None,
            },
        );
    }
    for caller in callers {
        resources.insert(
            caller.to_string(),
            ResourceSpec {
                type_: ResourceType::Service,
                direction: DependencyDirection::Inbound,
                id: None,
                class: None,
                metadata: None,
                params: ResourceParams::None,
                namespace: None,
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

    LatticeServiceSpec {
        workload: WorkloadSpec {
            containers,
            resources,
            service: Some(ServicePortsSpec { ports }),
        },
        ..Default::default()
    }
}

fn simple_service_spec() -> LatticeServiceSpec {
    service_spec_with_deps(&[], &[])
}

// =============================================================================
// Graph Setup Helpers
// =============================================================================

/// Chain topology: svc-0 → svc-1 → ... → svc-n with bilateral agreements
fn setup_chain_graph(n: usize) -> ServiceGraph {
    let graph = ServiceGraph::new("lattice.test");

    for i in 0..n {
        let dep_name = format!("svc-{}", i + 1);
        let spec = if i < n - 1 {
            service_spec_with_deps(&[&dep_name], &[])
        } else {
            simple_service_spec()
        };
        graph.put_service("default", &format!("svc-{}", i), &spec);
    }

    for i in 1..n {
        let caller_name = format!("svc-{}", i - 1);
        let spec = service_spec_with_deps(&[], &[&caller_name]);
        graph.put_service("default", &format!("svc-{}", i), &spec);
    }

    graph
}

/// Star topology: hub ← spoke-0, spoke-1, ..., spoke-n
fn setup_star_graph(n: usize) -> ServiceGraph {
    let graph = ServiceGraph::new("lattice.test");

    let caller_names: Vec<String> = (0..n).map(|i| format!("spoke-{}", i)).collect();
    let caller_refs: Vec<&str> = caller_names.iter().map(|s| s.as_str()).collect();
    let hub_spec = service_spec_with_deps(&[], &caller_refs);
    graph.put_service("default", "hub", &hub_spec);

    for i in 0..n {
        let spec = service_spec_with_deps(&["hub"], &[]);
        graph.put_service("default", &format!("spoke-{}", i), &spec);
    }

    graph
}

/// Realistic microservices topology with proper bilateral agreements
fn setup_realistic_graph(n: usize) -> ServiceGraph {
    let graph = ServiceGraph::new("lattice.test");
    let mut rng = StdRng::seed_from_u64(42);

    // First pass: compute deps
    let mut all_deps: Vec<Vec<usize>> = Vec::with_capacity(n);
    for i in 0..n {
        let max_deps = 4.min(n.saturating_sub(1));
        let num_deps = if max_deps > 0 {
            rng.gen_range(0..=max_deps)
        } else {
            0
        };
        let dep_indices: Vec<usize> = (0..n)
            .filter(|&j| j != i)
            .choose_multiple(&mut rng, num_deps);
        all_deps.push(dep_indices);
    }

    // Second pass: compute callers from deps
    let mut all_callers: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, deps) in all_deps.iter().enumerate() {
        for &dep in deps {
            all_callers[dep].push(i);
        }
    }

    // Third pass: register with bilateral agreements
    for i in 0..n {
        let dep_names: Vec<String> = all_deps[i].iter().map(|j| format!("svc-{}", j)).collect();
        let caller_names: Vec<String> = all_callers[i]
            .iter()
            .map(|j| format!("svc-{}", j))
            .collect();
        let dep_refs: Vec<&str> = dep_names.iter().map(|s| s.as_str()).collect();
        let caller_refs: Vec<&str> = caller_names.iter().map(|s| s.as_str()).collect();

        let spec = service_spec_with_deps(&dep_refs, &caller_refs);
        graph.put_service("default", &format!("svc-{}", i), &spec);
    }

    graph
}

/// Graph with some depends_all services (O(n²) worst case for active edges)
fn setup_depends_all_graph(n: usize, num_depends_all: usize) -> ServiceGraph {
    let graph = setup_realistic_graph(n);

    for i in 0..num_depends_all {
        let name = format!("svc-{}", i);
        let mm_spec = LatticeMeshMemberSpec {
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

// =============================================================================
// Benchmarks: Single Operations at Scale
// =============================================================================

fn bench_put_service(c: &mut Criterion) {
    let mut group = c.benchmark_group("put_service");

    for size in [10usize, 100, 1_000, 5_000, 10_000, 50_000] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("empty_graph", size), &size, |b, &size| {
            let graph = ServiceGraph::new("lattice.test");
            let spec = simple_service_spec();
            let mut i = 0;
            b.iter(|| {
                graph.put_service("default", &format!("svc-{}", i % size), black_box(&spec));
                i += 1;
            });
        });

        // Only run existing_graph for sizes that don't take too long to set up
        if size <= 10_000 {
            group.bench_with_input(
                BenchmarkId::new("existing_graph", size),
                &size,
                |b, &size| {
                    let graph = setup_realistic_graph(size);
                    let spec = simple_service_spec();
                    let mut i = 0;
                    b.iter(|| {
                        graph.put_service(
                            "default",
                            &format!("svc-{}", i % size),
                            black_box(&spec),
                        );
                        i += 1;
                    });
                },
            );
        }
    }

    group.finish();
}

fn bench_get_service(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_service");

    for size in [10usize, 100, 1_000, 5_000, 10_000, 50_000] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("lookup", size), &size, |b, &size| {
            let graph = setup_realistic_graph(size);
            let mut rng = StdRng::seed_from_u64(99);
            b.iter(|| {
                let idx = rng.gen_range(0..size);
                black_box(graph.get_service("default", &format!("svc-{}", idx)));
            });
        });
    }

    group.finish();
}

fn bench_delete_service(c: &mut Criterion) {
    let mut group = c.benchmark_group("delete_service");

    for size in [10usize, 100, 500, 5_000] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("delete", size), &size, |b, &size| {
            b.iter_batched(
                || setup_realistic_graph(size),
                |graph| {
                    let idx = size / 2;
                    graph.delete_service("default", &format!("svc-{}", idx));
                    black_box(graph)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Dependency/Dependent Lookups at Scale
// =============================================================================

fn bench_get_dependencies(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_dependencies");

    for size in [10usize, 100, 1_000, 5_000, 10_000] {
        group.throughput(Throughput::Elements(1));

        group.bench_with_input(BenchmarkId::new("chain", size), &size, |b, &size| {
            let graph = setup_chain_graph(size);
            let mut rng = StdRng::seed_from_u64(99);
            b.iter(|| {
                let idx = rng.gen_range(0..size);
                black_box(graph.get_dependencies("default", &format!("svc-{}", idx)));
            });
        });

        group.bench_with_input(BenchmarkId::new("star", size), &size, |b, &size| {
            let graph = setup_star_graph(size);
            let mut rng = StdRng::seed_from_u64(99);
            b.iter(|| {
                let idx = rng.gen_range(0..size);
                black_box(graph.get_dependencies("default", &format!("spoke-{}", idx)));
            });
        });
    }

    group.finish();
}

fn bench_get_dependents(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_dependents");

    for size in [10usize, 100, 500, 5_000, 10_000] {
        group.throughput(Throughput::Elements(1));

        group.bench_with_input(BenchmarkId::new("star_hub", size), &size, |b, _| {
            let graph = setup_star_graph(size);
            b.iter(|| {
                black_box(graph.get_dependents("default", "hub"));
            });
        });

        group.bench_with_input(BenchmarkId::new("realistic", size), &size, |b, &size| {
            let graph = setup_realistic_graph(size);
            let mut rng = StdRng::seed_from_u64(99);
            b.iter(|| {
                let idx = rng.gen_range(0..size);
                black_box(graph.get_dependents("default", &format!("svc-{}", idx)));
            });
        });
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Active Edge Operations (the hot path for mesh policy)
// =============================================================================

fn bench_get_active_edges(c: &mut Criterion) {
    let mut group = c.benchmark_group("active_edges");

    for size in [10usize, 100, 500, 5_000, 10_000, 50_000] {
        group.throughput(Throughput::Elements(1));

        group.bench_with_input(BenchmarkId::new("inbound", size), &size, |b, &size| {
            let graph = setup_realistic_graph(size);
            let mut rng = StdRng::seed_from_u64(99);
            b.iter(|| {
                let idx = rng.gen_range(0..size);
                black_box(graph.get_active_inbound_edges("default", &format!("svc-{}", idx)));
            });
        });

        group.bench_with_input(BenchmarkId::new("outbound", size), &size, |b, &size| {
            let graph = setup_realistic_graph(size);
            let mut rng = StdRng::seed_from_u64(99);
            b.iter(|| {
                let idx = rng.gen_range(0..size);
                black_box(graph.get_active_outbound_edges("default", &format!("svc-{}", idx)));
            });
        });

        // Star hub: one service with N inbound edges
        if size <= 10_000 {
            group.bench_with_input(BenchmarkId::new("star_hub_inbound", size), &size, |b, _| {
                let graph = setup_star_graph(size);
                b.iter(|| {
                    black_box(graph.get_active_inbound_edges("default", "hub"));
                });
            });
        }
    }

    group.finish();
}

// =============================================================================
// Benchmarks: depends_all — O(n²) worst case
// =============================================================================

fn bench_depends_all_edges(c: &mut Criterion) {
    let mut group = c.benchmark_group("active_edges_depends_all");

    // (total, depends_all count)
    for (total, da_count) in [
        (100, 10),
        (500, 50),
        (1_000, 100),
        (5_000, 500),
        (10_000, 1_000),
    ] {
        group.throughput(Throughput::Elements(1));

        // Bench a depends_all service (scans all vertices)
        group.bench_with_input(
            BenchmarkId::new("da_outbound", format!("{}total_{}da", total, da_count)),
            &(),
            |b, _| {
                let graph = setup_depends_all_graph(total, da_count);
                b.iter(|| {
                    black_box(graph.get_active_outbound_edges("default", "svc-0"));
                });
            },
        );

        // Bench inbound edges for a normal service when depends_all services exist
        // (depends_all services appear as extra callers)
        group.bench_with_input(
            BenchmarkId::new("normal_inbound", format!("{}total_{}da", total, da_count)),
            &total,
            |b, &total| {
                let graph = setup_depends_all_graph(total, da_count);
                b.iter(|| {
                    let idx = total - 1;
                    black_box(graph.get_active_inbound_edges("default", &format!("svc-{}", idx)));
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Concurrent Operations at Scale
// =============================================================================

fn bench_concurrent_reads(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_reads");

    for size in [100usize, 500, 5_000, 10_000] {
        group.throughput(Throughput::Elements(4));

        group.bench_with_input(BenchmarkId::new("parallel_get", size), &size, |b, &size| {
            let graph = Arc::new(setup_realistic_graph(size));

            b.iter(|| {
                let handles: Vec<_> = (0..4)
                    .map(|t| {
                        let g = Arc::clone(&graph);
                        thread::spawn(move || {
                            for i in 0..25 {
                                let idx = (t * 25 + i) % size;
                                black_box(g.get_service("default", &format!("svc-{}", idx)));
                            }
                        })
                    })
                    .collect();

                for h in handles {
                    h.join().unwrap();
                }
            });
        });
    }

    group.finish();
}

fn bench_concurrent_mixed(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_mixed");

    for size in [100usize, 500, 5_000] {
        group.throughput(Throughput::Elements(4));

        group.bench_with_input(
            BenchmarkId::new("read_write_mix", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    || Arc::new(setup_realistic_graph(size)),
                    |graph| {
                        let spec = simple_service_spec();

                        let handles: Vec<_> = (0..4)
                            .map(|t| {
                                let g = Arc::clone(&graph);
                                let s = spec.clone();
                                thread::spawn(move || {
                                    for i in 0..25 {
                                        let idx = (t * 25 + i) % size;
                                        if i % 5 == 0 {
                                            g.put_service("default", &format!("svc-{}", idx), &s);
                                        } else {
                                            black_box(
                                                g.get_service("default", &format!("svc-{}", idx)),
                                            );
                                        }
                                    }
                                })
                            })
                            .collect();

                        for h in handles {
                            h.join().unwrap();
                        }

                        black_box(graph)
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Full Reconciliation Pattern at Scale
// =============================================================================

fn bench_reconcile_pattern(c: &mut Criterion) {
    let mut group = c.benchmark_group("reconcile_pattern");

    for size in [100usize, 500, 5_000, 10_000, 50_000] {
        group.throughput(Throughput::Elements(1));

        group.bench_with_input(
            BenchmarkId::new("full_reconcile", size),
            &size,
            |b, &size| {
                let graph = setup_realistic_graph(size);
                let spec = simple_service_spec();
                let mut rng = StdRng::seed_from_u64(99);

                b.iter(|| {
                    let idx = rng.gen_range(0..size);
                    let name = format!("svc-{}", idx);

                    let _ = black_box(graph.get_service("default", &name));
                    graph.put_service("default", &name, &spec);

                    let deps = graph.get_dependencies("default", &name);
                    for dep in &deps {
                        black_box(graph.get_service("default", dep));
                    }

                    let _ = black_box(graph.get_active_inbound_edges("default", &name));
                    let _ = black_box(graph.get_active_outbound_edges("default", &name));
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Graph construction time (matters for operator restart at scale)
// =============================================================================

fn bench_graph_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("graph_construction");
    group.sample_size(10);

    for size in [100usize, 1_000, 5_000, 10_000, 25_000, 50_000] {
        group.bench_with_input(BenchmarkId::new("realistic", size), &size, |b, &size| {
            b.iter(|| {
                black_box(setup_realistic_graph(size));
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
    bench_put_service,
    bench_get_service,
    bench_delete_service,
    bench_get_dependencies,
    bench_get_dependents,
    bench_get_active_edges,
    bench_depends_all_edges,
    bench_concurrent_reads,
    bench_concurrent_mixed,
    bench_reconcile_pattern,
    bench_graph_construction,
);

criterion_main!(benches);
