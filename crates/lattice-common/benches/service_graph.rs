//! Criterion benchmarks for ServiceGraph
//!
//! These benchmarks measure the performance of common ServiceGraph operations
//! that will be used during reconciliation and network policy generation.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::prelude::*;

use lattice_common::crd::{
    ContainerSpec, DependencyDirection, DeploySpec, LatticeExternalServiceSpec, LatticeServiceSpec,
    PortSpec, ReplicaSpec, Resolution, ResourceSpec, ResourceType, ServicePortsSpec,
};
use lattice_common::graph::ServiceGraph;

// =============================================================================
// Test Fixtures
// =============================================================================

fn simple_container() -> ContainerSpec {
    ContainerSpec {
        image: "nginx:latest".to_string(),
        command: None,
        args: None,
        variables: BTreeMap::new(),
        resources: None,
        files: BTreeMap::new(),
        volumes: BTreeMap::new(),
        liveness_probe: None,
        readiness_probe: None,
        startup_probe: None,
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
                volume: None,
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
                volume: None,
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
        environment: "default".to_string(),
        containers,
        resources,
        service: Some(ServicePortsSpec { ports }),
        replicas: ReplicaSpec::default(),
        deploy: DeploySpec::default(),
        ingress: None,
    }
}

fn simple_service_spec() -> LatticeServiceSpec {
    service_spec_with_deps(&[], &[])
}

#[allow(dead_code)]
fn external_service_spec() -> LatticeExternalServiceSpec {
    let mut endpoints = BTreeMap::new();
    endpoints.insert("api".to_string(), "https://api.example.com".to_string());

    LatticeExternalServiceSpec {
        environment: "default".to_string(),
        endpoints,
        allowed_requesters: vec!["*".to_string()],
        resolution: Resolution::Dns,
        description: None,
    }
}

// =============================================================================
// Graph Setup Helpers
// =============================================================================

/// Create a chain topology: svc-0 → svc-1 → svc-2 → ... → svc-n
fn setup_chain_graph(n: usize) -> ServiceGraph {
    let graph = ServiceGraph::new();

    for i in 0..n {
        // Each service depends on the next one
        let dep_name = format!("svc-{}", i + 1);
        let spec = if i < n - 1 {
            service_spec_with_deps(&[&dep_name], &[])
        } else {
            simple_service_spec()
        };

        graph.put_service("default", &format!("svc-{}", i), &spec);
    }

    // Add allowed callers to make edges active
    for i in 1..n {
        let caller_name = format!("svc-{}", i - 1);
        let spec = service_spec_with_deps(&[], &[&caller_name]);
        graph.put_service("default", &format!("svc-{}", i), &spec);
    }

    graph
}

/// Create a star topology: hub ← spoke-0, spoke-1, ..., spoke-n
fn setup_star_graph(n: usize) -> ServiceGraph {
    let graph = ServiceGraph::new();

    // Hub service allows all spokes
    let caller_names: Vec<String> = (0..n).map(|i| format!("spoke-{}", i)).collect();
    let caller_refs: Vec<&str> = caller_names.iter().map(|s| s.as_str()).collect();
    let hub_spec = service_spec_with_deps(&[], &caller_refs);
    graph.put_service("default", "hub", &hub_spec);

    // Each spoke depends on hub
    for i in 0..n {
        let spec = service_spec_with_deps(&["hub"], &[]);
        graph.put_service("default", &format!("spoke-{}", i), &spec);
    }

    graph
}

/// Create a mesh topology: every service connected to every other
fn setup_mesh_graph(n: usize) -> ServiceGraph {
    let graph = ServiceGraph::new();

    // First pass: create all services with their dependencies
    for i in 0..n {
        let dep_names: Vec<String> = (0..n)
            .filter(|&j| j != i && j > i) // Only depend on services with higher indices
            .map(|j| format!("svc-{}", j))
            .collect();
        let dep_refs: Vec<&str> = dep_names.iter().map(|s| s.as_str()).collect();

        let caller_names: Vec<String> = (0..n)
            .filter(|&j| j != i && j < i) // Allow services with lower indices
            .map(|j| format!("svc-{}", j))
            .collect();
        let caller_refs: Vec<&str> = caller_names.iter().map(|s| s.as_str()).collect();

        let spec = service_spec_with_deps(&dep_refs, &caller_refs);
        graph.put_service("default", &format!("svc-{}", i), &spec);
    }

    graph
}

/// Create a realistic microservices topology
fn setup_realistic_graph(n: usize) -> ServiceGraph {
    let graph = ServiceGraph::new();
    let mut rng = rand::thread_rng();

    // Create n services with random but realistic connectivity
    // Average 2-3 dependencies per service
    for i in 0..n {
        let num_deps = rng.gen_range(0..=4.min(n.saturating_sub(1)));
        let dep_indices: Vec<usize> = (0..n)
            .filter(|&j| j != i)
            .choose_multiple(&mut rng, num_deps);

        let dep_names: Vec<String> = dep_indices.iter().map(|j| format!("svc-{}", j)).collect();
        let dep_refs: Vec<&str> = dep_names.iter().map(|s| s.as_str()).collect();

        // Random callers (simulating bilateral agreements)
        let num_callers = rng.gen_range(0..=3.min(n.saturating_sub(1)));
        let caller_indices: Vec<usize> = (0..n)
            .filter(|&j| j != i)
            .choose_multiple(&mut rng, num_callers);

        let caller_names: Vec<String> = caller_indices
            .iter()
            .map(|j| format!("svc-{}", j))
            .collect();
        let caller_refs: Vec<&str> = caller_names.iter().map(|s| s.as_str()).collect();

        let spec = service_spec_with_deps(&dep_refs, &caller_refs);
        graph.put_service("default", &format!("svc-{}", i), &spec);
    }

    graph
}

// =============================================================================
// Benchmarks: Single Operations
// =============================================================================

fn bench_put_service(c: &mut Criterion) {
    let mut group = c.benchmark_group("put_service");

    for size in [10usize, 100, 500, 1000] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("empty_graph", size), &size, |b, &size| {
            let graph = ServiceGraph::new();
            let spec = simple_service_spec();
            let mut i = 0;
            b.iter(|| {
                graph.put_service("default", &format!("svc-{}", i % size), black_box(&spec));
                i += 1;
            });
        });

        group.bench_with_input(
            BenchmarkId::new("existing_graph", size),
            &size,
            |b, &size| {
                let graph = setup_realistic_graph(size);
                let spec = simple_service_spec();
                let mut i = 0;
                b.iter(|| {
                    // Update existing service
                    graph.put_service("default", &format!("svc-{}", i % size), black_box(&spec));
                    i += 1;
                });
            },
        );
    }

    group.finish();
}

fn bench_get_service(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_service");

    for size in [10usize, 100, 500, 1000] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("lookup", size), &size, |b, &size| {
            let graph = setup_realistic_graph(size);
            let mut rng = rand::thread_rng();
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

    for size in [10usize, 100, 500] {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("delete", size), &size, |b, &size| {
            b.iter_batched(
                || setup_realistic_graph(size),
                |graph| {
                    // Delete a random service
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

fn bench_get_dependencies(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_dependencies");

    for size in [10usize, 100, 500, 1000] {
        group.throughput(Throughput::Elements(1));

        // Chain topology (single dependency each)
        group.bench_with_input(BenchmarkId::new("chain", size), &size, |b, &size| {
            let graph = setup_chain_graph(size);
            let mut rng = rand::thread_rng();
            b.iter(|| {
                let idx = rng.gen_range(0..size);
                black_box(graph.get_dependencies("default", &format!("svc-{}", idx)));
            });
        });

        // Star topology (hub has many dependents)
        group.bench_with_input(BenchmarkId::new("star", size), &size, |b, &size| {
            let graph = setup_star_graph(size);
            let mut rng = rand::thread_rng();
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

    for size in [10usize, 100, 500] {
        group.throughput(Throughput::Elements(1));

        // Star topology - hub has many dependents
        group.bench_with_input(BenchmarkId::new("star_hub", size), &size, |b, &size| {
            let graph = setup_star_graph(size);
            b.iter(|| {
                black_box(graph.get_dependents("default", "hub"));
            });
        });

        // Realistic topology
        group.bench_with_input(BenchmarkId::new("realistic", size), &size, |b, &size| {
            let graph = setup_realistic_graph(size);
            let mut rng = rand::thread_rng();
            b.iter(|| {
                let idx = rng.gen_range(0..size);
                black_box(graph.get_dependents("default", &format!("svc-{}", idx)));
            });
        });
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Active Edge Operations (for Network Policy)
// =============================================================================

fn bench_get_active_edges(c: &mut Criterion) {
    let mut group = c.benchmark_group("active_edges");

    for size in [10usize, 100, 500] {
        group.throughput(Throughput::Elements(1));

        // Inbound edges
        group.bench_with_input(BenchmarkId::new("inbound", size), &size, |b, &size| {
            let graph = setup_realistic_graph(size);
            let mut rng = rand::thread_rng();
            b.iter(|| {
                let idx = rng.gen_range(0..size);
                black_box(graph.get_active_inbound_edges("default", &format!("svc-{}", idx)));
            });
        });

        // Outbound edges
        group.bench_with_input(BenchmarkId::new("outbound", size), &size, |b, &size| {
            let graph = setup_realistic_graph(size);
            let mut rng = rand::thread_rng();
            b.iter(|| {
                let idx = rng.gen_range(0..size);
                black_box(graph.get_active_outbound_edges("default", &format!("svc-{}", idx)));
            });
        });

        // Star hub (many inbound)
        group.bench_with_input(
            BenchmarkId::new("star_hub_inbound", size),
            &size,
            |b, &size| {
                let graph = setup_star_graph(size);
                b.iter(|| {
                    black_box(graph.get_active_inbound_edges("default", "hub"));
                });
            },
        );
    }

    group.finish();
}

fn bench_list_active_edges(c: &mut Criterion) {
    let mut group = c.benchmark_group("list_active_edges");

    for size in [10usize, 100, 500] {
        group.throughput(Throughput::Elements(1));

        group.bench_with_input(BenchmarkId::new("realistic", size), &size, |b, &size| {
            let graph = setup_realistic_graph(size);
            b.iter(|| {
                black_box(graph.list_active_edges("default"));
            });
        });
    }

    group.finish();

    // Mesh benchmarks are O(n²) and very slow - use reduced sample size
    let mut mesh_group = c.benchmark_group("list_active_edges_mesh");
    mesh_group.sample_size(10);

    for size in [10usize, 100, 500] {
        mesh_group.throughput(Throughput::Elements(1));

        mesh_group.bench_with_input(BenchmarkId::new("mesh", size), &size, |b, &size| {
            let graph = setup_mesh_graph(size);
            b.iter(|| {
                black_box(graph.list_active_edges("default"));
            });
        });
    }

    mesh_group.finish();
}

// =============================================================================
// Benchmarks: Transitive Closure (Affected Services)
// =============================================================================

fn bench_get_affected_services(c: &mut Criterion) {
    let mut group = c.benchmark_group("affected_services");

    for size in [10usize, 100, 500] {
        group.throughput(Throughput::Elements(1));

        // Chain - affects all downstream
        group.bench_with_input(BenchmarkId::new("chain_head", size), &size, |b, &size| {
            let graph = setup_chain_graph(size);
            b.iter(|| {
                // Modify head of chain - affects all downstream
                black_box(graph.get_affected_services("default", "svc-0"));
            });
        });

        // Chain - affects only self at tail
        group.bench_with_input(BenchmarkId::new("chain_tail", size), &size, |b, &size| {
            let graph = setup_chain_graph(size);
            b.iter(|| {
                // Modify tail - affects only itself
                black_box(graph.get_affected_services("default", &format!("svc-{}", size - 1)));
            });
        });

        // Star - hub affects all spokes
        group.bench_with_input(BenchmarkId::new("star_hub", size), &size, |b, &size| {
            let graph = setup_star_graph(size);
            b.iter(|| {
                black_box(graph.get_affected_services("default", "hub"));
            });
        });

        // Realistic random
        group.bench_with_input(BenchmarkId::new("realistic", size), &size, |b, &size| {
            let graph = setup_realistic_graph(size);
            let mut rng = rand::thread_rng();
            b.iter(|| {
                let idx = rng.gen_range(0..size);
                black_box(graph.get_affected_services("default", &format!("svc-{}", idx)));
            });
        });
    }

    group.finish();
}

// =============================================================================
// Benchmarks: Concurrent Operations
// =============================================================================

fn bench_concurrent_reads(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_reads");

    for size in [100usize, 500] {
        group.throughput(Throughput::Elements(4)); // 4 threads

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

    for size in [100usize, 500] {
        group.throughput(Throughput::Elements(4)); // 4 threads

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
                                            // 20% writes
                                            g.put_service("default", &format!("svc-{}", idx), &s);
                                        } else {
                                            // 80% reads
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
// Benchmarks: Reconciliation Patterns
// =============================================================================

fn bench_reconcile_pattern(c: &mut Criterion) {
    let mut group = c.benchmark_group("reconcile_pattern");

    for size in [100usize, 500] {
        group.throughput(Throughput::Elements(1));

        // Typical reconcile: get service, update, check deps, get affected
        group.bench_with_input(
            BenchmarkId::new("full_reconcile", size),
            &size,
            |b, &size| {
                let graph = setup_realistic_graph(size);
                let spec = simple_service_spec();
                let mut rng = rand::thread_rng();

                b.iter(|| {
                    let idx = rng.gen_range(0..size);
                    let name = format!("svc-{}", idx);

                    // 1. Get current state
                    let _ = black_box(graph.get_service("default", &name));

                    // 2. Update service
                    graph.put_service("default", &name, &spec);

                    // 3. Check dependencies exist
                    let deps = graph.get_dependencies("default", &name);
                    for dep in &deps {
                        black_box(graph.get_service("default", dep));
                    }

                    // 4. Get active edges for network policy
                    let _ = black_box(graph.get_active_inbound_edges("default", &name));
                    let _ = black_box(graph.get_active_outbound_edges("default", &name));

                    // 5. Notify affected services
                    let _ = black_box(graph.get_affected_services("default", &name));
                });
            },
        );

        // Policy generation: list all active edges for environment
        group.bench_with_input(
            BenchmarkId::new("policy_generation", size),
            &size,
            |b, &size| {
                let graph = setup_realistic_graph(size);

                b.iter(|| {
                    // Get all active edges for policy generation
                    let edges = graph.list_active_edges("default");
                    black_box(edges);
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
    bench_put_service,
    bench_get_service,
    bench_delete_service,
    bench_get_dependencies,
    bench_get_dependents,
    bench_get_active_edges,
    bench_list_active_edges,
    bench_get_affected_services,
    bench_concurrent_reads,
    bench_concurrent_mixed,
    bench_reconcile_pattern,
);

criterion_main!(benches);
