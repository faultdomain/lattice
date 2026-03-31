//! Benchmarks for the ILP capacity solver with realistic workload sizes.

use std::collections::BTreeMap;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use lattice_common::crd::{GpuCapacity, InstanceType, WorkerPoolSpec};
use lattice_cost::CostRates;
use lattice_quota::solver::{solve, AggregateDemand};

fn rates() -> CostRates {
    CostRates {
        cpu: 0.031,
        memory: 0.004,
        gpu: BTreeMap::from([
            ("NVIDIA-H100-SXM".to_string(), 3.50),
            ("NVIDIA-A100-80GB".to_string(), 2.21),
            ("NVIDIA-L4".to_string(), 0.81),
            ("NVIDIA-T4".to_string(), 0.35),
        ]),
    }
}

fn make_cpu_pool(cores: u32, mem_gib: u32) -> WorkerPoolSpec {
    WorkerPoolSpec {
        instance_type: Some(InstanceType {
            cores: Some(cores),
            memory_gib: Some(mem_gib),
            disk_gib: Some(100),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn make_gpu_pool(gpu_count: u32, cores: u32, mem_gib: u32, model: &str) -> WorkerPoolSpec {
    WorkerPoolSpec {
        instance_type: Some(InstanceType {
            cores: Some(cores),
            memory_gib: Some(mem_gib),
            disk_gib: Some(100),
            gpu: Some(GpuCapacity {
                count: gpu_count,
                model: model.to_string(),
                memory_gib: Some(80),
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Generate a realistic set of AWS-like instance types.
/// Permutes CPU families, memory ratios, and GPU configs to reach large pool counts.
fn aws_like_pools(count: usize) -> BTreeMap<String, WorkerPoolSpec> {
    let mut pools = BTreeMap::new();

    // CPU instance families: general, compute-optimized, memory-optimized
    let families: Vec<(&str, u32)> = vec![
        ("m5", 2),  // 1:4 ratio (cores:gib)
        ("m6i", 2), // 1:4
        ("m7i", 2), // 1:4
        ("c5", 4),  // 1:2 ratio
        ("c6i", 4), // 1:2
        ("c7i", 4), // 1:2
        ("r5", 1),  // 1:8 ratio
        ("r6i", 1), // 1:8
        ("r7i", 1), // 1:8
    ];

    let sizes: Vec<(u32, &str)> = vec![
        (2, "large"),
        (4, "xlarge"),
        (8, "2xlarge"),
        (16, "4xlarge"),
        (32, "8xlarge"),
        (48, "12xlarge"),
        (64, "16xlarge"),
        (96, "24xlarge"),
        (128, "32xlarge"),
        (192, "48xlarge"),
    ];

    for (family, mem_ratio) in &families {
        for (cores, size) in &sizes {
            if pools.len() >= count {
                break;
            }
            let mem_gib = cores * (4 / mem_ratio).max(1) * mem_ratio;
            pools.insert(format!("{family}.{size}"), make_cpu_pool(*cores, mem_gib));
        }
    }

    // GPU instances
    let gpu_configs: Vec<(u32, u32, u32, &str)> = vec![
        (1, 4, 16, "NVIDIA-T4"),
        (1, 8, 32, "NVIDIA-T4"),
        (4, 48, 192, "NVIDIA-T4"),
        (1, 4, 16, "NVIDIA-L4"),
        (2, 24, 96, "NVIDIA-L4"),
        (4, 48, 192, "NVIDIA-L4"),
        (8, 96, 768, "NVIDIA-L4"),
        (1, 12, 85, "NVIDIA-A100-80GB"),
        (2, 24, 170, "NVIDIA-A100-80GB"),
        (4, 48, 340, "NVIDIA-A100-80GB"),
        (8, 96, 680, "NVIDIA-A100-80GB"),
        (8, 192, 2048, "NVIDIA-H100-SXM"),
        (4, 96, 1024, "NVIDIA-H100-SXM"),
        (2, 48, 512, "NVIDIA-H100-SXM"),
        (1, 24, 256, "NVIDIA-H100-SXM"),
    ];

    for (gpus, cores, mem, model) in &gpu_configs {
        if pools.len() >= count {
            break;
        }
        pools.insert(
            format!("gpu-{gpus}x{model}-{cores}c"),
            make_gpu_pool(*gpus, *cores, *mem, model),
        );
    }

    pools
}

fn bench_solve(c: &mut Criterion) {
    let rates = rates();

    let mut group = c.benchmark_group("solve");

    // Vary pool count (instance types) — push toward AWS-scale catalog
    for pool_count in [10, 31, 50, 100, 200] {
        let pools = aws_like_pools(pool_count);
        // Enterprise-scale hard quotas: 5k cores, 20TB RAM, 128 GPUs, $2.5k/hr budget
        let demand = AggregateDemand {
            hard_cpu_millis: 5_000_000,
            hard_memory_bytes: 20_000_i64 * 1024 * 1024 * 1024,
            hard_gpu_count: 128,
            hard_cost_budget: 2500.0,
        };

        group.bench_with_input(
            BenchmarkId::new("pools", pool_count),
            &pool_count,
            |b, _| {
                b.iter(|| solve(&pools, &demand, &rates));
            },
        );
    }

    // CPU-only: 25k reserved cores across 100 pool types
    let large_pools = aws_like_pools(100);
    let cpu_only = AggregateDemand {
        hard_cpu_millis: 25_000_000,
        hard_memory_bytes: 100_000_i64 * 1024 * 1024 * 1024,
        ..Default::default()
    };
    group.bench_function("cpu_only_100_pools", |b| {
        b.iter(|| solve(&large_pools, &cpu_only, &rates));
    });

    // GPU-heavy: 256 reserved GPUs, tight cost budget, 100 pool types
    let gpu_heavy = AggregateDemand {
        hard_gpu_count: 256,
        hard_cpu_millis: 10_000_000,
        hard_memory_bytes: 40_000_i64 * 1024 * 1024 * 1024,
        hard_cost_budget: 1000.0,
    };
    group.bench_function("gpu_heavy_100_pools", |b| {
        b.iter(|| solve(&large_pools, &gpu_heavy, &rates));
    });

    // Worst case: 200 pool types, all constraints active
    let max_pools = aws_like_pools(200);
    let max_demand = AggregateDemand {
        hard_cpu_millis: 50_000_000,
        hard_memory_bytes: 200_000_i64 * 1024 * 1024 * 1024,
        hard_gpu_count: 512,
        hard_cost_budget: 5_000.0,
    };
    group.bench_function("worst_case_200_pools", |b| {
        b.iter(|| solve(&max_pools, &max_demand, &rates));
    });

    // Zero demand (fast path)
    group.bench_function("zero_demand", |b| {
        b.iter(|| solve(&large_pools, &AggregateDemand::default(), &rates));
    });

    group.finish();
}

criterion_group!(benches, bench_solve);
criterion_main!(benches);
