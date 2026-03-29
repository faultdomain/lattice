//! Cost calculation for Lattice workloads.
//!
//! Computes hourly cost from resource requests × rates for each workload type.

use lattice_common::crd::{
    CostBreakdown, CostEstimate, LatticeJobSpec, LatticeModelSpec, LatticeServiceSpec, WorkloadSpec,
};
use lattice_common::resources::sum_container_cpu_memory;

use crate::error::CostError;
use crate::rates::CostRates;

const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

/// Estimate hourly cost for a LatticeService.
pub fn estimate_service_cost(
    spec: &LatticeServiceSpec,
    rates: &CostRates,
) -> Result<CostEstimate, CostError> {
    let (cpu, mem, gpu) = workload_cost(&spec.workload, rates, spec.replicas as f64)?;
    Ok(build_estimate(cpu, mem, gpu))
}

/// Estimate hourly cost for a LatticeJob (sum across all tasks).
pub fn estimate_job_cost(
    spec: &LatticeJobSpec,
    rates: &CostRates,
) -> Result<CostEstimate, CostError> {
    let mut total_cpu = 0.0;
    let mut total_mem = 0.0;
    let mut total_gpu = 0.0;

    for task in spec.merged_tasks().values() {
        let (cpu, mem, gpu) = workload_cost(&task.workload, rates, task.replicas() as f64)?;
        total_cpu += cpu;
        total_mem += mem;
        total_gpu += gpu;
    }

    Ok(build_estimate(total_cpu, total_mem, total_gpu))
}

/// Estimate hourly cost for a LatticeModel (sum across all roles, entry + worker).
pub fn estimate_model_cost(
    spec: &LatticeModelSpec,
    rates: &CostRates,
) -> Result<CostEstimate, CostError> {
    let mut total_cpu = 0.0;
    let mut total_mem = 0.0;
    let mut total_gpu = 0.0;

    for role in spec.merged_roles().values() {
        let (cpu, mem, gpu) = workload_cost(&role.entry_workload, rates, role.replicas() as f64)?;
        total_cpu += cpu;
        total_mem += mem;
        total_gpu += gpu;

        // Worker pods (P/D disaggregation)
        if let (Some(worker_replicas), Some(ref worker_workload)) =
            (role.worker_replicas, &role.worker_workload)
        {
            let (cpu, mem, gpu) = workload_cost(worker_workload, rates, worker_replicas as f64)?;
            total_cpu += cpu;
            total_mem += mem;
            total_gpu += gpu;
        }
    }

    Ok(build_estimate(total_cpu, total_mem, total_gpu))
}

/// Compute CPU, memory, and GPU hourly cost for a single workload × replica count.
fn workload_cost(
    workload: &WorkloadSpec,
    rates: &CostRates,
    replicas: f64,
) -> Result<(f64, f64, f64), CostError> {
    let (cpu_millis, mem_bytes) = sum_container_cpu_memory(&workload.containers)?;
    let gpu_hourly = sum_gpu_cost(workload, rates)?;

    let cpu = (cpu_millis as f64 / 1000.0) * rates.cpu * replicas;
    let mem = (mem_bytes as f64 / GIB) * rates.memory * replicas;
    let gpu = gpu_hourly * replicas;
    Ok((cpu, mem, gpu))
}

/// Sum GPU hourly cost from GPU resources declared in a WorkloadSpec.
fn sum_gpu_cost(workload: &WorkloadSpec, rates: &CostRates) -> Result<f64, CostError> {
    let mut total = 0.0;

    for resource in workload.resources.values() {
        if let Some(gpu) = resource.params.as_gpu() {
            let model = gpu.model.as_deref().ok_or_else(|| {
                CostError::MissingRate(
                    "GPU resource has no 'model' specified; cannot determine rate".to_string(),
                )
            })?;

            let rate = rates
                .gpu
                .get(model)
                .ok_or_else(|| CostError::MissingGpuRate(model.to_string()))?;

            total += *rate * gpu.count as f64;
        }
    }

    Ok(total)
}

fn format_rate(amount: f64) -> String {
    format!("{:.4}", amount)
}

fn build_estimate(cpu: f64, memory: f64, gpu: f64) -> CostEstimate {
    let total = cpu + memory + gpu;
    CostEstimate {
        hourly_cost: format_rate(total),
        breakdown: CostBreakdown {
            cpu: format_rate(cpu),
            memory: format_rate(memory),
            gpu: if gpu > 0.0 {
                Some(format_rate(gpu))
            } else {
                None
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lattice_common::crd::{
        ContainerSpec, GpuParams, ResourceParams, ResourceQuantity, ResourceRequirements,
        ResourceSpec, ResourceType,
    };

    use super::*;

    fn test_rates() -> CostRates {
        CostRates {
            cpu: 0.031,
            memory: 0.004,
            gpu: BTreeMap::from([("H100-SXM".to_string(), 3.50), ("L4".to_string(), 0.81)]),
        }
    }

    fn container_with_resources(cpu: &str, memory: &str) -> ContainerSpec {
        ContainerSpec {
            image: "test:latest".to_string(),
            resources: Some(ResourceRequirements {
                requests: Some(ResourceQuantity {
                    cpu: Some(cpu.to_string()),
                    memory: Some(memory.to_string()),
                }),
                limits: None,
            }),
            ..Default::default()
        }
    }

    fn gpu_resource(model: &str, count: u32) -> ResourceSpec {
        ResourceSpec {
            type_: ResourceType::Gpu,
            params: ResourceParams::Gpu(GpuParams {
                count,
                model: Some(model.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_service_cost_cpu_only() {
        let rates = test_rates();
        let spec = LatticeServiceSpec {
            workload: WorkloadSpec {
                containers: BTreeMap::from([(
                    "main".to_string(),
                    container_with_resources("500m", "1Gi"),
                )]),
                ..Default::default()
            },
            replicas: 2,
            ..Default::default()
        };

        let est = estimate_service_cost(&spec, &rates).unwrap();
        // CPU: 0.5 cores × $0.031 × 2 replicas = $0.031
        // Mem: 1 GiB × $0.004 × 2 replicas = $0.008
        // Total: $0.039
        let total: f64 = est.hourly_cost.parse().unwrap();
        assert!((total - 0.039).abs() < 0.001);
        assert!(est.breakdown.gpu.is_none());
    }

    #[test]
    fn test_service_cost_with_gpu() {
        let rates = test_rates();
        let spec = LatticeServiceSpec {
            workload: WorkloadSpec {
                containers: BTreeMap::from([(
                    "main".to_string(),
                    container_with_resources("4", "32Gi"),
                )]),
                resources: BTreeMap::from([("gpu".to_string(), gpu_resource("H100-SXM", 8))]),
                ..Default::default()
            },
            replicas: 1,
            ..Default::default()
        };

        let est = estimate_service_cost(&spec, &rates).unwrap();
        // CPU: 4 cores × $0.031 = $0.124
        // Mem: 32 GiB × $0.004 = $0.128
        // GPU: 8 × $3.50 = $28.00
        // Total: $28.252
        let total: f64 = est.hourly_cost.parse().unwrap();
        assert!((total - 28.252).abs() < 0.001);
        assert!(est.breakdown.gpu.is_some());
    }

    #[test]
    fn test_service_cost_missing_gpu_model() {
        let rates = test_rates();
        let spec = LatticeServiceSpec {
            workload: WorkloadSpec {
                containers: BTreeMap::from([(
                    "main".to_string(),
                    container_with_resources("1", "1Gi"),
                )]),
                resources: BTreeMap::from([(
                    "gpu".to_string(),
                    gpu_resource("H200-SXM", 4), // Not in rates
                )]),
                ..Default::default()
            },
            replicas: 1,
            ..Default::default()
        };

        let err = estimate_service_cost(&spec, &rates).unwrap_err();
        assert!(matches!(err, CostError::MissingGpuRate(_)));
    }

    // ---- job cost ----

    #[test]
    fn test_job_cost_multi_task() {
        use lattice_common::crd::JobTaskSpec;

        let rates = test_rates();
        let spec = LatticeJobSpec {
            tasks: BTreeMap::from([
                (
                    "coordinator".to_string(),
                    JobTaskSpec {
                        replicas: Some(1),
                        workload: WorkloadSpec {
                            containers: BTreeMap::from([(
                                "main".to_string(),
                                container_with_resources("2", "8Gi"),
                            )]),
                            ..Default::default()
                        },
                        runtime: Default::default(),
                        restart_policy: None,
                        policies: None,
                    },
                ),
                (
                    "worker".to_string(),
                    JobTaskSpec {
                        replicas: Some(4),
                        workload: WorkloadSpec {
                            containers: BTreeMap::from([(
                                "main".to_string(),
                                container_with_resources("4", "16Gi"),
                            )]),
                            resources: BTreeMap::from([(
                                "gpu".to_string(),
                                gpu_resource("H100-SXM", 8),
                            )]),
                            ..Default::default()
                        },
                        runtime: Default::default(),
                        restart_policy: None,
                        policies: None,
                    },
                ),
            ]),
            ..Default::default()
        };

        let est = estimate_job_cost(&spec, &rates).unwrap();
        // Coordinator: CPU 2×0.031 + Mem 8×0.004 = 0.062+0.032 = 0.094 × 1 replica
        // Worker: CPU 4×0.031 + Mem 16×0.004 + GPU 8×3.50 = 0.124+0.064+28.0 = 28.188 × 4 replicas = 112.752
        // Total: 0.094 + 112.752 = 112.846
        let total: f64 = est.hourly_cost.parse().unwrap();
        assert!((total - 112.846).abs() < 0.01);
    }

    // ---- model cost ----

    #[test]
    fn test_model_cost_with_workers() {
        use lattice_common::crd::ModelRoleSpec;

        let rates = test_rates();
        let spec = LatticeModelSpec {
            roles: BTreeMap::from([(
                "prefill".to_string(),
                ModelRoleSpec {
                    replicas: Some(2),
                    entry_workload: WorkloadSpec {
                        containers: BTreeMap::from([(
                            "main".to_string(),
                            container_with_resources("4", "32Gi"),
                        )]),
                        resources: BTreeMap::from([(
                            "gpu".to_string(),
                            gpu_resource("H100-SXM", 4),
                        )]),
                        ..Default::default()
                    },
                    worker_replicas: Some(4),
                    worker_workload: Some(WorkloadSpec {
                        containers: BTreeMap::from([(
                            "main".to_string(),
                            container_with_resources("2", "16Gi"),
                        )]),
                        resources: BTreeMap::from([("gpu".to_string(), gpu_resource("L4", 1))]),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let est = estimate_model_cost(&spec, &rates).unwrap();
        // Entry: (4×0.031 + 32×0.004 + 4×3.50) × 2 = (0.124+0.128+14.0) × 2 = 28.504
        // Worker: (2×0.031 + 16×0.004 + 1×0.81) × 4 = (0.062+0.064+0.81) × 4 = 3.744
        // Total: 28.504 + 3.744 = 32.248
        let total: f64 = est.hourly_cost.parse().unwrap();
        assert!((total - 32.248).abs() < 0.01);
    }

    #[test]
    fn test_zero_replicas() {
        let rates = test_rates();
        let spec = LatticeServiceSpec {
            workload: WorkloadSpec {
                containers: BTreeMap::from([(
                    "main".to_string(),
                    container_with_resources("1", "1Gi"),
                )]),
                ..Default::default()
            },
            replicas: 0,
            ..Default::default()
        };

        let est = estimate_service_cost(&spec, &rates).unwrap();
        let total: f64 = est.hourly_cost.parse().unwrap();
        assert!((total - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_no_resource_requests() {
        let rates = test_rates();
        let spec = LatticeServiceSpec {
            workload: WorkloadSpec {
                containers: BTreeMap::from([(
                    "main".to_string(),
                    ContainerSpec {
                        image: "test:latest".to_string(),
                        resources: None,
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            },
            replicas: 1,
            ..Default::default()
        };

        let est = estimate_service_cost(&spec, &rates).unwrap();
        let total: f64 = est.hourly_cost.parse().unwrap();
        assert!((total - 0.0).abs() < f64::EPSILON);
    }
}
