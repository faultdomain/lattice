//! Shared workload compilation pipeline for Lattice CRDs
//!
//! Compiles `WorkloadSpec` into Kubernetes primitives (pod template, ConfigMaps,
//! Secrets, PVCs, ExternalSecrets). CRD-specific crates wrap the output in their
//! own resource types (Deployment, VCJob, SparkApplication).
//!
//! # Usage
//!
//! ```rust,ignore
//! let compiled = WorkloadCompiler::new(name, namespace, workload, runtime, provider_type)
//!     .with_cedar(cedar)
//!     .with_cluster_name(cluster_name)
//!     .with_volume_authorization(VolumeAuthorizationMode::Full { graph })
//!     .with_annotations(&annotations)
//!     .compile()
//!     .await?;
//! ```

pub mod backup;
mod compiled;
mod compiler;
pub mod error;
pub mod helpers;
pub mod k8s;
mod pod_template_json;

mod authorization;
mod pipeline;

pub use authorization::{PrincipalFormatter, ServicePrincipal, VolumeAuthorizationMode};
pub use compiled::{CompiledConfig, CompiledWorkload};
pub use compiler::WorkloadCompiler;
pub use error::CompilationError;
pub use pipeline::pod_template::CompiledPodTemplate;
pub use pipeline::secrets::SecretRef;
pub use pod_template_json::pod_template_to_json;
