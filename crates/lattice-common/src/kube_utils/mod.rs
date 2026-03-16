//! Shared Kubernetes utilities using kube-rs
//!
//! Provides kubectl-equivalent operations without shelling out to kubectl.
//! FIPS compliant - no external binaries needed.

mod api_resource;
mod batch;
mod client;
mod conditions;
mod dynamic;
mod hash;
mod manifest;
mod metadata;
mod namespace;
mod service;
mod status;
mod token;
mod waiting;

// Re-export everything so `use lattice_common::kube_utils::*` continues to work.

// metadata.rs
pub use metadata::{
    strip_export_metadata, LabelSelector, ObjectMeta, OwnerReference, TopologySpreadConstraint,
};

// api_resource.rs
pub use api_resource::{
    build_api_resource, build_api_resource_with_discovery, parse_api_version, pluralize_kind,
    HasApiResource,
};

// conditions.rs
pub use conditions::{
    has_condition, HasConditionFields, CONDITION_AVAILABLE, CONDITION_READY, STATUS_TRUE,
};

// client.rs
pub use client::{create_client, DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT};

// waiting.rs
pub use waiting::{
    crd_exists, get_secret_data, secret_exists, wait_for_all_deployments, wait_for_crd,
    wait_for_deployment, wait_for_nodes_ready, wait_for_secret,
};
// namespace.rs
pub use namespace::ensure_namespace;

// manifest.rs
pub use manifest::{
    apply_manifest_with_retry, apply_manifests, is_deployment_json, kind_priority, ApplyOptions,
};

// batch.rs
pub use batch::ApplyBatch;

// status.rs
pub use status::{patch_cluster_resource_status, patch_resource_status};

// service.rs
pub use service::{build_cell_service, compile_service_account};

// dynamic.rs
pub use dynamic::{
    delete_resource_if_exists, get_dynamic_resource_status_field, get_machine_phases,
};

// hash.rs
pub use hash::{deterministic_hash, sha256};

// token.rs
pub use token::{request_istiod_proxy_token, PROXY_TOKEN_AUDIENCE, PROXY_TOKEN_EXPIRATION_SECS};

/// Build a K8s success Status JSON for exec sessions that exit cleanly.
///
/// kubectl expects a Status object on channel 3 (error/status channel) at
/// session end. For successful exits, this is `{"status": "Success"}`.
pub fn k8s_success_status() -> serde_json::Value {
    serde_json::json!({
        "status": "Success",
        "metadata": {}
    })
}

/// Return the namespace of a Kubernetes resource, defaulting to `lattice-system`.
pub fn effective_namespace<T: kube::ResourceExt>(resource: &T) -> String {
    resource
        .namespace()
        .unwrap_or_else(|| crate::LATTICE_SYSTEM_NAMESPACE.to_string())
}
