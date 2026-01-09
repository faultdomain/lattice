//! Controller implementations for Lattice CRDs
//!
//! This module contains the reconciliation logic for all Lattice custom resources.
//! Controllers follow the Kubernetes controller pattern with observe-diff-act loops.

mod cluster;
mod service;

pub use cluster::{
    error_policy, reconcile, CellCapabilities, ClusterBootstrap, ClusterBootstrapImpl, Context,
    ContextBuilder, KubeClient, KubeClientImpl, PivotOperations, PivotOperationsImpl,
};

pub use service::{
    cleanup_external_service, cleanup_service, error_policy as service_error_policy,
    error_policy_external, reconcile as service_reconcile, reconcile_external,
    ServiceContext, ServiceKubeClient, ServiceKubeClientImpl,
};
