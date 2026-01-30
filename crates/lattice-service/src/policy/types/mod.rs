//! Policy type definitions
//!
//! This module contains the Kubernetes resource types for:
//! - Istio AuthorizationPolicy (L7 mTLS identity-based access control)
//! - Cilium CiliumNetworkPolicy (L4 eBPF-based network enforcement)
//! - Istio ServiceEntry (external service mesh registration)

mod cilium;
mod istio;
mod service_entry;

// Re-export all types at the module level for convenience
pub use cilium::{
    CiliumEgressRule, CiliumIngressRule, CiliumNetworkPolicy, CiliumNetworkPolicySpec, CiliumPort,
    CiliumPortRule, EndpointSelector, FqdnSelector,
};
pub use istio::{
    AuthorizationOperation, AuthorizationPolicy, AuthorizationPolicySpec, AuthorizationRule,
    AuthorizationSource, OperationSpec, PolicyMetadata, SourceSpec, TargetRef, WorkloadSelector,
};
pub use service_entry::{ServiceEntry, ServiceEntryPort, ServiceEntrySpec};
