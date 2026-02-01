//! Policy type definitions for Kubernetes network policies
//!
//! Types for generating:
//! - Istio AuthorizationPolicy (L7 mTLS identity-based access control)
//! - Cilium CiliumNetworkPolicy (L4 eBPF-based network enforcement)
//! - Istio ServiceEntry (external service mesh registration)
//!
//! All policy types implement the `HasApiResource` trait for consistent
//! API version and kind handling.

mod cilium;
mod istio;
mod service_entry;

pub use cilium::{
    CiliumClusterwideNetworkPolicy, CiliumClusterwideSpec, CiliumEgressRule, CiliumIngressRule,
    CiliumNetworkPolicy, CiliumNetworkPolicySpec, CiliumPort, CiliumPortRule,
    ClusterwideEgressRule, ClusterwideEndpointSelector, ClusterwideIngressRule,
    ClusterwideMetadata, DnsMatch, DnsRules, EnableDefaultDeny, EndpointSelector, FqdnSelector,
    MatchExpression,
};
pub use istio::{
    AuthorizationOperation, AuthorizationPolicy, AuthorizationPolicySpec, AuthorizationRule,
    AuthorizationSource, MtlsConfig, OperationSpec, PeerAuthentication, PeerAuthenticationSpec,
    PolicyMetadata, SourceSpec, TargetRef, WorkloadSelector,
};
pub use service_entry::{ServiceEntry, ServiceEntryPort, ServiceEntrySpec};
