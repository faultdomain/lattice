//! Policy type definitions for Kubernetes network policies
//!
//! Types for generating:
//! - Istio AuthorizationPolicy (L7 mTLS identity-based access control)
//! - Cilium CiliumNetworkPolicy (L4 eBPF-based network enforcement)
//! - Istio ServiceEntry (external service mesh registration)
//!
//! All policy types implement the `HasApiResource` trait for consistent
//! API version and kind handling.

pub mod cilium;
pub mod istio;
pub mod service_entry;
pub mod tetragon;
