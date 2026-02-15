//! MeshMember controller and mesh policy compilation for Lattice
//!
//! This crate is the single source of truth for all mesh policy generation:
//!
//! - **L7 (Istio AuthorizationPolicy)**: mTLS identity-based access control using SPIFFE principals
//! - **L4 (CiliumNetworkPolicy)**: eBPF-based network enforcement at the kernel level
//! - **PeerAuthentication**: Port-level mTLS mode (STRICT/PERMISSIVE)
//! - **ServiceEntry**: External service registration in the mesh
//!
//! The [`PolicyCompiler`] generates all policies from the [`ServiceGraph`](lattice_common::graph::ServiceGraph)
//! based on bilateral agreements. The MeshMember controller watches `LatticeMeshMember` CRDs
//! and applies the generated policies.

pub mod controller;
pub mod ingress;
pub mod policy;
