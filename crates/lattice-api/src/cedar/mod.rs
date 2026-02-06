//! Cedar policy authorization
//!
//! Provides fine-grained access control to clusters using Cedar policies.

mod policy_engine;
pub mod validation;

pub use policy_engine::{ClusterAttributes, PolicyEngine};
