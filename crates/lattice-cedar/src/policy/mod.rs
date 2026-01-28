//! Cedar policy storage and compilation
//!
//! This module provides a concurrent policy store backed by DashMap, with
//! Cedar policy compilation and caching.

mod compiler;
mod store;

pub use compiler::PolicyCompiler;
pub use store::PolicyStore;
